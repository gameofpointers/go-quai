// Copyright 2017 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package quai

import (
	"errors"
	"sync"
	"time"

	"github.com/dominant-strategies/go-quai/common"
	"github.com/dominant-strategies/go-quai/core/rawdb"
	"github.com/dominant-strategies/go-quai/core/state"
	"github.com/dominant-strategies/go-quai/crypto"
	"github.com/dominant-strategies/go-quai/trie"
	"golang.org/x/crypto/sha3"
)

var (
	errCancelStateFetch = errors.New("state data download canceled (requested)")
)

// stateReq represents a batch of state fetch requests grouped together into
// a single data retrieval network packet.
type stateReq struct {
	nItems    uint16                    // Number of items requested for download (max is 384, so uint16 is sufficient)
	trieTasks map[common.Hash]*trieTask // Trie node download tasks to track previous attempts
	codeTasks map[common.Hash]*codeTask // Byte code download tasks to track previous attempts
	timeout   time.Duration             // Maximum round trip time for this to complete
	timer     *time.Timer               // Timer to fire when the RTT timeout expires
	delivered time.Time                 // Time when the packet was delivered (independent when we process it)
	response  [][]byte                  // Response data of the peer (nil for timeouts)
	dropped   bool                      // Flag whether the peer dropped off early
}

// timedOut returns if this request timed out.
func (req *stateReq) timedOut() bool {
	return req.response == nil
}

// stateSyncStats is a collection of progress stats to report during a state trie
// sync to RPC requests as well as to display in user logs.
type stateSyncStats struct {
	processed  uint64 // Number of state entries processed
	duplicate  uint64 // Number of state entries downloaded twice
	unexpected uint64 // Number of non-requested state entries received
	pending    uint64 // Number of still pending state entries
}

// syncState starts downloading state with the given root hash.
func (h *handler) syncState(root common.Hash) *stateSync {
	// Create the state sync
	s := newStateSync(h, root)
	select {
	case h.stateSyncStart <- s:
		// If we tell the statesync to restart with a new root, we also need
		// to wait for it to actually also start -- when old requests have timed
		// out or been delivered
		<-s.started
	case <-h.quitCh:
		s.err = errCancelStateFetch
		close(s.done)
	}
	return s
}

// stateFetcher manages the active state sync and accepts requests
// on its behalf.
func (h *handler) stateFetcher() {
	for {
		select {
		case s := <-h.stateSyncStart:
			for next := s; next != nil; {
				next = h.runStateSync(next)
			}
		case <-h.quitCh:
			return
		}
	}
}

// runStateSync runs a state synchronisation until it completes or another root
// hash is requested to be switched over to.
func (h *handler) runStateSync(s *stateSync) *stateSync {
	var (
		finished []*stateReq // Completed or failed requests
	)
	h.logger.Info("State sync starting", "root", s.root)

	go s.run()
	defer s.Cancel()

	for {
		// Enable sending of the first buffered element if there is one.
		var (
			deliverReq   *stateReq
			deliverReqCh chan *stateReq
		)
		if len(finished) > 0 {
			deliverReq = finished[0]
			deliverReqCh = s.deliver
		}

		select {
		// Send the next finished request to the current sync:
		case deliverReqCh <- deliverReq:
			// Shift out the first request, but also set the emptied slot to nil for GC
			copy(finished, finished[1:])
			finished[len(finished)-1] = nil
			finished = finished[:len(finished)-1]
		}
	}
}

// stateSync schedules requests for downloading a particular state trie defined
// by a given state root.
type stateSync struct {
	h *handler // Downloader instance to access and manage current peerset

	root   common.Hash        // State root currently being synced
	sched  *trie.Sync         // State trie sync scheduler defining the tasks
	keccak crypto.KeccakState // Keccak256 hasher to verify deliveries with

	trieTasks map[common.Hash]*trieTask // Set of trie node tasks currently queued for retrieval
	codeTasks map[common.Hash]*codeTask // Set of byte code tasks currently queued for retrieval

	numUncommitted   int
	bytesUncommitted int

	started chan struct{} // Started is signalled once the sync loop starts

	deliver    chan *stateReq // Delivery channel multiplexing peer responses
	cancel     chan struct{}  // Channel to signal a termination request
	cancelOnce sync.Once      // Ensures cancel only ever gets called once
	done       chan struct{}  // Channel to signal termination completion
	err        error          // Any error hit during sync (set before completion)
}

// trieTask represents a single trie node download task, containing a set of
// peers already attempted retrieval from to detect stalled syncs and abort.
type trieTask struct {
	path     [][]byte
	attempts map[string]struct{}
}

// codeTask represents a single byte code download task, containing a set of
// peers already attempted retrieval from to detect stalled syncs and abort.
type codeTask struct {
	attempts map[string]struct{}
}

// newStateSync creates a new state trie download scheduler. This method does not
// yet start the sync. The user needs to call run to initiate.
func newStateSync(h *handler, root common.Hash) *stateSync {
	return &stateSync{
		h:         h,
		root:      root,
		sched:     state.NewStateSync(root, h.stateDB, h.stateBloom, nil),
		keccak:    sha3.NewLegacyKeccak256().(crypto.KeccakState),
		trieTasks: make(map[common.Hash]*trieTask),
		codeTasks: make(map[common.Hash]*codeTask),
		deliver:   make(chan *stateReq),
		cancel:    make(chan struct{}),
		done:      make(chan struct{}),
		started:   make(chan struct{}),
	}
}

// run starts the task assignment and response processing loop, blocking until
// it finishes, and finally notifying any goroutines waiting for the loop to
// finish.
func (s *stateSync) run() {
	close(s.started)
	s.err = s.h.snapSyncer.Sync(s.root, s.cancel)
	close(s.done)
}

// Wait blocks until the sync is done or canceled.
func (s *stateSync) Wait() error {
	<-s.done
	return s.err
}

// Cancel cancels the sync and waits until it has shut down.
func (s *stateSync) Cancel() error {
	s.cancelOnce.Do(func() {
		close(s.cancel)
	})
	return s.Wait()
}

// updateStats bumps the various state sync progress counters and displays a log
// message for the user to see.
func (s *stateSync) updateStats(written, duplicate, unexpected int, duration time.Duration) {
	s.h.syncStatsLock.Lock()
	defer s.h.syncStatsLock.Unlock()

	s.h.syncStatsState.pending = uint64(s.sched.Pending())
	s.h.syncStatsState.processed += uint64(written)
	s.h.syncStatsState.duplicate += uint64(duplicate)
	s.h.syncStatsState.unexpected += uint64(unexpected)

	if written > 0 || duplicate > 0 || unexpected > 0 {
		s.h.logger.Info("Imported new state entries", "count", written, "elapsed", common.PrettyDuration(duration), "processed", s.h.syncStatsState.processed, "pending", s.h.syncStatsState.pending, "trieretry", len(s.trieTasks), "coderetry", len(s.codeTasks), "duplicate", s.h.syncStatsState.duplicate, "unexpected", s.h.syncStatsState.unexpected)
	}
	if written > 0 {
		rawdb.WriteFastTrieProgress(s.h.stateDB, s.h.syncStatsState.processed)
	}
}
