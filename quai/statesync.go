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

	"github.com/dominant-strategies/go-quai/common"
	"github.com/dominant-strategies/go-quai/core/state"
	"github.com/dominant-strategies/go-quai/crypto"
	"github.com/dominant-strategies/go-quai/trie"
	"golang.org/x/crypto/sha3"
)

var (
	errCancelStateFetch = errors.New("state data download canceled (requested)")
)

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
	defer h.wg.Done()
	for {
		select {
		case s := <-h.stateSyncStart:
			if !h.snapSync {
				h.snapSync = true
				go s.run()
			}
		case <-h.quitCh:
			return
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

	started chan struct{} // Started is signalled once the sync loop starts

	cancel     chan struct{} // Channel to signal a termination request
	cancelOnce sync.Once     // Ensures cancel only ever gets called once
	done       chan struct{} // Channel to signal termination completion
	err        error         // Any error hit during sync (set before completion)
}

// newStateSync creates a new state trie download scheduler. This method does not
// yet start the sync. The user needs to call run to initiate.
func newStateSync(h *handler, root common.Hash) *stateSync {
	return &stateSync{
		h:       h,
		root:    root,
		sched:   state.NewStateSync(root, h.stateDB, h.stateBloom, nil),
		keccak:  sha3.NewLegacyKeccak256().(crypto.KeccakState),
		cancel:  make(chan struct{}),
		done:    make(chan struct{}),
		started: make(chan struct{}),
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
