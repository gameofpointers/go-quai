package progpow

import (
	"bytes"
	"context"
	crand "crypto/rand"
	"encoding/json"
	"errors"
	"math"
	"math/big"
	"math/rand"
	"net/http"
	"runtime"
	"sync"
	"time"

	"github.com/dominant-strategies/go-quai/common"
	"github.com/dominant-strategies/go-quai/common/hexutil"
	"github.com/dominant-strategies/go-quai/core/types"
)

const (
	// staleThreshold is the maximum depth of the acceptable stale but valid progpow solution.
	staleThreshold = 7
	mantBits       = 64
)

var (
	errNoMiningWork      = errors.New("no mining work available yet")
	errInvalidSealResult = errors.New("invalid or stale proof-of-work solution")
)

// Seal implements consensus.Engine, attempting to find a nonce that satisfies
// the header's difficulty requirements.
func (progpow *Progpow) Seal(header *types.Header, results chan<- *types.Header, stop <-chan struct{}) error {
	// If we're running a fake PoW, simply return a 0 nonce immediately
	if progpow.config.PowMode == ModeFake || progpow.config.PowMode == ModeFullFake {
		header.SetNonce(types.BlockNonce{})
		select {
		case results <- header:
		default:
			progpow.config.Log.Warn("Sealing result is not read by miner", "mode", "fake", "sealhash", header.SealHash())
		}
		return nil
	}
	// If we're running a shared PoW, delegate sealing to it
	if progpow.shared != nil {
		return progpow.shared.Seal(header, results, stop)
	}
	// Create a runner and the multiple search threads it directs
	abort := make(chan struct{})

	progpow.lock.Lock()
	threads := progpow.threads
	if progpow.rand == nil {
		seed, err := crand.Int(crand.Reader, big.NewInt(math.MaxInt64))
		if err != nil {
			progpow.lock.Unlock()
			return err
		}
		progpow.rand = rand.New(rand.NewSource(seed.Int64()))
	}
	progpow.lock.Unlock()
	if threads == 0 {
		threads = runtime.NumCPU()
	}
	if threads < 0 {
		threads = 0 // Allows disabling local mining without extra logic around local/remote
	}
	// Push new work to remote sealer
	if progpow.remote != nil {
		progpow.remote.workCh <- &sealTask{header: header, results: results}
	}
	var (
		pend   sync.WaitGroup
		locals = make(chan *types.Header)
	)
	for i := 0; i < threads; i++ {
		pend.Add(1)
		go func(id int, nonce uint64) {
			defer pend.Done()
			progpow.mine(header, id, nonce, abort, locals)
		}(i, uint64(progpow.rand.Int63()))
	}
	// Wait until sealing is terminated or a nonce is found
	go func() {
		var result *types.Header
		select {
		case <-stop:
			// Outside abort, stop all miner threads
			close(abort)
		case result = <-locals:
			// One of the threads found a block, abort all others
			select {
			case results <- result:
			default:
				progpow.config.Log.Warn("Sealing result is not read by miner", "mode", "local", "sealhash", header.SealHash())
			}
			close(abort)
		case <-progpow.update:
			// Thread count was changed on user request, restart
			close(abort)
			if err := progpow.Seal(header, results, stop); err != nil {
				progpow.config.Log.Error("Failed to restart sealing after update", "err", err)
			}
		}
		// Wait for all miners to terminate and return the block
		pend.Wait()
	}()
	return nil
}

// mine is the actual proof-of-work miner that searches for a nonce starting from
// seed that results in correct final block difficulty.
func (progpow *Progpow) mine(header *types.Header, id int, seed uint64, abort chan struct{}, found chan *types.Header) {
	// Extract some data from the header
	var (
		target = new(big.Int).Div(big2e256, header.Difficulty())
	)
	// Start generating random nonces until we abort or find a good one
	var (
		attempts = int64(0)
		nonce    = seed
	)
search:
	for {
		select {
		case <-abort:
			// Mining terminated, update stats and abort
			progpow.hashrate.Mark(attempts)
			break search

		default:
			// We don't have to update hash rate on every nonce, so update after after 2^X nonces
			attempts++
			if (attempts % (1 << 15)) == 0 {
				progpow.hashrate.Mark(attempts)
				attempts = 0
			}
			powLight := func(size uint64, cache []uint32, hash []byte, nonce uint64, blockNumber uint64) ([]byte, []byte) {
				ethashCache := progpow.cache(blockNumber)
				if ethashCache.cDag == nil {
					cDag := make([]uint32, progpowCacheWords)
					generateCDag(cDag, ethashCache.cache, blockNumber/epochLength)
					ethashCache.cDag = cDag
				}
				return progpowLight(size, cache, hash, nonce, blockNumber, ethashCache.cDag)
			}
			cache := progpow.cache(header.NumberU64())
			size := datasetSize(header.NumberU64())
			// Compute the PoW value of this nonce
			digest, result := powLight(size, cache.cache, header.SealHash().Bytes(), nonce, header.NumberU64(common.ZONE_CTX))
			if new(big.Int).SetBytes(result).Cmp(target) <= 0 {
				// Correct nonce found, create a new header with it
				header = types.CopyHeader(header)
				header.SetNonce(types.EncodeNonce(nonce))
				hashBytes := common.BytesToHash(digest)
				header.SetMixHash(hashBytes)
				found <- header
				break search
			}
			nonce++
		}
	}
}

// This is the timeout for HTTP requests to notify external miners.
const remoteSealerTimeout = 1 * time.Second

type remoteSealer struct {
	works         map[common.Hash]*types.Header
	rates         map[common.Hash]hashrate
	currentHeader *types.Header
	currentWork   [4]string
	notifyCtx     context.Context
	cancelNotify  context.CancelFunc // cancels all notification requests
	reqWG         sync.WaitGroup     // tracks notification request goroutines

	progpow      *Progpow
	noverify     bool
	notifyURLs   []string
	results      chan<- *types.Header
	workCh       chan *sealTask   // Notification channel to push new work and relative result channel to remote sealer
	fetchWorkCh  chan *sealWork   // Channel used for remote sealer to fetch mining work
	submitWorkCh chan *mineResult // Channel used for remote sealer to submit their mining result
	fetchRateCh  chan chan uint64 // Channel used to gather submitted hash rate for local or remote sealer.
	submitRateCh chan *hashrate   // Channel used for remote sealer to submit their mining hashrate
	requestExit  chan struct{}
	exitCh       chan struct{}
}

// sealTask wraps a seal header with relative result channel for remote sealer thread.
type sealTask struct {
	header  *types.Header
	results chan<- *types.Header
}

// mineResult wraps the pow solution parameters for the specified block.
type mineResult struct {
	nonce types.BlockNonce
	hash  common.Hash

	errc chan error
}

// hashrate wraps the hash rate submitted by the remote sealer.
type hashrate struct {
	id   common.Hash
	ping time.Time
	rate uint64

	done chan struct{}
}

// sealWork wraps a seal work package for remote sealer.
type sealWork struct {
	errc chan error
	res  chan [4]string
}

func startRemoteSealer(progpow *Progpow, urls []string, noverify bool) *remoteSealer {
	ctx, cancel := context.WithCancel(context.Background())
	s := &remoteSealer{
		progpow:      progpow,
		noverify:     noverify,
		notifyURLs:   urls,
		notifyCtx:    ctx,
		cancelNotify: cancel,
		works:        make(map[common.Hash]*types.Header),
		rates:        make(map[common.Hash]hashrate),
		workCh:       make(chan *sealTask),
		fetchWorkCh:  make(chan *sealWork),
		submitWorkCh: make(chan *mineResult),
		fetchRateCh:  make(chan chan uint64),
		submitRateCh: make(chan *hashrate),
		requestExit:  make(chan struct{}),
		exitCh:       make(chan struct{}),
	}
	go s.loop()
	return s
}

func (s *remoteSealer) loop() {
	defer func() {
		s.progpow.config.Log.Trace("Progpow remote sealer is exiting")
		s.cancelNotify()
		s.reqWG.Wait()
		close(s.exitCh)
	}()

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case work := <-s.workCh:
			// Update current work with new received header.
			// Note same work can be past twice, happens when changing CPU threads.
			s.results = work.results
			s.makeWork(work.header)
			s.notifyWork()

		case work := <-s.fetchWorkCh:
			// Return current mining work to remote miner.
			if s.currentHeader == nil {
				work.errc <- errNoMiningWork
			} else {
				work.res <- s.currentWork
			}

		case result := <-s.submitWorkCh:
			// Verify submitted PoW solution based on maintained mining blocks.
			if s.submitWork(result.nonce, result.hash) {
				result.errc <- nil
			} else {
				result.errc <- errInvalidSealResult
			}

		case result := <-s.submitRateCh:
			// Trace remote sealer's hash rate by submitted value.
			s.rates[result.id] = hashrate{rate: result.rate, ping: time.Now()}
			close(result.done)

		case req := <-s.fetchRateCh:
			// Gather all hash rate submitted by remote sealer.
			var total uint64
			for _, rate := range s.rates {
				// this could overflow
				total += rate.rate
			}
			req <- total

		case <-ticker.C:
			// Clear stale submitted hash rate.
			for id, rate := range s.rates {
				if time.Since(rate.ping) > 10*time.Second {
					delete(s.rates, id)
				}
			}
			// Clear stale pending blocks
			if s.currentHeader != nil {
				for hash, header := range s.works {
					if header.NumberU64()+staleThreshold <= s.currentHeader.NumberU64() {
						delete(s.works, hash)
					}
				}
			}

		case <-s.requestExit:
			return
		}
	}
}

// makeWork creates a work package for external miner.
//
// The work package consists of 3 strings:
//
//	result[0], 32 bytes hex encoded current header pow-hash
//	result[1], 32 bytes hex encoded seed hash used for DAG
//	result[2], 32 bytes hex encoded boundary condition ("target"), 2^256/difficulty
//	result[3], hex encoded header number
func (s *remoteSealer) makeWork(header *types.Header) {
	hash := header.SealHash()
	s.currentWork[0] = hash.Hex()
	s.currentWork[1] = hexutil.EncodeBig(header.Number())
	s.currentWork[2] = common.BytesToHash(new(big.Int).Div(big2e256, header.Difficulty()).Bytes()).Hex()

	// Trace the seal work fetched by remote sealer.
	s.currentHeader = header
	s.works[hash] = header
}

// notifyWork notifies all the specified mining endpoints of the availability of
// new work to be processed.
func (s *remoteSealer) notifyWork() {
	work := s.currentWork

	// Encode the JSON payload of the notification. When NotifyFull is set,
	// this is the complete block header, otherwise it is a JSON array.
	var blob []byte
	if s.progpow.config.NotifyFull {
		blob, _ = json.Marshal(s.currentHeader)
	} else {
		blob, _ = json.Marshal(work)
	}

	s.reqWG.Add(len(s.notifyURLs))
	for _, url := range s.notifyURLs {
		go s.sendNotification(s.notifyCtx, url, blob, work)
	}
}

func (s *remoteSealer) sendNotification(ctx context.Context, url string, json []byte, work [4]string) {
	defer s.reqWG.Done()

	req, err := http.NewRequest("POST", url, bytes.NewReader(json))
	if err != nil {
		s.progpow.config.Log.Warn("Can't create remote miner notification", "err", err)
		return
	}
	ctx, cancel := context.WithTimeout(ctx, remoteSealerTimeout)
	defer cancel()
	req = req.WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		s.progpow.config.Log.Warn("Failed to notify remote miner", "err", err)
	} else {
		s.progpow.config.Log.Trace("Notified remote miner", "miner", url, "hash", work[0], "target", work[2])
		resp.Body.Close()
	}
}

// submitWork verifies the submitted pow solution, returning
// whether the solution was accepted or not (not can be both a bad pow as well as
// any other error, like no pending work or stale mining result).
func (s *remoteSealer) submitWork(nonce types.BlockNonce, sealhash common.Hash) bool {
	if s.currentHeader == nil {
		s.progpow.config.Log.Error("Pending work without block", "sealhash", sealhash)
		return false
	}
	// Make sure the work submitted is present
	header := s.works[sealhash]
	if header == nil {
		s.progpow.config.Log.Warn("Work submitted but none pending", "sealhash", sealhash, "curnumber", s.currentHeader.NumberU64())
		return false
	}
	// Verify the correctness of submitted result.
	header.SetNonce(nonce)

	start := time.Now()
	if !s.noverify {
		panic("submit work with verification not supported")
	}
	// Make sure the result channel is assigned.
	if s.results == nil {
		s.progpow.config.Log.Warn("Progpow result channel is empty, submitted mining result is rejected")
		return false
	}
	s.progpow.config.Log.Trace("Verified correct proof-of-work", "sealhash", sealhash, "elapsed", common.PrettyDuration(time.Since(start)))

	// Solutions seems to be valid, return to the miner and notify acceptance.
	solution := header

	// The submitted solution is within the scope of acceptance.
	if solution.NumberU64()+staleThreshold > s.currentHeader.NumberU64() {
		select {
		case s.results <- solution:
			s.progpow.config.Log.Debug("Work submitted is acceptable", "number", solution.NumberU64(), "sealhash", sealhash, "hash", solution.Hash())
			return true
		default:
			s.progpow.config.Log.Warn("Sealing result is not read by miner", "mode", "remote", "sealhash", sealhash)
			return false
		}
	}
	// The submitted block is too old to accept, drop it.
	s.progpow.config.Log.Warn("Work submitted is too old", "number", solution.NumberU64(), "sealhash", sealhash, "hash", solution.Hash())
	return false
}
