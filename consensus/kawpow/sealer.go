// Copyright 2017 The go-ethereum Authors
// This file is part of the go-ethereum library.

package kawpow

import (
	"context"
	crand "crypto/rand"
	"errors"
	"math"
	"math/big"
	"math/rand"
	"runtime"
	"sync"
	"time"

	"github.com/dominant-strategies/go-quai/common"
	"github.com/dominant-strategies/go-quai/consensus"
	"github.com/dominant-strategies/go-quai/core/types"
	"github.com/dominant-strategies/go-quai/log"
)

var (
	errNoMiningWork      = errors.New("no mining work available yet")
	errInvalidSealResult = errors.New("invalid or stale proof-of-work solution")
)

// Seal implements consensus.Engine, attempting to find a nonce that satisfies
// the block's difficulty requirements.
func (kawpow *Kawpow) Seal(header *types.WorkObject, results chan<- *types.WorkObject, stop <-chan struct{}) error {
	// If we're running a fake PoW, simply return a 0 nonce immediately
	if kawpow.config.PowMode == ModeFake || kawpow.config.PowMode == ModeFullFake {
		select {
		case results <- header:
		default:
			kawpow.logger.Warn("Sealing result is not read by miner", "mode", "fake", "sealhash", header.SealHash())
		}
		return nil
	}
	// If we're running a shared PoW, delegate sealing to it
	if kawpow.shared != nil {
		return kawpow.shared.Seal(header, results, stop)
	}
	// Create a runner and the multiple search threads it directs
	abort := make(chan struct{})

	kawpow.lock.Lock()
	threads := kawpow.threads
	if kawpow.rand == nil {
		seed, err := crand.Int(crand.Reader, big.NewInt(math.MaxInt64))
		if err != nil {
			kawpow.lock.Unlock()
			return err
		}
		kawpow.rand = rand.New(rand.NewSource(seed.Int64()))
	}
	kawpow.lock.Unlock()
	if threads == 0 {
		threads = runtime.NumCPU()
	}
	if threads < 0 {
		threads = 0 // Allows disabling local mining without extra logic around local/remote
	}
	// Push new work to remote sealer
	if kawpow.remote != nil {
		kawpow.remote.workCh <- &sealWork{errc: make(chan error, 1), res: results}
	}
	var (
		pend   sync.WaitGroup
		locals = make(chan *types.WorkObject)
	)
	for i := 0; i < threads; i++ {
		pend.Add(1)
		go func(id int, nonce uint64) {
			defer pend.Done()
			kawpow.mine(header, id, nonce, abort, locals)
		}(i, uint64(kawpow.rand.Int63()))
	}
	// Wait until sealing is terminated or a nonce is found
	go func() {
		var result *types.WorkObject
		select {
		case <-stop:
			// Outside abort, stop all miner threads
			close(abort)
		case result = <-locals:
			// One of the threads found a block, abort all others
			select {
			case results <- result:
			default:
				kawpow.logger.Warn("Sealing result is not read by miner", "mode", "local", "sealhash", result.SealHash())
			}
			close(abort)
		case <-kawpow.update:
			// Thread count was changed on user request, restart
			close(abort)
			if err := kawpow.Seal(header, results, stop); err != nil {
				kawpow.logger.Error("Failed to restart sealing after update", "err", err)
			}
		}
		// Wait for all miners to terminate and return the block
		pend.Wait()
	}()
	return nil
}

// mine is the actual proof-of-work miner that searches for a nonce starting from
// seed that results in correct final block difficulty.
func (kawpow *Kawpow) mine(header *types.WorkObject, id int, seed uint64, abort <-chan struct{}, found chan *types.WorkObject) {
	// Extract some data from the header
	var (
		target    = new(big.Int).Div(common.Big2e256, header.Difficulty())
		number    = header.NumberU64()
		hash      = header.SealHash().Bytes()
		nonce     = seed
		powBuffer = new(big.Int)
	)
	// Start generating random nonces until we abort or find a good one
	var (
		attempts  = int64(0)
		nonces    = make([]uint64, 1)
		powHashes = make([]common.Hash, 1)
	)
search:
	for {
		select {
		case <-abort:
			// Mining terminated, update stats and abort
			kawpow.logger.Trace("Kawpow nonce search aborted", "attempts", nonces)
			break search

		default:
			// We don't have to update hash rate on every nonce, so update after 2^X nonces
			attempts++
			if (attempts % (1 << 15)) == 0 {
				kawpow.logger.Trace("Kawpow nonce search", "attempts", attempts, "nonce", nonce)
			}
			// Compute the PoW value of this nonce
			nonces[0], powHashes[0] = nonce, kawpow.ComputePowLight(header.WorkObjectHeader())
			powBuffer.SetBytes(powHashes[0].Bytes())
			if powBuffer.Cmp(target) <= 0 {
				// Correct nonce found, create a new header with it
				headerCopy := types.CopyWorkObject(header)
				headerCopy.WorkObjectHeader().SetNonce(types.EncodeNonce(nonce))
				headerCopy.WorkObjectHeader().SetMixHash(powHashes[0])

				// Seal and return a block (if still needed)
				select {
				case found <- headerCopy:
					kawpow.logger.Trace("Kawpow nonce found and reported", "attempts", attempts, "nonce", nonce)
				case <-abort:
					kawpow.logger.Trace("Kawpow nonce found but discarded", "attempts", attempts, "nonce", nonce)
				}
				break search
			}
			nonce++
		}
	}
}

// Mine is the actual proof-of-work miner that searches for a nonce starting from
// seed that results in correct final block difficulty.
func (kawpow *Kawpow) Mine(workObject *types.WorkObject, abort <-chan struct{}, found chan *types.WorkObject) {
	kawpow.MineToThreshold(workObject, 0, abort, found)
}

// MineToThreshold allows for customization of the difficulty threshold.
func (kawpow *Kawpow) MineToThreshold(workObject *types.WorkObject, threshold int, abort <-chan struct{}, found chan *types.WorkObject) {
	var (
		target = new(big.Int).Div(common.Big2e256, workObject.Difficulty())
		number = workObject.NumberU64()
		hash   = workObject.SealHash().Bytes()
	)

	if threshold > 0 {
		workShareTarget := consensus.CalcWorkShareThreshold(workObject.WorkObjectHeader(), threshold)
		if workShareTarget != nil {
			target = workShareTarget
		}
	}

	kawpow.lock.Lock()
	threads := kawpow.threads
	if kawpow.rand == nil {
		seed, err := crand.Int(crand.Reader, big.NewInt(math.MaxInt64))
		if err != nil {
			kawpow.lock.Unlock()
			return
		}
		kawpow.rand = rand.New(rand.NewSource(seed.Int64()))
	}
	kawpow.lock.Unlock()

	if threads == 0 {
		threads = runtime.NumCPU()
	}
	if threads < 0 {
		threads = 0
	}

	var (
		pend   sync.WaitGroup
		locals = make(chan *types.WorkObject)
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	for i := 0; i < threads; i++ {
		pend.Add(1)
		go func(id int, nonce uint64) {
			defer pend.Done()
			kawpow.mineToThreshold(workObject, target, id, nonce, ctx, locals)
		}(i, uint64(kawpow.rand.Int63()))
	}

	go func() {
		var result *types.WorkObject
		select {
		case <-abort:
			cancel()
		case result = <-locals:
			select {
			case found <- result:
			default:
				kawpow.logger.Warn("Mining result not read", "sealhash", result.SealHash())
			}
			cancel()
		}
		pend.Wait()
	}()
}

// mineToThreshold is the actual mining loop with threshold support
func (kawpow *Kawpow) mineToThreshold(workObject *types.WorkObject, target *big.Int, id int, seed uint64, ctx context.Context, found chan *types.WorkObject) {
	var (
		nonce     = seed
		powBuffer = new(big.Int)
		attempts  = int64(0)
	)

search:
	for {
		select {
		case <-ctx.Done():
			kawpow.logger.Trace("Kawpow mining aborted", "attempts", attempts)
			break search

		default:
			attempts++
			if (attempts % (1 << 15)) == 0 {
				kawpow.logger.Trace("Kawpow mining progress", "attempts", attempts, "nonce", nonce)
			}

			// Compute the PoW value of this nonce
			_, powHash := kawpow.ComputePowLight(workObject.WorkObjectHeader())
			powBuffer.SetBytes(powHash.Bytes())

			if powBuffer.Cmp(target) <= 0 {
				// Correct nonce found
				headerCopy := types.CopyWorkObject(workObject)
				headerCopy.WorkObjectHeader().SetNonce(types.EncodeNonce(nonce))
				headerCopy.WorkObjectHeader().SetMixHash(powHash)

				select {
				case found <- headerCopy:
					kawpow.logger.Trace("Kawpow nonce found", "attempts", attempts, "nonce", nonce)
				case <-ctx.Done():
					kawpow.logger.Trace("Kawpow nonce found but discarded", "attempts", attempts, "nonce", nonce)
				}
				break search
			}
			nonce++
		}
	}
}