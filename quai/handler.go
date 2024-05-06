package quai

import (
	"math/big"
	"runtime/debug"
	"sync"
	"time"

	"github.com/dominant-strategies/go-quai/common"
	"github.com/dominant-strategies/go-quai/core"
	"github.com/dominant-strategies/go-quai/core/types"
	"github.com/dominant-strategies/go-quai/ethdb"
	"github.com/dominant-strategies/go-quai/event"
	"github.com/dominant-strategies/go-quai/log"
	"github.com/dominant-strategies/go-quai/quai/snap"
	"github.com/dominant-strategies/go-quai/trie"
	lru "github.com/hnlq715/golang-lru"
)

const (
	// c_missingBlockChanSize is the size of channel listening to the MissingBlockEvent
	c_missingBlockChanSize = 60
	// c_checkNextPrimeBlockInterval is the interval for checking the next Block in Prime
	c_checkNextPrimeBlockInterval = 60 * time.Second
	// c_txsChanSize is the size of channel listening to the new txs event
	c_newTxsChanSize = 100
	// c_recentBlockReqCache is the size of the cache for the recent block requests
	c_recentBlockReqCache = 1000
	// c_recentBlockReqTimeout is the timeout for the recent block requests cache
	c_recentBlockReqTimeout = 1 * time.Minute
)

// handler manages the fetch requests from the core and tx pool also takes care of the tx broadcast
type handler struct {
	nodeLocation    common.Location
	p2pBackend      NetworkingAPI
	core            *core.Core
	missingBlockCh  chan types.BlockRequest
	missingBlockSub event.Subscription
	txsCh           chan core.NewTxsEvent
	txsSub          event.Subscription
	wg              sync.WaitGroup
	quitCh          chan struct{}

	recentBlockReqCache *lru.Cache // cache the latest requests on a 1 min timer

	logger *log.Logger

	// snapsync fields
	snapSync       bool
	stateDB        ethdb.Database  // Database to state sync into (and deduplicate via)
	stateBloom     *trie.SyncBloom // Bloom filter for fast trie node and contract code existence checks
	snapSyncer     *snap.Syncer
	stateSyncStart chan *stateSync
	syncStatsState stateSyncStats
	syncStatsLock  sync.RWMutex // Lock protecting the sync stats fields

}

func newHandler(p2pBackend NetworkingAPI, core *core.Core, nodeLocation common.Location, db *ethdb.Database, logger *log.Logger) *handler {
	handler := &handler{
		nodeLocation: nodeLocation,
		p2pBackend:   p2pBackend,
		core:         core,
		quitCh:       make(chan struct{}),
		logger:       logger,
		snapSyncer:   snap.NewSyncer(*db, p2pBackend, logger, nodeLocation),
	}
	handler.recentBlockReqCache, _ = lru.NewWithExpire(c_recentBlockReqCache, c_recentBlockReqTimeout)

	return handler
}

func (h *handler) Start() {
	h.wg.Add(1)
	h.missingBlockCh = make(chan types.BlockRequest, c_missingBlockChanSize)
	h.missingBlockSub = h.core.SubscribeMissingBlockEvent(h.missingBlockCh)
	go h.missingBlockLoop()

	nodeCtx := h.nodeLocation.Context()
	if nodeCtx == common.ZONE_CTX && h.core.ProcessingState() {
		h.wg.Add(1)
		h.txsCh = make(chan core.NewTxsEvent, c_newTxsChanSize)
		h.txsSub = h.core.SubscribeNewTxsEvent(h.txsCh)
		go h.txBroadcastLoop()
	}

	if nodeCtx == common.PRIME_CTX {
		h.wg.Add(1)
		go h.checkNextPrimeBlock()
	}

	go h.stateFetcher()
}

func (h *handler) Stop() {
	h.missingBlockSub.Unsubscribe() // quits missingBlockLoop
	nodeCtx := h.nodeLocation.Context()
	if nodeCtx == common.ZONE_CTX && h.core.ProcessingState() {
		h.txsSub.Unsubscribe() // quits the txBroadcastLoop
	}
	close(h.quitCh)
	h.wg.Wait()
}

// missingBlockLoop announces new pendingEtxs to connected peers.
func (h *handler) missingBlockLoop() {
	defer h.wg.Done()
	defer func() {
		if r := recover(); r != nil {
			h.logger.WithFields(log.Fields{
				"error":      r,
				"stacktrace": string(debug.Stack()),
			}).Fatal("Go-Quai Panicked")
		}
	}()
	for {
		select {
		case blockRequest := <-h.missingBlockCh:

			_, exists := h.recentBlockReqCache.Get(blockRequest.Hash)
			if !exists {
				// Add the block request to the cache to avoid requesting the same block multiple times
				h.recentBlockReqCache.Add(blockRequest.Hash, true)
			} else {
				// Don't ask for the same block multiple times within a min window
				continue
			}

			go func() {
				defer func() {
					if r := recover(); r != nil {
						h.logger.WithFields(log.Fields{
							"error":      r,
							"stacktrace": string(debug.Stack()),
						}).Fatal("Go-Quai Panicked")
					}
				}()
				resultCh := h.p2pBackend.Request(h.nodeLocation, blockRequest.Hash, &types.WorkObject{})
				block := <-resultCh
				if block != nil {
					h.core.WriteBlock(block.(*types.WorkObject))
				}
			}()
		case <-h.missingBlockSub.Err():
			return
		}
	}
}

// txBroadcastLoop announces new transactions to connected peers.
func (h *handler) txBroadcastLoop() {
	defer h.wg.Done()
	defer func() {
		if r := recover(); r != nil {
			h.logger.WithFields(log.Fields{
				"error":      r,
				"stacktrace": string(debug.Stack()),
			}).Fatal("Go-Quai Panicked")
		}
	}()
	for {
		select {
		case event := <-h.txsCh:
			for _, tx := range event.Txs {
				err := h.p2pBackend.Broadcast(h.nodeLocation, tx)
				if err != nil {
					h.logger.Error("Error broadcasting transaction hash", tx.Hash(), err)
				}
			}
		case <-h.txsSub.Err():
			return
		}
	}
}

// checkNextPrimeBlock runs every c_checkNextPrimeBlockInterval and ask the peer for the next Block
func (h *handler) checkNextPrimeBlock() {
	defer h.wg.Done()
	defer func() {
		if r := recover(); r != nil {
			h.logger.WithFields(log.Fields{
				"error":      r,
				"stacktrace": string(debug.Stack()),
			}).Fatal("Go-Quai Panicked")
		}
	}()
	checkNextPrimeBlockTimer := time.NewTicker(c_checkNextPrimeBlockInterval)
	defer checkNextPrimeBlockTimer.Stop()
	for {
		select {
		case <-checkNextPrimeBlockTimer.C:
			currentHeight := h.core.CurrentHeader().Number(h.nodeLocation.Context())
			// Try to fetch the next 3 blocks
			h.GetNextPrimeBlock(currentHeight)
			h.GetNextPrimeBlock(new(big.Int).Add(currentHeight, big.NewInt(1)))
			h.GetNextPrimeBlock(new(big.Int).Add(currentHeight, big.NewInt(2)))
		case <-h.quitCh:
			return
		}
	}
}

func (h *handler) GetNextPrimeBlock(number *big.Int) {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				h.logger.WithFields(log.Fields{
					"error":      r,
					"stacktrace": string(debug.Stack()),
				}).Fatal("Go-Quai Panicked")
			}
		}()
		resultCh := h.p2pBackend.Request(h.nodeLocation, new(big.Int).Add(number, big.NewInt(1)), common.Hash{})
		data := <-resultCh
		// If we find a new hash for the requested block number we can check
		// first if we already have the block in the database otherwise ask the
		// peers for it
		if data != nil {
			blockHash, ok := data.(common.Hash)
			if ok {
				block := h.core.GetBlockByHash(blockHash)
				// If the blockHash for the asked number is not present in the
				// appended database we ask the peer for the block with this hash
				if block == nil {
					resultCh := h.p2pBackend.Request(h.nodeLocation, blockHash, &types.WorkObject{})
					block := <-resultCh
					if block != nil {
						h.core.WriteBlock(block.(*types.WorkObject))
					}
				}
			}
		}
	}()
}
