package quai

import (
	"context"
	"math/big"
	"runtime/debug"
	"sync"
	"time"

	"github.com/dominant-strategies/go-quai/common"
	"github.com/dominant-strategies/go-quai/core"
	"github.com/dominant-strategies/go-quai/core/types"
	"github.com/dominant-strategies/go-quai/event"
	"github.com/dominant-strategies/go-quai/log"
	"github.com/dominant-strategies/go-quai/metrics_config"
	"github.com/dominant-strategies/go-quai/params"
	expireLru "github.com/hashicorp/golang-lru/v2/expirable"
)

var (
	historicalSyncCounters = metrics_config.NewCounterVec("HistoricalSync", "Historical sync blocks, bytes, requests, and failures")
	historicalSyncGauges   = metrics_config.NewGaugeVec("HistoricalSyncHead", "Downloaded and processed historical sync heads")
)

const (
	// c_missingBlockChanSize is the size of channel listening to the MissingBlockEvent
	c_missingBlockChanSize = 4096
	// Historical sync responses are bounded below the stream's 3 MiB cap.
	c_syncBatchBlocks = 128
	c_syncBatchBytes  = 2 * 1024 * 1024
	c_syncWorkers     = 4
	c_syncIdlePeriod  = time.Second
	// c_recentBlockReqCache is the size of the cache for the recent block requests
	c_recentBlockReqCache = 16384
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
	wg              sync.WaitGroup
	quitCh          chan struct{}
	logger          *log.Logger

	txs types.Transactions

	recentBlockReqCache *expireLru.LRU[common.Hash, interface{}] // cache the latest requests on a 1 min timer

	ctx        context.Context
	cancelFunc context.CancelFunc
}

func newHandler(p2pBackend NetworkingAPI, core *core.Core, nodeLocation common.Location, logger *log.Logger) *handler {
	ctx, cancel := context.WithCancel(context.Background())
	handler := &handler{
		nodeLocation: nodeLocation,
		p2pBackend:   p2pBackend,
		core:         core,
		quitCh:       make(chan struct{}),
		logger:       logger,
		txs:          make(types.Transactions, 0),
		ctx:          ctx,
		cancelFunc:   cancel,
	}
	handler.recentBlockReqCache = expireLru.NewLRU[common.Hash, interface{}](c_recentBlockReqCache, nil, c_recentBlockReqTimeout)
	return handler
}

func (h *handler) Start() {
	h.missingBlockCh = make(chan types.BlockRequest, c_missingBlockChanSize)
	h.missingBlockSub = h.core.SubscribeMissingBlockEvent(h.missingBlockCh)
	for i := 0; i < c_syncWorkers; i++ {
		h.wg.Add(1)
		go h.missingBlockLoop()
	}

	nodeCtx := h.nodeLocation.Context()
	if nodeCtx == common.PRIME_CTX {
		h.wg.Add(1)
		go h.checkNextPrimeBlock()
	}
}

func (h *handler) Stop() {
	h.cancelFunc()
	h.missingBlockSub.Unsubscribe() // quits missingBlockLoop
	close(h.quitCh)
	h.wg.Wait()
	h.logger.Info("quai handler stopped")
}

// missingBlockLoop announces new pendingEtxs to connected peers.
func (h *handler) missingBlockLoop() {
	defer func() {
		if r := recover(); r != nil {
			h.logger.WithFields(log.Fields{
				"error":      r,
				"stacktrace": string(debug.Stack()),
			}).Error("Go-Quai Panicked")
		}
	}()
	defer h.wg.Done()

	for {
		select {
		case blockRequest := <-h.missingBlockCh:
			requests := []types.BlockRequest{blockRequest}
		collect:
			for len(requests) < c_syncBatchBlocks {
				select {
				case request := <-h.missingBlockCh:
					requests = append(requests, request)
				default:
					break collect
				}
			}
			h.fetchMissingBatch(requests)
		case <-h.missingBlockSub.Err():
			return
		case <-h.quitCh:
			return
		}
	}
}

func (h *handler) fetchMissingBatch(requests []types.BlockRequest) {
	unique := make(map[common.Hash]types.BlockRequest, len(requests))
	hashes := make([]common.Hash, 0, len(requests))
	for _, blockRequest := range requests {

		// If the blockRequest Hash is a bad block hash, node should not ask
		// any peer for the hash
		if h.core.IsBlockHashABadHash(blockRequest.Hash) {
			continue
		}

		// get the current header and compare the entropy of the block that
		// is getting fetched with the current header entropy
		currentHeader := h.core.CurrentHeader()

		if !blockRequest.Historical && currentHeader != nil && !h.core.IsGenesisHash(currentHeader.Hash()) && currentHeader.NumberU64(common.ZONE_CTX) > params.MaxCodeSizeForkHeight {
			currentHeaderPowHash, err := h.core.VerifySeal(currentHeader.WorkObjectHeader())
			if err != nil {
				continue
			}
			currentHeaderIntrinsic := common.IntrinsicLogEntropy(currentHeaderPowHash)
			currentS := h.core.CurrentHeader().ParentEntropy(h.core.NodeCtx())
			MaxAllowableEntropyDist := new(big.Int).Mul(currentHeaderIntrinsic, new(big.Int).SetUint64(params.MaxAllowableEntropyDist))

			// If someone is mining not within MaxAllowableEntropyDist*currentIntrinsicS dont broadcast
			if currentS.Cmp(new(big.Int).Add(blockRequest.Entropy, MaxAllowableEntropyDist)) > 0 {
				continue
			}
		}

		if _, exists := unique[blockRequest.Hash]; exists {
			continue
		}
		if _, exists := h.recentBlockReqCache.Get(blockRequest.Hash); exists {
			continue
		}
		h.recentBlockReqCache.Add(blockRequest.Hash, true)
		unique[blockRequest.Hash] = blockRequest
		hashes = append(hashes, blockRequest.Hash)
	}
	if len(hashes) == 0 {
		return
	}

	batch := &types.BlockBatchRequest{Hashes: hashes, MaxBlocks: uint32(len(hashes)), MaxBytes: c_syncBatchBytes}
	historicalSyncCounters.WithLabelValues(h.nodeLocation.Name() + "/requests").Inc()
	result := <-h.p2pBackend.Request(h.nodeLocation, batch, []*types.WorkObjectBlockView{})
	received := make(map[common.Hash]struct{}, len(hashes))
	if result != nil {
		views := result.([]*types.WorkObjectBlockView)
		blocks := make([]*types.WorkObject, 0, len(views))
		for _, view := range views {
			if view != nil && view.WorkObject != nil {
				blocks = append(blocks, view.WorkObject)
				received[view.Hash()] = struct{}{}
			}
		}
		if err := h.core.StageDownloadedBlocks(blocks); err != nil {
			h.logger.WithField("err", err).Warn("Rejected downloaded block batch")
			historicalSyncCounters.WithLabelValues(h.nodeLocation.Name() + "/failures").Inc()
		} else {
			h.recordDownloaded(blocks)
		}
	}
	for _, hash := range hashes {
		if _, ok := received[hash]; ok {
			h.recentBlockReqCache.Remove(hash)
		} else {
			// This is also the rolling-deployment fallback for peers that only
			// understand the legacy single-hash request.
			h.wg.Add(1)
			go func(request types.BlockRequest) {
				defer h.wg.Done()
				h.fetchMissingBlock(request)
			}(unique[hash])
		}
	}
}

func (h *handler) fetchMissingBlock(request types.BlockRequest) {
	defer h.recentBlockReqCache.Remove(request.Hash)
	if h.ctx.Err() != nil {
		return
	}
	if !h.core.ProcessingState() && h.nodeLocation.Context() == common.ZONE_CTX {
		result := <-h.p2pBackend.Request(h.nodeLocation, request.Hash, &types.WorkObjectHeaderView{})
		if result != nil {
			h.core.WriteBlock(result.(*types.WorkObjectHeaderView).WorkObject)
		}
		return
	}
	result := <-h.p2pBackend.Request(h.nodeLocation, request.Hash, &types.WorkObjectBlockView{})
	if result != nil {
		blocks := []*types.WorkObject{result.(*types.WorkObjectBlockView).WorkObject}
		if err := h.core.StageDownloadedBlocks(blocks); err != nil {
			h.logger.WithField("err", err).Warn("Rejected downloaded block")
			historicalSyncCounters.WithLabelValues(h.nodeLocation.Name() + "/failures").Inc()
		} else {
			h.recordDownloaded(blocks)
		}
	}
}

func (h *handler) recordDownloaded(blocks []*types.WorkObject) {
	var bytes float64
	for _, block := range blocks {
		bytes += float64(block.Size())
	}
	historicalSyncCounters.WithLabelValues(h.nodeLocation.Name() + "/blocks").Add(float64(len(blocks)))
	historicalSyncCounters.WithLabelValues(h.nodeLocation.Name() + "/bytes").Add(bytes)
	downloaded, _ := h.core.DownloadedHead()
	historicalSyncGauges.WithLabelValues(h.nodeLocation.Name() + "/downloaded").Set(float64(downloaded))
	if head := h.core.CurrentHeader(); head != nil {
		historicalSyncGauges.WithLabelValues(h.nodeLocation.Name() + "/processed").Set(float64(head.NumberU64(h.core.NodeCtx())))
	}
}

// checkNextPrimeBlock continuously downloads byte-bounded prime ranges from the
// durable downloaded head. Import/state processing advances independently.
func (h *handler) checkNextPrimeBlock() {
	defer func() {
		if r := recover(); r != nil {
			h.logger.WithFields(log.Fields{
				"error":      r,
				"stacktrace": string(debug.Stack()),
			}).Error("Go-Quai Panicked")
		}
	}()
	defer h.wg.Done()

	for {
		if h.ctx.Err() != nil {
			return
		}
		number, hash := h.core.DownloadedHead()
		request := &types.BlockBatchRequest{
			Origin:    new(big.Int).SetUint64(number + 1),
			MaxBlocks: c_syncBatchBlocks,
			MaxBytes:  c_syncBatchBytes,
		}
		historicalSyncCounters.WithLabelValues(h.nodeLocation.Name() + "/requests").Inc()
		result := <-h.p2pBackend.Request(h.nodeLocation, request, []*types.WorkObjectBlockView{})
		if result == nil {
			select {
			case <-time.After(c_syncIdlePeriod):
				continue
			case <-h.quitCh:
				return
			}
		}
		views := result.([]*types.WorkObjectBlockView)
		blocks := make([]*types.WorkObject, 0, len(views))
		for _, view := range views {
			if view != nil && view.WorkObject != nil {
				blocks = append(blocks, view.WorkObject)
			}
		}
		if len(blocks) == 0 || blocks[0].ParentHash(common.PRIME_CTX) != hash {
			h.logger.Warn("Peer returned prime range not anchored to downloaded head")
			h.core.RewindDownloadedHead()
			time.Sleep(c_syncIdlePeriod)
			continue
		}
		if err := h.core.StageDownloadedBlocks(blocks); err != nil {
			h.logger.WithField("err", err).Warn("Rejected downloaded prime range")
			historicalSyncCounters.WithLabelValues(h.nodeLocation.Name() + "/failures").Inc()
			time.Sleep(c_syncIdlePeriod)
		} else {
			h.recordDownloaded(blocks)
		}
	}
}
