package quai

import (
	"sync"

	"github.com/dominant-strategies/go-quai/common"
	"github.com/dominant-strategies/go-quai/core"
	"github.com/dominant-strategies/go-quai/core/types"
	"github.com/dominant-strategies/go-quai/event"
	"github.com/dominant-strategies/go-quai/log"
	"math/big"
	"time"
)

const (
	// c_missingBlockChanSize is the size of channel listening to the MissingBlockEvent
	c_missingBlockChanSize = 60
	// c_txsChanSize is the size of channel listening to the new txs event
	c_newTxsChanSize = 100
	// c_checkNextBlockInterval is the interval for checking the next Block in Prime
	c_checkNextBlockInterval = 10 * time.Second
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
}

func newHandler(p2pBackend NetworkingAPI, core *core.Core, nodeLocation common.Location) *handler {
	handler := &handler{
		nodeLocation: nodeLocation,
		p2pBackend:   p2pBackend,
		core:         core,
		quitCh:       make(chan struct{}),
	}
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
		go h.checkNextBlock()
	}
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
	for {
		select {
		case blockRequest := <-h.missingBlockCh:
			log.Global.Infof("Requesting block by hash %s", blockRequest.Hash)
			go func() {
				resultCh := h.p2pBackend.Request(h.nodeLocation, blockRequest.Hash, &types.Block{})
				block := <-resultCh
				if block != nil {
					log.Global.Infof("Block found %s", block)
					h.core.WriteBlock(block.(*types.Block))
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
	for {
		select {
		case event := <-h.txsCh:
			for _, tx := range event.Txs {
				err := h.p2pBackend.Broadcast(h.nodeLocation, tx)
				if err != nil {
					log.Global.Error("Error broadcasting transaction hash", tx.Hash())
				}
			}
		case <-h.txsSub.Err():
			return
		}
	}
}

// checkNextBlock runs every c_checkNextBlockInterval and ask the peer for the next Block
func (h *handler) checkNextBlock() {
	defer h.wg.Done()
	checkNextBlockTimer := time.NewTicker(c_checkNextBlockInterval)
	defer checkNextBlockTimer.Stop()
	for {
		select {
		case <-checkNextBlockTimer.C:
			currentHeight := h.core.CurrentHeader().Number(h.nodeLocation.Context())
			log.Global.Warn("Prime Height is", currentHeight)
			go func() {
				resultCh := h.p2pBackend.Request(h.nodeLocation, new(big.Int).Add(currentHeight, big.NewInt(1)), common.Hash{})
				data := <-resultCh
				if data != nil {
					blockHash, ok := data.(common.Hash)
					log.Global.Warn("Prime Height is", currentHeight)
					if ok {
						block := h.core.GetBlockByHash(blockHash)
						if block != nil {
							go func() {
								resultCh := h.p2pBackend.Request(h.nodeLocation, blockHash, &types.Block{})
								block := <-resultCh
								if block != nil {
									log.Global.Warn("Got Next Block is", currentHeight)
									h.core.WriteBlock(block.(*types.Block))
								}
							}()
						}
					}
				}
			}()
		case <-h.quitCh:
			return
		}
	}
}
