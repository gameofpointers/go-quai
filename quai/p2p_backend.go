package quai

import (
	"context"
	"math/big"

	"github.com/dominant-strategies/go-quai/common"
	"github.com/dominant-strategies/go-quai/core"
	"github.com/dominant-strategies/go-quai/core/types"
	"github.com/dominant-strategies/go-quai/internal/quaiapi"
	"github.com/dominant-strategies/go-quai/log"
	"github.com/dominant-strategies/go-quai/p2p"
	"github.com/dominant-strategies/go-quai/rpc"
	"github.com/dominant-strategies/go-quai/trie"
	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/libp2p/go-libp2p/core/peer"
)

// QuaiBackend implements the quai consensus protocol
type QuaiBackend struct {
	p2pBackend        NetworkingAPI // Interface for all the P2P methods the libp2p exposes to consensus
	primeApiBackend   *quaiapi.Backend
	regionApiBackends []*quaiapi.Backend
	zoneApiBackends   [][]*quaiapi.Backend
}

// Create a new instance of the QuaiBackend consensus service
func NewQuaiBackend() (*QuaiBackend, error) {
	zoneBackends := make([][]*quaiapi.Backend, common.MaxRegions)
	for i := 0; i < common.MaxRegions; i++ {
		zoneBackends[i] = make([]*quaiapi.Backend, common.MaxZones)
	}
	return &QuaiBackend{regionApiBackends: make([]*quaiapi.Backend, common.MaxZones), zoneApiBackends: zoneBackends}, nil
}

// Adds the p2pBackend into the given QuaiBackend
func (qbe *QuaiBackend) SetP2PApiBackend(p2pBackend NetworkingAPI) {
	qbe.p2pBackend = p2pBackend
}

func (qbe *QuaiBackend) SetApiBackend(apiBackend *quaiapi.Backend, location common.Location) {
	switch location.Context() {
	case common.PRIME_CTX:
		qbe.SetPrimeApiBackend(apiBackend)
	case common.REGION_CTX:
		qbe.SetRegionApiBackend(apiBackend, location)
	case common.ZONE_CTX:
		qbe.SetZoneApiBackend(apiBackend, location)
	}
}

// Set the PrimeBackend into the QuaiBackend
func (qbe *QuaiBackend) SetPrimeApiBackend(primeBackend *quaiapi.Backend) {
	qbe.primeApiBackend = primeBackend
}

// Set the RegionBackend into the QuaiBackend
func (qbe *QuaiBackend) SetRegionApiBackend(regionBackend *quaiapi.Backend, location common.Location) {
	qbe.regionApiBackends[location.Region()] = regionBackend
}

// Set the ZoneBackend into the QuaiBackend
func (qbe *QuaiBackend) SetZoneApiBackend(zoneBackend *quaiapi.Backend, location common.Location) {
	qbe.zoneApiBackends[location.Region()][location.Zone()] = zoneBackend
}

func (qbe *QuaiBackend) GetBackend(location common.Location) *quaiapi.Backend {
	switch location.Context() {
	case common.PRIME_CTX:
		return qbe.primeApiBackend
	case common.REGION_CTX:
		return qbe.regionApiBackends[location.Region()]
	case common.ZONE_CTX:
		return qbe.zoneApiBackends[location.Region()][location.Zone()]
	}
	return nil
}

// Handle consensus data propagated to us from our peers
func (qbe *QuaiBackend) OnNewBroadcast(sourcePeer p2p.PeerID, topic string, data interface{}, nodeLocation common.Location) bool {
	switch data := data.(type) {
	case types.WorkObject:
		backend := *qbe.GetBackend(nodeLocation)
		if backend == nil {
			log.Global.Error("no backend found")
			return false
		}
		// TODO: Verify the Block before writing it
		// TODO: Determine if the block information was lively or stale and rate
		// the peer accordingly

		// HANDLER ETH CHANGES
		// 		// Do not handle any broadcast until we finish resetting from the bad state.
		// // This should be a very small time window
		// if h.Core().BadHashExistsInChain() {
		// 	log.Warn("Bad Hashes still exist on chain, cannot handle block broadcast yet")
		// 	return nil
		// }
		//
		// syncEntropy, threshold := h.core.SyncTargetEntropy()
		// window := new(big.Int).Mul(threshold, big.NewInt(5))
		// syncThreshold := new(big.Int).Add(block.ParentEntropy(), window)
		// requestBlock := h.subSyncQueue.Contains(block.Hash())
		// beyondSyncPoint := syncEntropy.Cmp(syncThreshold) < 0
		// looseSyncEntropyDelta := new(big.Int).Div(syncEntropy, big.NewInt(100))
		// looseSyncEntropy := new(big.Int).Sub(syncEntropy, looseSyncEntropyDelta)
		// atFray := looseSyncEntropy.Cmp(h.core.CurrentHeader().ParentEntropy()) < 0
		//
		// // If block is greater than sync entropy, or its manifest cache, handle it
		// // If block if its in manifest cache, relay is set to true, set relay to false and handle
		// // !atFray checked because when "synced" we want to be able to check entropy against later window
		// log.Debug("Handle Block", "requestBlock", requestBlock, "atFray", atFray, "relay", relay, "beyondSync", beyondSyncPoint)
		// if relay && !atFray {
		// 	if !beyondSyncPoint {
		// 		if !requestBlock {
		// 			// drop peer
		// 			if common.NodeLocation.Context() != common.PRIME_CTX {
		// 				log.Info("Peer broadcasting block not in requestQueue or beyond sync target, dropping peer")
		// 				h.downloader.DropPeer(peer)
		// 			}
		// 			return nil
		// 		} else {
		// 			relay = false
		// 		}
		// 	}
		// }
		////  FETCHER CHANGES
		// 		powhash, err := f.verifySeal(block.Header())
		// if err != nil {
		// 	return
		// }
		// // Check if the Block is atleast half the current difficulty in Zone Context,
		// // this makes sure that the nodes don't listen to the forks with the PowHash
		// //	with less than 50% of current difficulty
		// if nodeCtx == common.ZONE_CTX && new(big.Int).SetBytes(powhash.Bytes()).Cmp(new(big.Int).Div(f.currentDifficulty(), big.NewInt(2))) < 0 {
		// 	return
		// }
		//
		// currentIntrinsicS := f.currentIntrinsicS()
		// MaxAllowableEntropyDist := new(big.Int).Mul(currentIntrinsicS, big.NewInt(c_maxAllowableEntropyDist))
		// looseMaxAllowableEntropy := new(big.Int).Div(MaxAllowableEntropyDist, big.NewInt(100))
		// looseSyncEntropyDist := new(big.Int).Add(MaxAllowableEntropyDist, looseMaxAllowableEntropy)
		//
		// broadCastEntropy := block.ParentEntropy()
		//
		// // If someone is mining not within MaxAllowableEntropyDist*currentIntrinsicS dont broadcast
		// if relay && f.currentS().Cmp(new(big.Int).Add(broadCastEntropy, MaxAllowableEntropyDist)) > 0 {
		// 	return
		// }
		// // But don't drop the peers if within 1% of that distance
		// if relay && f.currentS().Cmp(new(big.Int).Add(broadCastEntropy, looseSyncEntropyDist)) > 0 {
		// 	if nodeCtx != common.PRIME_CTX {
		// 		f.dropPeer(peer)
		// 	}
		// 	return
		// }
		//
		// // Run the import on a new thread
		// log.Debug("Importing propagated block", "peer", peer, "number", block.Number(), "hash", hash)
		// go func() {
		// 	defer func() { f.done <- hash }()
		//
		// 	// If Block broadcasted by the peer exists in the bad block list drop the peer
		// 	if f.isBlockHashABadHash(block.Hash()) {
		// 		f.dropPeer(peer)
		// 		return
		// 	}
		// 	// Quickly validate the header and propagate the block if it passes
		// 	err := f.verifyHeader(block.Header())
		//
		// 	// Including the ErrUnknownAncestor as well because a filter has already
		// 	// been applied for all the blocks that come until here. Since there
		// 	// exists a timedCache where the blocks expire, it is okay to let this
		// 	// block through and broadcast the block.
		// 	if err == nil || err.Error() == consensus.ErrUnknownAncestor.Error() {
		// 		// All ok, quickly propagate to our peers
		// 		blockBroadcastOutTimer.UpdateSince(block.ReceivedAt)
		//
		// 		// Only relay the Mined Blocks that meet the depth criteria
		// 		if relay {
		// 			go f.broadcastBlock(block, true)
		// 		}
		// 	} else if err.Error() == consensus.ErrFutureBlock.Error() {
		// 		// Weird future block, don't fail, but neither propagate
		// 	} else {
		// 		// Something went very wrong, drop the peer
		// 		log.Debug("Propagated block verification failed", "peer", peer, "number", block.Number(), "hash", hash, "err", err)
		// 		f.dropPeer(peer)
		// 		return
		// 	}
		backend.WriteBlock(&data)
		// If it was a good broadcast, mark the peer as lively
		qbe.p2pBackend.MarkLivelyPeer(sourcePeer, topic)
	case types.WorkObjectHeaderView:
		backend := *qbe.GetBackend(nodeLocation)
		if backend == nil {
			log.Global.Error("no backend found")
			return false
		}
		// Only append this in the case of the slice
		if !backend.ProcessingState() && backend.NodeCtx() == common.ZONE_CTX {
			backend.WriteBlock(data.ConvertToBlockView().WorkObject)
		}
		// If it was a good broadcast, mark the peer as lively
		qbe.p2pBackend.MarkLivelyPeer(sourcePeer, topic)
	case types.Transactions:
		backend := *qbe.GetBackend(nodeLocation)
		if backend == nil {
			log.Global.Error("no backend found")
			return false
		}
		if backend.ProcessingState() {
			backend.SendRemoteTxs(data)
		}
		// TODO: Handle the error here and mark the peers accordingly
	case types.WorkObjectHeader:
		backend := *qbe.GetBackend(nodeLocation)
		if backend == nil {
			log.Global.Error("no backend found")
			return false
		}
		backend.SendWorkShare(&data)
		// If it was a good broadcast, mark the peer as lively
		qbe.p2pBackend.MarkLivelyPeer(sourcePeer, topic)
	default:
		log.Global.WithFields(log.Fields{
			"peer":     sourcePeer,
			"topic":    topic,
			"location": nodeLocation,
		}).Error("received unknown broadcast")
		qbe.p2pBackend.BanPeer(sourcePeer)
		return false
	}
	return true
}

// GetTrieNode returns the TrieNodeResponse for a given hash
func (qbe *QuaiBackend) GetTrieNode(hash common.Hash, location common.Location) *trie.TrieNodeResponse {
	// Example/mock implementation
	panic("todo")
}

// Returns the current block height for the given location
func (qbe *QuaiBackend) GetHeight(location common.Location) uint64 {
	// Example/mock implementation
	panic("todo")
}

func (qbe *QuaiBackend) ValidatorFunc() func(ctx context.Context, id p2p.PeerID, msg *pubsub.Message) pubsub.ValidationResult {
	return func(ctx context.Context, id peer.ID, msg *pubsub.Message) pubsub.ValidationResult {
		var data interface{}
		data = msg.Message.GetData()
		switch data := data.(type) {
		case types.WorkObject:
			backend := *qbe.GetBackend(data.Location())
			if backend == nil {
				log.Global.WithFields(log.Fields{
					"peer":     id,
					"hash":     data.Hash(),
					"location": data.Location(),
				}).Error("no backend found for this location")
				return pubsub.ValidationReject
			}
		case types.Transaction:
			return pubsub.ValidationAccept
		}
		return pubsub.ValidationAccept
	}
}

// SetCurrentExpansionNumber sets the expansion number into the slice object on all the backends
func (qbe *QuaiBackend) SetCurrentExpansionNumber(expansionNumber uint8) {
	primeBackend := qbe.GetBackend(common.Location{})
	if primeBackend == nil {
		log.Global.Error("no backend found")
		return
	}
	backend := *primeBackend
	backend.SetCurrentExpansionNumber(expansionNumber)

	for i := 0; i < common.MaxRegions; i++ {
		regionBackend := qbe.GetBackend(common.Location{byte(i)})
		if regionBackend != nil {
			backend := *regionBackend
			backend.SetCurrentExpansionNumber(expansionNumber)
		}
	}

	for i := 0; i < common.MaxRegions; i++ {
		for j := 0; j < common.MaxZones; j++ {
			zoneBackend := qbe.GetBackend(common.Location{byte(i), byte(j)})
			if zoneBackend != nil {
				backend := *zoneBackend
				backend.SetCurrentExpansionNumber(expansionNumber)
			}
		}
	}
}

// WriteGenesisBlock adds the genesis block to the database and also writes the block to the disk
func (qbe *QuaiBackend) WriteGenesisBlock(block *types.WorkObject, location common.Location) {
	backend := *qbe.GetBackend(location)
	if backend == nil {
		log.Global.Error("no backend found")
		return
	}
	backend.WriteGenesisBlock(block, location)
}

// SetSubInterface sets the sub interface for the given subLocation
func (qbe *QuaiBackend) SetSubInterface(subInterface core.CoreBackend, nodeLocation common.Location, subLocation common.Location) {
	backend := *qbe.GetBackend(nodeLocation)
	if backend == nil {
		log.Global.Error("no backend found")
		return
	}
	backend.SetSubInterface(subInterface, subLocation)
}

// SetDomInterface sets the dom interface for the given location
func (qbe *QuaiBackend) SetDomInterface(domInterface core.CoreBackend, nodeLocation common.Location) {
	backend := *qbe.GetBackend(nodeLocation)
	if backend == nil {
		log.Global.Error("no backend found")
		return
	}
	backend.SetDomInterface(domInterface)
}

// AddGenesisPendingEtxs adds the genesis pending etxs for the given location
func (qbe *QuaiBackend) AddGenesisPendingEtxs(block *types.WorkObject, location common.Location) {
	backend := *qbe.GetBackend(location)
	if backend == nil {
		log.Global.Error("no backend found")
		return
	}
	backend.AddGenesisPendingEtxs(block)
}

func (qbe *QuaiBackend) LookupBlock(hash common.Hash, location common.Location) *types.WorkObject {
	if qbe == nil {
		return nil
	}
	backend := *qbe.GetBackend(location)
	if backend == nil {
		log.Global.Error("no backend found")
		return nil
	}
	return backend.BlockOrCandidateByHash(hash)
}

func (qbe *QuaiBackend) LookupBlockHashByNumber(number *big.Int, location common.Location) *common.Hash {
	backend := *qbe.GetBackend(location)
	if backend == nil {
		log.Global.Error("no backend found")
		return nil
	}
	block, err := backend.BlockByNumber(context.Background(), rpc.BlockNumber(number.Int64()))
	if err != nil {
		log.Global.Trace("Error looking up the BlockByNumber", location)
	}
	if block != nil {
		blockHash := block.Hash()
		return &blockHash
	} else {
		return nil
	}
}

func (qbe *QuaiBackend) ProcessingState(location common.Location) bool {
	backend := *qbe.GetBackend(location)
	if backend == nil {
		log.Global.Error("no backend found")
		return false
	}
	return backend.ProcessingState()
}
