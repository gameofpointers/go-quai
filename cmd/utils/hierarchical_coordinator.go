package utils

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"path/filepath"
	"runtime/debug"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/dominant-strategies/go-quai/common"
	"github.com/dominant-strategies/go-quai/common/hexutil"
	"github.com/dominant-strategies/go-quai/core"
	"github.com/dominant-strategies/go-quai/core/rawdb"
	"github.com/dominant-strategies/go-quai/core/types"
	"github.com/dominant-strategies/go-quai/event"
	"github.com/dominant-strategies/go-quai/internal/quaiapi"
	"github.com/dominant-strategies/go-quai/log"
	"github.com/dominant-strategies/go-quai/quai"
	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/spf13/viper"
	"github.com/syndtr/goleveldb/leveldb"
	"google.golang.org/protobuf/proto"
)

const (
	// c_expansionChSize is the size of the chain head channel listening to new
	// expansion events
	c_expansionChSize            = 10
	c_recentBlockCacheSize       = 1000
	c_ancestorCheckDist          = 10000
	c_chainEventChSize           = 1000
	c_buildPendingHeadersTimeout = 5 * time.Second
	c_pendingHeaderSize          = 2000
	c_pendingEventWorkers        = 2
)

var (
	c_currentExpansionNumberKey = []byte("cexp")
)

type Node struct {
	hash     common.Hash
	number   []*big.Int
	location common.Location
	entropy  *big.Int
}

type NodeSet struct {
	nodes map[string]Node
}

func (ch *Node) Empty() bool {
	return ch.hash == common.Hash{} && ch.location.Equal(common.Location{}) && ch.entropy == nil
}

type PendingHeaders struct {
	collection *lru.Cache[string, pendingHeaderEntry]
	order      []string
}

type pendingHeaderEntry struct {
	entropy *big.Int
	nodeSet NodeSet
}

type HierarchicalCoordinator struct {
	db *leveldb.DB
	// APIS
	consensus quai.ConsensusAPI
	p2p       quai.NetworkingAPI

	logLevel string

	currentExpansionNumber atomic.Uint32

	slicesRunning []common.Location

	chainSubs []event.Subscription

	recentBlocks  map[string]*lru.Cache[common.Hash, Node]
	recentBlockMu sync.RWMutex

	expansionCh  chan core.ExpansionEvent
	expansionSub event.Subscription
	wg           *sync.WaitGroup

	quitCh chan struct{}

	treeExpansionTriggerStarted bool // flag to indicate if the tree expansion trigger has started

	pendingHeaders *PendingHeaders

	bestEntropy *big.Int

	pendingMu              sync.Mutex
	headerWorkerRunning    bool
	queuedHeaderGeneration NodeSet
	hasQueuedGeneration    bool

	pendingHeaderBackupCh chan struct{}
	pendingHeaderEventCh  chan core.ChainEvent
}

func NewPendingHeaders() *PendingHeaders {
	pendingHeaders := &PendingHeaders{
		order: []string{},
	}
	pendingHeaders.collection, _ = lru.NewWithEvict[string, pendingHeaderEntry](c_pendingHeaderSize, func(key string, value pendingHeaderEntry) {
		removeFromSlice(key, pendingHeaders)
	})
	return pendingHeaders
}

func (hc *HierarchicalCoordinator) InitPendingHeaders() {
	nodeSet := NodeSet{
		nodes: make(map[string]Node),
	}

	numRegions, numZones := common.GetHierarchySizeForExpansionNumber(hc.expansionNumber())
	//Initialize for prime
	backend := hc.GetBackend(common.Location{})
	genesisBlock := backend.GetBlockByHash(backend.Config().DefaultGenesisHash)
	entropy := backend.TotalLogEntropy(genesisBlock)
	newNode := Node{
		hash:     genesisBlock.Hash(),
		number:   genesisBlock.NumberArray(),
		location: common.Location{},
		entropy:  entropy,
	}
	nodeSet.nodes[common.Location{}.Name()] = newNode

	for i := 0; i < int(numRegions); i++ {
		backend := hc.GetBackend(common.Location{byte(i)})
		entropy := backend.TotalLogEntropy(genesisBlock)
		newNode.location = common.Location{byte(i)}
		newNode.entropy = entropy
		nodeSet.nodes[common.Location{byte(i)}.Name()] = newNode
		for j := 0; j < int(numZones); j++ {
			backend := hc.GetBackend(common.Location{byte(i), byte(j)})
			entropy := backend.TotalLogEntropy(genesisBlock)
			newNode.location = common.Location{byte(i), byte(j)}
			newNode.entropy = entropy
			nodeSet.nodes[common.Location{byte(i), byte(j)}.Name()] = newNode
		}
	}
	hc.Add(new(big.Int).SetUint64(0), nodeSet, hc.pendingHeaders)
}

func (hc *HierarchicalCoordinator) Add(entropy *big.Int, node NodeSet, newPendingHeaders *PendingHeaders) {
	key := nodeSetKey(node)
	if _, exists := newPendingHeaders.collection.Peek(key); !exists {
		entry := pendingHeaderEntry{
			entropy: new(big.Int).Set(entropy),
			nodeSet: node,
		}
		newPendingHeaders.order = append(newPendingHeaders.order, key)
		newPendingHeaders.collection.Add(key, entry)
	}

	if newPendingHeaders == hc.pendingHeaders && hc.bestEntropy.Cmp(entropy) < 0 {
		hc.bestEntropy = new(big.Int).Set(entropy)
	}
}

func printNodeSet(nodeSet NodeSet) {
	for nodeName, n := range nodeSet.nodes {
		log.Global.WithFields(log.Fields{
			"hash":     n.hash,
			"number":   n.number,
			"location": n.location,
			"entropy":  common.BigBitsToBits(n.entropy),
			"node":     nodeName,
		}).Info("Node in the node set")
	}
}

func nodeSetKey(nodeSet NodeSet) string {
	locations := make([]string, 0, len(nodeSet.nodes))
	for location := range nodeSet.nodes {
		locations = append(locations, location)
	}
	sort.Strings(locations)

	key := make([]byte, 0, len(locations)*(common.HashLength+2))
	for _, location := range locations {
		key = append(key, location...)
		key = append(key, 0)
		hash := nodeSet.nodes[location].hash
		key = append(key, hash[:]...)
	}
	return string(key)
}

func removeFromSlice(keyToRemove string, pendingHeaders *PendingHeaders) {
	for i := 0; i < len(pendingHeaders.order); i++ {
		if pendingHeaders.order[i] == keyToRemove {
			pendingHeaders.order = append(pendingHeaders.order[:i], pendingHeaders.order[i+1:]...)
			return
		}
	}
}

func (ns *NodeSet) Extendable(wo *types.WorkObject, order int) bool {
	switch order {
	case common.PRIME_CTX:
		if wo.ParentHash(common.PRIME_CTX) == ns.nodes[common.Location{}.Name()].hash &&
			wo.ParentHash(common.REGION_CTX) == ns.nodes[common.Location{byte(wo.Location().Region())}.Name()].hash &&
			wo.ParentHash(common.ZONE_CTX) == ns.nodes[wo.Location().Name()].hash {
			return true
		}
	case common.REGION_CTX:
		if wo.ParentHash(common.REGION_CTX) == ns.nodes[common.Location{byte(wo.Location().Region())}.Name()].hash &&
			wo.ParentHash(common.ZONE_CTX) == ns.nodes[wo.Location().Name()].hash {
			return true
		}
	case common.ZONE_CTX:
		nodeHash := ns.nodes[wo.Location().Name()].hash
		parentHash := wo.ParentHash(common.ZONE_CTX)
		if parentHash == nodeHash {
			return true
		}
	}

	return false
}

func (ns *NodeSet) Entropy(numRegions int, numZones int) *big.Int {
	entropy := new(big.Int)

	entropy.Add(entropy, ns.nodes[common.Location{}.Name()].entropy)
	for i := 0; i < numRegions; i++ {
		entropy.Add(entropy, ns.nodes[common.Location{byte(i)}.Name()].entropy)
		for j := 0; j < numZones; j++ {
			entropy.Add(entropy, ns.nodes[common.Location{byte(i), byte(j)}.Name()].entropy)
		}
	}

	return entropy
}

func (ns *NodeSet) Update(wo *types.WorkObject, entropy *big.Int, order int) {
	newNode := Node{
		hash:     wo.Hash(),
		number:   wo.NumberArray(),
		location: common.Location{},
		entropy:  entropy,
	}
	switch order {
	case common.PRIME_CTX:
		ns.nodes[common.Location{}.Name()] = newNode
		newNode.location = common.Location{byte(wo.Location().Region())}
		ns.nodes[common.Location{byte(wo.Location().Region())}.Name()] = newNode
		newNode.location = wo.Location()
		ns.nodes[wo.Location().Name()] = newNode
	case common.REGION_CTX:
		newNode.location = common.Location{byte(wo.Location().Region())}
		ns.nodes[common.Location{byte(wo.Location().Region())}.Name()] = newNode
		newNode.location = wo.Location()
		ns.nodes[wo.Location().Name()] = newNode
	case common.ZONE_CTX:
		newNode.location = wo.Location()
		ns.nodes[wo.Location().Name()] = newNode
	}
}

func (ns *NodeSet) Copy() NodeSet {
	newNodeSet := NodeSet{
		nodes: make(map[string]Node),
	}
	for k, v := range ns.nodes {
		newNodeSet.nodes[k] = v
	}
	return newNodeSet
}

// NewHierarchicalCoordinator creates a new instance of the HierarchicalCoordinator
func NewHierarchicalCoordinator(p2p quai.NetworkingAPI, logLevel string, nodeWg *sync.WaitGroup, startingExpansionNumber uint64) *HierarchicalCoordinator {
	db, err := OpenBackendDB()
	if err != nil {
		log.Global.WithField("err", err).Fatal("Error opening the backend db")
	}
	if viper.GetBool(ReIndex.Name) {
		ReIndexChainIndexer()
	}
	if viper.GetBool(ValidateIndexer.Name) {
		ValidateChainIndexer()
	}
	hc := &HierarchicalCoordinator{
		wg:                          nodeWg,
		db:                          db,
		p2p:                         p2p,
		logLevel:                    logLevel,
		slicesRunning:               GetRunningZones(),
		treeExpansionTriggerStarted: false,
		quitCh:                      make(chan struct{}),
		recentBlocks:                make(map[string]*lru.Cache[common.Hash, Node]),
		bestEntropy:                 new(big.Int).Set(common.Big0),
		pendingHeaderBackupCh:       make(chan struct{}, 1),
		pendingHeaderEventCh:        make(chan core.ChainEvent, c_chainEventChSize),
	}
	hc.pendingHeaders = NewPendingHeaders()

	if startingExpansionNumber > common.MaxExpansionNumber {
		log.Global.Fatal("Starting expansion number is greater than the maximum expansion number")
	}

	expansionNumber := hc.readCurrentExpansionNumber()
	if expansionNumber == 0 {
		expansionNumber = startingExpansionNumber
	}
	hc.currentExpansionNumber.Store(uint32(expansionNumber))

	// Start the QuaiBackend and set the consensus backend
	backend, err := hc.StartQuaiBackend()
	if err != nil {
		log.Global.WithField("err", err).Fatal("Error starting the quai backend ")
	}
	hc.consensus = backend

	hc.InitPendingHeaders()

	return hc
}

func (hc *HierarchicalCoordinator) StartHierarchicalCoordinator() error {
	// get the prime backend
	primeApiBackend := *hc.consensus.GetBackend(common.Location{})
	if primeApiBackend == nil {
		log.Global.Fatal("prime backend not found starting the hierarchical coordinator")
	}

	// subscribe to the  chain head feed in prime
	hc.expansionCh = make(chan core.ExpansionEvent, c_expansionChSize)
	hc.expansionSub = primeApiBackend.SubscribeExpansionEvent(hc.expansionCh)

	hc.wg.Add(1)
	go hc.expansionEventLoop()

	hc.wg.Add(1)
	go hc.MapConstructProc()

	for i := 0; i < c_pendingEventWorkers; i++ {
		hc.wg.Add(1)
		go hc.pendingHeaderEventLoop()
	}

	numRegions, numZones := common.GetHierarchySizeForExpansionNumber(hc.expansionNumber())

	backend := *hc.consensus.GetBackend(common.Location{})
	chainEventCh := make(chan core.ChainEvent, c_chainEventChSize)
	chainSub := backend.SubscribeChainEventForHC(chainEventCh)
	hc.wg.Add(1)
	hc.chainSubs = append(hc.chainSubs, chainSub)
	go hc.ChainEventLoop(chainEventCh, chainSub)

	for i := 0; i < int(numRegions); i++ {
		backend := *hc.consensus.GetBackend(common.Location{byte(i)})
		chainEventCh := make(chan core.ChainEvent, c_chainEventChSize)
		chainSub := backend.SubscribeChainEventForHC(chainEventCh)
		hc.wg.Add(1)
		hc.chainSubs = append(hc.chainSubs, chainSub)
		go hc.ChainEventLoop(chainEventCh, chainSub)

		for j := 0; j < int(numZones); j++ {
			backend := *hc.consensus.GetBackend(common.Location{byte(i), byte(j)})
			chainEventCh := make(chan core.ChainEvent, c_chainEventChSize)
			chainSub := backend.SubscribeChainEventForHC(chainEventCh)
			hc.wg.Add(1)
			hc.chainSubs = append(hc.chainSubs, chainSub)
			go hc.ChainEventLoop(chainEventCh, chainSub)
		}
	}
	return nil
}

// Create a new instance of the QuaiBackend consensus service
func (hc *HierarchicalCoordinator) StartQuaiBackend() (*quai.QuaiBackend, error) {
	quaiBackend, _ := quai.NewQuaiBackend()
	// Set the consensus backend and subscribe to the new topics
	hc.p2p.SetConsensusBackend(quaiBackend)
	// Set the p2p backend inside the quaiBackend
	quaiBackend.SetP2PApiBackend(hc.p2p)

	currentRegions, currentZones := common.GetHierarchySizeForExpansionNumber(hc.expansionNumber())
	// Start nodes in separate goroutines
	hc.startNode("prime.log", quaiBackend, nil, nil)
	for i := 0; i < int(currentRegions); i++ {
		nodelogsFileName := "region-" + fmt.Sprintf("%d", i) + ".log"
		hc.startNode(nodelogsFileName, quaiBackend, common.Location{byte(i)}, nil)
	}
	for i := 0; i < int(currentRegions); i++ {
		for j := 0; j < int(currentZones); j++ {
			nodelogsFileName := "zone-" + fmt.Sprintf("%d", i) + "-" + fmt.Sprintf("%d", j) + ".log"
			hc.startNode(nodelogsFileName, quaiBackend, common.Location{byte(i), byte(j)}, nil)
		}
	}

	// Set the Dom Interface for all the regions and zones
	for i := 0; i < int(currentRegions); i++ {
		primeBackend := *quaiBackend.GetBackend(common.Location{})
		regionBackend := *quaiBackend.GetBackend(common.Location{byte(i)})
		// set the Prime with the sub interfaces
		primeBackend.SetSubInterface(regionBackend, common.Location{byte(i)})
		// set the Dom Interface for each region
		regionBackend.SetDomInterface(primeBackend)
	}
	for i := 0; i < int(currentRegions); i++ {
		regionBackend := *quaiBackend.GetBackend(common.Location{byte(i)})
		for j := 0; j < int(currentZones); j++ {
			zoneBackend := *quaiBackend.GetBackend(common.Location{byte(i), byte(j)})
			// Set the Sub Interface for each of the regions
			regionBackend.SetSubInterface(zoneBackend, common.Location{byte(i), byte(j)})
			// Set the Dom Interface for each of the zones
			zoneBackend.SetDomInterface(regionBackend)
		}
	}
	hc.recoverPendingHeaders(quaiBackend, int(currentRegions), int(currentZones))
	return quaiBackend, nil
}

func (hc *HierarchicalCoordinator) recoverPendingHeaders(quaiBackend quai.ConsensusAPI, currentRegions, currentZones int) {
	primeBackend := *quaiBackend.GetBackend(common.Location{})
	primeHead := primeBackend.CurrentHeader()
	if primeHead == nil {
		log.Global.Warn("Skipping pending header recovery: prime head is nil")
		return
	}

	// A crash or stale pending-header choice can leave every subordinate head
	// consistently referencing the next Prime block while Prime itself remains
	// on that block's parent. In that state the old logic below skips recovery
	// because the subordinate heights are ahead, and newly generated work keeps
	// failing PCRC. Recover the entire hierarchy to the unanimously referenced
	// Prime checkpoint so subordinate manifests restart at that coincidence.
	var forcedCheckpoint *common.Hash
	if checkpointText := viper.GetString(RecoverHierarchyCheckpointFlag.Name); checkpointText != "" {
		checkpointBytes, err := hexutil.Decode(checkpointText)
		if err != nil || len(checkpointBytes) != common.HashLength {
			log.Global.WithFields(log.Fields{"checkpoint": checkpointText, "err": err}).Error("Ignoring invalid hierarchy recovery checkpoint")
		} else {
			checkpointHash := common.BytesToHash(checkpointBytes)
			forcedCheckpoint = &checkpointHash
		}
	}
	primeHead, recovered := hc.recoverHierarchyFromSubordinatePrimeTerminus(quaiBackend, primeHead, currentRegions, currentZones, forcedCheckpoint)
	if recovered {
		return
	}

	var wg sync.WaitGroup
	for i := 0; i < currentRegions; i++ {
		regionLoc := common.Location{byte(i)}
		regionBackend := *quaiBackend.GetBackend(regionLoc)
		regionHead := regionBackend.CurrentHeader()
		if regionHead == nil {
			log.Global.WithField("location", regionLoc.Name()).Warn("Skipping pending header recovery: region head is nil")
			continue
		}
		for j := 0; j < currentZones; j++ {
			zoneLoc := common.Location{byte(i), byte(j)}
			zoneBackend := *quaiBackend.GetBackend(zoneLoc)
			zoneHead := zoneBackend.CurrentHeader()
			if zoneHead == nil {
				log.Global.WithField("location", zoneLoc.Name()).Warn("Skipping pending header recovery: zone head is nil")
				continue
			}

			if zoneHead.NumberU64(common.PRIME_CTX) >= primeHead.NumberU64(common.PRIME_CTX) &&
				zoneHead.NumberU64(common.REGION_CTX) >= regionHead.NumberU64(common.REGION_CTX) {
				continue
			}

			log.Global.WithFields(log.Fields{
				"location":     zoneLoc.Name(),
				"primeHead":    primeHead.NumberArray(),
				"regionHead":   regionHead.NumberArray(),
				"zoneHead":     zoneHead.NumberArray(),
				"zonePrimeNum": zoneHead.NumberU64(common.PRIME_CTX),
				"zoneRegion":   zoneHead.NumberU64(common.REGION_CTX),
			}).Info("Recovering pending header from current hierarchy heads")

			wg.Add(1)

			if primeHead.NumberU64(common.PRIME_CTX) > regionHead.NumberU64(common.PRIME_CTX) {
				go hc.computePendingHeaderWithConsensus(&wg, quaiBackend, primeHead.Hash(), primeHead.Hash(), primeHead.Hash(), zoneLoc)
			} else {
				go hc.computePendingHeaderWithConsensus(&wg, quaiBackend, regionHead.ParentHash(common.PRIME_CTX), regionHead.Hash(), regionHead.Hash(), zoneLoc)
			}
		}
	}
	wg.Wait()
}

// recoverHierarchyFromSubordinatePrimeTerminus recovers every context to a
// Prime checkpoint when all subordinate heads agree that the direct child of
// the current Prime head is their Prime terminus. The strict agreement,
// ancestry, availability, and PCRC checks keep this startup repair from
// choosing a fork merely because one subordinate is ahead.
func (hc *HierarchicalCoordinator) recoverHierarchyFromSubordinatePrimeTerminus(quaiBackend quai.ConsensusAPI, primeHead *types.WorkObject, currentRegions, currentZones int, forcedCheckpoint *common.Hash) (*types.WorkObject, bool) {
	if currentRegions == 0 || currentZones == 0 {
		return primeHead, false
	}

	expectedPrimeNumber := primeHead.NumberU64(common.PRIME_CTX) + 1
	candidateHash := common.Hash{}
	if forcedCheckpoint != nil {
		candidateHash = *forcedCheckpoint
	}

	for i := 0; i < currentRegions; i++ {
		regionLoc := common.Location{byte(i)}
		regionBackendRef := quaiBackend.GetBackend(regionLoc)
		if regionBackendRef == nil {
			return primeHead, false
		}
		regionHead := (*regionBackendRef).CurrentHeader()
		if regionHead == nil || (forcedCheckpoint == nil && regionHead.NumberU64(common.PRIME_CTX) != expectedPrimeNumber) {
			return primeHead, false
		}
		if candidateHash == (common.Hash{}) {
			candidateHash = regionHead.PrimeTerminusHash()
		}
		if candidateHash == (common.Hash{}) || regionHead.PrimeTerminusHash() != candidateHash {
			return primeHead, false
		}

		for j := 0; j < currentZones; j++ {
			zoneLoc := common.Location{byte(i), byte(j)}
			zoneBackendRef := quaiBackend.GetBackend(zoneLoc)
			if zoneBackendRef == nil {
				return primeHead, false
			}
			zoneHead := (*zoneBackendRef).CurrentHeader()
			if zoneHead == nil || (forcedCheckpoint == nil && zoneHead.NumberU64(common.PRIME_CTX) != expectedPrimeNumber) || zoneHead.PrimeTerminusHash() != candidateHash {
				return primeHead, false
			}
		}
	}

	primeBackendRef := quaiBackend.GetBackend(common.Location{})
	if primeBackendRef == nil {
		return primeHead, false
	}
	primeBackend := *primeBackendRef
	candidate := primeBackend.GetBlockByHash(candidateHash)
	isCurrentCheckpoint := candidate != nil && candidate.Hash() == primeHead.Hash()
	isDirectChild := candidate != nil && candidate.NumberU64(common.PRIME_CTX) == expectedPrimeNumber && candidate.ParentHash(common.PRIME_CTX) == primeHead.Hash()
	if candidate == nil || (forcedCheckpoint == nil && !isDirectChild) || (forcedCheckpoint != nil && !isCurrentCheckpoint && !isDirectChild) {
		log.Global.WithFields(log.Fields{
			"candidate":      candidateHash,
			"currentPrime":   primeHead.Hash(),
			"expectedNumber": expectedPrimeNumber,
		}).Warn("Skipping Prime head recovery: subordinate Prime terminus is not the direct child")
		return primeHead, false
	}

	primeTermini := primeBackend.GetTerminiByHash(candidateHash)
	if primeTermini == nil || !primeTermini.IsValid() {
		log.Global.WithField("candidate", candidateHash).Warn("Skipping Prime head recovery: candidate termini are unavailable")
		return primeHead, false
	}

	for i := 0; i < currentRegions; i++ {
		regionLoc := common.Location{byte(i)}
		regionBackend := *quaiBackend.GetBackend(regionLoc)
		regionHead := regionBackend.CurrentHeader()
		regionTermini := regionBackend.GetTerminiByHash(regionHead.Hash())
		if regionTermini == nil || !regionTermini.IsValid() {
			return primeHead, false
		}
		if regionTermini.DomTerminus(regionLoc) != primeTermini.SubTerminiAtIndex(i) {
			log.Global.WithFields(log.Fields{"candidate": candidateHash, "location": regionLoc.Name()}).Warn("Skipping Prime head recovery: Region is not PCRC-coherent")
			return primeHead, false
		}

		regionCheckpointHash := primeTermini.SubTerminiAtIndex(i)
		regionCheckpoint := regionBackend.GetBlockByHash(regionCheckpointHash)
		regionCheckpointTermini := regionBackend.GetTerminiByHash(regionCheckpointHash)
		if regionCheckpoint == nil || regionCheckpointTermini == nil || !regionCheckpointTermini.IsValid() {
			log.Global.WithFields(log.Fields{"candidate": candidateHash, "checkpoint": regionCheckpointHash, "location": regionLoc.Name()}).Warn("Skipping hierarchy recovery: Region checkpoint is unavailable")
			return primeHead, false
		}
		for j := 0; j < currentZones; j++ {
			zoneLoc := common.Location{byte(i), byte(j)}
			zoneBackend := *quaiBackend.GetBackend(zoneLoc)
			zoneHead := zoneBackend.CurrentHeader()
			zoneTermini := zoneBackend.GetTerminiByHash(zoneHead.Hash())
			if zoneTermini == nil || !zoneTermini.IsValid() || zoneTermini.DomTerminus(zoneLoc) != regionTermini.SubTerminiAtIndex(j) {
				log.Global.WithFields(log.Fields{"candidate": candidateHash, "location": zoneLoc.Name()}).Warn("Skipping Prime head recovery: Zone is not PCRC-coherent")
				return primeHead, false
			}

			zoneCheckpointHash := regionCheckpointTermini.SubTerminiAtIndex(j)
			zoneCheckpoint := zoneBackend.GetBlockByHash(zoneCheckpointHash)
			zoneCheckpointTermini := zoneBackend.GetTerminiByHash(zoneCheckpointHash)
			if zoneCheckpoint == nil || zoneCheckpointTermini == nil || !zoneCheckpointTermini.IsValid() {
				log.Global.WithFields(log.Fields{"candidate": candidateHash, "checkpoint": zoneCheckpointHash, "location": zoneLoc.Name()}).Warn("Skipping hierarchy recovery: Zone checkpoint is unavailable")
				return primeHead, false
			}
		}
	}

	primePendingHeader, err := primeBackend.GeneratePendingHeader(candidate, false)
	if err != nil {
		log.Global.WithFields(log.Fields{"candidate": candidateHash, "err": err}).Error("Failed to promote recovered Prime head")
		return primeHead, false
	}
	for i := 0; i < currentRegions; i++ {
		regionLoc := common.Location{byte(i)}
		regionBackend := *quaiBackend.GetBackend(regionLoc)
		regionCheckpointHash := primeTermini.SubTerminiAtIndex(i)
		regionCheckpoint := regionBackend.GetBlockByHash(regionCheckpointHash)
		regionPendingHeader, err := regionBackend.GeneratePendingHeader(regionCheckpoint, false)
		if err != nil {
			log.Global.WithFields(log.Fields{"candidate": candidateHash, "checkpoint": regionCheckpointHash, "location": regionLoc.Name(), "err": err}).Error("Failed to recover Region to Prime checkpoint")
			return primeHead, false
		}
		regionCheckpointTermini := regionBackend.GetTerminiByHash(regionCheckpointHash)
		for j := 0; j < currentZones; j++ {
			zoneLoc := common.Location{byte(i), byte(j)}
			zoneBackend := *quaiBackend.GetBackend(zoneLoc)
			zoneCheckpointHash := regionCheckpointTermini.SubTerminiAtIndex(j)
			zoneCheckpoint := zoneBackend.GetBlockByHash(zoneCheckpointHash)
			zonePendingHeader, err := zoneBackend.GeneratePendingHeader(zoneCheckpoint, false)
			if err != nil {
				log.Global.WithFields(log.Fields{"candidate": candidateHash, "checkpoint": zoneCheckpointHash, "location": zoneLoc.Name(), "err": err}).Error("Failed to recover Zone to Prime checkpoint")
				return primeHead, false
			}
			zoneBackend.MakeFullPendingHeader(primePendingHeader, regionPendingHeader, zonePendingHeader)
		}
	}
	recoveredHead := primeBackend.CurrentHeader()
	if recoveredHead == nil || recoveredHead.Hash() != candidateHash {
		log.Global.WithField("candidate", candidateHash).Error("Prime head recovery did not update the current head")
		return primeHead, false
	}
	for i := 0; i < currentRegions; i++ {
		regionLoc := common.Location{byte(i)}
		regionBackend := *quaiBackend.GetBackend(regionLoc)
		regionCheckpointHash := primeTermini.SubTerminiAtIndex(i)
		if regionBackend.CurrentHeader() == nil || regionBackend.CurrentHeader().Hash() != regionCheckpointHash {
			log.Global.WithFields(log.Fields{"candidate": candidateHash, "checkpoint": regionCheckpointHash, "location": regionLoc.Name()}).Error("Hierarchy recovery did not update the Region head")
			return primeHead, false
		}
		regionCheckpointTermini := regionBackend.GetTerminiByHash(regionCheckpointHash)
		for j := 0; j < currentZones; j++ {
			zoneLoc := common.Location{byte(i), byte(j)}
			zoneBackend := *quaiBackend.GetBackend(zoneLoc)
			zoneCheckpointHash := regionCheckpointTermini.SubTerminiAtIndex(j)
			if zoneBackend.CurrentHeader() == nil || zoneBackend.CurrentHeader().Hash() != zoneCheckpointHash {
				log.Global.WithFields(log.Fields{"candidate": candidateHash, "checkpoint": zoneCheckpointHash, "location": zoneLoc.Name()}).Error("Hierarchy recovery did not update the Zone head")
				return primeHead, false
			}
		}
	}

	log.Global.WithFields(log.Fields{
		"oldHash":   primeHead.Hash(),
		"oldNumber": primeHead.NumberU64(common.PRIME_CTX),
		"newHash":   recoveredHead.Hash(),
		"newNumber": recoveredHead.NumberU64(common.PRIME_CTX),
	}).Warn("Recovered hierarchy to unanimous Prime checkpoint")
	return recoveredHead, true
}

func (hc *HierarchicalCoordinator) startNode(logPath string, quaiBackend quai.ConsensusAPI, location common.Location, genesisBlock *types.WorkObject) {
	hc.wg.Add(1)
	logger := log.NewLogger(logPath, hc.logLevel, viper.GetInt(LogSizeFlag.Name))
	logger.Info("Starting Node at location", "location", location)
	stack, apiBackend := makeFullNode(hc.p2p, location, hc.slicesRunning, hc.expansionNumber(), genesisBlock, logger)
	quaiBackend.SetApiBackend(&apiBackend, location)

	hc.p2p.Subscribe(location, &types.WorkObjectHeaderView{})

	if quaiBackend.ProcessingState(location) && location.Context() == common.ZONE_CTX {
		// Subscribe to the new topics after setting the api backend
		hc.p2p.Subscribe(location, &types.WorkObjectShareView{})
	}

	if location.Context() == common.PRIME_CTX || location.Context() == common.REGION_CTX || quaiBackend.ProcessingState(location) {
		hc.p2p.Subscribe(location, &types.WorkObjectBlockView{})
	}

	// Nodes need to subscribe to the aux template on the upgrade to kawpow
	if location.Context() == common.ZONE_CTX {
		hc.p2p.Subscribe(location, &types.AuxTemplate{})
	}

	if location.Context() == common.ZONE_CTX {
		stack.SetZoneBackend(apiBackend)
	}
	StartNode(stack)

	go func() {
		defer func() {
			if r := recover(); r != nil {
				logger.WithFields(log.Fields{
					"error":      r,
					"stacktrace": string(debug.Stack()),
				}).Fatal("Go-Quai Panicked")
			}
		}()
		defer hc.wg.Done()
		<-hc.quitCh
		logger.Info("Context cancelled, shutting down node")
		stack.Close()
		stack.Wait()
	}()
}

func (hc *HierarchicalCoordinator) Stop() {
	close(hc.quitCh)
	for _, chainEventSub := range hc.chainSubs {
		chainEventSub.Unsubscribe()
	}
	hc.expansionSub.Unsubscribe()
	hc.wg.Wait()
	if err := hc.db.Close(); err != nil {
		log.Global.WithField("err", err).Error("Error closing hierarchical coordinator database")
	}
}

func (hc *HierarchicalCoordinator) ConsensusBackend() quai.ConsensusAPI {
	return hc.consensus
}

func (hc *HierarchicalCoordinator) expansionEventLoop() {
	defer func() {
		if r := recover(); r != nil {
			log.Global.WithFields(log.Fields{
				"error":      r,
				"stacktrace": string(debug.Stack()),
			}).Fatal("Go-Quai Panicked")
		}
	}()
	defer hc.wg.Done()

	for {
		select {
		case expansionHead := <-hc.expansionCh:
			log.Global.WithFields(log.Fields{
				"block number": expansionHead.Block.NumberU64(common.PRIME_CTX),
				"hash":         expansionHead.Block.Hash().Hex(),
			}).Info("Expansion Event received in Hierarchical Coordinator")

			// If the header has the same expansion number as the current expansion number, then it is an uncle
			if expansionHead.Block.Header().ExpansionNumber() > hc.expansionNumber() {
				// trigger an expansion every prime block
				hc.TriggerTreeExpansion(expansionHead.Block)
			} else {
				newChains := common.NewChainsAdded(hc.expansionNumber())
				for _, chain := range newChains {
					switch chain.Context() {
					case common.REGION_CTX:
						// Add the Pending Etxs into the database so that the existing
						// region can accept the Dom blocks from the new zone
						hc.consensus.AddGenesisPendingEtxs(expansionHead.Block, chain)
					case common.ZONE_CTX:
						// Expansion has already taken place, just update the genesis block
						hc.consensus.WriteGenesisBlock(expansionHead.Block, chain)
					}
				}
			}
		case <-hc.quitCh:
			return
		case <-hc.expansionSub.Err():
			return
		}
	}
}

func (hc *HierarchicalCoordinator) TriggerTreeExpansion(block *types.WorkObject) error {
	// set the current expansion on all the backends
	currentExpansionNumber := hc.expansionNumber()
	currentRegions, currentZones := common.GetHierarchySizeForExpansionNumber(currentExpansionNumber)
	newRegions, newZones := common.GetHierarchySizeForExpansionNumber(currentExpansionNumber + 1)

	newRegionShouldBeAdded := newRegions > currentRegions
	newZoneShouldBeAdded := newZones > currentZones

	// update the current expansion number
	err := hc.writeCurrentExpansionNumber(currentExpansionNumber + 1)
	if err != nil {
		log.Global.WithField("err", err).Error("Error setting the current expansion number")
		return err
	}

	// If only new zones to be added, go through all the regions and add a new zone
	if !newRegionShouldBeAdded && newZoneShouldBeAdded {
		// add a new zone to all the current active regions
		for i := 0; i < int(currentRegions); i++ {
			logLocation := "zone-" + fmt.Sprintf("%d", i) + "-" + fmt.Sprintf("%d", newZones-1) + ".log"
			hc.startNode(logLocation, hc.consensus, common.Location{byte(i), byte(newZones - 1)}, block)
			// Add the new zone to the new slices list
			// Set the subInterface for the region and Set the DomInterface for the new Zones
			zoneBackend := hc.consensus.GetBackend(common.Location{byte(i), byte(newZones - 1)})
			hc.consensus.SetSubInterface(*zoneBackend, common.Location{byte(i)}, common.Location{byte(i), byte(newZones - 1)})
			regionBackend := hc.consensus.GetBackend(common.Location{byte(i)})
			hc.consensus.SetDomInterface(*regionBackend, common.Location{byte(i)})
			// Add the Pending Etxs into the database so that the existing
			// region can accept the Dom blocks from the new zone
			hc.consensus.AddGenesisPendingEtxs(block, common.Location{byte(i)})
		}

	}

	// If new regions to be added, go through all the regions and add a new region
	if newRegionShouldBeAdded {

		// add a new region
		logLocation := "region-" + fmt.Sprintf("%d", newRegions-1) + ".log"
		hc.startNode(logLocation, hc.consensus, common.Location{byte(newRegions - 1)}, block)

		regionBackend := hc.consensus.GetBackend(common.Location{byte(newRegions - 1)})
		hc.consensus.SetSubInterface(*regionBackend, common.Location{}, common.Location{byte(newRegions - 1)})

		// new region has to activate all the zones
		for i := 0; i < int(newZones); i++ {
			logLocation = "zone-" + fmt.Sprintf("%d", newRegions-1) + "-" + fmt.Sprintf("%d", i) + ".log"
			hc.startNode(logLocation, hc.consensus, common.Location{byte(newRegions - 1), byte(i)}, block)
			// Set the DomInterface for each of the new zones
			hc.consensus.SetDomInterface(*regionBackend, common.Location{byte(newRegions - 1), byte(i)})
		}
	}

	// Giving enough time for the clients to connect before generating the pending header
	time.Sleep(5 * time.Second)

	// Set the current expansion number on all the backends
	hc.consensus.SetCurrentExpansionNumber(hc.expansionNumber())

	// Once the nodes are started, have to set the genesis block
	primeBackend := *hc.consensus.GetBackend(common.Location{})
	primeBackend.NewGenesisPendingHeader(nil, block.Hash(), block.Hash())

	return nil
}

// getCurrentExpansionNumber gets the current expansion number from the database
func (hc *HierarchicalCoordinator) readCurrentExpansionNumber() uint64 {
	currentExpansionNumber, _ := hc.db.Get(c_currentExpansionNumberKey, nil)
	if len(currentExpansionNumber) == 0 {
		// starting expansion number
		return 0
	}
	protoNumber := &common.ProtoNumber{}
	err := proto.Unmarshal(currentExpansionNumber, protoNumber)
	if err != nil {
		Fatalf("error unmarshalling current expansion number: %s", err)
	}
	return protoNumber.Value
}

func (hc *HierarchicalCoordinator) writeCurrentExpansionNumber(number uint8) error {
	// set the current expansion number and write it to the database
	// check if we have reached the max expansion, dont update the expansion
	// number past the max expansion number
	if number > common.MaxExpansionNumber {
		number = common.MaxExpansionNumber
	}
	hc.currentExpansionNumber.Store(uint32(number))
	protoExpansionNumber := &common.ProtoNumber{Value: uint64(number)}
	protoNumber, err := proto.Marshal(protoExpansionNumber)
	if err != nil {
		Fatalf("error marshalling expansion number: %s", err)
	}
	err = hc.db.Put(c_currentExpansionNumberKey, protoNumber, nil)
	if err != nil {
		Fatalf("error setting current expansion number: %s", err)
	}
	return nil
}

func (hc *HierarchicalCoordinator) expansionNumber() uint8 {
	return uint8(hc.currentExpansionNumber.Load())
}

///////// QUAI Mining Pick Logic

func (hc *HierarchicalCoordinator) ChainEventLoop(chainEvent chan core.ChainEvent, sub event.Subscription) {
	defer func() {
		if r := recover(); r != nil {
			log.Global.WithFields(log.Fields{
				"error":      r,
				"stacktrace": string(debug.Stack()),
			}).Fatal("Go-Quai Panicked")
		}
	}()
	defer hc.wg.Done()

	lastUpdateTime := time.Now()
	for {
		select {
		case head := <-chainEvent:
			// If this is the first block we have after a restart, then we can
			// add this block into the node set directly
			// Since on startup we initialize the pending headers cache with the
			// genesis block, we can check and see if we are in that state
			// We can do that by checking the length of the pendding headers order
			// cache length is 1
			hc.pendingMu.Lock()
			initializeFromHead := len(hc.pendingHeaders.order) == 1
			hc.pendingMu.Unlock()
			if initializeFromHead {
				// create a nodeset on this block
				nodeSet := NodeSet{
					nodes: make(map[string]Node),
				}

				//Initialize for prime
				backend := hc.GetBackend(common.Location{})
				entropy := backend.TotalLogEntropy(head.Block)
				newNode := Node{
					hash:     head.Block.ParentHash(common.PRIME_CTX),
					number:   head.Block.NumberArray(),
					location: common.Location{},
					entropy:  entropy,
				}
				nodeSet.nodes[common.Location{}.Name()] = newNode

				regionLocation := common.Location{byte(head.Block.Location().Region())}
				backend = hc.GetBackend(regionLocation)
				newNode.hash = head.Block.ParentHash(common.REGION_CTX)
				newNode.location = regionLocation
				newNode.entropy = entropy
				nodeSet.nodes[regionLocation.Name()] = newNode

				zoneLocation := head.Block.Location()
				backend = hc.GetBackend(zoneLocation)
				newNode.hash = head.Block.ParentHash(common.ZONE_CTX)
				newNode.location = zoneLocation
				newNode.entropy = entropy
				nodeSet.nodes[zoneLocation.Name()] = newNode
				hc.pendingMu.Lock()
				if len(hc.pendingHeaders.order) == 1 {
					hc.Add(entropy, nodeSet, hc.pendingHeaders)
				}
				hc.pendingMu.Unlock()
			}

			hc.ComputeMapPending(head)
			select {
			case hc.pendingHeaderEventCh <- head:
			case <-hc.quitCh:
				return
			}

			timeSinceLastUpdate := time.Since(lastUpdateTime)
			if timeSinceLastUpdate > 5*time.Second {
				select {
				case hc.pendingHeaderBackupCh <- struct{}{}:
				default:
					// A backup pass is already queued. Chain-event consumers must
					// never block behind the expensive map reconstruction.
				}
				lastUpdateTime = time.Now()
			}
		case <-hc.quitCh:
			return
		case <-sub.Err():
			return
		}
	}
}

func (hc *HierarchicalCoordinator) MapConstructProc() {
	defer func() {
		if r := recover(); r != nil {
			log.Global.WithFields(log.Fields{
				"error":      r,
				"stacktrace": string(debug.Stack()),
			}).Fatal("Go-Quai Panicked")
		}
	}()
	defer hc.wg.Done()

	for {
		select {
		case <-hc.pendingHeaderBackupCh:
			log.Global.Info("Running the backup calculation on recent blocks")
			hc.PendingHeadersMap()
		case <-hc.quitCh:
			return
		}
	}
}

func (hc *HierarchicalCoordinator) pendingHeaderEventLoop() {
	defer func() {
		if r := recover(); r != nil {
			log.Global.WithFields(log.Fields{
				"error":      r,
				"stacktrace": string(debug.Stack()),
			}).Fatal("Go-Quai Panicked")
		}
	}()
	defer hc.wg.Done()

	for {
		select {
		case head := <-hc.pendingHeaderEventCh:
			hc.BuildPendingHeaders(head.Block, head.Order, head.Entropy)
		case <-hc.quitCh:
			return
		}
	}
}

func (hc *HierarchicalCoordinator) ComputeMapPending(head core.ChainEvent) {
	defer func() {
		if r := recover(); r != nil {
			log.Global.WithFields(log.Fields{
				"error":      r,
				"stacktrace": string(debug.Stack()),
			}).Fatal("Go-Quai Panicked")
		}
	}()
	backend := hc.GetBackend(head.Block.Location())
	entropy := backend.TotalLogEntropy(head.Block)
	node := Node{
		hash:     head.Block.Hash(),
		number:   head.Block.NumberArray(),
		entropy:  entropy,
		location: head.Block.Location(),
	}
	hc.recentBlockMu.Lock()
	defer hc.recentBlockMu.Unlock()
	locationCache, exists := hc.recentBlocks[head.Block.Location().Name()]
	if !exists {
		// create a new lru and add this block
		locationCache, _ = lru.New[common.Hash, Node](c_recentBlockCacheSize)
		hc.recentBlocks[head.Block.Location().Name()] = locationCache
	}
	// This is a recency cache, not an entropy threshold. Keeping only heads
	// above the oldest entry discarded equal-work forks and made the backup
	// unable to choose an alternate branch after a constraint failure.
	locationCache.Add(head.Block.Hash(), node)
	log.Global.WithFields(log.Fields{"Hash": head.Block.Hash(), "Number": head.Block.NumberArray()}).Debug("Added a recent block for pending-header backup")
}

func (hc *HierarchicalCoordinator) PendingHeadersMap() {
	var badHashes map[common.Hash]bool
	badHashes = make(map[common.Hash]bool)
	count := 0
	var leaders []Node
search:
	if count > 2 {
		log.Global.Error("Too many iterations in the build pending headers, skipping generate")
		return
	}
	// Pick the leader among all the slices
	backend := *hc.consensus.GetBackend(common.Location{0, 0})
	defaultGenesisHash := backend.Config().DefaultGenesisHash

	constraintMap := make(map[string]common.Hash)
	numRegions, numZones := common.GetHierarchySizeForExpansionNumber(hc.expansionNumber())
	for i := 0; i < int(numRegions); i++ {
		for j := 0; j < int(numZones); j++ {
			location := common.Location{byte(i), byte(j)}
			hc.recentBlockMu.RLock()
			_, exists := hc.recentBlocks[location.Name()]
			hc.recentBlockMu.RUnlock()
			if !exists {
				backend := hc.GetBackend(location)
				genesisBlock := backend.GetBlockByHash(defaultGenesisHash)
				if genesisBlock == nil {
					log.Global.WithField("location", location.Name()).Warn("Genesis block missing while reconstructing pending headers")
					return
				}
				locationCache, _ := lru.New[common.Hash, Node](c_recentBlockCacheSize)
				locationCache.Add(genesisBlock.Hash(), Node{hash: genesisBlock.Hash(), number: genesisBlock.NumberArray(), location: location, entropy: big.NewInt(0)})
				hc.recentBlockMu.Lock()
				if _, loaded := hc.recentBlocks[location.Name()]; !loaded {
					hc.recentBlocks[location.Name()] = locationCache
				}
				hc.recentBlockMu.Unlock()
			}
		}
	}
	recentBlocks := hc.snapshotRecentBlocks()
	leaders = calculateLeaders(recentBlocks, badHashes, int(numRegions), int(numZones))
	// Go through all the zones to update the constraint map
	modifiedConstraintMap := constraintMap
	first := true
	for _, leader := range leaders {
		log.Global.WithFields(log.Fields{"Header": leader.hash, "Number": leader.number, "Location": leader.location, "Entropy": leader.entropy}).Debug("Starting leader")
		var err error
		location := leader.location
		backend := hc.GetBackend(location)
		otherNodes := getNodeListForLocation(recentBlocks, location, badHashes)
		for _, node := range otherNodes {
			leaderBlock := backend.GetBlockByHash(node.hash)
			if leaderBlock == nil {
				badHashes[node.hash] = true
				continue
			}
			modifiedConstraintMap, err = hc.calculateFrontierPoints(modifiedConstraintMap, leaderBlock, first)
			first = false
			if err != nil {
				log.Global.WithFields(log.Fields{"hash": leaderBlock.Hash().String(), "err": err}).Error("error tracing back from block")
			} else {
				break
			}
		}
	}

	_, exists := modifiedConstraintMap[common.Location{}.Name()]
	if !exists {
		modifiedConstraintMap[common.Location{}.Name()] = defaultGenesisHash
	}

	// Check if regions have twist
	primeTermini := hc.GetBackend(common.Location{}).GetTerminiByHash(modifiedConstraintMap[common.Location{}.Name()])
	if primeTermini == nil {
		log.Global.WithField("hash", modifiedConstraintMap[common.Location{}.Name()]).Warn("Prime termini missing while reconstructing pending headers")
		return
	}

	for i := 0; i < int(numRegions); i++ {
		regionLocation := common.Location{byte(i)}.Name()
		_, exists := modifiedConstraintMap[regionLocation]
		if !exists {
			modifiedConstraintMap[regionLocation] = defaultGenesisHash
		}

		if !hc.pcrc(modifiedConstraintMap[regionLocation], primeTermini.SubTerminiAtIndex(i), common.Location{byte(i)}, common.REGION_CTX) {
			badHashes[modifiedConstraintMap[regionLocation]] = true
			log.Global.WithFields(log.Fields{"hash": modifiedConstraintMap[regionLocation], "location": regionLocation}).Debug("Best Region doesnt satisfy pcrc")
			count++
			goto search
		}
		regionTermini := hc.GetBackend(common.Location{byte(i)}).GetTerminiByHash(modifiedConstraintMap[regionLocation])
		for j := 0; j < int(numZones); j++ {
			zoneLocation := common.Location{byte(i), byte(j)}.Name()
			_, exists := modifiedConstraintMap[zoneLocation]
			if !exists {
				modifiedConstraintMap[zoneLocation] = defaultGenesisHash
			}
			if !hc.pcrc(modifiedConstraintMap[zoneLocation], regionTermini.SubTerminiAtIndex(j), common.Location{byte(i), byte(j)}, common.ZONE_CTX) {
				badHashes[modifiedConstraintMap[zoneLocation]] = true
				log.Global.WithFields(log.Fields{"hash": modifiedConstraintMap[zoneLocation], "location": zoneLocation}).Debug("Best Zone doesnt satisfy pcrc")
				count++
				goto search
			}
		}
	}
	PrintConstraintMap(modifiedConstraintMap)
	// Build a node set
	nodeSet := NodeSet{nodes: make(map[string]Node)}
	primeNode, err := hc.NodeFromHash(modifiedConstraintMap[common.Location{}.Name()], common.Location{})
	if err != nil {
		log.Global.WithField("err", err).Error("error reading node from hash in prime")
		return
	}
	nodeSet.nodes[common.Location{}.Name()] = primeNode
	for i := 0; i < int(numRegions); i++ {
		regionNode, err := hc.NodeFromHash(modifiedConstraintMap[common.Location{byte(i)}.Name()], common.Location{byte(i)})
		if err != nil {
			log.Global.WithFields(log.Fields{"err": err, "region": i}).Error("error reading node from hash in region ", i, "err ", err)
			return
		}
		nodeSet.nodes[common.Location{byte(i)}.Name()] = regionNode
		for j := 0; j < int(numZones); j++ {
			zoneNode, err := hc.NodeFromHash(modifiedConstraintMap[common.Location{byte(i), byte(j)}.Name()], common.Location{byte(i), byte(j)})
			if err != nil {
				log.Global.WithFields(log.Fields{"err": err, "location": common.Location{byte(i), byte(j)}}).Error("error reading node from hash in zone")
				return
			}
			nodeSet.nodes[common.Location{byte(i), byte(j)}.Name()] = zoneNode
		}
	}
	entropy := nodeSet.Entropy(int(numRegions), int(numZones))
	hc.pendingMu.Lock()
	bestEntropy := new(big.Int).Set(hc.bestEntropy)
	hc.pendingMu.Unlock()
	log.Global.WithFields(log.Fields{"entropy": common.BigBitsToBits(entropy), "best entropy": common.BigBitsToBits(bestEntropy)}).Info("Map Based New Set Entropy")
	printNodeSet(nodeSet)
	hc.pendingMu.Lock()
	hc.Add(entropy, nodeSet, hc.pendingHeaders)
	generation, launchWorker := hc.queueBestHeaderGenerationLocked()
	hc.pendingMu.Unlock()
	if launchWorker {
		hc.startPendingHeaderWorker(generation)
	}
}

func (hc *HierarchicalCoordinator) NodeFromHash(hash common.Hash, location common.Location) (Node, error) {
	backend := hc.GetBackend(location)
	header := backend.GetHeaderByHash(hash)
	if header == nil {
		return Node{}, errors.New("header not found")
	}
	return Node{
		hash:     header.Hash(),
		number:   header.NumberArray(),
		location: location,
		entropy:  backend.TotalLogEntropy(header),
	}, nil
}

func (hc *HierarchicalCoordinator) snapshotRecentBlocks() map[string][]Node {
	hc.recentBlockMu.RLock()
	defer hc.recentBlockMu.RUnlock()

	snapshot := make(map[string][]Node, len(hc.recentBlocks))
	for location, cache := range hc.recentBlocks {
		nodes := make([]Node, 0, cache.Len())
		for _, key := range cache.Keys() {
			if node, ok := cache.Peek(key); ok {
				nodes = append(nodes, node)
			}
		}
		snapshot[location] = nodes
	}
	return snapshot
}

func calculateLeaders(recentBlocks map[string][]Node, badHashes map[common.Hash]bool, numRegions, numZones int) []Node {
	nodeList := []Node{}
	for i := 0; i < numRegions; i++ {
		for j := 0; j < numZones; j++ {
			nodes, exists := recentBlocks[common.Location{byte(i), byte(j)}.Name()]
			if exists {
				var bestNode Node
				for _, node := range nodes {
					if badHashes[node.hash] {
						continue
					}
					if bestNode.Empty() {
						bestNode = node
					} else if bestNode.entropy.Cmp(node.entropy) < 0 {
						bestNode = node
					}
				}
				if !bestNode.Empty() {
					nodeList = append(nodeList, bestNode)
				}
			}
		}
	}

	sort.Slice(nodeList, func(i, j int) bool {
		return nodeList[i].entropy.Cmp(nodeList[j].entropy) > 0
	})

	return nodeList
}

func getNodeListForLocation(recentBlocks map[string][]Node, location common.Location, badHashesList map[common.Hash]bool) []Node {
	recentNodes, exists := recentBlocks[location.Name()]
	if !exists {
		return []Node{}
	}
	nodeList := []Node{}
	for _, node := range recentNodes {
		if badHashesList[node.hash] {
			continue
		}
		if node.Empty() {
			continue
		}
		nodeList = append(nodeList, node)
	}
	sort.Slice(nodeList, func(i, j int) bool {
		return nodeList[i].entropy.Cmp(nodeList[j].entropy) > 0
	})
	return nodeList
}

func PrintConstraintMap(constraintMap map[string]common.Hash) {
	log.Global.Debug("constraint map")
	for location, child := range constraintMap {
		log.Global.WithFields(log.Fields(log.Fields{"Location": location, "Header": child})).Debug("constraint map")
	}
}

func (hc *HierarchicalCoordinator) BuildPendingHeaders(wo *types.WorkObject, order int, newEntropy *big.Int) {
	numRegions, numZones := common.GetHierarchySizeForExpansionNumber(hc.expansionNumber())

	hc.pendingMu.Lock()
	startingLen := len(hc.pendingHeaders.order)
	const scanLimit = 21
	start := max(0, startingLen-scanLimit)
	candidates := make([]pendingHeaderEntry, 0, startingLen-start)
	for i := startingLen - 1; i >= start; i-- {
		if entry, exists := hc.pendingHeaders.collection.Peek(hc.pendingHeaders.order[i]); exists {
			candidates = append(candidates, entry)
		}
	}
	bestEntropy := new(big.Int).Set(hc.bestEntropy)
	hc.pendingMu.Unlock()

	newPendingHeaders := NewPendingHeaders()
	startedAt := time.Now()
	deadline := startedAt.Add(c_buildPendingHeadersTimeout)
	log.Global.WithField("len", startingLen).Info("PendingHeadersOrder")
	for _, candidate := range candidates {
		if candidate.nodeSet.Extendable(wo, order) {
			// update the nodeset
			newNodeSet := candidate.nodeSet.Copy()
			newNodeSet.Update(wo, newEntropy, order)

			// Calculate new set entropy
			newSetEntropy := newNodeSet.Entropy(int(numRegions), int(numZones))
			if new(big.Int).Sub(bestEntropy, big.NewInt(30)).Cmp(newSetEntropy) < 0 {
				log.Global.WithFields(log.Fields{"newSetEntropy": common.BigBitsToBits(newSetEntropy), "Best Entropy": common.BigBitsToBits(bestEntropy)}).Info("Pending Headers Cache New Set Entropy")
				printNodeSet(newNodeSet)
			}
			hc.Add(newSetEntropy, newNodeSet, newPendingHeaders)
		} else {
			log.Global.WithFields(log.Fields{"entropy": common.BigBitsToBits(candidate.entropy), "order": order, "number": wo.NumberArray(), "hash": wo.Hash()}).Trace("NodeSet is not extendable")
		}
		if time.Now().After(deadline) {
			log.Global.WithField("timeout", c_buildPendingHeadersTimeout).Warn("Stopped pending-header scan at time budget")
			break
		}
	}

	hc.pendingMu.Lock()
	for _, key := range newPendingHeaders.order {
		newCollection, exists := newPendingHeaders.collection.Peek(key)
		if exists {
			_, exists = hc.pendingHeaders.collection.Peek(key)
			if !exists {
				hc.Add(newCollection.entropy, newCollection.nodeSet, hc.pendingHeaders)
			}
		}
	}

	sort.Slice(hc.pendingHeaders.order, func(i, j int) bool {
		left, leftExists := hc.pendingHeaders.collection.Peek(hc.pendingHeaders.order[i])
		right, rightExists := hc.pendingHeaders.collection.Peek(hc.pendingHeaders.order[j])
		if !leftExists {
			return true
		}
		if !rightExists {
			return false
		}
		return left.entropy.Cmp(right.entropy) < 0
	})

	generation, launchWorker := hc.queueBestHeaderGenerationLocked()
	hc.pendingMu.Unlock()

	if launchWorker {
		hc.startPendingHeaderWorker(generation)
	}
	log.Global.WithField("time since start", time.Since(startedAt)).Info("Time taken to compute pending headers")
}

// queueBestHeaderGenerationLocked schedules at most one active generation and
// coalesces all additional requests to the newest best hierarchy.
// hc.pendingMu must be held by the caller.
func (hc *HierarchicalCoordinator) queueBestHeaderGenerationLocked() (NodeSet, bool) {
	if len(hc.pendingHeaders.order) == 0 {
		return NodeSet{}, false
	}
	var best pendingHeaderEntry
	found := false
	for _, key := range hc.pendingHeaders.order {
		entry, exists := hc.pendingHeaders.collection.Peek(key)
		if exists && (!found || best.entropy.Cmp(entry.entropy) < 0) {
			best = entry
			found = true
		}
	}
	if !found {
		return NodeSet{}, false
	}
	generation := best.nodeSet.Copy()
	if hc.headerWorkerRunning {
		hc.queuedHeaderGeneration = generation
		hc.hasQueuedGeneration = true
		return NodeSet{}, false
	}
	hc.headerWorkerRunning = true
	return generation, true
}

func (hc *HierarchicalCoordinator) startPendingHeaderWorker(nodeSet NodeSet) {
	hc.wg.Add(1)
	go func() {
		defer hc.wg.Done()
		hc.ComputePendingHeaders(nodeSet)
	}()
}

func (hc *HierarchicalCoordinator) ComputePendingHeaders(nodeSet NodeSet) {
	defer func() {
		if r := recover(); r != nil {
			log.Global.WithFields(log.Fields{
				"error":      r,
				"stacktrace": string(debug.Stack()),
			}).Fatal("Go-Quai Panicked")
		}
	}()
	for {
		hc.computePendingHeaders(nodeSet)

		hc.pendingMu.Lock()
		if !hc.hasQueuedGeneration {
			hc.headerWorkerRunning = false
			hc.pendingMu.Unlock()
			return
		}
		nodeSet = hc.queuedHeaderGeneration
		hc.queuedHeaderGeneration = NodeSet{}
		hc.hasQueuedGeneration = false
		hc.pendingMu.Unlock()
	}
}

func (hc *HierarchicalCoordinator) computePendingHeaders(nodeSet NodeSet) {
	numRegions, numZones := common.GetHierarchySizeForExpansionNumber(hc.expansionNumber())
	if err := hc.validateNodeSetPCRC(nodeSet, numRegions, numZones); err != nil {
		hc.rejectPendingHeaderNodeSet(nodeSet, err)
		return
	}

	var wg sync.WaitGroup
	primeLocation := common.Location{}.Name()
	for i := 0; i < int(numRegions); i++ {
		regionLocation := common.Location{byte(i)}.Name()
		for j := 0; j < int(numZones); j++ {
			zoneLocation := common.Location{byte(i), byte(j)}.Name()

			wg.Add(1)
			go hc.ComputePendingHeader(&wg, nodeSet.nodes[primeLocation].hash, nodeSet.nodes[regionLocation].hash, nodeSet.nodes[zoneLocation].hash, common.Location{byte(i), byte(j)})
		}
	}
	wg.Wait()
}

// validateNodeSetPCRC is the final invariant check before pending-header
// generation. Every subordinate node must reference the terminus selected by
// its dominant node. Keeping this check at the generation boundary also covers
// node sets populated by the fast event path and startup recovery.
func (hc *HierarchicalCoordinator) validateNodeSetPCRC(nodeSet NodeSet, numRegions, numZones uint64) error {
	return validateNodeSetPCRC(nodeSet, numRegions, numZones, func(location common.Location, hash common.Hash) *types.Termini {
		backendRef := hc.consensus.GetBackend(location)
		if backendRef == nil || *backendRef == nil {
			return nil
		}
		return (*backendRef).GetTerminiByHash(hash)
	})
}

func validateNodeSetPCRC(nodeSet NodeSet, numRegions, numZones uint64, terminiForNode func(common.Location, common.Hash) *types.Termini) error {
	primeLocation := common.Location{}
	primeNode, exists := nodeSet.nodes[primeLocation.Name()]
	if !exists {
		return errors.New("prime node is missing")
	}
	primeTermini := terminiForNode(primeLocation, primeNode.hash)
	if !primeTermini.IsValid() {
		return fmt.Errorf("prime termini are missing or invalid for %s", primeNode.hash)
	}

	for i := 0; i < int(numRegions); i++ {
		regionLocation := common.Location{byte(i)}
		regionNode, exists := nodeSet.nodes[regionLocation.Name()]
		if !exists {
			return fmt.Errorf("region node is missing at %s", regionLocation.Name())
		}
		regionTermini := terminiForNode(regionLocation, regionNode.hash)
		if !regionTermini.IsValid() {
			return fmt.Errorf("region termini are missing or invalid at %s for %s", regionLocation.Name(), regionNode.hash)
		}
		expectedRegionTerminus := primeTermini.SubTerminiAtIndex(i)
		actualRegionTerminus := regionTermini.DomTerminus(regionLocation)
		if !pcrcMatches(regionTermini, expectedRegionTerminus, regionLocation) {
			return fmt.Errorf("prime-to-region PCRC failed at %s: prime requires %s, region references %s", regionLocation.Name(), expectedRegionTerminus, actualRegionTerminus)
		}

		for j := 0; j < int(numZones); j++ {
			zoneLocation := common.Location{byte(i), byte(j)}
			zoneNode, exists := nodeSet.nodes[zoneLocation.Name()]
			if !exists {
				return fmt.Errorf("zone node is missing at %s", zoneLocation.Name())
			}
			zoneTermini := terminiForNode(zoneLocation, zoneNode.hash)
			if !zoneTermini.IsValid() {
				return fmt.Errorf("zone termini are missing or invalid at %s for %s", zoneLocation.Name(), zoneNode.hash)
			}
			expectedZoneTerminus := regionTermini.SubTerminiAtIndex(j)
			actualZoneTerminus := zoneTermini.DomTerminus(zoneLocation)
			if !pcrcMatches(zoneTermini, expectedZoneTerminus, zoneLocation) {
				return fmt.Errorf("region-to-zone PCRC failed at %s: region requires %s, zone references %s", zoneLocation.Name(), expectedZoneTerminus, actualZoneTerminus)
			}
		}
	}
	return nil
}

func (hc *HierarchicalCoordinator) rejectPendingHeaderNodeSet(nodeSet NodeSet, validationErr error) {
	key := nodeSetKey(nodeSet)

	hc.pendingMu.Lock()
	hc.pendingHeaders.collection.Remove(key)
	if hc.hasQueuedGeneration && nodeSetKey(hc.queuedHeaderGeneration) == key {
		hc.queuedHeaderGeneration = NodeSet{}
		hc.hasQueuedGeneration = false
	}
	// The current worker will consume this queued candidate after returning
	// from computePendingHeaders.
	_, _ = hc.queueBestHeaderGenerationLocked()
	hc.pendingMu.Unlock()

	log.Global.WithField("error", validationErr).Error("Rejected pending-header NodeSet: PCRC validation failed")

	select {
	case hc.pendingHeaderBackupCh <- struct{}{}:
	default:
	}
}

// PCRC previous coincidence reference check makes sure there are not any cyclic references in the graph and calculates new termini and the block terminus
func (hc *HierarchicalCoordinator) pcrc(subParentHash common.Hash, domTerminus common.Hash, location common.Location, ctx int) bool {
	backend := hc.GetBackend(location)
	termini := backend.GetTerminiByHash(subParentHash)
	return pcrcMatches(termini, domTerminus, location)
}

func pcrcMatches(termini *types.Termini, domTerminus common.Hash, location common.Location) bool {
	return termini.IsValid() && termini.DomTerminus(location) == domTerminus
}

func CopyConstraintMap(constraintMap map[string]common.Hash) map[string]common.Hash {
	newMap := make(map[string]common.Hash)
	for k, v := range constraintMap {
		newMap[k] = v
	}
	return newMap
}

func (hc *HierarchicalCoordinator) GetBackend(location common.Location) quaiapi.Backend {
	switch location.Context() {
	case common.PRIME_CTX:
		return *hc.consensus.GetBackend(location)
	case common.REGION_CTX:
		return *hc.consensus.GetBackend(location)
	case common.ZONE_CTX:
		return *hc.consensus.GetBackend(location)
	}
	return nil
}

func (hc *HierarchicalCoordinator) GetContextLocation(location common.Location, ctx int) common.Location {
	switch ctx {
	case common.PRIME_CTX:
		return common.Location{}
	case common.REGION_CTX:
		return common.Location{byte(location.Region())}
	case common.ZONE_CTX:
		return location
	}
	return nil
}

func (hc *HierarchicalCoordinator) calculateFrontierPoints(constraintMap map[string]common.Hash, leader *types.WorkObject, first bool) (map[string]common.Hash, error) {
	leaderLocation := leader.Location()
	leaderBackend := *hc.consensus.GetBackend(leaderLocation)

	if leaderBackend.IsGenesisHash(leader.Hash()) {
		return constraintMap, nil
	}

	// copy the starting constraint map
	startingConstraintMap := CopyConstraintMap(constraintMap)

	// trace back from the leader and stop after finding a prime block from each region or reach genesis
	_, leaderOrder, err := leaderBackend.CalcOrder(leader)
	if err != nil {
		return startingConstraintMap, err
	}

	constraintMap[leader.Location().Name()] = leader.Hash()
	currentOrder := leaderOrder
	current := leader
	iteration := 0
	parent := current
	parentOrder := currentOrder
	finished := false

	for !finished {
		// If there is a change in order update constraint or break
		if parentOrder < currentOrder || iteration == 0 {
			t, exists := constraintMap[string(hc.GetContextLocation(parent.Location(), parentOrder).Name())]
			switch parentOrder {
			case common.PRIME_CTX:
				primeBackend := hc.GetBackend(common.Location{})
				primeTermini := primeBackend.GetTerminiByHash(parent.Hash())
				if primeTermini == nil {
					return startingConstraintMap, errors.New("prime termini shouldnt be nil")
				}
				regionBackend := hc.GetBackend(hc.GetContextLocation(parent.Location(), common.REGION_CTX))
				regionTermini := regionBackend.GetTerminiByHash(parent.Hash())
				if regionTermini == nil {
					return startingConstraintMap, errors.New("region termini shouldnt be nil")
				}
				if exists {
					parentHeader := primeBackend.GetHeaderByHash(parent.Hash())
					if parentHeader == nil {
						return startingConstraintMap, err
					}
					isAncestor := hc.IsAncestor(t, parent.Hash(), parentHeader.Location(), common.PRIME_CTX)
					isProgeny := hc.IsAncestor(parent.Hash(), t, hc.GetContextLocation(parent.Location(), common.PRIME_CTX), common.PRIME_CTX)
					if isAncestor || isProgeny {
						if isAncestor {
							if !isProgeny {
								constraintMap[string(hc.GetContextLocation(parent.Location(), common.PRIME_CTX).Name())] = parent.Hash()
							}

						}
						regionConstraint, exists := constraintMap[hc.GetContextLocation(parent.Location(), common.REGION_CTX).Name()]
						if exists {
							isRegionProgeny := hc.IsAncestor(parent.Hash(), regionConstraint, hc.GetContextLocation(parent.Location(), common.REGION_CTX), common.REGION_CTX)
							if !isRegionProgeny {
								constraintMap[string(hc.GetContextLocation(parent.Location(), common.REGION_CTX).Name())] = parent.Hash()
							}
						} else {
							constraintMap[string(hc.GetContextLocation(parent.Location(), common.REGION_CTX).Name())] = parent.Hash()
						}
						if !first {
							finished = true
						}
					} else {
						return startingConstraintMap, errors.New("zone not in region constraint")
					}
				} else {
					if parent.NumberU64(parentOrder) == 0 {
						constraintMap[common.Location{}.Name()] = current.Hash()
						constraintMap[string(hc.GetContextLocation(current.Location(), common.REGION_CTX).Name())] = current.Hash()
						finished = true
					} else {
						if parentOrder == common.PRIME_CTX && currentOrder == common.REGION_CTX {
							constraintMap[string(hc.GetContextLocation(parent.Location(), common.PRIME_CTX).Name())] = parent.Hash()
						} else if parentOrder == common.PRIME_CTX {
							constraintMap[string(hc.GetContextLocation(parent.Location(), common.PRIME_CTX).Name())] = parent.Hash()
							constraintMap[string(hc.GetContextLocation(parent.Location(), common.REGION_CTX).Name())] = parent.Hash()
						}
					}
				}

			case common.REGION_CTX:
				regionBackend := hc.GetBackend(hc.GetContextLocation(parent.Location(), common.REGION_CTX))
				regionTermini := regionBackend.GetTerminiByHash(parent.Hash())
				if regionTermini == nil {
					return startingConstraintMap, errors.New("termini shouldnt be nil in region")
				}
				if exists {
					parentHeader := regionBackend.GetHeaderByHash(parent.Hash())
					if parentHeader == nil {
						return startingConstraintMap, errors.New("prime parent header shouldnt be nil")
					}
					isAncestor := hc.IsAncestor(t, parent.Hash(), parentHeader.Location(), common.REGION_CTX)
					isProgeny := hc.IsAncestor(parent.Hash(), t, hc.GetContextLocation(parent.Location(), common.REGION_CTX), common.REGION_CTX)
					if isAncestor || isProgeny {
						if isAncestor && !isProgeny {
							constraintMap[string(hc.GetContextLocation(parent.Location(), common.REGION_CTX).Name())] = parent.Hash()
						}
					} else {
						return startingConstraintMap, errors.New("zone not in region constraint")
					}

				} else {
					constraintMap[string(hc.GetContextLocation(parent.Location(), common.REGION_CTX).Name())] = parent.Hash()
				}

			case common.ZONE_CTX:
				constraintMap[parent.Location().Name()] = parent.Hash()
			}
		}

		current = parent
		currentOrder = min(parentOrder, currentOrder)
		var backend quaiapi.Backend
		switch currentOrder {
		case common.PRIME_CTX:
			backend = hc.GetBackend(common.Location{})
		case common.REGION_CTX:
			backend = hc.GetBackend(common.Location{byte(current.Location().Region())})
		case common.ZONE_CTX:
			backend = hc.GetBackend(current.Location())
		}

		if backend.IsGenesisHash(parent.ParentHash(currentOrder)) || backend.IsGenesisHash(parent.Hash()) {
			break
		}
		parent = backend.GetHeaderByHash(parent.ParentHash(currentOrder))

		_, parentOrder, err = backend.CalcOrder(parent)
		if err != nil {
			return startingConstraintMap, err
		}
		iteration++

		if currentOrder == common.PRIME_CTX {
			break
		}

	}
	return constraintMap, nil
}

func (hc *HierarchicalCoordinator) IsAncestor(ancestor common.Hash, header common.Hash, headerLoc common.Location, order int) bool {
	if ancestor == header {
		return true
	}
	backend := hc.GetBackend(hc.GetContextLocation(headerLoc, order))
	for i := 0; i < c_ancestorCheckDist; i++ {
		parent := backend.GetHeaderByHash(header)
		if parent == nil {
			return false
		}
		if parent.ParentHash(order) == ancestor {
			return true
		}
		header = parent.ParentHash(order)
	}
	return false
}

func (hc *HierarchicalCoordinator) ComputePendingHeader(wg *sync.WaitGroup, primeNode, regionNode, zoneNode common.Hash, location common.Location) {
	hc.computePendingHeaderWithConsensus(wg, hc.consensus, primeNode, regionNode, zoneNode, location)
}

func (hc *HierarchicalCoordinator) computePendingHeaderWithConsensus(wg *sync.WaitGroup, consensus quai.ConsensusAPI, primeNode, regionNode, zoneNode common.Hash, location common.Location) {
	defer func() {
		if r := recover(); r != nil {
			log.Global.WithFields(log.Fields{
				"error":      r,
				"stacktrace": string(debug.Stack()),
			}).Fatal("Go-Quai Panicked")
		}
	}()
	defer wg.Done()
	var primePendingHeader, regionPendingHeader, zonePendingHeader *types.WorkObject
	var err error
	if consensus == nil {
		log.Global.WithField("location", location.Name()).Warn("Skipping pending header computation: consensus backend is nil")
		return
	}
	primeBackendRef := consensus.GetBackend(common.Location{})
	regionBackendRef := consensus.GetBackend(common.Location{byte(location.Region())})
	zoneBackendRef := consensus.GetBackend(location)
	if primeBackendRef == nil || regionBackendRef == nil || zoneBackendRef == nil {
		log.Global.WithFields(log.Fields{
			"location":  location.Name(),
			"primeNil":  primeBackendRef == nil,
			"regionNil": regionBackendRef == nil,
			"zoneNil":   zoneBackendRef == nil,
		}).Warn("Skipping pending header computation: backend missing")
		return
	}
	primeBackend := *primeBackendRef
	regionBackend := *regionBackendRef
	zoneBackend := *zoneBackendRef
	primeBlock := primeBackend.GetBlockByHash(primeNode)
	if primeBlock == nil {
		log.Global.WithField("hash", primeNode.String()).Error("prime block not found for hash")
	} else {
		primePendingHeader, err = primeBackend.GeneratePendingHeader(primeBlock, false)
		if err != nil {
			log.Global.WithFields(log.Fields{"error": err, "location": location.Name()}).Error("Error generating prime pending header")
		}
	}
	regionBlock := regionBackend.GetBlockByHash(regionNode)
	if regionBlock == nil {
		log.Global.WithField("hash", regionNode.String()).Error("region block not found for hash")
	} else {
		regionPendingHeader, err = regionBackend.GeneratePendingHeader(regionBlock, false)
		if err != nil {
			log.Global.WithFields(log.Fields{"error": err, "location": location.Name()}).Error("Error generating region pending header")
		}
	}
	zoneBlock := zoneBackend.GetBlockByHash(zoneNode)
	if zoneBlock == nil {
		log.Global.WithField("hash", zoneNode.String()).Error("zone block not found for hash")
	} else {
		zonePendingHeader, err = zoneBackend.GeneratePendingHeader(zoneBlock, false)
		if err != nil {
			log.Global.WithFields(log.Fields{"error": err, "location": location.Name()}).Error("Error generating zone pending header")
		}
	}

	// If any of the pending header is nil, return
	if primePendingHeader == nil || regionPendingHeader == nil || zonePendingHeader == nil {
		return
	}

	zoneBackend.MakeFullPendingHeader(primePendingHeader, regionPendingHeader, zonePendingHeader)
}

func (hc *HierarchicalCoordinator) GetBackendForLocationAndOrder(location common.Location, order int) quaiapi.Backend {
	switch order {
	case common.PRIME_CTX:
		return *hc.consensus.GetBackend(common.Location{})
	case common.REGION_CTX:
		return *hc.consensus.GetBackend(common.Location{byte(location.Region())})
	case common.ZONE_CTX:
		return *hc.consensus.GetBackend(common.Location{byte(location.Region()), byte(location.Zone())})
	}
	return nil
}

func ReIndexChainIndexer() {
	providedDataDir := viper.GetString(DataDirFlag.Name)
	if providedDataDir == "" {
		log.Global.Fatal("Data directory not provided for reindexing")
	}
	dbDir := filepath.Join(filepath.Join(providedDataDir, "zone-0-0/go-quai"), "chaindata")
	ancientDir := filepath.Join(dbDir, "ancient")
	zoneDb, err := rawdb.Open(rawdb.OpenOptions{
		Type:              "leveldb",
		Directory:         dbDir,
		AncientsDirectory: ancientDir,
		Namespace:         "eth/db/chaindata/",
		Cache:             512,
		Handles:           5120,
		ReadOnly:          false,
	}, common.ZONE_CTX, log.Global, common.Location{0, 0})
	if err != nil {
		log.Global.WithField("err", err).Fatal("Error opening the zone db for reindexing")
	}
	core.ReIndexChainIndexer(zoneDb)
	if err := zoneDb.Close(); err != nil {
		log.Global.WithField("err", err).Fatal("Error closing the zone db")
	}
	time.Sleep(10 * time.Second)
}

func ValidateChainIndexer() {
	providedDataDir := viper.GetString(DataDirFlag.Name)
	if providedDataDir == "" {
		log.Global.Fatal("Data directory not provided for reindexing")
	}
	dbDir := filepath.Join(filepath.Join(providedDataDir, "zone-0-0/go-quai"), "chaindata")
	ancientDir := filepath.Join(dbDir, "ancient")
	zoneDb, err := rawdb.Open(rawdb.OpenOptions{
		Type:              "leveldb",
		Directory:         dbDir,
		AncientsDirectory: ancientDir,
		Namespace:         "eth/db/chaindata/",
		Cache:             512,
		Handles:           5120,
		ReadOnly:          false,
	}, common.ZONE_CTX, log.Global, common.Location{0, 0})
	if err != nil {
		log.Global.WithField("err", err).Fatal("Error opening the zone db for reindexing")
	}
	start := time.Now()
	head := rawdb.ReadHeadBlockHash(zoneDb)
	if head == (common.Hash{}) {
		log.Global.Fatal("Head block hash not found")
	}
	headNum := rawdb.ReadHeaderNumber(zoneDb, head)
	latestSetSize := rawdb.ReadUTXOSetSize(zoneDb, head)
	log.Global.Infof("Starting the UTXO indexer validation for height %d set size %d", *headNum, latestSetSize)
	i := 0
	utxosChecked := make(map[[34]byte]uint8)
	it := zoneDb.NewIterator(rawdb.UtxoPrefix, nil)
	for it.Next() {
		if len(it.Key()) != rawdb.UtxoKeyLength {
			continue
		}
		data := it.Value()
		if len(data) == 0 {
			log.Global.Infof("Empty key found")
			continue
		}
		utxoProto := new(types.ProtoTxOut)
		if err := proto.Unmarshal(data, utxoProto); err != nil {
			log.Global.Errorf("Failed to unmarshal ProtoTxOut: %+v data: %+v key: %+v", err, data, it.Key())
			continue
		}

		utxo := new(types.UtxoEntry)
		if err := utxo.ProtoDecode(utxoProto); err != nil {
			log.Global.WithFields(log.Fields{
				"key":  it.Key(),
				"data": data,
				"err":  err,
			}).Error("Invalid utxo Proto")
			continue
		}
		txHash, index, err := rawdb.ReverseUtxoKey(it.Key())
		if err != nil {
			log.Global.WithField("err", err).Error("Failed to parse utxo key")
			continue
		}
		u16 := make([]byte, 2)
		binary.BigEndian.PutUint16(u16, index)
		key := [34]byte(append(txHash.Bytes(), u16...))
		if _, exists := utxosChecked[key]; exists {
			log.Global.WithField("hash", key).Error("Duplicate utxo found")
			continue
		}
		height := rawdb.ReadUtxoToBlockHeight(zoneDb, txHash, index)
		addr20 := common.BytesToAddress(utxo.Address, common.Location{0, 0}).Bytes20()
		binary.BigEndian.PutUint32(addr20[16:], height)
		outpoints, err := rawdb.ReadOutpointsForAddressAtBlock(zoneDb, addr20)
		if err != nil {
			log.Global.WithField("err", err).Error("Error reading outpoints for address")
			continue
		}
		found := false
		for _, outpoint := range outpoints {
			if outpoint.TxHash == txHash && outpoint.Index == index {
				utxosChecked[key] = outpoint.Denomination
				found = true
			}
		}
		if !found {
			log.Global.WithFields(log.Fields{
				"tx":    txHash,
				"index": index,
			}).Error("Utxo not found in outpoints")
			prefix := append(rawdb.AddressUtxosPrefix, addr20.Bytes()[:16]...)
			it2 := zoneDb.NewIterator(prefix, nil)
			for it2.Next() {
				if len(it.Key()) != len(rawdb.AddressUtxosPrefix)+common.AddressLength {
					continue
				}
				addressOutpointsProto := &types.ProtoAddressOutPoints{
					OutPoints: make([]*types.ProtoOutPointAndDenomination, 0),
				}
				if err := proto.Unmarshal(it.Value(), addressOutpointsProto); err != nil {
					log.Global.WithField("err", err).Fatal("Failed to proto Unmarshal addressOutpointsProto")
					continue
				}
				for _, outpointProto := range addressOutpointsProto.OutPoints {
					outpoint := new(types.OutpointAndDenomination)
					if err := outpoint.ProtoDecode(outpointProto); err != nil {
						log.Global.WithFields(log.Fields{
							"err":      err,
							"outpoint": outpointProto,
						}).Error("Invalid outpointProto")
						continue
					}
					if outpoint.TxHash == txHash && outpoint.Index == index {
						log.Global.WithFields(log.Fields{
							"tx":    txHash,
							"index": index,
						}).Error("Utxo found in address outpoints")
						utxosChecked[key] = outpoint.Denomination
						found = true
					}
				}
			}
			it2.Release()
		}
		i++
		if i%100000 == 0 {
			log.Global.Infof("Checked %d utxos out of %d total elapsed %s", i, latestSetSize, common.PrettyDuration(time.Since(start)))
		}
	}
	it.Release()
	log.Global.Infof("Checked %d utxos and %d are good, elapsed %s", i, len(utxosChecked), common.PrettyDuration(time.Since(start)))
	if len(utxosChecked) != int(latestSetSize) {
		log.Global.WithFields(log.Fields{
			"expected": latestSetSize,
			"actual":   len(utxosChecked),
		}).Error("Mismatch in utxo set size")
	}
	log.Global.Infof("Checking for duplicates in Address Outpoints Index...")
	utxosChecked_ := make(map[[34]byte]uint8)
	duplicatesFound := false
	it = zoneDb.NewIterator(rawdb.AddressUtxosPrefix, nil)
	for it.Next() {
		if len(it.Key()) != len(rawdb.AddressUtxosPrefix)+common.AddressLength {
			continue
		}
		addressOutpointsProto := &types.ProtoAddressOutPoints{
			OutPoints: make([]*types.ProtoOutPointAndDenomination, 0),
		}
		if err := proto.Unmarshal(it.Value(), addressOutpointsProto); err != nil {
			log.Global.WithField("err", err).Fatal("Failed to proto Unmarshal addressOutpointsProto")
			continue
		}
		for _, outpointProto := range addressOutpointsProto.OutPoints {
			outpoint := new(types.OutpointAndDenomination)
			if err := outpoint.ProtoDecode(outpointProto); err != nil {
				log.Global.WithFields(log.Fields{
					"err":      err,
					"outpoint": outpointProto,
				}).Error("Invalid outpointProto")
				continue
			}
			u16 := make([]byte, 2)
			binary.BigEndian.PutUint16(u16, outpoint.Index)
			key := [34]byte(append(outpoint.TxHash.Bytes(), u16...))
			if _, exists := utxosChecked_[key]; exists {
				log.Global.WithFields(log.Fields{
					"tx":    outpoint.TxHash.String(),
					"index": outpoint.Index,
				}).Error("Duplicate outpoint found")
				duplicatesFound = true
				continue
			}
			utxosChecked_[key] = outpoint.Denomination
		}
	}
	it.Release()
	if len(utxosChecked_) != int(latestSetSize) {
		log.Global.WithFields(log.Fields{
			"expected": latestSetSize,
			"actual":   len(utxosChecked_),
		}).Error("Mismatch in utxo set size")
		time.Sleep(5 * time.Second)
		if len(utxosChecked_) > len(utxosChecked) {
			log.Global.Infof("Finding diff...")
			for key, val := range utxosChecked_ {
				if _, exists := utxosChecked[key]; !exists {
					txhash := key[:32]
					index := binary.BigEndian.Uint16(key[32:])
					log.Global.WithFields(log.Fields{
						"tx":           common.BytesToHash(txhash).String(),
						"index":        index,
						"denomination": val,
					}).Error("Missing key")
				}
			}
		}
	}
	if duplicatesFound {
		log.Global.Error("Duplicates found in address outpoints")
	} else {
		log.Global.Info("No duplicates found in address-outpoints index. Validation completed")
	}
	if err := zoneDb.Close(); err != nil {
		log.Global.WithField("err", err).Fatal("Error closing the zone db")
	}
	time.Sleep(30 * time.Second)
}
