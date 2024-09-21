package utils

import (
	"errors"
	"fmt"
	"math/big"
	"runtime/debug"
	"sort"
	"sync"
	"time"

	"github.com/dominant-strategies/go-quai/common"
	"github.com/dominant-strategies/go-quai/core"
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
	collection map[string]NodeSet // Use string to store the big.Int value as a string key
	order      []*big.Int         // Maintain the order of entropies
}

type HierarchicalCoordinator struct {
	db *leveldb.DB
	// APIS
	consensus quai.ConsensusAPI
	p2p       quai.NetworkingAPI

	logLevel string

	currentExpansionNumber uint8

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
}

func NewPendingHeaders() *PendingHeaders {
	return &PendingHeaders{
		collection: make(map[string]NodeSet),
		order:      []*big.Int{},
	}
}

func (hc *HierarchicalCoordinator) InitPendingHeaders() {
	nodeSet := NodeSet{
		nodes: make(map[string]Node),
	}

	numRegions, numZones := common.GetHierarchySizeForExpansionNumber(hc.currentExpansionNumber)
	//Initialize for prime
	backend := hc.GetBackend(common.Location{})
	genesisBlock := backend.GetBlockByHash(backend.Config().DefaultGenesisHash)
	entropy := backend.TotalLogS(genesisBlock)
	newNode := Node{
		hash:     genesisBlock.Hash(),
		number:   genesisBlock.NumberArray(),
		location: common.Location{},
		entropy:  entropy,
	}
	nodeSet.nodes[common.Location{}.Name()] = newNode

	for i := 0; i < int(numRegions); i++ {
		backend := hc.GetBackend(common.Location{byte(i)})
		entropy := backend.TotalLogS(genesisBlock)
		newNode.location = common.Location{byte(i)}
		newNode.entropy = entropy
		nodeSet.nodes[common.Location{byte(i)}.Name()] = newNode
		for j := 0; j < int(numZones); j++ {
			backend := hc.GetBackend(common.Location{byte(i), byte(j)})
			entropy := backend.TotalLogS(genesisBlock)
			newNode.location = common.Location{byte(i), byte(j)}
			newNode.entropy = entropy
			nodeSet.nodes[common.Location{byte(i), byte(j)}.Name()] = newNode
		}
	}
	hc.Add(new(big.Int).SetUint64(0), nodeSet)
}

func (hc *HierarchicalCoordinator) Add(entropy *big.Int, node NodeSet) {
	entropyStr := entropy.String()
	if _, exists := hc.pendingHeaders.collection[entropyStr]; !exists {
		hc.pendingHeaders.order = append(hc.pendingHeaders.order, new(big.Int).Set(entropy)) // Store a copy of the big.Int
	}
	hc.pendingHeaders.collection[entropyStr] = node

	sort.Slice(hc.pendingHeaders.order, func(i, j int) bool {
		return hc.pendingHeaders.order[i].Cmp(hc.pendingHeaders.order[j]) < 0 // Sort based on big.Int values
	})
}

func (hc *HierarchicalCoordinator) Get(entropy *big.Int) (NodeSet, bool) {
	entropyStr := entropy.String()
	node, exists := hc.pendingHeaders.collection[entropyStr]
	return node, exists
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
		if wo.ParentHash(common.ZONE_CTX) == ns.nodes[wo.Location().Name()].hash {
			return true
		}
	}

	return false
}

func (ns *NodeSet) Entropy(numRegions int, numZones int) *big.Int {
	entropy := new(big.Int)

	for i := 0; i < numRegions; i++ {
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
		ns.nodes[common.Location{byte(wo.Location().Region())}.Name()] = newNode
		ns.nodes[wo.Location().Name()] = newNode
	case common.REGION_CTX:
		ns.nodes[common.Location{byte(wo.Location().Region())}.Name()] = newNode
		ns.nodes[wo.Location().Name()] = newNode
	case common.ZONE_CTX:
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
func NewHierarchicalCoordinator(p2p quai.NetworkingAPI, logLevel string, nodeWg *sync.WaitGroup, startingExpansionNumber uint64, quitCh chan struct{}) *HierarchicalCoordinator {
	db, err := OpenBackendDB()
	if err != nil {
		log.Global.WithField("err", err).Fatal("Error opening the backend db")
	}
	hc := &HierarchicalCoordinator{
		wg:                          nodeWg,
		db:                          db,
		p2p:                         p2p,
		logLevel:                    logLevel,
		slicesRunning:               GetRunningZones(),
		treeExpansionTriggerStarted: false,
		quitCh:                      quitCh,
		recentBlocks:                make(map[string]*lru.Cache[common.Hash, Node]),
		pendingHeaders:              NewPendingHeaders(),
	}

	if startingExpansionNumber > common.MaxExpansionNumber {
		log.Global.Fatal("Starting expansion number is greater than the maximum expansion number")
	}

	expansionNumber := hc.readCurrentExpansionNumber()
	if expansionNumber == 0 {
		expansionNumber = startingExpansionNumber
	}
	hc.currentExpansionNumber = uint8(expansionNumber)

	// Start the QuaiBackend and set the consensus backend
	backend, err := hc.StartQuaiBackend()
	if err != nil {
		log.Global.Fatal("Error starting the quai backend")
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

	numRegions, numZones := common.GetHierarchySizeForExpansionNumber(hc.currentExpansionNumber)

	backend := *hc.consensus.GetBackend(common.Location{})
	chainEventCh := make(chan core.ChainEvent, c_chainEventChSize)
	chainSub := backend.SubscribeChainEvent(chainEventCh)
	hc.wg.Add(1)
	hc.chainSubs = append(hc.chainSubs, chainSub)
	go hc.ChainEventLoop(chainEventCh, chainSub)

	for i := 0; i < int(numRegions); i++ {
		backend := *hc.consensus.GetBackend(common.Location{byte(i)})
		chainEventCh := make(chan core.ChainEvent, c_chainEventChSize)
		chainSub := backend.SubscribeChainEvent(chainEventCh)
		hc.wg.Add(1)
		hc.chainSubs = append(hc.chainSubs, chainSub)
		go hc.ChainEventLoop(chainEventCh, chainSub)

		for j := 0; j < int(numZones); j++ {
			backend := *hc.consensus.GetBackend(common.Location{byte(i), byte(j)})
			chainEventCh := make(chan core.ChainEvent, c_chainEventChSize)
			chainSub := backend.SubscribeChainEvent(chainEventCh)
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

	currentRegions, currentZones := common.GetHierarchySizeForExpansionNumber(hc.currentExpansionNumber)
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
	return quaiBackend, nil
}

func (hc *HierarchicalCoordinator) startNode(logPath string, quaiBackend quai.ConsensusAPI, location common.Location, genesisBlock *types.WorkObject) {
	hc.wg.Add(1)
	logger := log.NewLogger(logPath, hc.logLevel, viper.GetInt(LogSizeFlag.Name))
	logger.Info("Starting Node at location", "location", location)
	stack, apiBackend := makeFullNode(hc.p2p, location, hc.slicesRunning, hc.currentExpansionNumber, genesisBlock, logger)
	quaiBackend.SetApiBackend(&apiBackend, location)

	hc.p2p.Subscribe(location, &types.WorkObjectHeaderView{})

	if quaiBackend.ProcessingState(location) && location.Context() == common.ZONE_CTX {
		// Subscribe to the new topics after setting the api backend
		hc.p2p.Subscribe(location, &types.WorkObjectShareView{})
	}

	if location.Context() == common.PRIME_CTX || location.Context() == common.REGION_CTX || quaiBackend.ProcessingState(location) {
		hc.p2p.Subscribe(location, &types.WorkObjectBlockView{})
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
	for _, chainEventSub := range hc.chainSubs {
		chainEventSub.Unsubscribe()
	}
	hc.expansionSub.Unsubscribe()
	hc.db.Close()
	close(hc.quitCh)
	hc.wg.Wait()
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
			if expansionHead.Block.Header().ExpansionNumber() > hc.currentExpansionNumber {
				// trigger an expansion every prime block
				hc.TriggerTreeExpansion(expansionHead.Block)
			} else {
				newChains := common.NewChainsAdded(hc.currentExpansionNumber)
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

		case <-hc.expansionSub.Err():
			return
		}
	}
}

func (hc *HierarchicalCoordinator) TriggerTreeExpansion(block *types.WorkObject) error {
	// set the current expansion on all the backends
	currentRegions, currentZones := common.GetHierarchySizeForExpansionNumber(hc.currentExpansionNumber)
	newRegions, newZones := common.GetHierarchySizeForExpansionNumber(hc.currentExpansionNumber + 1)

	newRegionShouldBeAdded := newRegions > currentRegions
	newZoneShouldBeAdded := newZones > currentZones

	// update the current expansion number
	err := hc.writeCurrentExpansionNumber(hc.currentExpansionNumber + 1)
	if err != nil {
		log.Global.Error("Error setting the current expansion number, err: ", err)
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
	hc.consensus.SetCurrentExpansionNumber(hc.currentExpansionNumber)

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
	hc.currentExpansionNumber = number
	protoExpansionNumber := &common.ProtoNumber{Value: uint64(hc.currentExpansionNumber)}
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
	for {
		select {
		case head := <-chainEvent:
			hc.BuildPendingHeaders(head.Block, head.Order)
		case <-sub.Err():
			return
		}
	}
}

func (hc *HierarchicalCoordinator) CalculateLeaders(badHashes map[common.Hash]bool) []Node {
	nodeList := []Node{}
	numRegions, numZones := common.GetHierarchySizeForExpansionNumber(hc.currentExpansionNumber)
	for i := 0; i < int(numRegions); i++ {
		for j := 0; j < int(numZones); j++ {
			cache, exists := hc.recentBlocks[common.Location{byte(i), byte(j)}.Name()]
			if exists {
				var bestNode Node
				keys := cache.Keys()
				for _, key := range keys {
					if _, exists := badHashes[key]; exists {
						continue
					}
					node, _ := cache.Peek(key)
					if bestNode.Empty() {
						bestNode = node
					} else {
						if bestNode.entropy.Cmp(node.entropy) < 0 {
							bestNode = node
						}
					}
				}
				nodeList = append(nodeList, bestNode)
			}
		}
	}

	sort.Slice(nodeList, func(i, j int) bool {
		return nodeList[i].entropy.Cmp(nodeList[j].entropy) > 0
	})

	return nodeList
}

func (hc *HierarchicalCoordinator) GetNodeListForLocation(location common.Location, badHashesList map[common.Hash]bool) []Node {
	recentBlocksCache, exists := hc.recentBlocks[location.Name()]
	if !exists || recentBlocksCache == nil {
		return []Node{}
	}
	nodeList := []Node{}
	for _, key := range recentBlocksCache.Keys() {
		if _, exists := badHashesList[key]; exists {
			continue
		}
		node, _ := recentBlocksCache.Peek(key)
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

func (hc *HierarchicalCoordinator) BuildPendingHeaders(wo *types.WorkObject, order int) {
	timer := time.NewTimer(c_buildPendingHeadersTimeout)
	defer timer.Stop()
	numRegions, numZones := common.GetHierarchySizeForExpansionNumber(hc.currentExpansionNumber)
	hc.recentBlockMu.Lock()
	// Get a block
	// See if it can extend the best entropy
	for i := 0; i < len(hc.pendingHeaders.order); i++ {
		entropy := hc.pendingHeaders.order[i]
		nodeSet, exists := hc.Get(entropy)
		if !exists {
			log.Global.Info("NodeSet not found for entropy", " entropy: ", entropy, " order: ", order, " number: ", wo.NumberArray(), " hash: ", wo.Hash())
			continue
		}
		if nodeSet.Extendable(wo, order) {
			// update the nodeset
			newNodeSet := nodeSet.Copy()
			newNodeSet.Update(wo, entropy, order)

			// Calculate new set entropy
			newSetEntropy := newNodeSet.Entropy(int(numRegions), int(numZones))

			hc.Add(newSetEntropy, newNodeSet)
			hc.ComputePendingHeaders(newNodeSet)
			break
		}
	}
	// we continue to update older valid extensions
	// Once it can extend we create pending headers
	// we continue to update older valid extensions

	// Headers have been successfully computed, compute state.
	hc.recentBlockMu.Unlock()

}

func (hc *HierarchicalCoordinator) ComputePendingHeaders(nodeSet NodeSet) {
	numRegions, numZones := common.GetHierarchySizeForExpansionNumber(hc.currentExpansionNumber)
	stopChan := make(chan struct{})
	var wg sync.WaitGroup
	primeLocation := common.Location{}.Name()
	for i := 0; i < int(numRegions); i++ {
		regionLocation := common.Location{byte(i)}.Name()
		for j := 0; j < int(numZones); j++ {
			zoneLocation := common.Location{byte(i), byte(j)}.Name()

			wg.Add(1)
			go hc.ComputePendingHeader(&wg, nodeSet.nodes[primeLocation].hash, nodeSet.nodes[regionLocation].hash, nodeSet.nodes[zoneLocation].hash, common.Location{byte(i), byte(j)}, stopChan)
		}
	}
	wg.Wait()
}

func circularShift(arr []Node) []Node {
	if len(arr) <= 1 {
		return arr // No need to shift if array has 0 or 1 elements
	}

	shifted := arr[1:]

	return append(shifted, arr[0])
}

// PCRC previous coincidence reference check makes sure there are not any cyclic references in the graph and calculates new termini and the block terminus
func (hc *HierarchicalCoordinator) pcrc(subParentHash common.Hash, domTerminus common.Hash, location common.Location, ctx int) bool {
	backend := hc.GetBackend(location)
	termini := backend.GetTerminiByHash(subParentHash)
	if termini == nil {
		return false
	}
	if termini.DomTerminus(location) != domTerminus {
		return false
	}
	return true
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
		if parent != nil {
			if parent.ParentHash(order) == ancestor {
				return true
			}
			header = parent.ParentHash(order)
		}
	}
	return false
}

func (hc *HierarchicalCoordinator) ComputePendingHeader(wg *sync.WaitGroup, primeNode, regionNode, zoneNode common.Hash, location common.Location, stopChan chan struct{}) {
	defer func() {
		if r := recover(); r != nil {
			log.Global.WithFields(log.Fields{
				"error":      r,
				"stacktrace": string(debug.Stack()),
			}).Fatal("Go-Quai Panicked")
		}
	}()
	defer wg.Done()
	select {
	case <-stopChan:
		return
	default:
		primeBackend := *hc.consensus.GetBackend(common.Location{})
		regionBackend := *hc.consensus.GetBackend(common.Location{byte(location.Region())})
		zoneBackend := *hc.consensus.GetBackend(location)
		primeBlock := primeBackend.BlockOrCandidateByHash(primeNode)
		if primeBlock == nil {
			log.Global.Errorf("prime block not found for hash %s", primeNode.String())
			return
		}
		primePendingHeader, err := primeBackend.GeneratePendingHeader(primeBlock, false, stopChan)
		if err != nil {
			log.Global.WithFields(log.Fields{"error": err, "location": location.Name()}).Error("Error generating prime pending header")
			return
		}
		regionBlock := regionBackend.BlockOrCandidateByHash(regionNode)
		if regionBlock == nil {
			log.Global.Errorf("region block not found for hash %s", regionNode.String())
			return
		}
		regionPendingHeader, err := regionBackend.GeneratePendingHeader(regionBlock, false, stopChan)
		if err != nil {
			log.Global.WithFields(log.Fields{"error": err, "location": location.Name()}).Error("Error generating region pending header")
			return
		}
		zoneBlock := zoneBackend.GetBlockByHash(zoneNode)
		if zoneBlock == nil {
			log.Global.Errorf("zone block not found for hash %s", zoneNode.String())
			return
		}
		zonePendingHeader, err := zoneBackend.GeneratePendingHeader(zoneBlock, false, stopChan)
		if err != nil {
			log.Global.WithFields(log.Fields{"error": err, "location": location.Name()}).Error("Error generating zone pending header")
			return
		}
		zoneBackend.MakeFullPendingHeader(primePendingHeader, regionPendingHeader, zonePendingHeader)
	}
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
