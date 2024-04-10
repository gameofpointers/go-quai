package node

import (
	"bytes"
	"fmt"
	"math/big"
	"runtime/debug"
	"sync"
	"time"

	"github.com/pkg/errors"
	"github.com/spf13/viper"

	"github.com/dominant-strategies/go-quai/cmd/utils"
	"github.com/dominant-strategies/go-quai/core/state"
	"github.com/dominant-strategies/go-quai/core/types"
	"github.com/dominant-strategies/go-quai/crypto"
	"github.com/dominant-strategies/go-quai/log"
	"github.com/dominant-strategies/go-quai/p2p"
	"github.com/dominant-strategies/go-quai/p2p/peerManager"
	quaiprotocol "github.com/dominant-strategies/go-quai/p2p/protocol"
	"github.com/dominant-strategies/go-quai/quai"
	"github.com/dominant-strategies/go-quai/quai/snap"
	"github.com/dominant-strategies/go-quai/rlp"
	"github.com/dominant-strategies/go-quai/trie"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"

	"github.com/dominant-strategies/go-quai/common"
)

const (
	// softResponseLimit is the target maximum size of replies to data retrievals.
	softResponseLimit = 2 * 1024 * 1024

	// maxCodeLookups is the maximum number of bytecodes to serve. This number is
	// there to limit the number of disk lookups.
	maxCodeLookups = 1024

	// stateLookupSlack defines the ratio by how much a state response can exceed
	// the requested limit in order to try and avoid breaking up contracts into
	// multiple packages and proving them.
	stateLookupSlack = 0.1

	// maxTrieNodeLookups is the maximum number of state trie nodes to serve. This
	// number is there to limit the number of disk lookups.
	maxTrieNodeLookups = 1024

	// maxTrieNodeTimeSpent is the maximum time we should spend on looking up trie nodes.
	// If we spend too much time, then it's a fairly high chance of timing out
	// at the remote side, which means all the work is in vain.
	maxTrieNodeTimeSpent = 5 * time.Second
)

var (
	// emptyRoot is the known root hash of an empty trie.
	emptyRoot = common.HexToHash("56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421")

	// emptyCode is the known hash of the empty EVM bytecode.
	emptyCode = crypto.Keccak256Hash(nil)

	errBadRequest = errors.New("bad request")
)

// Starts the node and all of its services
func (p *P2PNode) Start() error {
	log.Global.Infof("starting P2P node...")

	// Start any async processes belonging to this node
	log.Global.Debugf("starting node processes...")
	go p.eventLoop()
	go p.statsLoop()

	// Is this node expected to have bootstrap peers to dial?
	if !viper.GetBool(utils.BootNodeFlag.Name) && !viper.GetBool(utils.SoloFlag.Name) && len(p.bootpeers) == 0 {
		err := errors.New("no bootpeers provided. Unable to join network")
		log.Global.Errorf("%s", err)
		return err
	}

	// Register the Quai protocol handler
	p.SetStreamHandler(quaiprotocol.ProtocolVersion, func(s network.Stream) {
		quaiprotocol.QuaiProtocolHandler(s, p)
	})

	// If the node is a bootnode, start the bootnode service
	if viper.GetBool(utils.BootNodeFlag.Name) {
		log.Global.Infof("starting node as a bootnode...")
		return nil
	}

	// Start the pubsub manager
	p.pubsub.Start(p.handleBroadcast)

	return nil
}

func (p *P2PNode) Subscribe(location common.Location, datatype interface{}) error {
	err := p.pubsub.Subscribe(location, datatype)
	if err != nil {
		return err
	}

	return p.peerManager.Provide(p.ctx, location, datatype)
}

func (p *P2PNode) Unsubscribe(location common.Location, datatype interface{}) {
	p.pubsub.Unsubscribe(location, datatype)
}

func (p *P2PNode) Broadcast(location common.Location, data interface{}) error {
	return p.pubsub.Broadcast(location, data)
}

func (p *P2PNode) SetConsensusBackend(be quai.ConsensusAPI) {
	p.consensus = be
	p.pubsub.SetQuaiBackend(be)
}

type stopFunc func() error

// Function to gracefully shtudown all running services
func (p *P2PNode) Stop() error {
	// define a list of functions to stop the services the node is running
	stopFuncs := []stopFunc{
		p.Host.Close,
		p.peerManager.Stop,
		p.pubsub.Stop,
	}
	// create a channel to collect errors
	errs := make(chan error, len(stopFuncs))
	// run each stop function in a goroutine
	for _, fn := range stopFuncs {
		go func(fn stopFunc) {
			defer func() {
				if r := recover(); r != nil {
					log.Global.WithFields(log.Fields{
						"error":      r,
						"stacktrace": string(debug.Stack()),
					}).Error("Go-Quai Panicked")
				}
			}()
			errs <- fn()
		}(fn)
	}

	var allErrors []error
	for i := 0; i < len(stopFuncs); i++ {
		select {
		case err := <-errs:
			if err != nil {
				log.Global.Errorf("error during shutdown: %s", err)
				allErrors = append(allErrors, err)
			}
		case <-time.After(5 * time.Second):
			err := errors.New("timeout during shutdown")
			log.Global.Warnf("error: %s", err)
			allErrors = append(allErrors, err)
		}
	}

	close(errs)
	if len(allErrors) > 0 {
		return errors.Errorf("errors during shutdown: %v", allErrors)
	} else {
		return nil
	}
}

func (p *P2PNode) requestFromPeers(location common.Location, data interface{}, datatype interface{}, resultChan chan interface{}) {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Global.WithFields(log.Fields{
					"error":      r,
					"stacktrace": string(debug.Stack()),
				}).Error("Go-Quai Panicked")
			}
		}()
		defer close(resultChan)
		peers := p.peerManager.GetPeers(location, data, peerManager.Best)
		log.Global.WithFields(log.Fields{
			"peers":    peers,
			"location": location,
		}).Debug("Requesting data from peers")

		var requestWg sync.WaitGroup
		for _, peerID := range peers {
			requestWg.Add(1)
			go func(peerID peer.ID) {
				defer func() {
					if r := recover(); r != nil {
						log.Global.WithFields(log.Fields{
							"error":      r,
							"stacktrace": string(debug.Stack()),
						}).Error("Go-Quai Panicked")
					}
				}()
				defer requestWg.Done()
				p.requestAndWait(peerID, location, data, datatype, resultChan)
			}(peerID)
		}
		requestWg.Wait()
	}()
}

func (p *P2PNode) requestAndWait(peerID peer.ID, location common.Location, data interface{}, dataType interface{}, resultChan chan interface{}) {
	defer func() {
		if r := recover(); r != nil {
			log.Global.WithFields(log.Fields{
				"error":      r,
				"stacktrace": string(debug.Stack()),
			}).Fatal("Go-Quai Panicked")
		}
	}()
	var recvd interface{}
	var err error
	// Ask peer and wait for response
	if recvd, err = p.requestFromPeer(peerID, location, data, dataType); err == nil {
		log.Global.WithFields(log.Fields{
			"data":     data,
			"dataType": dataType,
			"peerId":   peerID,
			"location": location.Name(),
		}).Trace("Received data from peer")

		// Mark this peer as behaving well
		p.peerManager.MarkResponsivePeer(peerID, location)
	} else {
		log.Global.WithFields(log.Fields{
			"peerId":   peerID,
			"location": location.Name(),
			"data":     data,
			"dataType": dataType,
			"err":      err,
		}).Error("Error requesting the data from peer")
		// Mark this peer as not responding
		p.peerManager.MarkUnresponsivePeer(peerID, location)
	}
	// send the block to the result channel
	resultChan <- recvd
}

// Request a data from the network for the specified slice
func (p *P2PNode) Request(location common.Location, requestData interface{}, responseDataType interface{}) chan interface{} {
	resultChan := make(chan interface{}, 1)
	// If it is a hash, first check to see if it is contained in the caches
	if hash, ok := requestData.(common.Hash); ok {
		result, ok := p.cacheGet(hash, responseDataType, location)
		if ok {
			resultChan <- result
			return resultChan
		}
	}

	p.requestFromPeers(location, requestData, responseDataType, resultChan)
	// TODO: optimize with waitgroups or a doneChan to only query if no peers responded
	// Right now this creates too many streams, so don't call this until we have a better solution
	// p.queryDHT(location, requestData, responseDataType, resultChan)

	return resultChan
}

func (p *P2PNode) MarkLivelyPeer(peer p2p.PeerID, location common.Location) {
	log.Global.WithFields(log.Fields{
		"peer":     peer,
		"location": location,
	}).Debug("Recording well-behaving peer")

	p.peerManager.MarkLivelyPeer(peer, location)
}

func (p *P2PNode) MarkLatentPeer(peer p2p.PeerID, location common.Location) {
	log.Global.WithFields(log.Fields{
		"peer":     peer,
		"location": location,
	}).Debug("Recording misbehaving peer")

	p.peerManager.MarkLatentPeer(peer, location)
}

func (p *P2PNode) ProtectPeer(peer p2p.PeerID) {
	log.Global.WithFields(log.Fields{
		"peer": peer,
	}).Debug("Protecting peer connection from pruning")

	p.peerManager.ProtectPeer(peer)
}

func (p *P2PNode) UnprotectPeer(peer p2p.PeerID) {
	log.Global.WithFields(log.Fields{
		"peer": peer,
	}).Debug("Unprotecting peer connection from pruning")

	p.peerManager.UnprotectPeer(peer)
}

func (p *P2PNode) BanPeer(peer p2p.PeerID) {
	log.Global.WithFields(log.Fields{
		"peer": peer,
	}).Warn("Banning peer for misbehaving")

	p.peerManager.BanPeer(peer)
	p.Host.Network().ClosePeer(peer)
}

// Returns the list of bootpeers
func (p *P2PNode) GetBootPeers() []peer.AddrInfo {
	return p.bootpeers
}

// Opens a new stream to the given peer using the given protocol ID
func (p *P2PNode) NewStream(peerID peer.ID) (network.Stream, error) {
	return p.peerManager.GetStream(peerID)
}

// Connects to the given peer
func (p *P2PNode) Connect(pi peer.AddrInfo) error {
	return p.Host.Connect(p.ctx, pi)
}

// Search for a block in the node's cache, or query the consensus backend if it's not found in cache.
// Returns nil if the block is not found.
func (p *P2PNode) GetWorkObject(hash common.Hash, location common.Location) *types.WorkObject {
	return p.consensus.LookupBlock(hash, location)
}

func (p *P2PNode) GetBlockHashByNumber(number *big.Int, location common.Location) *common.Hash {
	return p.consensus.LookupBlockHashByNumber(number, location)
}

func (p *P2PNode) GetHeader(hash common.Hash, location common.Location) *types.WorkObject {
	panic("TODO: implement")
}

func (p *P2PNode) GetAccountRanges(request *snap.AccountRangeRequest, location common.Location) *snap.AccountRangeResponse {
	// Decode the account retrieval request
	var req snap.AccountRangeRequest
	if req.Root == nil || req.Origin == nil || req.Limit == nil || req.Bytes == nil {
		// Invalid request, cannot serve an empty request, maybe throw an error
		return nil
	}

	// unpack the request
	id := req.Id
	var root, origin, limit common.Hash
	root.ProtoDecode(req.Root)
	origin.ProtoDecode(req.Origin)
	limit.ProtoDecode(req.Limit)
	bytesMax := *req.Bytes

	if bytesMax > softResponseLimit {
		bytesMax = softResponseLimit
	}
	// Retrieve the requested state and bail out if non existent
	tr, err := trie.New(root, p.consensus.StateCache(location).TrieDB())
	if err != nil {
		return &snap.AccountRangeResponse{Id: id}
	}
	it, err := p.consensus.Snapshots(location).AccountIterator(root, origin)
	if err != nil {
		return &snap.AccountRangeResponse{Id: id}
	}
	// Iterate over the requested range and pile accounts up
	var (
		accounts []*snap.AccountData
		size     uint64
		last     common.Hash
	)
	for it.Next() && size < bytesMax {
		hash, account := it.Hash(), common.CopyBytes(it.Account())

		// Track the returned interval for the Merkle proofs
		last = hash

		// Assemble the reply item
		size += uint64(common.HashLength + len(account))
		accounts = append(accounts, &snap.AccountData{
			Hash: hash.ProtoEncode(),
			Body: account,
		})
		// If we've exceeded the request threshold, abort
		if bytes.Compare(hash[:], limit[:]) >= 0 {
			break
		}
	}
	it.Release()

	// Generate the Merkle proofs for the first and last account
	proof := snap.NewNodeSet()
	if err := tr.Prove(origin[:], 0, proof); err != nil {
		log.Global.Warn("Failed to prove account range", "origin", req.Origin, "err", err)
		return &snap.AccountRangeResponse{Id: id}
	}
	if last != (common.Hash{}) {
		if err := tr.Prove(last[:], 0, proof); err != nil {
			log.Global.Warn("Failed to prove account range", "last", last, "err", err)
			return &snap.AccountRangeResponse{Id: req.Id}
		}
	}
	var proofs [][]byte
	for _, blob := range proof.NodeList() {
		proofs = append(proofs, blob)
	}
	// Send back anything accumulated
	return &snap.AccountRangeResponse{
		Id:       req.Id,
		Accounts: accounts,
		Proof:    proofs,
	}
}

func (p *P2PNode) GetStorageRanges(request *snap.StorageRangesRequest, location common.Location) *snap.StorageRangesResponse {
	// check sanity of the storage ranges request
	if request.Root == nil || request.Accounts == nil || request.Origin == nil || request.Limit == nil || request.Bytes == nil {
		// Invalid request, cannot serve an empty request, maybe throw an error
		return nil
	}

	// unpack the request
	id := request.Id
	var root common.Hash
	root.ProtoDecode(request.Root)
	var accounts common.Hashes
	accounts.ProtoDecode(request.Accounts)
	reqLimit := request.Limit
	reqOrigin := request.Origin
	bytesMax := *request.Bytes

	if bytesMax > softResponseLimit {
		bytesMax = softResponseLimit
	}
	// TODO(karalabe): Do we want to enforce > 0 accounts and 1 account if origin is set?
	// TODO(karalabe):   - Logging locally is not ideal as remote faulst annoy the local user
	// TODO(karalabe):   - Dropping the remote peer is less flexible wrt client bugs (slow is better than non-functional)

	// Calculate the hard limit at which to abort, even if mid storage trie
	hardLimit := uint64(float64(bytesMax) * (1 + stateLookupSlack))

	// Retrieve storage ranges until the packet limit is reached
	var (
		slots  [][]*snap.StorageData
		proofs [][]byte
		size   uint64
	)
	for _, account := range accounts {
		// If we've exceeded the requested data limit, abort without opening
		// a new storage range (that we'd need to prove due to exceeded size)
		if size >= bytesMax {
			break
		}
		// The first account might start from a different origin and end sooner
		var origin common.Hash
		if len(reqOrigin) > 0 {
			origin, reqOrigin = common.BytesToHash(reqOrigin), nil
		}
		var limit = common.HexToHash("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
		if len(reqLimit) > 0 {
			limit, reqLimit = common.BytesToHash(reqLimit), nil
		}
		// Retrieve the requested state and bail out if non existent
		it, err := p.consensus.Snapshots(location).StorageIterator(root, account, origin)
		if err != nil {
			return &snap.StorageRangesResponse{Id: id}
		}
		// Iterate over the requested range and pile slots up
		var (
			storage []*snap.StorageData
			last    common.Hash
			abort   bool
		)
		for it.Next() {
			if size >= hardLimit {
				abort = true
				break
			}
			hash, slot := it.Hash(), common.CopyBytes(it.Slot())

			// Track the returned interval for the Merkle proofs
			last = hash

			// Assemble the reply item
			size += uint64(common.HashLength + len(slot))
			storage = append(storage, &snap.StorageData{
				Hash: hash.ProtoEncode(),
				Body: slot,
			})
			// If we've exceeded the request threshold, abort
			if bytes.Compare(hash[:], limit[:]) >= 0 {
				break
			}
		}
		slots = append(slots, storage)
		it.Release()

		// Generate the Merkle proofs for the first and last storage slot, but
		// only if the response was capped. If the entire storage trie included
		// in the response, no need for any proofs.
		if origin != (common.Hash{}) || abort {
			// Request started at a non-zero hash or was capped prematurely, add
			// the endpoint Merkle proofs
			accTrie, err := trie.New(root, p.consensus.StateCache(location).TrieDB())
			if err != nil {
				return &snap.StorageRangesResponse{Id: id}
			}
			var acc state.Account
			if err := rlp.DecodeBytes(accTrie.Get(account[:]), &acc); err != nil {
				return &snap.StorageRangesResponse{Id: id}
			}
			stTrie, err := trie.New(acc.Root, p.consensus.StateCache(location).TrieDB())
			if err != nil {
				return &snap.StorageRangesResponse{Id: id}
			}
			proof := snap.NewNodeSet()
			if err := stTrie.Prove(origin[:], 0, proof); err != nil {
				log.Global.Warn("Failed to prove storage range", "origin", reqOrigin, "err", err)
				return &snap.StorageRangesResponse{Id: id}
			}
			if last != (common.Hash{}) {
				if err := stTrie.Prove(last[:], 0, proof); err != nil {
					log.Global.Warn("Failed to prove storage range", "last", last, "err", err)
					return &snap.StorageRangesResponse{Id: id}
				}
			}
			for _, blob := range proof.NodeList() {
				proofs = append(proofs, blob)
			}
			// Proof terminates the reply as proofs are only added if a node
			// refuses to serve more data (exception when a contract fetch is
			// finishing, but that's that).
			break
		}
	}

	resSlots := make([]*snap.StorageDatas, len(slots))
	for i, slot := range slots {
		resSlots[i] = &snap.StorageDatas{Data: slot}
	}
	// Send back anything accumulated
	return &snap.StorageRangesResponse{
		Id:    id,
		Slots: resSlots,
		Proof: proofs,
	}
}

func (p *P2PNode) GetByteCodes(request *snap.ByteCodesRequest, location common.Location) *snap.ByteCodesResponse {
	if request.Hashes == nil || request.Bytes == nil {
		// Invalid request, cannot serve an empty request, maybe throw an error
		return nil
	}

	// unpack the request
	id := request.Id
	var hashes common.Hashes
	hashes.ProtoDecode(request.Hashes)
	bytesMax := *request.Bytes

	if bytesMax > softResponseLimit {
		bytesMax = softResponseLimit
	}
	if len(hashes) > maxCodeLookups {
		hashes = hashes[:maxCodeLookups]
	}
	// Retrieve bytecodes until the packet size limit is reached
	var (
		codes [][]byte
		bytes uint64
	)
	for _, hash := range hashes {
		if hash == emptyCode {
			// Peers should not request the empty code, but if they do, at
			// least sent them back a correct response without db lookups
			codes = append(codes, []byte{})
		} else if blob, err := p.consensus.ContractCode(hash, location); err == nil {
			codes = append(codes, blob)
			bytes += uint64(len(blob))
		}
		if bytes > bytesMax {
			break
		}
	}
	// Send back anything accumulated
	return &snap.ByteCodesResponse{
		Id:    id,
		Codes: codes,
	}

}

func (p *P2PNode) GetTrieNodes(request *snap.TrieNodesRequest, location common.Location) (*snap.TrieNodesResponse, error) {
	if request.Root == nil || request.Paths == nil || request.Bytes == nil {
		// Invalid request, cannot serve an empty request, maybe throw an error
		return nil, nil
	}

	start := time.Now()
	// unpack the request
	id := request.Id
	var root common.Hash
	root.ProtoDecode(request.Root)
	paths := make([]*snap.TrieNodePathSet, len(request.Paths))
	for i, path := range request.Paths {
		paths[i] = new(snap.TrieNodePathSet)
		paths[i].ProtoDecode(path)
	}
	bytesMax := *request.Bytes

	if bytesMax > softResponseLimit {
		bytesMax = softResponseLimit
	}
	// Make sure we have the state associated with the request
	triedb := p.consensus.StateCache(location).TrieDB()

	accTrie, err := trie.NewSecure(root, triedb)
	if err != nil {
		// We don't have the requested state available, bail out
		return &snap.TrieNodesResponse{Id: id}, nil
	}
	snapshot := p.consensus.Snapshots(location).Snapshot(root)
	if snapshot == nil {
		// We don't have the requested state snapshotted yet, bail out.
		// In reality we could still serve using the account and storage
		// tries only, but let's protect the node a bit while it's doing
		// snapshot generation.
		return &snap.TrieNodesResponse{Id: id}, nil
	}
	// Retrieve trie nodes until the packet size limit is reached
	var (
		nodes [][]byte
		bytes uint64
		loads int // Trie hash expansions to cound database reads
	)
	for _, pathset := range paths {
		pathSet := *pathset
		switch len(pathSet) {
		case 0:
			// Ensure we penalize invalid requests
			return nil, fmt.Errorf("%w: zero-item pathset requested", errBadRequest)

		case 1:
			// If we're only retrieving an account trie node, fetch it directly
			blob, resolved, err := accTrie.TryGetNode(pathSet[0])
			loads += resolved // always account database reads, even for failures
			if err != nil {
				break
			}
			nodes = append(nodes, blob)
			bytes += uint64(len(blob))

		default:
			// Storage slots requested, open the storage trie and retrieve from there
			account, err := snapshot.Account(common.BytesToHash(pathSet[0]))
			loads++ // always account database reads, even for failures
			if err != nil {
				break
			}
			stTrie, err := trie.NewSecure(common.BytesToHash(account.Root), triedb)
			loads++ // always account database reads, even for failures
			if err != nil {
				break
			}
			for _, path := range pathSet[1:] {
				blob, resolved, err := stTrie.TryGetNode(path)
				loads += resolved // always account database reads, even for failures
				if err != nil {
					break
				}
				nodes = append(nodes, blob)
				bytes += uint64(len(blob))

				// Sanity check limits to avoid DoS on the store trie loads
				if bytes > bytesMax || loads > maxTrieNodeLookups || time.Since(start) > maxTrieNodeTimeSpent {
					break
				}
			}
		}
		// Abort request processing if we've exceeded our limits
		if bytes > bytesMax || loads > maxTrieNodeLookups || time.Since(start) > maxTrieNodeTimeSpent {
			break
		}
	}
	// Send back anything accumulated
	return &snap.TrieNodesResponse{
		Id:    id,
		Nodes: nodes,
	}, nil
}

func (p *P2PNode) handleBroadcast(sourcePeer peer.ID, data interface{}, nodeLocation common.Location) {
	switch v := data.(type) {
	case types.WorkObject:
		p.cacheAdd(v.Hash(), &v, nodeLocation)
	// TODO: send it to consensus
	case types.Transaction:
	default:
		log.Global.Debugf("received unsupported block broadcast")
		// TODO: ban the peer which sent it?
		return
	}

	// If we made it here, pass the data on to the consensus backend
	if p.consensus != nil {
		p.consensus.OnNewBroadcast(sourcePeer, data, nodeLocation)
	}
}
