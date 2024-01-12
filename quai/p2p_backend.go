package quai

import (
	"github.com/dominant-strategies/go-quai/common"
	"github.com/dominant-strategies/go-quai/core/types"
	"github.com/dominant-strategies/go-quai/internal/quaiapi"
	"github.com/dominant-strategies/go-quai/log"
	"github.com/dominant-strategies/go-quai/p2p"
)

// QuaiBackend implements the quai consensus protocol
type QuaiBackend struct {
	primeBackend   *quaiapi.Backend
	regionBackends []*quaiapi.Backend
	zoneBackends   [][]*quaiapi.Backend
}

// Create a new instance of the QuaiBackend consensus service
func NewQuaiBackend() (*QuaiBackend, error) {
	zoneBackends := make([][]*quaiapi.Backend, 1)
	for i := 0; i < 1; i++ {
		zoneBackends[i] = make([]*quaiapi.Backend, 1)
	}
	return &QuaiBackend{regionBackends: make([]*quaiapi.Backend, 1), zoneBackends: zoneBackends}, nil
}

func (qbe *QuaiBackend) SetBackend(backend quaiapi.Backend, location common.Location) {
	switch location.Context() {
	case common.PRIME_CTX:
		qbe.SetPrimeBackend(backend)
	case common.REGION_CTX:
		qbe.SetRegionBackend(backend, location)
	case common.ZONE_CTX:
		qbe.SetZoneBackend(backend, location)
	}
}

// Set the PrimeBackend into the QuaiBackend
func (qbe *QuaiBackend) SetPrimeBackend(primeBackend quaiapi.Backend) {
	qbe.primeBackend = &primeBackend
}

// Set the RegionBackend into the QuaiBackend
func (qbe *QuaiBackend) SetRegionBackend(regionBackend quaiapi.Backend, location common.Location) {
	qbe.regionBackends[location.Region()] = &regionBackend
}

// Set the ZoneBackend into the QuaiBackend
func (qbe *QuaiBackend) SetZoneBackend(zoneBackend quaiapi.Backend, location common.Location) {
	qbe.zoneBackends[location.Region()][location.Zone()] = &zoneBackend
}

func (qbe *QuaiBackend) GetBackend(location common.Location) *quaiapi.Backend {
	// TODO: Return the backened based on the sliceID and return it
	return nil
}

// Handle blocks received from the P2P client
func (qbe *QuaiBackend) OnNewBlock(sourcePeer p2p.PeerID, block types.Block) bool {
	log.Info("New Block Found", "Block", block)
	panic("todo")
}

// Handle transactions received from the P2P client
func (qbe *QuaiBackend) OnNewTransaction(sourcePeer p2p.PeerID, tx types.Transaction) bool {
	panic("todo")
}

// Returns the current block height for the given location
func (qbe *QuaiBackend) GetHeight(location common.Location) uint64 {
	// Example/mock implementation
	panic("todo")
}

func (qbe *QuaiBackend) LookupBlock(hash common.Hash, location common.Location) *types.Block {
	panic("todo")
}
