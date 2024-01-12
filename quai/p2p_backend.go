package quai

import (
	"context"
	"github.com/dominant-strategies/go-quai/common"
	"github.com/dominant-strategies/go-quai/core/types"
	"github.com/dominant-strategies/go-quai/internal/quaiapi"
	"github.com/dominant-strategies/go-quai/log"
	"github.com/dominant-strategies/go-quai/p2p"
)

// QuaiBackend implements the quai consensus protocol
type QuaiBackend struct {
	primeBackend   quaiapi.Backend
	regionBackends []quaiapi.Backend
	zoneBackends   [][]quaiapi.Backend

	runningSlices map[types.SliceID]*types.Slice
}

// Create a new instance of the QuaiBackend consensus service
func NewQuaiBackend() (*QuaiBackend, error) {
	zoneBackends := make([][]quaiapi.Backend, 1)
	for i := 0; i < 1; i++ {
		zoneBackends[i] = make([]quaiapi.Backend, 1)
	}
	return &QuaiBackend{regionBackends: make([]quaiapi.Backend, 1), zoneBackends: zoneBackends}, nil
}

// Set the PrimeBackend into the QuaiBackend
func (qbe *QuaiBackend) SetPrimeBackend(primeBackend quaiapi.Backend) {
	qbe.primeBackend = primeBackend
}

// Set the RegionBackend into the QuaiBackend
func (qbe *QuaiBackend) SetRegionBackend(regionBackend quaiapi.Backend, location common.Location) {
	qbe.regionBackends[location.Region()] = regionBackend
}

// Set the ZoneBackend into the QuaiBackend
func (qbe *QuaiBackend) SetZoneBackend(zoneBackend quaiapi.Backend, location common.Location) {
	qbe.zoneBackends[location.Region()][location.Zone()] = zoneBackend
}

func (qbe *QuaiBackend) GetBackend(sliceId types.SliceID) quaiapi.Backend {
	switch sliceId.Context.Level {
	case common.PRIME_CTX:
		return qbe.primeBackend
	case common.REGION_CTX:
		return qbe.regionBackends[sliceId.Region]
	case common.ZONE_CTX:
		return qbe.zoneBackends[sliceId.Region][sliceId.Zone]
	}
	return nil
}

// Start the QuaiBackend consensus service
func (qbe *QuaiBackend) Start() error {
	return nil
}

// Handle blocks received from the P2P client
func (qbe *QuaiBackend) OnNewBlock(sourcePeer p2p.PeerID, block types.Block) bool {
	log.Info("New Block Found", "Block", block)
	// TODO: Add the entropy logic
	panic("todo")
}

// Handle transactions received from the P2P client
func (qbe *QuaiBackend) OnNewTransaction(sourcePeer p2p.PeerID, tx types.Transaction) bool {
	panic("todo")
}

// Returns the current block height for the given sliceID
func (qbe *QuaiBackend) GetHeight(slice types.SliceID) uint64 {
	backend := qbe.GetBackend(slice)
	return backend.CurrentHeader().NumberU64(int(slice.Context.Level))
}

func (qbe *QuaiBackend) GetSlice(slice types.SliceID) *types.Slice {
	return qbe.runningSlices[slice]
}

func (qbe *QuaiBackend) GetRunningSlices() map[types.SliceID]*types.Slice {
	return qbe.runningSlices
}

func (qbe *QuaiBackend) SetRunningSlices(slices []types.Slice) {
	qbe.runningSlices = make(map[types.SliceID]*types.Slice)
	for _, slice := range slices {
		qbe.runningSlices[slice.SliceID] = &slice
	}
}

func (qbe *QuaiBackend) LookupBlock(hash common.Hash, slice types.SliceID) *types.Block {
	backend := qbe.GetBackend(slice)
	block, err := backend.BlockByHash(context.Background(), hash)
	if err != nil {
		return nil
	}
	return block
}
