package protocol

import (
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"
)

func TestProcRequestRateUsesWeightedAverage(t *testing.T) {
	peerID := peer.ID("bulk-sync-peer")
	requestRateMu.Lock()
	inRateTrackers = nil
	outRateTrackers = map[peer.ID]rateTracker{
		peerID: {avg_period: 100, last: time.Now().Add(-100 * time.Millisecond)},
	}
	requestRateMu.Unlock()

	require.NoError(t, ProcRequestRate(peerID, false))
	requestRateMu.RLock()
	average := outRateTrackers[peerID].avg_period
	requestRateMu.RUnlock()
	require.InDelta(t, 100, average, 2)

	requestRateMu.Lock()
	outRateTrackers[peerID] = rateTracker{avg_period: 1, last: time.Now()}
	requestRateMu.Unlock()
	require.Error(t, ProcRequestRate(peerID, false))
}
