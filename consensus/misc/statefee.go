package misc

import (
	"github.com/dominant-strategies/go-quai/common"
	"github.com/dominant-strategies/go-quai/core/types"
	"github.com/dominant-strategies/go-quai/params"
)

func CalcStateLimit(parent *types.WorkObject, stateCeil uint64) uint64 {
	// No Gas for TimeToStartTx days worth of zone blocks, this gives enough time to
	// onboard new miners into the slice
	if parent.NumberU64(common.ZONE_CTX) < params.TimeToStartTx {
		return 0
	}

	// If parent gas is zero and we have passed the 5 day threshold, we can set the first block gas limit to min gas limit
	if parent.StateLimit() == 0 {
		return params.MinGasLimit
	}

	parentStateLimit := parent.StateLimit()
	// Updating the parent state limit to the 10M at the fork block
	if parent.NumberU64(common.ZONE_CTX) == params.BigSporkForkNumber {
		parentStateLimit = params.MinGasLimit * 2
	}

	delta := parentStateLimit/params.StateLimitBoundDivisor - 1
	limit := parentStateLimit

	var desiredLimit uint64
	percentStateUsed := parent.StateUsed() * 100 / parent.StateLimit()
	if percentStateUsed > params.PercentStateUsedThreshold {
		desiredLimit = stateCeil
		if limit+delta > desiredLimit {
			return desiredLimit
		} else {
			return limit + delta
		}
	} else {
		desiredLimit = params.MinGasLimit
		if limit-delta/2 < desiredLimit {
			return desiredLimit
		} else {
			return limit - delta/2
		}
	}
}
