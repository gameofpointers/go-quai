package kawpow

import (
	"errors"
	"math/big"
	"runtime/debug"

	"github.com/dominant-strategies/go-quai/common"
	"github.com/dominant-strategies/go-quai/consensus"
	"github.com/dominant-strategies/go-quai/core/types"
	"github.com/dominant-strategies/go-quai/log"
	"github.com/dominant-strategies/go-quai/params"
	"modernc.org/mathutil"
)

// CalcOrder returns the order of the block within the hierarchy of chains
func (kawpow *Kawpow) CalcOrder(chain consensus.BlockReader, header *types.WorkObject) (*big.Int, int, error) {
	defer func() {
		if r := recover(); r != nil {
			kawpow.logger.WithFields(log.Fields{
				"error":      r,
				"stacktrace": string(debug.Stack()),
			}).Error("Go-Quai Panicked")
		}
	}()
	if header == nil {
		return common.Big0, 0, errors.New("order cannot be calculated for nil header")
	}
	nodeCtx := kawpow.NodeLocation().Context()
	// Verify the seal first
	_, err := kawpow.VerifySeal(header.WorkObjectHeader())
	if err != nil {
		// If we can't verify the seal, check if it might be a work share
		return kawpow.calcOrderWithWorkShare(chain, header)
	}

	intrinsicLogEntropy := kawpow.IntrinsicLogEntropy(header.Hash())
	target := new(big.Int).Div(common.Big2e256, header.Difficulty())
	zoneThresholdEntropy := new(big.Int).Sub(common.Big2e256, target)

	// Look for dom blocks
	primeEntropyThreshold := params.PrimeEntropyTarget(header.ExpansionNumber())
	regionEntropyThreshold := params.RegionEntropyTarget(header.ExpansionNumber())
	zoneEntropyThreshold := params.ZoneEntropyTarget(header.ExpansionNumber())

	switch {
	case intrinsicLogEntropy.Cmp(primeEntropyThreshold) >= 0:
		return zoneThresholdEntropy, common.PRIME_CTX, nil
	case intrinsicLogEntropy.Cmp(regionEntropyThreshold) >= 0:
		return zoneThresholdEntropy, common.REGION_CTX, nil
	case intrinsicLogEntropy.Cmp(zoneEntropyThreshold) >= 0:
		return zoneThresholdEntropy, common.ZONE_CTX, nil
	default:
		return zoneThresholdEntropy, nodeCtx, nil
	}
}

// calcOrderWithWorkShare calculates order for potential work shares
func (kawpow *Kawpow) calcOrderWithWorkShare(chain consensus.BlockReader, header *types.WorkObject) (*big.Int, int, error) {
	nodeCtx := kawpow.NodeLocation().Context()
	target := new(big.Int).Div(common.Big2e256, header.Difficulty())
	zoneThresholdEntropy := new(big.Int).Sub(common.Big2e256, target)

	// Check if it meets work share threshold
	if kawpow.config.WorkShareThreshold > 0 {
		workShareThreshold := consensus.CalcWorkShareThreshold(header.WorkObjectHeader(), kawpow.config.WorkShareThreshold)
		if workShareThreshold != nil {
			powHash, err := kawpow.ComputePowHash(header.WorkObjectHeader())
			if err == nil && new(big.Int).SetBytes(powHash.Bytes()).Cmp(workShareThreshold) <= 0 {
				// This is a valid work share
				return zoneThresholdEntropy, nodeCtx, nil
			}
		}
	}

	return common.Big0, -1, consensus.ErrInvalidPoW
}

// TotalLogEntropy returns the log of the total entropy reduction if the chain since genesis to the given header
func (kawpow *Kawpow) TotalLogEntropy(chain consensus.ChainHeaderReader, header *types.WorkObject) *big.Int {
	defer func() {
		if r := recover(); r != nil {
			kawpow.logger.WithFields(log.Fields{
				"error":      r,
				"stacktrace": string(debug.Stack()),
			}).Error("Go-Quai Panicked")
		}
	}()
	if header == nil {
		return common.Big0
	}
	nodeCtx := kawpow.NodeLocation().Context()
	intrinsicLogEntropy := kawpow.IntrinsicLogEntropy(header.Hash())
	if header.NumberU64(nodeCtx) == 0 {
		return intrinsicLogEntropy
	}
	totalLogEntropy := new(big.Int).Add(header.ParentEntropy(nodeCtx), intrinsicLogEntropy)
	return totalLogEntropy
}

// DeltaLogEntropy returns the log of the entropy delta for a chain since its prior coincidence
func (kawpow *Kawpow) DeltaLogEntropy(chain consensus.ChainHeaderReader, header *types.WorkObject) *big.Int {
	defer func() {
		if r := recover(); r != nil {
			kawpow.logger.WithFields(log.Fields{
				"error":      r,
				"stacktrace": string(debug.Stack()),
			}).Error("Go-Quai Panicked")
		}
	}()
	if header == nil {
		return common.Big0
	}
	nodeCtx := kawpow.NodeLocation().Context()

	if nodeCtx == common.PRIME_CTX {
		return kawpow.IntrinsicLogEntropy(header.Hash())
	}

	intrinsicLogEntropy := kawpow.IntrinsicLogEntropy(header.Hash())
	if header.NumberU64(nodeCtx) == 0 {
		return intrinsicLogEntropy
	}

	parentDeltaLogEntropy := header.ParentDeltaEntropy(nodeCtx)
	totalDeltaLogEntropy := new(big.Int).Add(parentDeltaLogEntropy, intrinsicLogEntropy)
	return totalDeltaLogEntropy
}

// UncledLogEntropy returns the log of the entropy reduction by uncles referenced in the block
func (kawpow *Kawpow) UncledLogEntropy(block *types.WorkObject) *big.Int {
	defer func() {
		if r := recover(); r != nil {
			kawpow.logger.WithFields(log.Fields{
				"error":      r,
				"stacktrace": string(debug.Stack()),
			}).Error("Go-Quai Panicked")
		}
	}()
	if block == nil {
		return common.Big0
	}
	uncledLogEntropy := new(big.Int)
	for _, uncle := range block.Uncles() {
		_, err := kawpow.VerifySeal(uncle)
		if err == nil {
			// This is a valid uncle (meets full difficulty)
			uncleEntropy := kawpow.IntrinsicLogEntropy(uncle.Hash())
			uncledLogEntropy.Add(uncledLogEntropy, uncleEntropy)
		}
	}
	return uncledLogEntropy
}

// WorkShareLogEntropy returns the log of the entropy reduction by the workshare referenced in the block
func (kawpow *Kawpow) WorkShareLogEntropy(chain consensus.ChainHeaderReader, block *types.WorkObject) (*big.Int, error) {
	defer func() {
		if r := recover(); r != nil {
			kawpow.logger.WithFields(log.Fields{
				"error":      r,
				"stacktrace": string(debug.Stack()),
			}).Error("Go-Quai Panicked")
		}
	}()
	if block == nil {
		return common.Big0, nil
	}
	workShareLogEntropy := new(big.Int)
	for _, uncle := range block.Uncles() {
		_, err := kawpow.VerifySeal(uncle)
		if err != nil {
			// This doesn't meet full difficulty, check if it's a valid work share
			if kawpow.config.WorkShareThreshold > 0 {
				workShareThreshold := consensus.CalcWorkShareThreshold(uncle, kawpow.config.WorkShareThreshold)
				if workShareThreshold != nil {
					powHash, err := kawpow.ComputePowHash(uncle)
					if err == nil && new(big.Int).SetBytes(powHash.Bytes()).Cmp(workShareThreshold) <= 0 {
						// This is a valid work share
						uncleEntropy := kawpow.IntrinsicLogEntropy(uncle.Hash())
						workShareLogEntropy.Add(workShareLogEntropy, uncleEntropy)
					}
				}
			}
		}
	}
	return workShareLogEntropy, nil
}

// CheckIfValidWorkShare checks if the workshare meets the work share requirements defined by the protocol
func (kawpow *Kawpow) CheckIfValidWorkShare(workShare *types.WorkObjectHeader) types.WorkShareValidity {
	defer func() {
		if r := recover(); r != nil {
			kawpow.logger.WithFields(log.Fields{
				"error":      r,
				"stacktrace": string(debug.Stack()),
			}).Error("Go-Quai Panicked")
		}
	}()
	if workShare == nil {
		return types.Invalid
	}

	// Check if it meets the full difficulty first
	_, err := kawpow.VerifySeal(workShare)
	if err == nil {
		return types.Valid // This is actually a full block, not just a work share
	}

	// Check if it meets work share threshold
	if kawpow.config.WorkShareThreshold <= 0 {
		return types.Invalid
	}

	workShareThreshold := consensus.CalcWorkShareThreshold(workShare, kawpow.config.WorkShareThreshold)
	if workShareThreshold == nil {
		return types.Invalid
	}

	powHash, err := kawpow.ComputePowHash(workShare)
	if err != nil {
		return types.Invalid
	}

	if new(big.Int).SetBytes(powHash.Bytes()).Cmp(workShareThreshold) <= 0 {
		return types.Valid
	}

	return types.Invalid
}

// UncledDeltaLogEntropy returns the log of the uncled entropy reduction since the past coincident
func (kawpow *Kawpow) UncledDeltaLogEntropy(chain consensus.ChainHeaderReader, header *types.WorkObject) *big.Int {
	defer func() {
		if r := recover(); r != nil {
			kawpow.logger.WithFields(log.Fields{
				"error":      r,
				"stacktrace": string(debug.Stack()),
			}).Error("Go-Quai Panicked")
		}
	}()
	if header == nil {
		return common.Big0
	}
	nodeCtx := kawpow.NodeLocation().Context()

	if nodeCtx == common.PRIME_CTX {
		return kawpow.UncledLogEntropy(header)
	}

	parentUncledDeltaLogEntropy := header.ParentUncledDeltaEntropy(nodeCtx)
	uncledLogEntropy := kawpow.UncledLogEntropy(header)
	totalUncledDeltaLogEntropy := new(big.Int).Add(parentUncledDeltaLogEntropy, uncledLogEntropy)
	return totalUncledDeltaLogEntropy
}

// CalcRank calculates the rank of the prime block
func (kawpow *Kawpow) CalcRank(chain consensus.ChainHeaderReader, header *types.WorkObject) (int, error) {
	defer func() {
		if r := recover(); r != nil {
			kawpow.logger.WithFields(log.Fields{
				"error":      r,
				"stacktrace": string(debug.Stack()),
			}).Error("Go-Quai Panicked")
		}
	}()
	if header == nil {
		return 0, errors.New("cannot calculate rank for nil header")
	}
	nodeCtx := kawpow.NodeLocation().Context()
	if nodeCtx != common.PRIME_CTX {
		return 0, errors.New("cannot calculate rank for non-prime context")
	}

	_, order, err := kawpow.CalcOrder(chain, header)
	if err != nil {
		return 0, err
	}

	if order < common.PRIME_CTX {
		return 0, errors.New("rank can only be calculated for prime blocks")
	}

	// Calculate rank based on intrinsic log entropy
	intrinsicLogEntropy := kawpow.IntrinsicLogEntropy(header.Hash())
	primeEntropyThreshold := params.PrimeEntropyTarget(header.ExpansionNumber())

	// Calculate how much above the prime threshold this block is
	entropyDelta := new(big.Int).Sub(intrinsicLogEntropy, primeEntropyThreshold)
	if entropyDelta.Sign() <= 0 {
		return 0, nil // Not above prime threshold
	}

	// Convert entropy delta to a rank (this is a simplified calculation)
	k, _ := mathutil.BinaryLog(entropyDelta, 64)
	rank := int(k)
	if rank < 0 {
		rank = 0
	}
	if rank > 255 {
		rank = 255
	}
	return rank, nil
}

// IntrinsicLogEntropy returns the logarithm of the intrinsic entropy reduction of a PoW hash
func (kawpow *Kawpow) IntrinsicLogEntropy(powHash common.Hash) *big.Int {
	defer func() {
		if r := recover(); r != nil {
			kawpow.logger.WithFields(log.Fields{
				"error":      r,
				"stacktrace": string(debug.Stack()),
			}).Error("Go-Quai Panicked")
		}
	}()
	x := new(big.Int).SetBytes(powHash.Bytes())
	d := new(big.Int).Sub(common.Big2e256, x)
	c, m := new(big.Int), new(big.Int)
	c.Exp(big.NewInt(2), big.NewInt(int64(consensus.MantBits)), nil)
	c.Mul(c, d)
	c.Div(c, common.Big2e256)
	m.Exp(big.NewInt(2), big.NewInt(int64(256-consensus.MantBits)), nil)
	m.Sub(m, big.NewInt(1))
	c.Or(c, m)
	return new(big.Int).Sub(common.Big2e256, c)
}