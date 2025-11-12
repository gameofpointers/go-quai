package kawpow

import (
	"errors"
	"math"
	"math/big"

	"github.com/dominant-strategies/go-quai/common"
	"github.com/dominant-strategies/go-quai/consensus"
	"github.com/dominant-strategies/go-quai/core"
	"github.com/dominant-strategies/go-quai/core/types"
	"github.com/dominant-strategies/go-quai/params"
)

// CalcOrder returns the order of the block within the hierarchy of chains
func (kawpow *Kawpow) CalcOrder(chain consensus.BlockReader, header *types.WorkObject) (*big.Int, int, error) {
	// check if the order for this block has already been computed
	intrinsicEntropy, order, exists := chain.CheckInCalcOrderCache(header.Hash())
	if exists {
		return intrinsicEntropy, order, nil
	}
	nodeCtx := kawpow.config.NodeLocation.Context()
	// Except for the slice [0,0] have to check if the header hash is the genesis hash
	if header.NumberU64(nodeCtx) == 0 {
		return big.NewInt(0), common.PRIME_CTX, nil
	}
	expansionNum := header.ExpansionNumber()

	// Verify the seal and get the powHash for the given header
	powHash, err := kawpow.verifySeal(header.WorkObjectHeader())
	if err != nil {
		return big.NewInt(0), -1, err
	}

	// Get entropy reduction of this header
	intrinsicEntropy = common.IntrinsicLogEntropy(powHash)
	target := new(big.Int).Div(common.Big2e256, header.Difficulty())
	zoneThresholdEntropy := common.IntrinsicLogEntropy(common.BytesToHash(target.Bytes()))

	// PRIME
	// PrimeEntropyThreshold number of zone blocks times the intrinsic logs of
	// the given header determines the prime block
	totalDeltaEntropyPrime := new(big.Int).Add(header.ParentDeltaEntropy(common.REGION_CTX), header.ParentDeltaEntropy(common.ZONE_CTX))
	totalDeltaEntropyPrime = new(big.Int).Add(totalDeltaEntropyPrime, intrinsicEntropy)

	primeDeltaEntropyTarget := new(big.Int).Mul(params.PrimeEntropyTarget(expansionNum), zoneThresholdEntropy)
	primeDeltaEntropyTarget = new(big.Int).Div(primeDeltaEntropyTarget, common.Big2)

	primeBlockEntropyThreshold := new(big.Int).Add(zoneThresholdEntropy, common.BitsToBigBits(params.PrimeEntropyTarget(expansionNum)))
	if intrinsicEntropy.Cmp(primeBlockEntropyThreshold) > 0 && totalDeltaEntropyPrime.Cmp(primeDeltaEntropyTarget) > 0 {
		chain.AddToCalcOrderCache(header.Hash(), common.PRIME_CTX, intrinsicEntropy)
		return intrinsicEntropy, common.PRIME_CTX, nil
	}

	// REGION
	// Compute the total accumulated entropy since the last region block
	totalDeltaSRegion := new(big.Int).Add(header.ParentDeltaEntropy(common.ZONE_CTX), intrinsicEntropy)

	regionDeltaSTarget := new(big.Int).Mul(zoneThresholdEntropy, params.RegionEntropyTarget(expansionNum))
	regionDeltaSTarget = new(big.Int).Div(regionDeltaSTarget, common.Big2)

	regionBlockEntropyThreshold := new(big.Int).Add(zoneThresholdEntropy, common.BitsToBigBits(params.RegionEntropyTarget(expansionNum)))
	if intrinsicEntropy.Cmp(regionBlockEntropyThreshold) > 0 && totalDeltaSRegion.Cmp(regionDeltaSTarget) > 0 {
		chain.AddToCalcOrderCache(header.Hash(), common.REGION_CTX, intrinsicEntropy)
		return intrinsicEntropy, common.REGION_CTX, nil
	}

	// Zone case
	chain.AddToCalcOrderCache(header.Hash(), common.ZONE_CTX, intrinsicEntropy)
	return intrinsicEntropy, common.ZONE_CTX, nil
}

// TotalLogEntropy returns the total entropy reduction if the chain since genesis to the given header
func (kawpow *Kawpow) TotalLogEntropy(chain consensus.ChainHeaderReader, header *types.WorkObject) *big.Int {
	if chain.IsGenesisHash(header.Hash()) {
		return big.NewInt(0)
	}
	intrinsicEntropy, order, err := kawpow.CalcOrder(chain, header)
	if err != nil {
		kawpow.logger.WithField("err", err).Error("Error calculating order in TotalLogEntropy")
		return big.NewInt(0)
	}
	if kawpow.NodeLocation().Context() == common.ZONE_CTX {
		workShareEntropy, err := chain.WorkShareLogEntropy(header)
		if err != nil {
			kawpow.logger.WithField("err", err).Error("Error calculating WorkShareLogEntropy in TotalLogEntropy")
			return big.NewInt(0)
		}
		intrinsicEntropy = new(big.Int).Add(intrinsicEntropy, workShareEntropy)
	}
	switch order {
	case common.PRIME_CTX:
		totalEntropy := new(big.Int).Add(header.ParentEntropy(common.PRIME_CTX), header.ParentDeltaEntropy(common.REGION_CTX))
		totalEntropy.Add(totalEntropy, header.ParentDeltaEntropy(common.ZONE_CTX))
		totalEntropy.Add(totalEntropy, intrinsicEntropy)
		return totalEntropy
	case common.REGION_CTX:
		totalEntropy := new(big.Int).Add(header.ParentEntropy(common.REGION_CTX), header.ParentDeltaEntropy(common.ZONE_CTX))
		totalEntropy.Add(totalEntropy, intrinsicEntropy)
		return totalEntropy
	case common.ZONE_CTX:
		totalEntropy := new(big.Int).Add(header.ParentEntropy(common.ZONE_CTX), intrinsicEntropy)
		return totalEntropy
	}
	return big.NewInt(0)
}

func (kawpow *Kawpow) DeltaLogEntropy(chain consensus.ChainHeaderReader, header *types.WorkObject) *big.Int {
	if chain.IsGenesisHash(header.Hash()) {
		return big.NewInt(0)
	}
	intrinsicS, order, err := kawpow.CalcOrder(chain, header)
	if err != nil {
		kawpow.logger.WithField("err", err).Error("Error calculating order in DeltaLogEntropy")
		return big.NewInt(0)
	}
	if kawpow.NodeLocation().Context() == common.ZONE_CTX {
		workShareS, err := chain.WorkShareLogEntropy(header)
		if err != nil {
			kawpow.logger.WithField("err", err).Error("Error calculating WorkShareLogEntropy in DeltaLogEntropy")
			return big.NewInt(0)
		}
		intrinsicS = new(big.Int).Add(intrinsicS, workShareS)
	}
	switch order {
	case common.PRIME_CTX:
		return big.NewInt(0)
	case common.REGION_CTX:
		totalDeltaEntropy := new(big.Int).Add(header.ParentDeltaEntropy(common.REGION_CTX), header.ParentDeltaEntropy(common.ZONE_CTX))
		totalDeltaEntropy = new(big.Int).Add(totalDeltaEntropy, intrinsicS)
		return totalDeltaEntropy
	case common.ZONE_CTX:
		totalDeltaEntropy := new(big.Int).Add(header.ParentDeltaEntropy(common.ZONE_CTX), intrinsicS)
		return totalDeltaEntropy
	}
	return big.NewInt(0)
}

func (kawpow *Kawpow) UncledDeltaLogEntropy(chain consensus.ChainHeaderReader, header *types.WorkObject) *big.Int {
	// Treating the genesis block differntly
	if chain.IsGenesisHash(header.Hash()) {
		return big.NewInt(0)
	}
	_, order, err := kawpow.CalcOrder(chain, header)
	if err != nil {
		kawpow.logger.WithField("err", err).Error("Error calculating order in UncledDeltaLogEntropy")
		return big.NewInt(0)
	}
	uncledLogS := header.UncledEntropy()
	switch order {
	case common.PRIME_CTX:
		return big.NewInt(0)
	case common.REGION_CTX:
		totalDeltaEntropy := new(big.Int).Add(header.ParentUncledDeltaEntropy(common.REGION_CTX), header.ParentUncledDeltaEntropy(common.ZONE_CTX))
		totalDeltaEntropy = new(big.Int).Add(totalDeltaEntropy, uncledLogS)
		return totalDeltaEntropy
	case common.ZONE_CTX:
		totalDeltaEntropy := new(big.Int).Add(header.ParentUncledDeltaEntropy(common.ZONE_CTX), uncledLogS)
		return totalDeltaEntropy
	}
	return big.NewInt(0)
}

// CalcRank returns the rank of the block within the hierarchy of chains, this
// determines the level of the interlink
func (kawpow *Kawpow) CalcRank(chain consensus.ChainHeaderReader, header *types.WorkObject) (int, error) {
	if chain.IsGenesisHash(header.Hash()) {
		return 0, nil
	}
	_, order, err := kawpow.CalcOrder(chain, header)
	if err != nil {
		return 0, err
	}
	if order != common.PRIME_CTX {
		return 0, errors.New("rank cannot be computed for a non-prime block")
	}

	// Verify the seal and get the powHash for the given header
	powHash, err := kawpow.verifySeal(header.WorkObjectHeader())
	if err != nil {
		return 0, err
	}

	target := new(big.Int).Div(common.Big2e256, header.Difficulty())
	zoneThresholdS := common.IntrinsicLogEntropy(common.BytesToHash(target.Bytes()))

	intrinsicS := common.IntrinsicLogEntropy(powHash)
	for i := common.InterlinkDepth; i > 0; i-- {
		extraBits := math.Pow(2, float64(i))
		primeBlockEntropyThreshold := new(big.Int).Add(zoneThresholdS, common.BitsToBigBits(big.NewInt(int64(extraBits))))
		primeBlockEntropyThreshold = new(big.Int).Add(primeBlockEntropyThreshold, common.BitsToBigBits(params.PrimeEntropyTarget(header.ExpansionNumber())))
		if intrinsicS.Cmp(primeBlockEntropyThreshold) > 0 {
			return i, nil
		}
	}
	return 0, nil
}

func (kawpow *Kawpow) CheckIfValidWorkShare(workShare *types.WorkObjectHeader) types.WorkShareValidity {
	if workShare.PrimeTerminusNumber().Uint64() < params.KawPowForkBlock {
		thresholdDiff := params.WorkSharesThresholdDiff
		if kawpow.CheckWorkThreshold(workShare, thresholdDiff) {
			return types.Valid
		} else if kawpow.CheckWorkThreshold(workShare, kawpow.config.WorkShareThreshold) {
			return types.Sub
		} else {
			return types.Invalid
		}
	} else {
		// After the fork the workshare is determined by the sha and scrypt share targets
		workshareTarget := new(big.Int).Div(common.Big2e256, core.CalculateKawpowShareDiff(workShare))
		powHash, err := kawpow.ComputePowHash(workShare)
		if err != nil {
			return types.Invalid
		}
		if new(big.Int).SetBytes(powHash.Bytes()).Cmp(workshareTarget) <= 0 {
			return types.Valid
		} else if kawpow.CheckWorkThreshold(workShare, kawpow.config.WorkShareThreshold) {
			return types.Sub
		} else {
			return types.Invalid
		}
	}
}

func (kawpow *Kawpow) CheckWorkThreshold(workShare *types.WorkObjectHeader, workShareThresholdDiff int) bool {
	workShareMinTarget, err := consensus.CalcWorkShareThreshold(workShare, workShareThresholdDiff)
	if err != nil {
		return false
	}
	powHash, err := kawpow.ComputePowHash(workShare)
	if err != nil {
		return false
	}
	return new(big.Int).SetBytes(powHash.Bytes()).Cmp(workShareMinTarget) <= 0
}
