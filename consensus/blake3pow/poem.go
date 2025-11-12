package blake3pow

import (
	"errors"
	"math"
	"math/big"

	"github.com/dominant-strategies/go-quai/common"
	"github.com/dominant-strategies/go-quai/consensus"
	"github.com/dominant-strategies/go-quai/core"
	"github.com/dominant-strategies/go-quai/core/types"
	"github.com/dominant-strategies/go-quai/log"
	"github.com/dominant-strategies/go-quai/params"
)

// CalcOrder returns the order of the block within the hierarchy of chains
func (blake3pow *Blake3pow) CalcOrder(chain consensus.BlockReader, header *types.WorkObject) (*big.Int, int, error) {
	// check if the order for this block has already been computed
	intrinsicEntropy, order, exists := chain.CheckInCalcOrderCache(header.Hash())
	if exists {
		return intrinsicEntropy, order, nil
	}
	nodeCtx := blake3pow.config.NodeLocation.Context()
	if header.NumberU64(nodeCtx) == 0 {
		return big.NewInt(0), common.PRIME_CTX, nil
	}

	expansionNum := header.ExpansionNumber()

	// Verify the seal and get the powHash for the given header
	err := blake3pow.verifySeal(header.WorkObjectHeader())
	if err != nil {
		return big.NewInt(0), -1, err
	}

	// Get entropy reduction of this header
	intrinsicEntropy = common.IntrinsicLogEntropy(header.Hash())
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
	totalDeltaEntropyRegion := new(big.Int).Add(header.ParentDeltaEntropy(common.ZONE_CTX), intrinsicEntropy)

	regionDeltaEntropyTarget := new(big.Int).Mul(zoneThresholdEntropy, params.RegionEntropyTarget(expansionNum))
	regionDeltaEntropyTarget = new(big.Int).Div(regionDeltaEntropyTarget, common.Big2)

	regionBlockEntropyThreshold := new(big.Int).Add(zoneThresholdEntropy, common.BitsToBigBits(params.RegionEntropyTarget(expansionNum)))
	if intrinsicEntropy.Cmp(regionBlockEntropyThreshold) > 0 && totalDeltaEntropyRegion.Cmp(regionDeltaEntropyTarget) > 0 {
		chain.AddToCalcOrderCache(header.Hash(), common.REGION_CTX, intrinsicEntropy)
		return intrinsicEntropy, common.REGION_CTX, nil
	}

	// Zone case
	chain.AddToCalcOrderCache(header.Hash(), common.ZONE_CTX, intrinsicEntropy)
	return intrinsicEntropy, common.ZONE_CTX, nil
}

// TotalLogEntropy returns the total entropy reduction if the chain since genesis to the given header
func (blake3pow *Blake3pow) TotalLogEntropy(chain consensus.ChainHeaderReader, header *types.WorkObject) *big.Int {
	// Treating the genesis block differntly
	if chain.IsGenesisHash(header.Hash()) {
		return big.NewInt(0)
	}
	intrinsicS, order, err := blake3pow.CalcOrder(chain, header)
	if err != nil {
		blake3pow.logger.WithFields(log.Fields{"err": err, "hash": header.Hash()}).Error("Error calculating order in TotalLogEntropy")
		return big.NewInt(0)
	}
	if blake3pow.NodeLocation().Context() == common.ZONE_CTX {
		workShareS, err := chain.WorkShareLogEntropy(header)
		if err != nil {
			blake3pow.logger.WithFields(log.Fields{"err": err, "hash": header.Hash()}).Error("Error calculating WorkShareLogEntropy in TotalLogEntropy")
			return big.NewInt(0)
		}
		intrinsicS = new(big.Int).Add(intrinsicS, workShareS)
	}
	switch order {
	case common.PRIME_CTX:
		totalS := new(big.Int).Add(header.ParentEntropy(common.PRIME_CTX), header.ParentDeltaEntropy(common.REGION_CTX))
		totalS.Add(totalS, header.ParentDeltaEntropy(common.ZONE_CTX))
		totalS.Add(totalS, intrinsicS)
		return totalS
	case common.REGION_CTX:
		totalS := new(big.Int).Add(header.ParentEntropy(common.REGION_CTX), header.ParentDeltaEntropy(common.ZONE_CTX))
		totalS.Add(totalS, intrinsicS)
		return totalS
	case common.ZONE_CTX:
		totalS := new(big.Int).Add(header.ParentEntropy(common.ZONE_CTX), intrinsicS)
		return totalS
	}
	return big.NewInt(0)
}

func (blake3pow *Blake3pow) DeltaLogEntropy(chain consensus.ChainHeaderReader, header *types.WorkObject) *big.Int {
	// Treating the genesis block differntly
	if chain.IsGenesisHash(header.Hash()) {
		return big.NewInt(0)
	}
	intrinsicS, order, err := blake3pow.CalcOrder(chain, header)
	if err != nil {
		blake3pow.logger.WithFields(log.Fields{"err": err, "hash": header.Hash()}).Error("Error calculating order in DeltaLogEntropy")
		return big.NewInt(0)
	}
	if blake3pow.NodeLocation().Context() == common.ZONE_CTX {
		workShareS, err := chain.WorkShareLogEntropy(header)
		if err != nil {
			blake3pow.logger.WithFields(log.Fields{"err": err, "hash": header.Hash()}).Error("Error calculating WorkShareLogEntropy in DeltaLogEntropy")
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

func (blake3pow *Blake3pow) UncledDeltaLogEntropy(chain consensus.ChainHeaderReader, header *types.WorkObject) *big.Int {
	// Treating the genesis block differntly
	if chain.IsGenesisHash(header.Hash()) {
		return big.NewInt(0)
	}
	_, order, err := blake3pow.CalcOrder(chain, header)
	if err != nil {
		blake3pow.logger.WithField("err", err).Error("Error calculating order in UncledDeltaLogEntropy")
		return big.NewInt(0)
	}
	uncledLogEntropy := header.UncledEntropy()
	switch order {
	case common.PRIME_CTX:
		return big.NewInt(0)
	case common.REGION_CTX:
		totalDeltaEntropy := new(big.Int).Add(header.ParentUncledDeltaEntropy(common.REGION_CTX), header.ParentUncledDeltaEntropy(common.ZONE_CTX))
		totalDeltaEntropy = new(big.Int).Add(totalDeltaEntropy, uncledLogEntropy)
		return totalDeltaEntropy
	case common.ZONE_CTX:
		totalDeltaEntropy := new(big.Int).Add(header.ParentUncledDeltaEntropy(common.ZONE_CTX), uncledLogEntropy)
		return totalDeltaEntropy
	}
	return big.NewInt(0)
}

// CalcRank returns the rank of the block within the hierarchy of chains, this
// determines the level of the interlink
func (blake3pow *Blake3pow) CalcRank(chain consensus.ChainHeaderReader, header *types.WorkObject) (int, error) {
	if chain.IsGenesisHash(header.Hash()) {
		return 0, nil
	}
	_, order, err := blake3pow.CalcOrder(chain, header)
	if err != nil {
		return 0, err
	}
	if order != common.PRIME_CTX {
		return 0, errors.New("rank cannot be computed for a non-prime block")
	}

	powHash := header.Hash()
	target := new(big.Int).Div(common.Big2e256, header.Difficulty())
	zoneThresholdEntropy := common.IntrinsicLogEntropy(common.BytesToHash(target.Bytes()))

	intrinsicEntropy := common.IntrinsicLogEntropy(powHash)
	for i := common.InterlinkDepth; i > 0; i-- {
		extraBits := math.Pow(2, float64(i))
		primeBlockEntropyThreshold := new(big.Int).Add(zoneThresholdEntropy, common.BitsToBigBits(big.NewInt(int64(extraBits))))
		primeBlockEntropyThreshold = new(big.Int).Add(primeBlockEntropyThreshold, common.BitsToBigBits(params.PrimeEntropyTarget(header.ExpansionNumber())))
		if intrinsicEntropy.Cmp(primeBlockEntropyThreshold) > 0 {
			return i, nil
		}
	}

	return 0, nil
}

func (blake3pow *Blake3pow) CheckIfValidWorkShare(workShare *types.WorkObjectHeader) types.WorkShareValidity {
	if workShare.PrimeTerminusNumber().Uint64() < params.KawPowForkBlock {
		thresholdDiff := params.WorkSharesThresholdDiff
		if blake3pow.CheckWorkThreshold(workShare, thresholdDiff) {
			return types.Valid
		} else if blake3pow.CheckWorkThreshold(workShare, blake3pow.config.WorkShareThreshold) {
			return types.Sub
		} else {
			return types.Invalid
		}
	} else {
		// After the fork the workshare is determined by the sha and scrypt share targets
		workshareTarget := new(big.Int).Div(common.Big2e256, core.CalculateKawpowShareDiff(workShare))
		powHash, err := blake3pow.ComputePowHash(workShare)
		if err != nil {
			return types.Invalid
		}
		if new(big.Int).SetBytes(powHash.Bytes()).Cmp(workshareTarget) <= 0 {
			return types.Valid
		} else if blake3pow.CheckWorkThreshold(workShare, blake3pow.config.WorkShareThreshold) {
			return types.Sub
		} else {
			return types.Invalid
		}
	}
}

func (blake3pow *Blake3pow) CheckWorkThreshold(workShare *types.WorkObjectHeader, workShareThresholdDiff int) bool {
	workShareMinTarget, err := consensus.CalcWorkShareThreshold(workShare, workShareThresholdDiff)
	if err != nil {
		return false
	}
	powHash, err := blake3pow.ComputePowHash(workShare)
	if err != nil {
		return false
	}
	return new(big.Int).SetBytes(powHash.Bytes()).Cmp(workShareMinTarget) <= 0
}
