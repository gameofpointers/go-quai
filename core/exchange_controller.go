package core

import (
	"errors"
	"math/big"
	"sort"

	"github.com/dominant-strategies/go-quai/common"
	"github.com/dominant-strategies/go-quai/consensus/misc"
	"github.com/dominant-strategies/go-quai/core/rawdb"
	"github.com/dominant-strategies/go-quai/core/types"
	"github.com/dominant-strategies/go-quai/params"
)

func CalculateBetaFromMiningChoiceAndConversions(hc *HeaderChain, block *types.WorkObject, newTokenChoiceSet types.TokenChoiceSet) (*big.Int, *big.Float, *big.Float, error) {
	betas := rawdb.ReadBetas(hc.headerDb, block.Hash())
	if betas == nil {
		return nil, nil, nil, errors.New("could not find the betas stored for parent hash")
	}

	if block.NumberU64(common.ZONE_CTX) < types.C_tokenChoiceSetSize {
		return params.ExchangeRate, betas.Beta0(), betas.Beta1(), nil
	}

	var totalQiChoices uint64 = 0
	var totalQuaiChoices uint64 = 0

	tokenChoicesSet := make([]types.TokenChoices, 0)
	for _, tokenChoices := range newTokenChoiceSet {
		totalQuaiChoices += tokenChoices.Quai
		totalQiChoices += tokenChoices.Qi
		tokenChoicesSet = append(tokenChoicesSet, tokenChoices)
	}

	sort.Slice(tokenChoicesSet, func(i, j int) bool {
		return tokenChoicesSet[i].Diff.Cmp(tokenChoicesSet[j].Diff) < 0
	})

	bestScore := uint64(0)
	bestDiff := big.NewInt(0)

	var left_zeros, right_zeros, left_ones, right_ones uint64 = 0, 0, 0, 0
	// once the tokenchoices set is sorted the difficulty values are looked from
	// smallest to the largest. The goal of this algorithm is to find the difficulty point
	// at which the number of choices of Qi and Quai are equal
	for i, choice := range tokenChoicesSet {
		left_zeros = left_zeros + choice.Quai
		right_zeros = totalQuaiChoices - left_zeros

		left_ones = left_ones + choice.Qi
		right_ones = totalQiChoices - left_ones

		score := left_zeros - right_zeros + right_ones - left_ones
		if i == 0 {
			bestDiff = new(big.Int).Set(choice.Diff)
			bestScore = score
		} else {
			if score > bestScore {
				bestScore = score
				bestDiff = new(big.Int).Set(choice.Diff)
			}
		}
	}
	// Note: All the calculations below assume that the beta1 is constant and it
	// is not changed per block

	// Firstly calculated the new beta from the best diff calculated from the previous step
	// Since, -B0/B1 = diff/log(diff)
	newBeta0 := new(big.Float).Mul(betas.Beta1(), new(big.Float).SetInt(bestDiff))
	newBeta0 = new(big.Float).Quo(newBeta0, new(big.Float).SetInt(common.LogBig(bestDiff)))
	newBeta0 = new(big.Float).Mul(newBeta0, big.NewFloat(-1))

	// Beta to be used for the calculation of the exchange rate is the moving
	// average value so that large changes in the beta value can be smoothed out
	beta0 := new(big.Float).Add(new(big.Float).Mul(big.NewFloat(99), betas.Beta0()), new(big.Float).Mul(big.NewFloat(1), newBeta0))
	newBeta0 = new(big.Float).Quo(beta0, big.NewFloat(100))

	// convert the beta values into the big numbers so that in the exchange rate
	// computation
	bigBeta0 := new(big.Float).Mul(newBeta0, new(big.Float).SetInt(common.Big2e64))
	bigBeta0Int, _ := bigBeta0.Int(nil)
	bigBeta1 := new(big.Float).Mul(betas.Beta1(), new(big.Float).SetInt(common.Big2e64))
	bigBeta1Int, _ := bigBeta1.Int(nil)

	// If parent is genesis, there is nothing to train
	exchangeRate := misc.CalculateKQuai(block, bigBeta0Int, bigBeta1Int)

	return exchangeRate, newBeta0, betas.Beta1(), nil
}

// CalculateTokenChoicesSet reads the block token choices set and adds in the
// choices generated in the current block
func CalculateTokenChoicesSet(hc *HeaderChain, block *types.WorkObject, etxs types.Transactions) (types.TokenChoiceSet, error) {
	// If the parent is genesis return an empty set
	if block.Hash() == hc.config.DefaultGenesisHash {
		return types.NewTokenChoiceSet(), nil
	}

	// Look up prior tokenChoiceSet and update
	parentTokenChoicesSet := rawdb.ReadTokenChoicesSet(hc.headerDb, block.ParentHash(common.ZONE_CTX))
	if parentTokenChoicesSet == nil {
		return types.TokenChoiceSet{}, errors.New("cannot find the token choice set for the parent hash")
	}

	tokenChoices := types.TokenChoices{Quai: 0, Qi: 0, Diff: block.Difficulty()}

	for _, tx := range etxs {
		if types.IsCoinBaseTx(tx) {
			if tx.To().IsInQiLedgerScope() {
				tokenChoices.Qi++
			} else if tx.To().IsInQuaiLedgerScope() {
				tokenChoices.Quai++
			}
		} else if types.IsConversionTx(tx) {
			if tx.To().IsInQiLedgerScope() {
				tokenChoices.Qi += NormalizeConversionValueToBlock(block, tx.Value(), true)
			} else if tx.To().IsInQuaiLedgerScope() {
				tokenChoices.Quai += NormalizeConversionValueToBlock(block, tx.Value(), false)
			}
		}
	}

	newTokenChoiceSet := types.NewTokenChoiceSet()

	// Until block number 100 is reached, we need to just accumulate to the
	// set and then after block 100 we trim and add the new element
	if block.NumberU64(common.ZONE_CTX) <= types.C_tokenChoiceSetSize {
		if hc.IsGenesisHash(block.ParentHash(common.ZONE_CTX)) { // parent is genesis
			newTokenChoiceSet[0] = tokenChoices
		} else {
			// go through the parent token choice set and copy it to the new
			// token choice set
			for i, prevTokenChoices := range *parentTokenChoicesSet {
				// TODO: can cut this short using parent Number
				newTokenChoiceSet[i] = prevTokenChoices
			}
			// add the elements from the current block at the end
			newTokenChoiceSet[block.NumberU64(common.ZONE_CTX)-1] = tokenChoices
		}
	} else {
		// Once block 100 is reached, the first element in the token set has
		// to be discarded and the current block elements have to appended
		// at the end
		for i, prevTokenChoices := range *parentTokenChoicesSet {
			if i > 0 {
				newTokenChoiceSet[i-1] = prevTokenChoices
			}
		}
		// Last element is set to the current block choices
		newTokenChoiceSet[types.C_tokenChoiceSetSize-1] = tokenChoices
	}

	return newTokenChoiceSet, nil
}

func NormalizeConversionValueToBlock(block *types.WorkObject, value *big.Int, chooseQi bool) uint64 {
	var reward *big.Int
	if chooseQi {
		reward = misc.CalculateQiReward(block.WorkObjectHeader())
	} else {
		reward = misc.CalculateQuaiReward(block)
	}

	numBlocks := int(new(big.Int).Quo(value, reward).Uint64())
	return uint64(numBlocks)
}
