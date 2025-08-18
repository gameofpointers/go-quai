package core

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/dominant-strategies/go-quai/common"
	"github.com/dominant-strategies/go-quai/core/types"
	"github.com/dominant-strategies/go-quai/params"
)

func TestCalculateBetaFromMiningChoiceAndConversions(t *testing.T) {
	// Helper function to create test block
	createTestBlock := func(blockNumber uint64, difficulty int64) *types.WorkObject {
		block := types.EmptyWorkObject(common.PRIME_CTX)
		block.SetNumber(big.NewInt(int64(blockNumber)), common.PRIME_CTX)
		block.Header().SetMinerDifficulty(big.NewInt(difficulty))
		return block
	}

	// Helper function to create token choice set
	createTokenChoiceSet := func(difficulty int64) types.TokenChoiceSet {
		tokenChoiceSet := types.NewTokenChoiceSet()
		tokenChoiceSet[0] = types.TokenChoices{
			Diff: big.NewInt(difficulty),
		}
		return tokenChoiceSet
	}

	initialExchangeRate := big.NewInt(500)
	difficulty := int64(200000)

	t.Run("KQuai Change at Block 3000000 (reset to starting rate)", func(t *testing.T) {
		// Test at the exact KQuaiChangeBlock
		block := createTestBlock(params.KQuaiChangeBlock, difficulty)
		tokenChoiceSet := createTokenChoiceSet(difficulty)

		exchangeRate, err := CalculateBetaFromMiningChoiceAndConversions(nil, block, initialExchangeRate, tokenChoiceSet)
		if err != nil {
			t.Fatalf("Expected no error, got %v", err)
		}

		// At KQuaiChangeBlock, rate should be reset to the starting exchange rate
		expectedRate := params.ExchangeRate
		
		if exchangeRate.Cmp(expectedRate) != 0 {
			t.Errorf("Expected exchange rate %v at KQuaiChangeBlock, got %v", expectedRate, exchangeRate)
		}
		fmt.Printf("KQuaiChangeBlock (%d): Rate reset to starting rate = %v\n", params.KQuaiChangeBlock, exchangeRate)
	})

	t.Run("Hold interval after KQuaiChangeBlock", func(t *testing.T) {
		// First get the reset rate at KQuaiChangeBlock
		block := createTestBlock(params.KQuaiChangeBlock, difficulty)
		tokenChoiceSet := createTokenChoiceSet(difficulty)
		resetRate, _ := CalculateBetaFromMiningChoiceAndConversions(nil, block, initialExchangeRate, tokenChoiceSet)

		// Test various blocks during the hold interval
		holdTestBlocks := []uint64{
			params.KQuaiChangeBlock + 1,
			params.KQuaiChangeBlock + params.KQuaiChangeHoldInterval/2,
			params.KQuaiChangeBlock + params.KQuaiChangeHoldInterval - 1,
		}

		for _, blockNum := range holdTestBlocks {
			block := createTestBlock(blockNum, difficulty)
			tokenChoiceSet := createTokenChoiceSet(difficulty)

			exchangeRate, err := CalculateBetaFromMiningChoiceAndConversions(nil, block, resetRate, tokenChoiceSet)
			if err != nil {
				t.Fatalf("Expected no error at block %d, got %v", blockNum, err)
			}

			// During hold interval, rate should stay at parent rate (reset rate)
			if exchangeRate.Cmp(resetRate) != 0 {
				t.Errorf("Expected exchange rate to be held at %v during hold interval (block %d), got %v", resetRate, blockNum, exchangeRate)
			}
			fmt.Printf("Block %d (hold interval): Rate held at %v\n", blockNum, exchangeRate)
		}
	})

	t.Run("After hold interval ends", func(t *testing.T) {
		// Get the reset rate from KQuaiChangeBlock
		block := createTestBlock(params.KQuaiChangeBlock, difficulty)
		tokenChoiceSet := createTokenChoiceSet(difficulty)
		resetRate, _ := CalculateBetaFromMiningChoiceAndConversions(nil, block, initialExchangeRate, tokenChoiceSet)

		// Test after hold interval ends
		blockAfterHold := params.KQuaiChangeBlock + params.KQuaiChangeHoldInterval
		block = createTestBlock(blockAfterHold, difficulty)
		tokenChoiceSet = createTokenChoiceSet(difficulty)

		exchangeRate, err := CalculateBetaFromMiningChoiceAndConversions(nil, block, resetRate, tokenChoiceSet)
		if err != nil {
			t.Fatalf("Expected no error after hold interval, got %v", err)
		}

		// After hold interval, normal controller logic should resume
		fmt.Printf("Block %d (after hold interval): Rate = %v (normal controller logic)\n", blockAfterHold, exchangeRate)
	})

	t.Run("All KQuai change periods", func(t *testing.T) {
		for i, entry := range params.KQuaiChangeTable {
			changeBlock := entry[0]
			reductionPercent := entry[1]

			t.Run(fmt.Sprintf("Change %d at block %d (%d%% remaining)", i+1, changeBlock, reductionPercent), func(t *testing.T) {
				// Test at the exact change block
				block := createTestBlock(changeBlock, difficulty)
				tokenChoiceSet := createTokenChoiceSet(difficulty)

				exchangeRate, err := CalculateBetaFromMiningChoiceAndConversions(nil, block, initialExchangeRate, tokenChoiceSet)
				if err != nil {
					t.Fatalf("Expected no error at change block %d, got %v", changeBlock, err)
				}

				var expectedRate *big.Int
				if changeBlock == params.KQuaiChangeBlock {
					// At the first KQuaiChangeBlock, reset to starting exchange rate
					expectedRate = params.ExchangeRate
					fmt.Printf("Change block %d: Rate reset to starting rate = %v\n", changeBlock, exchangeRate)
				} else {
					// For subsequent changes, apply percentage reduction
					expectedRate = new(big.Int).Mul(initialExchangeRate, big.NewInt(int64(reductionPercent)))
					expectedRate = new(big.Int).Div(expectedRate, big.NewInt(100))
					fmt.Printf("Change block %d: Rate reduced to %d%% = %v\n", changeBlock, reductionPercent, exchangeRate)
				}

				if exchangeRate.Cmp(expectedRate) != 0 {
					t.Errorf("Expected exchange rate %v at change block %d, got %v", expectedRate, changeBlock, exchangeRate)
				}

				// Test during hold interval after this change
				holdBlock := changeBlock + params.KQuaiChangeHoldInterval/2
				block = createTestBlock(holdBlock, difficulty)
				tokenChoiceSet = createTokenChoiceSet(difficulty)

				heldRate, err := CalculateBetaFromMiningChoiceAndConversions(nil, block, exchangeRate, tokenChoiceSet)
				if err != nil {
					t.Fatalf("Expected no error during hold interval at block %d, got %v", holdBlock, err)
				}

				if heldRate.Cmp(exchangeRate) != 0 {
					t.Errorf("Expected rate to be held at %v during hold interval (block %d), got %v", exchangeRate, holdBlock, heldRate)
				}
				fmt.Printf("Hold interval block %d: Rate held at %v\n", holdBlock, heldRate)

				// Test after hold interval ends
				afterHoldBlock := changeBlock + params.KQuaiChangeHoldInterval
				block = createTestBlock(afterHoldBlock, difficulty)
				tokenChoiceSet = createTokenChoiceSet(difficulty)

				afterHoldRate, err := CalculateBetaFromMiningChoiceAndConversions(nil, block, exchangeRate, tokenChoiceSet)
				if err != nil {
					t.Fatalf("Expected no error after hold interval at block %d, got %v", afterHoldBlock, err)
				}

				fmt.Printf("After hold interval block %d: Rate = %v (normal logic resumed)\n", afterHoldBlock, afterHoldRate)
			})
		}
	})

	t.Run("Edge cases and boundary conditions", func(t *testing.T) {
		// Test block just before KQuaiChangeBlock
		block := createTestBlock(params.KQuaiChangeBlock-1, difficulty)
		tokenChoiceSet := createTokenChoiceSet(difficulty)

		exchangeRate, err := CalculateBetaFromMiningChoiceAndConversions(nil, block, initialExchangeRate, tokenChoiceSet)
		if err != nil {
			t.Fatalf("Expected no error before KQuaiChangeBlock, got %v", err)
		}
		fmt.Printf("Block %d (before KQuaiChangeBlock): Rate = %v (normal logic)\n", params.KQuaiChangeBlock-1, exchangeRate)

		// Test at exact end of hold interval
		holdEndBlock := params.KQuaiChangeBlock + params.KQuaiChangeHoldInterval - 1
		block = createTestBlock(holdEndBlock, difficulty)
		tokenChoiceSet = createTokenChoiceSet(difficulty)

		// First get the reset rate
		changeBlock := createTestBlock(params.KQuaiChangeBlock, difficulty)
		changeTokenChoiceSet := createTokenChoiceSet(difficulty)
		resetRate, _ := CalculateBetaFromMiningChoiceAndConversions(nil, changeBlock, initialExchangeRate, changeTokenChoiceSet)

		heldRate, err := CalculateBetaFromMiningChoiceAndConversions(nil, block, resetRate, tokenChoiceSet)
		if err != nil {
			t.Fatalf("Expected no error at end of hold interval, got %v", err)
		}

		if heldRate.Cmp(resetRate) != 0 {
			t.Errorf("Expected rate to be held at %v at end of hold interval (block %d), got %v", resetRate, holdEndBlock, heldRate)
		}
		fmt.Printf("Block %d (last block of hold interval): Rate held at %v\n", holdEndBlock, heldRate)
	})

	t.Run("Chained KQuai changes with realistic parent rates", func(t *testing.T) {
		// This test verifies the logic with realistic parent rates for subsequent changes
		parentRate := initialExchangeRate

		// First change: Reset at KQuaiChangeBlock
		block := createTestBlock(params.KQuaiChangeBlock, difficulty)
		tokenChoiceSet := createTokenChoiceSet(difficulty)
		
		exchangeRate1, err := CalculateBetaFromMiningChoiceAndConversions(nil, block, parentRate, tokenChoiceSet)
		if err != nil {
			t.Fatalf("Expected no error at first change, got %v", err)
		}
		
		// Should be reset to starting exchange rate
		if exchangeRate1.Cmp(params.ExchangeRate) != 0 {
			t.Errorf("Expected first change to reset to %v, got %v", params.ExchangeRate, exchangeRate1)
		}
		
		t.Logf("First change (block %d): %v → %v (reset)", params.KQuaiChangeBlock, parentRate, exchangeRate1)
		
		// Simulate time passing - use the reset rate as parent for the next change
		// In reality, this would be after the hold period and some controller adjustments
		parentRate = exchangeRate1
		
		// Second change: 75% reduction at block 3,259,200
		secondChangeBlock := params.KQuaiChangeTable[1][0]
		block = createTestBlock(secondChangeBlock, difficulty)
		tokenChoiceSet = createTokenChoiceSet(difficulty)
		
		exchangeRate2, err := CalculateBetaFromMiningChoiceAndConversions(nil, block, parentRate, tokenChoiceSet)
		if err != nil {
			t.Fatalf("Expected no error at second change, got %v", err)
		}
		
		// Should be 75% of the parent rate
		expectedRate2 := new(big.Int).Mul(parentRate, big.NewInt(75))
		expectedRate2 = new(big.Int).Div(expectedRate2, big.NewInt(100))
		
		if exchangeRate2.Cmp(expectedRate2) != 0 {
			t.Errorf("Expected second change to be %v, got %v", expectedRate2, exchangeRate2)
		}
		
		t.Logf("Second change (block %d): %v → %v (75%% reduction)", secondChangeBlock, parentRate, exchangeRate2)
		
		// Verify the magnitude difference
		ratio := new(big.Float).Quo(new(big.Float).SetInt(parentRate), new(big.Float).SetInt(exchangeRate2))
		expectedRatio := 1.0 / 0.75 // Should be about 1.33
		ratioFloat, _ := ratio.Float64()
		
		if ratioFloat < expectedRatio-0.1 || ratioFloat > expectedRatio+0.1 {
			t.Errorf("Expected reduction ratio around %.2f, got %.2f", expectedRatio, ratioFloat)
		}
		
		t.Logf("Reduction ratio: %.2f (expected ~%.2f)", ratioFloat, expectedRatio)
	})
}
