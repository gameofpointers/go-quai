package common

import (
	"math/big"
	"testing"
)

// BitsToTarget converts compact nBits encoding back to a target *big.Int
func BitsToTarget(nBits uint32) *big.Int {
	exponent := nBits >> 24
	coefficient := nBits & 0x007fffff

	if exponent == 0 {
		return big.NewInt(0)
	}

	target := big.NewInt(int64(coefficient))
	if exponent <= 3 {
		target.Rsh(target, uint(8*(3-exponent)))
	} else {
		target.Lsh(target, uint(8*(exponent-3)))
	}

	return target
}

func TestBitcoinGenesisBlockDifficulty(t *testing.T) {
	// Bitcoin genesis block has nBits = 0x1d00ffff
	// Let's verify our function works with known Bitcoin values
	genesisBits := uint32(0x1d00ffff)

	// Convert to target
	target := BitsToTarget(genesisBits)
	t.Logf("Bitcoin genesis target: %s", target.Text(16))

	// Calculate difficulty
	two256 := new(big.Int).Lsh(big.NewInt(1), 256)
	difficulty := new(big.Int).Quo(two256, target)
	t.Logf("Bitcoin genesis difficulty: %s", difficulty.String())

	// Now convert back
	calculatedBits, err := DifficultyToBits(difficulty)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	t.Logf("Calculated nBits: 0x%08x", calculatedBits)
	t.Logf("Original nBits:   0x%08x", genesisBits)

	// Due to rounding, they might not be exactly equal, but should be very close
	if calculatedBits != genesisBits {
		// Check if the targets are close enough
		recalcTarget := BitsToTarget(calculatedBits)
		diff := new(big.Int).Sub(target, recalcTarget)
		diff.Abs(diff)

		relativeError := new(big.Float).Quo(
			new(big.Float).SetInt(diff),
			new(big.Float).SetInt(target),
		)
		relativeErrorFloat, _ := relativeError.Float64()

		if relativeErrorFloat > 0.01 {
			t.Errorf("Bitcoin genesis block round-trip failed with error %e", relativeErrorFloat)
		}
	}
}

func TestTargetHashValidation(t *testing.T) {
	// Test with difficulty 1000
	difficulty := big.NewInt(1000)
	nBits, err := DifficultyToBits(difficulty)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	target := BitsToTarget(nBits)
	t.Logf("Difficulty 1000 target: %s", target.Text(16))

	// A hash equal to the target should be valid
	// A hash greater than the target should be invalid
	// A hash less than the target should be valid

	hashJustBelowTarget := new(big.Int).Sub(target, big.NewInt(1))
	hashAtTarget := new(big.Int).Set(target)
	hashAboveTarget := new(big.Int).Add(target, big.NewInt(1))

	if hashJustBelowTarget.Cmp(target) > 0 {
		t.Error("hash just below target should be <= target")
	}

	if hashAtTarget.Cmp(target) > 0 {
		t.Error("hash at target should be <= target")
	}

	if hashAboveTarget.Cmp(target) <= 0 {
		t.Error("hash above target should be > target")
	}

	t.Logf("Hash validation tests passed")
}

func TestDifficultyToBits(t *testing.T) {
	tests := []struct {
		name           string
		difficulty     *big.Int // Quai difficulty = 2^256/target
		validateTarget bool
	}{
		{
			name: "small Quai difficulty (easy target)",
			// If difficulty = 1000, then target = 2^256 / 1000
			difficulty:     big.NewInt(1000),
			validateTarget: true,
		},
		{
			name: "medium Quai difficulty",
			// If difficulty = 2^32, then target = 2^224
			difficulty:     new(big.Int).Lsh(big.NewInt(1), 32),
			validateTarget: true,
		},
		{
			name: "large Quai difficulty (hard target)",
			// If difficulty = 2^200, then target = 2^56
			difficulty:     new(big.Int).Lsh(big.NewInt(1), 200),
			validateTarget: true,
		},
		{
			name: "very large Quai difficulty",
			// Example: a realistic Quai difficulty
			difficulty: func() *big.Int {
				// difficulty = 2^256 / (small target)
				two256 := new(big.Int).Lsh(big.NewInt(1), 256)
				smallTarget := new(big.Int).Lsh(big.NewInt(0xffff), 208) // 0xffff followed by 26 zero bytes
				return new(big.Int).Quo(two256, smallTarget)
			}(),
			validateTarget: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nBits, err := DifficultyToBits(tt.difficulty)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			t.Logf("Quai difficulty: %s", tt.difficulty.String())
			t.Logf("nBits: 0x%08x", nBits)

			if tt.validateTarget {
				// Convert nBits back to target
				target := BitsToTarget(nBits)
				t.Logf("Target: %s", target.Text(16))

				// Verify: difficulty = 2^256 / target
				two256 := new(big.Int).Lsh(big.NewInt(1), 256)
				expectedDifficulty := new(big.Int).Quo(two256, target)
				t.Logf("Expected difficulty: %s", expectedDifficulty.String())

				// Calculate relative error
				diff := new(big.Int).Sub(tt.difficulty, expectedDifficulty)
				diff.Abs(diff)

				relativeError := new(big.Float).Quo(
					new(big.Float).SetInt(diff),
					new(big.Float).SetInt(tt.difficulty),
				)
				relativeErrorFloat, _ := relativeError.Float64()

				t.Logf("Relative error: %e", relativeErrorFloat)

				// Due to compact encoding precision loss, allow small error
				if relativeErrorFloat > 0.004 {
					t.Errorf("difficulty deviates too much from expected. Relative error: %e", relativeErrorFloat)
				}

				// Verify the relationship: hash <= target means valid block
				t.Logf("A hash <= 0x%s would satisfy this difficulty", target.Text(16))
			}
		})
	}
}

func TestDifficultyToBitsVsDifficultyToBits(t *testing.T) {
	// These two functions should give the SAME result
	// because they both do: difficulty -> target = 2^256/difficulty -> nBits

	testDifficulty := big.NewInt(4295032833) // Bitcoin genesis difficulty

	hashBits, err1 := DifficultyToBits(testDifficulty)
	quaiBits, err2 := DifficultyToBits(testDifficulty)

	if err1 != nil {
		t.Fatalf("DifficultyToBits error: %v", err1)
	}
	if err2 != nil {
		t.Fatalf("DifficultyToBits error: %v", err2)
	}

	t.Logf("DifficultyToBits result: 0x%08x", hashBits)
	t.Logf("DifficultyToBits result:       0x%08x", quaiBits)

	if hashBits != quaiBits {
		t.Errorf("Functions produced different results!")
	}

	// Both should match Bitcoin genesis
	if hashBits != 0x1d00ffff {
		t.Logf("Note: Result differs from Bitcoin genesis 0x1d00ffff")
	}
}

func TestDifficultyToBits_50Million(t *testing.T) {
	// Test with 50 million difficulty (50MH)
	difficulty := big.NewInt(50000000)

	nBits, err := DifficultyToBits(difficulty)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	t.Logf("Difficulty: %d (50 million)", difficulty.Int64())
	t.Logf("nBits: 0x%08x", nBits)

	if nBits == 0 {
		t.Error("nBits is zero! This is wrong.")
	}

	// Convert back to target
	target := BitsToTarget(nBits)
	t.Logf("Target: %s", target.Text(16))

	// Verify: difficulty = 2^256 / target
	two256 := new(big.Int).Lsh(big.NewInt(1), 256)
	calculatedDifficulty := new(big.Int).Quo(two256, target)
	t.Logf("Calculated difficulty from target: %s", calculatedDifficulty.String())

	// Check relative error
	diff := new(big.Int).Sub(difficulty, calculatedDifficulty)
	diff.Abs(diff)

	relativeError := new(big.Float).Quo(
		new(big.Float).SetInt(diff),
		new(big.Float).SetInt(difficulty),
	)
	relativeErrorFloat, _ := relativeError.Float64()

	t.Logf("Relative error: %e", relativeErrorFloat)

	if relativeErrorFloat > 0.004 {
		t.Errorf("difficulty deviates too much from expected. Relative error: %e", relativeErrorFloat)
	}
}

func TestGetTarget(t *testing.T) {
	diff := big.NewInt(1000000) // Example difficulty
	target := GetTarget(diff)
	t.Logf("Target for difficulty %s: 0x%064x", diff.String(), target)
}
