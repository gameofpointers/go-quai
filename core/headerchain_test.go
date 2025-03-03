package core

import (
	"math/big"
	"testing"

	"github.com/dominant-strategies/go-quai/common"
	"github.com/dominant-strategies/go-quai/core/rawdb"
	"github.com/dominant-strategies/go-quai/core/types"
	"github.com/dominant-strategies/go-quai/log"
	"github.com/stretchr/testify/require"
)

func TestComputeKQuaiDiscount(t *testing.T) {

	// First value is the current block(1001) exchange rate
	// Second value is the block 1 exchange rate
	// Third value is the expected kQuai discount value given the starting
	// kQuaiDiscount of 50
	testcases := [][3]int64{{10000, 200000, 149}, {10000, 9000, 59}}
	startingKQuaiDiscount := big.NewInt(50)

	for _, test := range testcases {
		block := types.EmptyWorkObject(common.PRIME_CTX)
		blockNumber := big.NewInt(1001)
		block.Header().SetKQuaiDiscount(startingKQuaiDiscount)
		block.Header().SetNumber(blockNumber, common.PRIME_CTX)

		hc := NewTestHeaderChain()
		// Create a new header db
		hc.headerDb = rawdb.NewMemoryDatabase(log.Global)
		hc.bc = NewTestBodyDb(hc.headerDb)

		blockOne := types.EmptyWorkObject(common.PRIME_CTX)
		blockOne.Header().SetNumber(common.Big1, common.PRIME_CTX)
		blockOne.Header().SetExchangeRate(big.NewInt(test[0]))

		rawdb.WriteTermini(hc.headerDb, blockOne.Hash(), types.EmptyTermini())
		rawdb.WriteCanonicalHash(hc.headerDb, blockOne.Hash(), 1)
		rawdb.WriteWorkObject(hc.headerDb, blockOne.Hash(), blockOne, types.BlockObject, common.PRIME_CTX)

		computedKQuaiDiscount := hc.ComputeKQuaiDiscount(block, big.NewInt(test[1]))

		require.Equal(t, test[2], computedKQuaiDiscount.Int64())
	}
}

func TestApplyQuadraticDiscount(t *testing.T) {

	hc := NewTestHeaderChain()

	testCases := [][3]int64{
		{100, 10000, 0}, // If the value is more than 10 times the average, the realized amount should be zero
		{100, 90, 89},   // If the value is less than average the realized amount is 99% of the value
		{100, 100, 99},  // If the value is exactly the average, there is 1% slip
		{100, 150, 146},
		{100, 1000, 0},           // If the value is 10 times the average, 50% of the value is lost
		{10000000, 100000000, 0}, // If the value is 10 times the average, 50% of the value is lost
		{100, 1001, 0},
		{100, 999, 1},
		{0, 0, 0},
	}

	for _, test := range testCases {
		discountedValue := hc.ApplyQuadraticDiscount(big.NewInt(test[1]), big.NewInt(test[0]))
		discountedValueInt, _ := discountedValue.Int64()
		require.Equal(t, test[2], discountedValueInt)
	}

}
