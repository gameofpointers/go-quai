package types

import (
	"encoding/hex"
	"testing"

	"github.com/dominant-strategies/go-quai/common"
)

func TestCoinbaseWithExtraData(t *testing.T) {
	// Test data
	blockHeight := uint32(680000)
	extraData := []byte("Quai Network - Block mined with extra data!")
	minerAddress, _ := hex.DecodeString("76a914" + "89abcdefabbaabbaabbaabbaabbaabbaabbaabba" + "88ac") // P2PKH script
	blockReward := int64(5000000000) // 50 RVN in satoshis

	// Create coinbase transaction
	coinbase := CreateCoinbaseTransaction(blockHeight, extraData, minerAddress, blockReward)

	t.Logf("Coinbase transaction created:")
	t.Logf("  Hash: %s", coinbase.Hash().Hex())
	t.Logf("  ScriptSig length: %d bytes", len(coinbase.Inputs[0].ScriptSig))
	t.Logf("  ScriptSig hex: %x", coinbase.Inputs[0].ScriptSig)

	// Verify the coinbase properties
	if len(coinbase.Inputs) != 1 {
		t.Errorf("Expected 1 input, got %d", len(coinbase.Inputs))
	}
	if len(coinbase.Outputs) != 1 {
		t.Errorf("Expected 1 output, got %d", len(coinbase.Outputs))
	}

	// Check that previous output is null (coinbase marker)
	nullHash := common.Hash{}
	if coinbase.Inputs[0].PreviousOutput.Hash != nullHash {
		t.Errorf("Expected null hash for coinbase input")
	}
	if coinbase.Inputs[0].PreviousOutput.Index != 0xFFFFFFFF {
		t.Errorf("Expected 0xFFFFFFFF index for coinbase input, got %x", coinbase.Inputs[0].PreviousOutput.Index)
	}

	// Check output value
	if coinbase.Outputs[0].Value != blockReward {
		t.Errorf("Expected block reward %d, got %d", blockReward, coinbase.Outputs[0].Value)
	}
}

func TestMerkleRootCalculation(t *testing.T) {
	// Create a block with coinbase + extra data
	prevBlockHash := common.HexToHash("0000000000000000000a8c1f4e0a4e8e9a7b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6")
	blockHeight := uint32(680001)
	timestamp := uint32(1640995200) // 2022-01-01
	bits := uint32(0x1d00ffff)      // Difficulty target
	extraData := []byte("Quai Network Integration Test")
	minerAddress, _ := hex.DecodeString("76a914" + "1234567890abcdef1234567890abcdef12345678" + "88ac")
	blockReward := int64(5000000000)

	// Create some additional transactions (simplified)
	additionalTxs := []*RavencoinTransaction{
		{
			Version: 1,
			Inputs: []RavencoinTransactionIn{
				{
					PreviousOutput: RavencoinOutPoint{
						Hash:  common.HexToHash("abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"),
						Index: 0,
					},
					ScriptSig: []byte{0x47, 0x30, 0x44}, // Simplified signature
					Sequence:  0xFFFFFFFF,
				},
			},
			Outputs: []RavencoinTransactionOut{
				{
					Value:        1000000000, // 10 RVN
					ScriptPubKey: minerAddress,
				},
			},
			LockTime: 0,
		},
	}

	// Create block with extra data
	header, transactions := CreateRavencoinBlockWithExtraData(
		prevBlockHash,
		blockHeight,
		timestamp,
		bits,
		extraData,
		minerAddress,
		blockReward,
		additionalTxs,
	)

	t.Logf("Block created:")
	t.Logf("  Height: %d", header.Height)
	t.Logf("  Merkle Root: %s", header.HashMerkleRoot.Hex())
	t.Logf("  Transaction count: %d", len(transactions))
	t.Logf("  Coinbase hash: %s", transactions[0].Hash().Hex())

	// Verify merkle root calculation
	calculatedRoot := CalculateMerkleRoot(transactions)
	if calculatedRoot != header.HashMerkleRoot {
		t.Errorf("Merkle root mismatch. Expected %s, got %s",
			header.HashMerkleRoot.Hex(), calculatedRoot.Hex())
	}

	// Verify coinbase contains extra data
	coinbase := transactions[0]
	scriptSig := coinbase.Inputs[0].ScriptSig

	// The scriptSig should contain the block height and extra data
	if len(scriptSig) < len(extraData) {
		t.Errorf("ScriptSig too short to contain extra data")
	}

	t.Logf("  Coinbase ScriptSig: %x", scriptSig)
	t.Logf("  Extra data: %x", extraData)
}

func TestMerkleTreeWithSingleTransaction(t *testing.T) {
	// Test edge case: single transaction (coinbase only)
	coinbase := CreateCoinbaseTransaction(1, []byte("test"), []byte{0x76, 0xa9, 0x14}, 5000000000)
	transactions := []*RavencoinTransaction{coinbase}

	merkleRoot := CalculateMerkleRoot(transactions)
	expectedRoot := coinbase.Hash()

	if merkleRoot != expectedRoot {
		t.Errorf("Single transaction merkle root mismatch. Expected %s, got %s",
			expectedRoot.Hex(), merkleRoot.Hex())
	}
}

func TestMerkleTreeWithOddNumberOfTransactions(t *testing.T) {
	// Test with 3 transactions (odd number)
	coinbase := CreateCoinbaseTransaction(1, []byte("test"), []byte{0x76, 0xa9, 0x14}, 5000000000)

	tx1 := &RavencoinTransaction{
		Version: 1,
		Inputs: []RavencoinTransactionIn{
			{
				PreviousOutput: RavencoinOutPoint{Hash: common.HexToHash("abc123"), Index: 0},
				ScriptSig:      []byte{0x01, 0x02, 0x03},
				Sequence:       0xFFFFFFFF,
			},
		},
		Outputs: []RavencoinTransactionOut{
			{Value: 1000000, ScriptPubKey: []byte{0x76, 0xa9, 0x14}},
		},
		LockTime: 0,
	}

	tx2 := &RavencoinTransaction{
		Version: 1,
		Inputs: []RavencoinTransactionIn{
			{
				PreviousOutput: RavencoinOutPoint{Hash: common.HexToHash("def456"), Index: 1},
				ScriptSig:      []byte{0x04, 0x05, 0x06},
				Sequence:       0xFFFFFFFF,
			},
		},
		Outputs: []RavencoinTransactionOut{
			{Value: 2000000, ScriptPubKey: []byte{0x76, 0xa9, 0x14}},
		},
		LockTime: 0,
	}

	transactions := []*RavencoinTransaction{coinbase, tx1, tx2}
	merkleRoot := CalculateMerkleRoot(transactions)

	// Should not panic and should produce a valid hash
	if merkleRoot == (common.Hash{}) {
		t.Error("Merkle root should not be empty for valid transactions")
	}

	t.Logf("Merkle root for 3 transactions: %s", merkleRoot.Hex())
}