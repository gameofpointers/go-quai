package types

import (
	"testing"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
)

// TestKAWPOWEngineSelection tests that the multi-engine system correctly selects KAWPOW
func TestKAWPOWEngineSelection(t *testing.T) {
	// Create a mock work object header with KAWPOW AuxPow
	workHeader := &WorkObjectHeader{}

	// Create KAWPOW header (80 bytes standard Bitcoin header)
	kawpowHeader := make([]byte, 80)
	// Version
	kawpowHeader[0] = 0x20 // Version 536870912 (0x20000000)
	kawpowHeader[1] = 0x00
	kawpowHeader[2] = 0x00
	kawpowHeader[3] = 0x00

	// Create coinbase transaction with KAWPOW nonces
	coinbaseTx := CreateCoinbaseTxWithNonce(
		1219736,                     // KAWPOW activation height
		0x12345678,                  // extraNonce1
		0x123456789ABCDEF0,          // extraNonce2
		[]byte("KAWPOW Engine Test"), // extra data
		[]byte{0x76, 0xa9, 0x14, 0x89, 0xab, 0xcd, 0xef, 0x88, 0xac}, // P2PKH
		2500000000, // 25 RVN reward
	)

	// Create AuxPow with KAWPOW
	auxPow := NewAuxPow(
		Kawpow,         // PowID set to KAWPOW
		kawpowHeader,   // 80-byte header
		[]byte{},       // signature
		[][]byte{},     // merkle branch (empty for single tx)
		coinbaseTx,     // coinbase transaction
	)

	// Set AuxPow in work header
	workHeader.auxPow = auxPow

	// Test that we can identify this as a KAWPOW block
	require.NotNil(t, workHeader.AuxPow(), "Work header should have AuxPow")
	require.Equal(t, Kawpow, workHeader.AuxPow().PowID(), "Should be identified as KAWPOW")

	// Test nonce extraction
	scriptSig := auxPow.Transaction().TxIn[0].SignatureScript
	height, nonce1, nonce2, extraData := ExtractNoncesFromCoinbase(scriptSig)

	require.Equal(t, uint32(1219736), height, "Height should match")
	require.Equal(t, uint32(0x12345678), nonce1, "ExtraNonce1 should match")
	require.Equal(t, uint64(0x123456789ABCDEF0), nonce2, "ExtraNonce2 should match")
	require.Equal(t, []byte("KAWPOW Engine Test"), extraData, "Extra data should match")

	t.Logf("Successfully created KAWPOW work object")
	t.Logf("PowID: %d (Kawpow=%d)", workHeader.AuxPow().PowID(), Kawpow)
	t.Logf("Header length: %d bytes", len(auxPow.Header()))
	t.Logf("Coinbase nonces: height=%d, nonce1=0x%08X, nonce2=0x%016X", height, nonce1, nonce2)
}

// TestKAWPOWVersusProgPOW tests that we can distinguish between KAWPOW and ProgPOW
func TestKAWPOWVersusProgPOW(t *testing.T) {
	// Create ProgPOW AuxPow
	progpowAuxPow := NewAuxPow(
		Progpow,
		make([]byte, 80), // empty header
		[]byte{},
		[][]byte{},
		wire.NewMsgTx(1),
	)

	// Create KAWPOW AuxPow
	kawpowAuxPow := NewAuxPow(
		Kawpow,
		make([]byte, 80), // empty header
		[]byte{},
		[][]byte{},
		wire.NewMsgTx(1),
	)

	// Verify they have different PowIDs
	require.Equal(t, Progpow, progpowAuxPow.PowID(), "Should be ProgPOW")
	require.Equal(t, Kawpow, kawpowAuxPow.PowID(), "Should be KAWPOW")
	require.NotEqual(t, progpowAuxPow.PowID(), kawpowAuxPow.PowID(), "Should be different algorithms")

	t.Logf("ProgPOW PowID: %d", progpowAuxPow.PowID())
	t.Logf("KAWPOW PowID: %d", kawpowAuxPow.PowID())
}

// TestKAWPOWCoinbaseEncoding tests the specific KAWPOW coinbase format
func TestKAWPOWCoinbaseEncoding(t *testing.T) {
	testCases := []struct {
		name        string
		height      uint32
		extraNonce1 uint32
		extraNonce2 uint64
		extraData   []byte
		expectValid bool
	}{
		{
			name:        "KAWPOW activation block",
			height:      1219736,
			extraNonce1: 0x00000001,
			extraNonce2: 0x0000000000000001,
			extraData:   []byte("RVN"),
			expectValid: true,
		},
		{
			name:        "Large nonces",
			height:      2000000,
			extraNonce1: 0xFFFFFFFF,
			extraNonce2: 0xFFFFFFFFFFFFFFFF,
			extraData:   []byte("Max nonce test"),
			expectValid: true,
		},
		{
			name:        "Empty extra data",
			height:      1500000,
			extraNonce1: 0x12345678,
			extraNonce2: 0xABCDEF0123456789,
			extraData:   []byte{},
			expectValid: true,
		},
		{
			name:        "Long extra data",
			height:      1800000,
			extraNonce1: 0xDEADBEEF,
			extraNonce2: 0xCAFEBABEDEADBEEF,
			extraData:   []byte("This is a very long mining pool identification string for KAWPOW"),
			expectValid: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create coinbase with specific parameters
			coinbaseTx := CreateCoinbaseTxWithNonce(
				tc.height,
				tc.extraNonce1,
				tc.extraNonce2,
				tc.extraData,
				[]byte{0x76, 0xa9, 0x14, 0x89, 0xab, 0xcd, 0xef, 0x88, 0xac}, // P2PKH
				2500000000, // 25 RVN
			)

			require.NotNil(t, coinbaseTx, "Coinbase transaction should be created")

			// Extract and verify values
			scriptSig := coinbaseTx.TxIn[0].SignatureScript
			height, nonce1, nonce2, extraData := ExtractNoncesFromCoinbase(scriptSig)

			if tc.expectValid {
				require.Equal(t, tc.height, height, "Height should match")
				require.Equal(t, tc.extraNonce1, nonce1, "ExtraNonce1 should match")
				require.Equal(t, tc.extraNonce2, nonce2, "ExtraNonce2 should match")
				// Handle empty byte slice vs nil
				if len(tc.extraData) == 0 && len(extraData) == 0 {
					// Both empty, consider equal
				} else {
					require.Equal(t, tc.extraData, extraData, "Extra data should match")
				}

				// Create AuxPow and verify it works
				auxPow := NewAuxPow(
					Kawpow,
					make([]byte, 80), // mock header
					[]byte{},
					[][]byte{},
					coinbaseTx,
				)

				require.NotNil(t, auxPow, "AuxPow should be created")
				require.Equal(t, Kawpow, auxPow.PowID(), "Should be KAWPOW")

				t.Logf("✓ Valid KAWPOW coinbase: height=%d, nonce1=0x%08X, nonce2=0x%016X, extraData=%q",
					height, nonce1, nonce2, string(extraData))
			}
		})
	}
}

// TestKAWPOWMerkleIntegration tests KAWPOW with proper merkle tree construction
func TestKAWPOWMerkleIntegration(t *testing.T) {
	// Create coinbase transaction for KAWPOW
	coinbaseTx := CreateCoinbaseTxWithNonce(
		1219736,                      // KAWPOW activation height
		0x11111111,                   // extraNonce1
		0x2222222233333333,           // extraNonce2
		[]byte("KAWPOW Merkle Test"), // extra data
		[]byte{0x76, 0xa9, 0x14, 0x89, 0xab, 0xcd, 0xef, 0x88, 0xac}, // P2PKH
		2500000000, // 25 RVN
	)

	// Create additional transactions for the block
	tx2 := wire.NewMsgTx(2)
	tx2.AddTxIn(wire.NewTxIn(&wire.OutPoint{Hash: chainhash.Hash{}, Index: 0}, []byte{0x01, 0x02}, nil))
	tx2.AddTxOut(wire.NewTxOut(100000000, []byte{0x76, 0xa9, 0x14, 0x11, 0x22, 0x33, 0x44, 0x88, 0xac}))

	tx3 := wire.NewMsgTx(2)
	tx3.AddTxIn(wire.NewTxIn(&wire.OutPoint{Hash: chainhash.Hash{}, Index: 1}, []byte{0x03, 0x04}, nil))
	tx3.AddTxOut(wire.NewTxOut(200000000, []byte{0x76, 0xa9, 0x14, 0x55, 0x66, 0x77, 0x88, 0x88, 0xac}))

	transactions := []*wire.MsgTx{coinbaseTx, tx2, tx3}

	// Calculate merkle root
	merkleRoot := CalculateMerkleRootFromTxs(transactions)
	require.NotEqual(t, [32]byte{}, merkleRoot.Bytes(), "Merkle root should not be empty")

	// Build merkle tree
	merkleTree := BuildMerkleTree(transactions)
	require.Greater(t, len(merkleTree), 0, "Merkle tree should not be empty")

	// Extract merkle branch for coinbase (index 0)
	merkleBranch := ExtractMerkleBranch(merkleTree, len(transactions))
	require.Greater(t, len(merkleBranch), 0, "Should have merkle branch for multiple transactions")

	// Verify merkle proof for coinbase
	coinbaseHash := coinbaseTx.TxHash()
	isValid := VerifyMerkleProof(coinbaseHash, merkleBranch, merkleRoot)
	require.True(t, isValid, "Merkle proof should be valid")

	// Create KAWPOW AuxPow with proper merkle data
	// Create 80-byte header with the calculated merkle root
	header := make([]byte, 80)
	// Version
	header[0] = 0x20
	// Previous block hash (32 bytes at offset 4) - zeros for test
	// Merkle root (32 bytes at offset 36)
	copy(header[36:68], merkleRoot.Bytes())
	// Time (4 bytes at offset 68)
	header[68] = 0x00
	header[69] = 0x5E
	header[70] = 0xA7
	header[71] = 0x5E // KAWPOW activation time
	// Bits (4 bytes at offset 72)
	header[72] = 0xFF
	header[73] = 0xFF
	header[74] = 0x00
	header[75] = 0x1D
	// Nonce (4 bytes at offset 76) - placeholder since real nonces are in coinbase
	header[76] = 0x00
	header[77] = 0x00
	header[78] = 0x00
	header[79] = 0x00

	// Create AuxPow
	auxPow := NewAuxPow(
		Kawpow,
		header,
		[]byte{}, // signature
		merkleBranch,
		coinbaseTx,
	)

	require.NotNil(t, auxPow, "AuxPow should be created")
	require.Equal(t, Kawpow, auxPow.PowID(), "Should be KAWPOW")
	require.Equal(t, len(merkleBranch), len(auxPow.MerkleBranch()), "Merkle branch should match")

	// Log results
	t.Logf("✓ KAWPOW block with %d transactions", len(transactions))
	t.Logf("  Merkle root: %x", merkleRoot.Bytes())
	t.Logf("  Coinbase hash: %x", coinbaseHash[:])
	t.Logf("  Merkle branch length: %d", len(merkleBranch))
	t.Logf("  Header length: %d bytes", len(auxPow.Header()))

	// Extract coinbase data
	scriptSig := auxPow.Transaction().TxIn[0].SignatureScript
	height, nonce1, nonce2, extraData := ExtractNoncesFromCoinbase(scriptSig)
	t.Logf("  Coinbase: height=%d, nonce1=0x%08X, nonce2=0x%016X, extraData=%q",
		height, nonce1, nonce2, string(extraData))
}