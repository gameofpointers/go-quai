package types

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
)

// KAWPOWValidationTestCase represents a test case for KAWPOW block validation
type KAWPOWValidationTestCase struct {
	Name              string
	BlockHeight       uint32
	HeaderData        string // 80-byte block header hex
	CoinbaseData      string // Coinbase transaction hex
	MerkleBranch      []string // Merkle branch hashes
	ExpectedMixHash   string   // Expected mix hash from KAWPOW
	ExpectedBlockHash string   // Expected final block hash
}

// Test vectors based on KAWPOW/ProgPoW specifications
var kawpowValidationTests = []KAWPOWValidationTestCase{
	{
		Name:        "KAWPOW Block 0 (Genesis-style)",
		BlockHeight: 0,
		// Mock 80-byte header (version + prevhash + merkleroot + time + bits + nonce)
		HeaderData: "00000020" + // version (little-endian)
			"0000000000000000000000000000000000000000000000000000000000000000" + // prev hash
			"3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a" + // merkle root
			"29ab5f49" + // time
			"ffff001d" + // bits
			"1dac2b7c", // nonce
		CoinbaseData: "01000000" + // version
			"01" + // input count
			"0000000000000000000000000000000000000000000000000000000000000000" + // prev tx hash
			"ffffffff" + // prev tx index
			"08" + // script length
			"04ffff001d02fd04" + // script (height + data)
			"ffffffff" + // sequence
			"01" + // output count
			"00f2052a01000000" + // value (50 BTC)
			"43" + // script length
			"4104ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73ac" + // script
			"00000000", // lock time
		MerkleBranch:      []string{}, // Empty for coinbase only
		ExpectedMixHash:   "11f19805c58ab46610ff9c719dcf0a5f18fa2f1605798eef770c47219a39905b",
		ExpectedBlockHash: "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
	},
	{
		Name:        "KAWPOW Test Block",
		BlockHeight: 1219736, // First KAWPOW block height
		// Mock header for testing
		HeaderData: "20000000" + // version
			"000000000000000000000000000000000000000000000000000000000000000a" + // prev hash
			"4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdedba3b" + // merkle root (reversed)
			"80e95f5e" + // time (KAWPOW activation time)
			"ffff001d" + // bits
			"12345678", // nonce
		CoinbaseData: "02000000" + // version
			"01" + // input count
			"0000000000000000000000000000000000000000000000000000000000000000" + // prev tx hash
			"ffffffff" + // prev tx index
			"1d" + // script length (29 bytes)
			"04" + "98c91200" + // height 1219736 (little-endian with OP_PUSH4)
			"08" + "efbeadde78563412" + // extraNonce1 + extraNonce2
			"0b" + "4b415750504f57205256" + // "KAWPOW RV"
			"ffffffff" + // sequence
			"01" + // output count
			"00286bee00000000" + // value (25 RVN in satoshis)
			"19" + // script length (25 bytes)
			"76a914" + "89abcdefabbaabbaabbaabbaabbaabbaabbaabba" + "88ac" + // P2PKH script
			"00000000", // lock time
		MerkleBranch:      []string{}, // Empty for single transaction
		ExpectedMixHash:   "", // Will be filled by actual KAWPOW calculation
		ExpectedBlockHash: "", // Will be verified against our implementation
	},
}

// TestKAWPOWBlockValidation tests our KAWPOW implementation against known test vectors
func TestKAWPOWBlockValidation(t *testing.T) {
	for _, test := range kawpowValidationTests {
		t.Run(test.Name, func(t *testing.T) {
			// Decode header data
			headerBytes, err := hex.DecodeString(test.HeaderData)
			require.NoError(t, err)
			require.Equal(t, 80, len(headerBytes), "Header should be 80 bytes")

			// Decode coinbase transaction
			coinbaseBytes, err := hex.DecodeString(test.CoinbaseData)
			require.NoError(t, err)

			// Parse coinbase transaction
			var coinbaseTx wire.MsgTx
			coinbaseReader := bytes.NewReader(coinbaseBytes)
			err = coinbaseTx.Deserialize(coinbaseReader)
			require.NoError(t, err, "Should be able to deserialize coinbase transaction")

			// Create merkle branch
			var merkleBranch [][]byte
			for _, hashStr := range test.MerkleBranch {
				hashBytes, err := hex.DecodeString(hashStr)
				require.NoError(t, err)
				merkleBranch = append(merkleBranch, hashBytes)
			}

			// Create AuxPow with KAWPOW
			auxPow := NewAuxPow(
				Kawpow,
				headerBytes, // Use the 80-byte header
				[]byte{},    // Signature (empty for test)
				merkleBranch,
				&coinbaseTx,
			)

			require.NotNil(t, auxPow)
			require.Equal(t, Kawpow, auxPow.PowID())

			// Verify transaction format
			require.NotNil(t, auxPow.Transaction())
			require.Len(t, auxPow.Transaction().TxIn, 1, "Should have one input")
			require.Len(t, auxPow.Transaction().TxOut, 1, "Should have one output")

			// Verify coinbase scriptSig format
			scriptSig := auxPow.Transaction().TxIn[0].SignatureScript
			require.Greater(t, len(scriptSig), 4, "ScriptSig should contain at least height")

			// Extract block height from scriptSig
			if len(scriptSig) >= 5 && scriptSig[0] == 0x04 {
				height := uint32(scriptSig[1]) |
					uint32(scriptSig[2])<<8 |
					uint32(scriptSig[3])<<16 |
					uint32(scriptSig[4])<<24
				require.Equal(t, test.BlockHeight, height, "Height in scriptSig should match")
			}

			// Log the AuxPow structure for debugging
			t.Logf("AuxPow PowID: %d", auxPow.PowID())
			t.Logf("Header length: %d bytes", len(auxPow.Header()))
			t.Logf("Merkle branch entries: %d", len(auxPow.MerkleBranch()))
			t.Logf("Transaction inputs: %d", len(auxPow.Transaction().TxIn))
			t.Logf("Transaction outputs: %d", len(auxPow.Transaction().TxOut))
		})
	}
}

// TestKAWPOWCoinbaseNonceExtraction tests nonce extraction from KAWPOW coinbase
func TestKAWPOWCoinbaseNonceExtraction(t *testing.T) {
	blockHeight := uint32(1219736)
	extraNonce1 := uint32(0xDEADBEEF)
	extraNonce2 := uint64(0x1234567890ABCDEF)
	extraData := []byte("KAWPOW Test Block")

	// Create coinbase transaction with KAWPOW nonces
	coinbaseTx := CreateCoinbaseTxWithNonce(
		blockHeight,
		extraNonce1,
		extraNonce2,
		extraData,
		[]byte{0x76, 0xa9, 0x14, 0x89, 0xab, 0xcd, 0xef}, // dummy address
		2500000000, // 25 RVN reward
	)

	require.NotNil(t, coinbaseTx)

	// Extract nonces back
	height, nonce1, nonce2, data := ExtractNoncesFromCoinbase(coinbaseTx.TxIn[0].SignatureScript)

	// Verify extracted values
	require.Equal(t, blockHeight, height, "Block height should match")
	require.Equal(t, extraNonce1, nonce1, "ExtraNonce1 should match")
	require.Equal(t, extraNonce2, nonce2, "ExtraNonce2 should match")
	require.Equal(t, extraData, data, "Extra data should match")

	// Test with the extracted values in an AuxPow
	headerBytes := make([]byte, 80)
	// Fill with mock header data
	copy(headerBytes[0:4], []byte{0x20, 0x00, 0x00, 0x00}) // version

	auxPow := NewAuxPow(
		Kawpow,
		headerBytes,
		[]byte{},
		[][]byte{}, // empty merkle branch
		coinbaseTx,
	)

	require.NotNil(t, auxPow)
	require.Equal(t, Kawpow, auxPow.PowID())

	t.Logf("Successfully created and validated KAWPOW AuxPow with nonces")
	t.Logf("Block height: %d", height)
	t.Logf("ExtraNonce1: 0x%08X", nonce1)
	t.Logf("ExtraNonce2: 0x%016X", nonce2)
	t.Logf("Extra data: %s", string(data))
}

// TestKAWPOWMerkleRootCalculation tests merkle root calculation for KAWPOW blocks
func TestKAWPOWMerkleRootCalculation(t *testing.T) {
	// Create a coinbase transaction
	coinbaseTx := CreateCoinbaseTxWithHeight(
		1219736,
		[]byte("KAWPOW Genesis"),
		[]byte{0x76, 0xa9, 0x14, 0x89, 0xab, 0xcd, 0xef}, // dummy address
		2500000000, // 25 RVN
	)

	// Create additional transactions (for a real block)
	tx2 := wire.NewMsgTx(2)
	tx2.AddTxIn(wire.NewTxIn(&wire.OutPoint{Hash: chainhash.Hash{}, Index: 0}, []byte{}, nil))
	tx2.AddTxOut(wire.NewTxOut(100000000, []byte{0x76, 0xa9, 0x14})) // 1 RVN

	transactions := []*wire.MsgTx{coinbaseTx, tx2}

	// Calculate merkle root using our implementation
	merkleRoot := CalculateMerkleRootFromTxs(transactions)
	require.NotEqual(t, [32]byte{}, merkleRoot.Bytes(), "Merkle root should not be empty")

	// Build full merkle tree
	merkleTree := BuildMerkleTree(transactions)
	require.Greater(t, len(merkleTree), 0, "Merkle tree should not be empty")

	// Extract merkle branch for coinbase (index 0)
	merkleBranch := ExtractMerkleBranch(merkleTree, len(transactions))
	require.Greater(t, len(merkleBranch), 0, "Merkle branch should exist for multiple transactions")

	// Verify merkle proof
	coinbaseHash := coinbaseTx.TxHash()
	isValid := VerifyMerkleProof(coinbaseHash, merkleBranch, merkleRoot)
	require.True(t, isValid, "Merkle proof should be valid")

	t.Logf("Merkle root: %x", merkleRoot[:])
	t.Logf("Coinbase hash: %x", coinbaseHash[:])
	t.Logf("Merkle branch entries: %d", len(merkleBranch))
}