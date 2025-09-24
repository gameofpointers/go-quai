package types

import (
	"encoding/hex"
	"testing"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
)

// KAWPOW Test Vectors from cpp-kawpow
// Source: https://github.com/RavenCommunity/cpp-kawpow/blob/master/test/unittests/progpow_test_vectors.hpp
type KAWPOWTestVector struct {
	BlockHeight  uint32
	HeaderHash   string // 32 bytes hex
	Nonce        uint64
	MixHash      string // 32 bytes hex
	ExpectedHash string // 32 bytes hex (final hash)
}

var kawpowTestVectors = []KAWPOWTestVector{
	{
		BlockHeight:  0,
		HeaderHash:   "0000000000000000000000000000000000000000000000000000000000000000",
		Nonce:        0x0000000000000000,
		MixHash:      "6e97b47b134fda0c7888802988e1a373affeb28bcd813b6e9a0fc669c935d03a",
		ExpectedHash: "e601a7257a70dc48fccc97a7330d704d776047623b92883d77111fb36870f3d1",
	},
	{
		BlockHeight:  49,
		HeaderHash:   "63155f732f2bf556967f906155b510c917e48e99685ead76ea83f4eca03ab12b",
		Nonce:        0x0000000007073c07,
		MixHash:      "d36f7e815ee09e74eceb9c96993a3d681edf2bf0921fc7bb710364042db99777",
		ExpectedHash: "e7ced124598fd2500a55ad9f9f48e3569327fe50493c77a4ac9799b96efb9463",
	},
}

// TestKAWPOWBlockHeader tests creating a KAWPOW block header with AuxPow
func TestKAWPOWBlockHeader(t *testing.T) {
	// KAWPOW activation parameters for Ravencoin
	const (
		kawpowActivationHeight = 1219736 // Mainnet activation
		kawpowActivationTime   = 1588788000 // Wed May 06 2020 18:00:00 UTC
	)

	// Create a test KAWPOW header (120 bytes for KAWPOW)
	// KAWPOW header format:
	// - 4 bytes: version
	// - 32 bytes: previous block hash
	// - 32 bytes: merkle root
	// - 4 bytes: timestamp
	// - 4 bytes: bits (difficulty)
	// - 4 bytes: height
	// - 8 bytes: nonce (64-bit for KAWPOW)
	// - 32 bytes: mix hash
	kawpowHeader := make([]byte, 120)

	// Version (4 bytes)
	kawpowHeader[0] = 0x00
	kawpowHeader[1] = 0x00
	kawpowHeader[2] = 0x00
	kawpowHeader[3] = 0x20 // version 536870912

	// Previous block hash (32 bytes) - zeros for test
	// Merkle root (32 bytes) - zeros for test
	// Timestamp (4 bytes)
	kawpowHeader[68] = 0x20
	kawpowHeader[69] = 0xA7
	kawpowHeader[70] = 0xAC
	kawpowHeader[71] = 0x5E // timestamp around activation

	// Bits (4 bytes) - difficulty
	kawpowHeader[72] = 0xFF
	kawpowHeader[73] = 0xFF
	kawpowHeader[74] = 0x00
	kawpowHeader[75] = 0x1D

	// Height (4 bytes) - KAWPOW includes height in header
	kawpowHeader[76] = 0x98
	kawpowHeader[77] = 0x9C
	kawpowHeader[78] = 0x12
	kawpowHeader[79] = 0x00 // height 1219736 (little-endian)

	// Nonce (8 bytes) - 64-bit for KAWPOW
	kawpowHeader[80] = 0x01
	kawpowHeader[81] = 0x02
	kawpowHeader[82] = 0x03
	kawpowHeader[83] = 0x04
	kawpowHeader[84] = 0x05
	kawpowHeader[85] = 0x06
	kawpowHeader[86] = 0x07
	kawpowHeader[87] = 0x08

	// Mix hash (32 bytes) - result of KAWPOW mining
	// This would be filled by the miner

	// Create a test coinbase transaction
	coinbaseTx := wire.NewMsgTx(1)

	// Coinbase input
	prevOut := wire.NewOutPoint(&chainhash.Hash{}, 0xFFFFFFFF)
	scriptSig := BuildCoinbaseScriptSigWithNonce(
		kawpowActivationHeight,
		0xDEADBEEF,              // extraNonce1
		0x1234567890ABCDEF,      // extraNonce2
		[]byte("KAWPOW Test"),   // extra data
	)
	txIn := wire.NewTxIn(prevOut, scriptSig, nil)
	coinbaseTx.AddTxIn(txIn)

	// Coinbase output - miner reward
	minerScript, _ := hex.DecodeString("76a914" + "89abcdefabbaabbaabbaabbaabbaabbaabbaabba" + "88ac")
	txOut := wire.NewTxOut(625000000, minerScript) // 6.25 RVN reward
	coinbaseTx.AddTxOut(txOut)

	// Create merkle branch (empty for coinbase)
	merkleBranch := [][]byte{}

	// Create AuxPow with KAWPOW
	auxPow := NewAuxPow(
		Kawpow,
		kawpowHeader,
		[]byte{}, // signature would be filled by mining
		merkleBranch,
		coinbaseTx,
	)

	// Verify the AuxPow was created correctly
	require.NotNil(t, auxPow)
	require.Equal(t, Kawpow, auxPow.PowID())
	require.Equal(t, 120, len(auxPow.Header()))
	require.NotNil(t, auxPow.Transaction())

	// Extract nonces from coinbase
	height, nonce1, nonce2, extraData := ExtractNoncesFromCoinbase(coinbaseTx.TxIn[0].SignatureScript)
	require.Equal(t, uint32(kawpowActivationHeight), height)
	require.Equal(t, uint32(0xDEADBEEF), nonce1)
	require.Equal(t, uint64(0x1234567890ABCDEF), nonce2)
	require.Equal(t, []byte("KAWPOW Test"), extraData)
}

// TestKAWPOWRavencoinHeader tests parsing an actual Ravencoin KAWPOW header
func TestKAWPOWRavencoinHeader(t *testing.T) {
	// Create a RavencoinBlockHeader
	rvnHeader := NewRavencoinBlockHeader()

	// Set fields for a KAWPOW block
	rvnHeader.Version = 536870912 // 0x20000000
	rvnHeader.Height = 1219736    // First KAWPOW block
	rvnHeader.Time = 1588788000   // KAWPOW activation time
	rvnHeader.Bits = 0x1d00ffff   // Difficulty
	// 32-bit nonce field removed - KAWPOW only uses Nonce64

	// For KAWPOW, we also have Nonce64 and MixHash
	rvnHeader.Nonce64 = 0x1234567890ABCDEF // 64-bit nonce for KAWPOW
	// MixHash would be filled by mining

	// Create KAWPOW input for encoding
	kawpowInput := &RavencoinKAWPOWInput{
		Version:        rvnHeader.Version,
		HashPrevBlock:  rvnHeader.HashPrevBlock,
		HashMerkleRoot: rvnHeader.HashMerkleRoot,
		Time:           rvnHeader.Time,
		Bits:           rvnHeader.Bits,
		Height:         rvnHeader.Height,
	}

	// Encode to KAWPOW format
	kawpowBytes := kawpowInput.EncodeBinaryRavencoinKAWPOW()

	// KAWPOW header is 80 bytes (standard) + additional data
	// The actual header hash is computed from first 80 bytes
	headerHash := rvnHeader.GetKAWPOWHeaderHash()
	require.NotNil(t, headerHash)

	// Verify the header can be used in AuxPow
	// For KAWPOW, the header should be 120 bytes (80 standard + 40 KAWPOW extension)
	// But we'll use the actual encoded bytes
	auxPow := NewAuxPow(
		Kawpow,
		kawpowBytes[:120], // Use first 120 bytes as header
		[]byte{},  // signature
		[][]byte{}, // merkle branch
		wire.NewMsgTx(1), // dummy transaction
	)
	require.NotNil(t, auxPow)
	require.Equal(t, Kawpow, auxPow.PowID())
}

// TestKAWPOWCoinbaseFormat tests the KAWPOW-specific coinbase format
func TestKAWPOWCoinbaseFormat(t *testing.T) {
	tests := []struct {
		name        string
		height      uint32
		extraNonce1 uint32
		extraNonce2 uint64
		extraData   []byte
	}{
		{
			name:        "First KAWPOW block",
			height:      1219736,
			extraNonce1: 0x12345678,
			extraNonce2: 0xABCDEF0123456789,
			extraData:   []byte("RVN KAWPOW"),
		},
		{
			name:        "Recent block",
			height:      2000000,
			extraNonce1: 0xDEADBEEF,
			extraNonce2: 0xCAFEBABEDEADBEEF,
			extraData:   []byte("Test Mining Pool"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create coinbase with KAWPOW nonces
			tx := CreateCoinbaseTxWithNonce(
				tt.height,
				tt.extraNonce1,
				tt.extraNonce2,
				tt.extraData,
				[]byte{0x76, 0xa9, 0x14}, // dummy miner address
				625000000, // 6.25 RVN
			)

			require.NotNil(t, tx)

			// Verify we can extract the values back
			scriptSig := tx.TxIn[0].SignatureScript
			h, n1, n2, data := ExtractNoncesFromCoinbase(scriptSig)

			require.Equal(t, tt.height, h, "Height should match")
			require.Equal(t, tt.extraNonce1, n1, "ExtraNonce1 should match")
			require.Equal(t, tt.extraNonce2, n2, "ExtraNonce2 should match")
			require.Equal(t, tt.extraData, data, "Extra data should match")
		})
	}
}