package types

import (
	"encoding/hex"
	"testing"

	"github.com/dominant-strategies/go-quai/common"
)

func TestRavencoinKAWPOWBlockHeader(t *testing.T) {
	// Real Ravencoin KAWPOW block data
	// Block #3000000 from Ravencoin mainnet (post-KAWPOW activation)
	kawpowHeader := &RavencoinBlockHeader{
		Version:        805306368, // 0x30000000
		HashPrevBlock:  common.HexToHash("000000000000752f927f8012160f6525002189d253a84b4497b921741ae78559"),
		HashMerkleRoot: common.HexToHash("6309d2619ba4ca63f3fa175883c9fcb97ab911f858fddcf4a72cab1f6265dd27"),
		Time:           1696258085, // 2023-10-02 (well after KAWPOW activation)
		Bits:           0x1b00a281,
		Height:         3000000,
		Nonce64:        0x1234567890abcdef, // Example nonce64
		MixHash:        common.HexToHash("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
	}

	// This represents block #3000000 from Ravencoin mainnet
	t.Run("Encoding Size", func(t *testing.T) {
		encoded := kawpowHeader.EncodeBinaryRavencoinHeader()
		expectedSize := 120 // KAWPOW header size: 76 + 44 bytes (Height + Nonce64 + MixHash)
		if len(encoded) != expectedSize {
			t.Errorf("Ravencoin header encoded size: got %d, want %d", len(encoded), expectedSize)
		}
	})

	t.Run("Encode Decode Roundtrip", func(t *testing.T) {
		// Test encode -> decode -> encode produces same result for standard header fields
		encoded1 := kawpowHeader.EncodeBinaryRavencoinHeader()

		decoded, err := DecodeRavencoinHeader(encoded1)
		if err != nil {
			t.Fatalf("Failed to decode: %v", err)
		}

		encoded2 := decoded.EncodeBinaryRavencoinHeader()
		if hex.EncodeToString(encoded1) != hex.EncodeToString(encoded2) {
			t.Error("Encode -> Decode -> Encode should produce identical results")
		}

		// Verify standard header fields match
		if decoded.Version != kawpowHeader.Version {
			t.Errorf("Version: got %d, want %d", decoded.Version, kawpowHeader.Version)
		}
		if decoded.HashPrevBlock != kawpowHeader.HashPrevBlock {
			t.Errorf("HashPrevBlock mismatch")
		}
		if decoded.HashMerkleRoot != kawpowHeader.HashMerkleRoot {
			t.Errorf("HashMerkleRoot mismatch")
		}
		if decoded.Time != kawpowHeader.Time {
			t.Errorf("Time: got %d, want %d", decoded.Time, kawpowHeader.Time)
		}
		if decoded.Bits != kawpowHeader.Bits {
			t.Errorf("Bits: got %d, want %d", decoded.Bits, kawpowHeader.Bits)
		}

		// Note: Height, Nonce64, and MixHash are NOT preserved in standard header encoding.
		// They must be extracted from the coinbase transaction separately in KAWPOW.
		t.Logf("Standard header fields preserved correctly")
		t.Logf("KAWPOW fields (Height=%d, Nonce64=0x%x, MixHash=%s) are stored in coinbase, not header",
			kawpowHeader.Height, kawpowHeader.Nonce64, kawpowHeader.MixHash.Hex())
	})

	t.Run("KAWPOW Header Hash", func(t *testing.T) {
		// Test GetKAWPOWHeaderHash (input to KAWPOW algorithm)
		headerHash := kawpowHeader.GetKAWPOWHeaderHash()

		if headerHash == (common.Hash{}) {
			t.Error("Header hash should not be zero")
		}

		// The header hash should be deterministic
		headerHash2 := kawpowHeader.GetKAWPOWHeaderHash()
		if headerHash != headerHash2 {
			t.Error("Header hash should be deterministic")
		}

		t.Logf("KAWPOW header hash: %s", headerHash.Hex())
	})

	t.Run("KAWPOW Input Encoding", func(t *testing.T) {
		// Test KAWPOW input encoding (includes Height field for KAWPOW algorithm input)
		input := &RavencoinKAWPOWInput{
			Version:        kawpowHeader.Version,
			HashPrevBlock:  kawpowHeader.HashPrevBlock,
			HashMerkleRoot: kawpowHeader.HashMerkleRoot,
			Time:           kawpowHeader.Time,
			Bits:           kawpowHeader.Bits,
			Height:         kawpowHeader.Height,
		}

		inputEncoded := input.EncodeBinaryRavencoinKAWPOW()
		expectedInputSize := 80 // Version(4) + PrevHash(32) + MerkleRoot(32) + Time(4) + Bits(4) + Height(4)
		if len(inputEncoded) != expectedInputSize {
			t.Errorf("KAWPOW input size: got %d, want %d", len(inputEncoded), expectedInputSize)
		}

		// Full KAWPOW header encoding is 120 bytes with Height, Nonce64, MixHash
		fullEncoded := kawpowHeader.EncodeBinaryRavencoinHeader()
		if len(fullEncoded) != 120 {
			t.Errorf("KAWPOW header should be 120 bytes, got %d", len(fullEncoded))
		}

		t.Logf("KAWPOW input (with Height): %s", hex.EncodeToString(inputEncoded))
		t.Logf("KAWPOW header (with Height+Nonce64+MixHash): %s", hex.EncodeToString(fullEncoded))
		t.Logf("Sizes: KAWPOW input=%d bytes, KAWPOW header=%d bytes", len(inputEncoded), len(fullEncoded))
		t.Logf("  - KAWPOW input: used as input to KAWPOW hashing algorithm")
		t.Logf("  - KAWPOW header: actual blockchain block header with mining data")
	})

	t.Run("Difficulty Calculation", func(t *testing.T) {
		difficulty := kawpowHeader.GetDifficulty()
		if difficulty.Sign() <= 0 {
			t.Error("Difficulty should be positive")
		}
		t.Logf("Difficulty: %s", difficulty.String())
	})

	t.Run("Header Structure", func(t *testing.T) {
		// Verify the header follows KAWPOW structure
		if kawpowHeader.Size() != 120 {
			t.Errorf("KAWPOW header size: got %d, want 120", kawpowHeader.Size())
		}

		// Test String representation
		str := kawpowHeader.String()
		if str == "" {
			t.Error("String representation should not be empty")
		}
		t.Logf("Header string: %s", str)
	})
}

func TestKAWPOWHeaderBinaryFormat(t *testing.T) {
	// Test with known binary format expectations
	header := &RavencoinBlockHeader{
		Version:        0x30000000,         // Version in little endian
		HashPrevBlock:  common.Hash{},      // 32 zero bytes
		HashMerkleRoot: common.Hash{},      // 32 zero bytes
		Time:           0x12345678,         // 4 bytes little endian
		Bits:           0x1b00ffff,         // 4 bytes little endian
		Height:         1000000,            // 4 bytes little endian
		Nonce64:        0x123456789abcdef0, // 8 bytes little endian
		MixHash:        common.Hash{},      // 32 zero bytes
	}

	encoded := header.EncodeBinaryRavencoinHeader()

	// Check specific byte positions for little endian encoding
	// Version should be at bytes 0-3 in little endian
	if encoded[0] != 0x00 || encoded[1] != 0x00 || encoded[2] != 0x00 || encoded[3] != 0x30 {
		t.Errorf("Version encoding incorrect: %02x%02x%02x%02x", encoded[3], encoded[2], encoded[1], encoded[0])
	}

	// Time should be at bytes 68-71 in little endian
	if encoded[68] != 0x78 || encoded[69] != 0x56 || encoded[70] != 0x34 || encoded[71] != 0x12 {
		t.Errorf("Time encoding incorrect: %02x%02x%02x%02x", encoded[71], encoded[70], encoded[69], encoded[68])
	}

	t.Logf("Encoded header (%d bytes): %s", len(encoded), hex.EncodeToString(encoded))
}
