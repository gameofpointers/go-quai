// Copyright 2017-2025 The go-quai Authors
// This file is part of the go-quai library.

package types

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"

	"github.com/dominant-strategies/go-quai/common"
)

// RavencoinBlockHeader represents the Ravencoin block header structure
type RavencoinBlockHeader struct {
	// Standard Bitcoin-derived fields
	Version        int32       `json:"version"        gencodec:"required"`
	HashPrevBlock  common.Hash `json:"hashPrevBlock"  gencodec:"required"`
	HashMerkleRoot common.Hash `json:"hashMerkleRoot" gencodec:"required"`
	Time           uint32      `json:"time"           gencodec:"required"`
	Bits           uint32      `json:"bits"           gencodec:"required"`
	Nonce          uint32      `json:"nonce"          gencodec:"required"`

	// KAWPOW-specific fields (post-activation)
	Height  uint32      `json:"height"   gencodec:"required"`
	Nonce64 uint64      `json:"nonce64"  gencodec:"required"`
	MixHash common.Hash `json:"mixHash"  gencodec:"required"`
}

// RavencoinKAWPOWInput represents the input structure for KAWPOW hashing
// This excludes nNonce64 and mixHash for header hash calculation
type RavencoinKAWPOWInput struct {
	Version        int32       `json:"version"        gencodec:"required"`
	HashPrevBlock  common.Hash `json:"hashPrevBlock"  gencodec:"required"`
	HashMerkleRoot common.Hash `json:"hashMerkleRoot" gencodec:"required"`
	Time           uint32      `json:"time"           gencodec:"required"`
	Bits           uint32      `json:"bits"           gencodec:"required"`
	Height         uint32      `json:"height"         gencodec:"required"`
}

func EmptyRavencoinKAWPOWInput() *RavencoinKAWPOWInput {
	return &RavencoinKAWPOWInput{
		Version:        0,
		HashPrevBlock:  common.Hash{},
		HashMerkleRoot: common.Hash{},
		Time:           0,
		Bits:           0,
		Height:         0,
	}
}

// KAWPOW activation time constants (matching Ravencoin)
const (
	MainnetKAWPOWActivationTime = 1588788000 // May 6, 2020
	TestnetKAWPOWActivationTime = 1585683600 // March 31, 2020
	RegtestKAWPOWActivationTime = 1588731600 // May 5, 2020
)

// X16RV2 activation time constants
const (
	MainnetX16RV2ActivationTime = 1569945600
	TestnetX16RV2ActivationTime = 1567533600
	RegtestX16RV2ActivationTime = 1569931200
)

// NewRavencoinBlockHeader creates a new Ravencoin block header
func NewRavencoinBlockHeader() *RavencoinBlockHeader {
	return &RavencoinBlockHeader{}
}

// SetNull initializes the header with zero values
func (h *RavencoinBlockHeader) SetNull() {
	h.Version = 0
	h.HashPrevBlock = common.Hash{}
	h.HashMerkleRoot = common.Hash{}
	h.Time = 0
	h.Bits = 0
	h.Nonce = 0
	h.Height = 0
	h.Nonce64 = 0
	h.MixHash = common.Hash{}
}

// IsNull returns true if the header is in null state
func (h *RavencoinBlockHeader) IsNull() bool {
	return h.Bits == 0
}

// IsKAWPOWActive returns true if KAWPOW is active for this block time
func (h *RavencoinBlockHeader) IsKAWPOWActive(network string) bool {
	var activationTime uint32
	switch network {
	case "mainnet":
		activationTime = MainnetKAWPOWActivationTime
	case "testnet":
		activationTime = TestnetKAWPOWActivationTime
	case "regtest":
		activationTime = RegtestKAWPOWActivationTime
	default:
		activationTime = MainnetKAWPOWActivationTime
	}
	return h.Time >= activationTime
}

// IsX16RV2Active returns true if X16RV2 is active for this block time
func (h *RavencoinBlockHeader) IsX16RV2Active(network string) bool {
	var activationTime uint32
	switch network {
	case "mainnet":
		activationTime = MainnetX16RV2ActivationTime
	case "testnet":
		activationTime = TestnetX16RV2ActivationTime
	case "regtest":
		activationTime = RegtestX16RV2ActivationTime
	default:
		activationTime = MainnetX16RV2ActivationTime
	}
	return h.Time >= activationTime && !h.IsKAWPOWActive(network)
}

// GetKAWPOWHeaderHash returns the header hash for KAWPOW input
// This excludes nNonce64 and mixHash, following Ravencoin's CKAWPOWInput
func (h *RavencoinBlockHeader) GetKAWPOWHeaderHash() common.Hash {
	input := RavencoinKAWPOWInput{
		Version:        h.Version,
		HashPrevBlock:  h.HashPrevBlock,
		HashMerkleRoot: h.HashMerkleRoot,
		Time:           h.Time,
		Bits:           h.Bits,
		Height:         h.Height,
	}

	// Serialize the input and calculate SHA256D (double SHA256)
	data := input.EncodeBinaryRavencoinKAWPOW()

	first := sha256.Sum256(data)
	second := sha256.Sum256(first[:])

	return common.BytesToHash(second[:])
}

// GetDifficulty calculates the difficulty from nBits
func (h *RavencoinBlockHeader) GetDifficulty() *big.Int {
	// Extract mantissa and exponent from nBits (compact format)
	nBits := h.Bits
	nShift := (nBits >> 24) & 0xff

	target := big.NewInt(int64(nBits & 0x00ffffff))
	if nShift <= 3 {
		target.Rsh(target, uint(8*(3-nShift)))
	} else {
		target.Lsh(target, uint(8*(nShift-3)))
	}

	// Calculate difficulty = max_target / target
	maxTarget := new(big.Int)
	maxTarget.SetString("00000000FFFF0000000000000000000000000000000000000000000000000000", 16)

	if target.Sign() <= 0 {
		return big.NewInt(0)
	}

	return new(big.Int).Div(maxTarget, target)
}

// EncodeBinary encodes the header to Ravencoin's binary format
func (h *RavencoinBlockHeader) EncodeBinaryRavencoinHeader() []byte {
	var buf bytes.Buffer

	// Write version (4 bytes, little endian)
	binary.Write(&buf, binary.LittleEndian, h.Version)

	// Write hashPrevBlock (32 bytes)
	buf.Write(h.HashPrevBlock.Bytes())

	// Write hashMerkleRoot (32 bytes)
	buf.Write(h.HashMerkleRoot.Bytes())

	// Write time (4 bytes, little endian)
	binary.Write(&buf, binary.LittleEndian, h.Time)

	// Write bits (4 bytes, little endian)
	binary.Write(&buf, binary.LittleEndian, h.Bits)

	// For KAWPOW blocks, write height, nonce64, and mixHash
	// For pre-KAWPOW blocks, write nonce
	if h.IsKAWPOWActive("mainnet") { // Default to mainnet for now
		// Write height (4 bytes, little endian)
		binary.Write(&buf, binary.LittleEndian, h.Height)

		// Write nonce64 (8 bytes, little endian)
		binary.Write(&buf, binary.LittleEndian, h.Nonce64)

		// Write mixHash (32 bytes)
		buf.Write(h.MixHash.Bytes())
	} else {
		// Write nonce (4 bytes, little endian)
		binary.Write(&buf, binary.LittleEndian, h.Nonce)
	}

	return buf.Bytes()
}

// DecodeRavencoinHeader decodes bytes into a RavencoinBlockHeader
func DecodeRavencoinHeader(data []byte) (*RavencoinBlockHeader, error) {
	if len(data) < 80 {
		return nil, fmt.Errorf("header data too short: %d bytes (minimum 80)", len(data))
	}

	h := &RavencoinBlockHeader{}
	buf := bytes.NewReader(data)

	// Read version
	if err := binary.Read(buf, binary.LittleEndian, &h.Version); err != nil {
		return nil, err
	}

	// Read hashPrevBlock
	if _, err := io.ReadFull(buf, h.HashPrevBlock[:]); err != nil {
		return nil, err
	}

	// Read hashMerkleRoot
	if _, err := io.ReadFull(buf, h.HashMerkleRoot[:]); err != nil {
		return nil, err
	}

	// Read time
	if err := binary.Read(buf, binary.LittleEndian, &h.Time); err != nil {
		return nil, err
	}

	// Read bits
	if err := binary.Read(buf, binary.LittleEndian, &h.Bits); err != nil {
		return nil, err
	}

	// Check if this is a KAWPOW block based on time
	// First check with the time we just read to determine header size
	tempHeader := &RavencoinBlockHeader{Time: h.Time}
	isKawpow := tempHeader.IsKAWPOWActive("mainnet")

	if isKawpow {
		// Ensure we have enough data for KAWPOW header
		if len(data) < 120 {
			return nil, fmt.Errorf("KAWPOW header data too short: %d bytes (expected 120)", len(data))
		}

		// Read height
		if err := binary.Read(buf, binary.LittleEndian, &h.Height); err != nil {
			return nil, err
		}

		// Read nonce64
		if err := binary.Read(buf, binary.LittleEndian, &h.Nonce64); err != nil {
			return nil, err
		}

		// Read mixHash
		if _, err := io.ReadFull(buf, h.MixHash[:]); err != nil {
			return nil, err
		}
	} else {
		// Read nonce
		if err := binary.Read(buf, binary.LittleEndian, &h.Nonce); err != nil {
			return nil, err
		}
	}

	return h, nil
}

// EncodeBinary encodes the KAWPOW input structure (without nonce64 and mixHash)
func (input *RavencoinKAWPOWInput) EncodeBinaryRavencoinKAWPOW() []byte {
	var buf bytes.Buffer

	// Write version (4 bytes, little endian)
	binary.Write(&buf, binary.LittleEndian, input.Version)

	// Write hashPrevBlock (32 bytes)
	buf.Write(input.HashPrevBlock.Bytes())

	// Write hashMerkleRoot (32 bytes)
	buf.Write(input.HashMerkleRoot.Bytes())

	// Write time (4 bytes, little endian)
	binary.Write(&buf, binary.LittleEndian, input.Time)

	// Write bits (4 bytes, little endian)
	binary.Write(&buf, binary.LittleEndian, input.Bits)

	// Write height (4 bytes, little endian)
	binary.Write(&buf, binary.LittleEndian, input.Height)

	return buf.Bytes()
}

// String returns a string representation of the header
func (h *RavencoinBlockHeader) String() string {
	return fmt.Sprintf("RavencoinBlockHeader{Version: 0x%08x, HashPrevBlock: %s, HashMerkleRoot: %s, Time: %d, Bits: 0x%08x, Nonce: %d, Height: %d, Nonce64: %d, MixHash: %s}",
		h.Version,
		h.HashPrevBlock.Hex(),
		h.HashMerkleRoot.Hex(),
		h.Time,
		h.Bits,
		h.Nonce,
		h.Height,
		h.Nonce64,
		h.MixHash.Hex(),
	)
}

// Size returns the size of the header in bytes
func (h *RavencoinBlockHeader) Size() int {
	// Base size: version(4) + hashPrevBlock(32) + hashMerkleRoot(32) + time(4) + bits(4)
	baseSize := 4 + 32 + 32 + 4 + 4

	if h.IsKAWPOWActive("mainnet") {
		// KAWPOW: height(4) + nonce64(8) + mixHash(32) = 44 bytes
		return baseSize + 44 // 76 + 44 = 120 bytes
	} else {
		// Pre-KAWPOW: nonce(4)
		return baseSize + 4 // 76 + 4 = 80 bytes
	}
}
