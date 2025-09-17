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
	var buf bytes.Buffer
	input.EncodeBinary(&buf)

	first := sha256.Sum256(buf.Bytes())
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

// EncodeBinary encodes the header in Ravencoin's binary format
func (h *RavencoinBlockHeader) EncodeBinary(w io.Writer) error {
	// Write version (4 bytes, little endian)
	if err := binary.Write(w, binary.LittleEndian, h.Version); err != nil {
		return err
	}

	// Write hashPrevBlock (32 bytes)
	if _, err := w.Write(h.HashPrevBlock.Bytes()); err != nil {
		return err
	}

	// Write hashMerkleRoot (32 bytes)
	if _, err := w.Write(h.HashMerkleRoot.Bytes()); err != nil {
		return err
	}

	// Write time (4 bytes, little endian)
	if err := binary.Write(w, binary.LittleEndian, h.Time); err != nil {
		return err
	}

	// Write bits (4 bytes, little endian)
	if err := binary.Write(w, binary.LittleEndian, h.Bits); err != nil {
		return err
	}

	// For KAWPOW blocks, write height, nonce64, and mixHash
	// For pre-KAWPOW blocks, write nonce
	if h.IsKAWPOWActive("mainnet") { // Default to mainnet for now
		// Write height (4 bytes, little endian)
		if err := binary.Write(w, binary.LittleEndian, h.Height); err != nil {
			return err
		}

		// Write nonce64 (8 bytes, little endian)
		if err := binary.Write(w, binary.LittleEndian, h.Nonce64); err != nil {
			return err
		}

		// Write mixHash (32 bytes)
		if _, err := w.Write(h.MixHash.Bytes()); err != nil {
			return err
		}
	} else {
		// Write nonce (4 bytes, little endian)
		if err := binary.Write(w, binary.LittleEndian, h.Nonce); err != nil {
			return err
		}
	}

	return nil
}

// DecodeBinary decodes the header from Ravencoin's binary format
func (h *RavencoinBlockHeader) DecodeBinary(r io.Reader, network string) error {
	// Read version
	if err := binary.Read(r, binary.LittleEndian, &h.Version); err != nil {
		return err
	}

	// Read hashPrevBlock
	if _, err := io.ReadFull(r, h.HashPrevBlock[:]); err != nil {
		return err
	}

	// Read hashMerkleRoot
	if _, err := io.ReadFull(r, h.HashMerkleRoot[:]); err != nil {
		return err
	}

	// Read time
	if err := binary.Read(r, binary.LittleEndian, &h.Time); err != nil {
		return err
	}

	// Read bits
	if err := binary.Read(r, binary.LittleEndian, &h.Bits); err != nil {
		return err
	}

	// Determine if this is a KAWPOW block based on time
	if h.IsKAWPOWActive(network) {
		// Read height
		if err := binary.Read(r, binary.LittleEndian, &h.Height); err != nil {
			return err
		}

		// Read nonce64
		if err := binary.Read(r, binary.LittleEndian, &h.Nonce64); err != nil {
			return err
		}

		// Read mixHash
		if _, err := io.ReadFull(r, h.MixHash[:]); err != nil {
			return err
		}
	} else {
		// Read nonce
		if err := binary.Read(r, binary.LittleEndian, &h.Nonce); err != nil {
			return err
		}
	}

	return nil
}

// EncodeBinary encodes the KAWPOW input structure (without nonce64 and mixHash)
func (input *RavencoinKAWPOWInput) EncodeBinary(w io.Writer) error {
	// Write version (4 bytes, little endian)
	if err := binary.Write(w, binary.LittleEndian, input.Version); err != nil {
		return err
	}

	// Write hashPrevBlock (32 bytes)
	if _, err := w.Write(input.HashPrevBlock.Bytes()); err != nil {
		return err
	}

	// Write hashMerkleRoot (32 bytes)
	if _, err := w.Write(input.HashMerkleRoot.Bytes()); err != nil {
		return err
	}

	// Write time (4 bytes, little endian)
	if err := binary.Write(w, binary.LittleEndian, input.Time); err != nil {
		return err
	}

	// Write bits (4 bytes, little endian)
	if err := binary.Write(w, binary.LittleEndian, input.Bits); err != nil {
		return err
	}

	// Write height (4 bytes, little endian)
	if err := binary.Write(w, binary.LittleEndian, input.Height); err != nil {
		return err
	}

	return nil
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
		// KAWPOW: height(4) + nonce64(8) + mixHash(32)
		return baseSize + 4 + 8 + 32
	} else {
		// Pre-KAWPOW: nonce(4)
		return baseSize + 4
	}
}

