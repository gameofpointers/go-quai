// Copyright 2017-2025 The go-quai Authors
// This file is part of the go-quai library.

package types

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"

	"github.com/dominant-strategies/go-quai/common"
)

// RavencoinTransaction represents a simplified Ravencoin transaction
type RavencoinTransaction struct {
	Version  int32                    `json:"version"`
	Inputs   []RavencoinTransactionIn `json:"inputs"`
	Outputs  []RavencoinTransactionOut `json:"outputs"`
	LockTime uint32                   `json:"lockTime"`
}

// RavencoinTransactionIn represents a transaction input
type RavencoinTransactionIn struct {
	PreviousOutput RavencoinOutPoint `json:"previousOutput"`
	ScriptSig      []byte            `json:"scriptSig"`      // This is where extra data goes in coinbase
	Sequence       uint32            `json:"sequence"`
}

// RavencoinTransactionOut represents a transaction output
type RavencoinTransactionOut struct {
	Value        int64  `json:"value"`        // Amount in satoshis
	ScriptPubKey []byte `json:"scriptPubKey"` // Locking script
}

// RavencoinOutPoint represents a reference to a transaction output
type RavencoinOutPoint struct {
	Hash  common.Hash `json:"hash"`  // Transaction hash
	Index uint32      `json:"index"` // Output index
}

// CreateCoinbaseTransaction creates a coinbase transaction with extra data in scriptSig
func CreateCoinbaseTransaction(blockHeight uint32, extraData []byte, minerAddress []byte, blockReward int64) *RavencoinTransaction {
	// Coinbase input: previous output is null (all zeros)
	coinbaseInput := RavencoinTransactionIn{
		PreviousOutput: RavencoinOutPoint{
			Hash:  common.Hash{}, // All zeros for coinbase
			Index: 0xFFFFFFFF,    // Max uint32 for coinbase
		},
		ScriptSig: buildCoinbaseScriptSig(blockHeight, extraData),
		Sequence:  0xFFFFFFFF,
	}

	// Coinbase output: block reward to miner
	coinbaseOutput := RavencoinTransactionOut{
		Value:        blockReward,
		ScriptPubKey: minerAddress, // P2PKH or P2SH script
	}

	return &RavencoinTransaction{
		Version:  1,
		Inputs:   []RavencoinTransactionIn{coinbaseInput},
		Outputs:  []RavencoinTransactionOut{coinbaseOutput},
		LockTime: 0,
	}
}

// buildCoinbaseScriptSig constructs the coinbase scriptSig with block height and extra data
func buildCoinbaseScriptSig(blockHeight uint32, extraData []byte) []byte {
	var scriptSig bytes.Buffer

	// BIP34: Block height must be first item in coinbase scriptSig
	// Encode block height as minimal bytes
	heightBytes := encodeCompactSize(uint64(blockHeight))
	scriptSig.Write(heightBytes)

	// Add extra data if provided
	if len(extraData) > 0 {
		// Add length prefix for extra data
		extraLenBytes := encodeCompactSize(uint64(len(extraData)))
		scriptSig.Write(extraLenBytes)
		scriptSig.Write(extraData)
	}

	return scriptSig.Bytes()
}

// encodeCompactSize encodes a number using Bitcoin's variable-length integer format
func encodeCompactSize(size uint64) []byte {
	if size < 0xFD {
		return []byte{byte(size)}
	} else if size <= 0xFFFF {
		buf := make([]byte, 3)
		buf[0] = 0xFD
		binary.LittleEndian.PutUint16(buf[1:], uint16(size))
		return buf
	} else if size <= 0xFFFFFFFF {
		buf := make([]byte, 5)
		buf[0] = 0xFE
		binary.LittleEndian.PutUint32(buf[1:], uint32(size))
		return buf
	} else {
		buf := make([]byte, 9)
		buf[0] = 0xFF
		binary.LittleEndian.PutUint64(buf[1:], size)
		return buf
	}
}

// Serialize encodes the transaction to bytes
func (tx *RavencoinTransaction) Serialize() []byte {
	var buf bytes.Buffer

	// Write version
	binary.Write(&buf, binary.LittleEndian, tx.Version)

	// Write input count
	inputCount := encodeCompactSize(uint64(len(tx.Inputs)))
	buf.Write(inputCount)

	// Write inputs
	for _, input := range tx.Inputs {
		// Previous output hash
		buf.Write(input.PreviousOutput.Hash.Bytes())
		// Previous output index
		binary.Write(&buf, binary.LittleEndian, input.PreviousOutput.Index)
		// ScriptSig length + ScriptSig
		scriptSigLen := encodeCompactSize(uint64(len(input.ScriptSig)))
		buf.Write(scriptSigLen)
		buf.Write(input.ScriptSig)
		// Sequence
		binary.Write(&buf, binary.LittleEndian, input.Sequence)
	}

	// Write output count
	outputCount := encodeCompactSize(uint64(len(tx.Outputs)))
	buf.Write(outputCount)

	// Write outputs
	for _, output := range tx.Outputs {
		// Value
		binary.Write(&buf, binary.LittleEndian, output.Value)
		// ScriptPubKey length + ScriptPubKey
		scriptPubKeyLen := encodeCompactSize(uint64(len(output.ScriptPubKey)))
		buf.Write(scriptPubKeyLen)
		buf.Write(output.ScriptPubKey)
	}

	// Write lock time
	binary.Write(&buf, binary.LittleEndian, tx.LockTime)

	return buf.Bytes()
}

// Hash calculates the double SHA256 hash of the transaction
func (tx *RavencoinTransaction) Hash() common.Hash {
	serialized := tx.Serialize()
	first := sha256.Sum256(serialized)
	second := sha256.Sum256(first[:])
	return common.BytesToHash(second[:])
}

// CalculateMerkleRoot calculates the merkle root for a list of transactions
func CalculateMerkleRoot(transactions []*RavencoinTransaction) common.Hash {
	if len(transactions) == 0 {
		return common.Hash{}
	}

	// Get transaction hashes
	hashes := make([]common.Hash, len(transactions))
	for i, tx := range transactions {
		hashes[i] = tx.Hash()
	}

	// Build merkle tree
	return buildMerkleTree(hashes)
}

// buildMerkleTree builds a merkle tree from transaction hashes
func buildMerkleTree(hashes []common.Hash) common.Hash {
	if len(hashes) == 0 {
		return common.Hash{}
	}
	if len(hashes) == 1 {
		return hashes[0]
	}

	// If odd number of hashes, duplicate the last one
	if len(hashes)%2 == 1 {
		hashes = append(hashes, hashes[len(hashes)-1])
	}

	// Combine pairs and hash them
	var nextLevel []common.Hash
	for i := 0; i < len(hashes); i += 2 {
		combined := append(hashes[i].Bytes(), hashes[i+1].Bytes()...)
		first := sha256.Sum256(combined)
		second := sha256.Sum256(first[:])
		nextLevel = append(nextLevel, common.BytesToHash(second[:]))
	}

	// Recursively build the tree
	return buildMerkleTree(nextLevel)
}

// CreateRavencoinBlockWithExtraData creates a complete Ravencoin block with extra data
func CreateRavencoinBlockWithExtraData(
	prevBlockHash common.Hash,
	blockHeight uint32,
	timestamp uint32,
	bits uint32,
	extraData []byte,
	minerAddress []byte,
	blockReward int64,
	additionalTxs []*RavencoinTransaction,
) (*RavencoinBlockHeader, []*RavencoinTransaction) {

	// Create coinbase transaction with extra data
	coinbase := CreateCoinbaseTransaction(blockHeight, extraData, minerAddress, blockReward)

	// Combine coinbase with other transactions
	allTxs := []*RavencoinTransaction{coinbase}
	allTxs = append(allTxs, additionalTxs...)

	// Calculate merkle root
	merkleRoot := CalculateMerkleRoot(allTxs)

	// Create block header
	header := &RavencoinBlockHeader{
		Version:        0x20000000, // Version 4 with BIP34 support
		HashPrevBlock:  prevBlockHash,
		HashMerkleRoot: merkleRoot,
		Time:           timestamp,
		Bits:           bits,
		Height:         blockHeight,
		// Nonce64 and MixHash will be set during mining
	}

	return header, allTxs
}

// String representation for debugging
func (tx *RavencoinTransaction) String() string {
	return fmt.Sprintf("RavencoinTransaction{Version: %d, Inputs: %d, Outputs: %d, Hash: %s}",
		tx.Version, len(tx.Inputs), len(tx.Outputs), tx.Hash().Hex())
}