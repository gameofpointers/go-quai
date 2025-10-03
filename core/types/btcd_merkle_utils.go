package types

import (
	"bytes"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/dominant-strategies/go-quai/common"
)

// CreateCoinbaseTxWithHeight creates a coinbase transaction with block height and extra data
func CreateCoinbaseTxWithHeight(blockHeight uint32, extraData []byte, minerAddress []byte, blockReward int64) *wire.MsgTx {
	return CreateCoinbaseTxWithNonce(blockHeight, 0, 0, extraData, minerAddress, blockReward)
}

// CreateCoinbaseTxWithNonce creates a coinbase transaction with nonces for KAWPOW mining
func CreateCoinbaseTxWithNonce(blockHeight uint32, extraNonce1 uint32, extraNonce2 uint64, extraData []byte, minerAddress []byte, blockReward int64) *wire.MsgTx {
	tx := wire.NewMsgTx(1)

	// Coinbase input (null hash, max index)
	prevOut := wire.NewOutPoint(&chainhash.Hash{}, 0xFFFFFFFF)

	// Build scriptSig with height, nonces, and extra data for KAWPOW
	scriptSig := BuildCoinbaseScriptSigWithNonce(blockHeight, extraNonce1, extraNonce2, extraData)

	txIn := wire.NewTxIn(prevOut, scriptSig, nil)
	tx.AddTxIn(txIn)

	// Output to miner
	txOut := wire.NewTxOut(blockReward, minerAddress)
	tx.AddTxOut(txOut)

	return tx
}

// BuildCoinbaseScriptSig creates a scriptSig for coinbase with block height and extra data
// Uses the Ravencoin-compatible format (BIP34)
func BuildCoinbaseScriptSig(blockHeight uint32, extraData []byte) []byte {
	var buf bytes.Buffer

	// BIP34: Block height encoding (Ravencoin uses standard Bitcoin format)
	// Always use OP_PUSH4 (4 bytes) for heights in Ravencoin's range
	buf.WriteByte(0x04) // OP_PUSH4
	buf.WriteByte(byte(blockHeight))
	buf.WriteByte(byte(blockHeight >> 8))
	buf.WriteByte(byte(blockHeight >> 16))
	buf.WriteByte(byte(blockHeight >> 24))

	// Add extra data if present
	if len(extraData) > 0 {
		if len(extraData) <= 75 {
			// Direct push for small data (OP_PUSHx where x is the length)
			buf.WriteByte(byte(len(extraData)))
			buf.Write(extraData)
		} else if len(extraData) <= 255 {
			// For larger data, use OP_PUSHDATA1
			buf.WriteByte(0x4c) // OP_PUSHDATA1
			buf.WriteByte(byte(len(extraData)))
			buf.Write(extraData)
		} else {
			// For even larger data, use OP_PUSHDATA2 (up to 520 bytes total scriptSig)
			buf.WriteByte(0x4d) // OP_PUSHDATA2
			buf.WriteByte(byte(len(extraData)))
			buf.WriteByte(byte(len(extraData) >> 8))
			buf.Write(extraData)
		}
	}

	return buf.Bytes()
}

// BuildCoinbaseScriptSigWithNonce creates a scriptSig for KAWPOW coinbase with nonces
// Format: [height][extraNonce1][extraNonce2][extraData]
func BuildCoinbaseScriptSigWithNonce(blockHeight uint32, extraNonce1 uint32, extraNonce2 uint64, extraData []byte) []byte {
	var buf bytes.Buffer

	// BIP34: Block height encoding (4 bytes, little-endian)
	buf.WriteByte(0x04) // OP_PUSH4
	buf.WriteByte(byte(blockHeight))
	buf.WriteByte(byte(blockHeight >> 8))
	buf.WriteByte(byte(blockHeight >> 16))
	buf.WriteByte(byte(blockHeight >> 24))

	// Extra nonce 1 (4 bytes, little-endian) - pool nonce
	if extraNonce1 != 0 {
		buf.WriteByte(0x04) // OP_PUSH4
		buf.WriteByte(byte(extraNonce1))
		buf.WriteByte(byte(extraNonce1 >> 8))
		buf.WriteByte(byte(extraNonce1 >> 16))
		buf.WriteByte(byte(extraNonce1 >> 24))
	}

	// Extra nonce 2 (8 bytes, little-endian) - miner nonce space
	if extraNonce2 != 0 {
		buf.WriteByte(0x08) // OP_PUSH8
		buf.WriteByte(byte(extraNonce2))
		buf.WriteByte(byte(extraNonce2 >> 8))
		buf.WriteByte(byte(extraNonce2 >> 16))
		buf.WriteByte(byte(extraNonce2 >> 24))
		buf.WriteByte(byte(extraNonce2 >> 32))
		buf.WriteByte(byte(extraNonce2 >> 40))
		buf.WriteByte(byte(extraNonce2 >> 48))
		buf.WriteByte(byte(extraNonce2 >> 56))
	}

	// Add extra data if present
	if len(extraData) > 0 {
		if len(extraData) <= 75 {
			// Direct push for small data (OP_PUSHx where x is the length)
			buf.WriteByte(byte(len(extraData)))
			buf.Write(extraData)
		} else if len(extraData) <= 255 {
			// For larger data, use OP_PUSHDATA1
			buf.WriteByte(0x4c) // OP_PUSHDATA1
			buf.WriteByte(byte(len(extraData)))
			buf.Write(extraData)
		} else {
			// For even larger data, use OP_PUSHDATA2 (up to 520 bytes total scriptSig)
			buf.WriteByte(0x4d) // OP_PUSHDATA2
			buf.WriteByte(byte(len(extraData)))
			buf.WriteByte(byte(len(extraData) >> 8))
			buf.Write(extraData)
		}
	}

	return buf.Bytes()
}

// CalculateMerkleRootFromTxs calculates merkle root from wire.MsgTx transactions
func CalculateMerkleRootFromTxs(txs []*wire.MsgTx) common.Hash {
	if len(txs) == 0 {
		return common.Hash{}
	}

	// Convert to btcutil.Tx for btcd functions
	btcTxs := make([]*btcutil.Tx, len(txs))
	for i, tx := range txs {
		btcTxs[i] = btcutil.NewTx(tx)
	}

	// Use btcd's CalcMerkleRoot function
	root := blockchain.CalcMerkleRoot(btcTxs, false) // false = not witness
	return common.BytesToHash(root[:])
}

// BuildMerkleTree builds a complete merkle tree and returns all nodes
func BuildMerkleTree(txs []*wire.MsgTx) []*chainhash.Hash {
	if len(txs) == 0 {
		return nil
	}

	// Convert to btcutil.Tx
	btcTxs := make([]*btcutil.Tx, len(txs))
	for i, tx := range txs {
		btcTxs[i] = btcutil.NewTx(tx)
	}

	// Use btcd's BuildMerkleTreeStore
	return blockchain.BuildMerkleTreeStore(btcTxs, false)
}

// VerifyMerkleProof verifies a merkle proof for a transaction at index 0 (coinbase)
// merkleBranch contains the sibling hashes from leaf to root
func VerifyMerkleProof(txHash chainhash.Hash, merkleBranch [][]byte, merkleRoot common.Hash) bool {
	// Start with the transaction hash
	currentHash := txHash

	// For coinbase (index 0), we always take the right branch
	// and our hash goes on the left
	for _, siblingBytes := range merkleBranch {
		var sibling chainhash.Hash
		copy(sibling[:], siblingBytes)

		// Since we're at index 0 (coinbase), we're always the left child
		currentHash = blockchain.HashMerkleBranches(&currentHash, &sibling)
	}

	// Compare with expected merkle root
	return bytes.Equal(currentHash[:], merkleRoot[:])
}

// ExtractMerkleBranch extracts the merkle branch for the coinbase (index 0)
// from a complete merkle tree
func ExtractMerkleBranch(merkleTree []*chainhash.Hash, txCount int) [][]byte {
	if len(merkleTree) == 0 || txCount == 0 {
		return nil
	}

	var branch [][]byte

	// blockchain.BuildMerkleTreeStore lays out the tree level-by-level using a
	// power-of-two leaf width. Determine that width so we can walk the levels.
	width := 1
	for width < txCount {
		width <<= 1
	}

	index := 0
	levelOffset := 0
	levelWidth := width

	for levelWidth > 1 {
		siblingIndex := index ^ 1
		siblingPos := levelOffset + siblingIndex
		if siblingIndex >= levelWidth || siblingPos >= len(merkleTree) || merkleTree[siblingPos] == nil {
			siblingPos = levelOffset + index
		}
		branch = append(branch, merkleTree[siblingPos][:])

		levelOffset += levelWidth
		index >>= 1
		levelWidth >>= 1
	}

	return branch
}

// HashMerkleBranches is a wrapper around btcd's function for convenience
func HashMerkleBranches(left, right *chainhash.Hash) chainhash.Hash {
	return blockchain.HashMerkleBranches(left, right)
}

// ExtractHeightFromCoinbase extracts the block height from a coinbase transaction's scriptSig
// Returns the height and the offset where extra data begins (KAWPOW format only)
func ExtractHeightFromCoinbase(scriptSig []byte) (uint32, int) {
	if len(scriptSig) < 5 {
		return 0, 0
	}

	// KAWPOW format: expect OP_PUSH4 followed by 4 bytes
	if scriptSig[0] != 0x04 {
		return 0, 0
	}

	height := uint32(scriptSig[1]) |
		uint32(scriptSig[2])<<8 |
		uint32(scriptSig[3])<<16 |
		uint32(scriptSig[4])<<24
	return height, 5
}

// ExtractNoncesFromCoinbase extracts nonces from KAWPOW coinbase scriptSig
// Returns height, extraNonce1, extraNonce2, and remaining data
func ExtractNoncesFromCoinbase(scriptSig []byte) (uint32, uint32, uint64, []byte) {
	if len(scriptSig) < 5 {
		return 0, 0, 0, nil
	}

	offset := 0

	// Extract height (should be OP_PUSH4 + 4 bytes)
	if scriptSig[offset] != 0x04 || len(scriptSig) < offset+5 {
		return 0, 0, 0, nil
	}
	height := uint32(scriptSig[offset+1]) |
		uint32(scriptSig[offset+2])<<8 |
		uint32(scriptSig[offset+3])<<16 |
		uint32(scriptSig[offset+4])<<24
	offset += 5

	var extraNonce1 uint32
	var extraNonce2 uint64

	// Extract extraNonce1 if present (OP_PUSH4 + 4 bytes)
	if offset < len(scriptSig) && scriptSig[offset] == 0x04 && len(scriptSig) >= offset+5 {
		extraNonce1 = uint32(scriptSig[offset+1]) |
			uint32(scriptSig[offset+2])<<8 |
			uint32(scriptSig[offset+3])<<16 |
			uint32(scriptSig[offset+4])<<24
		offset += 5
	}

	// Extract extraNonce2 if present (OP_PUSH8 + 8 bytes)
	if offset < len(scriptSig) && scriptSig[offset] == 0x08 && len(scriptSig) >= offset+9 {
		extraNonce2 = uint64(scriptSig[offset+1]) |
			uint64(scriptSig[offset+2])<<8 |
			uint64(scriptSig[offset+3])<<16 |
			uint64(scriptSig[offset+4])<<24 |
			uint64(scriptSig[offset+5])<<32 |
			uint64(scriptSig[offset+6])<<40 |
			uint64(scriptSig[offset+7])<<48 |
			uint64(scriptSig[offset+8])<<56
		offset += 9
	}

	// Return remaining data
	var remainingData []byte
	if offset < len(scriptSig) {
		// Skip length prefix and extract data
		if scriptSig[offset] <= 75 && len(scriptSig) >= offset+1+int(scriptSig[offset]) {
			dataLen := int(scriptSig[offset])
			remainingData = scriptSig[offset+1 : offset+1+dataLen]
		}
	}

	return height, extraNonce1, extraNonce2, remainingData
}

// UpdateCoinbaseNonce updates the nonces in a coinbase transaction
func UpdateCoinbaseNonce(originalTx *wire.MsgTx, extraNonce1 uint32, extraNonce2 uint64) *wire.MsgTx {
	if originalTx == nil || len(originalTx.TxIn) == 0 {
		return originalTx
	}

	// Copy the transaction
	newTx := originalTx.Copy()

	// Extract existing scriptSig to get height and extra data
	scriptSig := newTx.TxIn[0].SignatureScript
	height, _, _, extraData := ExtractNoncesFromCoinbase(scriptSig)

	// Rebuild the scriptSig with new nonces
	newScriptSig := BuildCoinbaseScriptSigWithNonce(height, extraNonce1, extraNonce2, extraData)
	newTx.TxIn[0].SignatureScript = newScriptSig

	return newTx
}

func UpdateCoinbaseExtraData(originalTx *wire.MsgTx, extraData []byte) *wire.MsgTx {
	if originalTx == nil || len(originalTx.TxIn) == 0 {
		return originalTx
	}

	// Copy the transaction
	newTx := originalTx.Copy()

	// Extract existing scriptSig to get height and nonces
	scriptSig := newTx.TxIn[0].SignatureScript
	height, extraNonce1, extraNonce2, _ := ExtractNoncesFromCoinbase(scriptSig)

	// Rebuild the scriptSig with new extra data
	newScriptSig := BuildCoinbaseScriptSigWithNonce(height, extraNonce1, extraNonce2, extraData)
	newTx.TxIn[0].SignatureScript = newScriptSig

	return newTx
}
