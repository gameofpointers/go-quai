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
	tx := wire.NewMsgTx(1)

	// Coinbase input (null hash, max index)
	prevOut := wire.NewOutPoint(&chainhash.Hash{}, 0xFFFFFFFF)

	// Build scriptSig with height (BIP34) and extra data
	scriptSig := BuildCoinbaseScriptSig(blockHeight, extraData)

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

	// Calculate tree structure
	treeHeight := 0
	for size := txCount; size > 1; size = (size + 1) / 2 {
		treeHeight++
	}

	// For coinbase (index 0), collect right siblings at each level
	index := 0
	levelSize := txCount
	offset := 0

	for h := 0; h < treeHeight; h++ {
		// Get sibling index
		siblingIndex := index ^ 1 // XOR with 1 to get sibling

		// If sibling exists at this level
		if siblingIndex < levelSize {
			// Get the sibling hash from the tree
			if offset+siblingIndex < len(merkleTree) && merkleTree[offset+siblingIndex] != nil {
				branch = append(branch, merkleTree[offset+siblingIndex][:])
			} else if offset+index < len(merkleTree) && merkleTree[offset+index] != nil {
				// If no sibling, duplicate self (Bitcoin merkle tree rule)
				branch = append(branch, merkleTree[offset+index][:])
			}
		}

		// Move to parent level
		offset += levelSize
		levelSize = (levelSize + 1) / 2
		index = index / 2
	}

	return branch
}

// HashMerkleBranches is a wrapper around btcd's function for convenience
func HashMerkleBranches(left, right *chainhash.Hash) chainhash.Hash {
	return blockchain.HashMerkleBranches(left, right)
}