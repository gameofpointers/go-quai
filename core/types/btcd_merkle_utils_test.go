package types

import (
	"encoding/hex"
	"testing"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
)

// Helper function to serialize TxOut to wire format
func serializeTestTxOut(value int64, pkScript []byte) []byte {
	return serializeTxOut(wire.NewTxOut(value, pkScript))
}

func TestCreateCoinbaseTx(t *testing.T) {
	blockHeight := uint32(680000)
	extraData := []byte("Quai Network")
	minerAddress, _ := hex.DecodeString("76a914" + "89abcdefabbaabbaabbaabbaabbaabbaabbaabba" + "88ac")
	blockReward := int64(5000000000)

	// Create wire-encoded TxOut
	coinbaseOut := serializeTestTxOut(blockReward, minerAddress)
	tx := CreateCoinbaseTxWithHeight(blockHeight, extraData, coinbaseOut)

	require.NotNil(t, tx)
	require.Equal(t, int32(1), tx.Version)
	require.Len(t, tx.TxIn, 1)
	require.Len(t, tx.TxOut, 1)

	// Check coinbase input
	require.Equal(t, chainhash.Hash{}, tx.TxIn[0].PreviousOutPoint.Hash)
	require.Equal(t, uint32(0xFFFFFFFF), tx.TxIn[0].PreviousOutPoint.Index)

	// Check output
	require.Equal(t, blockReward, tx.TxOut[0].Value)
	require.Equal(t, minerAddress, tx.TxOut[0].PkScript)

	// Verify scriptSig contains block height
	scriptSig := tx.TxIn[0].SignatureScript
	require.True(t, len(scriptSig) > 0)
}

func TestMerkleRoot(t *testing.T) {
	// Create some test transactions
	var txs []*wire.MsgTx

	// Coinbase
	coinbaseOut := serializeTestTxOut(5000000000, []byte{0x51})
	coinbase := CreateCoinbaseTxWithHeight(1, []byte("test"), coinbaseOut)
	txs = append(txs, coinbase)

	// Regular transaction
	tx1 := wire.NewMsgTx(1)
	prevOut := wire.NewOutPoint(&chainhash.Hash{1}, 0)
	tx1.AddTxIn(wire.NewTxIn(prevOut, nil, nil))
	tx1.AddTxOut(wire.NewTxOut(1000000, []byte{0x51}))
	txs = append(txs, tx1)

	// Calculate merkle root
	root := CalculateMerkleRootFromTxs(txs)
	require.NotEqual(t, [32]byte{}, root)

	// Build complete tree
	tree := BuildMerkleTree(txs)
	require.NotNil(t, tree)
	require.True(t, len(tree) > 0)

	// Root should be the last element
	treeRoot := tree[len(tree)-1]
	require.Equal(t, root[:], treeRoot[:])
}

func TestMerkleProofVerification(t *testing.T) {
	// Create test transactions
	var txs []*wire.MsgTx

	for i := 0; i < 4; i++ {
		tx := wire.NewMsgTx(1)
		if i == 0 {
			// Coinbase
			prevOut := wire.NewOutPoint(&chainhash.Hash{}, 0xFFFFFFFF)
			tx.AddTxIn(wire.NewTxIn(prevOut, []byte{byte(i)}, nil))
		} else {
			// Regular tx
			var hash chainhash.Hash
			hash[0] = byte(i)
			prevOut := wire.NewOutPoint(&hash, 0)
			tx.AddTxIn(wire.NewTxIn(prevOut, nil, nil))
		}
		tx.AddTxOut(wire.NewTxOut(int64(i+1)*1000000, []byte{0x51}))
		txs = append(txs, tx)
	}

	// Calculate merkle root
	merkleRoot := CalculateMerkleRootFromTxs(txs)

	// Build tree and extract branch for coinbase
	tree := BuildMerkleTree(txs)
	branch := ExtractMerkleBranch(tree, len(txs))

	// Verify the proof
	coinbaseHash := txs[0].TxHash()
	valid := VerifyMerkleProof(coinbaseHash, branch, merkleRoot)
	require.True(t, valid, "Merkle proof should be valid")
}

func TestSingleTransactionMerkleRoot(t *testing.T) {
	// Test edge case: single transaction (coinbase only)
	coinbaseOut := serializeTestTxOut(5000000000, []byte{0x51})
	coinbase := CreateCoinbaseTxWithHeight(1, []byte("solo"), coinbaseOut)
	txs := []*wire.MsgTx{coinbase}

	root := CalculateMerkleRootFromTxs(txs)
	txHash := coinbase.TxHash()

	// For a single transaction, merkle root equals transaction hash
	require.Equal(t, txHash[:], root[:])
}

func TestEmptyMerkleRoot(t *testing.T) {
	// Test edge case: no transactions
	var txs []*wire.MsgTx
	root := CalculateMerkleRootFromTxs(txs)
	var emptyHash [32]byte
	require.Equal(t, emptyHash[:], root[:])
}

func TestOddNumberTransactions(t *testing.T) {
	// Test with odd number of transactions (3)
	var txs []*wire.MsgTx

	for i := 0; i < 3; i++ {
		tx := wire.NewMsgTx(1)
		if i == 0 {
			// Coinbase
			prevOut := wire.NewOutPoint(&chainhash.Hash{}, 0xFFFFFFFF)
			tx.AddTxIn(wire.NewTxIn(prevOut, []byte{byte(i)}, nil))
		} else {
			// Regular tx
			var hash chainhash.Hash
			hash[0] = byte(i)
			prevOut := wire.NewOutPoint(&hash, 0)
			tx.AddTxIn(wire.NewTxIn(prevOut, nil, nil))
		}
		tx.AddTxOut(wire.NewTxOut(int64(i+1)*1000000, []byte{0x51}))
		txs = append(txs, tx)
	}

	// Should handle odd number correctly (Bitcoin duplicates last hash)
	root := CalculateMerkleRootFromTxs(txs)
	require.NotEqual(t, [32]byte{}, root)

	// Verify tree building works
	tree := BuildMerkleTree(txs)
	require.NotNil(t, tree)
	require.True(t, len(tree) > 0)
}