package types

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
)

// TestDecodeRavencoinCoinbaseFromSnapshot ensures that coinbase transactions
// in the provided Ravencoin snapshot can be decoded using the non-witness
// helper that wraps btcd's wire.MsgTx.
func TestDecodeRavencoinCoinbaseFromSnapshot(t *testing.T) {
	_, thisFile, _, _ := runtime.Caller(0)
	repoRoot := filepath.Clean(filepath.Join(filepath.Dir(thisFile), "..", ".."))
	blockFile := filepath.Join(repoRoot, "raven-data", "home", "drk", "raven-snapshot", "blocks", "blk00226.dat")

	if _, err := os.Stat(blockFile); errors.Is(err, os.ErrNotExist) {
		t.Skipf("snapshot file %s not present", blockFile)
	} else if err != nil {
		t.Fatalf("failed to stat block file: %v", err)
	}

	fh, err := os.Open(blockFile)
	require.NoError(t, err)
	defer fh.Close()

	reader := bufio.NewReader(fh)

	const blocksToCheck = 5

	for i := 0; i < blocksToCheck; i++ {
		magic := make([]byte, 4)
		if _, err := io.ReadFull(reader, magic); err != nil {
			t.Fatalf("read magic (%d): %v", i, err)
		}
		if string(magic) != "RAVN" {
			t.Fatalf("unexpected magic %q in block %d", string(magic), i)
		}

		sizeBytes := make([]byte, 4)
		if _, err := io.ReadFull(reader, sizeBytes); err != nil {
			t.Fatalf("read size (%d): %v", i, err)
		}
		size := binary.LittleEndian.Uint32(sizeBytes)

		block := make([]byte, size)
		if _, err := io.ReadFull(reader, block); err != nil {
			t.Fatalf("read block payload (%d): %v", i, err)
		}
		require.GreaterOrEqual(t, len(block), 120)

		_, err = DecodeRavencoinHeader(block[:120])
		require.NoError(t, err)

		txReader := bufio.NewReader(bytes.NewReader(block[120:]))
		txCount, err := wire.ReadVarInt(txReader, wire.ProtocolVersion)
		require.NoError(t, err)
		require.Greater(t, txCount, uint64(0))

		tx, err := DecodeRavencoinTransaction(txReader)
		require.NoError(t, err)
		require.NotNil(t, tx)
		t.Logf("block %d tx version=%d inputs=%d outputs=%d", i, tx.Version, len(tx.TxIn), len(tx.TxOut))
		require.NotEmpty(t, tx.TxIn, "coinbase must have inputs")
		require.NotEmpty(t, tx.TxOut, "coinbase must have outputs")
	}
}

// TestRavencoinMerkleRootFromSnapshot recomputes the merkle root for the
// transactions in sampled Ravencoin blocks and ensures it matches the header
// commitment. It also verifies that the extracted merkle branch validates at
// the coinbase.
func TestRavencoinMerkleRootFromSnapshot(t *testing.T) {
	_, thisFile, _, _ := runtime.Caller(0)
	repoRoot := filepath.Clean(filepath.Join(filepath.Dir(thisFile), "..", ".."))
	blockFile := filepath.Join(repoRoot, "raven-data", "home", "drk", "raven-snapshot", "blocks", "blk00226.dat")

	if _, err := os.Stat(blockFile); errors.Is(err, os.ErrNotExist) {
		t.Skipf("snapshot file %s not present", blockFile)
	} else if err != nil {
		t.Fatalf("failed to stat block file: %v", err)
	}

	fh, err := os.Open(blockFile)
	require.NoError(t, err)
	defer fh.Close()

	reader := bufio.NewReader(fh)

	const blocksToCheck = 5

	for i := 0; i < blocksToCheck; i++ {
		magic := make([]byte, 4)
		if _, err := io.ReadFull(reader, magic); err != nil {
			if err == io.EOF {
				break
			}
			t.Fatalf("read magic (%d): %v", i, err)
		}
		if string(magic) != "RAVN" {
			t.Fatalf("unexpected magic %q in block %d", string(magic), i)
		}

		sizeBytes := make([]byte, 4)
		if _, err := io.ReadFull(reader, sizeBytes); err != nil {
			t.Fatalf("read size (%d): %v", i, err)
		}
		size := binary.LittleEndian.Uint32(sizeBytes)

		block := make([]byte, size)
		if _, err := io.ReadFull(reader, block); err != nil {
			t.Fatalf("read block payload (%d): %v", i, err)
		}
		require.GreaterOrEqual(t, len(block), 120)

		header, err := DecodeRavencoinHeader(block[:120])
		require.NoError(t, err)

		txReader := bufio.NewReader(bytes.NewReader(block[120:]))
		txCount, err := wire.ReadVarInt(txReader, wire.ProtocolVersion)
		require.NoError(t, err)
		require.Greater(t, txCount, uint64(0))

		txs := make([]*wire.MsgTx, 0, txCount)
		for j := uint64(0); j < txCount; j++ {
			tx, err := DecodeRavencoinTransaction(txReader)
			require.NoError(t, err)
			txs = append(txs, tx)
		}

		// Reconstruct merkle root from transactions and compare to header.
		rebuiltRoot := CalculateMerkleRootFromTxs(txs)
		require.Equalf(t, header.HashMerkleRoot.Hex(), rebuiltRoot.Hex(), "merkle root mismatch for block %d", header.Height)

		// Build merkle branch for the coinbase (index 0) and verify it matches.
		tree := BuildMerkleTree(txs)
		branch := ExtractMerkleBranch(tree, len(txs))
		coinbaseHash := txs[0].TxHash()
		require.Truef(t, VerifyMerkleProof(coinbaseHash, branch, header.HashMerkleRoot), "merkle proof invalid for block %d", header.Height)
	}
}
