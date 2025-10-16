package types

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"

	btcblockchain "github.com/btcsuite/btcd/blockchain"
	btcutil "github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/dominant-strategies/go-quai/common"
	ltcblockchain "github.com/dominant-strategies/ltcd/blockchain"
	ltcchainhash "github.com/dominant-strategies/ltcd/chaincfg/chainhash"
	ltcutil "github.com/dominant-strategies/ltcd/ltcutil"
	bchblockchain "github.com/gcash/bchd/blockchain"
	bchchainhash "github.com/gcash/bchd/chaincfg/chainhash"
	bchutil "github.com/gcash/bchutil"
)

// ExtractSealHashFromCoinbase scans a Ravencoin coinbase scriptSig and returns the
// embedded seal hash, if present.
func ExtractSealHashFromCoinbase(scriptSig []byte) (common.Hash, error) {
	if len(scriptSig) == 0 {
		return common.Hash{}, errors.New("coinbase scriptSig empty")
	}

	cursor := 0

	// First push must be the encoded height (ignore the actual value).
	_, consumed, err := parseScriptPush(scriptSig[cursor:])
	if err != nil {
		return common.Hash{}, fmt.Errorf("decode coinbase height: %w", err)
	}
	cursor += consumed

	for cursor < len(scriptSig) {
		sealBytes, consumed, err := parseScriptPush(scriptSig[cursor:])
		if err != nil {
			return common.Hash{}, fmt.Errorf("decode coinbase push: %w", err)
		}
		cursor += consumed

		if len(sealBytes) == common.HashLength {
			return common.BytesToHash(sealBytes), nil
		}

		if nested := searchSealHash(sealBytes); len(nested) == common.HashLength {
			return common.BytesToHash(nested), nil
		}
	}

	return common.Hash{}, errors.New("seal hash not found in coinbase script")
}

func searchSealHash(payload []byte) []byte {
	idx := 0
	for idx < len(payload) {
		data, consumed, err := parseScriptPush(payload[idx:])
		if err != nil {
			return nil
		}
		idx += consumed

		if len(data) == common.HashLength {
			return data
		}
	}
	return nil
}

func parseScriptPush(script []byte) ([]byte, int, error) {
	if len(script) == 0 {
		return nil, 0, errors.New("empty script segment")
	}

	opcode := script[0]
	read := 1
	var dataLen int

	switch {
	case opcode <= 75:
		dataLen = int(opcode)
	case opcode == 0x4c: // OP_PUSHDATA1
		if len(script) < 2 {
			return nil, 0, errors.New("short OP_PUSHDATA1")
		}
		dataLen = int(script[1])
		read++
	case opcode == 0x4d: // OP_PUSHDATA2
		if len(script) < 3 {
			return nil, 0, errors.New("short OP_PUSHDATA2")
		}
		dataLen = int(binary.LittleEndian.Uint16(script[1:3]))
		read += 2
	default:
		return nil, 0, fmt.Errorf("unsupported opcode 0x%x in coinbase script", opcode)
	}

	if len(script) < read+dataLen {
		return nil, 0, errors.New("coinbase push exceeds script bounds")
	}

	return script[read : read+dataLen], read + dataLen, nil
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
	root := btcblockchain.CalcMerkleRoot(btcTxs, false) // false = not witness
	return common.BytesToHash(root[:])
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
		currentHash = btcblockchain.HashMerkleBranches(&currentHash, &sibling)
	}

	// Compare with expected merkle root
	return bytes.Equal(currentHash[:], merkleRoot[:])
}

func BuildMerkleTreeStore(powID PowID, txs []*AuxPowTx, witness bool) []*chainhash.Hash {
	switch powID {
	case Kawpow:
		transactions := make([]*btcutil.Tx, len(txs))
		for i, tx := range txs {
			ravenTx, ok := tx.inner.(*RavencoinTx)
			if !ok || ravenTx == nil || ravenTx.MsgTx == nil {
				return nil
			}
			transactions[i] = btcutil.NewTx(ravenTx.MsgTx)
		}
		return btcblockchain.BuildMerkleTreeStore(transactions, witness)
	case Scrypt:
		transactions := make([]*ltcutil.Tx, len(txs))
		for i, tx := range txs {
			litecoinTx, ok := tx.inner.(*LitecoinTxWrapper)
			if !ok || litecoinTx == nil || litecoinTx.MsgTx == nil {
				return nil
			}
			transactions[i] = ltcutil.NewTx(litecoinTx.MsgTx)
		}
		ltcTree := ltcblockchain.BuildMerkleTreeStore(transactions, witness)
		return convertLTCChainhashSlice(ltcTree)
	case SHA_BTC:
		transactions := make([]*btcutil.Tx, len(txs))
		for i, tx := range txs {
			bitcoinTx, ok := tx.inner.(*BitcoinTxWrapper)
			if !ok || bitcoinTx == nil || bitcoinTx.MsgTx == nil {
				return nil
			}
			transactions[i] = btcutil.NewTx(bitcoinTx.MsgTx)
		}
		return btcblockchain.BuildMerkleTreeStore(transactions, witness)
	case SHA_BCH:
		transactions := make([]*bchutil.Tx, len(txs))
		for i, tx := range txs {
			bitcoinCashTx, ok := tx.inner.(*BitcoinCashTxWrapper)
			if !ok || bitcoinCashTx == nil || bitcoinCashTx.MsgTx == nil {
				return nil
			}
			transactions[i] = bchutil.NewTx(bitcoinCashTx.MsgTx)
		}
		bchTree := bchblockchain.BuildMerkleTreeStore(transactions)
		return convertBCHChainhashSlice(bchTree)
	}
	return nil
}

func convertLTCChainhashSlice(input []*ltcchainhash.Hash) []*chainhash.Hash {
	if input == nil {
		return nil
	}
	out := make([]*chainhash.Hash, len(input))
	for i, h := range input {
		if h == nil {
			continue
		}
		converted := new(chainhash.Hash)
		copy(converted[:], h[:])
		out[i] = converted
	}
	return out
}

func convertBCHChainhashSlice(input []*bchchainhash.Hash) []*chainhash.Hash {
	if input == nil {
		return nil
	}
	out := make([]*chainhash.Hash, len(input))
	for i, h := range input {
		if h == nil {
			continue
		}
		converted := new(chainhash.Hash)
		copy(converted[:], h[:])
		out[i] = converted
	}
	return out
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
