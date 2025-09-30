package types

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"

	"github.com/btcsuite/btcd/wire"
	"golang.org/x/crypto/scrypt"

	"github.com/dominant-strategies/go-quai/common"
)

type bitcoinLikeHeader struct {
	Version        int32
	HashPrevBlock  common.Hash
	HashMerkleRoot common.Hash
	Time           uint32
	Bits           uint32
	Nonce          uint32
}

type BitcoinBlockHeader struct {
	bitcoinLikeHeader
}

type LitecoinBlockHeader struct {
	bitcoinLikeHeader
}

type BitcoinCashBlockHeader struct {
	bitcoinLikeHeader
}

// LitecoinAuxPoW represents the auxiliary proof-of-work data for Dogecoin merged mining with Litecoin
type LitecoinAuxPoW struct {
	// Parent block header (80 bytes) from the Litecoin parent chain
	ParentHeader []byte
	// Coinbase transaction that commits to the aux chain
	CoinbaseTx []byte
	// Merkle branch from coinbase to parent block merkle root
	MerkleBranch []string
	// Chain merkle branch for aux chain commitment
	ChainMerkleBranch []string
	// Chain index for proper merkle branch ordering
	ChainIndex int
}

// Dogecoin uses AuxPoW (merged mining). The block header itself remains
// 80 bytes, but PoW is validated against the parent chain header (Litecoin)
// provided via AuxPoW. We keep the full AuxPoW data for complete validation.
type DogecoinBlockHeader struct {
	bitcoinLikeHeader
	// LitecoinAuxPoW contains the complete auxiliary proof-of-work data from Litecoin
	LitecoinAuxPoW *LitecoinAuxPoW
}

func (h *bitcoinLikeHeader) encodeBinary() []byte {
	var buf bytes.Buffer
	binary.Write(&buf, binary.LittleEndian, h.Version)
	buf.Write(reverseBytesCopy(h.HashPrevBlock.Bytes()))
	buf.Write(reverseBytesCopy(h.HashMerkleRoot.Bytes()))
	binary.Write(&buf, binary.LittleEndian, h.Time)
	binary.Write(&buf, binary.LittleEndian, h.Bits)
	binary.Write(&buf, binary.LittleEndian, h.Nonce)
	return buf.Bytes()
}

func (h *bitcoinLikeHeader) hash() common.Hash {
	data := h.encodeBinary()
	return doubleSHA256Hash(data)
}

func compactToTarget(bits uint32) *big.Int {
	exponent := (bits >> 24) & 0xff
	mantissa := bits & 0x00ffffff

	target := new(big.Int).SetUint64(uint64(mantissa))
	shift := int(exponent) - 3
	if shift < 0 {
		target.Rsh(target, uint(-shift*8))
	} else {
		target.Lsh(target, uint(shift*8))
	}
	return target
}

func comparePoW(hash common.Hash, bits uint32) bool {
	hashNum := new(big.Int).SetBytes(hash.Bytes())
	target := compactToTarget(bits)
	return hashNum.Cmp(target) <= 0
}

func reverseBytesCopy(b []byte) []byte {
	out := make([]byte, len(b))
	for i := range b {
		out[i] = b[len(b)-1-i]
	}
	return out
}

func doubleSHA256Hash(data []byte) common.Hash {
	first := sha256.Sum256(data)
	second := sha256.Sum256(first[:])
	return common.BytesToHash(reverseBytesCopy(second[:]))
}

func litecoinScryptHash(data []byte) (common.Hash, error) {
	digest, err := scrypt.Key(data, data, 1024, 1, 1, 32)
	if err != nil {
		return common.Hash{}, err
	}
	return common.BytesToHash(reverseBytesCopy(digest)), nil
}

// reverseHexString reverses bytes of a hex string for merkle proof validation
func reverseHexString(s string) string {
	b, _ := hex.DecodeString(s)
	for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
	return hex.EncodeToString(b)
}

// Note: parent merkle proof validation uses VerifyMerkleProof from btcd_merkle_utils.go

func (h *BitcoinBlockHeader) EncodeBinary() []byte     { return h.encodeBinary() }
func (h *LitecoinBlockHeader) EncodeBinary() []byte    { return h.encodeBinary() }
func (h *BitcoinCashBlockHeader) EncodeBinary() []byte { return h.encodeBinary() }
func (h *DogecoinBlockHeader) EncodeBinary() []byte    { return h.encodeBinary() }

func DecodeBitcoinHeader(data []byte) (*BitcoinBlockHeader, error) {
	hdr, err := decodeBitcoinLikeHeader(data)
	if err != nil {
		return nil, err
	}
	return &BitcoinBlockHeader{*hdr}, nil
}

func DecodeLitecoinHeader(data []byte) (*LitecoinBlockHeader, error) {
	hdr, err := decodeBitcoinLikeHeader(data)
	if err != nil {
		return nil, err
	}
	return &LitecoinBlockHeader{*hdr}, nil
}

func DecodeBitcoinCashHeader(data []byte) (*BitcoinCashBlockHeader, error) {
	hdr, err := decodeBitcoinLikeHeader(data)
	if err != nil {
		return nil, err
	}
	return &BitcoinCashBlockHeader{*hdr}, nil
}

func DecodeDogecoinHeader(data []byte) (*DogecoinBlockHeader, error) {
	hdr, err := decodeBitcoinLikeHeader(data)
	if err != nil {
		return nil, err
	}
	return &DogecoinBlockHeader{bitcoinLikeHeader: *hdr}, nil
}

func decodeBitcoinLikeHeader(data []byte) (*bitcoinLikeHeader, error) {
	if len(data) < 80 {
		return nil, fmt.Errorf("header data too short: %d bytes (minimum 80)", len(data))
	}
	buf := bytes.NewReader(data[:80])
	h := &bitcoinLikeHeader{}
	if err := binary.Read(buf, binary.LittleEndian, &h.Version); err != nil {
		return nil, err
	}
	var tmp [32]byte
	if _, err := io.ReadFull(buf, tmp[:]); err != nil {
		return nil, err
	}
	copy(h.HashPrevBlock[:], reverseBytesCopy(tmp[:]))
	if _, err := io.ReadFull(buf, tmp[:]); err != nil {
		return nil, err
	}
	copy(h.HashMerkleRoot[:], reverseBytesCopy(tmp[:]))
	if err := binary.Read(buf, binary.LittleEndian, &h.Time); err != nil {
		return nil, err
	}
	if err := binary.Read(buf, binary.LittleEndian, &h.Bits); err != nil {
		return nil, err
	}
	if err := binary.Read(buf, binary.LittleEndian, &h.Nonce); err != nil {
		return nil, err
	}
	return h, nil
}

func (h *BitcoinBlockHeader) Hash() common.Hash     { return h.hash() }
func (h *LitecoinBlockHeader) Hash() common.Hash    { return h.hash() }
func (h *BitcoinCashBlockHeader) Hash() common.Hash { return h.hash() }
func (h *DogecoinBlockHeader) Hash() common.Hash    { return h.hash() }

func (h *BitcoinBlockHeader) VerifyPow() (common.Hash, bool) {
	powHash := h.Hash()
	return powHash, comparePoW(powHash, h.Bits)
}

func (h *LitecoinBlockHeader) VerifyPow() (common.Hash, bool) {
	powHash, err := litecoinScryptHash(h.encodeBinary())
	if err != nil {
		return common.Hash{}, false
	}
	return powHash, comparePoW(powHash, h.Bits)
}

func (h *BitcoinCashBlockHeader) VerifyPow() (common.Hash, bool) {
	powHash := h.Hash()
	return powHash, comparePoW(powHash, h.Bits)
}

// VerifyPow for Dogecoin validates the complete AuxPoW proof.
// It verifies:
// 1. Parent block PoW (scrypt) satisfies Dogecoin difficulty
// 2. Coinbase transaction contains merged mining commitment
// 3. Chain merkle proof that commits to this Dogecoin block
// 4. Merkle proof from coinbase to parent block merkle root
// Returns the parent block PoW hash and an error if validation fails.
func (h *DogecoinBlockHeader) VerifyPow() (common.Hash, error) {
	// Require LitecoinAuxPoW for proper validation
	if h.LitecoinAuxPoW == nil {
		return common.Hash{}, fmt.Errorf("dogecoin block requires LitecoinAuxPoW for validation")
	}

	auxPow := h.LitecoinAuxPoW

	// 1. Validate parent block PoW
	powHash, err := h.validateParentBlockPoW(auxPow.ParentHeader)
	if err != nil {
		return powHash, err
	}

	// 2. Parse and validate coinbase transaction
	coinbaseTx, err := h.parseCoinbaseTransaction(auxPow.CoinbaseTx)
	if err != nil {
		return powHash, err
	}

	// 3. Verify merged mining commitment in coinbase scriptSig
	err = h.validateMergedMiningCommitment(coinbaseTx, auxPow.ChainMerkleBranch, auxPow.ChainIndex)
	if err != nil {
		return powHash, err
	}

	// 4. Verify merkle proof from coinbase to parent block merkle root
	err = h.validateParentMerkleProof(coinbaseTx, auxPow.MerkleBranch, auxPow.ParentHeader)
	if err != nil {
		return powHash, err
	}

	return powHash, nil
}

// validateParentBlockPoW validates that the parent block's PoW satisfies the Dogecoin difficulty
func (h *DogecoinBlockHeader) validateParentBlockPoW(parentHeader []byte) (common.Hash, error) {
	if len(parentHeader) < 80 {
		return common.Hash{}, fmt.Errorf("parent header too short: %d bytes (minimum 80)", len(parentHeader))
	}

	powHash, err := litecoinScryptHash(parentHeader[:80])
	if err != nil {
		return common.Hash{}, fmt.Errorf("failed to compute scrypt hash: %w", err)
	}

	if !comparePoW(powHash, h.Bits) {
		return powHash, fmt.Errorf("parent block PoW does not satisfy Dogecoin difficulty target")
	}

	return powHash, nil
}

// parseCoinbaseTransaction parses and validates the coinbase transaction
func (h *DogecoinBlockHeader) parseCoinbaseTransaction(coinbaseTxBytes []byte) (*wire.MsgTx, error) {
	var cb wire.MsgTx
	err := cb.Deserialize(bytes.NewReader(coinbaseTxBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize coinbase transaction: %w", err)
	}

	if len(cb.TxIn) == 0 {
		return nil, fmt.Errorf("coinbase transaction has no inputs")
	}

	return &cb, nil
}

// validateMergedMiningCommitment verifies the merged mining commitment in the coinbase scriptSig
func (h *DogecoinBlockHeader) validateMergedMiningCommitment(coinbaseTx *wire.MsgTx, chainMerkleBranch []string, chainIndex int) error {
	scriptSig := coinbaseTx.TxIn[0].SignatureScript
	magic := []byte{0xfa, 0xbe, 0x6d, 0x6d}
	idx := bytes.Index(scriptSig, magic)

	if idx < 0 {
		return fmt.Errorf("merged mining magic not found in coinbase scriptSig")
	}

	if len(scriptSig) < idx+4+32+8 {
		return fmt.Errorf("coinbase scriptSig too short for merged mining commitment")
	}

	// Extract chain merkle commitment
	chainRootFromScript := scriptSig[idx+4 : idx+4+32]

	if !h.validateChainCommitment(chainRootFromScript, chainMerkleBranch, chainIndex) {
		return fmt.Errorf("chain merkle commitment validation failed")
	}

	return nil
}

// validateParentMerkleProof verifies the merkle proof from coinbase to parent block merkle root
func (h *DogecoinBlockHeader) validateParentMerkleProof(coinbaseTx *wire.MsgTx, merkleBranch []string, parentHeader []byte) error {
    if len(parentHeader) < 80 {
        return fmt.Errorf("parent header too short: %d", len(parentHeader))
    }

    // Parent merkle root in header is already in internal (little-endian) byte order
    var parentRoot common.Hash
    copy(parentRoot[:], parentHeader[36:68])

    // Build merkle branch in internal order (reverse each sibling from display hex)
    branchLE := make([][]byte, len(merkleBranch))
    for i, s := range merkleBranch {
        b := common.FromHex(s)
        // reverse to little-endian
        for l, r := 0, len(b)-1; l < r; l, r = l+1, r-1 {
            b[l], b[r] = b[r], b[l]
        }
        branchLE[i] = b
    }

    if !VerifyMerkleProof(coinbaseTx.TxHash(), branchLE, parentRoot) {
        return fmt.Errorf("merkle proof validation failed")
    }
    return nil
}

// validateChainCommitment verifies that the chain commitment includes this Dogecoin block
// This implements the chain merkle proof validation for merged mining
func (h *DogecoinBlockHeader) validateChainCommitment(chainRootFromScript []byte, chainMerkleBranch []string, chainIndex int) bool {
	// Start with Dogecoin block hash as hex string (strip 0x prefix)
	current := h.Hash().Hex()
	if len(current) >= 2 && (current[:2] == "0x" || current[:2] == "0X") {
		current = current[2:]
	}

	// Use chainIndex bits to decide concatenation order at each level
	idx := chainIndex
	for _, proof := range chainMerkleBranch {
		curBytes, err := hex.DecodeString(reverseHexString(current))
		if err != nil {
			return false
		}
		proofBytes, err := hex.DecodeString(reverseHexString(proof))
		if err != nil {
			return false
		}

		var combined []byte
		if (idx & 1) == 1 {
			// current on right: H(proof || current)
			combined = append(proofBytes, curBytes...)
		} else {
			// current on left: H(current || proof)
			combined = append(curBytes, proofBytes...)
		}

		h1 := sha256.Sum256(combined)
		h2 := sha256.Sum256(h1[:])
		current = reverseHexString(hex.EncodeToString(h2[:]))
		idx >>= 1
	}

	// Compare final result with commitment from coinbase (accept either orientation)
	finalBytes, err := hex.DecodeString(current)
	if err != nil {
		return false
	}
	return bytes.Equal(finalBytes, chainRootFromScript) || bytes.Equal(reverseBytesCopy(finalBytes), chainRootFromScript)
}
