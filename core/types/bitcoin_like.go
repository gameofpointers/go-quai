package types

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"

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

func (h *BitcoinBlockHeader) EncodeBinary() []byte     { return h.encodeBinary() }
func (h *LitecoinBlockHeader) EncodeBinary() []byte    { return h.encodeBinary() }
func (h *BitcoinCashBlockHeader) EncodeBinary() []byte { return h.encodeBinary() }

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
