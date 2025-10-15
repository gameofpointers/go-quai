package types

import (
	"io"

	"github.com/dominant-strategies/go-quai/common"
	ltchash "github.com/ltcsuite/ltcd/chaincfg/chainhash"
	ltcdwire "github.com/ltcsuite/ltcd/wire"
)

// LitecoinHeaderWrapper wraps ltcdwire.BlockHeader to implement AuxHeaderData
type LitecoinHeaderWrapper struct {
	*ltcdwire.BlockHeader
}

type LitecoinCoinbaseTxWrapper struct {
	*ltcdwire.MsgTx
}

type LitecoinCoinbaseTxOutWrapper struct {
	*ltcdwire.TxOut
}

func NewLitecoinCoinbaseTx(version int32) *ltcdwire.MsgTx {
	return ltcdwire.NewMsgTx(version)
}

func NewLitecoinCoinbaseTxOut(value int64, pkScript []byte) *LitecoinCoinbaseTxOutWrapper {
	return &LitecoinCoinbaseTxOutWrapper{TxOut: &ltcdwire.TxOut{Value: value, PkScript: pkScript}}
}

func NewLitecoinHeaderWrapper(header *ltcdwire.BlockHeader) *LitecoinHeaderWrapper {
	return &LitecoinHeaderWrapper{BlockHeader: header}
}

func (ltc *LitecoinHeaderWrapper) PowHash() common.Hash {
	blockHash := ltc.BlockHeader.BlockHash()
	return common.BytesToHash(reverseBytesCopy(blockHash[:]))
}

func (ltc *LitecoinHeaderWrapper) Serialize(wr io.Writer) error {
	return ltc.BlockHeader.Serialize(wr)
}

func (ltc *LitecoinHeaderWrapper) Deserialize(r io.Reader) error {
	ltc.BlockHeader = &ltcdwire.BlockHeader{}
	return ltc.BlockHeader.Deserialize(r)
}

func NewLitecoinBlockHeader(version int32, prevBlockHash [32]byte, merkleRootHash [32]byte, time uint32, bits uint32, nonce uint32) *LitecoinHeaderWrapper {
	prevHash := ltchash.Hash{}
	copy(prevHash[:], prevBlockHash[:])
	merkleRoot := ltchash.Hash{}
	copy(merkleRoot[:], merkleRootHash[:])
	header := ltcdwire.NewBlockHeader(version, &prevHash, &merkleRoot, bits, nonce)
	return &LitecoinHeaderWrapper{BlockHeader: header}
}

func (ltc *LitecoinHeaderWrapper) GetVersion() int32 {
	return ltc.BlockHeader.Version
}

func (ltc *LitecoinHeaderWrapper) GetPrevBlock() [32]byte {
	return [32]byte(ltc.BlockHeader.PrevBlock)
}

func (ltc *LitecoinHeaderWrapper) GetMerkleRoot() [32]byte {
	return [32]byte(ltc.BlockHeader.MerkleRoot)
}

func (ltc *LitecoinHeaderWrapper) GetTimestamp() uint32 {
	return uint32(ltc.BlockHeader.Timestamp.Unix())
}

func (ltc *LitecoinHeaderWrapper) GetBits() uint32 {
	return ltc.BlockHeader.Bits
}

func (ltc *LitecoinHeaderWrapper) GetNonce() uint32 {
	return ltc.BlockHeader.Nonce
}

func (ltc *LitecoinHeaderWrapper) GetNonce64() uint64 {
	// Standard Litecoin headers don't have a 64-bit nonce
	return 0
}

func (ltc *LitecoinHeaderWrapper) GetMixHash() common.Hash {
	// Standard Litecoin headers don't have a mix hash
	return common.Hash{}
}

func (ltc *LitecoinHeaderWrapper) GetHeight() uint32 {
	// Standard Litecoin headers don't include height
	return 0
}

func (ltc *LitecoinHeaderWrapper) GetSealHash() common.Hash {
	// Standard Litecoin headers don't have a seal hash
	return common.Hash{}
}

func (ltc *LitecoinHeaderWrapper) SetNonce(nonce uint32) {
	ltc.BlockHeader.Nonce = nonce
}

func (ltc *LitecoinHeaderWrapper) SetNonce64(nonce uint64) {
	// Standard Litecoin headers don't have a 64-bit nonce, so this is a no-op
}

func (ltc *LitecoinHeaderWrapper) SetMixHash(mixHash common.Hash) {
	// Standard Litecoin headers don't have a mix hash, so this is a no-op
}

func (ltc *LitecoinHeaderWrapper) SetHeight(height uint32) {
	// Standard Litecoin headers don't have a height, so this is a no-op
}

func (ltc *LitecoinHeaderWrapper) Copy() *LitecoinHeaderWrapper {
	copiedHeader := *ltc.BlockHeader
	return &LitecoinHeaderWrapper{BlockHeader: &copiedHeader}
}

// CoinbaseTx functions
func (lct *LitecoinCoinbaseTxWrapper) Copy() AuxPowCoinbaseTxData {
	return &LitecoinCoinbaseTxWrapper{MsgTx: lct.MsgTx.Copy()}
}

func (lct *LitecoinCoinbaseTxWrapper) scriptSig() []byte {
	if lct.MsgTx == nil || len(lct.MsgTx.TxIn) == 0 {
		return nil
	}
	return lct.MsgTx.TxIn[0].SignatureScript
}

// CoinbaseTxOut functions
func (lco *LitecoinCoinbaseTxOutWrapper) Value() int64 {
	return lco.TxOut.Value
}

func (lco *LitecoinCoinbaseTxOutWrapper) PkScript() []byte {
	return lco.TxOut.PkScript
}
