package types

import (
	"errors"
	"io"

	"github.com/dominant-strategies/go-quai/common"
	bchhash "github.com/gcash/bchd/chaincfg/chainhash"
	bchdwire "github.com/gcash/bchd/wire"
)

// BitcoinCashHeaderWrapper wraps bchdwire.BlockHeader to implement AuxHeaderData
type BitcoinCashHeaderWrapper struct {
	*bchdwire.BlockHeader
}

type BitcoinCashCoinbaseTxWrapper struct {
	*bchdwire.MsgTx
}

type BitcoinCashCoinbaseTxOutWrapper struct {
	*bchdwire.TxOut
}

func NewBitcoinCashCoinbaseTx(version int32) *bchdwire.MsgTx {
	tx := bchdwire.NewMsgTx(version)
	return tx
}

func NewBitcoinCashCoinbaseTxOut(value int64, pkScript []byte) *bchdwire.TxOut {
	return &bchdwire.TxOut{Value: value, PkScript: pkScript}
}

func NewBitcoinCashHeaderWrapper(header *bchdwire.BlockHeader) *BitcoinCashHeaderWrapper {
	return &BitcoinCashHeaderWrapper{BlockHeader: header}
}

func NewBitcoinCashBlockHeader(version int32, prevBlockHash [32]byte, merkleRootHash [32]byte, time uint32, bits uint32, nonce uint32) *BitcoinCashHeaderWrapper {
	prevHash := bchhash.Hash{}
	copy(prevHash[:], prevBlockHash[:])
	merkleRoot := bchhash.Hash{}
	copy(merkleRoot[:], merkleRootHash[:])
	header := bchdwire.NewBlockHeader(version, &prevHash, &merkleRoot, bits, nonce)
	return &BitcoinCashHeaderWrapper{BlockHeader: header}
}

func (bch *BitcoinCashHeaderWrapper) PowHash() common.Hash {
	blockHash := bch.BlockHeader.BlockHash()
	return common.BytesToHash(reverseBytesCopy(blockHash[:]))
}

func (bch *BitcoinCashHeaderWrapper) Serialize(wr io.Writer) error {
	return bch.BlockHeader.Serialize(wr)
}

func (bch *BitcoinCashHeaderWrapper) Deserialize(r io.Reader) error {
	bch.BlockHeader = &bchdwire.BlockHeader{}
	return bch.BlockHeader.Deserialize(r)
}

func (bch *BitcoinCashHeaderWrapper) GetVersion() int32 {
	return bch.BlockHeader.Version
}

func (bch *BitcoinCashHeaderWrapper) GetPrevBlock() [32]byte {
	return [32]byte(bch.BlockHeader.PrevBlock)
}

func (bch *BitcoinCashHeaderWrapper) GetMerkleRoot() [32]byte {
	return [32]byte(bch.BlockHeader.MerkleRoot)
}

func (bch *BitcoinCashHeaderWrapper) GetTimestamp() uint32 {
	return uint32(bch.BlockHeader.Timestamp.Unix())
}

func (bch *BitcoinCashHeaderWrapper) GetBits() uint32 {
	return bch.BlockHeader.Bits
}

func (bch *BitcoinCashHeaderWrapper) GetNonce() uint32 {
	return bch.BlockHeader.Nonce
}

func (bch *BitcoinCashHeaderWrapper) GetNonce64() uint64 {
	// Standard Bitcoin Cash headers don't have a 64-bit nonce
	return 0
}

func (bch *BitcoinCashHeaderWrapper) GetMixHash() common.Hash {
	// Standard Bitcoin Cash headers don't have a mix hash
	return common.Hash{}
}

func (bch *BitcoinCashHeaderWrapper) GetHeight() uint32 {
	// Standard Bitcoin Cash headers don't include height
	return 0
}

func (bch *BitcoinCashHeaderWrapper) GetSealHash() common.Hash {
	// Standard Bitcoin Cash headers don't have a seal hash
	return common.Hash{}
}

func (bch *BitcoinCashHeaderWrapper) SetNonce(nonce uint32) {
	bch.BlockHeader.Nonce = nonce
}

func (bch *BitcoinCashHeaderWrapper) SetNonce64(nonce uint64) {
	// Standard Bitcoin Cash headers don't have a 64-bit nonce, so this is a no-op
}

func (bch *BitcoinCashHeaderWrapper) SetMixHash(mixHash common.Hash) {
	// Standard Bitcoin Cash headers don't have a mix hash, so this is a no-op
}

func (bch *BitcoinCashHeaderWrapper) SetHeight(height uint32) {
	// Standard Bitcoin Cash headers don't have a height, so this is a no-op
	return
}

func (bch *BitcoinCashHeaderWrapper) Copy() *BitcoinCashHeaderWrapper {
	copiedHeader := *bch.BlockHeader
	return &BitcoinCashHeaderWrapper{BlockHeader: &copiedHeader}
}

func (bct *BitcoinCashCoinbaseTxWrapper) Copy() AuxPowCoinbaseTxData {
	return &BitcoinCashCoinbaseTxWrapper{MsgTx: bct.MsgTx.Copy()}
}

func (bct *BitcoinCashCoinbaseTxWrapper) scriptSig() []byte {
	if bct.MsgTx == nil || len(bct.MsgTx.TxIn) == 0 {
		return nil
	}
	return bct.MsgTx.TxIn[0].SignatureScript
}

func (bct *BitcoinCashCoinbaseTxWrapper) DeserializeNoWitness(r io.Reader) error {
	return errors.New("DeserializeNoWitness not supported for Bitcoin Cash")
}

func (bco *BitcoinCashCoinbaseTxOutWrapper) Value() int64 {
	return bco.TxOut.Value
}

func (bco *BitcoinCashCoinbaseTxOutWrapper) PkScript() []byte {
	return bco.TxOut.PkScript
}
