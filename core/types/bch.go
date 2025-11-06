package types

import (
	"bytes"
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

type BitcoinCashTxWrapper struct {
	*bchdwire.MsgTx
}

type BitcoinCashCoinbaseTxOutWrapper struct {
	*bchdwire.TxOut
}

func NewBitcoinCashHeaderWrapper(header *bchdwire.BlockHeader) *BitcoinCashHeaderWrapper {
	return &BitcoinCashHeaderWrapper{BlockHeader: header}
}

func NewBitcoinCashCoinbaseTxOut(value int64, pkScript []byte) *BitcoinCashCoinbaseTxOutWrapper {
	return &BitcoinCashCoinbaseTxOutWrapper{TxOut: &bchdwire.TxOut{Value: value, PkScript: pkScript}}
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
}

func (bch *BitcoinCashHeaderWrapper) Copy() AuxHeaderData {
	copiedHeader := *bch.BlockHeader
	copiedHeader.Version = bch.BlockHeader.Version
	copiedHeader.PrevBlock = bch.BlockHeader.PrevBlock
	copiedHeader.MerkleRoot = bch.BlockHeader.MerkleRoot
	copiedHeader.Timestamp = bch.BlockHeader.Timestamp
	copiedHeader.Bits = bch.BlockHeader.Bits
	copiedHeader.Nonce = bch.BlockHeader.Nonce
	return &BitcoinCashHeaderWrapper{BlockHeader: &copiedHeader}
}

func NewBitcoinCashCoinbaseTxWrapper(height uint32, coinbaseOut []byte, sealHash common.Hash, signatureTime uint32) []byte {
	coinbaseTx := &BitcoinCashTxWrapper{MsgTx: bchdwire.NewMsgTx(2)}

	// Create the coinbase input with seal hash in scriptSig
	scriptSig := BuildCoinbaseScriptSigWithNonce(height, 0, 0, sealHash, 1, signatureTime)
	coinbaseTx.AddTxIn(&bchdwire.TxIn{
		PreviousOutPoint: bchdwire.OutPoint{
			Hash:  bchhash.Hash{}, // Coinbase has no previous output
			Index: 0xffffffff,     // Coinbase has no previous output
		},
		SignatureScript: scriptSig,
		Sequence:        0xffffffff,
	})

	var buffer bytes.Buffer

	coinbaseTx.Serialize(&buffer)

	// Since the emtpty serialization of the coinbase transaction adds 5 bytes at the end,
	// we need to trim these before appending the coinbaseOut
	raw := buffer.Bytes()
	if len(raw) < 5 {
		return append([]byte{}, coinbaseOut...)
	}
	trimmed := append([]byte{}, raw[:len(raw)-5]...)
	return append(trimmed, coinbaseOut...)
}

func (bct *BitcoinCashTxWrapper) Copy() AuxPowTxData {
	return &BitcoinCashTxWrapper{MsgTx: bct.MsgTx.Copy()}
}

func (bct *BitcoinCashTxWrapper) Serialize(w io.Writer) error {
	if bct.MsgTx == nil {
		return errors.New("cannot serialize: MsgTx is nil")
	}
	return bct.MsgTx.Serialize(w)
}

func (bct *BitcoinCashTxWrapper) SerializeNoWitness(w io.Writer) error {
	if bct.MsgTx == nil {
		return errors.New("cannot serialize: MsgTx is nil")
	}
	// Bitcoin Cash doesn't use SegWit, so Serialize is the same as SerializeNoWitness
	return bct.MsgTx.Serialize(w)
}

func (bct *BitcoinCashTxWrapper) Deserialize(r io.Reader) error {
	if bct.MsgTx == nil {
		return errors.New("cannot deserialize: MsgTx is nil")
	}
	return bct.MsgTx.Deserialize(r)
}

func (bct *BitcoinCashTxWrapper) DeserializeNoWitness(r io.Reader) error {
	if bct.MsgTx == nil {
		return errors.New("cannot deserialize: MsgTx is nil")
	}
	// Bitcoin Cash doesn't use SegWit, so Deserialize is the same as DeserializeNoWitness
	return bct.MsgTx.Deserialize(r)
}

func (bco *BitcoinCashCoinbaseTxOutWrapper) Value() int64 {
	return bco.TxOut.Value
}

func (bco *BitcoinCashCoinbaseTxOutWrapper) PkScript() []byte {
	return bco.TxOut.PkScript
}
