package types

import (
	"bytes"
	"fmt"
	"io"

	"github.com/dominant-strategies/go-quai/common"
	ltchash "github.com/dominant-strategies/ltcd/chaincfg/chainhash"
	ltcdwire "github.com/dominant-strategies/ltcd/wire"
)

// LitecoinHeaderWrapper wraps ltcdwire.BlockHeader to implement AuxHeaderData
type LitecoinHeaderWrapper struct {
	*ltcdwire.BlockHeader
}

type LitecoinTxWrapper struct {
	*ltcdwire.MsgTx
}

type LitecoinCoinbaseTxOutWrapper struct {
	*ltcdwire.TxOut
}

func NewLitecoinHeaderWrapper(header *ltcdwire.BlockHeader) *LitecoinHeaderWrapper {
	return &LitecoinHeaderWrapper{BlockHeader: header}
}

func NewLitecoinCoinbaseTxOut(value int64, pkScript []byte) *LitecoinCoinbaseTxOutWrapper {
	return &LitecoinCoinbaseTxOutWrapper{TxOut: &ltcdwire.TxOut{Value: value, PkScript: pkScript}}
}

func (ltc *LitecoinHeaderWrapper) PowHash() common.Hash {
	blockHash := ltc.BlockHeader.PowHash()
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

func (ltc *LitecoinHeaderWrapper) Copy() AuxHeaderData {
	copiedHeader := *ltc.BlockHeader
	copiedHeader.Version = ltc.BlockHeader.Version
	copiedHeader.PrevBlock = ltc.BlockHeader.PrevBlock
	copiedHeader.MerkleRoot = ltc.BlockHeader.MerkleRoot
	copiedHeader.Timestamp = ltc.BlockHeader.Timestamp
	copiedHeader.Bits = ltc.BlockHeader.Bits
	copiedHeader.Nonce = ltc.BlockHeader.Nonce
	return &LitecoinHeaderWrapper{BlockHeader: &copiedHeader}
}

// CoinbaseTx functions

func NewLitecoinCoinbaseTxWrapper(height uint32, coinbaseOut []byte, auxMerkleRoot common.Hash, signatureTime uint32, witness bool) []byte {
	coinbaseTx := &LitecoinTxWrapper{MsgTx: ltcdwire.NewMsgTx(2)}
	// Create the coinbase input with seal hash in scriptSig
	scriptSig := BuildCoinbaseScriptSigWithNonce(height, 0, 0, auxMerkleRoot, 2, signatureTime)
	coinbaseTx.AddTxIn(&ltcdwire.TxIn{
		PreviousOutPoint: ltcdwire.OutPoint{
			Hash:  ltchash.Hash{}, // Coinbase has no previous output
			Index: 0xffffffff,     // Coinbase has no previous output
		},
		SignatureScript: scriptSig,
		Sequence:        0xffffffff,
	})

	var buffer bytes.Buffer
	if witness {
		coinbaseTx.Serialize(&buffer)
	} else {
		coinbaseTx.SerializeNoWitness(&buffer)
	}

	// Since the emtpty serialization of the coinbase transaction adds 5 bytes at the end,
	// we need to trim these before appending the coinbaseOut
	raw := buffer.Bytes()
	if len(raw) < 5 {
		return append([]byte{}, coinbaseOut...)
	}
	trimmed := append([]byte{}, raw[:len(raw)-5]...)
	return append(trimmed, coinbaseOut...)
}

func (lct *LitecoinTxWrapper) Copy() AuxPowTxData {
	return &LitecoinTxWrapper{MsgTx: lct.MsgTx.Copy()}
}

func (lct *LitecoinTxWrapper) Serialize(w io.Writer) error {
	if lct.MsgTx == nil {
		return fmt.Errorf("cannot serialize: MsgTx is nil")
	}
	return lct.MsgTx.Serialize(w)
}

func (lct *LitecoinTxWrapper) SerializeNoWitness(w io.Writer) error {
	if lct.MsgTx == nil {
		return fmt.Errorf("cannot serialize: MsgTx is nil")
	}
	// Litecoin doesn't use SegWit, so Serialize is the same as SerializeNoWitness
	return lct.MsgTx.Serialize(w)
}

func (lct *LitecoinTxWrapper) Deserialize(r io.Reader) error {
	if lct.MsgTx == nil {
		return fmt.Errorf("cannot deserialize: MsgTx is nil")
	}
	return lct.MsgTx.Deserialize(r)
}

func (lct *LitecoinTxWrapper) DeserializeNoWitness(r io.Reader) error {
	if lct.MsgTx == nil {
		return fmt.Errorf("cannot deserialize: MsgTx is nil")
	}
	return lct.MsgTx.DeserializeNoWitness(r)
}

// CoinbaseTxOut functions
func (lco *LitecoinCoinbaseTxOutWrapper) Value() int64 {
	return lco.TxOut.Value
}

func (lco *LitecoinCoinbaseTxOutWrapper) PkScript() []byte {
	return lco.TxOut.PkScript
}
