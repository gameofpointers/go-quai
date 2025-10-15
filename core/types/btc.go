package types

import (
	"io"

	btchash "github.com/btcsuite/btcd/chaincfg/chainhash"
	btcdwire "github.com/btcsuite/btcd/wire"
	"github.com/dominant-strategies/go-quai/common"
)

// BitcoinHeaderWrapper wraps btcdwire.BlockHeader to implement AuxHeaderData
type BitcoinHeaderWrapper struct {
	*btcdwire.BlockHeader
}

type BitcoinCoinbaseTxWrapper struct {
	*btcdwire.MsgTx
}

type BitcoinCoinbaseTxOutWrapper struct {
	*btcdwire.TxOut
}

func NewBitcoinCoinbaseTxOut(value int64, pkScript []byte) *BitcoinCoinbaseTxOutWrapper {
	return &BitcoinCoinbaseTxOutWrapper{TxOut: &btcdwire.TxOut{Value: value, PkScript: pkScript}}
}

func NewBitcoinHeaderWrapper(header *btcdwire.BlockHeader) *BitcoinHeaderWrapper {
	return &BitcoinHeaderWrapper{BlockHeader: header}
}

func (bth *BitcoinHeaderWrapper) PowHash() common.Hash {
	blockHash := bth.BlockHeader.BlockHash()
	return common.BytesToHash(reverseBytesCopy(blockHash[:]))
}

func (bth *BitcoinHeaderWrapper) Serialize(wr io.Writer) error {
	return bth.BlockHeader.Serialize(wr)
}

func (bth *BitcoinHeaderWrapper) Deserialize(r io.Reader) error {
	bth.BlockHeader = &btcdwire.BlockHeader{}
	return bth.BlockHeader.Deserialize(r)
}

func NewBitcoinBlockHeader(version int32, prevBlockHash [32]byte, merkleRootHash [32]byte, time uint32, bits uint32, nonce uint32) *BitcoinHeaderWrapper {
	prevHash := btchash.Hash{}
	copy(prevHash[:], prevBlockHash[:])
	merkleRoot := btchash.Hash{}
	copy(merkleRoot[:], merkleRootHash[:])
	header := btcdwire.NewBlockHeader(version, &prevHash, &merkleRoot, bits, nonce)
	return &BitcoinHeaderWrapper{BlockHeader: header}
}

func (bth *BitcoinHeaderWrapper) GetVersion() int32 {
	return bth.BlockHeader.Version
}

func (bth *BitcoinHeaderWrapper) GetPrevBlock() [32]byte {
	return bth.BlockHeader.PrevBlock
}

func (bth *BitcoinHeaderWrapper) GetMerkleRoot() [32]byte {
	return bth.BlockHeader.MerkleRoot
}

func (bth *BitcoinHeaderWrapper) GetTimestamp() uint32 {
	return uint32(bth.BlockHeader.Timestamp.Unix())
}

func (bth *BitcoinHeaderWrapper) GetBits() uint32 {
	return bth.BlockHeader.Bits
}

func (bth *BitcoinHeaderWrapper) GetNonce() uint32 {
	return bth.BlockHeader.Nonce
}

func (bth *BitcoinHeaderWrapper) GetNonce64() uint64 {
	// Standard Bitcoin headers don't have a 64-bit nonce
	return 0
}

func (bth *BitcoinHeaderWrapper) GetHeight() uint32 {
	// Standard Bitcoin headers don't include height
	return 0
}

func (bth *BitcoinHeaderWrapper) GetMixHash() common.Hash {
	// Standard Bitcoin headers don't have a mix hash
	return common.Hash{}
}

func (bth *BitcoinHeaderWrapper) GetSealHash() common.Hash {
	// Standard Bitcoin headers don't have a seal hash
	return common.Hash{}
}

func (bth *BitcoinHeaderWrapper) SetNonce(nonce uint32) {
	bth.BlockHeader.Nonce = nonce
}

func (bth *BitcoinHeaderWrapper) SetNonce64(nonce uint64) {
	// Standard Bitcoin headers don't have a 64-bit nonce, so this is a no-op
}

func (bth *BitcoinHeaderWrapper) SetMixHash(mixHash common.Hash) {
	// Standard Bitcoin headers don't have a mix hash, so this is a no-op
}

func (bth *BitcoinHeaderWrapper) SetHeight(height uint32) {
	// Standard Bitcoin headers don't have a height, so this is a no-op
}

func (bth *BitcoinHeaderWrapper) Copy() AuxHeaderData {
	copiedHeader := *bth.BlockHeader
	copiedHeader.Version = bth.BlockHeader.Version
	copiedHeader.PrevBlock = bth.BlockHeader.PrevBlock
	copiedHeader.MerkleRoot = bth.BlockHeader.MerkleRoot
	copiedHeader.Timestamp = bth.BlockHeader.Timestamp
	copiedHeader.Bits = bth.BlockHeader.Bits
	copiedHeader.Nonce = bth.BlockHeader.Nonce
	return &BitcoinHeaderWrapper{BlockHeader: &copiedHeader}
}

func (bto *BitcoinCoinbaseTxOutWrapper) Value() int64 {
	return bto.TxOut.Value
}

func (bto *BitcoinCoinbaseTxOutWrapper) PkScript() []byte {
	return bto.TxOut.PkScript
}

func NewBitcoinCoinbaseTxWrapper(height uint32, coinbaseOut *AuxPowCoinbaseOut, extraData []byte) *BitcoinCoinbaseTxWrapper {
	coinbaseTx := &BitcoinCoinbaseTxWrapper{MsgTx: btcdwire.NewMsgTx(1)}

	// Create the coinbase input with height in scriptSig
	scriptSig := BuildCoinbaseScriptSigWithNonce(height, 0, 0, extraData)
	coinbaseTx.AddTxIn(&btcdwire.TxIn{
		PreviousOutPoint: btcdwire.OutPoint{
			Hash:  btchash.Hash{}, // Coinbase has no previous output
			Index: 0xffffffff,     // Coinbase has no previous output
		},
		SignatureScript: scriptSig,
		Sequence:        0xffffffff,
	})

	// Add the coinbase output
	if coinbaseOut != nil {
		value := coinbaseOut.Value()
		pkScript := coinbaseOut.PkScript()
		txOut := NewBitcoinCoinbaseTxOut(value, pkScript)
		coinbaseTx.AddTxOut(txOut.TxOut)
	}

	return coinbaseTx
}

func (btt *BitcoinCoinbaseTxWrapper) Copy() AuxPowCoinbaseTxData {
	return &BitcoinCoinbaseTxWrapper{MsgTx: btt.MsgTx.Copy()}
}

func (btt *BitcoinCoinbaseTxWrapper) scriptSig() []byte {
	if btt.MsgTx == nil || len(btt.MsgTx.TxIn) == 0 {
		return nil
	}
	return btt.MsgTx.TxIn[0].SignatureScript
}
