package types

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"

	"github.com/btcsuite/btcd/wire"
	"github.com/dominant-strategies/go-quai/common/hexutil"
	"github.com/dominant-strategies/go-quai/crypto/musig2"
	"google.golang.org/protobuf/proto"
)

// PowID represents a unique identifier for a proof-of-work algorithm
type PowID uint32

const (
	Progpow PowID = iota
	Kawpow
	SHA
	Scrypt
)

// NTimeMask represents a time mask for mining operations
type NTimeMask uint32

// SignerEnvelope contains a signer ID and their signature
type SignerEnvelope struct {
	signerID  string
	signature []byte
}

// Getters for SignerEnvelope
func (se *SignerEnvelope) SignerID() string  { return se.signerID }
func (se *SignerEnvelope) Signature() []byte { return se.signature }

// Setters for SignerEnvelope
func (se *SignerEnvelope) SetSignerID(id string)   { se.signerID = id }
func (se *SignerEnvelope) SetSignature(sig []byte) { se.signature = sig }

// NewSignerEnvelope creates a new SignerEnvelope with the given ID and signature
func NewSignerEnvelope(id string, signature []byte) SignerEnvelope {
	return SignerEnvelope{
		signerID:  id,
		signature: signature,
	}
}

// ProtoEncode converts SignerEnvelope to its protobuf representation
func (se *SignerEnvelope) ProtoEncode() *ProtoSignerEnvelope {
	if se == nil {
		return nil
	}
	signerID := se.signerID
	return &ProtoSignerEnvelope{
		SignerId:  &signerID,
		Signature: se.signature,
	}
}

// ProtoDecode populates SignerEnvelope from its protobuf representation
func (se *SignerEnvelope) ProtoDecode(data *ProtoSignerEnvelope) error {
	if data == nil {
		return nil
	}
	se.signerID = data.GetSignerId()
	se.signature = data.GetSignature()
	return nil
}

// AuxTemplate defines the template structure for auxiliary proof-of-work
type AuxTemplate struct {
	// === Consensus-correspondence (signed; Quai validators check against AuxPoW) ===
	powID           PowID    // must match ap.Chain (RVN)
	prevHash        [32]byte // must equal donor_header.hashPrevBlock
	payoutScript    []byte   // must equal coinbase.outputs[0].scriptPubKey
	scriptSigMaxLen uint16   // ≤ 100

	// === Header/DAA knobs for job construction (signed) ===
	version   uint32    // header.nVersion to use
	nBits     uint32    // header.nBits
	nTimeMask NTimeMask // allowed time range/step (e.g., {start, end, step})
	height    uint32    // BIP34 height (needed for scriptSig + KAWPOW epoch hint)

	// === Coinbase economics (signed) ===
	coinbaseValue uint64 // subsidy + fees for output[0] (in RVN sats)

	// === Tx set commitment for Merkle root (signed) ===
	// Choose ONE of the two modes below:

	// Mode A: COINBASE-ONLY (simplest; smallest template)
	coinbaseOnly bool // if true => MerkleBranch is empty; tx count = 1

	// Mode B: LOCKED TX SET (miners get fees; template is larger & updated more often)
	txCount      uint32   // total txs INCLUDING coinbase (index 0)
	merkleBranch [][]byte // siblings for coinbase index=0 up to root (little endian 32-byte hashes)

	// === Miner extranonce ergonomics (signed/advisory) ===
	extranonce2Size uint8 // typical 4..8

	// === Quorum signatures over CanonicalEncode(template WITHOUT Sigs) ===
	sigs []SignerEnvelope
}

func NewAuxTemplate() *AuxTemplate {
	return &AuxTemplate{}
}

func EmptyAuxTemplate() *AuxTemplate {
	return &AuxTemplate{
		powID:           0,
		prevHash:        [32]byte{},
		payoutScript:    nil,
		scriptSigMaxLen: 100,
		version:         536870912, // 0x20000000 (RVN)
		nBits:           0,
		nTimeMask:       0,
		height:          0,
		coinbaseValue:   0,
		coinbaseOnly:    true,
		txCount:         1,
		merkleBranch:    nil,
		extranonce2Size: 4,
		sigs:            nil,
	}
}

// RPCMarshalAuxTemplate converts AuxTemplate to a map for RPC serialization
func RPCMarshalAuxTemplate(at *AuxTemplate) map[string]interface{} {
	if at == nil {
		return nil
	}

	merkleBranch := make([]string, len(at.merkleBranch))
	for i, hash := range at.merkleBranch {
		merkleBranch[i] = hexutil.Encode(hash)
	}

	sigs := make([]map[string]interface{}, len(at.sigs))
	for i, sig := range at.sigs {
		sigs[i] = map[string]interface{}{
			"signerId":  sig.SignerID(),
			"signature": hexutil.Encode(sig.Signature()),
		}
	}

	return map[string]interface{}{
		"powId":           uint32(at.powID),
		"prevHash":        hexutil.Encode(at.prevHash[:]),
		"payoutScript":    hexutil.Encode(at.payoutScript),
		"scriptSigMaxLen": at.scriptSigMaxLen,
		"version":         at.version,
		"nBits":           at.nBits,
		"nTimeMask":       uint32(at.nTimeMask),
		"height":          at.height,
		"coinbaseValue":   at.coinbaseValue,
		"coinbaseOnly":    at.coinbaseOnly,
		"txCount":         at.txCount,
		"merkleBranch":    merkleBranch,
		"extranonce2Size": at.extranonce2Size,
		"sigs":            sigs,
	}
}

// RPCMarshalAuxPowForKawPow converts AuxPow to a map for RPC serialization
func RPCMarshalAuxPowForKawPow(ap *AuxPow) map[string]interface{} {
	if ap == nil {
		return nil
	}

	merkleBranch := make([]string, len(ap.merkleBranch))
	for i, hash := range ap.merkleBranch {
		merkleBranch[i] = hexutil.Encode(hash)
	}

	ravencoinHeader, err := DecodeRavencoinHeader(ap.header)
	if err != nil {
		return nil
	}

	var (
		coinbaseValue uint64
		coinbaseAux   []byte
		payoutScript  []byte
	)

	if tx := ap.transaction; tx != nil {
		if len(tx.TxOut) > 0 && tx.TxOut[0].Value >= 0 {
			coinbaseValue = uint64(tx.TxOut[0].Value)
		}
		if len(tx.TxIn) > 0 {
			coinbaseAux = tx.TxIn[0].SignatureScript
		}
		payoutScript = ap.transaction.TxOut[0].PkScript
	}

	return map[string]interface{}{
		"version":           ravencoinHeader.Version,
		"height":            hexutil.EncodeUint64(uint64(ravencoinHeader.Height)),
		"bits":              hexutil.EncodeUint64(uint64(ravencoinHeader.Bits)),
		"previousblockhash": hexutil.Encode(ravencoinHeader.HashPrevBlock.Bytes()),
		"coinbasevalue":     coinbaseValue,
		"target":            GetTargetInHex(ravencoinHeader.Bits),
		"coinbaseaux":       hexutil.Encode(coinbaseAux),
		"payoutscript":      hexutil.Encode(payoutScript),
		"merkleBranch":      merkleBranch,
	}
}

// Getters for AuxTemplate fields
func (at *AuxTemplate) PowID() PowID            { return at.powID }
func (at *AuxTemplate) PrevHash() [32]byte      { return at.prevHash }
func (at *AuxTemplate) PayoutScript() []byte    { return at.payoutScript }
func (at *AuxTemplate) ScriptSigMaxLen() uint16 { return at.scriptSigMaxLen }
func (at *AuxTemplate) Version() uint32         { return at.version }
func (at *AuxTemplate) NBits() uint32           { return at.nBits }
func (at *AuxTemplate) NTimeMask() NTimeMask    { return at.nTimeMask }
func (at *AuxTemplate) Height() uint32          { return at.height }
func (at *AuxTemplate) CoinbaseValue() uint64   { return at.coinbaseValue }
func (at *AuxTemplate) CoinbaseOnly() bool      { return at.coinbaseOnly }
func (at *AuxTemplate) TxCount() uint32         { return at.txCount }
func (at *AuxTemplate) MerkleBranch() [][]byte  { return at.merkleBranch }
func (at *AuxTemplate) Extranonce2Size() uint8  { return at.extranonce2Size }
func (at *AuxTemplate) Sigs() []SignerEnvelope  { return at.sigs }

// Setters for AuxTemplate fields
func (at *AuxTemplate) SetPowID(id PowID)               { at.powID = id }
func (at *AuxTemplate) SetPrevHash(hash [32]byte)       { at.prevHash = hash }
func (at *AuxTemplate) SetPayoutScript(script []byte)   { at.payoutScript = script }
func (at *AuxTemplate) SetScriptSigMaxLen(len uint16)   { at.scriptSigMaxLen = len }
func (at *AuxTemplate) SetVersion(v uint32)             { at.version = v }
func (at *AuxTemplate) SetNBits(bits uint32)            { at.nBits = bits }
func (at *AuxTemplate) SetNTimeMask(mask NTimeMask)     { at.nTimeMask = mask }
func (at *AuxTemplate) SetHeight(h uint32)              { at.height = h }
func (at *AuxTemplate) SetCoinbaseValue(val uint64)     { at.coinbaseValue = val }
func (at *AuxTemplate) SetCoinbaseOnly(only bool)       { at.coinbaseOnly = only }
func (at *AuxTemplate) SetTxCount(count uint32)         { at.txCount = count }
func (at *AuxTemplate) SetMerkleBranch(branch [][]byte) { at.merkleBranch = branch }
func (at *AuxTemplate) SetExtranonce2Size(size uint8)   { at.extranonce2Size = size }
func (at *AuxTemplate) SetSigs(sigs []SignerEnvelope)   { at.sigs = sigs }

// ProtoEncode converts AuxTemplate to its protobuf representation
func (at *AuxTemplate) ProtoEncode() *ProtoAuxTemplate {
	if at == nil {
		return nil
	}

	powID := uint32(at.powID)
	scriptSigMaxLen := uint32(at.scriptSigMaxLen)
	version := at.version
	nbits := at.nBits
	ntimeMask := uint32(at.nTimeMask)
	height := at.height
	coinbaseValue := at.coinbaseValue
	coinbaseOnly := at.coinbaseOnly
	txCount := at.txCount
	extranonce2Size := uint32(at.extranonce2Size)

	// Convert merkle branch
	merkleBranch := make([][]byte, len(at.merkleBranch))
	copy(merkleBranch, at.merkleBranch)

	// Convert signer envelopes
	sigs := make([]*ProtoSignerEnvelope, len(at.sigs))
	for i, sig := range at.sigs {
		sigs[i] = sig.ProtoEncode()
	}

	return &ProtoAuxTemplate{
		ChainId:         &powID,
		PrevHash:        at.prevHash[:],
		PayoutScript:    at.payoutScript,
		ScriptSigMaxLen: &scriptSigMaxLen,
		Version:         &version,
		Nbits:           &nbits,
		NtimeMask:       &ntimeMask,
		Height:          &height,
		CoinbaseValue:   &coinbaseValue,
		CoinbaseOnly:    &coinbaseOnly,
		TxCount:         &txCount,
		MerkleBranch:    merkleBranch,
		Extranonce2Size: &extranonce2Size,
		Sigs:            sigs,
	}
}

// ProtoDecode populates AuxTemplate from its protobuf representation
func (at *AuxTemplate) ProtoDecode(data *ProtoAuxTemplate) error {
	if data == nil {
		return nil
	}

	at.powID = PowID(data.GetChainId())

	// Copy PrevHash (32 bytes)
	if len(data.GetPrevHash()) == 32 {
		copy(at.prevHash[:], data.GetPrevHash())
	}

	at.payoutScript = data.GetPayoutScript()
	at.scriptSigMaxLen = uint16(data.GetScriptSigMaxLen())
	at.version = data.GetVersion()
	at.nBits = data.GetNbits()
	at.nTimeMask = NTimeMask(data.GetNtimeMask())
	at.height = data.GetHeight()
	at.coinbaseValue = data.GetCoinbaseValue()
	at.coinbaseOnly = data.GetCoinbaseOnly()
	at.txCount = data.GetTxCount()

	// Copy merkle branch
	at.merkleBranch = make([][]byte, len(data.GetMerkleBranch()))
	for i, hash := range data.GetMerkleBranch() {
		at.merkleBranch[i] = make([]byte, len(hash))
		copy(at.merkleBranch[i], hash)
	}

	at.extranonce2Size = uint8(data.GetExtranonce2Size())

	// Decode signer envelopes
	at.sigs = make([]SignerEnvelope, len(data.GetSigs()))
	for i, sig := range data.GetSigs() {
		if err := at.sigs[i].ProtoDecode(sig); err != nil {
			return err
		}
	}

	return nil
}

// Hash returns the SHA256 hash of the AuxTemplate with signature fields set to nil
// This is the same hash used for signing and verification
func (at *AuxTemplate) Hash() [32]byte {
	// Create a copy of the template without signatures for message hash calculation
	// We need to work with the protobuf representation to properly exclude signature fields
	protoTemplate := at.ProtoEncode()
	tempTemplate := proto.Clone(protoTemplate).(*ProtoAuxTemplate)
	tempTemplate.Sigs = nil

	// Marshal the template without signatures to get the message hash
	templateData, err := proto.Marshal(tempTemplate)
	if err != nil {
		// Return zero hash on error - this should be handled by the caller
		return [32]byte{}
	}

	// Calculate and return the message hash
	return sha256.Sum256(templateData)
}

// VerifySignature verifies the signature on this AuxTemplate by trying all possible 2-of-3 key combinations
// Returns true if any valid 2-of-3 signature is found, false otherwise
func (at *AuxTemplate) VerifySignature() bool {
	// Check if we have any signatures
	if len(at.sigs) == 0 {
		return false
	}

	// Get the first signature (assuming single signature for now)
	if len(at.sigs[0].Signature()) == 0 {
		return false
	}

	// Get the message hash using the new Hash() method
	messageHash := at.Hash()
	message := messageHash[:]

	// Get the signature
	signature := at.sigs[0].Signature()

	// Try all possible 2-of-3 key combinations (including order variations)
	// We have 3 keys (indices 0, 1, 2) and need to try all combinations of 2
	// MuSig2 signatures are order-dependent, so we need to try both orders
	combinations := [][]int{
		{0, 1}, // Keys 0 and 1
		{1, 0}, // Keys 1 and 0 (reverse order)
		{0, 2}, // Keys 0 and 2
		{2, 0}, // Keys 2 and 0 (reverse order)
		{1, 2}, // Keys 1 and 2
		{2, 1}, // Keys 2 and 1 (reverse order)
	}

	// Import the musig2 package for verification
	// We'll use the existing VerifyCompositeSignature function
	for _, signerIndices := range combinations {
		err := musig2.VerifyCompositeSignature(message, signature, signerIndices)
		if err == nil {
			// Found a valid signature with this combination
			return true
		}
	}

	// No valid signature found with any combination
	return false
}

// AuxPow represents auxiliary proof-of-work data
type AuxPow struct {
	powID         PowID       // PoW algorithm identifier
	header        []byte      // 120B donor header for KAWPOW
	signature     []byte      // Signature proving the work
	merkleBranch  [][]byte    // siblings for coinbase index=0 up to root (little endian 32-byte hashes)
	transaction   *wire.MsgTx // Full coinbase transaction (contains value in TxOut[0])
	signatureTime uint64      // Timestamp when signature was created
}

func NewAuxPow(powID PowID, header []byte, signature []byte, merkleBranch [][]byte, transaction *wire.MsgTx) *AuxPow {
	return &AuxPow{
		powID:         powID,
		header:        header,
		signature:     signature,
		merkleBranch:  merkleBranch,
		transaction:   transaction,
		signatureTime: 0,
	}
}

// NewAuxPowWithFields creates a new AuxPow with all fields specified
func NewAuxPowWithFields(powID PowID, header []byte, signature []byte, merkleBranch [][]byte, transaction *wire.MsgTx, signatureTime uint64) *AuxPow {
	return &AuxPow{
		powID:         powID,
		header:        header,
		signature:     signature,
		merkleBranch:  merkleBranch,
		transaction:   transaction,
		signatureTime: signatureTime,
	}
}

func (ap *AuxPow) PowID() PowID { return ap.powID }

func (ap *AuxPow) Header() []byte { return ap.header }

func (ap *AuxPow) Signature() []byte { return ap.signature }

func (ap *AuxPow) MerkleBranch() [][]byte { return ap.merkleBranch }

func (ap *AuxPow) Transaction() *wire.MsgTx { return ap.transaction }

func (ap *AuxPow) SignatureTime() uint64 { return ap.signatureTime }

func (ap *AuxPow) SetPowID(id PowID) { ap.powID = id }

func (ap *AuxPow) SetHeader(header []byte) { ap.header = header }

func (ap *AuxPow) SetSignature(sig []byte) { ap.signature = sig }

func (ap *AuxPow) SetMerkleBranch(branch [][]byte) { ap.merkleBranch = branch }

func (ap *AuxPow) SetTransaction(tx *wire.MsgTx) { ap.transaction = tx }

func (ap *AuxPow) SetSignatureTime(time uint64) { ap.signatureTime = time }

// RPCMarshal converts AuxPow to a map for RPC serialization
func (ap *AuxPow) RPCMarshal() map[string]interface{} {
	if ap == nil {
		return nil
	}

	// Convert merkle branch to hex strings
	merkleBranch := make([]string, len(ap.merkleBranch))
	for i, hash := range ap.merkleBranch {
		merkleBranch[i] = hexutil.Encode(hash)
	}

	// Serialize transaction to hex
	var txHex string
	if ap.transaction != nil {
		var buf bytes.Buffer
		if err := ap.transaction.Serialize(&buf); err == nil {
			txHex = hexutil.Encode(buf.Bytes())
		}
	}

	return map[string]interface{}{
		"powId":         uint32(ap.powID),
		"header":        hexutil.Encode(ap.header),
		"signature":     hexutil.Encode(ap.signature),
		"merkleBranch":  merkleBranch,
		"transaction":   txHex,
		"signatureTime": ap.signatureTime,
	}
}

// UnmarshalJSON implements json.Unmarshaler for AuxPow
func (ap *AuxPow) UnmarshalJSON(data []byte) error {
	var dec struct {
		PowID         uint32   `json:"powId"`
		Header        string   `json:"header"`
		Signature     string   `json:"signature"`
		MerkleBranch  []string `json:"merkleBranch"`
		Transaction   string   `json:"transaction"`
		SignatureTime uint64   `json:"signatureTime"`
	}

	if err := json.Unmarshal(data, &dec); err != nil {
		return err
	}

	// Decode header
	header, err := hexutil.Decode(dec.Header)
	if err != nil {
		return err
	}

	// Decode signature
	signature, err := hexutil.Decode(dec.Signature)
	if err != nil {
		return err
	}

	// Decode merkle branch
	merkleBranch := make([][]byte, len(dec.MerkleBranch))
	for i, hashHex := range dec.MerkleBranch {
		hash, err := hexutil.Decode(hashHex)
		if err != nil {
			return err
		}
		merkleBranch[i] = hash
	}

	// Decode transaction
	var tx *wire.MsgTx
	if dec.Transaction != "" {
		txBytes, err := hexutil.Decode(dec.Transaction)
		if err != nil {
			return err
		}
		tx = new(wire.MsgTx)
		if err := tx.Deserialize(bytes.NewReader(txBytes)); err != nil {
			return err
		}
	}

	// Set fields
	ap.powID = PowID(dec.PowID)
	ap.header = header
	ap.signature = signature
	ap.merkleBranch = merkleBranch
	ap.transaction = tx
	ap.signatureTime = dec.SignatureTime

	return nil
}

// ProtoEncode converts AuxPow to its protobuf representation
func (ap *AuxPow) ProtoEncode() *ProtoAuxPow {
	if ap == nil {
		return nil
	}

	powID := uint32(ap.PowID())

	// Convert merkle branch
	merkleBranch := make([][]byte, len(ap.MerkleBranch()))
	copy(merkleBranch, ap.MerkleBranch())

	// Serialize transaction to bytes
	var txBytes []byte
	if ap.transaction != nil {
		var buf bytes.Buffer
		if err := ap.transaction.Serialize(&buf); err == nil {
			txBytes = buf.Bytes()
		}
	}

	return &ProtoAuxPow{
		ChainId:       &powID,
		Header:        ap.Header(),
		Signature:     ap.Signature(),
		MerkleBranch:  merkleBranch,
		Transaction:   txBytes,
		SignatureTime: &ap.signatureTime,
	}
}

// ProtoDecode populates AuxPow from its protobuf representation
func (ap *AuxPow) ProtoDecode(data *ProtoAuxPow) error {
	if data == nil {
		return nil
	}

	ap.SetPowID(PowID(data.GetChainId()))
	ap.SetHeader(data.GetHeader())
	ap.SetSignature(data.GetSignature())

	// Decode merkle branch
	ap.merkleBranch = make([][]byte, len(data.GetMerkleBranch()))
	for i, hash := range data.GetMerkleBranch() {
		ap.merkleBranch[i] = make([]byte, len(hash))
		copy(ap.merkleBranch[i], hash)
	}

	// Deserialize transaction from bytes
	if txBytes := data.GetTransaction(); len(txBytes) > 0 {
		ap.transaction = new(wire.MsgTx)
		if err := ap.transaction.Deserialize(bytes.NewReader(txBytes)); err != nil {
			return err
		}
	}

	// Decode new fields
	ap.SetSignatureTime(data.GetSignatureTime())

	return nil
}
