package types

// ChainID represents a unique identifier for a blockchain
type ChainID uint32

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
	chainID         ChainID  // must match ap.Chain (RVN)
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

// Getters for AuxTemplate fields
func (at *AuxTemplate) ChainID() ChainID        { return at.chainID }
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
func (at *AuxTemplate) SetChainID(id ChainID)           { at.chainID = id }
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

	chainID := uint32(at.chainID)
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
		ChainId:         &chainID,
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

	at.chainID = ChainID(data.GetChainId())

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

// AuxPow represents auxiliary proof-of-work data
type AuxPow struct {
	chainID       ChainID              // Chain identifier
	header        []byte               // 80B donor header
	signature     []byte               // Signature proving the work
	merkleBranch  [][]byte             // siblings for coinbase index=0 up to root (little endian 32-byte hashes)
	coinbaseValue uint64               // subsidy + fees for output[0] (in RVN sats)
	transaction   RavencoinTransaction // Full coinbase transaction (for signature verification)
}

func NewAuxPow(chainID ChainID, header []byte, signature []byte, merkleBranch [][]byte, coinbaseValue uint64, transaction RavencoinTransaction) *AuxPow {
	return &AuxPow{
		chainID:       chainID,
		header:        header,
		signature:     signature,
		merkleBranch:  merkleBranch,
		coinbaseValue: coinbaseValue,
		transaction:   transaction,
	}
}

func (ap *AuxPow) ChainID() ChainID { return ap.chainID }

func (ap *AuxPow) Header() []byte { return ap.header }

func (ap *AuxPow) Signature() []byte { return ap.signature }

func (ap *AuxPow) MerkleBranch() [][]byte { return ap.merkleBranch }

func (ap *AuxPow) CoinbaseValue() uint64 { return ap.coinbaseValue }

func (ap *AuxPow) Transaction() RavencoinTransaction { return ap.transaction }

func (ap *AuxPow) SetChainID(id ChainID) { ap.chainID = id }

func (ap *AuxPow) SetHeader(header []byte) { ap.header = header }

func (ap *AuxPow) SetSignature(sig []byte) { ap.signature = sig }

func (ap *AuxPow) SetMerkleBranch(branch [][]byte) { ap.merkleBranch = branch }

func (ap *AuxPow) SetCoinbaseValue(val uint64) { ap.coinbaseValue = val }

func (ap *AuxPow) SetTransaction(tx RavencoinTransaction) { ap.transaction = tx }

// ProtoEncode converts AuxPow to its protobuf representation
func (ap *AuxPow) ProtoEncode() *ProtoAuxPow {
	if ap == nil {
		return nil
	}

	chainID := uint32(ap.ChainID())
	coinbaseValue := ap.CoinbaseValue()

	// Convert merkle branch
	merkleBranch := make([][]byte, len(ap.MerkleBranch()))
	copy(merkleBranch, ap.MerkleBranch())

	// Convert transaction
	var txProto *ProtoRavencoinTransaction
	if ap.transaction.Version != 0 { // Check if transaction is not empty
		txProto = ap.transaction.ProtoEncode()
	}

	return &ProtoAuxPow{
		ChainId:       &chainID,
		Header:        ap.Header(),
		Signature:     ap.Signature(),
		MerkleBranch:  merkleBranch,
		CoinbaseValue: &coinbaseValue,
		Transaction:   txProto,
	}
}

// ProtoDecode populates AuxPow from its protobuf representation
func (ap *AuxPow) ProtoDecode(data *ProtoAuxPow) error {
	if data == nil {
		return nil
	}

	ap.SetChainID(ChainID(data.GetChainId()))
	ap.SetHeader(data.GetHeader())
	ap.SetSignature(data.GetSignature())
	ap.SetCoinbaseValue(data.GetCoinbaseValue())

	// Decode merkle branch
	ap.merkleBranch = make([][]byte, len(data.GetMerkleBranch()))
	for i, hash := range data.GetMerkleBranch() {
		ap.merkleBranch[i] = make([]byte, len(hash))
		copy(ap.merkleBranch[i], hash)
	}

	// Decode transaction
	if data.GetTransaction() != nil {
		if err := ap.transaction.ProtoDecode(data.GetTransaction()); err != nil {
			return err
		}
	}

	return nil
}
