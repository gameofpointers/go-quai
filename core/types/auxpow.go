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

// Getter functions for SignerEnvelope struct
func (se *SignerEnvelope) SignerId() string {
	return se.signerID
}

func (se *SignerEnvelope) Signature() []byte {
	return se.signature
}

// Setter functions for SignerEnvelope struct
func (se *SignerEnvelope) SetSignerId(signerId string) {
	se.signerID = signerId
}

func (se *SignerEnvelope) SetSignature(sig []byte) {
	se.signature = sig
}

// AuxTemplate defines the template structure for auxiliary proof-of-work
type AuxTemplate struct {
	// Enforced correspondence
	chainID         ChainID  // must match ap.Chain
	prevHash        [32]byte // must equal donor_header.hashPrevBlock
	payoutScript    []byte   // must equal coinbase.outputs[0].scriptPubKey
	scriptSigMaxLen uint16   // ≤100; template may be tighter

	// Advisory (policy/UX; NOT consensus unless elevated)
	extranonce2Size uint8
	nBits           uint32
	nTimeMask       NTimeMask

	// Quorum signatures over CanonicalEncode(AuxTemplate) WITHOUT Sigs
	sigs []SignerEnvelope // (SignerID, Signature)
}

func (at *AuxTemplate) ChainId() ChainID {
	return at.chainID
}

func (at *AuxTemplate) PrevHash() [32]byte {
	return at.prevHash
}

func (at *AuxTemplate) PayoutScript() []byte {
	return at.payoutScript
}

func (at *AuxTemplate) ScriptSigMaxLen() uint16 {
	return at.scriptSigMaxLen
}

func (at *AuxTemplate) Extranonce2Size() uint8 {
	return at.extranonce2Size
}

func (at *AuxTemplate) NBits() uint32 {
	return at.nBits
}

func (at *AuxTemplate) NTimeMask() NTimeMask {
	return at.nTimeMask
}

func (at *AuxTemplate) Sigs() []SignerEnvelope {
	return at.sigs
}

// Setter functions for AuxTemplate struct
func (at *AuxTemplate) SetChainId(chainId ChainID) {
	at.chainID = chainId
}

func (at *AuxTemplate) SetPrevHash(prevHash [32]byte) {
	at.prevHash = prevHash
}

func (at *AuxTemplate) SetPayoutScript(payoutScript []byte) {
	at.payoutScript = payoutScript
}

func (at *AuxTemplate) SetScriptSigMaxLen(maxLen uint16) {
	at.scriptSigMaxLen = maxLen
}

func (at *AuxTemplate) SetExtranonce2Size(size uint8) {
	at.extranonce2Size = size
}

func (at *AuxTemplate) SetNBits(nBits uint32) {
	at.nBits = nBits
}

func (at *AuxTemplate) SetNTimeMask(mask NTimeMask) {
	at.nTimeMask = mask
}

func (at *AuxTemplate) SetSigs(sigs []SignerEnvelope) {
	at.sigs = sigs
}

func CopyAuxTemplate(at *AuxTemplate) *AuxTemplate {
	if at == nil {
		return nil
	}

	sigs := make([]SignerEnvelope, len(at.sigs))
	copy(sigs, at.sigs)

	return &AuxTemplate{
		chainID:         at.chainID,
		prevHash:        at.prevHash,
		payoutScript:    append([]byte(nil), at.payoutScript...),
		scriptSigMaxLen: at.scriptSigMaxLen,
		extranonce2Size: at.extranonce2Size,
		nBits:           at.nBits,
		nTimeMask:       at.nTimeMask,
		sigs:            sigs,
	}
}

// AuxPow represents auxiliary proof-of-work data
type AuxPow struct {
	chain    ChainID
	header   []byte // 80B donor header
	coinbase []byte // raw donor coinbase
	branch   [][]byte
	index    uint32
	// (Height, etc., optional)
}

func NewAuxPow(chain ChainID, header, coinbase []byte, branch [][]byte, index uint32) *AuxPow {
	return &AuxPow{
		chain:    chain,
		header:   header,
		coinbase: coinbase,
		branch:   branch,
		index:    index,
	}
}

// Getter functions for AuxPow struct
func (ap *AuxPow) Chain() ChainID {
	return ap.chain
}

func (ap *AuxPow) Header() []byte {
	return ap.header
}

func (ap *AuxPow) Coinbase() []byte {
	return ap.coinbase
}

func (ap *AuxPow) Branch() [][]byte {
	return ap.branch
}

func (ap *AuxPow) Index() uint32 {
	return ap.index
}

// Setter functions for AuxPow struct
func (ap *AuxPow) SetChain(chainId ChainID) {
	ap.chain = chainId
}

func (ap *AuxPow) SetHeader(header []byte) {
	ap.header = header
}

func (ap *AuxPow) SetCoinbase(coinbase []byte) {
	ap.coinbase = coinbase
}

func (ap *AuxPow) SetBranch(branch [][]byte) {
	ap.branch = branch
}

func (ap *AuxPow) SetIndex(index uint32) {
	ap.index = index
}

func CopyAuxPow(ap *AuxPow) *AuxPow {
	if ap == nil {
		return nil
	}

	branch := make([][]byte, len(ap.branch))
	for i, b := range ap.branch {
		branch[i] = make([]byte, len(b))
		copy(branch[i], b)
	}

	return &AuxPow{
		chain:    ap.chain,
		header:   append([]byte(nil), ap.header...),
		coinbase: append([]byte(nil), ap.coinbase...),
		branch:   branch,
		index:    ap.index,
	}
}

// ProtoEncode converts AuxPow to its protobuf representation
func (ap *AuxPow) ProtoEncode() *ProtoAuxPow {
	if ap == nil {
		return nil
	}

	branch := make([][]byte, len(ap.branch))
	for i, b := range ap.branch {
		branch[i] = make([]byte, len(b))
		copy(branch[i], b)
	}

	chain := uint32(ap.chain)
	index := ap.index

	return &ProtoAuxPow{
		Chain:    &chain,
		Header:   ap.header,
		Coinbase: ap.coinbase,
		Branch:   branch,
		Index:    &index,
	}
}

// ProtoDecode populates AuxPow from its protobuf representation
func (ap *AuxPow) ProtoDecode(data *ProtoAuxPow) error {
	if data == nil {
		return nil
	}

	ap.chain = ChainID(data.GetChain())
	ap.header = data.GetHeader()
	ap.coinbase = data.GetCoinbase()
	ap.index = data.GetIndex()

	ap.branch = make([][]byte, len(data.GetBranch()))
	for i, b := range data.GetBranch() {
		ap.branch[i] = make([]byte, len(b))
		copy(ap.branch[i], b)
	}

	return nil
}
