package types

// ChainID represents a unique identifier for a blockchain
type ChainID uint32

// NTimeMask represents a time mask for mining operations
type NTimeMask uint32

// SignerEnvelope contains a signer ID and their signature
type SignerEnvelope struct {
	SignerID  string
	Signature []byte
}

// AuxTemplate defines the template structure for auxiliary proof-of-work
type AuxTemplate struct {
	// Enforced correspondence
	ChainID      ChainID  // must match ap.Chain
	PrevHash     [32]byte // must equal donor_header.hashPrevBlock
	PayoutScript []byte   // must equal coinbase.outputs[0].scriptPubKey
	ScriptSigMaxLen uint16   // ≤100; template may be tighter

	// Advisory (policy/UX; NOT consensus unless elevated)
	Extranonce2Size uint8
	NBits           uint32
	NTimeMask       NTimeMask

	// Quorum signatures over CanonicalEncode(AuxTemplate) WITHOUT Sigs
	Sigs []SignerEnvelope // (SignerID, Signature)
}

// AuxPow represents auxiliary proof-of-work data
type AuxPow struct {
	Chain    ChainID
	Header   []byte   // 80B donor header
	Coinbase []byte   // raw donor coinbase
	Branch   [][]byte
	Index    uint32
	// (Height, etc., optional)
}

// ProtoEncode converts AuxPow to its protobuf representation
func (ap *AuxPow) ProtoEncode() *ProtoAuxPow {
	if ap == nil {
		return nil
	}

	branch := make([][]byte, len(ap.Branch))
	for i, b := range ap.Branch {
		branch[i] = make([]byte, len(b))
		copy(branch[i], b)
	}

	chain := uint32(ap.Chain)
	index := ap.Index

	return &ProtoAuxPow{
		Chain:    &chain,
		Header:   ap.Header,
		Coinbase: ap.Coinbase,
		Branch:   branch,
		Index:    &index,
	}
}

// ProtoDecode populates AuxPow from its protobuf representation
func (ap *AuxPow) ProtoDecode(data *ProtoAuxPow) error {
	if data == nil {
		return nil
	}

	ap.Chain = ChainID(data.GetChain())
	ap.Header = data.GetHeader()
	ap.Coinbase = data.GetCoinbase()
	ap.Index = data.GetIndex()

	ap.Branch = make([][]byte, len(data.GetBranch()))
	for i, b := range data.GetBranch() {
		ap.Branch[i] = make([]byte, len(b))
		copy(ap.Branch[i], b)
	}

	return nil
}