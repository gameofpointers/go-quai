package pb

import (
	"github.com/dominant-strategies/go-quai/common"
	"github.com/dominant-strategies/go-quai/core/types"
)

// Converts a custom Block type to a protobuf Block type
func convertBlockToProto(block *types.Block) *Block {
	protoBlock := &Block{}
	if block == nil {
		return protoBlock
	}

	protoBlock = &Block{
		Header:   convertHeaderToProto(block.Header()),
		Txs:      convertTransactionsToProto(block.Transactions()),
		Etxs:     convertTransactionsToProto(block.ExtTransactions()),
		Manifest: convertManifestsToProto(block.SubManifest()),
	}

	return protoBlock
}

// Converts a custom Header type to a protobuf Header type
func convertHeaderToProto(header *types.Header) *Header {
	protoHeader := &Header{}
	if header == nil {
		return protoHeader
	}

	protoHeader = &Header{
		ParentHash:    convertHashArrayToProto(header.ParentHashArray()),
		UncleHash:     header.UncleHash().Bytes(),
		Coinbase:      header.Coinbase().Bytes(),
		Root:          header.Root().Bytes(),
		TxHash:        header.TxHash().Bytes(),
		EtxHash:       header.EtxHash().Bytes(),
		EtxRollupHash: header.EtxRollupHash().Bytes(),
		ManifestHash:  convertHashArrayToProto(header.ManifestHashArray()),
		ReceiptHash:   header.ReceiptHash().Bytes(),
		Difficulty:    header.Difficulty().Bytes(),
		GasLimit:      header.GasLimit(),
		GasUsed:       header.GasUsed(),
		BaseFee:       header.BaseFee().Bytes(),
		Location:      header.Location(),
		Time:          header.Time(),
		Extra:         header.Extra(),
		MixHash:       header.MixHash().Bytes(),
		Nonce:         header.Nonce().Bytes(),
	}

	// Convert []*big.Int fields with HierarchyDepth
	for i := 0; i < common.HierarchyDepth; i++ {
		if header.ParentEntropy(i) != nil {
			protoHeader.ParentEntropy = append(protoHeader.ParentEntropy, header.ParentEntropy(i).Bytes())
		}
		if header.ParentDeltaS(i) != nil {
			protoHeader.ParentDeltaS = append(protoHeader.ParentDeltaS, header.ParentDeltaS(i).Bytes())
		}

		if header.Number(i) != nil {
			protoHeader.Number = append(protoHeader.Number, header.Number(i).Bytes())
		}
	}
	return protoHeader
}

// Converts a custom Transaction type to a protobuf Transaction type
func convertTransactionsToProto(transactions types.Transactions) *Transactions {
	protoTx := &Transactions{}
	if transactions == nil {
		return protoTx
	}
	for _, tx := range transactions {
		protoTx.Transactions = append(protoTx.Transactions, convertTransactionToProto(tx))
	}
	return protoTx
}

func convertTransactionToProto(t *types.Transaction) *Transaction {
	protoTx := &Transaction{}

	protoTx.Hash = t.Hash().Bytes()
	protoTx.Type = uint64(t.Type())

	// Other fields are set conditionally depending on tx type.
	switch t.Type() {
	case 0:
		protoTx.ChainId = t.ChainId().Bytes()
		protoTx.AccessList = convertAccessListToProto(t.AccessList())
		protoTx.Nonce = t.Nonce()
		protoTx.Gas = t.Gas()
		protoTx.MaxFeePerGas = t.GasFeeCap().Bytes()
		protoTx.MaxFeePerGas = t.GasTipCap().Bytes()
		protoTx.Value = t.Value().Bytes()
		protoTx.Input = t.Data()
		protoTx.To = t.To().String()
		V, R, S := t.RawSignatureValues()
		protoTx.V = V.Bytes()
		protoTx.R = R.Bytes()
		protoTx.S = S.Bytes()
	case 1:
		protoTx.ChainId = t.ChainId().Bytes()
		protoTx.AccessList = convertAccessListToProto(t.AccessList())
		protoTx.Nonce = t.Nonce()
		protoTx.Gas = t.Gas()
		protoTx.MaxFeePerGas = t.GasFeeCap().Bytes()
		protoTx.MaxFeePerGas = t.GasTipCap().Bytes()
		protoTx.Value = t.Value().Bytes()
		protoTx.Input = t.Data()
		protoTx.To = t.To().String()
	case 2:
		protoTx.ChainId = t.ChainId().Bytes()
		protoTx.AccessList = convertAccessListToProto(t.AccessList())
		protoTx.Nonce = t.Nonce()
		protoTx.Gas = t.Gas()
		protoTx.MaxFeePerGas = t.GasFeeCap().Bytes()
		protoTx.MaxFeePerGas = t.GasTipCap().Bytes()
		protoTx.Value = t.Value().Bytes()
		protoTx.Input = t.Data()
		protoTx.To = t.To().String()
		V, R, S := t.RawSignatureValues()
		protoTx.V = V.Bytes()
		protoTx.R = R.Bytes()
		protoTx.S = S.Bytes()
		protoTx.EtxGasLimit = t.ETXGasLimit()
		protoTx.EtxGasPrice = t.ETXGasPrice().Bytes()
		protoTx.EtxGasTip = t.ETXGasTip().Bytes()
		protoTx.EtxData = t.ETXData()
		protoTx.EtxAccessList = convertAccessListToProto(t.ETXAccessList())
	}
	return protoTx
}

// helper function to convert a array of manifest hashes to a slice of []byte
func convertManifestsToProto(manifest types.BlockManifest) *Manifest {
	protoManifest := &Manifest{}
	for _, hash := range manifest {
		protoManifest.Manifest = append(protoManifest.Manifest, hash.Bytes())
	}
	return protoManifest
}

// converts an access list to a protobuf access list
func convertAccessListToProto(accessLists types.AccessList) *Accesslist {
	protoAccessList := &Accesslist{}
	for _, accessList := range accessLists {
		protoAccessList.AccessTuples = append(protoAccessList.AccessTuples, convertAccessTupleToProto(&accessList))
	}
	return protoAccessList
}

func convertAccessTupleToProto(accessTuple *types.AccessTuple) *AccessTuple {
	protoAccessTuple := &AccessTuple{}
	protoAccessTuple.Address = accessTuple.Address.Bytes()
	protoAccessTuple.StorageKey = convertHashArrayToProto(accessTuple.StorageKeys)
	return protoAccessTuple
}

// Converts a custom Block type to a protobuf Block type
func convertHashToProto(hash common.Hash) *Hash {
	hashBytes := hash.Bytes()
	protoHash := &Hash{
		Hash: hashBytes[:],
	}
	return protoHash
}

// helper function to convert a slice of hashes to a slice of []byte
func convertHashArrayToProto(hashArray []common.Hash) [][]byte {
	hashes := make([][]byte, len(hashArray))
	for i, hash := range hashArray {
		hashes[i] = hash.Bytes()
	}
	return hashes
}

// Converts a custom Location type to a protobuf Location type
func convertLocationToProto(location common.Location) *Location {
	protoLocation := Location{
		Location: location,
	}
	return &protoLocation
}
