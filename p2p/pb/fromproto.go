package pb

import (
	"encoding/binary"
	"errors"
	"math/big"

	"github.com/dominant-strategies/go-quai/common"
	"github.com/dominant-strategies/go-quai/core/types"
)

// Converts a protobuf location type to a custom location type
func convertProtoToLocation(protoLocation *Location) common.Location {
	location := common.Location(protoLocation.GetLocation())
	return location
}

// Converts a protobuf Hash type to a custom Hash type
func convertProtoToHash(protoHash *Hash) common.Hash {
	hash := common.Hash{}
	hash.SetBytes(protoHash.Hash)
	return hash
}

// Converts a protobuf Block type to a custom Block type
func convertProtoToBlock(protoBlock *Block) (*types.Block, error) {
	header, err := convertProtoToHeader(protoBlock.Header)
	if err != nil {
		return nil, err
	}
	txs, err := convertProtoToTransactions(protoBlock.Txs, header.Location())
	if err != nil {
		return nil, err
	}
	etxs, err := convertProtoToTransactions(protoBlock.Etxs, header.Location())
	if err != nil {
		return nil, err
	}
	manifest, err := convertProtoToManifest(protoBlock.Manifest)
	if err != nil {
		return nil, err
	}
	uncles, err := convertProtoToUncles(protoBlock.Uncles)
	if err != nil {
		return nil, err
	}
	block := types.NewBlockWithHeader(header).WithBody(txs, uncles, etxs, manifest)
	return block, nil
}

// Converts a protobuf Header type to a custom Header type
func convertProtoToHeader(protoHeader *Header) (*types.Header, error) {
	header := types.EmptyHeader()
	if protoHeader.ParentHash == nil {
		return nil, errors.New("missing required field 'ParentHash' in Header")
	}
	if protoHeader.UncleHash == nil {
		return nil, errors.New("missing required field 'UncleHash' in Header")
	}
	if protoHeader.Coinbase == nil {
		return nil, errors.New("missing required field 'Coinbase' in Header")
	}
	if protoHeader.Root == nil {
		return nil, errors.New("missing required field 'Root' in Header")
	}
	if protoHeader.TxHash == nil {
		return nil, errors.New("missing required field 'TxHash' in Header")
	}
	if protoHeader.EtxHash == nil {
		return nil, errors.New("missing required field 'EtxHash' in Header")
	}
	if protoHeader.EtxRollupHash == nil {
		return nil, errors.New("missing required field 'EtxRollupHash' in Header")
	}
	if protoHeader.ManifestHash == nil {
		return nil, errors.New("missing required field 'ManifestHash' in Header")
	}
	if protoHeader.ReceiptHash == nil {
		return nil, errors.New("missing required field 'ReceiptHash' in Header")
	}
	if protoHeader.Difficulty == nil {
		return nil, errors.New("missing required field 'Difficulty' in Header")
	}
	if protoHeader.BaseFee == nil {
		return nil, errors.New("missing required field 'BaseFee' in Header")
	}
	if protoHeader.MixHash == nil {
		return nil, errors.New("missing required field 'MixHash' in Header")
	}
	if protoHeader.ParentEntropy == nil {
		return nil, errors.New("missing required field 'ParentEntropy' in Header")
	}
	if protoHeader.ParentDeltaS == nil {
		return nil, errors.New("missing required field 'ParentDeltaS' in Header")
	}
	if protoHeader.Number == nil {
		return nil, errors.New("missing required field 'Number' in Header")
	}
	if protoHeader.Location == nil {
		return nil, errors.New("missing required field 'Location' in Header")
	}
	if protoHeader.Extra == nil {
		return nil, errors.New("missing required field 'Extra' in Header")
	}
	if protoHeader.MixHash == nil {
		return nil, errors.New("missing required field 'MixHash' in Header")
	}

	// Check if the location is valid length
	if len(protoHeader.GetLocation()) < 2 {
		return nil, errors.New("invalid length for location in Header")
	}

	for i := 0; i < common.HierarchyDepth; i++ {
		header.SetParentHash(common.BytesToHash(protoHeader.GetParentHash()[i]), i)
		header.SetManifestHash(common.BytesToHash(protoHeader.GetManifestHash()[i]), i)
		header.SetParentEntropy(new(big.Int).SetBytes(protoHeader.GetParentEntropy()[i]), i)
		header.SetParentDeltaS(new(big.Int).SetBytes(protoHeader.GetParentDeltaS()[i]), i)
		header.SetNumber(new(big.Int).SetBytes(protoHeader.GetNumber()[i]), i)
	}

	header.SetUncleHash(common.BytesToHash(protoHeader.GetUncleHash()))
	header.SetCoinbase(common.BytesToAddress(protoHeader.GetCoinbase(), protoHeader.GetLocation()))
	header.SetRoot(common.BytesToHash(protoHeader.GetRoot()))
	header.SetTxHash(common.BytesToHash(protoHeader.GetTxHash()))
	header.SetReceiptHash(common.BytesToHash(protoHeader.GetReceiptHash()))
	header.SetEtxHash(common.BytesToHash(protoHeader.GetEtxHash()))
	header.SetEtxRollupHash(common.BytesToHash(protoHeader.GetEtxRollupHash()))
	header.SetDifficulty(new(big.Int).SetBytes(protoHeader.GetDifficulty()))
	header.SetGasLimit(protoHeader.GetGasLimit())
	header.SetGasUsed(protoHeader.GetGasUsed())
	header.SetBaseFee(new(big.Int).SetBytes(protoHeader.GetBaseFee()))
	header.SetTime(protoHeader.GetTime())
	header.SetExtra(protoHeader.GetExtra())
	header.SetMixHash(common.BytesToHash(protoHeader.GetMixHash()))
	header.SetNonce(uint64ToByteArr(protoHeader.GetNonce()))

	return header, nil
}

func convertProtoToTransactions(protoTransactions *Transactions, location common.Location) (types.Transactions, error) {
	var txs types.Transactions
	for _, tx := range protoTransactions.GetTransactions() {
		convertedTx, err := convertProtoToTransaction(tx, location)
		if err != nil {
			return nil, err
		}
		txs = append(txs, convertedTx)
	}
	return txs, nil
}

// Converts a protobuf Transaction type to native Transaction type
func convertProtoToTransaction(protoTx *Transaction, location common.Location) (*types.Transaction, error) {
	tx := &types.Transaction{}

	txType := protoTx.GetType()
	switch txType {
	case 0:
		var itx types.InternalTx
		if protoTx.AccessList == nil {
			return nil, errors.New("missing required field 'AccessList' in InternalTx")
		}
		itx.AccessList = convertProtoToAccessList(protoTx.GetAccessList(), location)
		if protoTx.ChainId == nil {
			return nil, errors.New("missing required field 'ChainId' in InternalTx")
		}
		itx.ChainID = new(big.Int).SetBytes(protoTx.GetChainId())
		itx.Nonce = protoTx.GetNonce()
		if protoTx.MaxPriorityGasFee == nil {
			return nil, errors.New("missing required field 'GasTipCap' in InternalTx")
		}
		itx.GasTipCap = new(big.Int).SetBytes(protoTx.GetMaxPriorityGasFee())
		if protoTx.MaxFeePerGas == nil {
			return nil, errors.New("missing required field 'GasFeeCap' in InternalTx")
		}
		itx.GasFeeCap = new(big.Int).SetBytes(protoTx.GetMaxFeePerGas())
		itx.Gas = protoTx.GetGas()
		if protoTx.Value == nil {
			return nil, errors.New("missing required field 'Value' in InternalTx")
		}
		itx.Value = new(big.Int).SetBytes(protoTx.GetValue())
		if protoTx.Input == nil {
			return nil, errors.New("missing required field 'Data' in InternalTx")
		}
		itx.Data = protoTx.GetInput()
		if protoTx.V == nil {
			return nil, errors.New("missing required field 'V' in InternalTx")
		}
		itx.V = new(big.Int).SetBytes(protoTx.GetV())
		if protoTx.R == nil {
			return nil, errors.New("missing required field 'R' in InternalTx")
		}
		itx.R = new(big.Int).SetBytes(protoTx.GetR())
		if protoTx.S == nil {
			return nil, errors.New("missing required field 'S' in InternalTx")
		}
		itx.S = new(big.Int).SetBytes(protoTx.GetS())
		withSignature := itx.V.Sign() != 0 || itx.R.Sign() != 0 || itx.S.Sign() != 0
		if withSignature {
			if err := types.SanityCheckSignature(itx.V, itx.R, itx.S); err != nil {
				return nil, err
			}
		}
		tx = types.NewTx(&itx)
		return tx, nil
	case 1:
		var etx types.ExternalTx
		if protoTx.AccessList == nil {
			return nil, errors.New("missing required field 'AccessList' in ExternalTx")
		}
		etx.AccessList = convertProtoToAccessList(protoTx.GetAccessList(), location)
		if protoTx.ChainId == nil {
			return nil, errors.New("missing required field 'ChainId' in ExternalTx")
		}
		etx.ChainID = new(big.Int).SetBytes(protoTx.GetChainId())
		if protoTx.MaxPriorityGasFee == nil {
			return nil, errors.New("missing required field 'GasTipCap' in ExternalTx")
		}
		etx.GasTipCap = new(big.Int).SetBytes(protoTx.GetMaxPriorityGasFee())
		if protoTx.MaxFeePerGas == nil {
			return nil, errors.New("missing required field 'GasFeeCap' in ExternalTx")
		}
		etx.GasFeeCap = new(big.Int).SetBytes(protoTx.GetMaxFeePerGas())
		etx.Gas = protoTx.GetGas()
		if protoTx.Input == nil {
			return nil, errors.New("missing required field 'Data' in ExternalTx")
		}
		etx.Data = protoTx.GetInput()
		etx.Value = new(big.Int).SetBytes(protoTx.GetValue())
		if protoTx.Sender == nil {
			return nil, errors.New("missing required field 'Sender' in ExternalTx")
		}
		etx.Sender = common.BytesToAddress(protoTx.GetSender(), location)

		tx = types.NewTx(&etx)
		return tx, nil
	case 2:
		var ietx types.InternalToExternalTx
		if protoTx.AccessList == nil {
			return nil, errors.New("missing required field 'AccessList' in InternalToExternalTx")
		}
		ietx.AccessList = convertProtoToAccessList(protoTx.GetAccessList(), location)
		if protoTx.ChainId == nil {
			return nil, errors.New("missing required field 'ChainId' in InternalToExternalTx")
		}
		if protoTx.ChainId == nil {
			return nil, errors.New("missing required field 'ChainId' in InternalToExternalTx")
		}
		ietx.ChainID = new(big.Int).SetBytes(protoTx.GetChainId())
		ietx.Nonce = protoTx.GetNonce()
		if protoTx.MaxPriorityGasFee == nil {
			return nil, errors.New("missing required field 'GasTipCap' in InternalToExternalTx")
		}
		ietx.GasTipCap = new(big.Int).SetBytes(protoTx.GetMaxPriorityGasFee())
		if protoTx.MaxFeePerGas == nil {
			return nil, errors.New("missing required field 'GasFeeCap' in InternalToExternalTx")
		}
		ietx.GasFeeCap = new(big.Int).SetBytes(protoTx.GetMaxFeePerGas())
		ietx.Gas = protoTx.GetGas()
		if protoTx.Value == nil {
			return nil, errors.New("missing required field 'Value' in InternalToExternalTx")
		}
		ietx.Value = new(big.Int).SetBytes(protoTx.GetValue())
		if protoTx.Input == nil {
			return nil, errors.New("missing required field 'Data' in InternalToExternalTx")
		}
		ietx.Data = protoTx.GetInput()
		if protoTx.V == nil {
			return nil, errors.New("missing required field 'V' in InternalToExternalTx")
		}
		ietx.V = new(big.Int).SetBytes(protoTx.GetV())
		if protoTx.R == nil {
			return nil, errors.New("missing required field 'R' in InternalToExternalTx")
		}
		ietx.R = new(big.Int).SetBytes(protoTx.GetR())
		if protoTx.S == nil {
			return nil, errors.New("missing required field 'S' in InternalToExternalTx")
		}
		ietx.S = new(big.Int).SetBytes(protoTx.GetS())
		if protoTx.Sender == nil {
			return nil, errors.New("missing required field 'Sender' in InternalToExternalTx")
		}
		withSignature := ietx.V.Sign() != 0 || ietx.R.Sign() != 0 || ietx.S.Sign() != 0
		if withSignature {
			if err := types.SanityCheckSignature(ietx.V, ietx.R, ietx.S); err != nil {
				return nil, err
			}
		}
		if protoTx.EtxAccessList == nil {
			return nil, errors.New("missing required field 'EtxAccessList' in InternalToExternalTx")
		}
		ietx.ETXAccessList = convertProtoToAccessList(protoTx.GetEtxAccessList(), location)
		ietx.ETXGasLimit = protoTx.GetEtxGasLimit()
		if protoTx.EtxGasPrice == nil {
			return nil, errors.New("missing required field 'EtxGasPrice' in InternalToExternalTx")
		}
		ietx.ETXGasPrice = new(big.Int).SetBytes(protoTx.GetEtxGasPrice())
		if protoTx.EtxGasTip == nil {
			return nil, errors.New("missing required field 'EtxGasTip' in InternalToExternalTx")
		}
		ietx.ETXGasTip = new(big.Int).SetBytes(protoTx.GetEtxGasTip())
		if protoTx.EtxData == nil {
			return nil, errors.New("missing required field 'EtxData' in InternalToExternalTx")
		}
		tx = types.NewTx(&ietx)
		return tx, nil
	default:
		return nil, errors.New("invalid transaction type")
	}
}

// Converts a protobuf manifest type to a BlockManifest type
func convertProtoToManifest(protoManifest *Manifest) (types.BlockManifest, error) {
	manifest := types.BlockManifest{}
	for _, m := range protoManifest.GetManifest() {
		manifest = append(manifest, common.BytesToHash(m))
	}
	return manifest, nil
}

// Converts a protobuf uncle type to a arary of headers
func convertProtoToUncles(protoUncles *Headers) ([]*types.Header, error) {
	uncles := []*types.Header{}
	for _, uncle := range protoUncles.GetHeaders() {
		convertedUncle, err := convertProtoToHeader(uncle)
		if err != nil {
			return nil, err
		}
		uncles = append(uncles, convertedUncle)
	}
	return uncles, nil
}

// Converts a protobuf AccessList type to a AccessList type
func convertProtoToAccessList(protoAccessList *AccessList, location common.Location) types.AccessList {
	accessList := types.AccessList{}
	for _, access := range protoAccessList.GetAccessTuples() {
		accessTuple := types.AccessTuple{}
		accessTuple.Address = common.BytesToAddress(access.GetAddress(), location)
		for _, key := range access.GetStorageKey() {
			accessTuple.StorageKeys = append(accessTuple.StorageKeys, common.BytesToHash(key))
		}
		accessList = append(accessList, accessTuple)
	}
	return accessList
}

// helper to convert uint64 into a byte array
func uint64ToByteArr(val uint64) [8]byte {
	var arr [8]byte
	binary.BigEndian.PutUint64(arr[:], val)
	return arr
}
