package pb

import (
	"github.com/dominant-strategies/go-quai/common"
	"github.com/dominant-strategies/go-quai/core/types"
	"github.com/pkg/errors"
)

// Creates a Quai Response protobuf message from the given action and data.
func convertDataToProtoResponse(action QuaiResponseMessage_ActionType, data interface{}) (*Response, error) {
	switch action {
	case QuaiResponseMessage_RESPONSE_BLOCK:
		if block, ok := data.(*types.Block); ok {
			protoBlock := convertBlockToProto(block)
			return &Response{
				Response: &Response_Block{
					Block: protoBlock,
				},
			}, nil
		}
	case QuaiResponseMessage_RESPONSE_HEADER:
		if header, ok := data.(*types.Header); ok {
			protoHeader := convertHeaderToProto(header)
			return &Response{
				Response: &Response_Header{
					Header: protoHeader,
				},
			}, nil
		}
	case QuaiResponseMessage_RESPONSE_TRANSACTION:
		if transaction, ok := data.(*types.Transaction); ok {
			protoTransaction := convertTransactionToProto(transaction)
			return &Response{
				Response: &Response_Transaction{
					Transaction: protoTransaction,
				},
			}, nil
		}
	}
	return nil, errors.Errorf("invalid data type or action")
}

// Converts a custom Block type to a protobuf Block type
func convertBlockToProto(block *types.Block) *Block {
	panic("TODO: implement")
}

// Converts a custom Header type to a protobuf Header type
func convertHeaderToProto(header *types.Header) *Header {
	panic("TODO: implement")
}

// Converts a custom Transaction type to a protobuf Transaction type
func convertTransactionToProto(transaction *types.Transaction) *Transaction {
	panic("TODO: implement")

}

// Converts a custom Block type to a protobuf Block type
func convertHashToProto(hash common.Hash) *Hash {
	hashBytes := hash.Bytes()
	protoHash := &Hash{
		Hash: hashBytes[:],
	}
	return protoHash
}

// Converts a custom Location type to a protobuf Location type
func convertLocationToProto(location common.Location) *Location {
	protoLocation := Location{
		Location: location,
	}
	return &protoLocation
}
