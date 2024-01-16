package pb

import (
	"github.com/dominant-strategies/go-quai/common"
	"github.com/dominant-strategies/go-quai/core/types"
	"github.com/dominant-strategies/go-quai/log"
	"github.com/pkg/errors"
	"google.golang.org/protobuf/proto"
)

// Unmarshals a serialized protobuf slice of bytes into a protocol buffer type
func UnmarshalProtoMessage(data []byte, msg proto.Message) error {
	if err := proto.Unmarshal(data, msg); err != nil {
		return err
	}
	return nil
}

// Marshals a protocol buffer type into a serialized protobuf slice of bytes
func MarshalProtoMessage(pbMsg proto.Message) ([]byte, error) {
	data, err := proto.Marshal(pbMsg)
	if err != nil {
		return nil, err
	}
	return data, nil
}

// EncodeRequestMessage creates a marshaled protobuf message for a Quai Request.
// Returns the serialized protobuf message.
func EncodeQuaiRequest(action QuaiRequestMessage_ActionType, location common.Location, hash common.Hash) ([]byte, error) {
	request := &Request{
		Hash:     convertHashToProto(hash),
		Location: convertLocationToProto(location),
	}

	quaiMsg := &QuaiRequestMessage{
		Action:  action,
		Request: request,
	}

	return MarshalProtoMessage(quaiMsg)

}

// DecodeRequestMessage unmarshals a protobuf message into a Quai Request.
// Returns the action type, sliceID, and hash.
func DecodeQuaiRequest(data []byte) (action QuaiRequestMessage_ActionType, location common.Location, hash common.Hash, err error) {
	var quaiMsg QuaiRequestMessage
	err = UnmarshalProtoMessage(data, &quaiMsg)
	if err != nil {
		return QuaiRequestMessage_UNKNOWN, common.Location{}, common.Hash{}, err
	}

	action = quaiMsg.Action
	if !isActionValid(action) {
		return QuaiRequestMessage_UNKNOWN, common.Location{}, common.Hash{}, errors.Errorf("unsupported action type: %v", action)
	}
	request := quaiMsg.GetRequest()
	protoHash := request.GetHash()
	protoLocation := request.GetLocation()

	location = convertProtoToLocation(protoLocation)
	hash = convertProtoToHash(protoHash)

	return action, location, hash, nil
}

// EncodeResponse creates a marshaled protobuf message for a Quai Response.
// Returns the serialized protobuf message.
func EncodeQuaiResponse(action QuaiResponseMessage_ActionType, data interface{}) ([]byte, error) {

	var quaiMsg *QuaiResponseMessage
	response, err := convertDataToProtoResponse(action, data)
	if err != nil {
		return nil, err
	}
	quaiMsg = &QuaiResponseMessage{
		Action:   action,
		Response: response,
	}

	return MarshalProtoMessage(quaiMsg)
}

// Unmarshals a serialized protobuf message into a Quai Response message.
// Returns the action type and the decoded type (i.e. *types.Header, *types.Block, etc).
func DecodeQuaiResponse(data []byte) (action QuaiResponseMessage_ActionType, response interface{}, err error) {
	var quaiMsg QuaiResponseMessage
	err = UnmarshalProtoMessage(data, &quaiMsg)
	if err != nil {
		return QuaiResponseMessage_UNKNOWN, nil, err
	}

	action = quaiMsg.Action

	switch action {
	case QuaiResponseMessage_RESPONSE_BLOCK:
		protoBlock := quaiMsg.Response.GetBlock()
		block := convertProtoToBlock(protoBlock)
		response = block

	case QuaiResponseMessage_RESPONSE_HEADER:
		protoHeader := quaiMsg.Response.GetHeader()
		header := convertProtoToHeader(protoHeader)
		response = header

	case QuaiResponseMessage_RESPONSE_TRANSACTION:
		protoTransaction := quaiMsg.Response.GetTransaction()
		transaction := convertProtoToTransaction(protoTransaction)
		response = transaction
	default:
		return QuaiResponseMessage_UNKNOWN, nil, errors.Errorf("unsupported action type: %v", action)
	}

	return action, response, nil
}

// Converts a custom go type to a proto type and marhsals it into a protobuf message
func ConvertAndMarshal(data interface{}) ([]byte, error) {
	switch data := data.(type) {
	case *types.Block:
		log.Tracef("marshalling block: %+v", data)
		protoBlock := convertBlockToProto(data)
		return MarshalProtoMessage(protoBlock)
	case *types.Transaction:
		log.Tracef("marshalling transaction: %+v", data)
		protoTransaction := convertTransactionToProto(data)
		return MarshalProtoMessage(protoTransaction)
	case *types.Header:
		log.Tracef("marshalling header: %+v", data)
		protoHeader := convertHeaderToProto(data)
		return MarshalProtoMessage(protoHeader)
	default:
		return nil, errors.New("unsupported data type")
	}
}

// Unmarshals a protobuf message into a proto type and converts it to a custom go type
func UnmarshalAndConvert(data []byte, dataPtr interface{}) error {
	switch dataPtr := dataPtr.(type) {
	case *types.Block:
		protoBlock := new(Block)
		err := UnmarshalProtoMessage(data, protoBlock)
		if err != nil {
			return err
		}
		block := convertProtoToBlock(protoBlock)
		*dataPtr = *block
		return nil
	case *types.Transaction:
		protoTransaction := new(Transaction)
		err := UnmarshalProtoMessage(data, protoTransaction)
		if err != nil {
			return err
		}
		transaction := convertProtoToTransaction(protoTransaction)
		*dataPtr = *transaction
		return nil
	case *types.Header:
		protoHeader := new(Header)
		err := UnmarshalProtoMessage(data, protoHeader)
		if err != nil {
			return err
		}
		header := convertProtoToHeader(protoHeader)
		*dataPtr = *header
		return nil
	default:
		return errors.New("unsupported data type")
	}
}

// helper function to determine if the action type is valid
func isActionValid(action QuaiRequestMessage_ActionType) bool {
	switch action {
	case QuaiRequestMessage_REQUEST_BLOCK, QuaiRequestMessage_REQUEST_HEADER, QuaiRequestMessage_REQUEST_TRANSACTION:
		return true
	default:
		return false
	}
}
