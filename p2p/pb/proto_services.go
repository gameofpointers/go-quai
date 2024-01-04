package pb

import (
	"encoding/hex"

	"github.com/dominant-strategies/go-quai/common"
	"github.com/dominant-strategies/go-quai/core/types"
	"github.com/gogo/protobuf/proto"
)

// Unmarshals a serialized protobuf slice of bytes into a protocol buffer type
func UnmarshalProtoMessage(data []byte, pbMsg proto.Message) error {
	if err := proto.Unmarshal(data, pbMsg); err != nil {
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

// converts a custom go Block type (types.Block) to a protocol buffer Block type (pb.Block)
func ConvertToProtoBlock(block types.Block) *Block {
	return &Block{
		Hash: hex.EncodeToString(block.Hash().Bytes()),
		// ... map other fields
	}

}

// converts a protocol buffer Block type (pb.Block) to a custom go Block type (types.Block)
func ConvertFromProtoBlock(pbBlock *Block) types.Block {
	var hash common.Hash
	copy(hash[:], pbBlock.Hash)
	// ... map other fields
	return types.Block{
		// ... map other fields
	}
}

// Unmarshals a serialized protobuf slice of bytes into a custom *types.Block type
func UnmarshalBlock(data []byte) (*types.Block, error) {
	var pbBlock Block
	err := UnmarshalProtoMessage(data, &pbBlock)
	if err != nil {
		return nil, err
	}
	block := ConvertFromProtoBlock(&pbBlock)
	return &block, nil
}

// Creates a BlockRequest protocol buffer message
func CreateProtoBlockRequest(hash common.Hash) *BlockRequest {
	return &BlockRequest{
		Hash: hex.EncodeToString(hash[:]),
	}
}
