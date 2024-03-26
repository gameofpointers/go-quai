package pubsubManager

import (
	"strings"

	"github.com/dominant-strategies/go-quai/common"
	"github.com/dominant-strategies/go-quai/core/types"
)

const (
	// Data types for gossipsub topics
	C_workObjectType  = "blocks"
	C_transactionType = "transactions"
	C_headerType      = "headers"
	C_hashType        = "hash"
)

// gets the name of the topic for the given type of data
func TopicName(location common.Location, data interface{}, datatype interface{}) (string, error) {
	switch datatype.(type) {
	case *types.WorkObject:
		return strings.Join([]string{location.Name(), C_workObjectType}, "/"), nil
	case common.Hash:
		return strings.Join([]string{location.Name(), C_hashType}, "/"), nil
	case *types.Transaction:
		return strings.Join([]string{location.Name(), C_transactionType}, "/"), nil
	default:
		return "", ErrUnsupportedType
	}
}
