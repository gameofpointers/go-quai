package pb

import (
	"math/big"
	reflect "reflect"
	"testing"

	"github.com/dominant-strategies/go-quai/common"
	"github.com/dominant-strategies/go-quai/core/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEncodeDecodeRequest(t *testing.T) {
	t.Skip("Fix broken test")
	loc := common.Location{0, 0}

	hash := &common.Hash{}
	hash.SetBytes([]byte("mockHash"))

	id := uint32(1)

	//TODO: Add transaction, workobject and header to test cases
	testCases := []struct {
		name         string
		input        interface{}
		expectedType reflect.Type
	}{
		{
			name:         "Hash",
			input:        common.Hash{},
			expectedType: reflect.TypeOf(common.Hash{}),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Encode the QuaiRequest
			data, err := EncodeQuaiRequest(id, loc, *hash, tc.input)
			require.NoError(t, err)

			// Decode the QuaiRequest
			quaiMsg, err := DecodeQuaiMessage(data)
			if err != nil {
				t.Fatal(err)
			}
			decodedId, decodedType, decodedLocation, decodedHash, err := DecodeQuaiRequest(quaiMsg.GetRequest())
			assert.NoError(t, err)
			assert.Equal(t, id, decodedId)
			assert.Equal(t, loc, decodedLocation)
			assert.Equal(t, hash, decodedHash)
			assert.IsType(t, tc.expectedType, reflect.TypeOf(decodedType))
		})
	}
}

func TestBlockBatchRequestRoundTrip(t *testing.T) {
	loc := common.Location{0, 1}
	hashes := []common.Hash{{1}, {2}, {3}}
	request := &types.BlockBatchRequest{Hashes: hashes, MaxBlocks: 3, MaxBytes: 2 * 1024 * 1024}
	data, err := EncodeQuaiRequest(7, loc, request, []*types.WorkObjectBlockView{})
	require.NoError(t, err)
	message, err := DecodeQuaiMessage(data)
	require.NoError(t, err)
	id, responseType, decodedLoc, query, err := DecodeQuaiRequest(message.GetRequest())
	require.NoError(t, err)
	assert.Equal(t, uint32(7), id)
	assert.Equal(t, loc, decodedLoc)
	assert.IsType(t, []*types.WorkObjectBlockView{}, responseType)
	assert.Equal(t, request, query)
}

func TestBlockRangeRequestRoundTrip(t *testing.T) {
	request := &types.BlockBatchRequest{Origin: big.NewInt(42), MaxBlocks: 128, MaxBytes: 1024}
	data, err := EncodeQuaiRequest(8, common.Location{}, request, []*types.WorkObjectBlockView{})
	require.NoError(t, err)
	message, err := DecodeQuaiMessage(data)
	require.NoError(t, err)
	_, _, _, query, err := DecodeQuaiRequest(message.GetRequest())
	require.NoError(t, err)
	assert.Equal(t, request, query)
}

func TestBlockBatchRequestRejectsAmbiguousQuery(t *testing.T) {
	request := &types.BlockBatchRequest{Origin: big.NewInt(1), Hashes: []common.Hash{{1}}}
	_, err := EncodeQuaiRequest(9, common.Location{}, request, []*types.WorkObjectBlockView{})
	require.Error(t, err)
}

func TestDecodeQuaiRequestRejectsNil(t *testing.T) {
	_, _, _, _, err := DecodeQuaiRequest(nil)
	require.Error(t, err)
}

func TestDecodeQuaiResponseRejectsNil(t *testing.T) {
	_, _, err := DecodeQuaiResponse(nil)
	require.Error(t, err)
}
