package protocol

import (
	"context"

	"testing"
	"time"

	"github.com/dominant-strategies/go-quai/common"
	"github.com/dominant-strategies/go-quai/core/types"
	"github.com/dominant-strategies/go-quai/p2p/pb"
	"github.com/dominant-strategies/go-quai/p2p/protocol/mocks"
	"github.com/golang/mock/gomock"
	"github.com/libp2p/go-libp2p/core/network"
	mocknet "github.com/libp2p/go-libp2p/p2p/net/mock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestQuaiProtocolHandler(t *testing.T) {

	loc := common.Location([]byte("test"))

	hash := common.Hash{}
	// set hash with all 0x11 bytes
	for i := 0; i < 32; i++ {
		hash[i] = 0x11
	}
	header := new(types.Header)
	header.SetGasLimit(1000)
	header.SetGasUsed(100)

	testCases := []struct {
		name      string
		mockStub  func(*mocks.MockQuaiP2PNode)
		action    pb.QuaiRequestMessage_ActionType
		location  *common.Location
		hash      *common.Hash
		ExpectErr bool
	}{
		{
			name:     "request header",
			action:   pb.QuaiRequestMessage_REQUEST_HEADER,
			location: &loc,
			hash:     &hash,
			mockStub: func(mockedQuaiNode *mocks.MockQuaiP2PNode) {
				mockedQuaiNode.EXPECT().GetHeader(gomock.Any(), gomock.Any()).Return(header).Times(1)
			},

			ExpectErr: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()

			// Create a mock network
			mnet := mocknet.New()

			// Setup two nodes on the mock network
			host1, err := mnet.GenPeer()
			require.NoError(t, err)
			defer host1.Close()

			host2, err := mnet.GenPeer()
			require.NoError(t, err)
			defer host2.Close()

			// Connect the two nodes
			err = mnet.LinkAll()
			require.NoError(t, err)
			err = mnet.ConnectAllButSelf()
			require.NoError(t, err)

			// Set up the protocol handler on the second node with the mockedQuaiNode
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			mockedQuaiNode := mocks.NewMockQuaiP2PNode(ctrl)
			tc.mockStub(mockedQuaiNode)
			host2.SetStreamHandler(ProtocolVersion, func(s network.Stream) {
				QuaiProtocolHandler(s, mockedQuaiNode)
			})

			// Set up a stream between the two hosts
			stream, err := host1.NewStream(ctx, host2.ID(), ProtocolVersion)
			assert.NoError(t, err)
			defer stream.Close()

			// Encode the message to send
			data, err := pb.EncodeQuaiRequest(tc.action, tc.location, tc.hash)
			require.NoError(t, err)

			// Send the message
			err = common.WriteMessageToStream(stream, data)
			require.NoError(t, err)
			// sleep for a bit to allow the stream to be read
			time.Sleep(1 * time.Second)

			// read the response

			msg, err := common.ReadMessageFromStream(stream)
			require.NoError(t, err)

			// Decode the response
			action, resp, err := pb.DecodeQuaiResponse(msg)
			require.NoError(t, err)
			// assert the response is type header
			assert.Equal(t, pb.QuaiResponseMessage_RESPONSE_HEADER, action)
			// assert the response is the same as the header we sent
			decodedHeader, ok := resp.(*types.Header)
			require.True(t, ok)
			assert.Equal(t, header, decodedHeader)
		})
	}
}
