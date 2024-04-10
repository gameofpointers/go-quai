package protocol

import (
	"errors"
	"io"
	"math/big"
	"runtime/debug"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/sirupsen/logrus"

	"github.com/dominant-strategies/go-quai/common"
	"github.com/dominant-strategies/go-quai/core/types"
	"github.com/dominant-strategies/go-quai/log"
	"github.com/dominant-strategies/go-quai/p2p/pb"
	"github.com/dominant-strategies/go-quai/quai/snap"
)

const numWorkers = 10    // Number of workers per stream
const msgChanSize = 5000 // 5k requests per stream

// QuaiProtocolHandler handles all the incoming requests and responds with corresponding data
func QuaiProtocolHandler(stream network.Stream, node QuaiP2PNode) {
	defer stream.Close()
	defer func() {
		if r := recover(); r != nil {
			log.Global.WithFields(log.Fields{
				"error":      r,
				"stacktrace": string(debug.Stack()),
			}).Fatal("Go-Quai Panicked")
		}
	}()

	log.Global.Debugf("Received a new stream from %s", stream.Conn().RemotePeer())

	// if there is a protocol mismatch, close the stream
	if stream.Protocol() != ProtocolVersion {
		log.Global.Warnf("Invalid protocol: %s", stream.Protocol())
		// TODO: add logic to drop the peer
		return
	}
	// Create a channel for messages
	msgChan := make(chan []byte, msgChanSize)
	full := 0
	// Start worker goroutines
	for i := 0; i < numWorkers; i++ {
		go func() {
			for message := range msgChan { // This should exit when msgChan is closed
				handleMessage(message, stream, node)
			}
		}()
	}

	// Enter the read loop for the stream and handle messages
	for {
		data, err := common.ReadMessageFromStream(stream)
		if err != nil {
			if errors.Is(err, network.ErrReset) || errors.Is(err, io.EOF) {
				close(msgChan)
				return
			}

			log.Global.Errorf("error reading message from stream: %s", err)
			// TODO: handle error
			continue
		}

		// Send to worker goroutines
		select {
		case msgChan <- data:
		default:
			if full%1000 == 0 {
				log.Global.WithField("stream with peer", stream.Conn().RemotePeer()).Warnf("QuaiProtocolHandler message channel is full. Lost messages: %d", full)
			}
			full++
		}

	}
}

func handleMessage(data []byte, stream network.Stream, node QuaiP2PNode) {
	defer func() {
		if r := recover(); r != nil {
			log.Global.WithFields(log.Fields{
				"error":      r,
				"stacktrace": string(debug.Stack()),
			}).Fatal("Go-Quai Panicked")
		}
	}()
	quaiMsg, err := pb.DecodeQuaiMessage(data)
	if err != nil {
		log.Global.Errorf("error decoding quai message: %s", err)
		return
	}

	switch {
	case quaiMsg.GetRequest() != nil:
		handleRequest(quaiMsg.GetRequest(), stream, node)
		if messageMetrics != nil {
			messageMetrics.WithLabelValues("requests").Inc()
		}

	case quaiMsg.GetResponse() != nil:
		handleResponse(quaiMsg.GetResponse(), node)
		if messageMetrics != nil {
			messageMetrics.WithLabelValues("responses").Inc()
		}

	default:
		log.Global.WithField("quaiMsg", quaiMsg).Errorf("unsupported quai message type")
	}
}

func handleRequest(quaiMsg *pb.QuaiRequestMessage, stream network.Stream, node QuaiP2PNode) {
	id, decodedType, loc, query, err := pb.DecodeQuaiRequest(quaiMsg)
	if err != nil {
		log.Global.WithField("err", err).Errorf("error decoding quai request")
		// TODO: handle error
		return
	}
	switch query.(type) {
	case *common.Hash:
		log.Global.WithFields(log.Fields{
			"requestID":   id,
			"decodedType": decodedType,
			"location":    loc,
			"hash":        query,
			"peer":        stream.Conn().RemotePeer(),
		}).Debug("Received request by hash to handle")
	case *big.Int:
		log.Global.WithFields(log.Fields{
			"requestID":   id,
			"decodedType": decodedType,
			"location":    loc,
			"number":      query,
			"peer":        stream.Conn().RemotePeer(),
		}).Debug("Received request by number to handle")
	case *snap.AccountRangeRequest:
		log.Global.WithFields(log.Fields{
			"requestID":           id,
			"decodedType":         decodedType,
			"location":            loc,
			"accountRangeRequest": query,
			"peer":                stream.Conn().RemotePeer(),
		}).Debug("Received request by account range to handle")
	case *snap.StorageRangesRequest:
		log.Global.WithFields(log.Fields{
			"requestID":            id,
			"decodedType":          decodedType,
			"location":             loc,
			"storageRangesRequest": query,
			"peer":                 stream.Conn().RemotePeer(),
		}).Debug("Received request by storage ranges to handle")
	case *snap.ByteCodesRequest:
		log.Global.WithFields(log.Fields{
			"requestID":        id,
			"decodedType":      decodedType,
			"location":         loc,
			"byteCodesRequest": query,
			"peer":             stream.Conn().RemotePeer(),
		}).Debug("Received request by byte codes to handle")
	case *snap.TrieNodesRequest:
		log.Global.WithFields(log.Fields{
			"requestID":        id,
			"decodedType":      decodedType,
			"location":         loc,
			"trieNodesRequest": query,
			"peer":             stream.Conn().RemotePeer(),
		}).Debug("Received request by trie nodes to handle")
	default:
		log.Global.Errorf("unsupported request input data field type: %T", query)
	}

	switch decodedType.(type) {
	case *types.WorkObject:
		requestedHash := &common.Hash{}
		switch query := query.(type) {
		case *common.Hash:
			requestedHash = query
		case *big.Int:
			number := query
			log.Global.Tracef("Looking hash for block %s and location %s", number.String(), loc.Name())
			requestedHash = node.GetBlockHashByNumber(number, loc)
			if requestedHash == nil {
				log.Global.Debugf("block hash not found for block %s and location %s", number.String(), loc.Name())
				// TODO: handle error
				return
			}
			log.Global.Tracef("Found hash for block %s and location: %s", number.String(), loc.Name(), requestedHash)
		default:
			log.Global.Errorf("unsupported query type %v", query)
			// TODO: handle error
			return
		}
		err = handleBlockRequest(id, loc, *requestedHash, stream, node)
		if err != nil {
			log.Global.WithFields(
				logrus.Fields{
					"peer": stream.Conn().RemotePeer(),
					"err":  err,
				}).Error("error handling block request")
			// TODO: handle error
			return
		}
		if messageMetrics != nil {
			messageMetrics.WithLabelValues("blocks").Inc()
		}
	case *types.Header:
		requestedHash := query.(*common.Hash)
		err = handleHeaderRequest(id, loc, *requestedHash, stream, node)
		if err != nil {
			log.Global.WithField("err", err).Error("error handling header request")
			// TODO: handle error
			return
		}
		if messageMetrics != nil {
			messageMetrics.WithLabelValues("headers").Inc()
		}
	case *types.Transaction:
		requestedHash := query.(*common.Hash)
		err = handleTransactionRequest(id, loc, *requestedHash, stream, node)
		if err != nil {
			log.Global.WithField("err", err).Error("error handling transaction request")
			// TODO: handle error
			return
		}
		if messageMetrics != nil {
			messageMetrics.WithLabelValues("transactions").Inc()
		}
	case *common.Hash:
		number := query.(*big.Int)
		err = handleBlockNumberRequest(id, loc, number, stream, node)
		if err != nil {
			log.Global.WithField("err", err).Error("error handling block number request")
			return
		}
	case *snap.AccountRangeResponse:
		accountRequest := query.(*snap.AccountRangeRequest)
		err = handleAccountRangeRequest(id, loc, accountRequest, stream, node)
		if err != nil {
			log.Global.WithField("err", err).Error("error handling account range request")
			return
		}
	case *snap.StorageRangesResponse:
		storageRequest := query.(*snap.StorageRangesRequest)
		err = handleStorageRangesRequest(id, loc, storageRequest, stream, node)
		if err != nil {
			log.Global.WithField("err", err).Error("error handling storage ranges request")
			return

		}
	case *snap.ByteCodesResponse:
		byteCodesRequest := query.(*snap.ByteCodesRequest)
		err = handleByteCodesRequest(id, loc, byteCodesRequest, stream, node)
		if err != nil {
			log.Global.WithField("err", err).Error("error handling byte codes request")
			return
		}
	case *snap.TrieNodesResponse:
		trieNodesRequest := query.(*snap.TrieNodesRequest)
		err = handleTrieNodesRequest(id, loc, trieNodesRequest, stream, node)
		if err != nil {
			log.Global.WithField("err", err).Error("error handling trie nodes request")
			return
		}
	default:
		log.Global.WithField("request type", decodedType).Error("unsupported request data type")
		// TODO: handle error
		return

	}
}

func handleResponse(quaiResp *pb.QuaiResponseMessage, node QuaiP2PNode) {
	recvdID, recvdType, err := pb.DecodeQuaiResponse(quaiResp)
	if err != nil {
		log.Global.WithField(
			"err", err,
		).Errorf("error decoding quai response: %s", err)
		return
	}

	dataChan, err := node.GetRequestManager().GetRequestChan(recvdID)
	if err != nil {
		log.Global.WithFields(log.Fields{
			"requestID": recvdID,
			"err":       err,
		}).Error("error associating request ID with data channel")
		return
	}
	dataChan <- recvdType
}

// Seeks the block in the cache or database and sends it to the peer in a pb.QuaiResponseMessage
func handleBlockRequest(id uint32, loc common.Location, hash common.Hash, stream network.Stream, node QuaiP2PNode) error {
	// check if we have the block in our cache or database
	block := node.GetWorkObject(hash, loc)
	if block == nil {
		log.Global.Debugf("block not found")
		return nil
	}
	log.Global.Debugf("block found %s", block.Hash())
	// create a Quai Message Response with the block
	data, err := pb.EncodeQuaiResponse(id, loc, block)
	if err != nil {
		return err
	}
	err = common.WriteMessageToStream(stream, data)
	if err != nil {
		return err
	}
	log.Global.WithFields(log.Fields{
		"blockHash": block.Hash(),
		"peer":      stream.Conn().RemotePeer(),
	}).Trace("Sent block to peer")
	return nil
}

// Seeks the header in the cache or database and sends it to the peer in a pb.QuaiResponseMessage
func handleHeaderRequest(id uint32, loc common.Location, hash common.Hash, stream network.Stream, node QuaiP2PNode) error {
	header := node.GetHeader(hash, loc)
	if header == nil {
		log.Global.Debugf("header not found")
		// TODO: handle header not found
		return nil
	}
	log.Global.Debugf("header found %s", header.Hash())
	// create a Quai Message Response with the header
	data, err := pb.EncodeQuaiResponse(id, loc, header)
	if err != nil {
		return err
	}
	err = common.WriteMessageToStream(stream, data)
	if err != nil {
		return err
	}
	log.Global.Debugf("Sent header %s to peer %s", header.Hash(), stream.Conn().RemotePeer())
	return nil
}

func handleTransactionRequest(id uint32, loc common.Location, hash common.Hash, stream network.Stream, node QuaiP2PNode) error {
	panic("TODO: implement")
}

// Seeks the block in the cache or database and sends it to the peer in a pb.QuaiResponseMessage
func handleBlockNumberRequest(id uint32, loc common.Location, number *big.Int, stream network.Stream, node QuaiP2PNode) error {
	// check if we have the block in our cache or database
	blockHash := node.GetBlockHashByNumber(number, loc)
	if blockHash == nil {
		log.Global.Tracef("block not found")
		return nil
	}
	log.Global.Tracef("block found %s", blockHash)
	// create a Quai Message Response with the block
	data, err := pb.EncodeQuaiResponse(id, loc, blockHash)
	if err != nil {
		return err
	}

	err = common.WriteMessageToStream(stream, data)
	if err != nil {
		return err
	}
	log.Global.Tracef("Sent block hash %s to peer %s", blockHash, stream.Conn().RemotePeer())
	return nil
}

func handleAccountRangeRequest(id uint32, loc common.Location, request *snap.AccountRangeRequest, stream network.Stream, node QuaiP2PNode) error {
	accountResponse := node.GetAccountRanges(request, loc)
	if accountResponse == nil {
		log.Global.Tracef("account range not found")
		return nil
	}
	data, err := pb.EncodeQuaiResponse(id, loc, accountResponse)
	if err != nil {
		return err
	}
	err = common.WriteMessageToStream(stream, data)
	if err != nil {
		return err
	}
	return nil
}

func handleStorageRangesRequest(id uint32, loc common.Location, request *snap.StorageRangesRequest, stream network.Stream, node QuaiP2PNode) error {
	storageResponse := node.GetStorageRanges(request, loc)
	if storageResponse == nil {
		log.Global.Tracef("storage ranges not found")
		return nil
	}
	data, err := pb.EncodeQuaiResponse(id, loc, storageResponse)
	if err != nil {
		return err
	}
	err = common.WriteMessageToStream(stream, data)
	if err != nil {
		return err
	}
	return nil
}

func handleByteCodesRequest(id uint32, loc common.Location, request *snap.ByteCodesRequest, stream network.Stream, node QuaiP2PNode) error {
	byteCodesResponse := node.GetByteCodes(request, loc)
	if byteCodesResponse == nil {
		log.Global.Tracef("byte codes not found")
		return nil
	}
	data, err := pb.EncodeQuaiResponse(id, loc, byteCodesResponse)
	if err != nil {
		return err
	}
	err = common.WriteMessageToStream(stream, data)
	if err != nil {
		return err
	}
	return nil
}

func handleTrieNodesRequest(id uint32, loc common.Location, request *snap.TrieNodesRequest, stream network.Stream, node QuaiP2PNode) error {
	trieNodesResponse, err := node.GetTrieNodes(request, loc)
	if err != nil {
		return err
	}
	if trieNodesResponse == nil {
		log.Global.Tracef("trie nodes not found")
		return nil
	}
	data, err := pb.EncodeQuaiResponse(id, loc, trieNodesResponse)
	if err != nil {
		return err
	}
	err = common.WriteMessageToStream(stream, data)
	if err != nil {
		return err
	}
	return nil
}
