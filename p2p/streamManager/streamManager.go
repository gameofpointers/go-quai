package streamManager

import (
	"context"
	"errors"

	"github.com/dominant-strategies/go-quai/log"
	"github.com/dominant-strategies/go-quai/p2p"
	quaiprotocol "github.com/dominant-strategies/go-quai/p2p/protocol"

	lru "github.com/hnlq715/golang-lru"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
)

const (
	// The amount of redundancy for open streams
	// c_peerCount * c_streamReplicationFactor = total number of open streams
	c_streamReplicationFactor = 3
)

var (
	errStreamNotFound = errors.New("stream not found")
)

type StreamManager interface {
	// GetStream returns a valid stream, either creating a new one or returning an existing one
	GetStream(peer.ID) (network.Stream, error)

	// RemoveStream goes through all the steps to properly close and remove a stream's resources
	CloseStream(peer.ID) error

	// SetP2PBackend sets the P2P backend for the stream manager
	SetP2PBackend(quaiprotocol.QuaiP2PNode)
}

type basicStreamManager struct {
	ctx         context.Context
	streamCache *lru.Cache
	p2pBackend  quaiprotocol.QuaiP2PNode
}

func NewStreamManager(peerCount int) (StreamManager, error) {
	lruCache, err := lru.NewWithEvict(
		peerCount*c_streamReplicationFactor,
		severStream,
	)
	if err != nil {
		log.Global.WithField("err", err).Fatal("Failed to create LRU cache")
		return nil, err
	}

	return &basicStreamManager{
		ctx:         context.Background(),
		streamCache: lruCache,
	}, nil
}

func severStream(key interface{}, value interface{}) {
	stream := value.(network.Stream)
	err := stream.Close()
	if err != nil {
		log.Global.WithField("err", err).Error("Failed to close stream")
	}
	if streamMetrics != nil {
		streamMetrics.WithLabelValues("NumStreams").Dec()
	}
}

func (sm *basicStreamManager) CloseStream(peerID p2p.PeerID) error {
	stream, ok := sm.streamCache.Get(peerID)
	if ok {
		log.Global.WithField("peerID", peerID).Debug("Pruned connection with peer")
		severStream(peerID, stream)
		sm.streamCache.Remove(peerID)
		return nil
	}
	return errStreamNotFound
}

func (sm *basicStreamManager) GetStream(peerID p2p.PeerID) (network.Stream, error) {
	stream, ok := sm.streamCache.Get(peerID)
	var err error
	if !ok {
		// Create a new stream to the peer and register it in the cache
		stream, err = sm.p2pBackend.GetHostBackend().NewStream(sm.ctx, peerID, quaiprotocol.ProtocolVersion)
		if err != nil {
			// Explicitly return nil here to avoid casting a nil later
			return nil, err
		}
		sm.streamCache.Add(peerID, stream)
		go quaiprotocol.QuaiProtocolHandler(stream.(network.Stream), sm.p2pBackend)
		log.Global.Debug("Had to create new stream")
		if streamMetrics != nil {
			streamMetrics.WithLabelValues("NumStreams").Inc()
		}
	} else {
		log.Global.Trace("Requested stream was found in cache")
	}

	return stream.(network.Stream), err
}

func (sm *basicStreamManager) SetP2PBackend(host quaiprotocol.QuaiP2PNode) {
	sm.p2pBackend = host
}
