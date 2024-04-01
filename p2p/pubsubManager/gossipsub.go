package pubsubManager

import (
	"context"
	"errors"

	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"

	"github.com/dominant-strategies/go-quai/common"
	"github.com/dominant-strategies/go-quai/log"
	"github.com/dominant-strategies/go-quai/p2p/pb"
	"github.com/dominant-strategies/go-quai/quai"
)

var (
	ErrUnsupportedType = errors.New("data type not supported")
)

type PubsubManager struct {
	*pubsub.PubSub
	ctx           context.Context
	subscriptions map[string]*pubsub.Subscription
	topics        map[string]*pubsub.Topic
	consensus     quai.ConsensusAPI

	// Callback function to handle received data
	onReceived func(peer.ID, interface{}, common.Location)
}

// creates a new gossipsub instance
// TODO: what options do we need for quai network? See:
// See https://pkg.go.dev/github.com/libp2p/go-libp2p-pubsub@v0.10.0#Option
func NewGossipSubManager(ctx context.Context, h host.Host) (*PubsubManager, error) {
	ps, err := pubsub.NewGossipSub(ctx, h)
	if err != nil {
		return nil, err
	}
	return &PubsubManager{
		ps,
		ctx,
		make(map[string]*pubsub.Subscription),
		make(map[string]*pubsub.Topic),
		nil,
		nil,
	}, nil
}

func (g *PubsubManager) SetQuaiBackend(consensus quai.ConsensusAPI) {
	g.consensus = consensus
}

func (g *PubsubManager) Start(receiveCb func(peer.ID, interface{}, common.Location)) {
	g.onReceived = receiveCb
}

// subscribe to broadcasts of the given type of data
func (g *PubsubManager) Subscribe(location common.Location, datatype interface{}) error {
	// build topic name
	topicName, err := TopicName(location, datatype, datatype)
	if err != nil {
		return err
	}

	// join the topic
	topic, err := g.Join(topicName)
	if err != nil {
		return err
	}
	g.topics[topicName] = topic
	g.PubSub.RegisterTopicValidator(topic.String(), g.consensus.ValidatorFunc())

	// subscribe to the topic
	subscription, err := topic.Subscribe()
	if err != nil {
		return err
	}
	g.subscriptions[topicName] = subscription

	go func(location common.Location, sub *pubsub.Subscription) {
		log.Global.Debugf("waiting for first message on subscription: %s", sub.Topic())
		for {
			msg, err := sub.Next(g.ctx)
			if err != nil {
				// if context was cancelled, then we are shutting down
				if g.ctx.Err() != nil {
					return
				}
				log.Global.Errorf("error getting next message from subscription: %s", err)
			}
			log.Global.Tracef("received message on topic: %s", topicName)

			var data interface{}
			// unmarshal the received data depending on the topic's type
			err = pb.UnmarshalAndConvert(msg.Data, location, &data, datatype)
			if err != nil {
				log.Global.Errorf("error unmarshalling data: %s", err)
				return
			}

			// handle the received data
			if g.onReceived != nil {
				g.onReceived(msg.ReceivedFrom, data, location)
			}
		}
	}(location, subscription)

	return nil
}

// broadcasts data to subscribing peers
func (g *PubsubManager) Broadcast(location common.Location, data interface{}, datatype interface{}) error {
	topicName, err := TopicName(location, data, datatype)
	if err != nil {
		return err
	}
	protoData, err := pb.ConvertAndMarshal(data, datatype)
	if err != nil {
		return err
	}
	return g.topics[topicName].Publish(g.ctx, protoData)
}
