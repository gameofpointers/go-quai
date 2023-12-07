package node

import (
	"time"

	"github.com/pkg/errors"
	"github.com/spf13/viper"

	"github.com/dominant-strategies/go-quai/cmd/utils"
	"github.com/dominant-strategies/go-quai/consensus"
	"github.com/dominant-strategies/go-quai/consensus/types"
	"github.com/dominant-strategies/go-quai/log"
	"github.com/dominant-strategies/go-quai/p2p"
	quaiprotocol "github.com/dominant-strategies/go-quai/p2p/protocol"
)

// Api defines an interface which can be used to interact with the node
type Api interface {
	// Start the node
	Start() error

	// Stop the node
	Stop() error

	// Methods to broadcast data to the network
	BroadcastBlock(block types.Block) error
	BroadcastTransaction(tx types.Transaction) error

	// Methods to lookup specific data from the network. Each request method
	// returns a result channel. If the result is found, it will be put into the
	// channel. If the result is not found, the channel will be closed.
	RequestBlock(hash types.Hash, loc types.Location) chan types.Block
	RequestTransaction(hash types.Hash, loc types.Location) chan types.Transaction

	// Method to report a peer to the P2PClient as behaving maliciously
	ReportBadPeer(peer p2p.PeerID)
}

// Starts the node and all of its services
func (p *P2PNode) Start() error {
	log.Infof("starting P2P node...")

	// Is this node expected to have bootstrap peers to dial?
	if !viper.GetBool(utils.BootNodeFlag.Name) && len(p.bootpeers) == 0 {
		log.Warnf("no bootpeers provided. Unable to join network.")
	}

	// Start any async processes belonging to this node
	log.Debugf("starting node processes...")
	go p.eventLoop()
	go p.statsLoop()

	// Register the Quai protocol handler
	p.SetStreamHandler(quaiprotocol.ProtocolVersion, quaiprotocol.QuaiProtocolHandler)

	// Bootstrap the node
	if err := p.bootstrap(); err != nil {
		log.Warnf("error bootstrapping the node: %s", err)
	}
	return nil
}

type stopFunc func() error

// Function to gracefully shtudown all running services
func (p *P2PNode) Stop() error {
	// define a list of functions to stop the services the node is running
	stopFuncs := []stopFunc{
		p.Host.Close,
		p.dht.Close,
	}
	// create a channel to collect errors
	errs := make(chan error, len(stopFuncs))
	// run each stop function in a goroutine
	for _, fn := range stopFuncs {
		go func(fn stopFunc) {
			errs <- fn()
		}(fn)
	}

	var allErrors []error
	for i := 0; i < len(stopFuncs); i++ {
		select {
		case err := <-errs:
			if err != nil {
				log.Errorf("error during shutdown: %s", err)
				allErrors = append(allErrors, err)
			}
		case <-time.After(5 * time.Second):
			err := errors.New("timeout during shutdown")
			log.Warnf("error: %s", err)
			allErrors = append(allErrors, err)
		}
	}
	close(errs)
	if len(allErrors) > 0 {
		return errors.Errorf("errors during shutdown: %v", allErrors)
	} else {
		return nil
	}
}

func (p *P2PNode) SetConsensusBackend(be consensus.ConsensusBackend) {
	p.consensus = be
}

func (p *P2PNode) BroadcastBlock(block types.Block) error {
	panic("todo")
}

func (p *P2PNode) BroadcastTransaction(tx types.Transaction) error {
	panic("todo")
}

func (p *P2PNode) RequestBlock(hash types.Hash, loc types.Location) chan types.Block {
	panic("todo")
}

func (p *P2PNode) RequestTransaction(hash types.Hash, loc types.Location) chan types.Transaction {
	panic("todo")
}

func (p *P2PNode) ReportBadPeer(peer p2p.PeerID) {
	panic("todo")
}
