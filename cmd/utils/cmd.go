package utils

import (
	"fmt"
	"github.com/dominant-strategies/go-quai/common"
	"github.com/dominant-strategies/go-quai/core/vm"
	"github.com/dominant-strategies/go-quai/internal/quaiapi"
	"github.com/dominant-strategies/go-quai/log"
	"github.com/dominant-strategies/go-quai/node"
	"github.com/dominant-strategies/go-quai/params"
	"github.com/dominant-strategies/go-quai/quai"
	"github.com/dominant-strategies/go-quai/quai/quaiconfig"
	"io"
	"os"
	"runtime"
	"time"
)

type quaiConfig struct {
	Quai quaiconfig.Config
	Node node.Config
}

// QuaiBackend implements the quai consensus protocol
type QuaiBackend struct {
	p2p interface{}
}

// Create a new instance of the QuaiBackend consensus service
func StartQuaiBackend() (*QuaiBackend, error) {

	// Make full node
	go func() {
		log.Info("Starting Prime")
		stackPrime, backendPrime := makeFullNode(nil)
		defer stackPrime.Close()
		log.Info("Calling Start Node in Prime")
		startNode(stackPrime, backendPrime)
		stackPrime.Wait()
	}()

	time.Sleep(2 * time.Second)

	go func() {
		log.Info("Starting Region")
		stackRegion, backendRegion := makeFullNode(common.Location{0})
		defer stackRegion.Close()
		log.Info("Calling Start Node in Region")
		startNode(stackRegion, backendRegion)
		stackRegion.Wait()
	}()

	time.Sleep(2 * time.Second)

	go func() {
		log.Info("Starting Zone")
		stackZone, backendZone := makeFullNode(common.Location{0, 0})
		defer stackZone.Close()
		log.Info("Calling Start Node in Zone")
		startNode(stackZone, backendZone)
		stackZone.Wait()
	}()

	return &QuaiBackend{}, nil
}

// startNode boots up the system node and all registered protocols, after which
// it unlocks any requested accounts, and starts the RPC interfaces and the
// miner.
func startNode(stack *node.Node, backend quaiapi.Backend) {
	// Start up the node itself
	StartNode(stack)
	// TODO: Maybe do some developer related stuff
}

func StartNode(stack *node.Node) {
	if err := stack.Start(); err != nil {
		Fatalf("Error starting protocol stack: %v", err)
	}
	// Stop the node if the memory pressure
}

// makeConfigNode loads quai configuration and creates a blank node instance.
func makeConfigNode(nodeLocation common.Location) (*node.Node, quaiConfig) {
	// Load defaults.
	cfg := quaiConfig{
		Quai: quaiconfig.Defaults,
		Node: defaultNodeConfig(),
	}

	// Apply flags.
	// set the node location
	log.Info("Node", "Location", nodeLocation)
	cfg.Node.NodeLocation = nodeLocation

	SetNodeConfig(&cfg.Node, nodeLocation)
	stack, err := node.New(&cfg.Node)
	if err != nil {
		Fatalf("Failed to create the protocol stack: %v", err)
	}
	SetQuaiConfig(stack, &cfg.Quai, nodeLocation)

	// TODO: Apply stats
	// TODO: Apply metric config

	nodeCtx := nodeLocation.Context()
	// Onlt initialize the precompile for the zone chain
	if nodeCtx == common.ZONE_CTX {
		vm.InitializePrecompiles(nodeLocation)
	}
	return stack, cfg
}

func defaultNodeConfig() node.Config {
	cfg := node.DefaultConfig
	cfg.Name = ""
	cfg.Version = params.VersionWithCommit("", "")
	cfg.HTTPModules = append(cfg.HTTPModules, "eth")
	cfg.WSModules = append(cfg.WSModules, "eth")
	return cfg
}

// makeFullNode loads quai configuration and creates the Quai backend.
func makeFullNode(nodeLocation common.Location) (*node.Node, quaiapi.Backend) {
	stack, cfg := makeConfigNode(nodeLocation)
	backend, _ := RegisterQuaiService(stack, &cfg.Quai, cfg.Node.NodeLocation.Context())
	// TODO: Start quai stats service
	return stack, backend
}

// RegisterQuaiService adds a Quai client to the stack.
// The second return value is the full node instance, which may be nil if the
// node is running as a light client.
func RegisterQuaiService(stack *node.Node, cfg *quaiconfig.Config, nodeCtx int) (quaiapi.Backend, *quai.Quai) {
	backend, err := quai.New(stack, cfg, nodeCtx)
	if err != nil {
		Fatalf("Failed to register the Quai service: %v", err)
	}
	return backend.APIBackend, backend
}

// Fatalf formats a message to standard error and exits the program.
// The message is also printed to standard output if standard error
// is redirected to a different file.
func Fatalf(format string, args ...interface{}) {
	w := io.MultiWriter(os.Stdout, os.Stderr)
	if runtime.GOOS == "windows" {
		// The SameFile check below doesn't work on Windows.
		// stdout is unlikely to get redirected though, so just print there.
		w = os.Stdout
	} else {
		outf, _ := os.Stdout.Stat()
		errf, _ := os.Stderr.Stat()
		if outf != nil && errf != nil && os.SameFile(outf, errf) {
			w = os.Stderr
		}
	}
	fmt.Fprintf(w, "Fatal: "+format+"\n", args...)
	os.Exit(1)
}
