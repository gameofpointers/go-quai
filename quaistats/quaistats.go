// Copyright 2016 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

// Package quaistats implements the network stats reporting service.
package quaistats

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
	"net/http"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/dgrijalva/jwt-go"

	lru "github.com/hashicorp/golang-lru"
	"github.com/shirou/gopsutil/cpu"
	"github.com/shirou/gopsutil/mem"

	"os/exec"

	"github.com/dominant-strategies/go-quai/common"
	"github.com/dominant-strategies/go-quai/consensus"
	"github.com/dominant-strategies/go-quai/core"
	"github.com/dominant-strategies/go-quai/core/types"
	"github.com/dominant-strategies/go-quai/eth/downloader"
	ethproto "github.com/dominant-strategies/go-quai/eth/protocols/eth"
	"github.com/dominant-strategies/go-quai/event"
	"github.com/dominant-strategies/go-quai/log"
	"github.com/dominant-strategies/go-quai/node"
	"github.com/dominant-strategies/go-quai/p2p"
	"github.com/dominant-strategies/go-quai/params"
	"github.com/dominant-strategies/go-quai/rpc"
	"github.com/gorilla/websocket"
)

const (
	// chainHeadChanSize is the size of channel listening to ChainHeadEvent.
	chainHeadChanSize = 10
	chainSideChanSize = 10

	// reportInterval is the time interval between two reports.
	reportInterval = 15

	c_alpha              = 8
	c_txBatchSize        = 20
	c_blocksPerMinute    = 5
	c_blocksPerHour      = c_blocksPerMinute * 60
	c_txLookupCacheLimit = c_blocksPerHour / c_txBatchSize
	c_statsErrorValue    = int64(-1)
)

// backend encompasses the bare-minimum functionality needed for quaistats reporting
type backend interface {
	SubscribeChainHeadEvent(ch chan<- core.ChainHeadEvent) event.Subscription
	SubscribeChainSideEvent(ch chan<- core.ChainSideEvent) event.Subscription
	SubscribeNewTxsEvent(ch chan<- core.NewTxsEvent) event.Subscription
	CurrentHeader() *types.Header
	TotalLogS(header *types.Header) *big.Int
	HeaderByNumber(ctx context.Context, number rpc.BlockNumber) (*types.Header, error)
	Stats() (pending int, queued int)
	Downloader() *downloader.Downloader
	ChainConfig() *params.ChainConfig
	ProcessingState() bool
}

// fullNodeBackend encompasses the functionality necessary for a full node
// reporting to quaistats
type fullNodeBackend interface {
	backend
	BlockByNumber(ctx context.Context, number rpc.BlockNumber) (*types.Block, error)
	CurrentBlock() *types.Block
}

// Service implements an Quai netstats reporting daemon that pushes local
// chain statistics up to a monitoring server.
type Service struct {
	server  *p2p.Server // Peer-to-peer server to retrieve networking infos
	backend backend
	engine  consensus.Engine // Consensus engine to retrieve variadic block fields

	node    string // Name of the node to display on the monitoring page
	pass    string // Password to authorize access to the monitoring page
	host    string // Remote address of the monitoring service
	trusted bool   // Whether the node is trusted or not

	pongCh  chan struct{} // Pong notifications are fed into this channel
	headSub event.Subscription
	sideSub event.Subscription

	txLookupCache *lru.Cache

	chainID *big.Int

	instanceDir string // Path to the node's instance directory
}

// connWrapper is a wrapper to prevent concurrent-write or concurrent-read on the
// websocket.
//
// From Gorilla websocket docs:
//
//	Connections support one concurrent reader and one concurrent writer.
//	Applications are responsible for ensuring that no more than one goroutine calls the write methods
//	  - NextWriter, SetWriteDeadline, WriteMessage, WriteJSON, EnableWriteCompression, SetCompressionLevel
//	concurrently and that no more than one goroutine calls the read methods
//	  - NextReader, SetReadDeadline, ReadMessage, ReadJSON, SetPongHandler, SetPingHandler
//	concurrently.
//	The Close and WriteControl methods can be called concurrently with all other methods.
type connWrapper struct {
	conn *websocket.Conn

	rlock sync.Mutex
	wlock sync.Mutex
}

func newConnectionWrapper(conn *websocket.Conn) *connWrapper {
	return &connWrapper{conn: conn}
}

// WriteJSON wraps corresponding method on the websocket but is safe for concurrent calling
func (w *connWrapper) WriteJSON(v interface{}) error {
	w.wlock.Lock()
	defer w.wlock.Unlock()

	return w.conn.WriteJSON(v)
}

// ReadJSON wraps corresponding method on the websocket but is safe for concurrent calling
func (w *connWrapper) ReadJSON(v interface{}) error {
	w.rlock.Lock()
	defer w.rlock.Unlock()

	return w.conn.ReadJSON(v)
}

// Close wraps corresponding method on the websocket but is safe for concurrent calling
func (w *connWrapper) Close() error {
	// The Close and WriteControl methods can be called concurrently with all other methods,
	// so the mutex is not used here
	return w.conn.Close()
}

// parseEthstatsURL parses the netstats connection url.
// URL argument should be of the form <nodename:secret@host:port>
// If non-erroring, the returned slice contains 3 elements: [nodename, pass, host]
func parseEthstatsURL(url string) (parts []string, err error) {
	err = fmt.Errorf("invalid netstats url: \"%s\", should be nodename:secret@host:port", url)

	hostIndex := strings.LastIndex(url, "@")
	if hostIndex == -1 || hostIndex == len(url)-1 {
		return nil, err
	}
	preHost, host := url[:hostIndex], url[hostIndex+1:]

	passIndex := strings.LastIndex(preHost, ":")
	if passIndex == -1 {
		return []string{preHost, "", host}, nil
	}
	nodename, pass := preHost[:passIndex], ""
	if passIndex != len(preHost)-1 {
		pass = preHost[passIndex+1:]
	}

	return []string{nodename, pass, host}, nil
}

// New returns a monitoring service ready for stats reporting.
func New(node *node.Node, backend backend, engine consensus.Engine, url string, trustednode bool) error {
	parts, err := parseEthstatsURL(url)
	if err != nil {
		return err
	}

	txLookupCache, _ := lru.New(c_txLookupCacheLimit)

	quaistats := &Service{
		backend:       backend,
		engine:        engine,
		server:        node.Server(),
		node:          parts[0],
		pass:          parts[1],
		host:          parts[2],
		pongCh:        make(chan struct{}),
		chainID:       backend.ChainConfig().ChainID,
		trusted:       trustednode,
		txLookupCache: txLookupCache,
		instanceDir:   node.InstanceDir(),
	}

	node.RegisterLifecycle(quaistats)
	return nil
}

// Start implements node.Lifecycle, starting up the monitoring and reporting daemon.
func (s *Service) Start() error {
	// Subscribe to chain events to execute updates on
	chainHeadCh := make(chan core.ChainHeadEvent, chainHeadChanSize)
	chainSideCh := make(chan core.ChainSideEvent, chainSideChanSize)

	s.headSub = s.backend.SubscribeChainHeadEvent(chainHeadCh)
	s.sideSub = s.backend.SubscribeChainSideEvent(chainSideCh)

	go s.loop(chainHeadCh, chainSideCh)

	log.Info("Stats daemon started")
	return nil
}

// Stop implements node.Lifecycle, terminating the monitoring and reporting daemon.
func (s *Service) Stop() error {
	s.headSub.Unsubscribe()
	s.sideSub.Unsubscribe()
	log.Info("Stats daemon stopped")
	return nil
}

// loop keeps trying to connect to the netstats server, reporting chain events
// until termination.
func (s *Service) loop(chainHeadCh chan core.ChainHeadEvent, chainSideCh chan core.ChainSideEvent) {
	// Start a goroutine that exhausts the subscriptions to avoid events piling up
	var (
		quitCh = make(chan struct{})
		headCh = make(chan *types.Block, 1)
		sideCh = make(chan *types.Block, 1)
	)
	go func() {
	HandleLoop:
		for {
			select {
			// Notify of chain head events, but drop if too frequent
			case head := <-chainHeadCh:
				select {
				case headCh <- head.Block:
				default:
				}
			// Notify of chain side events, but drop if too frequent
			case sideEvent := <-chainSideCh:
				select {
				case sideCh <- sideEvent.Block:
				default:
				}
			case <-s.headSub.Err():
				break HandleLoop
			}
		}
		close(quitCh)
	}()

	// Resolve the URL, defaulting to TLS, but falling back to none too
	paths := map[string]string{
		"internalBlockStats": fmt.Sprintf("%s/internalBlockStats", s.host),
		"blockAppendTime":    fmt.Sprintf("%s/blockAppendTime", s.host),
		"blockLocation":      fmt.Sprintf("%s/blockLocation", s.host),
		"nodeStats":          fmt.Sprintf("%s/nodeStats", s.host),
		"login":              fmt.Sprintf("%s/auth/login", s.host),
	}

	urlMap := make(map[string][]string)

	for key, path := range paths {
		// url.Parse and url.IsAbs is unsuitable (https://github.com/golang/go/issues/19779)
		if !strings.Contains(path, "://") {
			// Append both secure (wss) and non-secure (ws) URLs
			if key == "login" {
				urlMap[key] = []string{"http://" + path}
			} else {
				urlMap[key] = []string{"wss://" + path, "ws://" + path}
			}
		} else {
			urlMap[key] = []string{path}
		}
	}

	errTimer := time.NewTimer(0)
	defer errTimer.Stop()
	var authJwt = ""
	// Loop reporting until termination
	for {
		select {
		case <-quitCh:
			return
		case <-errTimer.C:
			// If we don't have a JWT or it's expired, get a new one

			isJwtExpiredResult, jwtIsExpiredErr := s.isJwtExpired(authJwt)
			if authJwt == "" || isJwtExpiredResult || jwtIsExpiredErr != nil {
				var err error
				authJwt, err = s.login2(urlMap["login"][0])
				if err != nil {
					log.Warn("Stats login failed", "err", err)
					errTimer.Reset(10 * time.Second)
					continue
				}
			}
			// Establish a websocket connection to the server on any supported URL
			dialer := websocket.Dialer{HandshakeTimeout: 5 * time.Second}
			header := make(http.Header)
			header.Set("origin", "http://localhost")
			header.Set("sec-websocket-protocol", authJwt)

			conns := make(map[string]*connWrapper)
			errs := make(map[string]error)

			for key, urls := range urlMap {
				if key == "login" {
					continue
				}
				for _, url := range urls {
					c, _, e := dialer.Dial(url, header)
					err := e
					if err == nil {
						conns[key] = newConnectionWrapper(c)
						break
					}
					if err != nil {
						log.Warn(key+" stats server unreachable", "err", err)
						errs[key] = err
						errTimer.Reset(10 * time.Second)
						continue
					}
					go s.readLoop(conns[key])
				}
			}

			// Authenticate the client with the server
			for key, conn := range conns {
				if errs[key] = s.report(key, conn); errs[key] != nil {
					log.Warn("Initial stats report failed", "err", errs[key])
					conn.Close()
					errTimer.Reset(0)
					continue
				}

			}

			// Keep sending status updates until the connection breaks
			fullReport := time.NewTicker(reportInterval * time.Second)

			var noErrs = true
			for noErrs {
				var err error
				select {
				case <-quitCh:
					fullReport.Stop()
					// Make sure the connection is closed
					for _, conn := range conns {
						conn.Close()
					}

					return

				case <-fullReport.C:
					if err = s.report("nodeStats", conns["nodeStats"]); err != nil {
						noErrs = false
						log.Warn("nodeStats full stats report failed", "err", err)
					}
				case head := <-headCh:
					// Report blockLocation every block if node is trusted
					if s.trusted {
						if err = s.reportBlockLocation(conns["blockLocation"], head); err != nil {
							noErrs = false
							log.Warn("Block location report failed", "err", err)
						}
					}

					// Every node reports appendtime each block
					if err = s.reportBlockAppendTime(conns["blockAppendTime"], head); err != nil {
						noErrs = false
						log.Warn("Block append time report failed", "err", err)
					}

					// Report internal blockstats every 20 block stats if trusted node
					if head.NumberU64()%c_txBatchSize == 0 && s.trusted {
						if err = s.reportInternalBlockStats(conns["internalBlockStats"], head); err != nil {
							noErrs = false
							log.Warn("Block internal stats report failed", "err", err)
						}
					}
				case sideEvent := <-sideCh:
					if err = s.reportSideBlock(conns["block"], sideEvent); err != nil {
						noErrs = false
						log.Warn("Block stats report failed", "err", err)
					}
				}
			}
			fullReport.Stop()
			// Close the current connection and establish a new one
			for _, conn := range conns {
				conn.Close()
			}

			errTimer.Reset(0)
		}
	}
}

// readLoop loops as long as the connection is alive and retrieves data packets
// from the network socket. If any of them match an active request, it forwards
// it, if they themselves are requests it initiates a reply, and lastly it drops
// unknown packets.
func (s *Service) readLoop(conn *connWrapper) {
	// If the read loop exits, close the connection
	defer conn.Close()

	for {
		// Retrieve the next generic network packet and bail out on error
		var blob json.RawMessage
		if err := conn.ReadJSON(&blob); err != nil {
			log.Warn("Failed to retrieve stats server message", "err", err)
			return
		}
		// If the network packet is a system ping, respond to it directly
		var ping string
		if err := json.Unmarshal(blob, &ping); err == nil && strings.HasPrefix(ping, "primus::ping::") {
			if err := conn.WriteJSON(strings.Replace(ping, "ping", "pong", -1)); err != nil {
				log.Warn("Failed to respond to system ping message", "err", err)
				return
			}
			continue
		}
		// Not a system ping, try to decode an actual state message
		var msg map[string][]interface{}
		if err := json.Unmarshal(blob, &msg); err != nil {
			log.Warn("Failed to decode stats server message", "err", err)
			return
		}
		log.Trace("Received message from stats server", "msg", msg)
		if len(msg["emit"]) == 0 {
			log.Warn("Stats server sent non-broadcast", "msg", msg)
			return
		}
		command, ok := msg["emit"][0].(string)
		if !ok {
			log.Warn("Invalid stats server message type", "type", msg["emit"][0])
			return
		}
		// If the message is a ping reply, deliver (someone must be listening!)
		if len(msg["emit"]) == 2 && command == "node-pong" {
			select {
			case s.pongCh <- struct{}{}:
				// Pong delivered, continue listening
				continue
			default:
				// Ping routine dead, abort
				log.Warn("Stats server pinger seems to have died")
				return
			}
		}
		// Report anything else and continue
		log.Info("Unknown stats message", "msg", msg)
	}
}

// nodeInfo is the collection of meta information about a node that is displayed
// on the monitoring page.
type nodeInfo struct {
	Name     string `json:"name"`
	Node     string `json:"node"`
	Port     int    `json:"port"`
	Network  string `json:"net"`
	Protocol string `json:"protocol"`
	API      string `json:"api"`
	Os       string `json:"os"`
	OsVer    string `json:"os_v"`
	Client   string `json:"client"`
	History  bool   `json:"canUpdateHistory"`
	Chain    string `json:"chain"`
	ChainID  uint64 `json:"chainId"`
}

// authMsg is the authentication infos needed to login to a monitoring server.
type authMsg struct {
	ID     string      `json:"id"`
	Info   nodeInfo    `json:"info"`
	Secret loginSecret `json:"secret"`
}

type loginSecret struct {
	Name     string `json:"name"`
	Password string `json:"password"`
}

type Credentials struct {
	Name     string `json:"name"`
	Password string `json:"password"`
}

type AuthResponse struct {
	Success bool   `json:"success"`
	Token   string `json:"token"`
}

func (s *Service) login2(url string) (string, error) {
	// Substitute with your actual service address and port

	infos := s.server.NodeInfo()

	var protocols []string
	for _, proto := range s.server.Protocols {
		protocols = append(protocols, fmt.Sprintf("%s/%d", proto.Name, proto.Version))
	}
	var network string
	if info := infos.Protocols["eth"]; info != nil {
		network = fmt.Sprintf("%d", info.(*ethproto.NodeInfo).Network)
	}

	auth := &authMsg{
		ID: s.node,
		Info: nodeInfo{
			Name:     s.node,
			Node:     infos.Name,
			Port:     infos.Ports.Listener,
			Network:  network,
			Protocol: strings.Join(protocols, ", "),
			API:      "No",
			Os:       runtime.GOOS,
			OsVer:    runtime.GOARCH,
			Client:   "0.1.1",
			History:  true,
			Chain:    common.NodeLocation.Name(),
			ChainID:  s.chainID.Uint64(),
		},
		Secret: loginSecret{
			Name:     "admin",
			Password: s.pass,
		},
	}

	authJson, err := json.Marshal(auth)
	if err != nil {
		return "", err
	}

	resp, err := http.Post(url, "application/json", bytes.NewBuffer(authJson))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)

	var authResponse AuthResponse
	err = json.Unmarshal(body, &authResponse)
	if err != nil {
		return "", err
	}

	if authResponse.Success {
		return authResponse.Token, nil
	}

	return "", fmt.Errorf("login failed")
}

// isJwtExpired checks if the JWT token is expired
func (s *Service) isJwtExpired(authJwt string) (bool, error) {
	if authJwt == "" {
		return false, errors.New("token is nil")
	}

	parts := strings.Split(authJwt, ".")
	if len(parts) != 3 {
		return false, errors.New("invalid token")
	}

	claims := jwt.MapClaims{}
	_, _, err := new(jwt.Parser).ParseUnverified(authJwt, claims)
	if err != nil {
		return false, err
	}

	if exp, ok := claims["exp"].(float64); ok {
		return time.Now().Unix() >= int64(exp), nil
	}

	return false, errors.New("exp claim not found in token")
}

// report collects all possible data to report and send it to the stats server.
// This should only be used on reconnects or rarely to avoid overloading the
// server. Use the individual methods for reporting subscribed events.
func (s *Service) report(dataType string, conn *connWrapper) error {
	if conn == nil || conn.conn == nil {
		log.Warn(dataType + " connection is nil")
		return errors.New(dataType + " connection is nil")
	}

	switch dataType {
	case "nodeStats":
		if err := s.reportNodeStats(conn); err != nil {
			return err
		}
	default:
		return nil
	}
	return nil
}

// reportSideBlock retrieves the current chain side event and reports it to the stats server.
func (s *Service) reportSideBlock(conn *connWrapper, block *types.Block) error {
	log.Trace("Sending new side block to quaistats", "number", block.Number(), "hash", block.Hash())
	if conn == nil || conn.conn == nil {
		log.Warn("block connection is nil")
		return errors.New("block connection is nil")
	}

	stats := map[string]interface{}{
		"id":        s.node,
		"sideBlock": block,
	}
	report := map[string][]interface{}{
		"emit": {"sideBlock", stats},
	}
	return conn.WriteJSON(report)
}

// reportBlock retrieves the current chain head and reports it to the stats server.
func (s *Service) reportInternalBlockStats(conn *connWrapper, block *types.Block) error {
	// Gather the block details from the header or block chain
	details := s.assembleInternalBlockStats(block)

	// Assemble the block report and send it to the server
	log.Trace("Sending internal block stats to quaistats", "timestamp", details.Timestamp)

	if conn == nil || conn.conn == nil {
		log.Warn("internal block stats connection is nil")
		return errors.New("internal block stats connection is nil")
	}

	stats := map[string]interface{}{
		"id":                 s.node,
		"internalBlockStats": details,
	}
	report := map[string][]interface{}{
		"emit": {"internalBlockStats", stats},
	}
	return conn.WriteJSON(report)
}

// reportBlock retrieves the current chain head and reports it to the stats server.
func (s *Service) reportBlockAppendTime(conn *connWrapper, block *types.Block) error {
	// Gather the block details from the header or block chain
	details := s.assembleBlockAppendTimeStats(block)

	// Assemble the block report and send it to the server
	log.Trace("Sending internal block stats to quaistats", "number", details.BlockNumber)

	if conn == nil || conn.conn == nil {
		log.Warn("block append time connection is nil")
		return errors.New("block append time connection is nil")
	}

	stats := map[string]interface{}{
		"id":              s.node,
		"blockAppendTime": details,
	}
	report := map[string][]interface{}{
		"emit": {"blockAppendTime", stats},
	}
	return conn.WriteJSON(report)
}

// reportBlock retrieves the current chain head and reports it to the stats server.
func (s *Service) reportBlockLocation(conn *connWrapper, block *types.Block) error {
	// Gather the block details from the header or block chain
	details := s.assembleBlockLocationStats(block)

	// Assemble the block report and send it to the server
	log.Trace("Sending internal block stats to quaistats", "time", details.Timestamp, "zoneHeight", details.ZoneHeight, "chain", details.Chain, "entropy", details.Entropy)

	if conn == nil || conn.conn == nil {
		log.Warn("block location connection is nil")
		return errors.New("block location connection is nil")
	}

	stats := map[string]interface{}{
		"id":            s.node,
		"blockLocation": details,
	}
	report := map[string][]interface{}{
		"emit": {"blockLocation", stats},
	}
	return conn.WriteJSON(report)
}

// Trusted Only
type internalBlockStats struct {
	Timestamp             *big.Int `json:"timestamp"`
	TotalNoTransactions1h uint64   `json:"totalNoTransactions1h"`
	TotalNoTransactions1m uint64   `json:"totalNoTransactions1m"`
	Chain                 string   `json:"chain"`
	Difficulty            string   `json:"difficulty"`
}

// Trusted Only
type blockLocation struct {
	Timestamp    *big.Int `json:"timestamp"`
	ZoneHeight   uint64   `json:"zoneHeight"`
	RegionHeight uint64   `json:"regionHeight"`
	PrimeHeight  uint64   `json:"primeHeight"`
	Chain        string   `json:"chain"`
	Entropy      string   `json:"entropy"`
}

// Everyone sends every block
type blockAppendTime struct {
	AppendTime  time.Duration `json:"appendTime"`
	BlockNumber *big.Int      `json:"number"`
	Chain       string        `json:"chain"`
}

type nodeStats struct {
	Name                string     `json:"name"`
	Timestamp           *big.Int   `json:"timestamp"`
	RAMUsage            int64      `json:"ramUsage"`
	RAMUsagePercent     int64      `json:"ramUsagePercent"`
	RAMFreePercent      int64      `json:"ramFreePercent"`
	RAMAvailablePercent int64      `json:"ramAvailablePercent"`
	CPUUsagePercent     int64      `json:"cpuPercent"`
	DiskUsagePercent    int64      `json:"diskUsagePercent"`
	DiskUsageValue      int64      `json:"diskUsageValue"`
	CurrentBlockNumber  []*big.Int `json:"currentBlockNumber"`
	RegionLocation      int        `json:"regionLocation"`
	ZoneLocation        int        `json:"zoneLocation"`
}

type totalTransactions struct {
	TotalNoTransactions1h uint64
	TotalNoTransactions1m uint64
}

func (s *Service) evictOutdatedEntries(currentMaxBlock uint64) {
	minAcceptableBlock := currentMaxBlock - c_blocksPerHour
	for key := minAcceptableBlock - 20; key >= minAcceptableBlock-c_blocksPerHour; key -= 20 {
		// Check if the key exists before trying to delete
		if _, found := s.txLookupCache.Get(key); found {
			s.txLookupCache.Remove(key)
		} else {
			return
		}
	}
}

func (s *Service) calculateTotalNoTransactions(block *types.Block) *totalTransactions {
	var totalTransactions1h uint64
	var totalTransactions1m uint64

	currentBlock := block
	batchesNeeded := c_blocksPerHour / c_txBatchSize // calculate how many batches of c_txBatchSize are needed

	for i := 0; i < batchesNeeded; i++ {
		startBlockNum := currentBlock.NumberU64() - uint64(i*c_txBatchSize)

		// Try to get the data from the LRU cache
		cachedTxCount, ok := s.txLookupCache.Get(startBlockNum)
		if !ok {
			// Not in cache, so we need to calculate the transaction count for this batch
			txCount := uint64(0)

			for j := 0; j < c_txBatchSize; j++ {
				if currentBlock == nil {
					log.Error("Encountered a nil block, stopping iteration")
					break
				}

				// Add the number of transactions in the current block to the total
				txCount += uint64(len(currentBlock.Transactions()))

				// If within the last 5 blocks, add to the 1-minute total
				if i == 0 && j < c_blocksPerMinute {
					totalTransactions1m += uint64(len(currentBlock.Transactions()))
				}

				// Get the parent block for the next iteration
				fullBackend, ok := s.backend.(fullNodeBackend)
				if !ok {
					log.Error("Not running fullnode, cannot get parent block")
					break
				}

				var err error
				var currentNumber = currentBlock.NumberU64()
				currentBlock, err = fullBackend.BlockByNumber(context.Background(), rpc.BlockNumber(currentNumber-1))
				if err != nil {
					log.Error(fmt.Sprintf("Error getting block number %d: %s", currentNumber-1, err.Error()))
					break
				}
				if currentBlock == nil {
					log.Error(fmt.Sprintf("No block found at number %d", currentNumber-1))
					break
				}
			}

			// Store the sum in the cache
			s.txLookupCache.Add(startBlockNum, txCount)

			cachedTxCount = txCount
		}

		// Add the transactions from this batch
		txCount, ok := cachedTxCount.(uint64)
		if !ok {
			log.Error("Error casting cachedTxCount to uint64")
			break
		}
		totalTransactions1h += txCount
	}

	if s.txLookupCache.Len() > c_txLookupCacheLimit {
		s.evictOutdatedEntries(block.NumberU64())
	}

	// Now totalTransactions1h and totalTransactions1m have the transaction counts for the last c_blocksPerHour and c_txBatchSize blocks respectively
	return &totalTransactions{
		TotalNoTransactions1h: totalTransactions1h,
		TotalNoTransactions1m: totalTransactions1m,
	}
}

func (s *Service) assembleBlockLocationStats(block *types.Block) *blockLocation {
	header := block.Header()
	location := header.NumberArray()
	primeHeight := location[0]
	regionHeight := location[1]
	zoneHeight := location[2]

	// Assemble and return the block stats
	return &blockLocation{
		Timestamp:    new(big.Int).SetUint64(header.Time()),
		ZoneHeight:   zoneHeight.Uint64(),
		RegionHeight: regionHeight.Uint64(),
		PrimeHeight:  primeHeight.Uint64(),
		Chain:        common.NodeLocation.Name(),
		Entropy:      s.backend.TotalLogS(block.Header()).String(),
	}
}

func (s *Service) assembleBlockAppendTimeStats(block *types.Block) *blockAppendTime {
	header := block.Header()
	appendTime := block.GetAppendTime()

	log.Info("Raw Block Append Time", "appendTime", appendTime.Microseconds())

	// Assemble and return the block stats
	return &blockAppendTime{
		AppendTime:  appendTime,
		BlockNumber: header.Number(),
		Chain:       common.NodeLocation.Name(),
	}
}

func (s *Service) assembleInternalBlockStats(block *types.Block) *internalBlockStats {
	header := block.Header()
	totalTransactions := s.calculateTotalNoTransactions(block)

	// Assemble and return the block stats
	return &internalBlockStats{
		Timestamp:             new(big.Int).SetUint64(header.Time()),
		TotalNoTransactions1h: totalTransactions.TotalNoTransactions1h,
		TotalNoTransactions1m: totalTransactions.TotalNoTransactions1m,
		Chain:                 common.NodeLocation.Name(),
		Difficulty:            header.Difficulty().String(),
	}
}

// reportNodeStats retrieves various stats about the node at the networking and
// mining layer and reports it to the stats server.
func (s *Service) reportNodeStats(conn *connWrapper) error {
	// Get RAM usage
	var ramUsagePercent, ramFreePercent, ramAvailablePercent, ramUsage float64
	if vmStat, err := mem.VirtualMemory(); err == nil {
		ramUsagePercent = float64(vmStat.UsedPercent)
		ramFreePercent = float64(vmStat.Free) / float64(vmStat.Total) * 100
		ramAvailablePercent = float64(vmStat.Available) / float64(vmStat.Total) * 100
		ramUsage = float64(vmStat.Used)
	} else {
		log.Warn("Error getting RAM usage:", err)
		// Handle error, possibly with default values or by returning an error
	}

	// Get CPU usage
	var cpuUsagePercent float64
	if cpuStat, err := cpu.Percent(0, false); err == nil {
		cpuUsagePercent = float64(cpuStat[0])
	} else {
		log.Warn("Error getting CPU percent usage:", err)
		// Handle error
	}

	// Get disk usage (as a percentage)
	diskUsage, err := dirSize(s.instanceDir)
	if err != nil {
		log.Warn("Error calculating directory sizes:", err)
		diskUsage = c_statsErrorValue
	}

	diskSize, err := diskTotalSize()
	if err != nil {
		log.Warn("Error calculating disk size:", err)
		diskUsage = c_statsErrorValue
	}

	diskUsagePercent := float64(diskUsage) / float64(diskSize) * 100

	// Get current block number
	currentBlockHeight := s.backend.CurrentHeader().NumberArray()

	// Get location
	location := s.backend.CurrentHeader().Location()

	// Assemble the new node stats
	log.Trace("Sending node details to quaistats")

	stats := map[string]interface{}{
		"id": s.node,
		"stats": &nodeStats{
			Name:                s.node,
			Timestamp:           big.NewInt(time.Now().Unix()), // Current timestamp
			RAMUsage:            int64(ramUsage),
			RAMUsagePercent:     int64(ramUsagePercent),
			RAMFreePercent:      int64(ramFreePercent),
			RAMAvailablePercent: int64(ramAvailablePercent),
			CPUUsagePercent:     int64(cpuUsagePercent),
			DiskUsageValue:      int64(diskUsage),
			DiskUsagePercent:    int64(diskUsagePercent),
			CurrentBlockNumber:  currentBlockHeight,
			RegionLocation:      location.Region(),
			ZoneLocation:        location.Zone(),
		},
	}

	report := map[string][]interface{}{
		"emit": {"stats", stats},
	}
	return conn.WriteJSON(report)
}

// dirSize returns the size of a directory in bytes.
func dirSize(path string) (int64, error) {
	var cmd *exec.Cmd
	if runtime.GOOS == "darwin" {
		cmd = exec.Command("du", "-sk", path)
	} else if runtime.GOOS == "linux" {
		cmd = exec.Command("du", "-bs", path)
	} else {
		return -1, errors.New("unsupported OS")
	}
	// Execute command
	output, err := cmd.Output()
	if err != nil {
		return -1, err
	}

	// Split the output and parse the size.
	sizeStr := strings.Split(string(output), "\t")[0]
	size, err := strconv.ParseInt(sizeStr, 10, 64)
	if err != nil {
		return -1, err
	}

	// If on macOS, convert size from kilobytes to bytes.
	if runtime.GOOS == "darwin" {
		size *= 1024
	}

	return size, nil
}

// diskTotalSize returns the total size of the disk in bytes.
func diskTotalSize() (int64, error) {
	var cmd *exec.Cmd
	if runtime.GOOS == "darwin" {
		cmd = exec.Command("df", "-k", "/")
	} else if runtime.GOOS == "linux" {
		cmd = exec.Command("df", "--block-size=1K", "/")
	} else {
		return 0, errors.New("unsupported OS")
	}

	output, err := cmd.Output()
	if err != nil {
		return 0, err
	}

	lines := strings.Split(string(output), "\n")
	if len(lines) < 2 {
		return 0, errors.New("unexpected output from df command")
	}

	fields := strings.Fields(lines[1])
	if len(fields) < 2 {
		return 0, errors.New("unexpected output from df command")
	}

	totalSize, err := strconv.ParseInt(fields[1], 10, 64)
	if err != nil {
		return 0, err
	}

	return totalSize * 1024, nil // convert from kilobytes to bytes
}
