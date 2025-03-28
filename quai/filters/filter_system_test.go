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

package filters

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"math/rand"
	"reflect"
	"testing"
	"time"

	quai "github.com/dominant-strategies/go-quai"
	"github.com/dominant-strategies/go-quai/common"
	"github.com/dominant-strategies/go-quai/core"
	"github.com/dominant-strategies/go-quai/core/bloombits"
	"github.com/dominant-strategies/go-quai/core/rawdb"
	"github.com/dominant-strategies/go-quai/core/types"
	"github.com/dominant-strategies/go-quai/ethdb"
	"github.com/dominant-strategies/go-quai/event"
	"github.com/dominant-strategies/go-quai/log"
	"github.com/dominant-strategies/go-quai/params"
	"github.com/dominant-strategies/go-quai/rpc"
)

var (
	deadline = 5 * time.Minute
)

type testBackend struct {
	mux               *event.TypeMux
	db                ethdb.Database
	sections          uint64
	txFeed            event.Feed
	logsFeed          event.Feed
	rmLogsFeed        event.Feed
	pendingLogsFeed   event.Feed
	chainFeed         event.Feed
	chainHeadFeed     event.Feed
	pendingHeaderFeed event.Feed
	unlocksFeed       event.Feed
}

func (b *testBackend) ChainDb() ethdb.Database {
	return b.db
}

func (b *testBackend) GetBlock(hash common.Hash, number uint64) (*types.WorkObject, error) {
	return rawdb.ReadWorkObject(b.db, number, hash, types.WorkObjectView(0)), nil
}

func (b *testBackend) HeaderByNumber(ctx context.Context, blockNr rpc.BlockNumber) (*types.WorkObject, error) {
	var (
		hash common.Hash
		num  uint64
	)
	if blockNr == rpc.LatestBlockNumber {
		hash = rawdb.ReadHeadBlockHash(b.db)
		number := rawdb.ReadHeaderNumber(b.db, hash)
		if number == nil {
			return nil, nil
		}
		num = *number
	} else {
		num = uint64(blockNr)
		hash = rawdb.ReadCanonicalHash(b.db, num)
	}
	return rawdb.ReadHeader(b.db, num, hash), nil
}

func (b *testBackend) HeaderByHash(ctx context.Context, hash common.Hash) (*types.WorkObject, error) {
	number := rawdb.ReadHeaderNumber(b.db, hash)
	if number == nil {
		return nil, errors.New("could not read the header number")
	}
	return rawdb.ReadHeader(b.db, *number, hash), nil
}

func (b *testBackend) GetReceipts(ctx context.Context, hash common.Hash) (types.Receipts, error) {
	if number := rawdb.ReadHeaderNumber(b.db, hash); number != nil {
		return rawdb.ReadReceipts(b.db, hash, *number, params.TestChainConfig), nil
	}
	return nil, nil
}

func (b *testBackend) GetLogs(ctx context.Context, hash common.Hash) ([][]*types.Log, error) {
	number := rawdb.ReadHeaderNumber(b.db, hash)
	if number == nil {
		return nil, nil
	}
	receipts := rawdb.ReadReceipts(b.db, hash, *number, params.TestChainConfig)

	logs := make([][]*types.Log, len(receipts))
	for i, receipt := range receipts {
		logs[i] = receipt.Logs
	}
	return logs, nil
}

func (b *testBackend) SubscribeRemovedLogsEvent(ch chan<- core.RemovedLogsEvent) event.Subscription {
	return b.rmLogsFeed.Subscribe(ch)
}

func (b *testBackend) SubscribeLogsEvent(ch chan<- []*types.Log) event.Subscription {
	return b.logsFeed.Subscribe(ch)
}

func (b *testBackend) SubscribePendingLogsEvent(ch chan<- []*types.Log) event.Subscription {
	return b.pendingLogsFeed.Subscribe(ch)
}

func (b *testBackend) SubscribeChainEvent(ch chan<- core.ChainEvent) event.Subscription {
	return b.chainFeed.Subscribe(ch)
}

func (b *testBackend) SubscribeChainHeadEvent(ch chan<- core.ChainHeadEvent) event.Subscription {
	return b.chainHeadFeed.Subscribe(ch)
}

func (b *testBackend) BloomStatus() (uint64, uint64) {
	return params.BloomBitsBlocks, b.sections
}

func (b *testBackend) ServiceFilter(ctx context.Context, session *bloombits.MatcherSession) {
	requests := make(chan chan *bloombits.Retrieval)

	go session.Multiplex(16, 0, requests)
	go func() {
		for {
			// Wait for a service request or a shutdown
			select {
			case <-ctx.Done():
				return

			case request := <-requests:
				task := <-request

				task.Bitsets = make([][]byte, len(task.Sections))
				for i, section := range task.Sections {
					if rand.Int()%4 != 0 { // Handle occasional missing deliveries
						head := rawdb.ReadCanonicalHash(b.db, (section+1)*params.BloomBitsBlocks-1)
						task.Bitsets[i], _ = rawdb.ReadBloomBits(b.db, task.Bit, section, head)
					}
				}
				request <- task
			}
		}
	}()
}

func (b *testBackend) GetBloom(blockHash common.Hash) (*types.Bloom, error) {
	return rawdb.ReadBloom(b.db, blockHash), nil
}

func (b *testBackend) Logger() *log.Logger {
	return log.Global
}

func (b *testBackend) NodeCtx() int {
	return common.ZONE_CTX
}

func (b *testBackend) NodeLocation() common.Location {
	return common.Location{0, 0}
}

func (b *testBackend) ProcessingState() bool {
	return true
}

func (b *testBackend) SubscribePendingHeaderEvent(ch chan<- *types.WorkObject) event.Subscription {
	return b.pendingHeaderFeed.Subscribe(ch)
}

func (b *testBackend) SubscribeUnlocksEvent(ch chan<- core.UnlocksEvent) event.Subscription {
	return b.unlocksFeed.Subscribe(ch)
}

// TestPendingTxFilter tests whether pending tx filters retrieve all pending transactions that are posted to the event mux.
func TestPendingTxFilter(t *testing.T) {
	t.Skip("Todo: Fix broken test")
	t.Parallel()
	var (
		db      = rawdb.NewMemoryDatabase(log.Global)
		backend = &testBackend{db: db}
		api     = NewPublicFilterAPI(backend, deadline, 1)

		to = common.HexToAddress("0x0094f5ea0ba39494ce83a213fffba74279579268", common.Location{0, 0})

		transactions = []*types.Transaction{
			types.NewTx(&types.QuaiTx{
				ChainID:    new(big.Int).SetUint64(1),
				Nonce:      uint64(0),
				GasPrice:   new(big.Int).SetUint64(0),
				Gas:        uint64(0),
				To:         &to,
				Value:      new(big.Int).SetUint64(0),
				Data:       []byte{0x04},
				AccessList: types.AccessList{},
				V:          new(big.Int).SetUint64(0),
				R:          new(big.Int).SetUint64(0),
				S:          new(big.Int).SetUint64(0),
			}),
			types.NewTx(&types.QuaiTx{
				ChainID:    new(big.Int).SetUint64(1),
				Nonce:      uint64(1),
				GasPrice:   new(big.Int).SetUint64(0),
				Gas:        uint64(0),
				To:         &to,
				Value:      new(big.Int).SetUint64(0),
				Data:       []byte{0x04},
				AccessList: types.AccessList{},
				V:          new(big.Int).SetUint64(0),
				R:          new(big.Int).SetUint64(0),
				S:          new(big.Int).SetUint64(0),
			}),
			types.NewTx(&types.QuaiTx{
				ChainID:    new(big.Int).SetUint64(1),
				Nonce:      uint64(2),
				GasPrice:   new(big.Int).SetUint64(0),
				Gas:        uint64(0),
				To:         &to,
				Value:      new(big.Int).SetUint64(0),
				Data:       []byte{0x04},
				AccessList: types.AccessList{},
				V:          new(big.Int).SetUint64(0),
				R:          new(big.Int).SetUint64(0),
				S:          new(big.Int).SetUint64(0),
			}),
			types.NewTx(&types.QuaiTx{
				ChainID:    new(big.Int).SetUint64(1),
				Nonce:      uint64(3),
				GasPrice:   new(big.Int).SetUint64(0),
				Gas:        uint64(0),
				To:         &to,
				Value:      new(big.Int).SetUint64(0),
				Data:       []byte{0x04},
				AccessList: types.AccessList{},
				V:          new(big.Int).SetUint64(0),
				R:          new(big.Int).SetUint64(0),
				S:          new(big.Int).SetUint64(0),
			}),
			types.NewTx(&types.QuaiTx{
				ChainID:    new(big.Int).SetUint64(1),
				Nonce:      uint64(4),
				GasPrice:   new(big.Int).SetUint64(0),
				Gas:        uint64(0),
				To:         &to,
				Value:      new(big.Int).SetUint64(0),
				Data:       []byte{0x04},
				AccessList: types.AccessList{},
				V:          new(big.Int).SetUint64(0),
				R:          new(big.Int).SetUint64(0),
				S:          new(big.Int).SetUint64(0),
			}),
		}

		hashes []common.Hash
	)

	fid0 := api.NewPendingTransactionFilter()

	time.Sleep(1 * time.Second)
	backend.txFeed.Send(core.NewTxsEvent{Txs: transactions})

	timeout := time.Now().Add(1 * time.Second)
	for {
		results, err := api.GetFilterChanges(fid0)
		if err != nil {
			t.Fatalf("Unable to retrieve logs: %v", err)
		}

		h := results.([]common.Hash)
		hashes = append(hashes, h...)
		if len(hashes) >= len(transactions) {
			break
		}
		// check timeout
		if time.Now().After(timeout) {
			break
		}

		time.Sleep(100 * time.Millisecond)
	}

	if len(hashes) != len(transactions) {
		t.Errorf("invalid number of transactions, want %d transactions(s), got %d", len(transactions), len(hashes))
		return
	}
	for i := range hashes {
		if hashes[i] != transactions[i].Hash() {
			t.Errorf("hashes[%d] invalid, want %x, got %x", i, transactions[i].Hash(), hashes[i])
		}
	}
}

// TestLogFilterCreation test whether a given filter criteria makes sense.
// If not it must return an error.
func TestLogFilterCreation(t *testing.T) {
	var (
		db      = rawdb.NewMemoryDatabase(log.Global)
		backend = &testBackend{db: db}
		api     = NewPublicFilterAPI(backend, deadline, 1)

		testCases = []struct {
			crit    FilterCriteria
			success bool
		}{
			// defaults
			{FilterCriteria{}, true},
			// valid block number range
			{FilterCriteria{FromBlock: big.NewInt(1), ToBlock: big.NewInt(2)}, true},
			// "mined" block range to pending
			{FilterCriteria{FromBlock: big.NewInt(1), ToBlock: big.NewInt(rpc.LatestBlockNumber.Int64())}, true},
			// new mined and pending blocks
			{FilterCriteria{FromBlock: big.NewInt(rpc.LatestBlockNumber.Int64()), ToBlock: big.NewInt(rpc.PendingBlockNumber.Int64())}, true},
			// from block "higher" than to block
			{FilterCriteria{FromBlock: big.NewInt(2), ToBlock: big.NewInt(1)}, false},
			// from block "higher" than to block
			{FilterCriteria{FromBlock: big.NewInt(rpc.LatestBlockNumber.Int64()), ToBlock: big.NewInt(100)}, false},
			// from block "higher" than to block
			{FilterCriteria{FromBlock: big.NewInt(rpc.PendingBlockNumber.Int64()), ToBlock: big.NewInt(100)}, false},
			// from block "higher" than to block
			{FilterCriteria{FromBlock: big.NewInt(rpc.PendingBlockNumber.Int64()), ToBlock: big.NewInt(rpc.LatestBlockNumber.Int64())}, false},
		}
	)

	for i, test := range testCases {
		_, err := api.NewFilter(test.crit)
		if test.success && err != nil {
			t.Errorf("expected filter creation for case %d to success, got %v", i, err)
		}
		if !test.success && err == nil {
			t.Errorf("expected testcase %d to fail with an error", i)
		}
	}
}

// TestInvalidLogFilterCreation tests whether invalid filter log criteria results in an error
// when the filter is created.
func TestInvalidLogFilterCreation(t *testing.T) {
	t.Parallel()
	var (
		db      = rawdb.NewMemoryDatabase(log.Global)
		backend = &testBackend{db: db}
		api     = NewPublicFilterAPI(backend, deadline, 1)
	)

	// different situations where log filter creation should fail.
	// Reason: fromBlock > toBlock
	testCases := []FilterCriteria{
		0: {FromBlock: big.NewInt(rpc.PendingBlockNumber.Int64()), ToBlock: big.NewInt(rpc.LatestBlockNumber.Int64())},
		1: {FromBlock: big.NewInt(rpc.PendingBlockNumber.Int64()), ToBlock: big.NewInt(100)},
		2: {FromBlock: big.NewInt(rpc.LatestBlockNumber.Int64()), ToBlock: big.NewInt(100)},
	}

	for i, test := range testCases {
		if _, err := api.NewFilter(test); err == nil {
			t.Errorf("Expected NewFilter for case #%d to fail", i)
		}
	}
}

func TestInvalidGetLogsRequest(t *testing.T) {
	var (
		db        = rawdb.NewMemoryDatabase(log.Global)
		backend   = &testBackend{db: db}
		api       = NewPublicFilterAPI(backend, deadline, 1)
		blockHash = common.HexToHash("0x1111111111111111111111111111111111111111111111111111111111111111")
	)

	// Reason: Cannot specify both BlockHash and FromBlock/ToBlock)
	testCases := []FilterCriteria{
		0: {BlockHash: &blockHash, FromBlock: big.NewInt(100)},
		1: {BlockHash: &blockHash, ToBlock: big.NewInt(500)},
		2: {BlockHash: &blockHash, FromBlock: big.NewInt(rpc.LatestBlockNumber.Int64())},
	}

	for i, test := range testCases {
		if _, err := api.GetLogs(context.Background(), test); err == nil {
			t.Errorf("Expected Logs for case #%d to fail", i)
		}
	}
}

// TestLogFilter tests whether log filters match the correct logs that are posted to the event feed.
func TestLogFilter(t *testing.T) {
	t.Skip("Todo: Fix broken test")
	t.Parallel()
	var (
		db      = rawdb.NewMemoryDatabase(log.Global)
		backend = &testBackend{db: db}
		api     = NewPublicFilterAPI(backend, deadline, 1)

		firstAddr      = common.HexToAddressBytes("0x0011111111111111111111111111111111111111")
		secondAddr     = common.HexToAddressBytes("0x0022222222222222222222222222222222222222")
		thirdAddress   = common.HexToAddressBytes("0x0033333333333333333333333333333333333333")
		notUsedAddress = common.HexToAddressBytes("0x0099999999999999999999999999999999999999")
		firstTopic     = common.HexToHash("0x1111111111111111111111111111111111111111111111111111111111111111")
		secondTopic    = common.HexToHash("0x2222222222222222222222222222222222222222222222222222222222222222")
		notUsedTopic   = common.HexToHash("0x9999999999999999999999999999999999999999999999999999999999999999")

		// posted twice, once as regular logs and once as pending logs.
		allLogs = []*types.Log{
			{Address: common.Bytes20ToAddress(firstAddr, common.Location{0, 0})},
			{Address: common.Bytes20ToAddress(firstAddr, common.Location{0, 0}), Topics: []common.Hash{firstTopic}, BlockNumber: 1},
			{Address: common.Bytes20ToAddress(secondAddr, common.Location{0, 0}), Topics: []common.Hash{firstTopic}, BlockNumber: 1},
			{Address: common.Bytes20ToAddress(thirdAddress, common.Location{0, 0}), Topics: []common.Hash{secondTopic}, BlockNumber: 2},
			{Address: common.Bytes20ToAddress(thirdAddress, common.Location{0, 0}), Topics: []common.Hash{secondTopic}, BlockNumber: 3},
		}

		expectedCase7  = []*types.Log{allLogs[3], allLogs[4], allLogs[0], allLogs[1], allLogs[2], allLogs[3], allLogs[4]}
		expectedCase11 = []*types.Log{allLogs[1], allLogs[2], allLogs[1], allLogs[2]}

		testCases = []struct {
			crit     FilterCriteria
			expected []*types.Log
			id       rpc.ID
		}{
			// match all
			0: {FilterCriteria{}, allLogs, ""},
			// match none due to no matching addresses
			1: {FilterCriteria{Addresses: []common.AddressBytes{{}, notUsedAddress}, Topics: [][]common.Hash{nil}}, []*types.Log{}, ""},
			// match logs based on addresses, ignore topics
			2: {FilterCriteria{Addresses: []common.AddressBytes{firstAddr}}, allLogs[:2], ""},
			// match none due to no matching topics (match with address)
			3: {FilterCriteria{Addresses: []common.AddressBytes{secondAddr}, Topics: [][]common.Hash{{notUsedTopic}}}, []*types.Log{}, ""},
			// match logs based on addresses and topics
			4: {FilterCriteria{Addresses: []common.AddressBytes{thirdAddress}, Topics: [][]common.Hash{{firstTopic, secondTopic}}}, allLogs[3:5], ""},
			// match logs based on multiple addresses and "or" topics
			5: {FilterCriteria{Addresses: []common.AddressBytes{secondAddr, thirdAddress}, Topics: [][]common.Hash{{firstTopic, secondTopic}}}, allLogs[2:5], ""},
			// logs in the pending block
			6: {FilterCriteria{Addresses: []common.AddressBytes{firstAddr}, FromBlock: big.NewInt(rpc.PendingBlockNumber.Int64()), ToBlock: big.NewInt(rpc.PendingBlockNumber.Int64())}, allLogs[:2], ""},
			// mined logs with block num >= 2 or pending logs
			7: {FilterCriteria{FromBlock: big.NewInt(2), ToBlock: big.NewInt(rpc.PendingBlockNumber.Int64())}, expectedCase7, ""},
			// all "mined" logs with block num >= 2
			8: {FilterCriteria{FromBlock: big.NewInt(2), ToBlock: big.NewInt(rpc.LatestBlockNumber.Int64())}, allLogs[3:], ""},
			// all "mined" logs
			9: {FilterCriteria{ToBlock: big.NewInt(rpc.LatestBlockNumber.Int64())}, allLogs, ""},
			// all "mined" logs with 1>= block num <=2 and topic secondTopic
			10: {FilterCriteria{FromBlock: big.NewInt(1), ToBlock: big.NewInt(2), Topics: [][]common.Hash{{secondTopic}}}, allLogs[3:4], ""},
			// all "mined" and pending logs with topic firstTopic
			11: {FilterCriteria{FromBlock: big.NewInt(rpc.LatestBlockNumber.Int64()), ToBlock: big.NewInt(rpc.PendingBlockNumber.Int64()), Topics: [][]common.Hash{{firstTopic}}}, expectedCase11, ""},
			// match all logs due to wildcard topic
			12: {FilterCriteria{Topics: [][]common.Hash{nil}}, allLogs[1:], ""},
		}
	)

	// create all filters
	for i := range testCases {
		testCases[i].id, _ = api.NewFilter(testCases[i].crit)
	}

	// raise events
	time.Sleep(1 * time.Second)
	if nsend := backend.logsFeed.Send(allLogs); nsend == 0 {
		t.Fatal("Logs event not delivered")
	}
	if nsend := backend.pendingLogsFeed.Send(allLogs); nsend == 0 {
		t.Fatal("Pending logs event not delivered")
	}

	for i, tt := range testCases {
		var fetched []*types.Log
		timeout := time.Now().Add(1 * time.Second)
		for { // fetch all expected logs
			results, err := api.GetFilterChanges(tt.id)
			if err != nil {
				t.Fatalf("Unable to fetch logs: %v", err)
			}

			fetched = append(fetched, results.([]*types.Log)...)
			if len(fetched) >= len(tt.expected) {
				break
			}
			// check timeout
			if time.Now().After(timeout) {
				break
			}

			time.Sleep(100 * time.Millisecond)
		}

		if len(fetched) != len(tt.expected) {
			t.Errorf("invalid number of logs for case %d, want %d log(s), got %d", i, len(tt.expected), len(fetched))
			return
		}

		for l := range fetched {
			if fetched[l].Removed {
				t.Errorf("expected log not to be removed for log %d in case %d", l, i)
			}
			if !reflect.DeepEqual(fetched[l], tt.expected[l]) {
				t.Errorf("invalid log on index %d for case %d", l, i)
			}
		}
	}
}

// TestPendingLogsSubscription tests if a subscription receives the correct pending logs that are posted to the event feed.
func TestPendingLogsSubscription(t *testing.T) {
	t.Parallel()
	var (
		db      = rawdb.NewMemoryDatabase(log.Global)
		backend = &testBackend{db: db}
		api     = NewPublicFilterAPI(backend, deadline, 1)

		firstAddr    = common.HexToAddressBytes("0x0011111111111111111111111111111111111111")
		secondAddr   = common.HexToAddressBytes("0x0022222222222222222222222222222222222222")
		thirdAddress = common.HexToAddressBytes("0x0033333333333333333333333333333333333333")
		firstTopic   = common.HexToHash("0x1111111111111111111111111111111111111111111111111111111111111111")
		secondTopic  = common.HexToHash("0x2222222222222222222222222222222222222222222222222222222222222222")
		thirdTopic   = common.HexToHash("0x3333333333333333333333333333333333333333333333333333333333333333")
		fourthTopic  = common.HexToHash("0x4444444444444444444444444444444444444444444444444444444444444444")
		notUsedTopic = common.HexToHash("0x9999999999999999999999999999999999999999999999999999999999999999")

		allLogs = [][]*types.Log{
			{{Address: common.Bytes20ToAddress(firstAddr, common.Location{0, 0}), Topics: []common.Hash{}, BlockNumber: 0}},
			{{Address: common.Bytes20ToAddress(firstAddr, common.Location{0, 0}), Topics: []common.Hash{firstTopic}, BlockNumber: 1}},
			{{Address: common.Bytes20ToAddress(secondAddr, common.Location{0, 0}), Topics: []common.Hash{firstTopic}, BlockNumber: 2}},
			{{Address: common.Bytes20ToAddress(thirdAddress, common.Location{0, 0}), Topics: []common.Hash{secondTopic}, BlockNumber: 3}},
			{{Address: common.Bytes20ToAddress(thirdAddress, common.Location{0, 0}), Topics: []common.Hash{secondTopic}, BlockNumber: 4}},
			{
				{Address: common.Bytes20ToAddress(thirdAddress, common.Location{0, 0}), Topics: []common.Hash{firstTopic}, BlockNumber: 5},
				{Address: common.Bytes20ToAddress(thirdAddress, common.Location{0.0}), Topics: []common.Hash{thirdTopic}, BlockNumber: 5},
				{Address: common.Bytes20ToAddress(thirdAddress, common.Location{0, 0}), Topics: []common.Hash{fourthTopic}, BlockNumber: 5},
				{Address: common.Bytes20ToAddress(firstAddr, common.Location{0, 0}), Topics: []common.Hash{firstTopic}, BlockNumber: 5},
			},
		}

		testCases = []struct {
			crit     quai.FilterQuery
			expected []*types.Log
			c        chan []*types.Log
			sub      *Subscription
		}{
			// match all
			{
				quai.FilterQuery{}, flattenLogs(allLogs),
				nil, nil,
			},
			// match none due to no matching addresses
			{
				quai.FilterQuery{Addresses: []common.AddressBytes{{}}, Topics: [][]common.Hash{nil}},
				nil,
				nil, nil,
			},
			// match logs based on addresses, ignore topics
			{
				quai.FilterQuery{Addresses: []common.AddressBytes{firstAddr}},
				append(flattenLogs(allLogs[:2]), allLogs[5][3]),
				nil, nil,
			},
			// match none due to no matching topics (match with address)
			{
				quai.FilterQuery{Addresses: []common.AddressBytes{secondAddr}, Topics: [][]common.Hash{{notUsedTopic}}},
				nil, nil, nil,
			},
			// match logs based on addresses and topics
			{
				quai.FilterQuery{Addresses: []common.AddressBytes{thirdAddress}, Topics: [][]common.Hash{{firstTopic, secondTopic}}},
				append(flattenLogs(allLogs[3:5]), allLogs[5][0]),
				nil, nil,
			},
			// match logs based on multiple addresses and "or" topics
			{
				quai.FilterQuery{Addresses: []common.AddressBytes{secondAddr, thirdAddress}, Topics: [][]common.Hash{{firstTopic, secondTopic}}},
				append(flattenLogs(allLogs[2:5]), allLogs[5][0]),
				nil,
				nil,
			},
			// block numbers are ignored for filters created with New***Filter, these return all logs that match the given criteria when the state changes
			{
				quai.FilterQuery{Addresses: []common.AddressBytes{firstAddr}, FromBlock: big.NewInt(2), ToBlock: big.NewInt(3)},
				append(flattenLogs(allLogs[:2]), allLogs[5][3]),
				nil, nil,
			},
			// multiple pending logs, should match only 2 topics from the logs in block 5
			{
				quai.FilterQuery{Addresses: []common.AddressBytes{thirdAddress}, Topics: [][]common.Hash{{firstTopic, fourthTopic}}},
				[]*types.Log{allLogs[5][0], allLogs[5][2]},
				nil, nil,
			},
		}
	)

	// create all subscriptions, this ensures all subscriptions are created before the events are posted.
	// on slow machines this could otherwise lead to missing events when the subscription is created after
	// (some) events are posted.
	for i := range testCases {
		testCases[i].c = make(chan []*types.Log)
		testCases[i].sub, _ = api.events.SubscribeLogs(testCases[i].crit, testCases[i].c)
	}

	for n, test := range testCases {
		i := n
		tt := test
		go func() {
			var fetched []*types.Log
		fetchLoop:
			for {
				logs := <-tt.c
				fetched = append(fetched, logs...)
				if len(fetched) >= len(tt.expected) {
					break fetchLoop
				}
			}

			if len(fetched) != len(tt.expected) {
				panic(fmt.Sprintf("invalid number of logs for case %d, want %d log(s), got %d", i, len(tt.expected), len(fetched)))
			}

			for l := range fetched {
				if fetched[l].Removed {
					panic(fmt.Sprintf("expected log not to be removed for log %d in case %d", l, i))
				}
				if !reflect.DeepEqual(fetched[l], tt.expected[l]) {
					panic(fmt.Sprintf("invalid log on index %d for case %d", l, i))
				}
			}
		}()
	}

	// raise events
	time.Sleep(1 * time.Second)
	for _, ev := range allLogs {
		backend.pendingLogsFeed.Send(ev)
	}
}

func flattenLogs(pl [][]*types.Log) []*types.Log {
	var logs []*types.Log
	for _, l := range pl {
		logs = append(logs, l...)
	}
	return logs
}
