package utils

import (
	"math/big"
	"testing"

	"github.com/dominant-strategies/go-quai/common"
)

func testNodeSet(hash common.Hash, entropy int64) NodeSet {
	return NodeSet{nodes: map[string]Node{
		common.Location{}.Name(): {
			hash:     hash,
			location: common.Location{},
			entropy:  big.NewInt(entropy),
		},
	}}
}

func TestPendingHeadersKeepsDistinctSetsWithEqualEntropy(t *testing.T) {
	hc := &HierarchicalCoordinator{
		pendingHeaders: NewPendingHeaders(),
		bestEntropy:    new(big.Int),
	}
	first := testNodeSet(common.HexToHash("0x01"), 10)
	second := testNodeSet(common.HexToHash("0x02"), 10)

	hc.Add(big.NewInt(10), first, hc.pendingHeaders)
	hc.Add(big.NewInt(10), second, hc.pendingHeaders)

	if got := hc.pendingHeaders.collection.Len(); got != 2 {
		t.Fatalf("equal-entropy head sets collapsed: got %d entries, want 2", got)
	}
	if got := len(hc.pendingHeaders.order); got != 2 {
		t.Fatalf("got %d ordered entries, want 2", got)
	}
}

func TestNodeSetKeyIsIndependentOfMapIterationOrder(t *testing.T) {
	prime := Node{hash: common.HexToHash("0x01"), location: common.Location{}, entropy: big.NewInt(1)}
	zone := Node{hash: common.HexToHash("0x02"), location: common.Location{0, 0}, entropy: big.NewInt(2)}
	first := NodeSet{nodes: map[string]Node{
		prime.location.Name(): prime,
		zone.location.Name():  zone,
	}}
	second := NodeSet{nodes: map[string]Node{
		zone.location.Name():  zone,
		prime.location.Name(): prime,
	}}

	if nodeSetKey(first) != nodeSetKey(second) {
		t.Fatal("node-set identity depends on map iteration order")
	}
}

func TestHeaderGenerationCoalescesToNewestBestSet(t *testing.T) {
	hc := &HierarchicalCoordinator{
		pendingHeaders: NewPendingHeaders(),
		bestEntropy:    new(big.Int),
	}
	first := testNodeSet(common.HexToHash("0x01"), 1)
	second := testNodeSet(common.HexToHash("0x02"), 2)
	hc.Add(big.NewInt(1), first, hc.pendingHeaders)

	generation, launch := hc.queueBestHeaderGenerationLocked()
	if !launch || generation.nodes[common.Location{}.Name()].hash != common.HexToHash("0x01") {
		t.Fatal("first generation was not launched")
	}

	hc.Add(big.NewInt(2), second, hc.pendingHeaders)
	if _, launch = hc.queueBestHeaderGenerationLocked(); launch {
		t.Fatal("launched a second concurrent header worker")
	}
	if !hc.hasQueuedGeneration {
		t.Fatal("new best hierarchy was not queued")
	}
	if got := hc.queuedHeaderGeneration.nodes[common.Location{}.Name()].hash; got != common.HexToHash("0x02") {
		t.Fatalf("queued hash %s, want newest best hash", got)
	}
}

func TestCalculateLeadersSkipsRejectedHeads(t *testing.T) {
	location := common.Location{0, 0}
	rejected := Node{hash: common.HexToHash("0x01"), location: location, entropy: big.NewInt(20)}
	fallback := Node{hash: common.HexToHash("0x02"), location: location, entropy: big.NewInt(10)}
	recent := map[string][]Node{
		location.Name(): {rejected, fallback},
	}

	leaders := calculateLeaders(recent, map[common.Hash]bool{rejected.hash: true}, 1, 1)
	if len(leaders) != 1 || leaders[0].hash != fallback.hash {
		t.Fatalf("got leaders %#v, want fallback head", leaders)
	}
}
