package blake3pow

import (
	"io/ioutil"
	"math/big"
	"math/rand"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/dominant-strategies/go-quai/core/types"
)

const epochLength = int64(100)

// Tests that blake3pow works correctly in test mode.
func TestTestMode(t *testing.T) {
	header := &types.Header{}
	header.SetNumber(big.NewInt(1))
	header.SetDifficulty(big.NewInt(100))

	blake3pow := NewTester(nil, false)
	defer blake3pow.Close()

	results := make(chan *types.Header)
	err := blake3pow.Seal(header, results, nil)
	if err != nil {
		t.Fatalf("failed to seal block: %v", err)
	}
	select {
	case header := <-results:
		header.SetNonce(types.EncodeNonce(header.Nonce().Uint64()))
		if err := blake3pow.verifySeal(nil, header, false); err != nil {
			t.Fatalf("unexpected verification error: %v", err)
		}
	case <-time.NewTimer(4 * time.Second).C:
		t.Error("sealing result timeout")
	}
}

// This test checks that cache lru logic doesn't crash under load.
// It reproduces https://github.com/ethereum/go-ethereum/issues/14943
func TestCacheFileEvict(t *testing.T) {
	tmpdir, err := ioutil.TempDir("", "blake3pow-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpdir)

	config := Config{
		PowMode: ModeTest,
	}
	e := New(config, nil, false)
	defer e.Close()

	workers := 8
	epochs := 100
	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go verifyTest(&wg, e, i, epochs)
	}
	wg.Wait()
}

func verifyTest(wg *sync.WaitGroup, e *Blake3pow, workerIndex, epochs int) {
	defer wg.Done()

	const wiggle = 4 * epochLength
	r := rand.New(rand.NewSource(int64(workerIndex)))
	for epoch := 0; epoch < epochs; epoch++ {
		block := int64(epoch)*epochLength - wiggle/2 + r.Int63n(wiggle)
		if block < 0 {
			block = 0
		}
		header := &types.Header{}
		header.SetNumber(big.NewInt(block))
		header.SetDifficulty(big.NewInt(100))
		e.verifySeal(nil, header, false)
	}
}
