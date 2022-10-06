package blake3pow

import (
	"encoding/json"
	"io/ioutil"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/dominant-strategies/go-quai/common"
	"github.com/dominant-strategies/go-quai/core/types"
	"github.com/dominant-strategies/go-quai/internal/testlog"
	"github.com/dominant-strategies/go-quai/log"
)

// Tests whether remote HTTP servers are correctly notified of new work.
func TestRemoteNotify(t *testing.T) {
	// Start a simple web server to capture notifications.
	sink := make(chan [3]string)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		blob, err := ioutil.ReadAll(req.Body)
		if err != nil {
			t.Errorf("failed to read miner notification: %v", err)
		}
		var work [3]string
		if err := json.Unmarshal(blob, &work); err != nil {
			t.Errorf("failed to unmarshal miner notification: %v", err)
		}
		sink <- work
	}))
	defer server.Close()

	// Create the custom blake3pow engine.
	blake3pow := NewTester([]string{server.URL}, false)
	defer blake3pow.Close()

	// Stream a work task and ensure the notification bubbles out.
	header := &types.Header{}
	header.SetNumber(big.NewInt(1))
	header.SetDifficulty(big.NewInt(100))

	blake3pow.Seal(header, nil, nil)
	select {
	case work := <-sink:
		if want := blake3pow.SealHash(header).Hex(); work[0] != want {
			t.Errorf("work packet hash mismatch: have %s, want %s", work[0], want)
		}
		target := new(big.Int).Div(new(big.Int).Lsh(big.NewInt(1), 256), header.Difficulty())
		if want := common.BytesToHash(target.Bytes()).Hex(); work[2] != want {
			t.Errorf("work packet target mismatch: have %s, want %s", work[2], want)
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("notification timed out")
	}
}

// Tests whether remote HTTP servers are correctly notified of new work. (Full pending block body / --miner.notify.full)
func TestRemoteNotifyFull(t *testing.T) {
	// Start a simple web server to capture notifications.
	sink := make(chan map[string]interface{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		blob, err := ioutil.ReadAll(req.Body)
		if err != nil {
			t.Errorf("failed to read miner notification: %v", err)
		}
		var work map[string]interface{}
		if err := json.Unmarshal(blob, &work); err != nil {
			t.Errorf("failed to unmarshal miner notification: %v", err)
		}
		sink <- work
	}))
	defer server.Close()

	// Create the custom blake3pow engine.
	config := Config{
		PowMode:    ModeTest,
		NotifyFull: true,
		Log:        testlog.Logger(t, log.LvlWarn),
	}
	blake3pow := New(config, []string{server.URL}, false)
	defer blake3pow.Close()

	// Stream a work task and ensure the notification bubbles out.
	header := &types.Header{}
	header.SetNumber(big.NewInt(1))
	header.SetDifficulty(big.NewInt(100))

	blake3pow.Seal(header, nil, nil)
	select {
	case work := <-sink:
		if want := "0x" + strconv.FormatUint(header.Number().Uint64(), 16); work["number"] != want {
			t.Errorf("pending block number mismatch: have %v, want %v", work["number"], want)
		}
		if want := "0x" + header.Difficulty().Text(16); work["difficulty"] != want {
			t.Errorf("pending block difficulty mismatch: have %s, want %s", work["difficulty"], want)
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("notification timed out")
	}
}

// Tests that pushing work packages fast to the miner doesn't cause any data race
// issues in the notifications.
func TestRemoteMultiNotify(t *testing.T) {
	// Start a simple web server to capture notifications.
	sink := make(chan [3]string, 64)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		blob, err := ioutil.ReadAll(req.Body)
		if err != nil {
			t.Errorf("failed to read miner notification: %v", err)
		}
		var work [3]string
		if err := json.Unmarshal(blob, &work); err != nil {
			t.Errorf("failed to unmarshal miner notification: %v", err)
		}
		sink <- work
	}))
	defer server.Close()

	// Create the custom blake3pow engine.
	blake3pow := NewTester([]string{server.URL}, false)
	blake3pow.config.Log = testlog.Logger(t, log.LvlWarn)
	defer blake3pow.Close()

	// Provide a results reader.
	// Otherwise the unread results will be logged asynchronously
	// and this can happen after the test is finished, causing a panic.
	results := make(chan *types.Header, cap(sink))

	// Stream a lot of work task and ensure all the notifications bubble out.
	for i := 0; i < cap(sink); i++ {
		header := &types.Header{}
		header.SetNumber(big.NewInt(int64(i)))
		header.SetDifficulty(big.NewInt(100))

		blake3pow.Seal(header, results, nil)
	}

	for i := 0; i < cap(sink); i++ {
		select {
		case <-sink:
			<-results
		case <-time.After(10 * time.Second):
			t.Fatalf("notification %d timed out", i)
		}
	}
}

// Tests that pushing work packages fast to the miner doesn't cause any data race
// issues in the notifications. Full pending block body / --miner.notify.full)
func TestRemoteMultiNotifyFull(t *testing.T) {
	// Start a simple web server to capture notifications.
	sink := make(chan map[string]interface{}, 64)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		blob, err := ioutil.ReadAll(req.Body)
		if err != nil {
			t.Errorf("failed to read miner notification: %v", err)
		}
		var work map[string]interface{}
		if err := json.Unmarshal(blob, &work); err != nil {
			t.Errorf("failed to unmarshal miner notification: %v", err)
		}
		sink <- work
	}))
	defer server.Close()

	// Create the custom blake3pow engine.
	config := Config{
		PowMode:    ModeTest,
		NotifyFull: true,
		Log:        testlog.Logger(t, log.LvlWarn),
	}
	blake3pow := New(config, []string{server.URL}, false)
	defer blake3pow.Close()

	// Provide a results reader.
	// Otherwise the unread results will be logged asynchronously
	// and this can happen after the test is finished, causing a panic.
	results := make(chan *types.Header, cap(sink))

	// Stream a lot of work task and ensure all the notifications bubble out.
	for i := 0; i < cap(sink); i++ {
		header := &types.Header{}
		header.SetNumber(big.NewInt(int64(i)))
		header.SetDifficulty(big.NewInt(100))

		blake3pow.Seal(header, results, nil)
	}

	for i := 0; i < cap(sink); i++ {
		select {
		case <-sink:
			<-results
		case <-time.After(10 * time.Second):
			t.Fatalf("notification %d timed out", i)
		}
	}
}

// Tests whether stale solutions are correctly processed.
func TestStaleSubmission(t *testing.T) {
	blake3pow := NewTester(nil, true)
	defer blake3pow.Close()
	api := &API{blake3pow}

	fakeNonce, fakeDigest := types.BlockNonce{0x01, 0x02, 0x03}, common.HexToHash("deadbeef")

	header1 := &types.Header{}
	header1.SetParentHash(common.BytesToHash([]byte{0xa}))
	header1.SetNumber(big.NewInt(1))
	header1.SetDifficulty(big.NewInt(100000000))

	header2 := &types.Header{}
	header2.SetParentHash(common.BytesToHash([]byte{0xb}))
	header2.SetNumber(big.NewInt(2))
	header2.SetDifficulty(big.NewInt(100000000))

	header3 := &types.Header{}
	header3.SetParentHash(common.BytesToHash([]byte{0xb}))
	header3.SetNumber(big.NewInt(2))
	header3.SetDifficulty(big.NewInt(100000001))

	header4 := &types.Header{}
	header4.SetParentHash(common.BytesToHash([]byte{0xc}))
	header4.SetNumber(big.NewInt(3))
	header4.SetDifficulty(big.NewInt(100000000))

	header5 := &types.Header{}
	header5.SetParentHash(common.BytesToHash([]byte{0xd}))
	header5.SetNumber(big.NewInt(9))
	header5.SetDifficulty(big.NewInt(100000000))

	header6 := &types.Header{}
	header6.SetParentHash(common.BytesToHash([]byte{0xe}))
	header6.SetNumber(big.NewInt(10))
	header6.SetDifficulty(big.NewInt(100000000))

	header7 := &types.Header{}
	header7.SetParentHash(common.BytesToHash([]byte{0xf}))
	header7.SetNumber(big.NewInt(17))
	header7.SetDifficulty(big.NewInt(100000000))

	testcases := []struct {
		headers     []*types.Header
		submitIndex int
		submitRes   bool
	}{
		// Case1: submit solution for the latest mining package
		{
			[]*types.Header{
				header1,
			},
			0,
			true,
		},
		// Case2: submit solution for the previous package but have same parent.
		{
			[]*types.Header{
				header2,
				header3,
			},
			0,
			true,
		},
		// Case3: submit stale but acceptable solution
		{
			[]*types.Header{
				header4,
				header5,
			},
			0,
			true,
		},
		// Case4: submit very old solution
		{
			[]*types.Header{
				header6,
				header7,
			},
			0,
			false,
		},
	}
	results := make(chan *types.Header, 16)

	for id, c := range testcases {
		for _, h := range c.headers {
			blake3pow.Seal(h, results, nil)
		}
		if res := api.SubmitWork(fakeNonce, blake3pow.SealHash(c.headers[c.submitIndex]), fakeDigest); res != c.submitRes {
			t.Errorf("case %d submit result mismatch, want %t, get %t", id+1, c.submitRes, res)
		}
		if !c.submitRes {
			continue
		}
		select {
		case res := <-results:
			if res.Nonce() != fakeNonce {
				t.Errorf("case %d block nonce mismatch, want %x, get %x", id+1, fakeNonce, res.Nonce())
			}
			if res.Difficulty().Uint64() != c.headers[c.submitIndex].Difficulty().Uint64() {
				t.Errorf("case %d block difficulty mismatch, want %d, get %d", id+1, c.headers[c.submitIndex].Difficulty(), res.Difficulty())
			}
			if res.Number().Uint64() != c.headers[c.submitIndex].Number().Uint64() {
				t.Errorf("case %d block number mismatch, want %d, get %d", id+1, c.headers[c.submitIndex].Number().Uint64(), res.Number().Uint64())
			}
			if res.ParentHash() != c.headers[c.submitIndex].ParentHash() {
				t.Errorf("case %d block parent hash mismatch, want %s, get %s", id+1, c.headers[c.submitIndex].ParentHash().Hex(), res.ParentHash().Hex())
			}
		case <-time.NewTimer(time.Second).C:
			t.Errorf("case %d fetch blake3pow result timeout", id+1)
		}
	}
}
