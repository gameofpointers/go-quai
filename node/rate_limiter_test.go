package node

import (
	"strings"
	"testing"

	"github.com/dominant-strategies/go-quai/log"
	"github.com/dominant-strategies/go-quai/rpc"
)

func TestRateLimiterConfigValidation(t *testing.T) {
	tests := []Config{
		{RPCRateLimit: -1},
		{RPCRateLimitBurst: -1},
	}
	for _, config := range tests {
		_, err := New(&config, log.Global)
		if err == nil || !strings.Contains(err.Error(), "cannot be negative") {
			t.Fatalf("New(%+v) returned %v", config, err)
		}
	}
}

func TestRateLimitAPIRequiresExplicitModule(t *testing.T) {
	limiter := rpc.NewRateLimiter(rpc.RateLimitConfig{RequestsPerSecond: 10}, log.Global)
	apis := []rpc.API{{
		Namespace: "rpcstats",
		Version:   "1.0",
		Service:   rpc.NewRateLimitAPI(limiter),
		Public:    false,
	}}

	hiddenServer := rpc.NewServer(log.Global)
	if err := RegisterApis(apis, nil, hiddenServer, false, log.Global); err != nil {
		t.Fatal(err)
	}
	hiddenClient := rpc.DialInProc(hiddenServer)
	defer hiddenClient.Close()
	var status rpc.RateLimitStatus
	if err := hiddenClient.Call(&status, "rpcstats_status"); err == nil {
		t.Fatal("private rpcstats API was registered without an explicit module")
	}

	exposedServer := rpc.NewServer(log.Global)
	if err := RegisterApis(apis, []string{"rpcstats"}, exposedServer, false, log.Global); err != nil {
		t.Fatal(err)
	}
	exposedClient := rpc.DialInProc(exposedServer)
	defer exposedClient.Close()
	if err := exposedClient.Call(&status, "rpcstats_status"); err != nil {
		t.Fatalf("explicit rpcstats module was not registered: %v", err)
	}
	if !status.Enabled {
		t.Fatal("rpcstats status did not report the enabled limiter")
	}
}
