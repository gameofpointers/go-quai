package rpc

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dominant-strategies/go-quai/log"
)

func TestServerRateLimitAndObservabilityAPI(t *testing.T) {
	server := NewServer(log.Global)
	server.SetRateLimiter(NewRateLimiter(RateLimitConfig{RequestsPerSecond: 1, Burst: 1}, log.Global))
	if err := server.RegisterName("rpcstats", NewRateLimitAPI(server.rateLimiter)); err != nil {
		t.Fatal(err)
	}

	first := serveRPCRequest(t, server, `{"jsonrpc":"2.0","id":1,"method":"rpcstats_status"}`)
	if first.Error != nil {
		t.Fatalf("first request failed: %v", first.Error)
	}
	var status RateLimitStatus
	if err := json.Unmarshal(first.Result, &status); err != nil {
		t.Fatal(err)
	}
	if !status.Enabled || status.Accepted != 1 || status.Rejected != 0 {
		t.Fatalf("unexpected API status: %+v", status)
	}

	second := serveRPCRequest(t, server, `{"jsonrpc":"2.0","id":2,"method":"rpcstats_status"}`)
	if second.Error == nil || second.Error.Code != -32005 {
		t.Fatalf("expected rate-limit error, got %+v", second)
	}
	if got := server.rateLimiter.Status(); got.Rejected != 1 {
		t.Fatalf("rejection was not tracked: %+v", got)
	}
}

func TestWebsocketServerRateLimit(t *testing.T) {
	server := NewServer(log.Global)
	server.SetRateLimiter(NewRateLimiter(RateLimitConfig{RequestsPerSecond: 1, Burst: 1}, log.Global))
	httpServer := httptest.NewServer(server.WebsocketHandler([]string{"*"}))
	defer httpServer.Close()

	client, err := DialWebsocket(context.Background(), "ws"+strings.TrimPrefix(httpServer.URL, "http"), "")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	var modules map[string]string
	if err := client.Call(&modules, "rpc_modules"); err != nil {
		t.Fatalf("first WebSocket request failed: %v", err)
	}
	if err := client.Call(&modules, "rpc_modules"); err == nil {
		t.Fatal("WebSocket request beyond burst was accepted")
	} else if rpcErr, ok := err.(Error); !ok || rpcErr.ErrorCode() != -32005 {
		t.Fatalf("unexpected WebSocket rejection: %v", err)
	}

	clients := server.rateLimiter.Clients(1)
	if len(clients) != 1 || clients[0].Client != "127.0.0.1" {
		t.Fatalf("WebSocket peer was not tracked by IP: %+v", clients)
	}
}

func serveRPCRequest(t *testing.T, server *Server, body string) jsonrpcMessage {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, "http://example.invalid/", bytes.NewBufferString(body))
	request.Header.Set("Content-Type", contentType)
	request.RemoteAddr = "192.0.2.1:1234"
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("HTTP status %d: %s", recorder.Code, recorder.Body.String())
	}
	var response jsonrpcMessage
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("invalid RPC response %q: %v", recorder.Body.String(), err)
	}
	return response
}

func TestRateLimiterPerClientAndStatus(t *testing.T) {
	limiter := NewRateLimiter(RateLimitConfig{RequestsPerSecond: 1, Burst: 2}, log.Global)

	if !limiter.Allow("192.0.2.1:1000", "test_call") {
		t.Fatal("first request was rejected")
	}
	if !limiter.Allow("192.0.2.1:2000", "test_call") {
		t.Fatal("second request from same client was rejected")
	}
	if limiter.Allow("192.0.2.1:3000", "test_call") {
		t.Fatal("request beyond burst was accepted")
	}
	if !limiter.Allow("192.0.2.2:1000", "test_call") {
		t.Fatal("a different client did not get an independent bucket")
	}

	status := limiter.Status()
	if !status.Enabled || status.ActiveClients != 2 || status.Accepted != 3 || status.Rejected != 1 {
		t.Fatalf("unexpected status: %+v", status)
	}
	clients := limiter.Clients(1)
	if len(clients) != 1 || clients[0].Client != "192.0.2.1" || clients[0].Rejected != 1 {
		t.Fatalf("unexpected clients: %+v", clients)
	}
}

func TestRateLimiterDisabled(t *testing.T) {
	limiter := NewRateLimiter(RateLimitConfig{}, log.Global)
	for i := 0; i < 100; i++ {
		if !limiter.Allow("192.0.2.1:1000", "test_call") {
			t.Fatal("disabled limiter rejected a request")
		}
	}
	status := limiter.Status()
	if status.Enabled || status.Accepted != 0 || status.Rejected != 0 {
		t.Fatalf("unexpected disabled status: %+v", status)
	}
}

func TestRateLimitClientKey(t *testing.T) {
	tests := map[string]string{
		"127.0.0.1:1234":     "127.0.0.1",
		"[2001:db8::1]:1234": "2001:db8::1",
		"inproc":             "inproc",
		"":                   "unknown",
	}
	for input, want := range tests {
		if got := rateLimitClientKey(input); got != want {
			t.Errorf("rateLimitClientKey(%q) = %q, want %q", input, got, want)
		}
	}
}
