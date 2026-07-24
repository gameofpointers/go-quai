package rpc

import (
	"net"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/dominant-strategies/go-quai/log"
)

const (
	defaultRateLimitClientTTL = 10 * time.Minute
	rateLimitLogInterval      = 5 * time.Second
)

// RateLimitConfig controls the per-client RPC token bucket. A rate of zero
// disables limiting. Burst defaults to the next whole second of traffic.
type RateLimitConfig struct {
	RequestsPerSecond float64
	Burst             int
}

// RateLimitStatus is the process-local state returned by rpc_rateLimitStatus.
type RateLimitStatus struct {
	Enabled           bool      `json:"enabled"`
	RequestsPerSecond float64   `json:"requestsPerSecond"`
	Burst             int       `json:"burst"`
	ActiveClients     int       `json:"activeClients"`
	Accepted          uint64    `json:"accepted"`
	Rejected          uint64    `json:"rejected"`
	StartedAt         time.Time `json:"startedAt"`
}

// RateLimitClientStatus is a per-client entry returned by rpc_rateLimitClients.
type RateLimitClientStatus struct {
	Client     string    `json:"client"`
	Tokens     float64   `json:"tokens"`
	Accepted   uint64    `json:"accepted"`
	Rejected   uint64    `json:"rejected"`
	LastSeenAt time.Time `json:"lastSeenAt"`
}

// RateLimitAPI exposes read-only limiter snapshots. It is intended to be
// registered as a non-public RPC namespace by the node.
type RateLimitAPI struct {
	limiter *RateLimiter
}

// NewRateLimitAPI creates the read-only RPC facade for a limiter.
func NewRateLimitAPI(limiter *RateLimiter) *RateLimitAPI {
	return &RateLimitAPI{limiter: limiter}
}

// Status returns aggregate, process-local rate limiter state.
func (api *RateLimitAPI) Status() RateLimitStatus {
	return api.limiter.Status()
}

// Clients returns the busiest process-local clients.
func (api *RateLimitAPI) Clients(limit int) []RateLimitClientStatus {
	return api.limiter.Clients(limit)
}

type rateLimitClient struct {
	tokens        float64
	lastRefill    time.Time
	lastSeen      time.Time
	lastLog       time.Time
	accepted      uint64
	rejected      uint64
	suppressedLog uint64
}

// RateLimiter is an in-memory, per-client token bucket shared by a node's HTTP
// and WebSocket RPC transports.
type RateLimiter struct {
	mu sync.Mutex

	rate        float64
	burst       int
	clientTTL   time.Duration
	clients     map[string]*rateLimitClient
	lastCleanup time.Time
	startedAt   time.Time
	logger      *log.Logger

	accepted uint64
	rejected uint64
}

// NewRateLimiter creates a process-local limiter. It is safe to share between
// multiple RPC servers.
func NewRateLimiter(config RateLimitConfig, logger *log.Logger) *RateLimiter {
	burst := config.Burst
	if config.RequestsPerSecond > 0 && burst <= 0 {
		burst = int(config.RequestsPerSecond)
		if float64(burst) < config.RequestsPerSecond {
			burst++
		}
		if burst < 1 {
			burst = 1
		}
	}
	now := time.Now()
	return &RateLimiter{
		rate:        config.RequestsPerSecond,
		burst:       burst,
		clientTTL:   defaultRateLimitClientTTL,
		clients:     make(map[string]*rateLimitClient),
		lastCleanup: now,
		startedAt:   now,
		logger:      logger,
	}
}

func (l *RateLimiter) enabled() bool {
	return l != nil && l.rate > 0 && l.burst > 0
}

// Allow consumes one token for remote. Method is used for structured logs and
// does not create independent per-method limits.
func (l *RateLimiter) Allow(remote, method string) bool {
	if !l.enabled() {
		return true
	}
	now := time.Now()
	client := rateLimitClientKey(remote)
	var logReject bool
	var suppressed uint64

	l.mu.Lock()
	if now.Sub(l.lastCleanup) >= time.Minute {
		for key, entry := range l.clients {
			if now.Sub(entry.lastSeen) > l.clientTTL {
				delete(l.clients, key)
			}
		}
		l.lastCleanup = now
	}
	entry := l.clients[client]
	if entry == nil {
		entry = &rateLimitClient{tokens: float64(l.burst), lastRefill: now}
		l.clients[client] = entry
	}
	entry.tokens += now.Sub(entry.lastRefill).Seconds() * l.rate
	if entry.tokens > float64(l.burst) {
		entry.tokens = float64(l.burst)
	}
	entry.lastRefill = now
	entry.lastSeen = now

	allowed := entry.tokens >= 1
	if allowed {
		entry.tokens--
		entry.accepted++
		atomic.AddUint64(&l.accepted, 1)
	} else {
		entry.rejected++
		atomic.AddUint64(&l.rejected, 1)
		if entry.lastLog.IsZero() || now.Sub(entry.lastLog) >= rateLimitLogInterval {
			logReject = true
			suppressed = entry.suppressedLog
			entry.suppressedLog = 0
			entry.lastLog = now
		} else {
			entry.suppressedLog++
		}
	}
	l.mu.Unlock()

	if logReject && l.logger != nil {
		l.logger.WithFields(log.Fields{
			"client":           client,
			"method":           method,
			"rate_limit_rps":   l.rate,
			"rate_limit_burst": l.burst,
			"suppressed":       suppressed,
		}).Warn("RPC rate limit exceeded")
	}
	return allowed
}

// Status returns a consistent snapshot of aggregate limiter state.
func (l *RateLimiter) Status() RateLimitStatus {
	if l == nil {
		return RateLimitStatus{}
	}
	l.mu.Lock()
	activeClients := len(l.clients)
	l.mu.Unlock()
	return RateLimitStatus{
		Enabled:           l.enabled(),
		RequestsPerSecond: l.rate,
		Burst:             l.burst,
		ActiveClients:     activeClients,
		Accepted:          atomic.LoadUint64(&l.accepted),
		Rejected:          atomic.LoadUint64(&l.rejected),
		StartedAt:         l.startedAt,
	}
}

// Clients returns the busiest clients, capped at 100 entries.
func (l *RateLimiter) Clients(limit int) []RateLimitClientStatus {
	if l == nil {
		return nil
	}
	if limit <= 0 {
		limit = 20
	}
	if limit > 100 {
		limit = 100
	}
	now := time.Now()
	l.mu.Lock()
	clients := make([]RateLimitClientStatus, 0, len(l.clients))
	for key, entry := range l.clients {
		tokens := entry.tokens + now.Sub(entry.lastRefill).Seconds()*l.rate
		if tokens > float64(l.burst) {
			tokens = float64(l.burst)
		}
		clients = append(clients, RateLimitClientStatus{
			Client:     key,
			Tokens:     tokens,
			Accepted:   entry.accepted,
			Rejected:   entry.rejected,
			LastSeenAt: entry.lastSeen,
		})
	}
	l.mu.Unlock()
	sort.Slice(clients, func(i, j int) bool {
		if clients[i].Rejected != clients[j].Rejected {
			return clients[i].Rejected > clients[j].Rejected
		}
		if clients[i].Accepted != clients[j].Accepted {
			return clients[i].Accepted > clients[j].Accepted
		}
		return clients[i].Client < clients[j].Client
	})
	if len(clients) > limit {
		clients = clients[:limit]
	}
	return clients
}

func rateLimitClientKey(remote string) string {
	host, _, err := net.SplitHostPort(remote)
	if err == nil {
		return host
	}
	if remote == "" {
		return "unknown"
	}
	return remote
}

type rateLimitError struct{}

func (*rateLimitError) ErrorCode() int { return -32005 }
func (*rateLimitError) Error() string  { return "RPC rate limit exceeded" }
