# RPC rate limiting

The node can apply one in-memory token bucket per directly connected client IP.
The bucket is shared by the node's HTTP and WebSocket RPC servers. State is
discarded when the process restarts, and inactive client entries are removed
after ten minutes.

Rate limiting is disabled by default. Enable it with:

```text
go-quai start --rpc.rate-limit 50 --rpc.rate-limit-burst 100
```

- `rpc.rate-limit` is the sustained number of JSON-RPC calls per second for
  each client IP. `0` disables the limiter.
- `rpc.rate-limit-burst` is the maximum burst for each client IP. `0` uses one
  second of configured traffic.

Each item in a JSON-RPC batch consumes one token. Rejected calls return JSON-RPC
error code `-32005` with the message `RPC rate limit exceeded`. Empty health
check GETs and CORS preflight requests do not consume tokens.

The limiter deliberately keys clients from the TCP peer address and does not
trust `X-Forwarded-For`. When a reverse proxy or load balancer is in front of
the node, the configured limit therefore applies to each proxy address. Enforce
end-user limits at that trusted proxy if per-origin-client limiting is needed.

## Observability

The non-public `rpcstats` namespace provides process-local snapshots. Add
`rpcstats` to the HTTP or WebSocket API module list on operator-controlled
endpoints; for example:

```text
--rpc.http-api quai,net,web3,rpcstats
```

It is intentionally not exposed by default because per-client results contain
IP addresses. Query aggregate status with:

```bash
curl -s http://127.0.0.1:9001 \
  -H 'content-type: application/json' \
  --data '{"jsonrpc":"2.0","id":1,"method":"rpcstats_status","params":[]}'
```

The response includes whether the limiter is enabled, its configured rate and
burst, active client count, and total accepted and rejected calls.

The busiest client entries can be queried with:

```bash
curl -s http://127.0.0.1:9001 \
  -H 'content-type: application/json' \
  --data '{"jsonrpc":"2.0","id":1,"method":"rpcstats_clients","params":[20]}'
```

The limit argument defaults to 20 when it is zero or negative and is capped at
100.

Startup configuration and rejections are written to the node's normal shard log
under `nodelogs/`. Rejection warnings contain `client`, `method`,
`rate_limit_rps`, `rate_limit_burst`, and `suppressed` fields. Rejection log
lines are coalesced per client for five seconds to prevent log flooding; all
rejections are still reflected in the API counters.
