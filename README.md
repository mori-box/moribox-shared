# moribox-shared

Generic process infrastructure extracted from [`mori-box/moribox`](https://github.com/mori-box/moribox):
connection pooling, HTTP plumbing, envelope-agnostic identifiers, money,
observability, secrets, and the other seams that would mean the same thing to
any Go service, not just this one.

This module holds no MORI BOX business logic — no campaigns, boxes, promo
codes, wallets or the admin permission model. Those stay in `moribox`. See
[docs/adr in moribox](https://github.com/mori-box/moribox/tree/main/docs/adr)
for the extraction record and the reasoning behind what moved and what did
not.

## Packages

| Package | What it is |
|---|---|
| `audit` | Hash-chained administrative event log |
| `cache` | Redis-protocol cache client |
| `database` | MySQL connection pooling, transactions, error classification |
| `health` | Startup / readiness / liveness probes |
| `httpx` | RFC 9457 problem+json errors, HTTP middleware, JSON helpers |
| `idempotency` | Idempotency-Key storage and replay |
| `ids` | ULID identifier type |
| `money` | Exact decimal money and asset codes |
| `observability` | Structured logging, tracing, the Prometheus registry and generic process metrics |
| `oci` | Oracle Cloud Infrastructure authentication |
| `outbox` | Transactional outbox |
| `providers` | Outbound HTTP client: mTLS, OAuth2 client credentials, circuit breaker, signed callback verification |
| `queue` intentionally absent | this platform's queue broker names fixed business queues; see the ADR |
| `ratelimit` | Multi-dimensional quota engine |
| `secrets` | Secret resolution (AWS Secrets Manager, OCI Vault, environment) |
| `telegram` | Telegram Mini App launch data verification |

## Versioning

Tagged with semver. `moribox` and any other consuming service pin an exact
version in their own `go.mod`; nothing here assumes it is the only version in
use.

## Developing

```
go build ./...
go vet ./...
go test ./...
gofmt -l .
golangci-lint run --timeout=10m
```
