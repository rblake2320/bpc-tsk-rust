# BPC–TSK production-candidate service

This Linux service runs only the pinned protocol composition: `ProtocolBpcGate` → `CombinedVerifier` → `ProtocolTskVerifier`, using `BridgeAxumState::try_new`. It has **no development mode, migration command, plaintext connector, map export, registration, retry, or compensation path**. This is a runnable candidate, not an HA/production attestation. Separate deployment/fault testing of all authorities and the TLS edge remains mandatory.

## Build and start

```sh
cargo build --locked --release -p bpc-tsk-service
./target/release/bpc-tsk-service --config /absolute/path/to/config.toml
```

Exactly these two arguments are accepted. There are no environment, inline-secret, default-config, relative-path, `--help`, or permissive CLI alternatives. Errors print **only a static configuration field**, never a value, path, parser error, driver error, credential, header, or principal. Panic diagnostics are static; do not enable driver/debug tracing, core dumps, or external request logging containing factor headers.

Use [`deploy/config.example.toml`](deploy/config.example.toml). All config and secret files must be absolute, regular, nonempty, single-link and mode `0400` or `0600` (no group/other access). Files are opened by descriptor-relative `O_NOFOLLOW` traversal on **every path component**, with bounded reads and pre/post metadata validation; no canonicalize/reopen race exists. Parent directories and file writers must remain controlled by root/the service owner. Concurrent in-place writes are unsupported; replace configuration atomically and restart. No filesystem mechanism can prevent an authorized writer from changing equal-length contents during a read; protect ownership and mount policy. Every configured file path is distinct. Do not use symlink-based secret volume layouts directly; materialize private regular files instead.

### Credential formats and isolation

- BPC, TSK, bridge PostgreSQL DSNs: independent UTF-8 secret files, ≤8 KiB, one URL or PostgreSQL keyword DSN, optional final LF. **Values must differ**. Exactly one TCP host; no Unix sockets, multi-host failover, `sslmode=disable`, or caller `options`. Use different database roles and dedicated schemas, not just different textual forms of one role. The service cannot prove backend identity from a DSN string.
- BPC, TSK, bridge, Redis CA files: separate files, each exactly one PEM CA certificate, ≤16 KiB. TSK, bridge and Redis trust only these private roots. The pinned BPC connector adds its private CA to platform roots and verifies hostname/certificate with TLS ≥1.2; it offers no system-root disabling API. Bridge requires TLS 1.3. No insecure constructor is called or feature-enabled by this service.
- Redis endpoint: ≤8 KiB, verified `rediss://`, one TCP endpoint, optional database index, **no query or fragment**, no verification bypass. Independent Redis ACL credential goes in this endpoint file.
- Optional Redis client mTLS: configure both files or neither. PEM certificate chain ≤8 certificates/64 KiB and matching unencrypted PEM private key ≤64 KiB. Trust and key material are validated before startup sockets. TLS certificates/keys are never logged.
- Audit key: **exactly 32 raw binary bytes**, independently provisioned from KMS/secure randomness, no newline or encoding. It is only a bridge audit-context HMAC key. Never use a BPC factor secret or TSK shared secret. This service does not obtain factor secrets and therefore cannot compare them to the audit key; independent key provisioning is a required operator control.
- Schemas: lowercase safe PostgreSQL identifiers, not `public`/`pg_*`, all distinct. Bridge schema must be the reviewed fixed `bpc_tsk_bridge` because its SQL is fully qualified. BPC and TSK schemas are configurable dedicated schemas. No search-path rewrite of bridge SQL.

The synchronous authorities stay within their respective protocol wrappers. The service never looks up, copies, transfers, logs, serializes or exposes a TSK shared secret/map. PostgreSQL, Redis and audit ownership must remain independent even when co-located.

### Provisioning happens elsewhere

Use separate privileged operators/migrator binaries to provision BPC and TSK schemas, bridge migrations in the root `migrations/`, roles, grants, and bindings. Runtime roles must lack DDL and secret-export/control-plane grants. **The request service never runs migrations.** Bridge startup calls `check_schema` read-only. The pinned BPC/TSK constructors establish their sessions; their schema/authority checks occur through their own contracts. Review runtime grants and schema checks independently.

Redis must use `maxmemory-policy noeviction`, durable persistence and governed namespace/epoch. Provision its epoch separately, wait the complete retention/quarantine horizon, then start this service. Startup calls `connect_tls_with_config` and **explicit `reconcile`**, never `provision_epoch`, never automatic recovery or verification retries. Missing/mismatched/quarantined continuity causes startup failure. An uncertain Redis verification closes its gate until separately governed recovery and restart. BPC verifier lockout is explicitly `0`; its signature window is exactly the Redis configured window and Redis retention uses the pinned default safety/continuity buffers.

### Bounds and cancellation

All numeric values must be positive. Maxima: method 32 bytes, headers 128 fields and 32 KiB, body 2 MiB, concurrency/blocking/runtime blocking threads 1024, runtime workers 64, request admission timeout 60 s, drain/startup 120 s, signature window 300 s and Redis command timeout 30 s. Blocking admission must not exceed Tokio `max_blocking_threads`. Lower limits are encouraged.

The global outer layer buffers **all raw body bytes** with the same cap as core before the raw adapter. It rejects forwarding headers, ambiguous framing, invalid header bytes and unsigned trailers before either factor. The HTTP/1.1 transport bounds header acquisition within the same admission deadline, validates origin-form request framing before Hyper, and uses one request per connection with keepalive disabled. Header-block bytes including request line are additionally bounded by the configured header byte cap. This intentionally rejects some otherwise legal HTTP traffic (`Expect`, HTTP/1.0, HTTP/2, transfer-coding chains, trailers). Do not insert decompression, rewriting, normalization, retries or transparent proxies between the signing client and signed request target/body; the authenticated edge must forward exact method/path/query/body.

**Request timeout is an admission deadline**, starting at accepted TCP connection: header/body timeouts return empty `408` before factors run. Framing/header failures return empty `400`; body size overflow returns empty `413`. Resource overload returns empty `503` with `Retry-After: 1`; protected factor denial stays generic empty `401`. Once BPC/TSK verification starts it is always awaited, not wrapped in a cancellation timeout, retried, or compensated. BPC has controlled 5 s connection/statement/idle bounds, 1 s lock timeout and Linux TCP user timeout 10 s. TSK/bridge enforce their bounded session/transport settings; TSK serialization retries are explicitly **zero**. These are per-operation bounds, not an overall cryptographic transaction deadline. Redis's published synchronous constructor does not expose a total DNS/connect/TLS-handshake deadline; the service's separate `startup_timeout_ms` bounds initialization before exposing a listener. On expiry it exits without waiting indefinitely for blocking startup. The Type=simple systemd template does not use readiness notification or rely on TimeoutStartSec as an application startup deadline.

SIGINT/SIGTERM first atomically change readiness to shutting down, then stop accepting connections and request graceful drain. In-flight started verification can finish until the configured drain deadline. On drain expiry request tasks are aborted and runtime wait is bounded; blocking operations cannot be safely canceled, so process termination can leave uncertain factor/audit outcomes. **Do not replay such requests automatically**; perform authoritative reconciliation separately. systemd `TimeoutStopSec` must exceed configured drain plus transport write allowance. Process restart is not factor retry.

## HTTP routes

- `GET /livez`: empty `204`, no authority work (even before readiness or during shutdown).
- `GET /readyz`: empty `204` only after config/file validation, all authority construction, Redis reconciliation and bridge schema check; empty generic `503` after shutdown begins. It is a startup/shutdown latch, **not a per-request dependency ping or continuous health attestation**. Startup fails without exposing a listener if construction fails.
- `POST /v1/protected`: core `bpc_tsk_admission` first; handler requires `CombinedAuthSnapshot` and returns only empty `204`. It neither emits a principal nor calls a factor again. Only the core's secret-free TSK status response metadata may be added after success.

All responses have overriding `Cache-Control: no-store`, `nosniff`, `no-referrer`, deny-all CSP with sandbox, frame `DENY`, restrictive Permissions-Policy, and no `Server`. No default CORS or HSTS: the service is a private HTTP origin behind a **separately authenticated TLS edge**. Never expose the listener directly to the Internet. Bind only loopback/RFC1918 IPv4/IPv6 ULA; wildcard, public, link-local and IPv4-mapped IPv6 addresses are rejected. Firewall edge access and authenticate it independently; source-IP privacy is not authentication. `Forwarded` and **all `X-Forwarded-*`** are rejected; configure the edge to omit them. Edge owns public TLS/HSTS, client authentication, rate/abuse limits and request-smuggling protections.

## systemd and release validation

[`deploy/bpc-tsk-service.service`](deploy/bpc-tsk-service.service) is a hardening template with fixed non-root identity and systemd credentials, read-only filesystem, protected system/home, private tmp, empty capabilities, no-new-privileges, exact endpoint allow-list placeholders and bounded stop. Adapt paths/IPs; provision `bpc-tsk` without login. DynamicUser can be used with equivalent credential accessibility. This service requires **no persistent writable directory**; only the declared private runtime directory is writable. Use a separate audit outbox publisher/control plane.

Unit tests exercise config/CLI rejection, file permissions/link/symlink handling, readiness, protected generic denial and no handler/factor side effects on edge errors, security headers, forwarding, overload, body/framing/deadline failures and raw-byte preservation. Transport tests exercise real Linux loopback sockets with no external authority. Live PostgreSQL/Redis TLS/mTLS and successful signed two-factor requests require the separately provisioned deployment test environment; unit doubles exist only under `cfg(test)`.
