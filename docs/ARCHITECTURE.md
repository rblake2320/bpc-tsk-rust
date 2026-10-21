# Architecture and verification order

## Boundaries

The bridge depends on pinned releases of the standalone BPC and TSK crates. It has four narrow authority boundaries:

- `BpcGate` invokes BPC against the immutable request snapshot and exposes only `{pair_id, authorization_version, verified_at_ms, fresh_and_closed_scope}`.
- `BindingStore` resolves a privileged control-plane mapping from BPC pair ID to `{principal_id, tsk_client_id, binding_revision}`. A client cannot create or select this mapping through request headers.
- `TskRequestVerifier` calls the TSK verifier only after identity binding succeeds. The runnable service requires its bounded, independent pre-lookup TSK verification limiter. It receives headers only; no TSK secret enters the bridge.
- `AuditSink` records a correlation ID and a domain-separated HMAC request-context digest. The core’s `NoopAuditSink` and `MemoryBindingStore` are explicitly development/test facilities, not production authority.

## Required flow

1. An HTTP adapter enforces header/body limits and creates one `ImmutableRequest` from raw method, path-and-query, multi-value headers, and exact body bytes.
2. The bridge writes a secret-free audit attempt. Audit uncertainty denies before either factor.
3. The core rejects missing, empty or duplicate authentication fields and invalid TSK client-ID syntax before either verifier. This preflight does not call BPC, load a binding or touch TSK state; remaining BPC/TSK syntax validation belongs to the respective verifier.
4. `BpcGate` verifies BPC first. BPC denial, malformed result, stale or open-scope result, exception/panic, or unavailable authority produces generic denial. No TSK store lookup occurs.
5. `BindingStore` resolves one active mapping for the verified pair. The raw submitted `x-tsk-client-id` must byte-equal the stored mapping. Missing/revoked/revision-mismatched mappings or identity mismatch deny before TSK.
6. The core constructs the TSK multi-value header snapshot from the immutable request and invokes TSK exactly once through the mandatory service limiter. Exhausted admission denies before a TSK lookup or HOTP commit. TSK replay/lifecycle/authority failures are generic public denial.
7. After a TSK success, the bridge rechecks BPC and binding fences. Any uncertainty denies; it does not roll back a BPC nonce or HOTP value.
8. Only then is `CombinedAuthSnapshot` made available to a protected business handler. The adapter writes `X-TSK-Authenticated: 1` exactly once from the snapshot’s response headers.

A production HTTP adapter must not use the BPC Axum middleware directly for bridge routes, because the standalone middleware intentionally exposes BPC-specific public error codes. The bridge owns generic response mapping.

The optional `axum-adapter` feature supplies that bridge-owned admission middleware. It collects every raw header value, bounds body collection, captures the exact method/path-and-query/body tuple, then takes a non-waiting bounded admission permit before running the entire synchronous composition coordinator on Tokio's blocking executor. Saturation, task failure/panic, and invalid capacity configuration fail closed without calling the coordinator. It places only `CombinedAuthSnapshot` in request extensions and replaces any handler-supplied TSK response-control headers with the verified TSK values. Mount it outside decompression, URI rewrite, retry, and request-normalizing middleware. The production service adds a transport-level one-request connection boundary, strict framing and request deadlines, a required TSK verification limiter, loopback/private binding and hardened systemd template. Every deployment terminates TLS and provides edge request-smuggling, WAF/DDoS and distributed source-aware rate controls in its separately authenticated private edge.

## Deployment topology

BPC replay/fencing and BPC key lifecycle remain within the BPC authority. TSK HOTP authority, credential lifecycle, and HA remain within the TSK authority. PostgreSQL in the bridge owns only bindings, audit intent/outbox, and application-facing authorization decisions. Redis is not a bridge binding source of truth. It may be used only where the BPC or future TSK authority already owns the corresponding replay/fencing semantics.

## Optional durable bridge implementation

`postgres-authority` supplies `PostgresAuthority` for both synchronous `BindingStore` and `AuditSink`. All runtime operations verify the fixed schema version/checksum. Mutations run at SERIALIZABLE isolation, require an exact expected revision, preserve revoked tombstones, and commit mapping state, append-only history and outbox intent together. Active TSK identities are unique across pairs/principals. Operation UUIDs provide idempotent lifecycle reconciliation without repeating either factor.

Verification audits store only a domain-separated SHA-256 commitment to the core's independent audit digest, correlation ID, closed phase/failure code and optional trusted binding revision. No HMAC values, signatures, keys, JWKs, raw signed data, headers or bodies are persisted. Attempts/final events are immutable and idempotent per correlation/phase. The separate publisher claims delivery metadata with expiring random-token/owner leases and acknowledges after external durable acceptance; external event-UUID deduplication is required. Binding/history/outbox payloads never change during delivery recovery.

Production constructors require certificate/hostname-verified TLS 1.3 and explicit trust roots, with no plaintext fallback. Only the explicitly named loopback test API uses NoTls. Separate migrator, verifier, control-plane and publisher credentials, bounded blocking admission, external publication/anchoring, cancellation and deployment/fault validation are required. Final rechecks remain point-in-time assertions, not a distributed transaction with downstream effects. See [the operator guide](POSTGRES_AUTHORITY.md) and [migration contract](../migrations/README.md).
