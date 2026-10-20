# Architecture and verification order

## Boundaries

The bridge depends on pinned releases of the standalone BPC and TSK crates. It has four narrow authority boundaries:

- `BpcGate` invokes BPC against the immutable request snapshot and exposes only `{pair_id, authorization_version, verified_at_ms, fresh_and_closed_scope}`.
- `BindingStore` resolves a privileged control-plane mapping from BPC pair ID to `{principal_id, tsk_client_id, binding_revision}`. A client cannot create or select this mapping through request headers.
- `TskRequestVerifier` calls `tsk_rust_protocol::verify_tsk_request` only after identity binding succeeds. It receives headers only; no TSK secret enters the bridge.
- `AuditSink` records a correlation ID and a domain-separated HMAC request-context digest. The core’s `NoopAuditSink` and `MemoryBindingStore` are explicitly development/test facilities, not production authority.

## Required flow

1. An HTTP adapter enforces header/body limits and creates one `ImmutableRequest` from raw method, path-and-query, multi-value headers, and exact body bytes.
2. The core rejects missing, empty, malformed, or duplicate BPC/TSK authentication fields. This is pure syntax validation. It does not call BPC, load a binding, or touch TSK state.
3. The bridge writes a secret-free audit attempt. Audit uncertainty denies before BPC.
4. `BpcGate` verifies BPC first. BPC denial, malformed result, stale or open-scope result, exception/panic, or unavailable authority produces generic denial. No TSK store lookup occurs.
5. `BindingStore` resolves one active mapping for the verified pair. The raw submitted `x-tsk-client-id` must byte-equal the stored mapping. Missing/revoked/revision-mismatched mappings or identity mismatch deny before TSK.
6. The core constructs the TSK multi-value header snapshot from the immutable request and invokes TSK exactly once. TSK replay/lifecycle/authority failures are generic public denial.
7. After a TSK success, the bridge rechecks BPC and binding fences. Any uncertainty denies; it does not roll back a BPC nonce or HOTP value.
8. Only then is `CombinedAuthSnapshot` made available to a protected business handler. The adapter writes `X-TSK-Authenticated: 1` exactly once from the snapshot’s response headers.

A production HTTP adapter must not use the BPC Axum middleware directly for bridge routes, because the standalone middleware intentionally exposes BPC-specific public error codes. The bridge owns generic response mapping.

## Deployment topology

BPC replay/fencing and BPC key lifecycle remain within the BPC authority. TSK HOTP authority, credential lifecycle, and HA remain within the TSK authority. PostgreSQL in the bridge owns only bindings, audit intent/outbox, and application-facing authorization decisions. Redis is not a bridge binding source of truth. It may be used only where the BPC or future TSK authority already owns the corresponding replay/fencing semantics.
