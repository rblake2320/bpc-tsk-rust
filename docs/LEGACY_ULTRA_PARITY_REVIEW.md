# Confidential legacy Ultra Protocol parity review

**Classification:** Confidential / pre-patent source review. Do not publish externally.

**Reviewed baseline:** `rblake2320/ultra-protocol` at `bdf339b758807398df7dafe8df79f0d44b554f1d` (`v1.2.1: Fix 4 bugs found by deep audit`)

**Rust checkpoints compared:**

- BPC: `a8000c95aab1c33bdbfb2151bc70278a7cf668c5`
- TSK: `2dcded8eba3a8c09a7ffdbc74e8f05b2829b34d0`
- Composition bridge: `fe80993f94117768927b5fb259831bbe0e52c3a8` before this review document

This document records a source-level compatibility and security review. It does **not** authorize a production claim.

## Executive conclusion

The pre-Rust project is the original seven-layer architecture: BPC provides P-256 signing, pair approval, a second secret-derived proof, replay controls, and behavioral telemetry; TSK adds rotating HMAC-derived segments and a server-held map; the bridge intends to require BPC, TSK, and an identity binding.

The Rust work preserves the important factor separation and improves several high-risk correctness properties. In particular, the Rust bridge validates BPC, resolves a server-controlled active BPC-pair-to-TSK-client binding, checks the request client ID against that binding, and only then permits a TSK lookup or HOTP state transition. It also rechecks BPC and binding revisions after TSK. The legacy bridge instead verifies TSK before resolving the binding, which could consume HOTP state on a later identity mismatch.

The legacy source must be treated as a valuable protocol/test-taxonomy source, **not** as an unquestioned production baseline. The source, its specifications, and its README contain material drift; its release gate is not reproducible at the checked commit. The Rust code is not wire-compatible with this particular TypeScript baseline, so migration must be explicitly versioned rather than silently called BPC/TSK v1 interoperability.

## Direct validation of the legacy repository

The private reference checkout was not changed.

- `npm ci --ignore-scripts` failed before test execution because `package-lock.json` is out of sync with the workspace manifest: it lacks `@ultra/graphql-adapter@0.1.0`. This is a release/supply-chain reproducibility failure.
- A disposable copy was installed with lifecycle scripts disabled and without changing the lockfile. `npm run build` passed.
- Root `npm run typecheck` failed with 22 TypeScript errors: the root compiler configuration lacks the DOM/Web Crypto declarations needed for `CryptoKey`, `JsonWebKey`, `IDBDatabase`, `window`, and `indexedDB`.
- The legacy `npm run test:all` command passed in the disposable dependency resolution:
  - 23 BPC-core tests, 26 BPC-server tests, and 8 BPC-client tests;
  - 36 TSK core tests, 12 attack-suite scenarios, and 14 adversarial-proof assertions;
  - 37 bridge assertions and 33 GraphQL-guard assertions.
- The actual executable total is therefore 189 listed checks, not the README total of 142 or the security-position total of 156.
- `npm run test --workspace=red-team` fails because its Vitest configuration finds **no test files**. The red-team directory is an orchestrator and attack taxonomy, not a tested deterministic release gate.

The disposable install is useful behavioral evidence only. It is not a reproducible build because it resolved the current dependency ranges after the checked-in lockfile gate had failed.

## Controls that Rust already improves

### BPC standalone crate

The Rust BPC implementation is stronger than the legacy source in several concrete ways:

- strict eight-field canonical payload handling, strict compact JSON bytes, strict P-256 JWK validation, UUID-v4 nonces, JS-safe timestamp bounds, duplicate-header rejection, and raw-body capture/restoration in the Axum adapter;
- Redis replay continuity guardrails: no-eviction requirement, fixed retention, epoch quarantine, timeout ambiguity closure, and replay claims only after cryptographic verification;
- PostgreSQL serializable pairing/rotation/final-use fencing, hashed approval tokens, versioned authorization state, and redacted list views;
- tamper-evident, append-only SHA-256 audit-chain primitive with external-anchor verification;
- Ghost/canary pairs that consume a validated nonce but never authorize;
- a redirect-denying HTTP client that refuses authority-changing paths;
- default BPC lockout disabled. The legacy default can lock a known pair after unauthenticated malformed requests; that is a credential-specific denial-of-service primitive. The Rust regression test proves malformed traffic cannot mutate pair state by default.

### TSK standalone crate

Rust improves actual map/counter behavior, including OS randomness without modulo bias, strict map validation, mandatory HOTP presence, atomic multi-HOTP/lifecycle commits, counter exhaustion handling, duplicate header rejection, hard-link/symlink-resistant local persistence, secret-redacted debug output, and acknowledgement-gated client counter advancement.

The legacy TypeScript client key assembly concatenates full HMAC values instead of each configured segment length, so it cannot generally reconstruct the server’s positional key. Rust derives exactly the configured segment lengths.

### Composition bridge

The Rust bridge materially improves the old thin wrapper:

- it rejects missing, empty, duplicated, and case-colliding BPC/TSK security headers before either factor;
- BPC is always evaluated before binding and TSK;
- it binds TSK identity before TSK lookup or HOTP consumption;
- it performs final BPC and binding fences after TSK, denying stale/revoked results without retries;
- it captures exact raw method/path/query/body evidence once;
- it returns generic public denials rather than exposing BPC/TSK/internal error details;
- it maintains factor authority separation and does not share BPC/TSK secrets.

## Material gaps or divergence that must be managed

### 1. Freeze a protocol-version and migration decision — P0

The Rust code is **not** wire-compatible with the supplied `ultra-protocol` baseline.

For BPC, the legacy actual client computes a request proof from `HMAC-SHA-256(SHA256("bpc:" + secret), nonce || timestamp)`, while Rust derives an HKDF-SHA-256 request key and HMACs with it. The legacy specification says something else again: HMAC directly with the plaintext secret. Rotation payload encodings also differ. The legacy specification says body hashes are truncated, while current client and Rust code use the full `sha256:`-prefixed digest.

For TSK, the legacy default is a 52-character key with an 8-character checksum. The Rust default is a 64-character key with a mandatory 12-character checksum; long-output padding behavior also differs. Existing Rust compatibility fixtures target another TSK checkout, not this private Ultra source.

**Required decision:** either implement exact legacy BPC/TSK verification behind an explicit legacy profile with authoritative golden vectors, or designate the hardened Rust formats as BPC/TSK v2 and perform dual-verify plus re-enrollment. Do not describe the present Rust releases as interoperable replacements for this checkout.

### 2. Do not reproduce inaccurate legacy secret claims — P0/P1

The legacy specification and README claim Argon2id-backed server secret storage. The actual `packages/bpc-core/src/hmac.ts` implementation computes only `SHA-256("bpc:" + secret)`, and the client registration path sends a deterministic hash. Its HMAC verification code also has a structural-only fallback if no stored HMAC key exists.

Rust correctly documents its different model: a provisioned request-HMAC verifier key. The high-assurance Rust API now generates an independent random 32-byte registration secret. Production must choose one clear model:

1. independently provisioned high-entropy secret plus HKDF/HMAC verifier; or
2. user password with a reviewed Argon2id registration/enrollment path.

The system must not claim password-hardening or hardware-bound custody that its executable implementation does not provide.

### 3. Complete the shared authorities before production — P0

The composition workspace currently has only `MemoryBindingStore` and `NoopAuditSink`. It lacks the required PostgreSQL binding authority, serializable revision fence, lifecycle history, transactional audit/outbox, reconciliation, immutable anchor delivery, and operator controls. The standalone TSK implementation has only memory/JSON storage, not a shared HA authority.

A production checkpoint requires durable PostgreSQL-backed BPC binding and TSK authority, atomic HOTP/binding lifecycle commits, protected migrator/runtime roles, failover/partition/restore drills, and a clear ambiguous-outcome policy.

### 4. Port the useful legacy pre-auth controls, but redesign their enforcement — P0/P1

The legacy BPC server wires per-IP/per-pair/global rate limiting, anomaly counters, and verification audit writes. Rust has stronger independent primitives, but its verifier and Axum adapter do not automatically run a rate limiter, anomaly policy, or verification/lifecycle audit writer. These are required production controls, especially before expensive public-key work.

Port them as a dedicated, durable pre-auth/telemetry boundary with:

- trusted-proxy source-IP extraction;
- global, source, and pair-keyed atomic limits;
- absolute thresholds in addition to ratio scoring, so legitimate traffic cannot dilute an attack signal;
- bounded secret-free audit events for every ingress rejection, verified denial, success, replay, lifecycle event, and canary use;
- operator-only response policy. Telemetry must never become an allow/deny bypass.

The legacy automatic pair lockout is specifically **not** a control to restore: it is opt-in only and unsuitable as the default exposed-endpoint response.

### 5. Fix the structural-secrecy claim before making it a security layer — P1

Both implementations currently disclose ordered segment types and lengths. Because layouts are contiguous, the ordered lengths reconstruct every segment boundary. The legacy "shuffle" of boundaries is sorted again before output and has no effect. Therefore the map-position claim is not a separate cryptographic secret as currently serialized; its benefit must not be counted as an independent layer or added to a bit-security total.

Either design an opaque, versioned client/server representation that prevents map-layout reconstruction, or document layout metadata as non-secret and base security claims only on independent secrets, rotation, replay state, and integrity checks.

### 6. Restore a safe client custody interface — P1

The legacy browser code uses a non-extractable Web Crypto key and browser/Node storage adapters. It does not prove TPM/Secure Enclave protection, but it provides a concrete custody path. Rust currently exposes an in-memory `p256::SigningKey`; applications are responsible for HSM/KMS/platform secure-store custody.

The Rust BPC client needs an async signing-provider abstraction with software, OS-keychain/platform, KMS/HSM, and WebAuthn/attestation-capable adapters. Raw private-key material must not be required by the normal production request path. This is a critical future parity item, not a reason to reuse the legacy client unchanged.

### 7. Port specific high-value tests, not marketing totals — P1

The old attack suites demonstrate useful categories—header oversize/control input, duplicate headers, concurrent nonce/HOTP replay, TOTP boundaries, malformed encodings, body/path tampering, cross-protocol identity failure, lifecycle races, and GraphQL scope semantics. Some legacy tests are self-contained reimplementations instead of exercising shipping packages, so their high assertion totals are not sufficient release evidence.

The Rust release gate should turn those categories into direct crate/integration/property/fuzz tests against the actual artifacts. Add real PostgreSQL/Redis fault injection, multi-process replay, proxy normalization, lost-response/retry, binding-revision/revoke race, parser fuzzing, and response-header replacement tests.

### 8. Conditional GraphQL guard — P2

The original stack has a useful post-auth GraphQL operation guard: read-scoped identities may execute queries but not POST GraphQL mutations. Rust has no GraphQL integration. If GraphQL is in scope, port this as a post-auth explicit adapter; otherwise document GraphQL as unsupported rather than relying on HTTP method scope.

## Legacy issues that Rust must deliberately retain as fixed

- Legacy BPC lockout after ten unauthenticated failures creates a pair-ID denial-of-service path. Keep Rust’s default lockout disabled.
- Legacy bridge resolves identity after TSK and can consume HOTP state before discovering a mismatch. Keep Rust’s binding-first ordering and final fences.
- Legacy TSK can generate a map with no HOTP factor. Keep Rust’s mandatory HOTP requirement.
- Legacy TSK counter commits can be partial across multiple HOTP segments. Keep Rust’s one atomic vector/lifecycle commit.
- Legacy nonce storage uses simple Redis `SET NX PX` and memory eviction; retain Rust’s continuity/quarantine/no-eviction fail-closed design.
- Legacy public factor-specific error messages become an oracle. Keep generic external denials and protected internal correlation.

## Recommended checkpoint order

1. Create a versioned canonical conformance suite and migration plan for the actual private TypeScript baseline.
2. Implement production PostgreSQL authorities for bridge binding/outbox and TSK HOTP/lifecycle, with real HA/fault tests.
3. Add the mandatory pre-auth rate/anomaly/audit boundary, including canary alert delivery and a tested response playbook.
4. Add secure signing-provider/key-custody interfaces and high-entropy secret enrollment policy.
5. Port deterministic adversarial tests and fuzz/property tests into committed Rust CI; fix the incomplete workflow so all optional production features build and test.
6. Decide and correct the structural-layout disclosure before making a seven-layer or additive-bit-strength claim.

## Accurate status statement

The original design is a strong multi-control architecture, and the Rust composition already improves its most sensitive ordering and state-consumption properties. It is not yet a production-parity port of this exact private TypeScript checkout. The remaining work is concrete: canonical-version migration, durable authorities, operational anti-abuse/audit controls, secure custody, red-team-derived test gates, and independent review.
