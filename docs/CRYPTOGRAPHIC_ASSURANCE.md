# Cryptographic assurance and attack-cost assessment

Author: Manus AI

Reviewed: 2026-10-20
Status: private checkpoint assessment, **not a production-readiness certification**

This composition is materially stronger than a static API key when its independent factors are provisioned and operated correctly. A static API key is usually a bearer secret: theft often gives direct, replayable access until rotation. The composed design instead requires BPC first, binds BPC to an exact method/path/body plus a fresh nonce, resolves a server-controlled binding, and only then lets TSK perform its atomic HOTP-sensitive validation. A BPC denial, malformed result, stale result, duplicated authentication field or initial binding mismatch denies before TSK lookup or HOTP consumption. A later BPC/binding final-fence change denies after TSK consumption, without retry or compensation.

That does **not** make a defensible claim of “unhackable,” “endless,” or a simple sum of bit strengths. The relevant question is always: *what is the cheapest complete path to authorization or to a damaging outcome?* Key theft, compromised recovery/control planes, writable authority stores, unbounded traffic, deployment mistakes, and a future cryptanalytic break can be cheaper than brute force. The math below is therefore a work-factor description under explicit assumptions, not a guarantee.

## What the current Rust code requires

BPC v1 verifies both an ECDSA P-256/SHA-256 signature over canonical exact-request evidence and a full HMAC-SHA-256 value derived by HKDF from a separate registration secret. It also verifies the method, path-and-query, raw-body digest, a UUID-v4 nonce, the time window, pair lifecycle, scope, and an atomic first-use nonce claim. The BPC private signing key and the registration secret must be independently generated and stored. They are not interchangeable.

TSK v1 uses an independently generated 256-bit shared secret. It derives static, TOTP, and at least one HOTP segment with HMAC-SHA-256, checks a 12-character HMAC-derived integrity tag, and atomically advances HOTP counters only after validation. Its secret is never passed to BPC or the composition layer. The bridge then rechecks BPC authorization and the durable BPC-pair-to-TSK-client binding after TSK succeeds, so a concurrent revoke or binding change fails closed rather than authorizing from a stale snapshot.

The bridge’s optional Axum adapter captures bounded exact request bytes, preserves duplicate headers for fail-closed rejection, gives protected handlers only an immutable authorization snapshot, and replaces any handler-supplied TSK response-control headers with the verified response headers. This prevents a handler from emitting an ambiguous or fabricated TSK acknowledgement.

## Classical work factors

NIST maps a 256-bit elliptic-curve key to **128 bits** of estimated classical security strength; NIST also notes that ECC strength estimates change significantly once practical quantum computing is relevant.[1] For a generic classical discrete-log attack against the P-256 signing key, the work scale is approximately `2^128` group operations; a midpoint search estimate is `2^127` operations.

For a uniformly random 32-byte registration secret or TSK shared secret, the candidate space is `2^256`; a brute-force recovery search expects about `2^255` candidates. The new BPC helper `generate_high_assurance_registration_secret()` produces exactly this 32-byte random, canonical base64url value. The legacy BPC v1 password-style policy remains only for compatibility and is not evidence of high entropy.

At an intentionally unrealistic rate of `10^18` operations per second, `2^127` operations take approximately `5.39 × 10^12` years, and an expected `2^255` secret search takes approximately `1.83 × 10^51` years. Those figures demonstrate scale; they do not model actual ECDSA, HMAC, storage, network, power, parallelism, or a future algorithmic breakthrough. They must not be represented as a promise that an attack cannot succeed.

BPC’s factors must also not be advertised as `128 + 256 = 384` bits. Security strengths do not safely add this way. A conservative security statement is that the public-key signature component is a 128-bit classical component, while the independently generated HMAC factor has a 256-bit candidate space. An attacker who has not compromised either needs a valid signature *and* a valid HMAC; an attacker who steals one factor faces the other. A full compositional proof would require an independent cryptographic review of the exact protocol and implementation.

## TSK online-guessing bound

The current default TSK map has a 64-character base64url key. Each character has 64 possible values, so the full key space is `64^64 = 2^384`. This is not a claim of 384-bit secret security—the value is generated from a 256-bit HMAC secret—but it is the correct starting point for estimating a random online key guess.

The default HOTP look-ahead accepts the stored counter plus five future counters, at most six candidates per HOTP segment. A conservative worst case for the default map shape is five rotating HOTP segments, or `6^5 = 7,776` simultaneously accepted keys. The probability of a random base64url key succeeding is therefore at most:

```text
6^5 / 64^64
```

The expected number of online guesses is about `64^64 / 6^5`, or `2^371.075` guesses. Even at an impossible `10^18` online guesses per second, that is about `1.61 × 10^86` years. In the actual composition, BPC must authorize first, so a request cannot reach that TSK validation path after BPC failure.

This bound is configuration-sensitive. TSK v1 intentionally permits a legal minimum 28-character layout: one static eight-character segment, one HOTP eight-character segment, and the 12-character checksum. With six accepted HOTP states, the corresponding random-guess estimate is `64^28 / 6`, or about `2^165.415` guesses. That is still above P-256’s classical 128-bit level, but it is not the 64-character default. High-assurance production policy must pin a minimum 64-character map and disallow ad hoc weakening through provisioning options.

## Fixes made in this checkpoint

The BPC source had a real availability weakness: its former default of ten verifier failures could lock a known pair ID after malformed requests. An attacker did not need either cryptographic factor to create that credential-specific denial of service. The default `lockout_after` is now `0`, a true no-mutation mode. The verifier and both in-memory and PostgreSQL registries no longer increment or lock a pair at that threshold. The regression suite submits 100 malformed requests for a known pair and proves its status, failure count, and authorization revision remain unchanged.

The dangerous lockout behavior is retained only as an explicit non-default legacy policy. It is not recommended for exposed endpoints. The required control is independent pre-verification rate limiting, per-source and per-pair pressure controls, protected telemetry, canary-pair alerts, and operator-authorized revoke/lock actions. NIST requires verifiers to limit online guessing; OWASP likewise recommends account-based throttling and warns that lockout design must avoid becoming a denial-of-service mechanism.[3] [5]

BPC now exposes `generate_high_assurance_registration_secret`, `validate_high_assurance_registration_secret`, and `derive_high_assurance_request_hmac_key`. The BPC checkpoint is pinned at `a8000c95aab1c33bdbfb2151bc70278a7cf668c5`; the bridge is pinned to that exact revision. The BPC all-feature test and strict Clippy gate passed against live local Redis and PostgreSQL. The bridge all-feature test and strict Clippy gate passed with the new immutable pin.

## What can still beat the mathematics

A complete defense must make the following routes harder than brute force. None is solved merely by choosing long keys.

- **Endpoint or secret-store compromise.** If an attacker obtains both BPC client factors, or the TSK shared secret and its current counter state, there is no brute-force problem left. Use separate HSM/KMS or platform secure stores, distinct service identities, narrowly scoped runtime access, memory/core-dump controls, rotation, revocation, and recovery drills. The two factors must not be co-resident by default.

- **Control-plane compromise.** Pair approval, BPC-to-TSK binding creation, TSK provisioning, lifecycle actions, backups, CI release authority, and break-glass access are high-value targets. They need stronger authentication than the data plane, dual control for privileged changes, immutable audit anchoring outside the primary database, least privilege, and rehearsed recovery.

- **Replay/authority availability failures.** BPC’s nonce store, TSK counter authority, and bridge binding authority must remain durable, transactionally fenced, and fail closed across failover, restore, partition, and timeout. A cache is not a binding source of truth. An ambiguous state transition must deny, not retry into authorization.

- **Phishing and adversary-in-the-middle attacks.** Exact request signatures reduce replay and tampering, but they do not automatically make a user-held software secret phishing-resistant. CISA identifies FIDO/WebAuthn and PKI-based authenticators as phishing-resistant MFA approaches and recommends moving high-value systems in that direction.[4] A future operator/control-plane authentication layer should use hardware-backed WebAuthn or PKI rather than a reusable shared secret.

- **Quantum risk.** P-256 ECDSA is not a post-quantum signature scheme. NIST finalized ML-KEM, ML-DSA, and SLH-DSA standards and recommends beginning integration now.[2] This design needs a versioned BPC v2 migration that adds a reviewed hybrid signature policy such as P-256 plus ML-DSA, pins algorithm identifiers into the signed payload, supports dual verification during cutover, and never silently downgrades to v1. This is a planned hardening gate, not a claim that v1 is quantum-safe.

- **Deployment and supply chain.** TLS, reverse-proxy normalization, request-smuggling defenses, dependency provenance, protected build/release identity, signed artifacts, SBOM/SCA, vulnerability response, segmented networks, DDoS protection, and tested backups are mandatory. The recent developer-tool supply-chain attacks are reminders that a protocol can be mathematically sound while the executable running it is compromised.

Laya does not add cryptographic bits or make authorization safer. It may later classify redacted audit events for human triage, but it must remain asynchronous and non-authoritative. It must never receive BPC/TSK secrets or make allow/deny, replay, lifecycle, or key-management decisions.

## Release gate

This is a strong private checkpoint, not a production release. The optional durable bridge PostgreSQL binding authority and transactional audit outbox are now implemented with opt-in local integration tests. Before a production claim, the project still needs their deployment/role/cancellation/reconciliation validation, external audit anchoring, bridge cross-node/partition/failover/crash drills, a TSK durable HA authority parity assessment, independent cryptographic and application-security review, fuzzing/property testing of parsers and state transitions, SAST/SCA/SBOM/signing gates, external penetration testing, an incident/recovery runbook, and a reviewed PQ migration plan. Point-in-time final fences are not an atomic distributed business-effect transaction.

The accurate claim today is: **under uncompromised, independently generated and stored factors, the classical brute-force work factors are far beyond practical attack; the project is deliberately designed so BPC failure cannot consume TSK state.** It is not accurate to claim that no attack can work, that the factors’ bit strengths simply add, or that the implementation is already production-complete.

## References

[1]: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r5.pdf "NIST SP 800-57 Part 1 Revision 5"

[2]: https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards "NIST releases first finalized post-quantum encryption standards"

[3]: https://pages.nist.gov/800-63-4/sp800-63b.html "NIST SP 800-63B digital identity guidelines"

[4]: https://www.cisa.gov/sites/default/files/publications/fact-sheet-implementing-phishing-resistant-mfa-508c.pdf "CISA implementing phishing-resistant MFA"

[5]: https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html "OWASP authentication cheat sheet"
