# Production-readiness gate

This repository is a private checkpoint. Passing its Rust unit tests or CI does not authorize a production deployment.

The optional `postgres-authority` implementation now provides explicit version/checksum migrations, expected-revision serializable binding lifecycle, tombstones and immutable history, secret-free transactional outbox intent, verified TLS 1.3, bounded statement/lock/idle/connect/contention limits, and fenced publisher claims/acknowledgements. Its opt-in local PostgreSQL tests are development evidence only. This does not complete the cross-authority final-decision, cancellation, failover or audit-anchoring requirements.

Before a release, all of the following must pass:

1. Deploy the implemented `postgres-authority` instead of `MemoryBindingStore`/`NoopAuditSink` with independently provisioned least-privilege migrator, verifier, control-plane and publisher roles and verified TLS. Review/test the example grants and migration upgrade/forward-repair/restoration path against the release database. Complete whole-operation cancellation/timeout behavior, reconnect/pooling/failover policy, ambiguous-commit reconciliation, abandoned-attempt recovery, external publisher/deduplication/backlog controls and external audit anchors. Current lookup/recheck transactions are point-in-time fences, not a cross-database atomic business-effect decision. See [the operator guide](POSTGRES_AUTHORITY.md).
2. Complete deployment validation for the optional raw-body Axum adapter. It already preserves exact BPC bytes, enforces bounded headers/body, rejects duplicates before both factors, returns generic public denial, protects the TSK acknowledgement response headers, and exposes only the immutable authorization snapshot. It still needs real reverse-proxy/TLS integration, slow-request and request-smuggling testing, trusted-proxy rules, connection/body timeouts, route integration tests, and externally enforced rate/DDoS controls.
3. Complete the BPC authorization-fence contract so BPC revocation/rotation can be rechecked under a durable final decision. The adapter must not infer TSK identity or principal data from BPC headers.
4. Port TSK’s documented durable PostgreSQL authority, Redis fencing, signed HA control, replication, cutover, promotion/failback, and real-service drill gates. Single-process maps and JSON file stores are not a shared authority.
5. Run real PostgreSQL/Redis integration, partition, failover, crash, serialization, ambiguous-commit, concurrent mixed-replay, binding-revision race, and audit-outbox recovery tests against the exact release candidate.
6. Run BPC and TSK native suites and JavaScript/TypeScript interoperability vectors together with bridge adversarial tests. Verify every BPC deny/exception/malformed/stale/open-scope result, duplicate header, binding failure, and identity mismatch yields zero TSK lookup/commit calls.
7. Complete SAST, SCA, secret scanning, SBOM/provenance, artifact signing, reproducible-build/package-boundary checks, load/fault testing, independent security review, incident-response exercise, source-license decision, and release governance. CI/release credentials must be short-lived, least-privilege, isolated from pull-request jobs, and independently rotatable.

The current Axum adapter invokes synchronous dependencies on its async reactor; bounded blocking-executor/offloading integration is required before attaching the PostgreSQL authority. Database statement/TCP limits alone are not an end-to-end request deadline.

Until every item is evidenced and approved, use the existing production reference implementations for deployments. Do not call this composition an encryption primitive or production-ready service.
