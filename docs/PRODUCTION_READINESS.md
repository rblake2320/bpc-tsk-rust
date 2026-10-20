# Production-readiness gate

This repository is a private checkpoint. Passing its Rust unit tests or CI does not authorize a production deployment.

Before a release, all of the following must pass:

1. Replace `MemoryBindingStore` and `NoopAuditSink` with a PostgreSQL implementation that provides versioned migrations, least-privilege runtime and migrator roles, serializable binding lookup/recheck, transactional audit intent/outbox, bounded cancellation, ambiguous-commit classification, reconciliation, and external audit anchors.
2. Add the raw-body HTTP adapter. It must preserve exact BPC bytes, enforce bounded headers/body, reject duplicates before both factors, return generic public denial only, protect telemetry, and make successful TSK acknowledgement emission impossible more than once.
3. Complete the BPC authorization-fence contract so BPC revocation/rotation can be rechecked under a durable final decision. The adapter must not infer TSK identity or principal data from BPC headers.
4. Port TSK’s documented durable PostgreSQL authority, Redis fencing, signed HA control, replication, cutover, promotion/failback, and real-service drill gates. Single-process maps and JSON file stores are not a shared authority.
5. Run real PostgreSQL/Redis integration, partition, failover, crash, serialization, ambiguous-commit, concurrent mixed-replay, binding-revision race, and audit-outbox recovery tests against the exact release candidate.
6. Run BPC and TSK native suites and JavaScript/TypeScript interoperability vectors together with bridge adversarial tests. Verify every BPC deny/exception/malformed/stale/open-scope result, duplicate header, binding failure, and identity mismatch yields zero TSK lookup/commit calls.
7. Complete SAST, SCA, secret scanning, SBOM/provenance, artifact signing, reproducible-build/package-boundary checks, load/fault testing, independent security review, incident-response exercise, source-license decision, and release governance. CI/release credentials must be short-lived, least-privilege, isolated from pull-request jobs, and independently rotatable.

Until every item is evidenced and approved, use the existing production reference implementations for deployments. Do not call this composition an encryption primitive or production-ready service.
