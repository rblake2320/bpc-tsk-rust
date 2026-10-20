# 2026 security baseline for TSK, BPC, and the composition service

This document records threat-driven release requirements extracted from confirmed 2026 security disclosures. It is a design and test input, not a claim that any component is production-ready.

## Developer-tool and localhost-service exposure

The January 2026 OpenCode advisory describes an automatically started unauthenticated HTTP server whose shell, PTY, and file-read endpoints could be reached by local processes and, through permissive CORS, by a browser. The affected implementation allowed arbitrary command execution under the user’s privileges. A separate September disclosure describes a cross-origin upgrade-path RCE: a `text/plain` top-level form navigation reached a local endpoint that accepted JSON without enforcing its content type and passed an attacker-controlled package target to a package manager. The upstream remediation restricted the target to a semantic version and enforced the expected media type.[1] [2]

For all three Rust deliverables, this means a local listener is a networked security boundary. The service must be loopback-only by default, have no command, package-update, arbitrary URL-fetch, shell, filesystem, or administrative endpoint in the public protocol listener, and require explicit, mutually authenticated operator controls for any administration. HTTP adapters must preserve and bound raw request data, reject unsupported content types before parsing, reject duplicate security headers, set a narrow origin policy with no credentialed wildcard CORS, disable browser-hostile admin endpoints, and apply a strict URL allowlist plus DNS/IP revalidation if a future feature needs outbound fetching. There is no self-update mechanism in the protocol services.

## Linked-provider credential containment

On October 18, 2026, OpenCode disclosed an ongoing Console breach that affected a subset of Console users with linked external AI providers. The vendor had not published a root cause at the time of the technical analysis. The incident nevertheless demonstrates that provider keys kept by developer tooling have a separate blast radius and must be inventoried, scoped, rotated, and monitored.[3]

The protocol repositories must never retain AI-provider credentials, CI tokens, source-control tokens, deployment tokens, or unrelated application secrets in configuration, stores, snapshots, vectors, traces, logs, outbox records, cache entries, CI artifacts, or releases. BPC key material, BPC private P-256 keys, TSK shared credentials, bridge audit keys, and CI/release credentials remain distinct secret domains with distinct access policies and independent rotation. Any suspected developer-tool or CI compromise requires revocation/rotation of reachable credentials and a review of CI logs, source-control audit trails, and developer endpoints before release resumes.

## Supply-chain and release integrity

CISA reported that a poisoned developer extension contributed to access to internal GitHub repositories and that a distinct campaign injected malicious GitHub Action workflows to harvest CI/CD secrets, cloud credentials, and tokens. CISA recommends auditing workflow and contributor activity, rotating all reachable pipeline credentials after compromise, delaying package adoption to permit community detection, and pinning trusted versions.[4]

The March 2026 Trivy advisory shows why version tags are insufficient: compromised credentials were used to publish malicious releases, force-push action tags, and push malicious registry images. The advisory further notes that incomplete, non-atomic credential rotation can preserve attacker access. It recommends full immutable SHA pinning for GitHub Actions, signature verification, and immediate rotation of all secrets reachable by affected pipelines.[5]

OpenAI’s response to the May 2026 TanStack incident describes credential-focused exfiltration through a compromised dependency and reports hardening of CI/CD credential material, minimum package-release age controls, provenance validation, incident isolation, credential rotation, and code-signing certificate rotation.[6]

Therefore the repositories must use only immutable, full-commit-SHA GitHub Action references; have least-privilege, short-lived, environment-scoped CI tokens; keep releases manually approval-gated with separate signing authority; generate and verify SBOM/provenance attestations; build from a locked dependency graph with `--locked`; reject mutable branch/tag dependencies in production workflows; scan for secrets and vulnerable dependencies; and require review of every workflow/action change. An immutable source release must carry a signed tag plus an artifact checksum and provenance record. A suspected pipeline compromise is release-blocking until the source, workflow history, action SHAs, registry artifacts, developer endpoints, and all exposed credentials have been investigated and re-established from a known-good boundary.

## Composition-specific requirements

The bridge always captures a bounded immutable request snapshot, denies duplicate security headers, runs BPC first against exact raw method/path/query/body bytes, requires a fresh closed-scope BPC result with concrete pair and principal identities, resolves a durable active server-controlled binding, then compares the BPC-bound, binding-bound, and request-supplied TSK IDs byte-for-byte before any TSK lookup or HOTP commit. BPC denial, exception, malformed/future/stale/mutable/open-scope result, binding error, duplicate header, or identity mismatch must deny without TSK state consumption. A BPC nonce or TSK HOTP value already consumed by a later-denied request is never rolled back or retried.

The bridge stores no TSK shared secret and no BPC signing or private-key material. It emits only bounded secret-free audit events with a correlation ID and a domain-separated keyed request-context digest. It never describes the combination as "ultra encryption"; confidentiality is a separate TLS 1.3 and storage-encryption/key-management design.

## Release gates derived from these incidents

1. CI blocks mutable action references, non-locked dependency builds, known critical dependency advisories, leaked secrets, unsigned/unattested candidate artifacts, and unreviewed workflow changes.
2. HTTP fuzz and integration tests cover duplicate/case-collision headers, body and header limits, unsupported content types, request smuggling boundaries, malformed encodings, cross-origin browser-form requests, and public/admin listener separation.
3. Protocol tests prove that every BPC failure class and identity/binding mismatch makes zero TSK store lookup or commit calls. They also prove no success acknowledgement can be emitted more than once.
4. Real PostgreSQL/Redis fault tests cover serialization failures, ambiguous commits, network partitions, replay races, revocation/rotation races, fencing continuity loss, and crash/restart reconciliation.
5. A release candidate is private and explicitly non-production until independent security review, SAST/SCA/secret scanning, full upstream compatibility, real-service HA/fault drills, signed provenance, and a documented incident-response exercise have all passed.

## References

[1]: https://github.com/advisories/GHSA-vxw4-wv6m-9hhh "OpenCode unauthenticated HTTP server arbitrary command execution advisory"
[2]: https://securitylabs.datadoghq.com/articles/opencode-upgrade-remote-code-execution/ "OpenCode upgrade endpoint remote code execution analysis"
[3]: https://www.stepsecurity.io/blog/opencode-security-breach "OpenCode Console security breach analysis"
[4]: https://www.cisa.gov/news-events/alerts/2026/05/28/supply-chain-compromises-impact-nx-console-and-github-repositories "CISA alert on developer ecosystem supply chain compromises"
[5]: https://github.com/advisories/GHSA-69fq-xp46-6x23 "Trivy ecosystem supply chain compromise advisory"
[6]: https://openai.com/index/our-response-to-the-tanstack-npm-supply-chain-attack/ "OpenAI response to TanStack npm supply chain attack"
