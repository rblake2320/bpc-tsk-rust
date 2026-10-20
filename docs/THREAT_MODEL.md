# Threat model

The bridge assumes an attacker can submit malformed HTTP, duplicate or case-variant headers, replay valid artifacts, race revocation against verification, steal one factor, operate from a compromised developer endpoint, or attempt to influence CI/release artifacts. It also assumes downstream business effects need their own transaction/idempotency controls.

A TSK key alone is insufficient because BPC must authenticate first. A BPC pair alone is insufficient because an active server-controlled mapping and TSK verification are also required. A principal/header assertion is not an authority source. The bridge does not protect against compromise of both factors plus the privileged binding control plane.

The implementation captures the exact BPC-bound method, path-and-query, and body bytes. It rejects authentication-header ambiguity before factor execution and uses exact byte comparison for the mapped TSK identity. It catches BPC facade panics and treats them as denial. BPC nonce or TSK HOTP consumption is intentionally irreversible after it occurs; retrying a request on an unknown outcome could weaken replay protection.

The current TSK v1 header credential is an independent second factor. It does not independently bind method/path/body, so it must not be represented as a second message signature. The bridge does not claim new confidentiality or “ultra encryption.” Use TLS 1.3 for transport and separately designed AEAD/KMS controls for data at rest.

The 2026 OpenCode disclosures and supply-chain compromises inform the delivery posture: no local listener or update endpoint is trusted merely because it is loopback; no user-controlled URL is permitted for protocol update/fetch behavior; protected services do not offer shell, file, package, or public administration endpoints; CI uses immutable action/image references and locked builds; and any developer/CI compromise triggers rotation of every reachable credential. The full incident-derived control set is retained in [SECURITY_BASELINE_2026.md](SECURITY_BASELINE_2026.md).
