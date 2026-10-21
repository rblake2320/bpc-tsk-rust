# CycloneDX SBOM evidence

This directory contains the all-feature dependency inventory for the bridge core.

| Field | Value |
|---|---|
| Source checkpoint | `7a61ed9819484c1f76c9bd5265cad137e761138e` |
| Product toolchain | Rust/Cargo 1.85.0 |
| Generator | `cargo-cyclonedx-cyclonedx 0.5.9` |
| Format | CycloneDX JSON 1.5; all Cargo features; all target dependency sets |
| Components | 166 |
| SHA-256 | `95d397d6df9d508af59e8675c2022ff88e1ef63986a71a53a3d099f368802dbe` |

## Reproduction

Run only in a controlled build environment after obtaining the exact source checkpoint and its locked dependencies:

```bash
export CARGO_NET_OFFLINE=true
export SOURCE_DATE_EPOCH=1792545058
cargo +1.85.0 cyclonedx --all-features --target all --format json --spec-version 1.5 --override-filename cyclonedx-all-features
# The workspace member output is crates/bpc-tsk-core/cyclonedx-all-features.json.
# Move it to sbom/cyclonedx-all-features.json and verify Cargo.lock is byte-identical.
sha256sum sbom/cyclonedx-all-features.json
```

The CycloneDX plugin does not implement Cargo's `--locked` option. Offline generation plus the post-generation `Cargo.lock` byte-identical check prevents it from updating the resolved graph. This SBOM inventories dependencies; it is not an artifact signature or provenance attestation.
