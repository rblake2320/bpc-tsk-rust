# CycloneDX SBOM evidence

This directory contains the all-feature dependency inventories for the two deployable composition crates at the listed source checkpoint.

| Field | Bridge core | Admission service |
|---|---:|---:|
| Source checkpoint | `47718fcc1f1bef82b5f144a6c904cfd5286bbbc0` | `47718fcc1f1bef82b5f144a6c904cfd5286bbbc0` |
| Product toolchain | Rust/Cargo 1.85.0 | Rust/Cargo 1.85.0 |
| Generator | `cargo-cyclonedx-cyclonedx 0.5.9` | `cargo-cyclonedx-cyclonedx 0.5.9` |
| Format | CycloneDX JSON 1.5; all Cargo features; all target dependency sets | CycloneDX JSON 1.5; all Cargo features; all target dependency sets |
| Components | 229 | 239 |
| File | `bridge-core-cyclonedx-all-features.json` | `service-cyclonedx-all-features.json` |
| SHA-256 | `b051821cd571461b2b32d4a840c6c9952aff24691592b835aebe33aaadce8bf5` | `3d6cf62a931280deaa0770dac6252be51f8cf85b9d85d2182ce6c8dff3915f4b` |

## Reproduction

Run only in a controlled build environment after obtaining the exact source checkpoint and its locked dependencies:

```bash
export CARGO_NET_OFFLINE=true
export SOURCE_DATE_EPOCH=1792545058
before=$(sha256sum Cargo.lock | awk '{print $1}')
cargo +1.85.0 cyclonedx --all-features --target all --format json --spec-version 1.5 --override-filename cyclonedx-all-features
mv crates/bpc-tsk-core/cyclonedx-all-features.json sbom/bridge-core-cyclonedx-all-features.json
mv crates/bpc-tsk-service/cyclonedx-all-features.json sbom/service-cyclonedx-all-features.json
test "$before" = "$(sha256sum Cargo.lock | awk '{print $1}')"
sha256sum sbom/*cyclonedx-all-features.json
```

The CycloneDX plugin does not implement Cargo's `--locked` option. Offline generation plus the post-generation `Cargo.lock` byte-identical check prevents it from updating the resolved graph. These SBOMs inventory dependencies; they are not artifact signatures or provenance attestations.
