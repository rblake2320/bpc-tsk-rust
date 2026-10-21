//! Executable-level CLI rejection without authority sockets or secret disclosure.

use std::{fs, os::unix::fs::PermissionsExt, process::Command};

#[test]
fn executable_accepts_no_extra_or_inline_config_sources() {
    for args in [
        vec![],
        vec!["--help"],
        vec!["--config", "relative"],
        vec!["--dsn", "never-print-this-secret"],
        vec!["--config", "/not/opened", "--config", "/other"],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_bpc-tsk-service"))
            .args(args)
            .env("RUST_BACKTRACE", "1")
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert_eq!(output.stderr, b"config\n");
    }
}

#[test]
fn executable_rejects_bad_config_and_insecure_permissions_generically() {
    let directory = tempfile::tempdir_in(env!("CARGO_MANIFEST_DIR")).unwrap();
    let path = directory.path().join("bad.toml");
    fs::write(&path, b"credential = 'never-print-this-secret'\n").unwrap();
    for mode in [0o600, 0o644] {
        fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
        let output = Command::new(env!("CARGO_BIN_EXE_bpc-tsk-service"))
            .arg("--config")
            .arg(&path)
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert_eq!(output.stderr, b"config\n");
    }
}
