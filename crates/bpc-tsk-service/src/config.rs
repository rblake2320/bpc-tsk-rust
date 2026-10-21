use std::{
    collections::HashSet,
    ffi::OsString,
    fs::File,
    io::Read,
    net::{IpAddr, SocketAddr},
    os::unix::fs::MetadataExt,
    path::{Component, Path, PathBuf},
    time::Duration,
};

use rustix::fs::{Mode, OFlags, open, openat};
use rustls::pki_types::{
    CertificateDer, PrivateKeyDer,
    pem::{SectionKind, SliceIter},
};
use serde::Deserialize;
use zeroize::Zeroizing;

use crate::ServiceError;

type Result<T> = std::result::Result<T, ServiceError>;

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Config {
    pub listener: SocketAddr,
    pub max_method_bytes: usize,
    pub max_header_count: usize,
    pub max_header_bytes: usize,
    pub max_body_bytes: usize,
    pub max_concurrency: usize,
    pub blocking_admission: usize,
    pub max_blocking_threads: usize,
    pub worker_threads: usize,
    pub request_timeout_ms: u64,
    pub drain_timeout_ms: u64,
    pub startup_timeout_ms: u64,
    pub bpc: Database,
    pub tsk: Database,
    pub bridge: Database,
    pub audit_key_file: PathBuf,
    pub redis: Redis,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Database {
    pub dsn_file: PathBuf,
    pub ca_file: PathBuf,
    pub schema: String,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Redis {
    pub endpoint_file: PathBuf,
    pub ca_file: PathBuf,
    pub client_certificate_file: Option<PathBuf>,
    pub client_key_file: Option<PathBuf>,
    pub namespace: String,
    pub epoch: String,
    pub signature_window_ms: u64,
    pub command_timeout_ms: u64,
}

pub(crate) struct Secrets {
    pub bpc_dsn: Zeroizing<String>,
    pub tsk_dsn: Zeroizing<String>,
    pub bridge_dsn: Zeroizing<String>,
    pub redis_endpoint: Zeroizing<String>,
    pub bpc_ca: Vec<u8>,
    pub tsk_ca: Vec<u8>,
    pub bridge_ca_der: Vec<u8>,
    pub redis_ca: Vec<u8>,
    pub client_certificate: Option<Vec<u8>>,
    pub client_key: Option<Zeroizing<Vec<u8>>>,
    pub audit_key: Zeroizing<[u8; 32]>,
}

pub(crate) fn command(args: impl IntoIterator<Item = OsString>) -> Result<PathBuf> {
    let mut args = args.into_iter();
    if args.next().as_deref() != Some(std::ffi::OsStr::new("--config")) {
        return Err(ServiceError("config"));
    }
    let path = args
        .next()
        .map(PathBuf::from)
        .ok_or(ServiceError("config"))?;
    if !path.is_absolute() || args.next().is_some() {
        return Err(ServiceError("config"));
    }
    Ok(path)
}

/// Walk pinned directory descriptors; O_NOFOLLOW applies to every component.
/// No pathname reopen or canonicalize/open race is used. Rust code is safe.
fn private_file(path: &Path, field: &'static str, maximum: usize) -> Result<Vec<u8>> {
    let failure = || ServiceError(field);
    if !path.is_absolute() {
        return Err(failure());
    }
    let mut components = path.components();
    if components.next() != Some(Component::RootDir) {
        return Err(failure());
    }
    let components: Vec<_> = components.collect();
    if components.is_empty()
        || components
            .iter()
            .any(|c| !matches!(c, Component::Normal(_)))
    {
        return Err(failure());
    }
    let flags = OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::DIRECTORY;
    let mut directory = open("/", flags, Mode::empty()).map_err(|_| failure())?;
    for component in &components[..components.len() - 1] {
        directory = openat(&directory, component.as_os_str(), flags, Mode::empty())
            .map_err(|_| failure())?;
    }
    let fd = openat(
        &directory,
        components.last().ok_or_else(failure)?.as_os_str(),
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|_| failure())?;
    let mut file = File::from(fd);
    let before = file.metadata().map_err(|_| failure())?;
    if !before.is_file()
        || before.nlink() != 1
        || before.mode() & 0o077 != 0
        || before.len() == 0
        || before.len() > maximum as u64
    {
        return Err(failure());
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take(maximum as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| failure())?;
    let after = file.metadata().map_err(|_| failure())?;
    if bytes.is_empty()
        || bytes.len() > maximum
        || bytes.len() as u64 != before.len()
        || before.len() != after.len()
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
        || before.ctime() != after.ctime()
        || before.ctime_nsec() != after.ctime_nsec()
        || after.nlink() != 1
        || after.mode() & 0o077 != 0
    {
        return Err(failure());
    }
    Ok(bytes)
}

fn text(path: &Path, field: &'static str) -> Result<Zeroizing<String>> {
    let bytes = Zeroizing::new(private_file(path, field, 8_192)?);
    let value = std::str::from_utf8(&bytes).map_err(|_| ServiceError(field))?;
    let value = value.strip_suffix('\n').unwrap_or(value);
    if value.is_empty() || value.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return Err(ServiceError(field));
    }
    Ok(Zeroizing::new(value.to_owned()))
}

fn certificate(path: &Path, field: &'static str) -> Result<(Vec<u8>, Vec<u8>)> {
    let bytes = private_file(path, field, 16_384)?;
    let items = SliceIter::<(SectionKind, Vec<u8>)>::new(&bytes)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|_| ServiceError(field))?;
    let [(SectionKind::Certificate, der)] = items.as_slice() else {
        return Err(ServiceError(field));
    };
    if bytes
        .windows(11)
        .filter(|window| *window == b"-----BEGIN ")
        .count()
        != 1
    {
        return Err(ServiceError(field));
    }
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(CertificateDer::from(der.clone()))
        .map_err(|_| ServiceError(field))?;
    Ok((bytes, der.clone()))
}

fn bounded(value: u64, maximum: u64, field: &'static str) -> Result<()> {
    if value == 0 || value > maximum {
        Err(ServiceError(field))
    } else {
        Ok(())
    }
}

fn private_address(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => ip.is_loopback() || ip.is_private(),
        IpAddr::V6(ip) => ip.is_loopback() || (ip.segments()[0] & 0xfe00 == 0xfc00),
    }
}

fn schema(value: &str, field: &'static str) -> Result<()> {
    if value.is_empty()
        || value.len() > 63
        || value == "public"
        || value.starts_with("pg_")
        || !value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
        || !value
            .bytes()
            .next()
            .is_some_and(|b| b.is_ascii_lowercase() || b == b'_')
    {
        return Err(ServiceError(field));
    }
    Ok(())
}

pub(crate) fn postgres_config(dsn: &str, field: &'static str) -> Result<postgres::Config> {
    let mut parsed = dsn
        .parse::<postgres::Config>()
        .map_err(|_| ServiceError(field))?;
    if parsed.get_hosts().len() != 1
        || !matches!(parsed.get_hosts()[0], postgres::config::Host::Tcp(_))
        || parsed.get_hostaddrs().len() > 1
        || parsed.get_options().is_some()
        || parsed.get_ssl_mode() == postgres::config::SslMode::Disable
    {
        return Err(ServiceError(field));
    }
    parsed
        .connect_timeout(Duration::from_secs(5))
        .tcp_user_timeout(Duration::from_secs(10));
    Ok(parsed)
}

impl Config {
    fn validate(&self) -> Result<()> {
        if !private_address(self.listener.ip()) || self.listener.port() == 0 {
            return Err(ServiceError("listener"));
        }
        for (value, maximum, field) in [
            (self.max_method_bytes as u64, 32, "max_method_bytes"),
            (self.max_header_count as u64, 128, "max_header_count"),
            (self.max_header_bytes as u64, 32_768, "max_header_bytes"),
            (
                self.max_body_bytes as u64,
                2 * 1024 * 1024,
                "max_body_bytes",
            ),
            (self.max_concurrency as u64, 1_024, "max_concurrency"),
            (self.blocking_admission as u64, 1_024, "blocking_admission"),
            (
                self.max_blocking_threads as u64,
                1_024,
                "max_blocking_threads",
            ),
            (self.worker_threads as u64, 64, "worker_threads"),
            (self.request_timeout_ms, 60_000, "request_timeout_ms"),
            (self.drain_timeout_ms, 120_000, "drain_timeout_ms"),
            (self.startup_timeout_ms, 120_000, "startup_timeout_ms"),
            (
                self.redis.signature_window_ms,
                300_000,
                "redis.signature_window_ms",
            ),
            (
                self.redis.command_timeout_ms,
                30_000,
                "redis.command_timeout_ms",
            ),
        ] {
            bounded(value, maximum, field)?;
        }
        if self.blocking_admission > self.max_blocking_threads {
            return Err(ServiceError("blocking_admission"));
        }
        schema(&self.bpc.schema, "bpc.schema")?;
        schema(&self.tsk.schema, "tsk.schema")?;
        schema(&self.bridge.schema, "bridge.schema")?;
        // The bridge SQL is intentionally schema-qualified, not search_path based.
        if self.bridge.schema != "bpc_tsk_bridge" {
            return Err(ServiceError("bridge.schema"));
        }
        if self.bpc.schema == self.tsk.schema || self.bpc.schema == self.bridge.schema {
            return Err(ServiceError("bpc.schema"));
        }
        if self.tsk.schema == self.bridge.schema {
            return Err(ServiceError("tsk.schema"));
        }
        let mut governed = bpc_protocol::GovernedRedisNonceConfig::new(
            &self.redis.namespace,
            &self.redis.epoch,
            self.redis.signature_window_ms,
        )
        .map_err(|_| ServiceError("redis.namespace"))?;
        governed.command_timeout = Duration::from_millis(self.redis.command_timeout_ms);
        governed
            .validate()
            .map_err(|_| ServiceError("redis.epoch"))?;
        if self.redis.client_certificate_file.is_some() != self.redis.client_key_file.is_some() {
            return Err(ServiceError("redis.client_key_file"));
        }
        let paths = [
            (&self.bpc.dsn_file, "bpc.dsn_file"),
            (&self.tsk.dsn_file, "tsk.dsn_file"),
            (&self.bridge.dsn_file, "bridge.dsn_file"),
            (&self.bpc.ca_file, "bpc.ca_file"),
            (&self.tsk.ca_file, "tsk.ca_file"),
            (&self.bridge.ca_file, "bridge.ca_file"),
            (&self.redis.endpoint_file, "redis.endpoint_file"),
            (&self.redis.ca_file, "redis.ca_file"),
            (&self.audit_key_file, "audit_key_file"),
        ];
        let mut unique = HashSet::new();
        for (path, field) in paths
            .into_iter()
            .chain(
                self.redis
                    .client_certificate_file
                    .as_ref()
                    .map(|p| (p, "redis.client_certificate_file")),
            )
            .chain(
                self.redis
                    .client_key_file
                    .as_ref()
                    .map(|p| (p, "redis.client_key_file")),
            )
        {
            if !path.is_absolute() || !unique.insert(path) {
                return Err(ServiceError(field));
            }
        }
        Ok(())
    }

    pub(crate) fn load(path: &Path) -> Result<(Self, Secrets)> {
        let config_bytes = private_file(path, "config", 65_536)?;
        let config_text = std::str::from_utf8(&config_bytes).map_err(|_| ServiceError("config"))?;
        let config: Self = toml::from_str(config_text).map_err(|_| ServiceError("config"))?;
        config.validate()?;
        let bpc_dsn = text(&config.bpc.dsn_file, "bpc.dsn_file")?;
        let tsk_dsn = text(&config.tsk.dsn_file, "tsk.dsn_file")?;
        let bridge_dsn = text(&config.bridge.dsn_file, "bridge.dsn_file")?;
        if *bpc_dsn == *tsk_dsn || *bpc_dsn == *bridge_dsn {
            return Err(ServiceError("bpc.dsn_file"));
        }
        if *tsk_dsn == *bridge_dsn {
            return Err(ServiceError("tsk.dsn_file"));
        }
        postgres_config(&bpc_dsn, "bpc.dsn_file")?;
        postgres_config(&tsk_dsn, "tsk.dsn_file")?;
        postgres_config(&bridge_dsn, "bridge.dsn_file")?;
        let redis_endpoint = text(&config.redis.endpoint_file, "redis.endpoint_file")?;
        let url =
            url::Url::parse(&redis_endpoint).map_err(|_| ServiceError("redis.endpoint_file"))?;
        if url.scheme() != "rediss"
            || url.host_str().is_none()
            || url.port() == Some(0)
            || url.fragment().is_some()
            || url.query().is_some()
            || !(url.path().is_empty()
                || url.path() == "/"
                || url
                    .path()
                    .strip_prefix('/')
                    .is_some_and(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())))
        {
            return Err(ServiceError("redis.endpoint_file"));
        }
        let (bpc_ca, _) = certificate(&config.bpc.ca_file, "bpc.ca_file")?;
        let (tsk_ca, _) = certificate(&config.tsk.ca_file, "tsk.ca_file")?;
        let (_, bridge_ca_der) = certificate(&config.bridge.ca_file, "bridge.ca_file")?;
        let (redis_ca, _) = certificate(&config.redis.ca_file, "redis.ca_file")?;
        let mut audit = Zeroizing::new(private_file(&config.audit_key_file, "audit_key_file", 32)?);
        let audit_key = Zeroizing::new(
            audit
                .as_slice()
                .try_into()
                .map_err(|_| ServiceError("audit_key_file"))?,
        );
        audit.clear();
        let client_certificate = config
            .redis
            .client_certificate_file
            .as_ref()
            .map(|p| private_file(p, "redis.client_certificate_file", 65_536))
            .transpose()?;
        let client_key = config
            .redis
            .client_key_file
            .as_ref()
            .map(|p| private_file(p, "redis.client_key_file", 65_536).map(Zeroizing::new))
            .transpose()?;
        if let (Some(cert), Some(key)) = (&client_certificate, &client_key) {
            let items = SliceIter::<(SectionKind, Vec<u8>)>::new(cert)
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(|_| ServiceError("redis.client_certificate_file"))?;
            if items.is_empty()
                || items.len() > 8
                || cert
                    .windows(11)
                    .filter(|window| *window == b"-----BEGIN ")
                    .count()
                    != items.len()
                || items
                    .iter()
                    .any(|(kind, _)| *kind != SectionKind::Certificate)
            {
                return Err(ServiceError("redis.client_certificate_file"));
            }
            let certificates = items
                .into_iter()
                .map(|(_, der)| CertificateDer::from(der))
                .collect();
            let mut keys = SliceIter::<PrivateKeyDer<'static>>::new(key);
            let private_key = keys
                .next()
                .transpose()
                .map_err(|_| ServiceError("redis.client_key_file"))?
                .ok_or(ServiceError("redis.client_key_file"))?;
            if keys.next().is_some()
                || key
                    .windows(11)
                    .filter(|window| *window == b"-----BEGIN ")
                    .count()
                    != 1
            {
                return Err(ServiceError("redis.client_key_file"));
            }
            rustls::ClientConfig::builder()
                .with_root_certificates(rustls::RootCertStore::empty())
                .with_client_auth_cert(certificates, private_key)
                .map_err(|_| ServiceError("redis.client_key_file"))?;
        }
        Ok((
            config,
            Secrets {
                bpc_dsn,
                tsk_dsn,
                bridge_dsn,
                redis_endpoint,
                bpc_ca,
                tsk_ca,
                bridge_ca_der,
                redis_ca,
                client_certificate,
                client_key,
                audit_key,
            },
        ))
    }
}

// BPC exposes a string constructor; append controlled settings using its exact
// accepted URL/keyword DSN syntax. Never format this value into diagnostics.
pub(crate) fn bounded_bpc_dsn(dsn: &str) -> Result<Zeroizing<String>> {
    let options = "-c statement_timeout=5000 -c lock_timeout=1000 -c idle_in_transaction_session_timeout=5000 -c synchronous_commit=on";
    let bounded = if dsn.starts_with("postgres://") || dsn.starts_with("postgresql://") {
        let mut url = url::Url::parse(dsn).map_err(|_| ServiceError("bpc.dsn_file"))?;
        // PostgreSQL URL queries decode percent escapes, NOT form-encoded '+'.
        let options =
            percent_encoding::utf8_percent_encode(options, percent_encoding::NON_ALPHANUMERIC);
        let prefix = url
            .query()
            .filter(|q| !q.is_empty())
            .map_or(String::new(), |q| format!("{q}&"));
        url.set_query(Some(&format!(
            "{prefix}connect_timeout=5&tcp_user_timeout=10&options={options}"
        )));
        Zeroizing::new(String::from(url))
    } else {
        Zeroizing::new(format!(
            "{dsn} connect_timeout=5 tcp_user_timeout=10 options='{options}'"
        ))
    };
    let parsed = bounded
        .parse::<postgres::Config>()
        .map_err(|_| ServiceError("bpc.dsn_file"))?;
    if parsed.get_connect_timeout() != Some(&Duration::from_secs(5))
        || parsed.get_tcp_user_timeout() != Some(&Duration::from_secs(10))
        || parsed.get_options() != Some(options)
    {
        return Err(ServiceError("bpc.dsn_file"));
    }
    Ok(bounded)
}

#[cfg(test)]
pub(crate) fn test_config() -> Config {
    toml::from_str(include_str!("../deploy/config.example.toml")).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        os::unix::fs::{PermissionsExt, symlink},
    };

    fn directory() -> tempfile::TempDir {
        tempfile::tempdir_in(env!("CARGO_MANIFEST_DIR")).unwrap()
    }
    fn put(path: &Path, data: &[u8]) {
        fs::write(path, data).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    fn fixture() -> (tempfile::TempDir, PathBuf) {
        let dir = directory();
        let example = include_str!("../deploy/config.example.toml").replace(
            "/run/credentials/bpc-tsk-service.service",
            dir.path().to_str().unwrap(),
        );
        let config = dir.path().join("config.toml");
        put(&config, example.as_bytes());
        for name in ["bpc", "tsk", "bridge"] {
            put(
                &dir.path().join(format!("{name}.dsn")),
                format!(
                    "host=localhost dbname={name} user={name} password=test-only sslmode=require"
                )
                .as_bytes(),
            );
            put(
                &dir.path().join(format!("{name}.ca.pem")),
                include_bytes!("../tests/fixtures/ca.pem"),
            );
        }
        put(
            &dir.path().join("redis.ca.pem"),
            include_bytes!("../tests/fixtures/ca.pem"),
        );
        put(
            &dir.path().join("redis.endpoint"),
            b"rediss://test-only:dummy@localhost:6380/0",
        );
        put(&dir.path().join("audit.key"), &[0x42; 32]);
        (dir, config)
    }

    #[test]
    fn command_is_exact_and_absolute() {
        let args = |v: &[&str]| v.iter().map(OsString::from).collect::<Vec<_>>();
        assert_eq!(
            command(args(&["--config", "/etc/private.toml"])).unwrap(),
            Path::new("/etc/private.toml")
        );
        for invalid in [
            vec![],
            vec!["--help"],
            vec!["--config"],
            vec!["--config", "relative"],
            vec!["--config=/secret"],
            vec!["--config", "/secret", "--config", "/other"],
            vec!["--dsn", "secret"],
            vec!["/etc/config"],
        ] {
            assert_eq!(command(args(&invalid)).unwrap_err().to_string(), "config");
        }
    }

    #[test]
    fn example_loads_all_files_without_sockets_and_exact_audit_size() {
        let (dir, path) = fixture();
        let (config, secrets) = Config::load(&path).unwrap();
        assert_eq!(config.bridge.schema, "bpc_tsk_bridge");
        assert_eq!(*secrets.audit_key, [0x42; 32]);
        put(&dir.path().join("audit.key"), &[0x42; 31]);
        assert_eq!(
            Config::load(&path).err().unwrap().to_string(),
            "audit_key_file"
        );
        put(&dir.path().join("audit.key"), &[0x42; 33]);
        assert_eq!(
            Config::load(&path).err().unwrap().to_string(),
            "audit_key_file"
        );
    }

    #[test]
    fn permissions_links_symlinks_and_nonregular_files_are_rejected() {
        let dir = directory();
        let file = dir.path().join("private");
        put(&file, b"never-return-this-secret");
        assert!(private_file(&file, "field", 32).is_ok());
        for mode in [0o640, 0o644, 0o604, 0o666, 0o601] {
            fs::set_permissions(&file, fs::Permissions::from_mode(mode)).unwrap();
            assert_eq!(
                private_file(&file, "field", 32).unwrap_err().to_string(),
                "field"
            );
        }
        fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
        let link = dir.path().join("hardlink");
        fs::hard_link(&file, &link).unwrap();
        assert!(private_file(&file, "field", 32).is_err());
        fs::remove_file(link).unwrap();
        let link = dir.path().join("symlink");
        symlink(&file, &link).unwrap();
        assert!(private_file(&link, "field", 32).is_err());
        let parent_link = dir.path().join("parent-link");
        symlink(dir.path(), &parent_link).unwrap();
        assert!(private_file(&parent_link.join("private"), "field", 32).is_err());
        assert!(private_file(dir.path(), "field", 32).is_err());
        assert!(private_file(Path::new("relative"), "field", 32).is_err());
        assert!(private_file(&dir.path().join("../private"), "field", 32).is_err());
        assert!(private_file(&file, "field", 3).is_err());
        put(&file, b"");
        assert!(private_file(&file, "field", 32).is_err());
        let (dir, config) = fixture();
        fs::set_permissions(&config, fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(Config::load(&config).err().unwrap().to_string(), "config");
        fs::set_permissions(&config, fs::Permissions::from_mode(0o600)).unwrap();
        fs::set_permissions(
            dir.path().join("bpc.dsn"),
            fs::Permissions::from_mode(0o640),
        )
        .unwrap();
        assert_eq!(
            Config::load(&config).err().unwrap().to_string(),
            "bpc.dsn_file"
        );
    }

    #[test]
    fn numeric_bounds_listener_schemas_and_governance_are_closed() {
        macro_rules! invalid {
            ($field:ident, $value:expr) => {{
                let mut c = test_config();
                c.$field = $value;
                assert!(c.validate().is_err(), stringify!($field));
            }};
        }
        for value in [0, 33] {
            invalid!(max_method_bytes, value);
        }
        for value in [0, 129] {
            invalid!(max_header_count, value);
        }
        for value in [0, 32_769] {
            invalid!(max_header_bytes, value);
        }
        for value in [0, 2 * 1024 * 1024 + 1] {
            invalid!(max_body_bytes, value);
        }
        for value in [0, 1_025] {
            invalid!(max_concurrency, value);
            invalid!(blocking_admission, value);
            invalid!(max_blocking_threads, value);
        }
        for value in [0, 65] {
            invalid!(worker_threads, value);
        }
        for value in [0, 60_001] {
            invalid!(request_timeout_ms, value);
        }
        for value in [0, 120_001] {
            invalid!(drain_timeout_ms, value);
            invalid!(startup_timeout_ms, value);
        }
        let mut c = test_config();
        c.blocking_admission = c.max_blocking_threads + 1;
        assert!(c.validate().is_err());
        for address in [
            "0.0.0.0:8080",
            "8.8.8.8:8080",
            "[::]:8080",
            "[fe80::1]:8080",
            "[::ffff:127.0.0.1]:8080",
            "127.0.0.1:0",
        ] {
            invalid!(listener, address.parse().unwrap());
        }
        for address in [
            "127.0.0.1:8080",
            "10.1.2.3:8080",
            "[::1]:8080",
            "[fd00::1]:8080",
        ] {
            let mut c = test_config();
            c.listener = address.parse().unwrap();
            assert!(c.validate().is_ok());
        }
        for value in ["public", "pg_private", "tsk;DROP", "", "1invalid"] {
            let mut c = test_config();
            c.tsk.schema = value.into();
            assert!(c.validate().is_err());
        }
        let mut c = test_config();
        c.tsk.schema = c.bpc.schema.clone();
        assert!(c.validate().is_err());
        let mut c = test_config();
        c.bpc.schema = c.bridge.schema.clone();
        assert!(c.validate().is_err());
        let mut c = test_config();
        c.bridge.schema = "other".into();
        assert!(c.validate().is_err());
        for (namespace, epoch) in [("bad{}", "ok"), ("ok", ""), ("ok", "bad/epoch")] {
            let mut c = test_config();
            c.redis.namespace = namespace.into();
            c.redis.epoch = epoch.into();
            assert!(c.validate().is_err());
        }
        let mut c = test_config();
        c.redis.client_key_file = Some("/key".into());
        assert!(c.validate().is_err());
        let mut c = test_config();
        c.audit_key_file = c.bpc.dsn_file.clone();
        assert!(c.validate().is_err());
    }

    #[test]
    fn secret_values_and_dsn_parsing_fail_with_only_field_names() {
        let (dir, config) = fixture();
        let bpc = fs::read(dir.path().join("bpc.dsn")).unwrap();
        put(&dir.path().join("tsk.dsn"), &bpc);
        assert_eq!(
            Config::load(&config).err().unwrap().to_string(),
            "bpc.dsn_file"
        );
        put(&dir.path().join("tsk.dsn"), b"host=localhost dbname=tsk");
        for endpoint in [
            "redis://secret@localhost/0",
            "rediss://secret@localhost/0#insecure",
            "rediss://secret@localhost/0?insecure=true",
        ] {
            put(&dir.path().join("redis.endpoint"), endpoint.as_bytes());
            assert_eq!(
                Config::load(&config).err().unwrap().to_string(),
                "redis.endpoint_file"
            );
        }
        for dsn in [
            "host=/tmp user=secret",
            "host=one,two",
            "host=localhost sslmode=disable",
            "host=localhost options='-c role=secret'",
            "secret-invalid",
        ] {
            assert_eq!(
                postgres_config(dsn, "dsn_file").unwrap_err().to_string(),
                "dsn_file"
            );
        }
        for dsn in [
            "host=localhost user=test-only password=dummy",
            "postgresql://test-only:dummy@localhost/test",
        ] {
            let bounded = bounded_bpc_dsn(dsn).unwrap();
            let config: postgres::Config = bounded.parse().unwrap();
            assert_eq!(config.get_connect_timeout(), Some(&Duration::from_secs(5)));
            assert_eq!(
                config.get_tcp_user_timeout(),
                Some(&Duration::from_secs(10))
            );
        }
        let (dir, config) = fixture();
        let mut value = fs::read_to_string(&config).unwrap();
        value.push_str("\nunknown_secret = 'not-logged'\n");
        put(&config, value.as_bytes());
        assert_eq!(Config::load(&config).err().unwrap().to_string(), "config");
        drop(dir);
    }
}

#[cfg(test)]
mod mtls_tests {
    use super::*;
    use std::{fs, os::unix::fs::PermissionsExt};

    #[test]
    fn configured_mtls_material_is_rejected_before_construction() {
        let dir = tempfile::tempdir_in(env!("CARGO_MANIFEST_DIR")).unwrap();
        let put = |name: &str, bytes: &[u8]| {
            let path = dir.path().join(name);
            fs::write(&path, bytes).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        };
        let mut example = include_str!("../deploy/config.example.toml").replace(
            "/run/credentials/bpc-tsk-service.service",
            dir.path().to_str().unwrap(),
        );
        example.push_str(&format!(
            "\nclient_certificate_file = '{}'\nclient_key_file = '{}'\n",
            dir.path().join("client.pem").display(),
            dir.path().join("client.key").display()
        ));
        put("config.toml", example.as_bytes());
        for name in ["bpc", "tsk", "bridge"] {
            put(
                &format!("{name}.dsn"),
                format!("host=localhost dbname={name} user={name}").as_bytes(),
            );
            put(
                &format!("{name}.ca.pem"),
                include_bytes!("../tests/fixtures/ca.pem"),
            );
        }
        put("redis.endpoint", b"rediss://localhost:6380/0");
        put("redis.ca.pem", include_bytes!("../tests/fixtures/ca.pem"));
        put("audit.key", &[1; 32]);
        put("client.pem", include_bytes!("../tests/fixtures/ca.pem"));
        put("client.key", b"not-a-private-key");
        assert_eq!(
            Config::load(&dir.path().join("config.toml"))
                .err()
                .unwrap()
                .to_string(),
            "redis.client_key_file"
        );
        let cert = include_bytes!("../tests/fixtures/ca.pem");
        put("client.pem", &cert.repeat(9));
        assert_eq!(
            Config::load(&dir.path().join("config.toml"))
                .err()
                .unwrap()
                .to_string(),
            "redis.client_certificate_file"
        );
    }
}
