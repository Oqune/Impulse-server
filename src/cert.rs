//! Certificate management for the Impulse server.
//!
//! The server uses self-signed certificates with an **ECDSA P-256** key pair.
//! Ed25519 is NOT used because Chromium's WebTransport stack (used by Android)
//! does not support Ed25519 as a TLS 1.3 signature scheme.
//! Certificates are short-lived (14 days) and rotated automatically with a
//! 2-day overlap so that clients trusting the previous fingerprint keep working
//! during the transition.
//!
//! For **TOFU (Trust On First Use)** the server exposes the SHA-256 hash of the
//! DER-encoded certificate (the same value a WebTransport client receives in
//! `serverCertificateHashes`). Scanning the QR code in the TUI lets a client
//! pin the current fingerprint before the first connection.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rcgen::{CertificateParams, KeyPair, SanType};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use tracing::{debug, info, warn};

use rustls::crypto::CryptoProvider;
use rustls::server::ResolvesServerCert;
use rustls::sign::CertifiedKey;
use wtransport::tls::rustls;

/// How long a generated certificate is valid for.
pub const CERT_VALIDITY: Duration = Duration::from_secs(60 * 60 * 24 * 14); // 14 days

/// Overlap window: a new certificate is generated this long before the old one
/// expires, so both are valid simultaneously for `OVERLAP` time.
pub const CERT_OVERLAP: Duration = Duration::from_secs(60 * 60 * 24 * 2); // 2 days

/// When to start rotating relative to expiry (mirror of [`CERT_OVERLAP`]).
const ROTATE_BEFORE_EXPIRY: Duration = CERT_OVERLAP;

/// File names used to persist the active key material on disk (PEM).
const CERT_FILE: &str = "impulse_cert.pem";
const KEY_FILE: &str = "impulse_key.pem";

/// A managed certificate: the signed DER cert, the private key (DER), its
/// validity window, the precomputed SHA-256 fingerprint used for TOFU, and the
/// PEM forms used by the QUIC/TLS stack.
#[derive(Clone)]
pub struct Cert {
    pub der: CertificateDer<'static>,
    pub key_der: Arc<Vec<u8>>,
    pub not_before: SystemTime,
    pub not_after: SystemTime,
    /// SHA-256 of the DER certificate, hex-encoded (lowercase, no separators).
    pub fingerprint: String,
    /// PEM-encoded certificate chain (single cert).
    pub pem_cert: String,
    /// PEM-encoded private key (PKCS#8).
    pub pem_key: String,
}

impl Cert {
    /// Compute the SHA-256 fingerprint of a DER certificate (TOFU hash).
    pub fn fingerprint_of(der: &CertificateDer<'static>) -> String {
        let mut hasher = Sha256::new();
        hasher.update(der.as_ref());
        let digest = hasher.finalize();
        digest.iter().map(|b| format!("{:02x}", b)).collect()
    }

    /// The SHA-256 fingerprint as raw 32 bytes (TOFU hash), matching what a
    /// WebTransport client receives in `serverCertificateHashes`.
    pub fn fingerprint_bytes_of(der: &CertificateDer<'static>) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(der.as_ref());
        let digest = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest);
        out
    }

    /// Convert the fingerprint into a human-friendly grouped form, e.g.
    /// `ab:cd:ef:...` for display in the TUI.
    pub fn fingerprint_grouped(&self) -> String {
        self.fingerprint
            .as_bytes()
            .chunks(2)
            .map(|c| std::str::from_utf8(c).unwrap_or("??"))
            .collect::<Vec<_>>()
            .join(":")
    }

    /// The SHA-256 fingerprint as raw 32 bytes (TOFU hash), matching the value a
    /// WebTransport client verifies against `serverCertificateHashes`.
    pub fn fingerprint_bytes(&self) -> [u8; 32] {
        Self::fingerprint_bytes_of(&self.der)
    }

    /// Seconds remaining until this certificate expires.
    pub fn expires_in(&self) -> u64 {
        self.not_after
            .duration_since(SystemTime::now())
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    /// Whether this certificate should be rotated now (expired or within the
    /// overlap window before expiry).
    pub fn needs_rotation(&self) -> bool {
        let now = SystemTime::now();
        if now >= self.not_after {
            return true;
        }
        match self.not_after.checked_sub(ROTATE_BEFORE_EXPIRY) {
            Some(threshold) => now >= threshold,
            None => true,
        }
    }

    /// Build a rustls [`CertifiedKey`] (cert chain + signing key) for this
    /// certificate, using the provided crypto provider to load the key.
    pub fn certified_key(&self, provider: &CryptoProvider) -> anyhow::Result<Arc<CertifiedKey>> {
        let key = PrivateKeyDer::try_from(self.key_der.as_ref().clone())
            .map_err(|e| anyhow::anyhow!("invalid private key DER: {}", e))?;
        let certified = CertifiedKey::from_der(vec![self.der.clone()], key, provider)
            .map_err(|e| anyhow::anyhow!("failed to build certified key: {}", e))?;
        Ok(Arc::new(certified))
    }
}

/// Owns the current (and during overlap, previous) certificate and is able to
/// persist/load it from disk and rotate it when required.
pub struct CertManager {
    dir: PathBuf,
    current: Cert,
    /// Previous certificate kept during the overlap window, so already-connected
    /// clients continue to validate.
    previous: Option<Cert>,
    san: Vec<String>,
}

impl CertManager {
    /// Load a previously persisted certificate, or generate a fresh one.
    pub fn load_or_create(dir: &Path, san: Vec<String>) -> anyhow::Result<Self> {
        let dir = if dir.is_absolute() {
            dir.to_path_buf()
        } else if let Ok(exe) = std::env::current_exe()
            && let Some(parent) = exe.parent()
        {
            parent.join(dir)
        } else {
            dir.to_path_buf()
        };

        std::fs::create_dir_all(&dir)?;

        let cert_path = dir.join(CERT_FILE);
        let key_path = dir.join(KEY_FILE);

        if cert_path.exists() && key_path.exists() {
            match Self::load_from_disk(&cert_path, &key_path) {
                Ok(cert) => {
                    info!(
                        "Loaded persisted certificate (expires in {}s)",
                        cert.expires_in()
                    );
                    // If the loaded cert is already near expiry, rotate immediately.
                    let current = if cert.needs_rotation() {
                        warn!("Persisted certificate needs rotation, generating fresh one");
                        Self::generate(&dir, &san)?
                    } else {
                        cert
                    };
                    return Ok(Self {
                        dir: dir.clone(),
                        current,
                        previous: None,
                        san,
                    });
                }
                Err(e) => warn!("Failed to load persisted certificate ({}), regenerating", e),
            }
        }

        let current = Self::generate(&dir, &san)?;
        Ok(Self {
            dir,
            current,
            previous: None,
            san,
        })
    }

    fn load_from_disk(cert_path: &Path, key_path: &Path) -> anyhow::Result<Cert> {
        let pem_cert = std::fs::read_to_string(cert_path)?;
        let pem_key = std::fs::read_to_string(key_path)?;

        let der = rustls_pki_types::CertificateDer::from_pem_slice(pem_cert.as_bytes())
            .map_err(|e| anyhow::anyhow!("invalid cert PEM: {}", e))?;
        let key = rustls_pki_types::PrivateKeyDer::from_pem_slice(pem_key.as_bytes())
            .map_err(|e| anyhow::anyhow!("invalid key PEM: {}", e))?;
        let key_der = Arc::new(key.secret_der().to_vec());

        let (not_before, not_after) = parse_validity(&der)
            .unwrap_or_else(|| (SystemTime::now(), SystemTime::now() + CERT_VALIDITY));

        let fingerprint = Cert::fingerprint_of(&der);
        Ok(Cert {
            der,
            key_der,
            not_before,
            not_after,
            fingerprint,
            pem_cert,
            pem_key,
        })
    }

    /// Generate a brand-new Ed25519 self-signed certificate and persist it.
    fn generate(dir: &Path, san: &[String]) -> anyhow::Result<Cert> {
        let now = SystemTime::now();
        let not_before: OffsetDateTime = to_offset(now);
        let not_after: OffsetDateTime = to_offset(now + CERT_VALIDITY);

        let mut params = CertificateParams::new(vec!["impulse.local".to_string()])?;
        params.not_before = not_before;
        params.not_after = not_after;

        // SANs: always localhost + loopback, plus user-provided.
        let mut sans: Vec<SanType> = Vec::new();
        sans.push(SanType::DnsName("localhost".try_into()?));
        sans.push(SanType::IpAddress("127.0.0.1".parse()?));
        for extra in san {
            if let Ok(ip) = extra.parse::<std::net::IpAddr>() {
                sans.push(SanType::IpAddress(ip));
            } else if let Ok(dns) = extra.as_str().try_into() {
                sans.push(SanType::DnsName(dns));
            }
        }
        params.subject_alt_names = sans;

        // ECDSA P-256 key pair. Chromium's WebTransport (used by Android) does
        // NOT support Ed25519 as a TLS 1.3 signature scheme, so we use P-256
        // which is universally supported across all WebTransport clients.
        let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
        let cert = params.self_signed(&key_pair)?;

        let der: CertificateDer<'static> = cert.der().clone();
        let pem_cert = cert.pem();
        let pem_key = key_pair.serialize_pem();

        let key_der = Arc::new(key_pair.serialize_der());
        let fingerprint = Cert::fingerprint_of(&der);

        std::fs::write(dir.join(CERT_FILE), &pem_cert)?;
        let key_path = dir.join(KEY_FILE);
        std::fs::write(&key_path, &pem_key)?;
        // Restrict the private key so only the current process/user can read the
        // signing material (E5). On Unix we use POSIX mode 0600; on Windows we
        // rewrite the DACL to grant access only to the current user.
        if let Err(e) = Self::restrict_key_permissions(&key_path) {
            warn!("Failed to restrict private key permissions: {}", e);
        }
        info!(
            "Generated new ECDSA P-256 certificate (valid {}s, fp={})",
            not_after.unix_timestamp() - not_before.unix_timestamp(),
            &fingerprint[..16]
        );

        Ok(Cert {
            der,
            key_der,
            not_before: now,
            not_after: now + CERT_VALIDITY,
            fingerprint,
            pem_cert,
            pem_key,
        })
    }

    /// Restrict the private key file so that only the current user/process can
    /// read it. On Unix this sets POSIX mode `0600`; on Windows it rewrites the
    /// file's DACL to grant access exclusively to the current user (E5).
    fn restrict_key_permissions(path: &Path) -> anyhow::Result<()> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perm = std::fs::Permissions::from_mode(0o600);
            std::fs::set_permissions(path, perm)?;
            return Ok(());
        }

        #[cfg(windows)]
        {
            restrict_key_permissions_windows(path)
        }

        #[cfg(not(any(unix, windows)))]
        {
            let _ = path;
            Ok(())
        }
    }

    /// Return the resolved (absolute) directory where the certificate/key
    /// material is persisted. Used by the server to locate the PEM files.
    pub fn cert_dir(&self) -> &std::path::Path {
        &self.dir
    }

    /// Return the active certificate.
    pub fn current(&self) -> &Cert {
        &self.current
    }

    /// Return the previous certificate, if one is retained during the overlap
    /// window. Used by the TUI to indicate an active rotation.
    pub fn previous(&self) -> Option<&Cert> {
        self.previous.as_ref()
    }

    /// Rotate if necessary. When rotating, the current cert is moved to
    /// `previous` (kept until it fully expires) and a new one is generated.
    pub fn maybe_rotate(&mut self) -> bool {
        if !self.current.needs_rotation() {
            return false;
        }
        match Self::generate(&self.dir, &self.san) {
            Ok(new_cert) => {
                self.previous = self
                    .previous
                    .take()
                    .filter(|c| c.not_after > SystemTime::now());
                self.previous = Some(std::mem::replace(&mut self.current, new_cert));
                info!(
                    "Rotated certificate, new fp={}",
                    &self.current.fingerprint[..16]
                );
                true
            }
            Err(e) => {
                warn!("Certificate rotation failed: {}", e);
                false
            }
        }
    }

    /// Expire the previous certificate once it is fully past its validity.
    pub fn prune_previous(&mut self) {
        if let Some(prev) = &self.previous
            && prev.not_after <= SystemTime::now()
        {
            self.previous = None;
            debug!("Pruned expired previous certificate");
        }
    }

    /// Build a [`rustls::ServerConfig`] backed by a [`DynamicCertResolver`].
    ///
    /// The config is wired to the `WebTransport` ALPN (`h3`) and presents the
    /// current certificate on every new handshake. Because the resolver is a
    /// shared `Arc`, swapping its inner certificate ([`DynamicCertResolver::update`])
    /// makes freshly-connecting clients immediately see a rotated certificate —
    /// no `Endpoint` recreation. Trust continuity across rotations is handled at
    /// the application layer via the `NewCertHash` (0x07) control packet.
    ///
    /// Returns the TLS config (passed to the QUIC endpoint) alongside the resolver
    /// handle, which must be retained so it can be updated on rotation.
    pub fn build_dynamic_tls_config(
        &self,
    ) -> anyhow::Result<(rustls::ServerConfig, Arc<DynamicCertResolver>)> {
        let provider = Arc::new(default_crypto_provider());
        let key = self.current.certified_key(&provider)?;
        let resolver = DynamicCertResolver::new(key)?;

        let mut tls_config = rustls::ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|e| anyhow::anyhow!("invalid TLS versions: {}", e))?
            .with_no_client_auth()
            .with_cert_resolver(resolver.clone());

        tls_config.alpn_protocols = [b"h3".to_vec()].to_vec();

        Ok((tls_config, resolver))
    }
}

/// Post-quantum hybrid TLS key exchange (X25519Kyber768) via aws-lc-rs.
/// wtransport 0.7 + rustls + aws-lc-rs handle the rest.
pub(crate) fn default_crypto_provider() -> rustls::crypto::CryptoProvider {
    rustls::crypto::aws_lc_rs::default_provider()
}

/// A [`ResolvesServerCert`] whose backing certificate can be swapped at runtime.
///
/// The QUIC/TLS stack invokes [`resolve`](ResolvesServerCert::resolve) on every
/// new handshake, so replacing the inner [`CertifiedKey`] (via
/// [`DynamicCertResolver::update`]) makes freshly-connecting clients immediately
/// see the rotated certificate — no `Endpoint` recreation required.
///
/// Trust continuity during rotation is handled at the application layer: the
/// server publishes the new SHA-256 fingerprint via the `NewCertHash` (0x07)
/// control packet and the QR code, so clients pinned to the previous fingerprint
/// learn the new one and re-pin before the old certificate expires (the 2-day
/// overlap window). The resolver therefore always presents the current
/// (`primary`) certificate.
#[derive(Debug)]
pub struct DynamicCertResolver {
    inner: std::sync::RwLock<DynamicCertState>,
}

#[derive(Debug)]
struct DynamicCertState {
    /// Current certificate (presented for all new handshakes).
    primary: Arc<CertifiedKey>,
}

impl DynamicCertResolver {
    /// Create a resolver from the initial certified key (current cert).
    pub fn new(key: Arc<CertifiedKey>) -> anyhow::Result<Arc<Self>> {
        Ok(Arc::new(Self {
            inner: std::sync::RwLock::new(DynamicCertState { primary: key }),
        }))
    }

    /// Atomically swap in the rotated certificate.
    pub fn update(&self, key: Arc<CertifiedKey>) {
        let mut guard = self.inner.write().unwrap();
        guard.primary = key;
    }
}

impl ResolvesServerCert for DynamicCertResolver {
    fn resolve(&self, _client_hello: rustls::server::ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.inner.read().unwrap().primary.clone())
    }
}

fn to_offset(t: SystemTime) -> OffsetDateTime {
    let secs = t.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() as i64;
    OffsetDateTime::from_unix_timestamp(secs).unwrap_or(OffsetDateTime::UNIX_EPOCH)
}

/// Minimal X.509 validity parser (reads notBefore/notAfter as UTCTime).
/// Returns None if the structure cannot be parsed.
fn parse_validity(der: &CertificateDer<'static>) -> Option<(SystemTime, SystemTime)> {
    let bytes = der.as_ref();
    let mut times: Vec<SystemTime> = Vec::new();
    let mut i = 0;
    while i + 1 < bytes.len() {
        if bytes[i] == 0x17 || bytes[i] == 0x18 {
            let len = bytes[i + 1] as usize;
            if i + 2 + len <= bytes.len() {
                let slice = &bytes[i + 2..i + 2 + len];
                if let Some(t) = parse_x509_time(slice) {
                    times.push(t);
                    if times.len() == 2 {
                        break;
                    }
                }
            }
        }
        i += 1;
    }
    if times.len() == 2 {
        Some((times[0], times[1]))
    } else {
        None
    }
}

fn parse_x509_time(b: &[u8]) -> Option<SystemTime> {
    let s = std::str::from_utf8(b).ok()?;
    if !s.ends_with('Z') {
        return None;
    }
    let digits = &s[..s.len() - 1];
    let (year, rest): (i32, &str) = if digits.len() == 12 {
        let yy: i32 = digits[0..2].parse().ok()?;
        let year = if yy >= 50 { 1900 + yy } else { 2000 + yy };
        (year, &digits[2..])
    } else if digits.len() == 14 {
        let yyyy: i32 = digits[0..4].parse().ok()?;
        (yyyy, &digits[4..])
    } else {
        return None;
    };
    let mo: u32 = rest[0..2].parse().ok()?;
    let day: u32 = rest[2..4].parse().ok()?;
    let h: u32 = rest[4..6].parse().ok()?;
    let mi: u32 = rest[6..8].parse().ok()?;
    let s: u32 = rest[8..10].parse().ok()?;

    let days = days_from_civil(year, mo, day)?;
    let secs = days * 86400 + h as i64 * 3600 + mi as i64 * 60 + s as i64;
    Some(UNIX_EPOCH + Duration::from_secs(secs as u64))
}

/// Howard Hinnant's civil-date -> days since 1970-01-01 algorithm.
fn days_from_civil(y: i32, m: u32, d: u32) -> Option<i64> {
    let y = y as i64;
    let m = m as i64;
    let d = d as i64;
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719468;
    if days < 0 { None } else { Some(days) }
}

/// Replace the DACL of `path` with one that grants only the current user full
/// control, removing any inherited/other-account entries (E5, Windows).
///
/// Uses `icacls.exe` (always present on Windows) to (1) disable inheritance and
/// (2) grant the current user exclusive `(F)` access, which leaves no other
/// local account able to read the private key.
#[cfg(windows)]
fn restrict_key_permissions_windows(path: &Path) -> anyhow::Result<()> {
    let path_str = path
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("non-UTF-8 key path"))?;

    // /inheritance:r removes all inherited ACEs; (F) grants the current user
    // full control and becomes the only entry in the DACL.
    let status = std::process::Command::new("icacls")
        .arg(path_str)
        .arg("/inheritance:r")
        .arg("/grant:r")
        .arg(format!("{}:(F)", whoami_user()?))
        .status()
        .map_err(|e| anyhow::anyhow!("failed to spawn icacls: {}", e))?;

    if !status.success() {
        return Err(anyhow::anyhow!("icacls failed with status {}", status));
    }
    Ok(())
}

/// Best-effort resolve the current user account in `DOMAIN\user` form for
/// `icacls`. Falls back to the `USERNAME` env var if the `whoami` utility is
/// unavailable.
#[cfg(windows)]
fn whoami_user() -> anyhow::Result<String> {
    if let Ok(out) = std::process::Command::new("whoami").output()
        && out.status.success()
    {
        let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if !s.is_empty() {
            return Ok(s);
        }
    }
    std::env::var("USERNAME").map_err(|_| anyhow::anyhow!("cannot resolve current user"))
}
