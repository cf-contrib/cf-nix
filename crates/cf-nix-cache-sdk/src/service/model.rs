//! The `.narinfo` format: parsing it the way Nix does, checking it the way the
//! Worker does before it stores an upload, and (with the `signing` feature)
//! signing it the way Nix does.
//!
//! Errors are messages for the uploader: Nix prints the body of a failed
//! upload, and the Worker puts them there.

use base64::{Engine, engine::general_purpose::STANDARD};
#[cfg(feature = "signing")]
use ed25519_dalek::{Signature, Signer, SigningKey as DalekSigningKey};

use crate::v1::{Error, ErrorCode};

impl Error {
    /// An error in the shape shared with cf-oidc-auth:
    /// `{ "error": "<code>", "message": "<reason>" }`. Nix prints the body of
    /// a failed upload, so the message says what to fix.
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            error: code,
            message: message.into(),
        }
    }
}

#[cfg(feature = "server")]
impl ErrorCode {
    /// The status an error with this code is answered with, as the spec's
    /// responses have it.
    pub fn status(&self) -> axum::http::StatusCode {
        use axum::http::StatusCode;
        match self {
            ErrorCode::BadRequest => StatusCode::BAD_REQUEST,
            ErrorCode::Unauthorized => StatusCode::UNAUTHORIZED,
            ErrorCode::Forbidden => StatusCode::FORBIDDEN,
            ErrorCode::NotFound => StatusCode::NOT_FOUND,
            ErrorCode::Misconfigured | ErrorCode::InternalError => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
            ErrorCode::UpstreamError => StatusCode::BAD_GATEWAY,
        }
    }
}

/// The error as a response outside the generated routes, such as from a
/// layer over them: its code's status, and the JSON every error has.
#[cfg(feature = "server")]
impl axum::response::IntoResponse for Error {
    fn into_response(self) -> axum::response::Response {
        (self.error.status(), axum::Json(self)).into_response()
    }
}

/// A parsed `.narinfo`, borrowing from its text.
///
/// Parsing follows Nix's own parser (`NarInfo::NarInfo` in libstore's
/// `nar-info.cc`): a value starts after `": "`, the last of a duplicate key
/// wins, `Sig` lines accumulate and unknown keys are ignored. The Worker only
/// parses to validate and sign. It stores and serves the text Nix uploaded, so
/// no field is ever dropped or reordered.
#[derive(Debug, Default, PartialEq)]
pub struct NarInfo<'a> {
    pub store_path: &'a str,
    pub url: &'a str,
    pub compression: Option<&'a str>,
    pub file_hash: Option<&'a str>,
    pub file_size: Option<u64>,
    pub nar_hash: &'a str,
    pub nar_size: u64,
    /// Store path basenames (`<hash>-<name>`). Empty when there are none.
    pub references: Vec<&'a str>,
    /// The `.drv` basename.
    pub deriver: Option<&'a str>,
    pub system: Option<&'a str>,
    /// `<key-name>:<base64>`, one per `Sig:` line.
    pub sigs: Vec<&'a str>,
    /// `text:<hash>` or `fixed:<hash>`, for content-addressed paths.
    pub ca: Option<&'a str>,
}

impl<'a> NarInfo<'a> {
    pub fn parse(text: &'a str) -> Result<Self, String> {
        let mut info = NarInfo::default();
        let (mut store_path, mut url, mut nar_hash, mut nar_size) = (None, None, None, None);

        for line in text.lines().filter(|line| !line.is_empty()) {
            let Some((key, value)) = line.split_once(':') else {
                return Err(format!("invalid narinfo line: {line}"));
            };
            let value = value.strip_prefix(' ').unwrap_or(value);
            match key {
                "StorePath" => store_path = Some(value),
                "URL" => url = Some(value),
                "Compression" => info.compression = Some(value),
                "FileHash" => info.file_hash = Some(value),
                "FileSize" => info.file_size = Some(parse_size(key, value)?),
                "NarHash" => nar_hash = Some(value),
                "NarSize" => nar_size = Some(parse_size(key, value)?),
                "References" => {
                    info.references = value.split(' ').filter(|r| !r.is_empty()).collect()
                }
                // Nix writes this when it doesn't know the deriver.
                "Deriver" => info.deriver = Some(value).filter(|d| *d != "unknown-deriver"),
                "System" => info.system = Some(value),
                "Sig" => info.sigs.push(value),
                "CA" => info.ca = Some(value),
                _ => {}
            }
        }

        let missing = |field: &str| format!("narinfo is missing {field}");
        info.store_path = store_path.ok_or_else(|| missing("StorePath"))?;
        info.url = url.ok_or_else(|| missing("URL"))?;
        info.nar_hash = nar_hash.ok_or_else(|| missing("NarHash"))?;
        info.nar_size = nar_size.ok_or_else(|| missing("NarSize"))?;
        Ok(info)
    }
}

fn parse_size(field: &str, value: &str) -> Result<u64, String> {
    value
        .parse()
        .map_err(|_| format!("{field} must be a non-negative integer"))
}

/// Appends a `Sig:` line to narinfo text, keeping everything Nix sent.
pub fn append_sig(text: &str, sig: &str) -> String {
    let mut out = String::with_capacity(text.len() + sig.len() + 7);
    out.push_str(text);
    if !out.is_empty() && !out.ends_with('\n') {
        out.push('\n');
    }
    out.push_str("Sig: ");
    out.push_str(sig);
    out.push('\n');
    out
}

/// Parsed Nix signing secret used to produce `.narinfo` `Sig:` entries.
///
/// The form is `<key-name>:<base64>`, where the base64 decodes to 64 Ed25519
/// key bytes (secret + public), as emitted by `nix key generate-secret`.
#[cfg(feature = "signing")]
pub struct NarInfoSigKey {
    /// Nix signing key name (e.g. `cache.example.org-1`).
    pub key_name: String,
    /// Base64 secret key bytes (64 bytes when decoded, as emitted by `nix key generate-secret`).
    pub secret_key_b64: String,
}

#[cfg(feature = "signing")]
impl NarInfoSigKey {
    pub fn parse(secret: &str) -> Result<Self, String> {
        // Format:
        //   <key-name>:<base64>
        // where <base64> is 64 bytes (secret + public) for Ed25519.
        let (key_name, b64) = secret
            .split_once(':')
            .ok_or_else(|| "signing key must be in the format <key-name>:<base64>".to_string())?;

        let key_name = key_name.trim();
        let b64 = b64.trim();

        if key_name.is_empty() {
            return Err("signing key name must not be empty".to_string());
        }

        let decoded = STANDARD
            .decode(b64)
            .map_err(|_| "signing key must contain valid base64 key bytes".to_string())?;

        if decoded.len() != 64 {
            return Err("signing key base64 must decode to 64 bytes".to_string());
        }

        Ok(Self {
            key_name: key_name.to_string(),
            secret_key_b64: b64.to_string(),
        })
    }

    /// Sign narinfo fields required by Nix.
    ///
    /// Nix signs the fingerprint:
    /// `1;<StorePath>;<NarHash>;<NarSize>;<References>`
    /// where `NarHash` is in Nix-base32 format (not SRI/base64), and references are
    /// joined by `,`. Returns the `Sig:` value, `<key-name>:<base64>`.
    pub fn sign(&self, info: &NarInfo<'_>) -> Result<String, String> {
        let fingerprint = narinfo_fingerprint(info)?;

        let secret_bytes = STANDARD
            .decode(&self.secret_key_b64)
            .map_err(|_| "signing key must be valid base64".to_string())?;

        let secret_bytes: [u8; 64] = secret_bytes
            .try_into()
            .map_err(|_| "signing key must decode to 64 bytes".to_string())?;

        let signing_key = DalekSigningKey::from_keypair_bytes(&secret_bytes)
            .map_err(|_| "invalid Ed25519 signing key".to_string())?;

        // `ed25519-dalek` uses Ed25519 (SHA-512) internally.
        let sig: Signature = signing_key.sign(fingerprint.as_bytes());
        let sig_b64 = STANDARD.encode(sig.to_bytes());

        Ok(format!("{}:{sig_b64}", self.key_name))
    }
}

/// Context for validating a narinfo upload.
///
/// `hash` is the store path hash the narinfo is uploaded under: the route's
/// `/<hash>.narinfo`.
pub struct NarInfoContext {
    pub hash: String,
}

/// Generic validation trait for domain objects.
///
/// `Validate` allows model types (e.g. `NarInfo`) to validate themselves
/// using additional request-specific context (route params, etc.) provided via
/// the associated `Context` type.
pub trait Validate {
    /// Extra inputs required to validate `Self`.
    type Context;

    /// Validate `self` using the provided `ctx`.
    ///
    /// Returns `Ok(())` on success, or a human-readable error message on failure.
    fn validate(&self, ctx: &Self::Context) -> Result<(), String>;
}

impl Validate for NarInfo<'_> {
    type Context = NarInfoContext;

    fn validate(&self, ctx: &Self::Context) -> Result<(), String> {
        // Required fields
        if !self.store_path.starts_with("/nix/store/") {
            return Err("StorePath must start with /nix/store/".to_string());
        }

        // Bind the narinfo to its route: the store path must start with the
        // hash from the request URL (`/<hash>.narinfo`). Prevents uploading
        // narinfo for store path B under route /A.narinfo.
        let store_path_hash_prefix = format!("/nix/store/{}-", ctx.hash);
        if !self.store_path.starts_with(&store_path_hash_prefix) {
            return Err(format!(
                "StorePath hash must match the request route ({})",
                ctx.hash
            ));
        }

        // URL must be of the form `nar/<file-hash>.nar`. The file hash is
        // distinct from the store-path hash (it's derived from the NAR bytes),
        // so we only validate shape, not equality with `ctx.hash`. Compression
        // suffixes (e.g. `.nar.xz`) are not supported by this cache.
        if !self.url.starts_with("nar/") || !self.url.ends_with(".nar") {
            return Err("URL must be of the form nar/<file-hash>.nar".to_string());
        }
        if self.url.len() <= "nar/.nar".len() {
            return Err("URL must include a non-empty file hash".to_string());
        }

        validate_sha256_hash_field("NarHash", self.nar_hash)?;

        if self.nar_size == 0 {
            return Err("NarSize must be a positive integer".to_string());
        }

        // References are store path *basenames* (`<hash>-<name>`, relative to
        // /nix/store), like Deriver. Empty means no references.
        for reference in self.references.iter() {
            if !is_store_path_basename(reference) {
                return Err(
                    "References must be space-separated store path basenames (<hash>-<name>)"
                        .to_string(),
                );
            }
        }

        // Optional fields
        // Deriver is the *basename* of the .drv (path relative to /nix/store),
        // not a full store path. See the cache.nixos.org narinfo format.
        if let Some(deriver) = self.deriver
            && (!deriver.ends_with(".drv") || deriver.contains('/'))
        {
            return Err("Deriver must be a basename ending in .drv".to_string());
        }

        if let Some(compression) = self.compression {
            match compression {
                "xz" | "bzip2" | "zstd" | "none" => {}
                _ => return Err("Compression must be one of xz, bzip2, zstd, none".to_string()),
            }
        }

        if let Some(file_hash) = self.file_hash {
            validate_sha256_hash_field("FileHash", file_hash)?;
        }

        if self.file_size == Some(0) {
            return Err("FileSize must be a positive integer".to_string());
        }

        // Content-addressed paths (`nix store add`, fixed-output derivation
        // outputs) carry CA. Nix doesn't sign it, but clients use it.
        if let Some(ca) = self.ca {
            validate_ca(ca)?;
        }

        for sig in self.sigs.iter() {
            match sig.split_once(':') {
                Some((name, value)) if !name.is_empty() && !value.is_empty() => {}
                _ => return Err("Sig must be <key-name>:<signature>".to_string()),
            }
        }

        Ok(())
    }
}

/// `CA` is `text:<hash>` or `fixed:<hash>`, where `<hash>` may carry a method
/// (`r:`, `git:`) and is any algorithm: fixed-output derivations aren't limited
/// to SHA-256.
fn validate_ca(value: &str) -> Result<(), String> {
    let hash = value
        .strip_prefix("text:")
        .or_else(|| value.strip_prefix("fixed:"));
    match hash {
        Some(hash) if !hash.is_empty() && !hash.contains(char::is_whitespace) => Ok(()),
        _ => Err("CA must be text:<hash> or fixed:<hash>".to_string()),
    }
}

/// Whether `name` is a store path basename: a 32-character Nix-base32 hash, a
/// dash, and a name of the characters Nix allows in store path names.
fn is_store_path_basename(name: &str) -> bool {
    let Some((hash, rest)) = name.split_once('-') else {
        return false;
    };
    hash.len() == 32
        && hash.bytes().all(|c| NIX32_ALPHABET.contains(&c))
        && !rest.is_empty()
        && rest
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"+-._?=".contains(&c))
}

const NIX32_ALPHABET: &[u8; 32] = b"0123456789abcdfghijklmnpqrsvwxyz";

#[cfg(feature = "signing")]
fn narinfo_fingerprint(info: &NarInfo<'_>) -> Result<String, String> {
    // NarHash must be sha256:<nix32> to match Nix's fingerprinting.
    let nar_hash_nix32 = nar_hash_to_nix32(info.nar_hash)?;

    // narinfo lists references as basenames, but Nix signs their full paths.
    let refs = info
        .references
        .iter()
        .map(|r| format!("/nix/store/{r}"))
        .collect::<Vec<_>>()
        .join(",");

    Ok(format!(
        "1;{};{};{};{}",
        info.store_path, nar_hash_nix32, info.nar_size, refs
    ))
}

#[cfg(feature = "signing")]
fn nar_hash_to_nix32(value: &str) -> Result<String, String> {
    // Accept sha256:<base32|base64> or sha256-<base64>
    let (prefix, hash) = if let Some((prefix, hash)) = value.split_once(':') {
        (prefix, hash)
    } else if let Some((prefix, hash)) = value.split_once('-') {
        (prefix, hash)
    } else {
        return Err("NarHash must be sha256:<...> or sha256-<...>".to_string());
    };

    if prefix != "sha256" {
        return Err("NarHash must start with sha256".to_string());
    }

    if hash.is_empty() {
        return Err("NarHash must include a hash value".to_string());
    }

    // Already nix32?
    let nix32_alphabet = b"0123456789abcdfghijklmnpqrsvwxyz";
    if hash.bytes().all(|c| nix32_alphabet.contains(&c)) {
        return Ok(format!("sha256:{}", hash));
    }

    // Otherwise assume base64.
    let bytes = STANDARD
        .decode(hash)
        .map_err(|_| "NarHash must be nix32 or base64".to_string())?;

    if bytes.len() != 32 {
        return Err("NarHash base64 must decode to 32 bytes".to_string());
    }

    Ok(format!("sha256:{}", encode_nix32(&bytes)))
}

#[cfg(feature = "signing")]
fn encode_nix32(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return String::new();
    }

    const CHARS: &[u8; 32] = b"0123456789abcdfghijklmnpqrsvwxyz";

    let len = (bytes.len() * 8 - 1) / 5 + 1;

    let mut out = String::with_capacity(len);

    for n in (0..len).rev() {
        let b = n * 5;
        let i = b / 8;
        let j = b % 8;

        let cur = bytes[i] as u16;
        let next = if i >= bytes.len() - 1 {
            0u16
        } else {
            bytes[i + 1] as u16
        };

        // Combine current and next byte so shifting by 8 is well-defined.
        let combined = (cur >> j) | (next << (8 - j));
        let c = (combined & 0x1f) as usize;

        out.push(CHARS[c] as char);
    }

    out
}

fn validate_sha256_hash_field(field: &str, value: &str) -> Result<(), String> {
    // Accept both common narinfo formats:
    // - "sha256:<base32>" (cache.nixos.org)
    // - "sha256-<base64>" (often emitted by tooling)
    let (prefix, hash, hint) = if let Some((prefix, hash)) = value.split_once(':') {
        (prefix, hash, "sha256:<base32> or sha256:<base64>")
    } else if let Some((prefix, hash)) = value.split_once('-') {
        (prefix, hash, "sha256-<base64>")
    } else {
        return Err(format!(
            "{field} must be sha256:<base32>, sha256:<base64>, or sha256-<base64>"
        ));
    };

    if prefix != "sha256" {
        return Err(format!("{field} must start with sha256"));
    }

    if hash.is_empty() {
        return Err(format!("{field} must include a hash value"));
    }

    // The ecosystem has both base32 and base64 representations. For ':' format we accept both.
    // For '-' format we only accept base64.
    let allow_base32 = value.contains(':');

    if allow_base32 && hash.bytes().all(|c| matches!(c, b'a'..=b'z' | b'2'..=b'7')) {
        return Ok(());
    }

    STANDARD
        .decode(hash)
        .map_err(|_| format!("{field} must be {hint}"))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The public half of the key Nix signed the fixtures below with. The
    /// secret half isn't needed: a fingerprint that Nix's signature verifies
    /// against is the one Nix signs.
    #[cfg(feature = "signing")]
    const NIX_PUBLIC_KEY: &str = "ZYrYhXBwADB1xnpDXOAa9F+q9pheJP3qgyE7A+4UiVw=";

    /// Written and signed by Nix itself (`nix copy --to
    /// 'file://…?compression=none&secret-key=…'`), so the signature is the
    /// ground truth for a path with references.
    const NIX_SIGNED: &str = "\
StorePath: /nix/store/mgc3m5ad39b84vkdrca6zd9jan5a28c2-hello-2.12.3
URL: nar/0139403halzgnamd4wcc0j80yd06sf1wb0gjn4xswh855nvrwgd6.nar
Compression: none
FileHash: sha256:0139403halzgnamd4wcc0j80yd06sf1wb0gjn4xswh855nvrwgd6
FileSize: 113096
NarHash: sha256:0139403halzgnamd4wcc0j80yd06sf1wb0gjn4xswh855nvrwgd6
NarSize: 113096
References: ls125wfdax9gk2ryq7fgzrncpi6x5v2s-libiconv-115.100.1
Deriver: lhbc5cbhqmaq5mq5171lxhkr1qf0mkbr-hello-2.12.3.drv
";
    #[cfg(feature = "signing")]
    const NIX_SIG: &str =
        "Asy0nOGVV5q3qTjAICHgn7g7Xdm8fxYPv90mmG1LhBdmgFwr8PH9nSoYNNHgCthL34dgBdnLAorV/4cJzJoiCg==";

    /// A content-addressed path (`nix store add`), written and signed by Nix
    /// the same way. It has no references, and a `CA:` line.
    const NIX_SIGNED_CA: &str = "\
StorePath: /nix/store/2h2g7i4x6gsadn2s7vi0af6g8b24n584-cf-nix-cache-ca
URL: nar/1yk2kns0dq14y0gny9hkg9vnzw02bgqxpqxhbaqgi1i8p7yj78rq.nar
Compression: none
FileHash: sha256:1yk2kns0dq14y0gny9hkg9vnzw02bgqxpqxhbaqgi1i8p7yj78rq
FileSize: 136
NarHash: sha256:1yk2kns0dq14y0gny9hkg9vnzw02bgqxpqxhbaqgi1i8p7yj78rq
NarSize: 136
References: 
CA: fixed:r:sha256:1yk2kns0dq14y0gny9hkg9vnzw02bgqxpqxhbaqgi1i8p7yj78rq
";
    const NIX_CA: &str = "fixed:r:sha256:1yk2kns0dq14y0gny9hkg9vnzw02bgqxpqxhbaqgi1i8p7yj78rq";
    #[cfg(feature = "signing")]
    const NIX_CA_SIG: &str =
        "qNaG672O6KwKQkp4RZ6aG1jFsCyi7DsOmZtuwvHgMXuXFUpo0cBKBsGQFL2qLM6oW+9vN/Xk2/NpYle7sdq7BA==";

    fn narinfo() -> NarInfo<'static> {
        NarInfo {
            store_path: "/nix/store/abc-min",
            url: "nar/abc.nar",
            nar_hash: "sha256-LHdODcc9LKl8TykaDMvSkpcBrXrTcP8aW2B6trJhxdE=",
            nar_size: 1,
            compression: Some("none"),
            ..NarInfo::default()
        }
    }

    #[test]
    fn narinfo_validate_ok_minimal() {
        let info = narinfo();
        let ctx = NarInfoContext {
            hash: "abc".to_string(),
        };
        assert!(info.validate(&ctx).is_ok());
    }

    #[test]
    fn narinfo_validate_rejects_store_path() {
        let mut info = narinfo();
        info.store_path = "/tmp/abc";

        let ctx = NarInfoContext {
            hash: "abc".to_string(),
        };
        let err = info.validate(&ctx).unwrap_err();
        assert!(err.contains("StorePath"));
    }

    #[test]
    fn narinfo_validate_accepts_url_with_distinct_file_hash() {
        // The URL's file hash is different from the store-path hash by design.
        let mut info = narinfo();
        info.url = "nar/zzz.nar";

        let ctx = NarInfoContext {
            hash: "abc".to_string(),
        };
        assert!(info.validate(&ctx).is_ok());
    }

    #[test]
    fn narinfo_validate_rejects_url_outside_nar_dir() {
        let mut info = narinfo();
        info.url = "foo/abc.nar";

        let ctx = NarInfoContext {
            hash: "abc".to_string(),
        };
        let err = info.validate(&ctx).unwrap_err();
        assert!(err.contains("URL"));
    }

    #[test]
    fn narinfo_validate_rejects_compressed_url() {
        let mut info = narinfo();
        info.url = "nar/abc.nar.xz";

        let ctx = NarInfoContext {
            hash: "abc".to_string(),
        };
        let err = info.validate(&ctx).unwrap_err();
        assert!(err.contains("URL"));
    }

    #[test]
    fn narinfo_validate_rejects_nar_size_zero() {
        let mut info = narinfo();
        info.nar_size = 0;

        let ctx = NarInfoContext {
            hash: "abc".to_string(),
        };
        let err = info.validate(&ctx).unwrap_err();
        assert!(err.contains("NarSize"));
    }

    #[test]
    fn narinfo_validate_rejects_bad_compression() {
        let mut info = narinfo();
        info.compression = Some("gzip");

        let ctx = NarInfoContext {
            hash: "abc".to_string(),
        };
        let err = info.validate(&ctx).unwrap_err();
        assert!(err.contains("Compression"));
    }

    #[test]
    fn sha256_hash_field_accepts_base32_colon_format() {
        let value = "sha256:0c8ld5yxcr6a6j63mvrqbqiy08q6f85wd74817ai7pvd5nkidcqw";
        assert!(validate_sha256_hash_field("NarHash", value).is_ok());
    }

    #[test]
    fn sha256_hash_field_rejects_invalid_base64_dash_format() {
        let value = "sha256-not_base64";
        let err = validate_sha256_hash_field("NarHash", value).unwrap_err();
        assert!(err.contains("sha256-<base64>"));
    }

    /// A made-up signing key, as `nix key generate-secret` prints it, and its
    /// public half.
    #[cfg(feature = "signing")]
    fn made_up_key() -> (String, ed25519_dalek::VerifyingKey) {
        let key = DalekSigningKey::from_bytes(&[7; 32]);
        let secret = format!("test-1:{}", STANDARD.encode(key.to_keypair_bytes()));
        (secret, key.verifying_key())
    }

    /// Checks `sig`, a `Sig:` value's base64, against the fingerprint of `info`.
    #[cfg(feature = "signing")]
    fn verify(info: &NarInfo<'_>, public_key: &ed25519_dalek::VerifyingKey, sig: &str) {
        let sig = STANDARD.decode(sig).expect("signature should be base64");
        let sig = Signature::from_slice(&sig).expect("signature should be 64 bytes");
        let fingerprint = narinfo_fingerprint(info).expect("fingerprint");
        public_key
            .verify_strict(fingerprint.as_bytes(), &sig)
            .expect("signature should verify");
    }

    #[cfg(feature = "signing")]
    fn nix_public_key() -> ed25519_dalek::VerifyingKey {
        let bytes: [u8; 32] = STANDARD.decode(NIX_PUBLIC_KEY).unwrap().try_into().unwrap();
        ed25519_dalek::VerifyingKey::from_bytes(&bytes).unwrap()
    }

    #[test]
    #[cfg(feature = "signing")]
    fn signing_key_parses_name_and_secret() {
        let (secret, _) = made_up_key();
        let key = NarInfoSigKey::parse(&secret).expect("key should parse");

        assert_eq!(key.key_name, "test-1");
        assert_eq!(
            Some(key.secret_key_b64.as_str()),
            secret.strip_prefix("test-1:")
        );
    }

    #[test]
    #[cfg(feature = "signing")]
    fn sign_produces_a_sig_the_public_key_verifies() {
        let info = narinfo();
        let (secret, public_key) = made_up_key();
        let key = NarInfoSigKey::parse(&secret).expect("key should parse");

        let sig = key.sign(&info).expect("should sign");

        let (key_name, sig) = sig.split_once(':').expect("Sig is <key-name>:<base64>");
        assert_eq!(key_name, "test-1");
        verify(&info, &public_key, sig);
    }

    #[test]
    fn narinfo_validate_accepts_nix_written_narinfo() {
        let info = NarInfo::parse(NIX_SIGNED).expect("NarInfo should parse");
        let ctx = NarInfoContext {
            hash: "mgc3m5ad39b84vkdrca6zd9jan5a28c2".to_string(),
        };
        assert_eq!(info.validate(&ctx), Ok(()));
    }

    #[test]
    fn narinfo_validate_rejects_bad_references() {
        for reference in [
            "/nix/store/ls125wfdax9gk2ryq7fgzrncpi6x5v2s-libiconv-115.100.1",
            "ls125wfdax9gk2ryq7fgzrncpi6x5v2s",
            "ls125wfdax9gk2ryq7fgzrncpi6x5v2-short-hash",
            "ls125wfdax9gk2ryq7fgzrncpi6x5v2e-not-nix32",
            "ls125wfdax9gk2ryq7fgzrncpi6x5v2s-bad/name",
        ] {
            let mut info = narinfo();
            info.references = vec![reference];
            let ctx = NarInfoContext {
                hash: "abc".to_string(),
            };
            let err = info.validate(&ctx).unwrap_err();
            assert!(err.contains("References"), "{reference}: {err}");
        }
    }

    #[test]
    #[cfg(feature = "signing")]
    fn fingerprint_matches_nix_for_a_path_with_references() {
        let info = NarInfo::parse(NIX_SIGNED).expect("NarInfo should parse");
        verify(&info, &nix_public_key(), NIX_SIG);
    }

    #[test]
    fn narinfo_validate_accepts_a_content_addressed_path() {
        let info = NarInfo::parse(NIX_SIGNED_CA).expect("NarInfo should parse");
        assert_eq!(info.ca, Some(NIX_CA));
        let ctx = NarInfoContext {
            hash: "2h2g7i4x6gsadn2s7vi0af6g8b24n584".to_string(),
        };
        assert_eq!(info.validate(&ctx), Ok(()));
    }

    #[test]
    fn narinfo_validate_rejects_bad_ca() {
        for ca in [
            "sha256:1yk2kns0dq14y0gny9hkg9vnzw02bgqxpqxhbaqgi1i8p7yj78rq",
            "fixed:",
            "fixed:r:sha256:1yk2 kns0dq14",
        ] {
            let mut info = narinfo();
            info.ca = Some(ca);
            let ctx = NarInfoContext {
                hash: "abc".to_string(),
            };
            let err = info.validate(&ctx).unwrap_err();
            assert!(err.contains("CA"), "{ca}: {err}");
        }
    }

    #[test]
    fn narinfo_validate_rejects_bad_sigs() {
        for sig in ["no-colon", ":sig", "key:"] {
            let mut info = narinfo();
            info.sigs = vec![sig];
            let ctx = NarInfoContext {
                hash: "abc".to_string(),
            };
            let err = info.validate(&ctx).unwrap_err();
            assert!(err.contains("Sig"), "{sig}: {err}");
        }
    }

    #[test]
    #[cfg(feature = "signing")]
    fn fingerprint_matches_nix_for_a_content_addressed_path() {
        let info = NarInfo::parse(NIX_SIGNED_CA).expect("NarInfo should parse");
        verify(&info, &nix_public_key(), NIX_CA_SIG);
    }

    /// Written by Nix for a path with a reference and a deriver.
    const PARSE_WITH_REFERENCES: &str = "\
StorePath: /nix/store/mgc3m5ad39b84vkdrca6zd9jan5a28c2-hello-2.12.3
URL: nar/0139403halzgnamd4wcc0j80yd06sf1wb0gjn4xswh855nvrwgd6.nar
Compression: none
FileHash: sha256:0139403halzgnamd4wcc0j80yd06sf1wb0gjn4xswh855nvrwgd6
FileSize: 113096
NarHash: sha256:0139403halzgnamd4wcc0j80yd06sf1wb0gjn4xswh855nvrwgd6
NarSize: 113096
References: ls125wfdax9gk2ryq7fgzrncpi6x5v2s-libiconv-115.100.1
Deriver: lhbc5cbhqmaq5mq5171lxhkr1qf0mkbr-hello-2.12.3.drv
Sig: cache.example.org-1:Asy0nOGVV5q3qTjAICHgn7g7Xdm8fxYPv90mmG1LhBdmgFwr8PH9nSoYNNHgCthL34dgBdnLAorV/4cJzJoiCg==
";

    #[test]
    fn parses_every_field() {
        let info = NarInfo::parse(PARSE_WITH_REFERENCES).expect("should parse");
        assert_eq!(
            info,
            NarInfo {
                store_path: "/nix/store/mgc3m5ad39b84vkdrca6zd9jan5a28c2-hello-2.12.3",
                url: "nar/0139403halzgnamd4wcc0j80yd06sf1wb0gjn4xswh855nvrwgd6.nar",
                compression: Some("none"),
                file_hash: Some("sha256:0139403halzgnamd4wcc0j80yd06sf1wb0gjn4xswh855nvrwgd6"),
                file_size: Some(113096),
                nar_hash: "sha256:0139403halzgnamd4wcc0j80yd06sf1wb0gjn4xswh855nvrwgd6",
                nar_size: 113096,
                references: vec!["ls125wfdax9gk2ryq7fgzrncpi6x5v2s-libiconv-115.100.1"],
                deriver: Some("lhbc5cbhqmaq5mq5171lxhkr1qf0mkbr-hello-2.12.3.drv"),
                system: None,
                sigs: vec![
                    "cache.example.org-1:Asy0nOGVV5q3qTjAICHgn7g7Xdm8fxYPv90mmG1LhBdmgFwr8PH9nSoYNNHgCthL34dgBdnLAorV/4cJzJoiCg=="
                ],
                ca: None,
            }
        );
    }

    #[test]
    fn parses_ca_and_system_and_empty_references() {
        let text = "StorePath: /nix/store/2h2g7i4x6gsadn2s7vi0af6g8b24n584-ca\nURL: nar/x.nar\nNarHash: sha256:x\nNarSize: 1\nReferences: \nSystem: x86_64-linux\nCA: fixed:r:sha256:x\n";
        let info = NarInfo::parse(text).expect("should parse");
        assert_eq!(info.references, Vec::<&str>::new());
        assert_eq!(info.system, Some("x86_64-linux"));
        assert_eq!(info.ca, Some("fixed:r:sha256:x"));
    }

    #[test]
    fn follows_nix_for_unknown_and_duplicate_keys() {
        let text = format!(
            "{PARSE_WITH_REFERENCES}Future: anything\nNarSize: 7\nSig: other-1:abc\nDeriver: unknown-deriver\n"
        );
        let info = NarInfo::parse(&text).expect("unknown keys are ignored");
        assert_eq!(info.nar_size, 7, "the last duplicate wins");
        assert_eq!(info.sigs.len(), 2, "Sig lines accumulate");
        assert_eq!(info.deriver, None);
    }

    #[test]
    fn rejects_missing_fields_and_bad_lines() {
        for (text, expected) in [
            (
                "URL: nar/x.nar\nNarHash: sha256:x\nNarSize: 1\n",
                "StorePath",
            ),
            (
                "StorePath: /nix/store/x\nNarHash: sha256:x\nNarSize: 1\n",
                "URL",
            ),
            (
                "StorePath: /nix/store/x\nURL: nar/x.nar\nNarSize: 1\n",
                "NarHash",
            ),
            (
                "StorePath: /nix/store/x\nURL: nar/x.nar\nNarHash: sha256:x\n",
                "NarSize",
            ),
            (
                "StorePath: /nix/store/x\nURL: nar/x.nar\nNarHash: sha256:x\nNarSize: -1\n",
                "NarSize",
            ),
            ("StorePath /nix/store/x\n", "invalid narinfo line"),
        ] {
            let err = NarInfo::parse(text).unwrap_err();
            assert!(err.contains(expected), "{text:?}: {err}");
        }
    }

    #[test]
    fn append_sig_keeps_the_text() {
        assert_eq!(append_sig("A: 1\n", "k:s"), "A: 1\nSig: k:s\n");
        assert_eq!(append_sig("A: 1", "k:s"), "A: 1\nSig: k:s\n");
    }
}
