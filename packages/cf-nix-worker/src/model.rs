use std::fmt::Write;

use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::{Signature, Signer, SigningKey as DalekSigningKey};
use narinfo::{NarInfo, Sig};

/// Parsed Nix signing secret used to produce `.narinfo` `Sig:` entries.
///
/// This corresponds to `CF_NIX_WORKER_SECRET` in the form `<key-name>:<base64>`,
/// where the base64 decodes to 64 Ed25519 key bytes (secret + public) as emitted
/// by `nix key generate-secret`.
pub struct NarInfoSigKey {
    /// Nix signing key name (e.g. `cache.example.org-1`).
    pub key_name: String,
    /// Base64 secret key bytes (64 bytes when decoded, as emitted by `nix key generate-secret`).
    pub secret_key_b64: String,
}

impl NarInfoSigKey {
    pub fn parse(secret: &str) -> Result<Self, String> {
        // Format:
        //   <key-name>:<base64>
        // where <base64> is 64 bytes (secret + public) for Ed25519.
        let (key_name, b64) = secret.split_once(':').ok_or_else(|| {
            "CF_NIX_WORKER_SECRET must be in the format <key-name>:<base64>".to_string()
        })?;

        let key_name = key_name.trim();
        let b64 = b64.trim();

        if key_name.is_empty() {
            return Err("CF_NIX_WORKER_SECRET key name must not be empty".to_string());
        }

        let decoded = STANDARD
            .decode(b64)
            .map_err(|_| "CF_NIX_WORKER_SECRET must contain valid base64 key bytes".to_string())?;

        if decoded.len() != 64 {
            return Err("CF_NIX_WORKER_SECRET base64 must decode to 64 bytes".to_string());
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
    /// joined by `,`.
    pub fn sign(&self, info: &NarInfo<'_>) -> Result<Sig<'static>, String> {
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

        Ok(Sig {
            key_name: self.key_name.clone().into(),
            sig: sig_b64.into(),
        })
    }
}

/// Context for validating a narinfo upload.
///
/// `hash` is taken from the request route param (without `.narinfo`).
pub struct NarInfoContext {
    pub hash: String,
}

/// Generic validation trait for domain objects.
///
/// `Validate` allows model types (e.g. `narinfo::NarInfo`) to validate themselves
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

        validate_sha256_hash_field("NarHash", &self.nar_hash)?;

        if self.nar_size == 0 {
            return Err("NarSize must be a positive integer".to_string());
        }

        // References are store path *basenames* (`<hash>-<name>`, relative to
        // /nix/store), like Deriver. Empty means no references.
        for reference in self.references.iter() {
            if reference.is_empty() {
                continue;
            }
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
        if let Some(deriver) = &self.deriver {
            let s = deriver.as_ref();
            if !s.ends_with(".drv") || s.contains('/') {
                return Err("Deriver must be a basename ending in .drv".to_string());
            }
        }

        if let Some(compression) = &self.compression {
            let compression = compression.as_ref();
            match compression {
                "xz" | "bzip2" | "zstd" | "none" => {}
                _ => return Err("Compression must be one of xz, bzip2, zstd, none".to_string()),
            }
        }

        if let Some(file_hash) = self.file_hash {
            validate_sha256_hash_field("FileHash", file_hash)?;
        }

        if let Some(file_size) = self.file_size {
            if file_size == 0 {
                return Err("FileSize must be a positive integer".to_string());
            }
        }

        Ok(())
    }
}

/// Splits the `CA:` field off a narinfo body.
///
/// Content-addressed paths (`nix store add`, fixed-output derivation outputs)
/// carry `CA: <method>:<hash>`, which the `narinfo` crate rejects as an unknown
/// key. Nix doesn't sign it, so the rest parses, validates and signs as before,
/// and `serialize_narinfo` writes it back. Returns the body without the `CA:`
/// line, and its value.
pub fn split_ca(body: &str) -> Result<(String, Option<String>), String> {
    let mut rest = String::with_capacity(body.len());
    let mut ca = None;
    for line in body.lines() {
        let Some(value) = line.strip_prefix("CA:") else {
            rest.push_str(line);
            rest.push('\n');
            continue;
        };
        if ca.is_some() {
            return Err("CA must appear at most once".to_string());
        }
        let value = value.trim();
        validate_ca(value)?;
        ca = Some(value.to_string());
    }
    Ok((rest, ca))
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

/// Serializes a narinfo and its `CA:` field, without a trailing newline.
pub fn serialize_narinfo(info: &NarInfo<'_>, ca: Option<&str>) -> String {
    let mut data = String::new();
    info.serialize_into(&mut data).unwrap();
    if let Some(ca) = ca {
        write!(data, "\nCA: {ca}").unwrap();
    }
    data
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

fn narinfo_fingerprint(info: &NarInfo<'_>) -> Result<String, String> {
    // NarHash must be sha256:<nix32> to match Nix's fingerprinting.
    let nar_hash_nix32 = nar_hash_to_nix32(&info.nar_hash)?;

    // narinfo lists references as basenames, but Nix signs their full paths.
    let refs = info
        .references
        .iter()
        .filter(|r| !r.is_empty())
        .map(|r| format!("/nix/store/{r}"))
        .collect::<Vec<_>>()
        .join(",");

    Ok(format!(
        "1;{};{};{};{}",
        info.store_path, nar_hash_nix32, info.nar_size, refs
    ))
}

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

    const TEST_KEY: &str = "cache.example.org-1:wpzRsj2Xn0OiTVS0kP0L0ecJ9tuFNH6qKlGmOb8+a51litiFcHAAMHXGekNc4Br0X6r2mF4k/eqDITsD7hSJXA==";

    /// Written and signed by Nix itself (`nix copy --to
    /// 'file://…?compression=none&secret-key=…'` with TEST_KEY), so the
    /// signature is the ground truth for a path with references.
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
    const NIX_CA_SIG: &str =
        "qNaG672O6KwKQkp4RZ6aG1jFsCyi7DsOmZtuwvHgMXuXFUpo0cBKBsGQFL2qLM6oW+9vN/Xk2/NpYle7sdq7BA==";

    fn narinfo() -> NarInfo<'static> {
        NarInfo::builder()
            .store_path("/nix/store/abc-min".into())
            .url("nar/abc.nar")
            .nar_hash("sha256-LHdODcc9LKl8TykaDMvSkpcBrXrTcP8aW2B6trJhxdE=".into())
            .nar_size(1)
            .references(vec![])
            .compression(Some("none".into()))
            .build()
            .expect("NarInfo should build")
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
        info.store_path = "/tmp/abc".into();

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
        info.compression = Some("gzip".into());

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

    #[test]
    fn signing_key_parses_name_and_secret() {
        let key = NarInfoSigKey::parse(
            TEST_KEY,
        )
        .expect("key should parse");

        assert_eq!(key.key_name, "cache.example.org-1");
        assert_eq!(
            key.secret_key_b64,
            "wpzRsj2Xn0OiTVS0kP0L0ecJ9tuFNH6qKlGmOb8+a51litiFcHAAMHXGekNc4Br0X6r2mF4k/eqDITsD7hSJXA=="
        );
    }

    #[test]
    fn sign_produces_sig_field() {
        let info = narinfo();
        let key = NarInfoSigKey::parse(
            TEST_KEY,
        )
        .expect("key should parse");

        let sig = key.sign(&info).expect("should sign");

        assert_eq!(sig.key_name, "cache.example.org-1");
        // Ed25519 signature is 64 bytes.
        let decoded = STANDARD
            .decode(sig.sig.as_ref())
            .expect("signature should be base64");
        assert_eq!(decoded.len(), 64);
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
            info.references = vec![reference.into()];
            let ctx = NarInfoContext {
                hash: "abc".to_string(),
            };
            let err = info.validate(&ctx).unwrap_err();
            assert!(err.contains("References"), "{reference}: {err}");
        }
    }

    #[test]
    fn sign_matches_nix_for_a_path_with_references() {
        let info = NarInfo::parse(NIX_SIGNED).expect("NarInfo should parse");
        let key = NarInfoSigKey::parse(TEST_KEY).expect("key should parse");
        let sig = key.sign(&info).expect("should sign");
        assert_eq!(sig.key_name, "cache.example.org-1");
        assert_eq!(sig.sig, NIX_SIG);
    }

    #[test]
    fn split_ca_extracts_ca_and_the_rest_validates() {
        let (rest, ca) = split_ca(NIX_SIGNED_CA).expect("CA should split");
        assert_eq!(ca.as_deref(), Some(NIX_CA));
        assert!(!rest.contains("CA:"));

        let info = NarInfo::parse(&rest).expect("NarInfo should parse");
        let ctx = NarInfoContext {
            hash: "2h2g7i4x6gsadn2s7vi0af6g8b24n584".to_string(),
        };
        assert_eq!(info.validate(&ctx), Ok(()));
    }

    #[test]
    fn split_ca_without_ca_keeps_the_body() {
        let (rest, ca) = split_ca(NIX_SIGNED).expect("body should split");
        assert_eq!(ca, None);
        assert_eq!(rest, NIX_SIGNED);
    }

    #[test]
    fn split_ca_rejects_bad_ca() {
        for line in [
            "CA: sha256:1yk2kns0dq14y0gny9hkg9vnzw02bgqxpqxhbaqgi1i8p7yj78rq",
            "CA: fixed:",
            "CA: fixed:r:sha256:1yk2 kns0dq14",
            "CA: text:sha256:abc\nCA: text:sha256:abc",
        ] {
            let body = format!("{NIX_SIGNED}{line}\n");
            let err = split_ca(&body).unwrap_err();
            assert!(err.contains("CA"), "{line}: {err}");
        }
    }

    #[test]
    fn serialize_narinfo_writes_ca_back() {
        let (rest, ca) = split_ca(NIX_SIGNED_CA).expect("CA should split");
        let info = NarInfo::parse(&rest).expect("NarInfo should parse");
        let data = serialize_narinfo(&info, ca.as_deref());
        assert!(data.ends_with(&format!("\nCA: {NIX_CA}")), "{data}");

        let (_, ca) = split_ca(&data).expect("serialized narinfo should split");
        assert_eq!(ca.as_deref(), Some(NIX_CA));
    }

    #[test]
    fn sign_matches_nix_for_a_content_addressed_path() {
        let (rest, _) = split_ca(NIX_SIGNED_CA).expect("CA should split");
        let info = NarInfo::parse(&rest).expect("NarInfo should parse");
        let key = NarInfoSigKey::parse(TEST_KEY).expect("key should parse");
        let sig = key.sign(&info).expect("should sign");
        assert_eq!(sig.sig, NIX_CA_SIG);
    }
}
