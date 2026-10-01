use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::{Signature, Signer, SigningKey as DalekSigningKey};
use narinfo::{NarInfo, Sig};

/// Parsed Nix signing secret used to produce `.narinfo` `Sig:` entries.
///
/// This corresponds to `CF_NIX_CACHE_SECRET` in the form `<key-name>:<base64>`,
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
            "CF_NIX_CACHE_SECRET must be in the format <key-name>:<base64>".to_string()
        })?;

        let key_name = key_name.trim();
        let b64 = b64.trim();

        if key_name.is_empty() {
            return Err("CF_NIX_CACHE_SECRET key name must not be empty".to_string());
        }

        let decoded = STANDARD
            .decode(b64)
            .map_err(|_| "CF_NIX_CACHE_SECRET must contain valid base64 key bytes".to_string())?;

        if decoded.len() != 64 {
            return Err("CF_NIX_CACHE_SECRET base64 must decode to 64 bytes".to_string());
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

        // References: allow empty, but if present each entry must look like a store path.
        for reference in self.references.iter() {
            if reference.is_empty() {
                continue;
            }
            if !reference.starts_with("/nix/store/") {
                return Err("References must be space-separated store paths".to_string());
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

fn narinfo_fingerprint(info: &NarInfo<'_>) -> Result<String, String> {
    // NarHash must be sha256:<nix32> to match Nix's fingerprinting.
    let nar_hash_nix32 = nar_hash_to_nix32(&info.nar_hash)?;

    let refs = info
        .references
        .iter()
        .map(|r| r.as_ref())
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
            "cache.example.org-1:wpzRsj2Xn0OiTVS0kP0L0ecJ9tuFNH6qKlGmOb8+a51litiFcHAAMHXGekNc4Br0X6r2mF4k/eqDITsD7hSJXA==",
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
            "cache.example.org-1:wpzRsj2Xn0OiTVS0kP0L0ecJ9tuFNH6qKlGmOb8+a51litiFcHAAMHXGekNc4Br0X6r2mF4k/eqDITsD7hSJXA==",
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
}
