//! ML-DSA-65 issuer keypair used to sign denylist responses.

use crate::error::TrustError;
use saorsa_pqc::api::sig::{MlDsa, MlDsaPublicKey, MlDsaSecretKey, MlDsaVariant};
use std::path::Path;

/// Wraps the issuer's ML-DSA-65 keypair.
pub struct IssuerSigner {
    dsa: MlDsa,
    public_key: MlDsaPublicKey,
    secret_key: MlDsaSecretKey,
    /// Stable identifier tagging which key signed a response.
    pub key_id: String,
}

impl IssuerSigner {
    /// Generate a fresh keypair with the supplied id tag.
    ///
    /// # Errors
    /// Returns `TrustError::IssuerKey` on keygen failure.
    pub fn generate(key_id: impl Into<String>) -> Result<Self, TrustError> {
        let dsa = MlDsa::new(MlDsaVariant::MlDsa65);
        let (public_key, secret_key) = dsa
            .generate_keypair()
            .map_err(|e| TrustError::IssuerKey(e.to_string()))?;
        Ok(Self {
            dsa,
            public_key,
            secret_key,
            key_id: key_id.into(),
        })
    }

    /// Load a keypair from `dir/issuer.pk` + `dir/issuer.sk`, or
    /// generate a fresh one (writing it back) if either file is absent.
    ///
    /// # Errors
    /// Returns `TrustError::IssuerKey` for keygen or PK / SK parse
    /// failures, and `TrustError::Io` for filesystem failures.
    pub fn load_or_generate(dir: &Path, key_id: &str) -> Result<Self, TrustError> {
        let pk_path = dir.join("issuer.pk");
        let sk_path = dir.join("issuer.sk");
        if pk_path.exists() && sk_path.exists() {
            let pk_bytes = std::fs::read(&pk_path)?;
            let sk_bytes = std::fs::read(&sk_path)?;
            let dsa = MlDsa::new(MlDsaVariant::MlDsa65);
            let public_key = MlDsaPublicKey::from_bytes(MlDsaVariant::MlDsa65, &pk_bytes)
                .map_err(|e| TrustError::IssuerKey(format!("pk: {e}")))?;
            let secret_key = MlDsaSecretKey::from_bytes(MlDsaVariant::MlDsa65, &sk_bytes)
                .map_err(|e| TrustError::IssuerKey(format!("sk: {e}")))?;
            Ok(Self {
                dsa,
                public_key,
                secret_key,
                key_id: key_id.to_owned(),
            })
        } else {
            std::fs::create_dir_all(dir)?;
            set_dir_perms_0700(dir)?;
            let signer = Self::generate(key_id)?;
            std::fs::write(&pk_path, signer.public_key.to_bytes())?;
            write_secret(&sk_path, &signer.secret_key.to_bytes())?;
            Ok(signer)
        }
    }

    /// Sign `message`, returning the raw signature bytes.
    ///
    /// # Errors
    /// Returns `TrustError::IssuerKey` on signing failure.
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, TrustError> {
        self.dsa
            .sign(&self.secret_key, message)
            .map(|s| s.to_bytes())
            .map_err(|e| TrustError::IssuerKey(e.to_string()))
    }

    /// The signer's public key bytes (clients use this to verify denylists).
    #[must_use]
    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.public_key.to_bytes()
    }
}

/// Write the secret-key bytes to `path` with owner-only (0600) mode
/// where the filesystem supports it. Truncates any pre-existing file.
fn write_secret(path: &Path, bytes: &[u8]) -> Result<(), TrustError> {
    use std::io::Write;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path)?;
    f.write_all(bytes)?;
    Ok(())
}

/// Tighten directory permissions to owner-only (0700) on Unix.
// On non-unix the body is a no-op so clippy sees the `Result` as redundant;
// it is real on unix (the `?`s below can fail) and the signature must stay
// uniform across platforms.
#[cfg_attr(not(unix), allow(clippy::unnecessary_wraps))]
fn set_dir_perms_0700(path: &Path) -> Result<(), TrustError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(path)?.permissions();
        perms.set_mode(0o700);
        std::fs::set_permissions(path, perms)?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn generate_then_sign_self_verifies() {
        let signer = IssuerSigner::generate("test-v1").unwrap();
        let msg = b"hi";
        let sig = signer.sign(msg).unwrap();

        let dsa = MlDsa::new(MlDsaVariant::MlDsa65);
        let pk =
            MlDsaPublicKey::from_bytes(MlDsaVariant::MlDsa65, &signer.public_key_bytes()).unwrap();
        let sig_value =
            saorsa_pqc::api::sig::MlDsaSignature::from_bytes(MlDsaVariant::MlDsa65, &sig).unwrap();
        assert!(dsa.verify(&pk, msg, &sig_value).unwrap());
    }

    #[test]
    fn load_or_generate_round_trips() {
        let dir = tempdir().unwrap();
        let a = IssuerSigner::load_or_generate(dir.path(), "v1").unwrap();
        let b = IssuerSigner::load_or_generate(dir.path(), "v1").unwrap();
        assert_eq!(a.public_key_bytes(), b.public_key_bytes());
    }
}
