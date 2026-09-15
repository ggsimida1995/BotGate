use std::{convert::TryInto, fs, path::Path};

use anyhow::{bail, Context, Result};
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine,
};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::{config::LicenseConfig, unix_now};

const PREFIX: &str = "BG1";
const MAX_LIFETIME_SECS: u64 = 366 * 24 * 60 * 60;
const CLOCK_SKEW_SECS: u64 = 5 * 60;

#[derive(Debug, Clone, Deserialize)]
struct Claims {
    license_id: String,
    issued_at: u64,
    expires_at: u64,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct LicenseStatus {
    pub(crate) status: &'static str,
    pub(crate) expires_at: Option<u64>,
    pub(crate) license_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) message: Option<String>,
}

pub(crate) fn status(config: &LicenseConfig) -> LicenseStatus {
    if !config.enabled {
        return LicenseStatus {
            status: "disabled",
            expires_at: None,
            license_id: None,
            message: None,
        };
    }
    let token = match fs::read_to_string(&config.file) {
        Ok(token) => token,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return LicenseStatus {
                status: "not_activated",
                expires_at: None,
                license_id: None,
                message: None,
            };
        }
        Err(error) => {
            return LicenseStatus {
                status: "invalid",
                expires_at: None,
                license_id: None,
                message: Some(format!("无法读取许可证: {error}")),
            };
        }
    };
    match verify_token(config, token.trim()) {
        Ok(claims) if claims.expires_at > unix_now() => LicenseStatus {
            status: "active",
            expires_at: Some(claims.expires_at),
            license_id: Some(claims.license_id),
            message: None,
        },
        Ok(claims) => LicenseStatus {
            status: "expired",
            expires_at: Some(claims.expires_at),
            license_id: Some(claims.license_id),
            message: Some("许可证已过期".to_string()),
        },
        Err(error) => LicenseStatus {
            status: "invalid",
            expires_at: None,
            license_id: None,
            message: Some(error.to_string()),
        },
    }
}

pub(crate) fn activate(config: &LicenseConfig, token: &str) -> Result<LicenseStatus> {
    if !config.enabled {
        bail!("license activation is disabled")
    }
    let token = token.trim();
    let claims = verify_token(config, token)?;
    if claims.expires_at <= unix_now() {
        bail!("license has expired")
    }
    let parent = Path::new(&config.file)
        .parent()
        .filter(|path| !path.as_os_str().is_empty());
    if let Some(parent) = parent {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create license directory {}", parent.display()))?;
    }
    fs::write(&config.file, format!("{token}\n"))
        .with_context(|| format!("failed to save license {}", config.file))?;
    Ok(LicenseStatus {
        status: "active",
        expires_at: Some(claims.expires_at),
        license_id: Some(claims.license_id),
        message: None,
    })
}

fn verify_token(config: &LicenseConfig, token: &str) -> Result<Claims> {
    let mut parts = token.split('.');
    let Some(prefix) = parts.next() else {
        bail!("invalid license key")
    };
    let Some(payload_encoded) = parts.next() else {
        bail!("invalid license key")
    };
    let Some(signature_encoded) = parts.next() else {
        bail!("invalid license key")
    };
    if prefix != PREFIX || parts.next().is_some() {
        bail!("invalid license key format")
    }
    let payload = decode(payload_encoded).context("invalid license payload")?;
    let signature_bytes = decode(signature_encoded).context("invalid license signature")?;
    let public_key_bytes =
        decode(config.public_key.trim()).context("invalid license public key")?;
    let public_key: [u8; 32] = public_key_bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("license public key must be 32 bytes"))?;
    let verifying_key =
        VerifyingKey::from_bytes(&public_key).context("invalid license public key")?;
    let signature = Signature::from_slice(&signature_bytes).context("invalid license signature")?;
    verifying_key
        .verify(&payload, &signature)
        .context("license signature verification failed")?;
    let claims: Claims = serde_json::from_slice(&payload).context("invalid license claims")?;
    let now = unix_now();
    if claims.license_id.trim().is_empty() {
        bail!("license_id must not be empty")
    }
    if claims.expires_at <= claims.issued_at {
        bail!("license expiry must be after issue time")
    }
    if claims.expires_at - claims.issued_at > MAX_LIFETIME_SECS {
        bail!("license lifetime exceeds one year")
    }
    if claims.issued_at > now.saturating_add(CLOCK_SKEW_SECS) {
        bail!("license issue time is in the future")
    }
    Ok(claims)
}

fn decode(value: &str) -> Result<Vec<u8>> {
    URL_SAFE_NO_PAD
        .decode(value)
        .or_else(|_| STANDARD.decode(value))
        .context("invalid base64")
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    fn config(public_key: String, file: String) -> LicenseConfig {
        LicenseConfig {
            enabled: true,
            public_key,
            file,
        }
    }

    fn token(signing_key: &SigningKey, issued_at: u64, expires_at: u64) -> String {
        let payload = serde_json::to_vec(&serde_json::json!({
            "license_id": "test-license",
            "issued_at": issued_at,
            "expires_at": expires_at,
        }))
        .unwrap();
        let signature = signing_key.sign(&payload);
        format!(
            "BG1.{}.{}",
            URL_SAFE_NO_PAD.encode(payload),
            URL_SAFE_NO_PAD.encode(signature.to_bytes()),
        )
    }

    #[test]
    fn verifies_and_persists_a_signed_license() {
        let signing_key = SigningKey::from_bytes(&[7; 32]);
        let public_key = URL_SAFE_NO_PAD.encode(signing_key.verifying_key().to_bytes());
        let file = std::env::temp_dir().join(format!(
            "bot-gate-license-test-{}-{}.key",
            std::process::id(),
            now_seed()
        ));
        let now = unix_now();
        let config = config(public_key, file.to_string_lossy().into_owned());
        let token = token(&signing_key, now.saturating_sub(10), now + 3600);
        let result = activate(&config, &token).unwrap();
        assert_eq!(result.status, "active");
        assert_eq!(status(&config).license_id.as_deref(), Some("test-license"));
        let _ = std::fs::remove_file(file);
    }

    fn now_seed() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64
    }
}
