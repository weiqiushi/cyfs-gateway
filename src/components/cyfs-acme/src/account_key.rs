use anyhow::Result;
use base64::Engine;
use rand08::rngs::OsRng;
use rsa::RsaPrivateKey;
use rsa::pkcs1v15::SigningKey;
use rsa::pkcs8::{DecodePrivateKey, EncodePrivateKey, LineEnding};
use rsa::signature::{SignatureEncoding, Signer};
use rsa::traits::PublicKeyParts;
use sha2::{Digest, Sha256};

#[derive(Clone)]
pub(crate) struct AcmeAccountKey {
    key: RsaPrivateKey,
}

impl AcmeAccountKey {
    pub(crate) fn generate_rsa2048() -> Result<Self> {
        let mut rng = OsRng;
        let key = RsaPrivateKey::new(&mut rng, 2048)?;
        Ok(Self { key })
    }

    pub(crate) fn from_pkcs8_pem(pem: &str) -> Result<Self> {
        let key = RsaPrivateKey::from_pkcs8_pem(pem)?;
        Ok(Self { key })
    }

    pub(crate) fn to_pkcs8_pem(&self) -> Result<String> {
        Ok(self.key.to_pkcs8_pem(LineEnding::LF)?.to_string())
    }

    pub(crate) fn alg(&self) -> &'static str {
        "RS256"
    }

    pub(crate) fn jwk(&self) -> serde_json::Value {
        serde_json::json!({
            "kty": "RSA",
            "n": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(self.key.n().to_bytes_be()),
            "e": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(self.key.e().to_bytes_be()),
        })
    }

    pub(crate) fn thumbprint(&self) -> Result<Vec<u8>> {
        let jwk_str = serde_json::to_string(&self.jwk())?;
        let mut hasher = Sha256::new();
        hasher.update(jwk_str.as_bytes());
        Ok(hasher.finalize().to_vec())
    }

    pub(crate) fn sign(&self, signing_input: &[u8]) -> Result<Vec<u8>> {
        let signing_key = SigningKey::<Sha256>::new(self.key.clone());
        let signature = signing_key.sign(signing_input);
        Ok(signature.to_vec())
    }
}
