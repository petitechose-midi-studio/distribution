use anyhow::{anyhow, bail, Result};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

pub fn sign_manifest_bytes(manifest: &[u8], sk_seed_b64: &str) -> Result<String> {
    let sk = decode_32_bytes(sk_seed_b64)?;
    let signing_key = SigningKey::from_bytes(&sk);
    let sig: Signature = signing_key.sign(manifest);
    Ok(B64.encode(sig.to_bytes()))
}

pub fn verify_manifest_bytes(manifest: &[u8], sig_b64: &str, pk_b64: &str) -> Result<()> {
    let sig_raw = B64
        .decode(sig_b64.trim().as_bytes())
        .map_err(|e| anyhow!("invalid signature base64: {e}"))?;
    let sig: Signature =
        Signature::from_slice(&sig_raw).map_err(|e| anyhow!("invalid signature bytes: {e}"))?;

    let pk = decode_32_bytes(pk_b64)?;
    let vk = VerifyingKey::from_bytes(&pk).map_err(|e| anyhow!("invalid public key: {e}"))?;

    vk.verify_strict(manifest, &sig)
        .map_err(|e| anyhow!("signature verify failed: {e}"))?;
    Ok(())
}

fn decode_32_bytes(b64: &str) -> Result<[u8; 32]> {
    let raw = B64
        .decode(b64.trim().as_bytes())
        .map_err(|e| anyhow!("invalid base64: {e}"))?;
    if raw.len() != 32 {
        bail!("expected 32 bytes, got {}", raw.len());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&raw);
    Ok(out)
}
