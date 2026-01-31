use ms_dist_manifest::{sign_manifest_bytes, verify_manifest_bytes};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ed25519_dalek::SigningKey;

#[test]
fn sign_and_verify_roundtrip() {
    // Fixed test key seed (all zeros). Do NOT use this in production.
    let sk_seed = [0u8; 32];
    let sk_seed_b64 = B64.encode(sk_seed);

    let signing_key = SigningKey::from_bytes(&sk_seed);
    let pk_b64 = B64.encode(signing_key.verifying_key().to_bytes());

    let manifest = b"{\n  \"schema\": 2\n}\n";
    let sig_b64 = sign_manifest_bytes(manifest, &sk_seed_b64).expect("sign");
    verify_manifest_bytes(manifest, &sig_b64, &pk_b64).expect("verify");
}
