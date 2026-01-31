use anyhow::{anyhow, bail, Context, Result};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use clap::{Parser, Subcommand};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

#[derive(Parser)]
#[command(
    name = "ms-dist-manifest",
    about = "Generate and sign MIDI Studio distribution manifests",
    version
)]
struct Cli {
    #[command(subcommand)]
    cmd: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Build a manifest.json from release-spec.json + dist/ directory.
    Build {
        /// Path to release-spec.json
        #[arg(long)]
        spec: PathBuf,
        /// Directory containing the built assets.
        #[arg(long)]
        dist: PathBuf,
        /// Output manifest.json path.
        #[arg(long)]
        out: PathBuf,
        /// Override published_at (RFC3339). Defaults to now.
        #[arg(long)]
        published_at: Option<String>,
    },

    /// Sign a manifest.json into manifest.json.sig.
    Sign {
        /// Input manifest.json
        #[arg(long = "in")]
        input: PathBuf,
        /// Output manifest.json.sig
        #[arg(long)]
        out: PathBuf,
        /// Secret key seed env var name (base64, 32 bytes)
        #[arg(long, default_value = "MS_DIST_ED25519_SK")]
        key_env: String,
    },

    /// Verify a manifest.json + manifest.json.sig.
    Verify {
        /// Input manifest.json
        #[arg(long = "in")]
        input: PathBuf,
        /// Input manifest.json.sig
        #[arg(long)]
        sig: PathBuf,
        /// Public key env var name (base64, 32 bytes)
        #[arg(long, default_value = "MS_DIST_ED25519_PK")]
        pk_env: String,
    },
}

#[derive(Debug, Deserialize)]
struct ReleaseSpec {
    schema: u32,
    channel: String,
    tag: String,
    repos: Vec<SpecRepo>,
    assets: Vec<SpecAsset>,
    install_sets: Vec<InstallSet>,
    #[serde(default)]
    pages: Option<Pages>,
}

#[derive(Debug, Deserialize)]
struct SpecRepo {
    id: String,
    url: String,
    #[serde(rename = "ref")]
    git_ref: String,
    sha: String,
    #[serde(default)]
    required_ci_workflow_file: Option<String>,
}

#[derive(Debug, Deserialize)]
struct SpecAsset {
    id: String,
    kind: String,
    #[serde(default)]
    os: Option<String>,
    #[serde(default)]
    arch: Option<String>,
    filename: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct InstallSet {
    id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    os: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    arch: Option<String>,
    assets: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct Pages {
    #[serde(skip_serializing_if = "Option::is_none")]
    demo_url: Option<String>,
}

#[derive(Debug, Serialize)]
struct Manifest {
    schema: u32,
    channel: String,
    tag: String,
    published_at: String,
    repos: Vec<ManifestRepo>,
    assets: Vec<ManifestAsset>,
    install_sets: Vec<InstallSet>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pages: Option<Pages>,
}

#[derive(Debug, Serialize)]
struct ManifestRepo {
    id: String,
    url: String,
    sha: String,
}

#[derive(Debug, Serialize)]
struct ManifestAsset {
    id: String,
    kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    os: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    arch: Option<String>,
    filename: String,
    size: u64,
    sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    url: Option<String>,
}

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Command::Build {
            spec,
            dist,
            out,
            published_at,
        } => cmd_build(&spec, &dist, &out, published_at.as_deref()),
        Command::Sign {
            input,
            out,
            key_env,
        } => cmd_sign(&input, &out, &key_env),
        Command::Verify { input, sig, pk_env } => cmd_verify(&input, &sig, &pk_env),
    }
}

fn cmd_build(
    spec_path: &Path,
    dist_dir: &Path,
    out_path: &Path,
    published_at: Option<&str>,
) -> Result<()> {
    let spec_bytes =
        fs::read(spec_path).with_context(|| format!("read spec: {}", spec_path.display()))?;
    let spec: ReleaseSpec = serde_json::from_slice(&spec_bytes)
        .with_context(|| format!("parse spec JSON: {}", spec_path.display()))?;

    if spec.schema != 1 {
        bail!("unsupported release spec schema: {}", spec.schema);
    }

    let mut asset_ids = HashSet::<String>::new();
    for a in &spec.assets {
        if !asset_ids.insert(a.id.clone()) {
            bail!("duplicate asset id in spec: {}", a.id);
        }
    }

    if !spec.install_sets.iter().any(|s| s.id == "default") {
        bail!("missing required install set: default");
    }

    for set in &spec.install_sets {
        for id in &set.assets {
            if !asset_ids.contains(id) {
                bail!(
                    "install set '{}' references unknown asset id: {}",
                    set.id,
                    id
                );
            }
        }
    }

    let published_at = match published_at {
        Some(v) => {
            let _ = OffsetDateTime::parse(v, &Rfc3339)
                .map_err(|e| anyhow!("invalid --published-at: {e}"))?;
            v.to_string()
        }
        None => OffsetDateTime::now_utc().format(&Rfc3339)?,
    };

    let repos = spec
        .repos
        .into_iter()
        .map(|r| ManifestRepo {
            id: r.id,
            url: r.url,
            sha: r.sha,
        })
        .collect::<Vec<_>>();

    let mut assets = Vec::with_capacity(spec.assets.len());
    for a in spec.assets {
        let path = dist_dir.join(&a.filename);
        let meta = fs::metadata(&path)
            .with_context(|| format!("missing asset file: {}", path.display()))?;
        if !meta.is_file() {
            bail!("asset is not a file: {}", path.display());
        }

        let bytes = fs::read(&path).with_context(|| format!("read asset: {}", path.display()))?;
        let sha256 = Sha256::digest(&bytes);
        let sha256_hex = hex_lower(&sha256);

        assets.push(ManifestAsset {
            id: a.id,
            kind: a.kind,
            os: a.os,
            arch: a.arch,
            filename: a.filename,
            size: meta.len(),
            sha256: sha256_hex,
            url: None,
        });
    }

    let manifest = Manifest {
        schema: 2,
        channel: spec.channel,
        tag: spec.tag,
        published_at,
        repos,
        assets,
        install_sets: spec.install_sets,
        pages: spec.pages,
    };

    let json = serde_json::to_string_pretty(&manifest)?;
    fs::write(out_path, format!("{json}\n"))
        .with_context(|| format!("write manifest: {}", out_path.display()))?;
    Ok(())
}

fn cmd_sign(input: &Path, out: &Path, key_env: &str) -> Result<()> {
    let manifest_bytes =
        fs::read(input).with_context(|| format!("read manifest: {}", input.display()))?;
    let sk_b64 = env::var(key_env).with_context(|| format!("missing env var: {key_env}"))?;
    let sk =
        decode_32_bytes(&sk_b64).with_context(|| format!("decode {key_env} (base64, 32 bytes)"))?;
    let signing_key = SigningKey::from_bytes(&sk);
    let sig: Signature = signing_key.sign(&manifest_bytes);

    let sig_b64 = B64.encode(sig.to_bytes());
    fs::write(out, format!("{sig_b64}\n"))
        .with_context(|| format!("write sig: {}", out.display()))?;
    Ok(())
}

fn cmd_verify(input: &Path, sig_path: &Path, pk_env: &str) -> Result<()> {
    let manifest_bytes =
        fs::read(input).with_context(|| format!("read manifest: {}", input.display()))?;
    let sig_txt = fs::read_to_string(sig_path)
        .with_context(|| format!("read sig: {}", sig_path.display()))?;
    let sig_txt = sig_txt.trim();
    let sig_raw = B64
        .decode(sig_txt.as_bytes())
        .map_err(|e| anyhow!("invalid signature base64: {e}"))?;
    let sig: Signature =
        Signature::from_slice(&sig_raw).map_err(|e| anyhow!("invalid signature bytes: {e}"))?;

    let pk_b64 = env::var(pk_env).with_context(|| format!("missing env var: {pk_env}"))?;
    let pk =
        decode_32_bytes(&pk_b64).with_context(|| format!("decode {pk_env} (base64, 32 bytes)"))?;
    let vk = VerifyingKey::from_bytes(&pk).map_err(|e| anyhow!("invalid public key: {e}"))?;

    vk.verify_strict(&manifest_bytes, &sig)
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

fn hex_lower(bytes: &[u8]) -> String {
    const LUT: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(LUT[(b >> 4) as usize] as char);
        out.push(LUT[(b & 0x0f) as usize] as char);
    }
    out
}
