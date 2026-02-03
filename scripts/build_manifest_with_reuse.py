from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import cast


# Files that define how artifacts are built/packaged.
# If any of these change since the previous tag, we force a full rebuild (no reuse).
RECIPE_PATHS: tuple[str, ...] = (
    "scripts/package_bundle.py",
    "scripts/build_manifest_with_reuse.py",
    ".github/workflows/publish.yml",
    ".github/workflows/nightly.yml",
    "Cargo.lock",
)


JsonObject = dict[str, object]
JsonArray = list[object]


class AssetGroup(str, Enum):
    bundles = "bundles"
    firmware_default = "firmware_default"
    firmware_bitwig = "firmware_bitwig"
    bitwig_extension = "bitwig_extension"
    other = "other"


@dataclass(frozen=True, slots=True)
class SpecRepo:
    id: str
    url: str
    ref: str
    sha: str
    required_ci_workflow_file: str | None


@dataclass(frozen=True, slots=True)
class SpecAsset:
    id: str
    kind: str
    filename: str
    os: str | None
    arch: str | None

    @property
    def group(self) -> AssetGroup:
        # Prefer explicit ids; keep kind-based fallback minimal.
        if self.kind == "bundle":
            return AssetGroup.bundles
        if self.id == "firmware-default":
            return AssetGroup.firmware_default
        if self.id == "firmware-bitwig":
            return AssetGroup.firmware_bitwig
        if self.id == "bitwig-extension":
            return AssetGroup.bitwig_extension
        return AssetGroup.other


@dataclass(frozen=True, slots=True)
class SpecInstallSet:
    id: str
    assets: tuple[str, ...]
    os: str | None
    arch: str | None


@dataclass(frozen=True, slots=True)
class ReleaseSpec:
    schema: int
    channel: str
    tag: str
    repos: tuple[SpecRepo, ...]
    assets: tuple[SpecAsset, ...]
    install_sets: tuple[SpecInstallSet, ...]
    pages_demo_url: str | None

    def repo_sha(self, repo_id: str) -> str | None:
        for r in self.repos:
            if r.id == repo_id:
                return r.sha
        return None

    def asset_by_id(self) -> dict[str, SpecAsset]:
        out: dict[str, SpecAsset] = {}
        for a in self.assets:
            out[a.id] = a
        return out

    def bundle_asset_ids(self) -> set[str]:
        return {a.id for a in self.assets if a.kind == "bundle"}


@dataclass(frozen=True, slots=True)
class PrevAssetMeta:
    filename: str
    size: int
    sha256: str
    url: str | None


@dataclass(frozen=True, slots=True)
class PrevManifest:
    repos: dict[str, str]
    assets: dict[str, PrevAssetMeta]

    def repo_sha(self, repo_id: str) -> str | None:
        return self.repos.get(repo_id)


@dataclass(frozen=True, slots=True)
class ReusePlan:
    schema: int
    repo: str
    channel: str
    tag: str
    prev_tag: str | None
    recipe_paths: tuple[str, ...]
    recipe_current_fingerprint: str | None
    recipe_prev_fingerprint: str | None
    recipe_changed: bool
    reuse: dict[AssetGroup, bool]
    build: dict[AssetGroup, bool]
    prev: PrevManifest
    reason: str

    def to_json(self) -> JsonObject:
        return {
            "schema": self.schema,
            "repo": self.repo,
            "channel": self.channel,
            "tag": self.tag,
            "prev_tag": self.prev_tag,
            "recipe": {
                "paths": list(self.recipe_paths),
                "current_fingerprint": self.recipe_current_fingerprint,
                "prev_fingerprint": self.recipe_prev_fingerprint,
                "changed": self.recipe_changed,
            },
            "reuse": {g.value: self.reuse.get(g, False) for g in AssetGroup},
            "build": {g.value: self.build.get(g, False) for g in AssetGroup},
            "prev": {
                "repos": dict(self.prev.repos),
                "assets": {
                    k: {
                        "filename": v.filename,
                        "size": v.size,
                        "sha256": v.sha256,
                        **({"url": v.url} if v.url is not None else {}),
                    }
                    for k, v in self.prev.assets.items()
                },
            },
            "reason": self.reason,
        }


def _is_hex(s: str) -> bool:
    hexdigits = set("0123456789abcdef")
    return all(c in hexdigits for c in s.lower())


def _as_object(v: object, ctx: str) -> JsonObject:
    if not isinstance(v, dict):
        raise ValueError(f"{ctx}: expected object")
    # Break pyright's Unknown key/value types after the isinstance() check.
    raw = cast(dict[object, object], v)
    out: JsonObject = {}
    for k, val in raw.items():
        if not isinstance(k, str):
            raise ValueError(f"{ctx}: expected string keys")
        out[k] = val
    return out


def _as_array(v: object, ctx: str) -> JsonArray:
    if not isinstance(v, list):
        raise ValueError(f"{ctx}: expected array")
    # Break pyright's Unknown element type after the isinstance() check.
    return cast(list[object], v)


def _as_str(v: object, ctx: str) -> str:
    if not isinstance(v, str) or not v:
        raise ValueError(f"{ctx}: expected non-empty string")
    return v


def _as_int(v: object, ctx: str) -> int:
    # bool is a subclass of int; reject it.
    if isinstance(v, bool) or not isinstance(v, int):
        raise ValueError(f"{ctx}: expected integer")
    return v


def _opt_str(v: object, ctx: str) -> str | None:
    if v is None:
        return None
    if not isinstance(v, str) or not v:
        raise ValueError(f"{ctx}: expected string or null")
    return v


def _load_json_object_from_bytes(data: bytes, ctx: str) -> JsonObject:
    raw: object = json.loads(data.decode("utf-8"))
    return _as_object(raw, ctx)


def _read_json_object(path: Path, ctx: str) -> JsonObject:
    raw: object = json.loads(path.read_text(encoding="utf-8"))
    return _as_object(raw, ctx)


def _parse_release_spec(obj: JsonObject) -> ReleaseSpec:
    schema = _as_int(obj.get("schema"), "spec.schema")
    if schema != 1:
        raise ValueError(f"spec.schema: unsupported: {schema}")

    channel = _as_str(obj.get("channel"), "spec.channel")
    tag = _as_str(obj.get("tag"), "spec.tag")

    repos_raw = _as_array(obj.get("repos"), "spec.repos")
    repos: list[SpecRepo] = []
    for i, item in enumerate(repos_raw):
        r = _as_object(item, f"spec.repos[{i}]")
        repo_id = _as_str(r.get("id"), f"spec.repos[{i}].id")
        url = _as_str(r.get("url"), f"spec.repos[{i}].url")
        ref = _as_str(r.get("ref"), f"spec.repos[{i}].ref")
        sha = _as_str(r.get("sha"), f"spec.repos[{i}].sha")
        if len(sha) != 40 or not _is_hex(sha):
            raise ValueError(f"spec.repos[{i}].sha: expected 40 hex chars")
        wf = _opt_str(
            r.get("required_ci_workflow_file"), f"spec.repos[{i}].required_ci_workflow_file"
        )
        repos.append(SpecRepo(id=repo_id, url=url, ref=ref, sha=sha, required_ci_workflow_file=wf))

    assets_raw = _as_array(obj.get("assets"), "spec.assets")
    assets: list[SpecAsset] = []
    for i, item in enumerate(assets_raw):
        a = _as_object(item, f"spec.assets[{i}]")
        asset_id = _as_str(a.get("id"), f"spec.assets[{i}].id")
        kind = _as_str(a.get("kind"), f"spec.assets[{i}].kind")
        filename = _as_str(a.get("filename"), f"spec.assets[{i}].filename")
        os_name = _opt_str(a.get("os"), f"spec.assets[{i}].os")
        arch = _opt_str(a.get("arch"), f"spec.assets[{i}].arch")
        assets.append(SpecAsset(id=asset_id, kind=kind, filename=filename, os=os_name, arch=arch))

    sets_raw = _as_array(obj.get("install_sets"), "spec.install_sets")
    install_sets: list[SpecInstallSet] = []
    for i, item in enumerate(sets_raw):
        s = _as_object(item, f"spec.install_sets[{i}]")
        set_id = _as_str(s.get("id"), f"spec.install_sets[{i}].id")
        assets_any = _as_array(s.get("assets"), f"spec.install_sets[{i}].assets")
        set_assets: list[str] = []
        for j, aid_any in enumerate(assets_any):
            set_assets.append(_as_str(aid_any, f"spec.install_sets[{i}].assets[{j}]"))
        os_name = _opt_str(s.get("os"), f"spec.install_sets[{i}].os")
        arch = _opt_str(s.get("arch"), f"spec.install_sets[{i}].arch")
        install_sets.append(
            SpecInstallSet(id=set_id, assets=tuple(set_assets), os=os_name, arch=arch)
        )

    pages_demo_url: str | None = None
    pages_any = obj.get("pages")
    if pages_any is not None:
        pages = _as_object(pages_any, "spec.pages")
        pages_demo_url = _opt_str(pages.get("demo_url"), "spec.pages.demo_url")

    return ReleaseSpec(
        schema=schema,
        channel=channel,
        tag=tag,
        repos=tuple(repos),
        assets=tuple(assets),
        install_sets=tuple(install_sets),
        pages_demo_url=pages_demo_url,
    )


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            b = f.read(1024 * 1024)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def _sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _http_get_json(url: str, *, token: str | None) -> object:
    req = urllib.request.Request(url)
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("X-GitHub-Api-Version", "2022-11-28")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(req, timeout=30) as r:
        raw: object = json.loads(r.read().decode("utf-8"))
    return raw


def _http_get_bytes(url: str) -> bytes:
    req = urllib.request.Request(url)
    with urllib.request.urlopen(req, timeout=120) as r:
        return r.read()


def _github_releases(repo: str, *, token: str | None) -> list[JsonObject]:
    url = f"https://api.github.com/repos/{repo}/releases?per_page=100"
    raw = _http_get_json(url, token=token)
    arr = _as_array(raw, "github.releases")
    out: list[JsonObject] = []
    for i, item in enumerate(arr):
        out.append(_as_object(item, f"github.releases[{i}]"))
    return out


def _select_prev_tag(*, channel: str, current_tag: str, releases: list[JsonObject]) -> str | None:
    # GitHub API returns releases in reverse chronological order.
    for r in releases:
        tag = r.get("tag_name")
        if not isinstance(tag, str) or not tag or tag == current_tag:
            continue
        # Ignore drafts (they may exist if a previous publish attempt failed).
        draft_any = r.get("draft")
        draft = bool(draft_any is True)
        if draft:
            continue
        prerelease_any = r.get("prerelease")
        prerelease = bool(prerelease_any is True)

        if channel == "nightly":
            if prerelease and tag.startswith("nightly-"):
                return tag
            continue

        if channel == "beta":
            if prerelease and ("-beta." in tag):
                return tag
            continue

        if channel == "stable":
            if not prerelease and not tag.startswith("nightly-"):
                return tag
            continue

    return None


def _git_show_bytes(ref: str, rel_path: str) -> bytes | None:
    cmd = ["git", "show", f"{ref}:{rel_path}"]
    try:
        p = subprocess.run(cmd, capture_output=True)
    except OSError:
        return None
    if p.returncode != 0:
        return None
    return p.stdout


def _recipe_fingerprint_current() -> str:
    h = hashlib.sha256()
    for rel in RECIPE_PATHS:
        b = Path(rel).read_bytes()
        h.update(rel.encode("ascii", "ignore"))
        h.update(b"\n")
        h.update(_sha256_bytes(b).encode("ascii"))
        h.update(b"\n")
    return h.hexdigest()


def _recipe_fingerprint_at(ref: str) -> str | None:
    h = hashlib.sha256()
    for rel in RECIPE_PATHS:
        b = _git_show_bytes(ref, rel)
        if b is None:
            return None
        h.update(rel.encode("ascii", "ignore"))
        h.update(b"\n")
        h.update(_sha256_bytes(b).encode("ascii"))
        h.update(b"\n")
    return h.hexdigest()


def _run_ms_dist_manifest_verify(
    *, workspace_root: Path, manifest_path: Path, sig_path: Path, pubkey_b64: str
) -> None:
    env = os.environ.copy()
    env["MS_DIST_ED25519_PK"] = pubkey_b64
    cmd = [
        "cargo",
        "run",
        "-p",
        "ms-dist-manifest",
        "--",
        "verify",
        "--in",
        str(manifest_path),
        "--sig",
        str(sig_path),
    ]
    p = subprocess.run(cmd, cwd=workspace_root, env=env)
    if p.returncode != 0:
        raise RuntimeError("previous manifest signature verification failed")


def _parse_prev_manifest(manifest_bytes: bytes) -> PrevManifest:
    obj = _load_json_object_from_bytes(manifest_bytes, "prev.manifest")
    schema = _as_int(obj.get("schema"), "prev.manifest.schema")
    if schema != 2:
        raise ValueError(f"prev.manifest.schema: unsupported: {schema}")

    repos_raw = _as_array(obj.get("repos"), "prev.manifest.repos")
    repos: dict[str, str] = {}
    for i, item in enumerate(repos_raw):
        r = _as_object(item, f"prev.manifest.repos[{i}]")
        rid = _as_str(r.get("id"), f"prev.manifest.repos[{i}].id")
        sha = _as_str(r.get("sha"), f"prev.manifest.repos[{i}].sha")
        if len(sha) != 40 or not _is_hex(sha):
            raise ValueError(f"prev.manifest.repos[{i}].sha: expected 40 hex chars")
        repos[rid] = sha

    assets_raw = _as_array(obj.get("assets"), "prev.manifest.assets")
    assets: dict[str, PrevAssetMeta] = {}
    for i, item in enumerate(assets_raw):
        a = _as_object(item, f"prev.manifest.assets[{i}]")
        aid = _as_str(a.get("id"), f"prev.manifest.assets[{i}].id")
        filename = _as_str(a.get("filename"), f"prev.manifest.assets[{i}].filename")
        size = _as_int(a.get("size"), f"prev.manifest.assets[{i}].size")
        sha256 = _as_str(a.get("sha256"), f"prev.manifest.assets[{i}].sha256")
        url = _opt_str(a.get("url"), f"prev.manifest.assets[{i}].url")
        if len(sha256) != 64 or not _is_hex(sha256):
            raise ValueError(f"prev.manifest.assets[{i}].sha256: expected 64 hex chars")
        assets[aid] = PrevAssetMeta(filename=filename, size=size, sha256=sha256, url=url)

    return PrevManifest(repos=repos, assets=assets)


def _default_plan(*, repo: str, channel: str, tag: str, reason: str) -> ReusePlan:
    reuse = {g: False for g in AssetGroup}
    build = {g: True for g in AssetGroup}
    prev = PrevManifest(repos={}, assets={})
    return ReusePlan(
        schema=1,
        repo=repo,
        channel=channel,
        tag=tag,
        prev_tag=None,
        recipe_paths=RECIPE_PATHS,
        recipe_current_fingerprint=None,
        recipe_prev_fingerprint=None,
        recipe_changed=True,
        reuse=reuse,
        build=build,
        prev=prev,
        reason=reason,
    )


def _compute_plan(
    *,
    workspace_root: Path,
    spec: ReleaseSpec,
    repo: str,
    token: str | None,
    pubkey_b64: str,
    out_path: Path,
) -> ReusePlan:
    # Default: no reuse.
    plan = _default_plan(
        repo=repo, channel=spec.channel, tag=spec.tag, reason="no_previous_release"
    )

    if not token:
        plan = _default_plan(
            repo=repo, channel=spec.channel, tag=spec.tag, reason="missing_github_token"
        )
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(plan.to_json(), indent=2) + "\n", encoding="utf-8")
        return plan

    releases = _github_releases(repo, token=token)
    prev_tag = _select_prev_tag(channel=spec.channel, current_tag=spec.tag, releases=releases)
    if not prev_tag:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(plan.to_json(), indent=2) + "\n", encoding="utf-8")
        return plan

    current_fp = _recipe_fingerprint_current()
    prev_fp = _recipe_fingerprint_at(prev_tag)
    recipe_changed = prev_fp is None or prev_fp != current_fp
    if recipe_changed:
        plan = ReusePlan(
            schema=1,
            repo=repo,
            channel=spec.channel,
            tag=spec.tag,
            prev_tag=prev_tag,
            recipe_paths=RECIPE_PATHS,
            recipe_current_fingerprint=current_fp,
            recipe_prev_fingerprint=prev_fp,
            recipe_changed=True,
            reuse={g: False for g in AssetGroup},
            build={g: True for g in AssetGroup},
            prev=PrevManifest(repos={}, assets={}),
            reason="recipe_changed",
        )
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(plan.to_json(), indent=2) + "\n", encoding="utf-8")
        return plan

    # Download previous manifest + signature and verify.
    base = f"https://github.com/{repo}/releases/download/{urllib.parse.quote(prev_tag)}/"
    try:
        prev_manifest_bytes = _http_get_bytes(base + "manifest.json")
        prev_sig_bytes = _http_get_bytes(base + "manifest.json.sig")
    except urllib.error.HTTPError as e:
        plan = _default_plan(
            repo=repo,
            channel=spec.channel,
            tag=spec.tag,
            reason=f"previous_manifest_missing:{e.code}",
        )
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(plan.to_json(), indent=2) + "\n", encoding="utf-8")
        return plan

    out_path.parent.mkdir(parents=True, exist_ok=True)
    prev_manifest_path = out_path.parent / "prev.manifest.json"
    prev_sig_path = out_path.parent / "prev.manifest.json.sig"
    prev_manifest_path.write_bytes(prev_manifest_bytes)
    prev_sig_path.write_bytes(prev_sig_bytes)

    try:
        _run_ms_dist_manifest_verify(
            workspace_root=workspace_root,
            manifest_path=prev_manifest_path,
            sig_path=prev_sig_path,
            pubkey_b64=pubkey_b64,
        )
    except Exception:
        plan = ReusePlan(
            schema=1,
            repo=repo,
            channel=spec.channel,
            tag=spec.tag,
            prev_tag=prev_tag,
            recipe_paths=RECIPE_PATHS,
            recipe_current_fingerprint=current_fp,
            recipe_prev_fingerprint=prev_fp,
            recipe_changed=False,
            reuse={g: False for g in AssetGroup},
            build={g: True for g in AssetGroup},
            prev=PrevManifest(repos={}, assets={}),
            reason="previous_manifest_verify_failed",
        )
        out_path.write_text(json.dumps(plan.to_json(), indent=2) + "\n", encoding="utf-8")
        return plan

    try:
        prev = _parse_prev_manifest(prev_manifest_bytes)
    except Exception:
        plan = ReusePlan(
            schema=1,
            repo=repo,
            channel=spec.channel,
            tag=spec.tag,
            prev_tag=prev_tag,
            recipe_paths=RECIPE_PATHS,
            recipe_current_fingerprint=current_fp,
            recipe_prev_fingerprint=prev_fp,
            recipe_changed=False,
            reuse={g: False for g in AssetGroup},
            build={g: True for g in AssetGroup},
            prev=PrevManifest(repos={}, assets={}),
            reason="previous_manifest_invalid",
        )
        out_path.write_text(json.dumps(plan.to_json(), indent=2) + "\n", encoding="utf-8")
        return plan

    # Compare pinned SHAs for groups.
    def same_repo(repo_id: str) -> bool:
        return (spec.repo_sha(repo_id) is not None) and (
            spec.repo_sha(repo_id) == prev.repo_sha(repo_id)
        )

    bundles_ok = same_repo("loader") and same_repo("oc-bridge")
    firmware_default_ok = same_repo("core")
    # bitwig firmware uses core as a library + plugin-bitwig sources.
    firmware_bitwig_ok = same_repo("core") and same_repo("plugin-bitwig")
    bitwig_extension_ok = same_repo("plugin-bitwig")

    spec_assets = spec.asset_by_id()

    def has_asset(asset_id: str) -> bool:
        a = spec_assets.get(asset_id)
        m = prev.assets.get(asset_id)
        return a is not None and m is not None and m.filename == a.filename

    bundle_ids = spec.bundle_asset_ids()
    has_bundles = bool(bundle_ids) and all(has_asset(aid) for aid in bundle_ids)
    has_fw_default = has_asset("firmware-default")
    has_fw_bitwig = has_asset("firmware-bitwig")
    has_bwext = has_asset("bitwig-extension")

    reuse: dict[AssetGroup, bool] = {g: False for g in AssetGroup}
    reuse[AssetGroup.bundles] = bundles_ok and has_bundles
    reuse[AssetGroup.firmware_default] = firmware_default_ok and has_fw_default
    reuse[AssetGroup.firmware_bitwig] = firmware_bitwig_ok and has_fw_bitwig
    reuse[AssetGroup.bitwig_extension] = bitwig_extension_ok and has_bwext

    build: dict[AssetGroup, bool] = {g: not reuse[g] for g in AssetGroup}

    plan = ReusePlan(
        schema=1,
        repo=repo,
        channel=spec.channel,
        tag=spec.tag,
        prev_tag=prev_tag,
        recipe_paths=RECIPE_PATHS,
        recipe_current_fingerprint=current_fp,
        recipe_prev_fingerprint=prev_fp,
        recipe_changed=False,
        reuse=reuse,
        build=build,
        prev=prev,
        reason="ok",
    )

    out_path.write_text(json.dumps(plan.to_json(), indent=2) + "\n", encoding="utf-8")
    return plan


def _plan_from_file(path: Path) -> ReusePlan:
    obj = _read_json_object(path, "plan")
    schema = _as_int(obj.get("schema"), "plan.schema")
    if schema != 1:
        raise ValueError(f"plan.schema: unsupported: {schema}")

    repo = _as_str(obj.get("repo"), "plan.repo")
    channel = _as_str(obj.get("channel"), "plan.channel")
    tag = _as_str(obj.get("tag"), "plan.tag")
    prev_tag_any = obj.get("prev_tag")
    prev_tag = prev_tag_any if isinstance(prev_tag_any, str) and prev_tag_any else None

    recipe_obj = _as_object(obj.get("recipe"), "plan.recipe")
    paths_any = _as_array(recipe_obj.get("paths"), "plan.recipe.paths")
    recipe_paths: list[str] = []
    for i, p_any in enumerate(paths_any):
        recipe_paths.append(_as_str(p_any, f"plan.recipe.paths[{i}]"))
    current_fp_any = recipe_obj.get("current_fingerprint")
    current_fp = current_fp_any if isinstance(current_fp_any, str) and current_fp_any else None
    prev_fp_any = recipe_obj.get("prev_fingerprint")
    prev_fp = prev_fp_any if isinstance(prev_fp_any, str) and prev_fp_any else None
    changed_any = recipe_obj.get("changed")
    recipe_changed = bool(changed_any is True)

    reuse_obj = _as_object(obj.get("reuse"), "plan.reuse")
    build_obj = _as_object(obj.get("build"), "plan.build")

    reuse: dict[AssetGroup, bool] = {g: False for g in AssetGroup}
    build: dict[AssetGroup, bool] = {g: True for g in AssetGroup}
    for g in AssetGroup:
        reuse[g] = bool(reuse_obj.get(g.value) is True)
        build[g] = bool(build_obj.get(g.value) is True)

    prev_root = _as_object(obj.get("prev"), "plan.prev")
    prev_repos_obj = _as_object(prev_root.get("repos"), "plan.prev.repos")
    prev_assets_obj = _as_object(prev_root.get("assets"), "plan.prev.assets")

    prev_repos: dict[str, str] = {}
    for k, v in prev_repos_obj.items():
        if not isinstance(v, str):
            continue
        prev_repos[k] = v

    prev_assets: dict[str, PrevAssetMeta] = {}
    for asset_id, meta_any in prev_assets_obj.items():
        meta = _as_object(meta_any, f"plan.prev.assets.{asset_id}")
        filename = _as_str(meta.get("filename"), f"plan.prev.assets.{asset_id}.filename")
        size = _as_int(meta.get("size"), f"plan.prev.assets.{asset_id}.size")
        sha256 = _as_str(meta.get("sha256"), f"plan.prev.assets.{asset_id}.sha256")
        url = _opt_str(meta.get("url"), f"plan.prev.assets.{asset_id}.url")
        prev_assets[asset_id] = PrevAssetMeta(filename=filename, size=size, sha256=sha256, url=url)

    reason = _as_str(obj.get("reason"), "plan.reason")

    return ReusePlan(
        schema=schema,
        repo=repo,
        channel=channel,
        tag=tag,
        prev_tag=prev_tag,
        recipe_paths=tuple(recipe_paths),
        recipe_current_fingerprint=current_fp,
        recipe_prev_fingerprint=prev_fp,
        recipe_changed=recipe_changed,
        reuse=reuse,
        build=build,
        prev=PrevManifest(repos=prev_repos, assets=prev_assets),
        reason=reason,
    )


def _build_manifest(
    *,
    spec: ReleaseSpec,
    dist_dir: Path,
    plan: ReusePlan,
    out_path: Path,
) -> None:
    published_at = dt.datetime.now(tz=dt.timezone.utc).replace(microsecond=0).isoformat()
    if published_at.endswith("+00:00"):
        published_at = published_at[:-6] + "Z"

    repos_out: list[JsonObject] = []
    for r in spec.repos:
        repos_out.append({"id": r.id, "url": r.url, "sha": r.sha})

    def asset_url(prev_tag: str, filename: str) -> str:
        return (
            f"https://github.com/{plan.repo}/releases/download/"
            f"{urllib.parse.quote(prev_tag)}/{urllib.parse.quote(filename)}"
        )

    assets_out: list[JsonObject] = []
    for a in spec.assets:
        obj: JsonObject = {
            "id": a.id,
            "kind": a.kind,
            "filename": a.filename,
        }
        if a.os is not None:
            obj["os"] = a.os
        if a.arch is not None:
            obj["arch"] = a.arch

        # Prefer a local file if present.
        # This enables a "copy reuse" mode (e.g. stable/beta) where unchanged assets
        # are downloaded from a previous tag and re-uploaded to the current tag,
        # while nightly can keep URL reuse by simply omitting the file.
        p = dist_dir / a.filename
        if p.exists() and p.is_file():
            obj["size"] = p.stat().st_size
            obj["sha256"] = _sha256_file(p)
            assets_out.append(obj)
            continue

        # Reuse if allowed.
        if (
            a.group != AssetGroup.other
            and plan.prev_tag is not None
            and plan.reuse.get(a.group, False)
            and a.id in plan.prev.assets
        ):
            prev_meta = plan.prev.assets[a.id]
            if prev_meta.filename == a.filename:
                obj["size"] = prev_meta.size
                obj["sha256"] = prev_meta.sha256
                if prev_meta.url is not None:
                    obj["url"] = prev_meta.url
                else:
                    obj["url"] = asset_url(plan.prev_tag, a.filename)
                assets_out.append(obj)
                continue

        raise FileNotFoundError(f"missing asset file: {p}")

    install_sets_out: list[JsonObject] = []
    for s in spec.install_sets:
        s_obj: JsonObject = {"id": s.id, "assets": list(s.assets)}
        if s.os is not None:
            s_obj["os"] = s.os
        if s.arch is not None:
            s_obj["arch"] = s.arch
        install_sets_out.append(s_obj)

    manifest: JsonObject = {
        "schema": 2,
        "channel": spec.channel,
        "tag": spec.tag,
        "published_at": published_at,
        "repos": repos_out,
        "assets": assets_out,
        "install_sets": install_sets_out,
    }
    if spec.pages_demo_url is not None:
        manifest["pages"] = {"demo_url": spec.pages_demo_url}

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")


def _materialize_reused_assets(*, spec: ReleaseSpec, dist_dir: Path, plan: ReusePlan) -> int:
    """Download reused assets into dist_dir (copy reuse).

    This is intended for channels where we want each tag to be self-contained
    (stable/beta), while still skipping rebuilds.
    """

    dist_dir.mkdir(parents=True, exist_ok=True)

    missing: list[str] = []
    downloaded: list[str] = []

    def url_for(asset_id: str, filename: str) -> str | None:
        meta = plan.prev.assets.get(asset_id)
        if meta is None:
            return None
        if meta.url is not None:
            return meta.url
        if plan.prev_tag is None:
            return None
        return (
            f"https://github.com/{plan.repo}/releases/download/"
            f"{urllib.parse.quote(plan.prev_tag)}/{urllib.parse.quote(filename)}"
        )

    for a in spec.assets:
        p = dist_dir / a.filename
        if p.exists() and p.is_file():
            continue

        # Only materialize assets that are explicitly reusable.
        if (
            a.group == AssetGroup.other
            or plan.prev_tag is None
            or not plan.reuse.get(a.group, False)
            or a.id not in plan.prev.assets
        ):
            missing.append(a.filename)
            continue

        meta = plan.prev.assets[a.id]
        if meta.filename != a.filename:
            missing.append(a.filename)
            continue

        url = url_for(a.id, a.filename)
        if url is None:
            missing.append(a.filename)
            continue

        data = _http_get_bytes(url)
        got_size = len(data)
        got_sha256 = _sha256_bytes(data)

        if got_size != meta.size:
            raise ValueError(
                f"downloaded size mismatch for {a.filename}: expected {meta.size} got {got_size}"
            )
        if got_sha256 != meta.sha256:
            raise ValueError(
                f"downloaded sha256 mismatch for {a.filename}: expected {meta.sha256} got {got_sha256}"
            )

        tmp = p.with_name(p.name + ".part")
        tmp.write_bytes(data)
        os.replace(tmp, p)
        downloaded.append(a.filename)
        print(f"materialize: downloaded {a.filename} from {url}")

    if missing:
        missing_preview = ", ".join(missing[:10])
        more = "" if len(missing) <= 10 else f" (+{len(missing) - 10} more)"
        raise FileNotFoundError(
            f"materialize: missing assets (not reusable or missing prev meta): {missing_preview}{more}"
        )

    if not downloaded:
        print("materialize: no assets needed")
    else:
        print(f"materialize: downloaded {len(downloaded)} asset(s)")
    return len(downloaded)


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Build manifest.json with optional asset reuse (assets[].url)"
    )
    sub = ap.add_subparsers(dest="cmd", required=True)

    ap_plan = sub.add_parser("plan", help="Compute a reuse plan from spec + previous release")
    ap_plan.add_argument("--spec", required=True, help="Path to release spec JSON")
    ap_plan.add_argument("--out", required=True, help="Output plan JSON path")
    ap_plan.add_argument(
        "--repo",
        default=os.environ.get("GITHUB_REPOSITORY", ""),
        help="GitHub repo slug (owner/name)",
    )
    ap_plan.add_argument(
        "--token-env",
        default="GITHUB_TOKEN",
        help="Env var holding a GitHub token",
    )
    ap_plan.add_argument(
        "--pubkey-env",
        default="MS_DIST_ED25519_PK",
        help="Env var holding the Ed25519 public key (base64)",
    )
    ap_plan.add_argument(
        "--workspace-root",
        default=".",
        help="Path to the distribution repo root (for cargo/git)",
    )

    ap_build = sub.add_parser("build", help="Build manifest.json from spec + dist + plan")
    ap_build.add_argument("--spec", required=True, help="Path to release spec JSON")
    ap_build.add_argument("--dist", required=True, help="Directory containing built assets")
    ap_build.add_argument("--out", required=True, help="Output manifest.json path")
    ap_build.add_argument("--plan", required=True, help="Path to plan JSON")

    ap_mat = sub.add_parser(
        "materialize",
        help="Download reused assets into dist/ (copy reuse for self-contained tags)",
    )
    ap_mat.add_argument("--spec", required=True, help="Path to release spec JSON")
    ap_mat.add_argument("--dist", required=True, help="Directory to write assets into")
    ap_mat.add_argument("--plan", required=True, help="Path to plan JSON")

    args = ap.parse_args()

    if args.cmd == "plan":
        repo = args.repo
        if not isinstance(repo, str) or not repo:
            print("error: missing --repo (or GITHUB_REPOSITORY)", file=sys.stderr)
            return 1
        token = os.environ.get(args.token_env)
        pubkey_b64 = os.environ.get(args.pubkey_env)
        if not pubkey_b64:
            print(f"error: missing env var: {args.pubkey_env}", file=sys.stderr)
            return 1

        workspace_root = Path(args.workspace_root)
        spec_obj = _read_json_object(Path(args.spec), "spec")
        spec = _parse_release_spec(spec_obj)
        plan = _compute_plan(
            workspace_root=workspace_root,
            spec=spec,
            repo=repo,
            token=token,
            pubkey_b64=pubkey_b64,
            out_path=Path(args.out),
        )
        # Also print a tiny summary for CI logs.
        print(
            f"reuse: bundles={int(plan.reuse[AssetGroup.bundles])} "
            f"fw_default={int(plan.reuse[AssetGroup.firmware_default])} "
            f"fw_bitwig={int(plan.reuse[AssetGroup.firmware_bitwig])} "
            f"bwext={int(plan.reuse[AssetGroup.bitwig_extension])}"
        )
        return 0

    if args.cmd == "build":
        spec_obj = _read_json_object(Path(args.spec), "spec")
        spec = _parse_release_spec(spec_obj)
        plan = _plan_from_file(Path(args.plan))
        _build_manifest(
            spec=spec,
            dist_dir=Path(args.dist),
            plan=plan,
            out_path=Path(args.out),
        )
        return 0

    if args.cmd == "materialize":
        spec_obj = _read_json_object(Path(args.spec), "spec")
        spec = _parse_release_spec(spec_obj)
        plan = _plan_from_file(Path(args.plan))
        _materialize_reused_assets(spec=spec, dist_dir=Path(args.dist), plan=plan)
        return 0

    return 2


if __name__ == "__main__":
    raise SystemExit(main())
