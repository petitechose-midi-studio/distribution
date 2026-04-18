from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import cast

JsonObject = dict[str, object]
JsonArray = list[object]


@dataclass(frozen=True, slots=True)
class SpecRepo:
    id: str
    url: str
    sha: str


@dataclass(frozen=True, slots=True)
class SpecTooling:
    repo: str
    ref: str
    sha: str


@dataclass(frozen=True, slots=True)
class SpecAsset:
    id: str
    kind: str
    filename: str
    os: str | None
    arch: str | None


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
    tooling: SpecTooling
    assets: tuple[SpecAsset, ...]
    install_sets: tuple[SpecInstallSet, ...]
    pages_demo_url: str | None


def _as_object(v: object, ctx: str) -> JsonObject:
    if not isinstance(v, dict):
        raise ValueError(f"{ctx}: expected object")
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
    return cast(list[object], v)


def _as_str(v: object, ctx: str) -> str:
    if not isinstance(v, str) or not v:
        raise ValueError(f"{ctx}: expected non-empty string")
    return v


def _as_int(v: object, ctx: str) -> int:
    if isinstance(v, bool) or not isinstance(v, int):
        raise ValueError(f"{ctx}: expected integer")
    return v


def _opt_str(v: object, ctx: str) -> str | None:
    if v is None:
        return None
    if not isinstance(v, str) or not v:
        raise ValueError(f"{ctx}: expected string or null")
    return v


def _is_hex(s: str) -> bool:
    return all(c in "0123456789abcdef" for c in s.lower())


def _read_json_object(path: Path, ctx: str) -> JsonObject:
    raw: object = json.loads(path.read_text(encoding="utf-8"))
    return _as_object(raw, ctx)


def _parse_release_spec(obj: JsonObject) -> ReleaseSpec:
    schema = _as_int(obj.get("schema"), "spec.schema")
    if schema not in {1, 2}:
        raise ValueError(f"spec.schema: unsupported: {schema}")

    channel = _as_str(obj.get("channel"), "spec.channel")
    tag = _as_str(obj.get("tag"), "spec.tag")

    repos_raw = _as_array(obj.get("repos"), "spec.repos")
    repos: list[SpecRepo] = []
    for i, item in enumerate(repos_raw):
        repo = _as_object(item, f"spec.repos[{i}]")
        sha = _as_str(repo.get("sha"), f"spec.repos[{i}].sha")
        if len(sha) != 40 or not _is_hex(sha):
            raise ValueError(f"spec.repos[{i}].sha: expected 40 hex chars")
        repos.append(
            SpecRepo(
                id=_as_str(repo.get("id"), f"spec.repos[{i}].id"),
                url=_as_str(repo.get("url"), f"spec.repos[{i}].url"),
                sha=sha,
            )
        )

    tooling_obj = _as_object(obj.get("tooling"), "spec.tooling")
    tooling_sha = _as_str(tooling_obj.get("sha"), "spec.tooling.sha")
    if len(tooling_sha) != 40 or not _is_hex(tooling_sha):
        raise ValueError("spec.tooling.sha: expected 40 hex chars")
    tooling = SpecTooling(
        repo=_as_str(tooling_obj.get("repo"), "spec.tooling.repo"),
        ref=_as_str(tooling_obj.get("ref"), "spec.tooling.ref"),
        sha=tooling_sha,
    )

    assets_raw = _as_array(obj.get("assets"), "spec.assets")
    assets: list[SpecAsset] = []
    for i, item in enumerate(assets_raw):
        asset = _as_object(item, f"spec.assets[{i}]")
        assets.append(
            SpecAsset(
                id=_as_str(asset.get("id"), f"spec.assets[{i}].id"),
                kind=_as_str(asset.get("kind"), f"spec.assets[{i}].kind"),
                filename=_as_str(asset.get("filename"), f"spec.assets[{i}].filename"),
                os=_opt_str(asset.get("os"), f"spec.assets[{i}].os"),
                arch=_opt_str(asset.get("arch"), f"spec.assets[{i}].arch"),
            )
        )

    install_sets_raw = _as_array(obj.get("install_sets"), "spec.install_sets")
    install_sets: list[SpecInstallSet] = []
    for i, item in enumerate(install_sets_raw):
        install_set = _as_object(item, f"spec.install_sets[{i}]")
        asset_ids: list[str] = []
        for j, asset_id in enumerate(
            _as_array(install_set.get("assets"), f"spec.install_sets[{i}].assets")
        ):
            asset_ids.append(_as_str(asset_id, f"spec.install_sets[{i}].assets[{j}]"))
        install_sets.append(
            SpecInstallSet(
                id=_as_str(install_set.get("id"), f"spec.install_sets[{i}].id"),
                assets=tuple(asset_ids),
                os=_opt_str(install_set.get("os"), f"spec.install_sets[{i}].os"),
                arch=_opt_str(install_set.get("arch"), f"spec.install_sets[{i}].arch"),
            )
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
        tooling=tooling,
        assets=tuple(assets),
        install_sets=tuple(install_sets),
        pages_demo_url=pages_demo_url,
    )


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            chunk = f.read(1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def _published_at_utc() -> str:
    published_at = dt.datetime.now(tz=dt.UTC).replace(microsecond=0).isoformat()
    if published_at.endswith("+00:00"):
        return published_at[:-6] + "Z"
    return published_at


def _build_manifest(*, spec: ReleaseSpec, dist_dir: Path, out_path: Path) -> None:
    repos_out: list[JsonObject] = []
    for repo in spec.repos:
        repos_out.append({"id": repo.id, "url": repo.url, "sha": repo.sha})

    assets_out: list[JsonObject] = []
    for asset in spec.assets:
        asset_path = dist_dir / asset.filename
        if not asset_path.exists() or not asset_path.is_file():
            raise FileNotFoundError(f"missing asset file: {asset_path}")
        asset_out: JsonObject = {
            "id": asset.id,
            "kind": asset.kind,
            "filename": asset.filename,
            "size": asset_path.stat().st_size,
            "sha256": _sha256_file(asset_path),
        }
        if asset.os is not None:
            asset_out["os"] = asset.os
        if asset.arch is not None:
            asset_out["arch"] = asset.arch
        assets_out.append(asset_out)

    install_sets_out: list[JsonObject] = []
    for install_set in spec.install_sets:
        install_set_out: JsonObject = {
            "id": install_set.id,
            "assets": list(install_set.assets),
        }
        if install_set.os is not None:
            install_set_out["os"] = install_set.os
        if install_set.arch is not None:
            install_set_out["arch"] = install_set.arch
        install_sets_out.append(install_set_out)

    manifest: JsonObject = {
        "schema": 3,
        "channel": spec.channel,
        "tag": spec.tag,
        "published_at": _published_at_utc(),
        "repos": repos_out,
        "tooling": {
            "repo": spec.tooling.repo,
            "ref": spec.tooling.ref,
            "sha": spec.tooling.sha,
        },
        "assets": assets_out,
        "install_sets": install_sets_out,
    }
    if spec.pages_demo_url is not None:
        manifest["pages"] = {"demo_url": spec.pages_demo_url}

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")


def main() -> int:
    ap = argparse.ArgumentParser(description="Build manifest.json from local dist assets")
    ap.add_argument("--spec", required=True, help="Path to release spec JSON")
    ap.add_argument("--dist", required=True, help="Directory containing release assets")
    ap.add_argument("--out", required=True, help="Output manifest.json path")
    args = ap.parse_args()

    spec = _parse_release_spec(_read_json_object(Path(args.spec), "spec"))
    _build_manifest(spec=spec, dist_dir=Path(args.dist), out_path=Path(args.out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
