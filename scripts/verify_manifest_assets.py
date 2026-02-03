from __future__ import annotations

import argparse
import hashlib
import json
import zipfile
from pathlib import Path
from typing import cast
import urllib.request


def _as_object(v: object, ctx: str) -> dict[str, object]:
    if not isinstance(v, dict):
        raise ValueError(f"{ctx}: expected object")
    raw = cast(dict[object, object], v)
    out: dict[str, object] = {}
    for k, val in raw.items():
        if not isinstance(k, str):
            raise ValueError(f"{ctx}: expected string keys")
        out[k] = val
    return out


def _as_array(v: object, ctx: str) -> list[object]:
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


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            b = f.read(1024 * 1024)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def _download_to_path(*, url: str, out_path: Path) -> None:
    if not url.startswith("https://"):
        raise ValueError(f"unsupported url (expected https): {url}")

    out_path.parent.mkdir(parents=True, exist_ok=True)
    tmp = out_path.with_name(out_path.name + ".part")

    req = urllib.request.Request(url)
    with urllib.request.urlopen(req, timeout=120) as r:
        with tmp.open("wb") as f:
            while True:
                b = r.read(1024 * 1024)
                if not b:
                    break
                f.write(b)

    tmp.replace(out_path)


def _validate_bundle_zip(path: Path) -> None:
    with zipfile.ZipFile(path, "r") as zf:
        names = zf.namelist()

    def has_exact(p: str) -> bool:
        return p in names

    if not (has_exact("bin/oc-bridge") or has_exact("bin/oc-bridge.exe")):
        raise ValueError(f"{path.name}: missing bin/oc-bridge(.exe)")
    if not (has_exact("bin/midi-studio-loader") or has_exact("bin/midi-studio-loader.exe")):
        raise ValueError(f"{path.name}: missing bin/midi-studio-loader(.exe)")
    if not has_exact("bin/config/default.toml"):
        raise ValueError(f"{path.name}: missing bin/config/default.toml")
    if not has_exact("bin/config/devices/teensy.toml"):
        raise ValueError(f"{path.name}: missing bin/config/devices/teensy.toml")


def main() -> int:
    ap = argparse.ArgumentParser(description="Verify assets directory matches manifest.json")
    ap.add_argument("--manifest", required=True, help="Path to manifest.json")
    ap.add_argument("--assets-dir", required=True, help="Directory containing asset files")
    ap.add_argument(
        "--fetch-urls",
        action="store_true",
        help="Download missing assets referenced via manifest.assets[].url",
    )
    args = ap.parse_args()

    manifest_path = Path(args.manifest)
    assets_dir = Path(args.assets_dir)

    raw: object = json.loads(manifest_path.read_text(encoding="utf-8"))
    m = _as_object(raw, "manifest")
    schema = _as_int(m.get("schema"), "manifest.schema")
    if schema != 2:
        raise ValueError(f"manifest.schema: expected 2, got {schema}")

    assets = _as_array(m.get("assets"), "manifest.assets")

    for i, item in enumerate(assets):
        a = _as_object(item, f"manifest.assets[{i}]")
        kind = _as_str(a.get("kind"), f"manifest.assets[{i}].kind")
        filename = _as_str(a.get("filename"), f"manifest.assets[{i}].filename")
        expected_size = _as_int(a.get("size"), f"manifest.assets[{i}].size")
        expected_sha = _as_str(a.get("sha256"), f"manifest.assets[{i}].sha256")
        url_any = a.get("url")
        url = url_any if isinstance(url_any, str) and url_any else None

        p = assets_dir / filename
        if not p.exists() or not p.is_file():
            if args.fetch_urls and url is not None:
                fetched = assets_dir / "_fetched" / filename
                _download_to_path(url=url, out_path=fetched)
                p = fetched
            else:
                raise FileNotFoundError(f"missing asset file: {p}")

        got_size = p.stat().st_size
        if got_size != expected_size:
            raise ValueError(
                f"size mismatch for {filename}: expected {expected_size} got {got_size}"
            )

        got_sha = _sha256_file(p)
        if got_sha != expected_sha:
            raise ValueError(
                f"sha256 mismatch for {filename}: expected {expected_sha} got {got_sha}"
            )

        if kind == "bundle":
            _validate_bundle_zip(p)

    print(f"OK: verified {len(assets)} asset(s) against manifest")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
