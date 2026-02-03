from __future__ import annotations

import argparse
import json
import zipfile
from pathlib import Path
from typing import cast


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


def _load_spec(path: Path) -> dict[str, object]:
    raw: object = json.loads(path.read_text(encoding="utf-8"))
    spec = _as_object(raw, "spec")
    schema = spec.get("schema")
    if schema != 1:
        raise ValueError(f"spec.schema: expected 1, got {schema!r}")
    return spec


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
    ap = argparse.ArgumentParser(description="Validate a dist/ directory against a release spec")
    ap.add_argument("--spec", required=True, help="Path to release spec JSON")
    ap.add_argument("--dist", required=True, help="Directory containing release assets")
    args = ap.parse_args()

    spec_path = Path(args.spec)
    dist_dir = Path(args.dist)

    spec = _load_spec(spec_path)
    assets_any = spec.get("assets")
    assets = _as_array(assets_any, "spec.assets")

    expected_files: list[tuple[str, str]] = []
    for i, item in enumerate(assets):
        a = _as_object(item, f"spec.assets[{i}]")
        kind = _as_str(a.get("kind"), f"spec.assets[{i}].kind")
        filename = _as_str(a.get("filename"), f"spec.assets[{i}].filename")
        expected_files.append((kind, filename))

    missing: list[str] = []
    for _kind, filename in expected_files:
        p = dist_dir / filename
        if not p.exists() or not p.is_file():
            missing.append(filename)
    if missing:
        preview = ", ".join(missing[:10])
        more = "" if len(missing) <= 10 else f" (+{len(missing) - 10} more)"
        raise FileNotFoundError(f"dist missing expected asset files: {preview}{more}")

    # Bundle layout checks.
    bundle_files = [dist_dir / fn for kind, fn in expected_files if kind == "bundle"]
    for p in bundle_files:
        _validate_bundle_zip(p)

    print(f"OK: dist contains {len(expected_files)} asset(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
