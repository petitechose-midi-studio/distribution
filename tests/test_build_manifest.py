from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

_MODULE_PATH = Path(__file__).resolve().parents[1] / "scripts" / "build_manifest.py"
_SPEC = importlib.util.spec_from_file_location("build_manifest", _MODULE_PATH)
assert _SPEC is not None
assert _SPEC.loader is not None
build_manifest = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = build_manifest
_SPEC.loader.exec_module(build_manifest)


def test_parse_release_spec_reads_tooling_from_schema_1() -> None:
    spec = build_manifest._parse_release_spec(  # pyright: ignore[reportPrivateUsage]
        {
            "schema": 1,
            "channel": "beta",
            "tag": "v1.2.3-beta.1",
            "repos": [
                {
                    "id": "core",
                    "url": "https://github.com/petitechose-midi-studio/core",
                    "ref": "main",
                    "sha": "1" * 40,
                    "required_ci_workflow_file": ".github/workflows/ci.yml",
                }
            ],
            "tooling": {
                "repo": "petitechose-midi-studio/ms-dev-env",
                "ref": "main",
                "sha": "f" * 40,
            },
            "assets": [
                {
                    "id": "firmware-default",
                    "kind": "firmware",
                    "filename": "midi-studio-default-firmware.hex",
                }
            ],
            "install_sets": [{"id": "default", "assets": ["firmware-default"]}],
        }
    )

    assert spec.tooling.repo == "petitechose-midi-studio/ms-dev-env"
    assert spec.tooling.sha == "f" * 40


def test_build_manifest_uses_local_dist_only(tmp_path: Path) -> None:
    spec_path = tmp_path / "spec.json"
    dist_dir = tmp_path / "dist"
    manifest_path = tmp_path / "manifest.json"

    dist_dir.mkdir()
    firmware_path = dist_dir / "midi-studio-default-firmware.hex"
    bundle_path = dist_dir / "midi-studio-linux-x86_64-bundle.zip"
    firmware_path.write_bytes(b"firmware")
    bundle_path.write_bytes(b"bundle")

    spec_path.write_text(
        json.dumps(
            {
                "schema": 1,
                "channel": "beta",
                "tag": "v1.2.3-beta.1",
                "repos": [
                    {
                        "id": "core",
                        "url": "https://github.com/petitechose-midi-studio/core",
                        "ref": "main",
                        "sha": "1" * 40,
                    }
                ],
                "tooling": {
                    "repo": "petitechose-midi-studio/ms-dev-env",
                    "ref": "main",
                    "sha": "f" * 40,
                },
                "assets": [
                    {
                        "id": "bundle-linux-x86_64",
                        "kind": "bundle",
                        "os": "linux",
                        "arch": "x86_64",
                        "filename": bundle_path.name,
                    },
                    {
                        "id": "firmware-default",
                        "kind": "firmware",
                        "filename": firmware_path.name,
                    },
                ],
                "install_sets": [
                    {
                        "id": "default",
                        "os": "linux",
                        "arch": "x86_64",
                        "assets": ["bundle-linux-x86_64", "firmware-default"],
                    }
                ],
                "pages": {
                    "demo_url": "https://petitechose-midi-studio.github.io/distribution/demos/beta/"
                },
            }
        ),
        encoding="utf-8",
    )

    build_manifest._build_manifest(  # pyright: ignore[reportPrivateUsage]
        spec=build_manifest._parse_release_spec(  # pyright: ignore[reportPrivateUsage]
            build_manifest._read_json_object(spec_path, "spec")  # pyright: ignore[reportPrivateUsage]
        ),
        dist_dir=dist_dir,
        out_path=manifest_path,
    )

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["schema"] == 3
    assert manifest["tooling"]["sha"] == "f" * 40
    assert manifest["pages"]["demo_url"].endswith("/beta/")
    assets = {asset["id"]: asset for asset in manifest["assets"]}
    assert assets["firmware-default"]["size"] == len(b"firmware")
    assert assets["bundle-linux-x86_64"]["os"] == "linux"
    assert "url" not in assets["firmware-default"]
