from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

from pytest import MonkeyPatch

_MODULE_PATH = (
    Path(__file__).resolve().parents[1] / "scripts" / "build_manifest_with_reuse.py"
)
_SPEC = importlib.util.spec_from_file_location("build_manifest_with_reuse", _MODULE_PATH)
assert _SPEC is not None
assert _SPEC.loader is not None
build_manifest_with_reuse = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = build_manifest_with_reuse
_SPEC.loader.exec_module(build_manifest_with_reuse)


def test_parse_release_spec_reads_tooling() -> None:
    spec = build_manifest_with_reuse._parse_release_spec(  # pyright: ignore[reportPrivateUsage]
        {
            "schema": 2,
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


def test_compute_plan_forces_rebuild_when_tooling_changes(
    monkeypatch: MonkeyPatch, tmp_path: Path
) -> None:
    module = build_manifest_with_reuse
    spec = module.ReleaseSpec(
        schema=2,
        channel="beta",
        tag="v1.2.3-beta.1",
        repos=(
            module.SpecRepo(
                id="core",
                url="https://github.com/petitechose-midi-studio/core",
                ref="main",
                sha="1" * 40,
                required_ci_workflow_file=".github/workflows/ci.yml",
            ),
        ),
        tooling=module.SpecTooling(
            repo="petitechose-midi-studio/ms-dev-env",
            ref="main",
            sha="f" * 40,
        ),
        assets=(),
        install_sets=(),
        pages_demo_url=None,
    )

    prev_manifest = {
        "schema": 3,
        "channel": "beta",
        "tag": "v1.2.2-beta.1",
        "published_at": "2026-04-18T12:00:00Z",
        "repos": [
            {
                "id": "core",
                "url": "https://github.com/petitechose-midi-studio/core",
                "sha": "1" * 40,
            }
        ],
        "tooling": {
            "repo": "petitechose-midi-studio/ms-dev-env",
            "ref": "main",
            "sha": "e" * 40,
        },
        "assets": [],
        "install_sets": [],
    }

    def fake_github_releases(repo: str, token: str | None) -> list[dict[str, object]]:
        del repo, token
        return [{"tag_name": "v1.2.2-beta.1", "draft": False, "prerelease": True}]

    def fake_recipe_fingerprint_at(ref: str) -> str:
        del ref
        return "recipe"

    def fake_http_get_bytes(url: str) -> bytes:
        if url.endswith("manifest.json"):
            return json.dumps(prev_manifest).encode("utf-8")
        return b"sig"

    def fake_verify_manifest(**kwargs: object) -> None:
        del kwargs

    monkeypatch.setattr(module, "_github_releases", fake_github_releases)
    monkeypatch.setattr(module, "_recipe_fingerprint_current", lambda: "recipe")
    monkeypatch.setattr(module, "_recipe_fingerprint_at", fake_recipe_fingerprint_at)
    monkeypatch.setattr(module, "_http_get_bytes", fake_http_get_bytes)
    monkeypatch.setattr(module, "_run_ms_dist_manifest_verify", fake_verify_manifest)

    plan = module._compute_plan(  # pyright: ignore[reportPrivateUsage]
        workspace_root=tmp_path,
        spec=spec,
        repo="petitechose-midi-studio/distribution",
        token="token",
        pubkey_b64="pubkey",
        out_path=tmp_path / "reuse-plan.json",
    )

    assert plan.reason == "tooling_changed"
    assert plan.tooling_current_sha == "f" * 40
    assert plan.tooling_prev_sha == "e" * 40
    assert all(plan.build.values())
