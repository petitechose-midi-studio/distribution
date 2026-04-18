from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

from pytest import MonkeyPatch

_MODULE_PATH = Path(__file__).resolve().parents[1] / "scripts" / "select_latest_green.py"
_SPEC = importlib.util.spec_from_file_location("select_latest_green", _MODULE_PATH)
assert _SPEC is not None
assert _SPEC.loader is not None
select_latest_green = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = select_latest_green
_SPEC.loader.exec_module(select_latest_green)


def test_load_tooling_reads_tracked_file(tmp_path: Path) -> None:
    tooling_path = tmp_path / "release-tooling.json"
    tooling_path.write_text(
        json.dumps(
            {
                "repo": "petitechose-midi-studio/ms-dev-env",
                "ref": "main",
                "sha": "f" * 40,
            }
        ),
        encoding="utf-8",
    )

    tooling = select_latest_green._load_tooling(str(tooling_path))  # pyright: ignore[reportPrivateUsage]
    assert tooling == {
        "repo": "petitechose-midi-studio/ms-dev-env",
        "ref": "main",
        "sha": "f" * 40,
    }


def test_main_injects_tooling_into_selected_spec(
    monkeypatch: MonkeyPatch, tmp_path: Path
) -> None:
    template_path = tmp_path / "nightly.template.json"
    tooling_path = tmp_path / "release-tooling.json"
    out_path = tmp_path / "release-spec.json"

    template_path.write_text(
        json.dumps(
            {
                "schema": 1,
                "channel": "nightly",
                "tag": "nightly-YYYY-MM-DD",
                "tooling": {
                    "repo": "petitechose-midi-studio/ms-dev-env",
                    "ref": "main",
                    "sha": "0" * 40,
                },
                "repos": [
                    {
                        "id": "loader",
                        "url": "https://github.com/petitechose-midi-studio/loader",
                        "ref": "main",
                        "sha": "0" * 40,
                        "required_ci_workflow_file": ".github/workflows/ci.yml",
                    }
                ],
                "assets": [],
                "install_sets": [],
            }
        ),
        encoding="utf-8",
    )
    tooling_path.write_text(
        json.dumps(
            {
                "repo": "petitechose-midi-studio/ms-dev-env",
                "ref": "main",
                "sha": "f" * 40,
            }
        ),
        encoding="utf-8",
    )

    def _fake_latest_green_sha(_token: str, _owner_repo: str, _workflow_file: str) -> str:
        return "1" * 40

    monkeypatch.setattr(select_latest_green, "_get_latest_green_sha", _fake_latest_green_sha)
    monkeypatch.setenv("GITHUB_TOKEN", "token")
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "select_latest_green.py",
            "--template",
            str(template_path),
            "--tooling-file",
            str(tooling_path),
            "--out",
            str(out_path),
            "--tag",
            "nightly-2026-04-18",
        ],
    )

    rc = select_latest_green.main()
    assert rc == 0

    spec = json.loads(out_path.read_text(encoding="utf-8"))
    assert spec["tag"] == "nightly-2026-04-18"
    assert spec["tooling"]["sha"] == "f" * 40
    assert spec["repos"][0]["sha"] == "1" * 40
