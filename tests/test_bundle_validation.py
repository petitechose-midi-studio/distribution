from __future__ import annotations

import zipfile
from collections.abc import Callable
from pathlib import Path

import pytest

from scripts.validate_dist import _validate_bundle_zip as validate_dist_bundle
from scripts.verify_manifest_assets import _validate_bundle_zip as validate_manifest_bundle


def _write_bundle(path: Path, *, include_core_file_tool: bool) -> None:
    names = [
        "bin/oc-bridge",
        "bin/midi-studio-loader",
        "bin/config/default.toml",
        "bin/config/devices/teensy.toml",
    ]
    if include_core_file_tool:
        names.append("bin/ms-core-file-tool")

    with zipfile.ZipFile(path, "w") as bundle:
        for name in names:
            bundle.writestr(name, name.encode())


@pytest.mark.parametrize("validator", [validate_dist_bundle, validate_manifest_bundle])
def test_bundle_validators_require_core_file_tool(
    tmp_path: Path,
    validator: Callable[[Path], None],
) -> None:
    bundle = tmp_path / "bundle.zip"
    _write_bundle(bundle, include_core_file_tool=False)

    with pytest.raises(ValueError, match=r"missing bin/ms-core-file-tool\(\.exe\)"):
        validator(bundle)

    _write_bundle(bundle, include_core_file_tool=True)
    validator(bundle)
