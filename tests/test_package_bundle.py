from __future__ import annotations

import subprocess
import sys
import zipfile
from pathlib import Path


def test_package_bundle_normalizes_runtime_binary_names(tmp_path: Path) -> None:
    loader = tmp_path / "midi-studio-loader-windows-x86_64.exe"
    bridge = tmp_path / "oc-bridge-windows-x86_64.exe"
    config_dir = tmp_path / "config"
    device_dir = config_dir / "devices"
    out = tmp_path / "bundle.zip"

    loader.write_bytes(b"loader")
    bridge.write_bytes(b"bridge")
    device_dir.mkdir(parents=True)
    (config_dir / "default.toml").write_text("default = true\n", encoding="utf-8")
    (device_dir / "teensy.toml").write_text("device = 'teensy'\n", encoding="utf-8")

    subprocess.run(
        [
            sys.executable,
            "scripts/package_bundle.py",
            "--out",
            str(out),
            "--loader",
            str(loader),
            "--oc-bridge",
            str(bridge),
            "--oc-bridge-config",
            str(config_dir),
        ],
        check=True,
        cwd=Path(__file__).resolve().parents[1],
    )

    with zipfile.ZipFile(out, "r") as zf:
        names = set(zf.namelist())

    assert "bin/midi-studio-loader.exe" in names
    assert "bin/oc-bridge.exe" in names
    assert "bin/config/default.toml" in names
    assert "bin/config/devices/teensy.toml" in names
