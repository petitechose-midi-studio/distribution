import argparse
import os
import pathlib
import zipfile


def _add_file(zf: zipfile.ZipFile, src: pathlib.Path, arcname: str) -> None:
    data = src.read_bytes()
    zi = zipfile.ZipInfo(arcname)
    zi.compress_type = zipfile.ZIP_DEFLATED

    # Preserve basic permissions where possible.
    try:
        mode = os.stat(src).st_mode & 0o777
        zi.external_attr = mode << 16
    except OSError:
        pass

    zf.writestr(zi, data)


def _add_tree(zf: zipfile.ZipFile, root: pathlib.Path, prefix: str) -> None:
    root = root.resolve()
    files = [p for p in root.rglob("*") if p.is_file()]
    files.sort(key=lambda p: p.as_posix())

    for p in files:
        rel = p.relative_to(root).as_posix()
        arc = f"{prefix}/{rel}" if prefix else rel
        _add_file(zf, p, arc)


def main() -> int:
    ap = argparse.ArgumentParser(description="Create a MIDI Studio bundle zip")
    ap.add_argument("--out", required=True, help="Output zip path")
    ap.add_argument("--oc-bridge", required=True, help="Path to oc-bridge binary")
    ap.add_argument("--loader", required=True, help="Path to midi-studio-loader binary")
    ap.add_argument(
        "--oc-bridge-config",
        required=True,
        help="Path to oc-bridge config directory (will be zipped under bridge/config)",
    )
    args = ap.parse_args()

    out = pathlib.Path(args.out)
    oc_bridge = pathlib.Path(args.oc_bridge)
    loader = pathlib.Path(args.loader)
    oc_cfg = pathlib.Path(args.oc_bridge_config)

    out.parent.mkdir(parents=True, exist_ok=True)

    with zipfile.ZipFile(out, "w") as zf:
        _add_file(zf, oc_bridge, f"bin/{oc_bridge.name}")
        _add_file(zf, loader, f"bin/{loader.name}")
        _add_tree(zf, oc_cfg, "bridge/config")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
