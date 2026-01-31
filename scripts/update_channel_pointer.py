import argparse
import json
import pathlib
from typing import Any
from typing import cast


def main() -> int:
    ap = argparse.ArgumentParser(description="Update a MIDI Studio channel pointer JSON")
    ap.add_argument("--file", required=True, help="Path to channels/<channel>.json")
    ap.add_argument("--channel", required=True, choices=["stable", "beta", "nightly"])
    ap.add_argument("--key-id", required=True, choices=["stable", "nightly"])
    ap.add_argument("--tag", required=True)
    ap.add_argument("--manifest-url", required=True)
    ap.add_argument("--signature-url", required=True)
    args = ap.parse_args()

    path = pathlib.Path(args.file)
    data_any = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data_any, dict):
        raise SystemExit("channel pointer must be a JSON object")

    data = cast(dict[str, Any], data_any)

    schema = data.get("schema")
    if schema != 1:
        raise SystemExit(f"unsupported channel pointer schema: {schema!r}")

    ch = data.get("channel")
    if ch != args.channel:
        raise SystemExit(f"channel mismatch: file has {ch!r}, expected {args.channel!r}")

    data["key_id"] = args.key_id
    data["tag"] = args.tag
    data["manifest_url"] = args.manifest_url
    data["signature_url"] = args.signature_url

    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
