import argparse
import json
import os
import sys
from typing import Any
from typing import cast
import urllib.error
import urllib.parse
import urllib.request


def _repo_slug_from_url(url: str) -> str:
    u = urllib.parse.urlparse(url)
    if u.netloc != "github.com":
        raise ValueError(f"unsupported repo url: {url}")
    parts = [p for p in u.path.split("/") if p]
    if len(parts) != 2:
        raise ValueError(f"unsupported repo url: {url}")
    return f"{parts[0]}/{parts[1]}"


def _get_latest_green_sha(token: str, owner_repo: str, workflow_file: str) -> str | None:
    wf = urllib.parse.quote(workflow_file, safe="")
    url = (
        f"https://api.github.com/repos/{owner_repo}/actions/workflows/{wf}/runs"
        f"?branch=main&event=push&status=success&per_page=1"
    )

    req = urllib.request.Request(url)
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("X-GitHub-Api-Version", "2022-11-28")
    req.add_header("Authorization", f"Bearer {token}")

    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            data: dict[str, Any] = json.loads(r.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        msg = e.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"GitHub API error for {owner_repo}: {e.code} {msg}")

    runs_any = data.get("workflow_runs")
    if not isinstance(runs_any, list) or not runs_any:
        return None
    runs = cast(list[Any], runs_any)
    run0_any = runs[0]
    if not isinstance(run0_any, dict):
        return None
    run0 = cast(dict[str, Any], run0_any)
    head_sha = run0.get("head_sha")
    if not isinstance(head_sha, str) or len(head_sha) != 40:
        return None
    return head_sha


def main() -> int:
    ap = argparse.ArgumentParser(description="Select latest green commits and fill a release spec")
    ap.add_argument("--template", required=True, help="Path to nightly.template.json")
    ap.add_argument("--out", required=True, help="Output release spec path")
    ap.add_argument("--tag", required=True, help="Nightly tag to write")
    ap.add_argument("--token-env", default="GITHUB_TOKEN", help="GitHub token env var")
    args = ap.parse_args()

    token = os.environ.get(args.token_env)
    if not token:
        print(f"missing env var: {args.token_env}", file=sys.stderr)
        return 1

    with open(args.template, "r", encoding="utf-8") as f:
        spec_any = json.load(f)
    if not isinstance(spec_any, dict):
        print("template must be a JSON object", file=sys.stderr)
        return 1

    spec = cast(dict[str, Any], spec_any)
    repos_any = spec.get("repos")
    if not isinstance(repos_any, list) or not repos_any:
        print("template missing repos[]", file=sys.stderr)
        return 1

    repos = cast(list[Any], repos_any)

    for r_obj in repos:
        if not isinstance(r_obj, dict):
            print(f"invalid repo entry: {r_obj}", file=sys.stderr)
            return 1

        r_any = cast(dict[str, Any], r_obj)

        repo_url = r_any.get("url")
        wf = r_any.get("required_ci_workflow_file")
        if not isinstance(repo_url, str) or not isinstance(wf, str):
            print(f"invalid repo entry: {r_any}", file=sys.stderr)
            return 1

        slug = _repo_slug_from_url(repo_url)
        sha = _get_latest_green_sha(token, slug, wf)
        if sha is None:
            print(f"skip nightly: no successful CI run for {slug} ({wf})", file=sys.stderr)
            return 2
        r_any["sha"] = sha

    spec["tag"] = args.tag
    spec_bytes = json.dumps(spec, indent=2, sort_keys=False).encode("utf-8")
    out_path = args.out
    with open(out_path, "wb") as f:
        f.write(spec_bytes + b"\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
