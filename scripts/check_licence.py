#!/usr/bin/env python3
"""Check that every workspace crate declares the engine's licence: "MIT OR Apache-2.0".

A new crate fails until its Cargo.toml says so.

Run from the repository root: python3 scripts/check_licence.py
"""
import json
import subprocess
import sys

LICENCE = "MIT OR Apache-2.0"


def main() -> int:
    run = subprocess.run(
        ["cargo", "metadata", "--format-version", "1", "--no-deps", "--locked"],
        capture_output=True,
        text=True,
    )
    if run.returncode != 0:
        print(run.stderr, file=sys.stderr)
        print("cargo metadata failed", file=sys.stderr)
        return 1
    packages = json.loads(run.stdout)["packages"]
    problems = [
        f"{p['name']}: license must be {LICENCE!r}, found {p.get('license')!r}"
        for p in sorted(packages, key=lambda p: p["name"])
        if p.get("license") != LICENCE
    ]
    for line in problems:
        print(line, file=sys.stderr)
    if not problems:
        print(f"licence ok: {len(packages)} crates, all {LICENCE}")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
