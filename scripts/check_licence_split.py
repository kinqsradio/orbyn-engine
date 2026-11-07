#!/usr/bin/env python3
"""Check the engine's licence split: no app-side crate may depend on a server-side one.

App-side crates are embedded by clients and are "MIT OR Apache-2.0"; server-side crates are
"AGPL-3.0-only". Each workspace crate must declare one of the two in its Cargo.toml, and no
crate declaring "MIT OR Apache-2.0" may depend, directly or through other workspace crates,
on one declaring "AGPL-3.0-only" (normal and build dependencies; dev-dependencies are tests).

Run from the repository root: python3 scripts/check_licence_split.py
"""
import json
import subprocess
import sys

APP = "MIT OR Apache-2.0"
SERVER = "AGPL-3.0-only"


def main() -> int:
    meta = json.loads(
        subprocess.run(
            ["cargo", "metadata", "--format-version", "1", "--no-deps", "--locked"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout
    )
    crates = {p["name"]: p for p in meta["packages"]}
    problems = []
    for name, pkg in sorted(crates.items()):
        if pkg.get("license") not in (APP, SERVER):
            problems.append(f"{name}: license must be {APP!r} or {SERVER!r}, found {pkg.get('license')!r}")

    def workspace_deps(name):
        return [
            d["name"]
            for d in crates[name]["dependencies"]
            if d["name"] in crates and d.get("kind") in (None, "build")
        ]

    for name, pkg in sorted(crates.items()):
        if pkg.get("license") != APP:
            continue
        seen, stack = set(), [(name, [name])]
        while stack:
            current, path = stack.pop()
            for dep in workspace_deps(current):
                if dep in seen:
                    continue
                seen.add(dep)
                if crates[dep].get("license") == SERVER:
                    problems.append(f"{name} is app-side but depends on server-side {dep}: {' -> '.join(path + [dep])}")
                stack.append((dep, path + [dep]))
    for line in problems:
        print(line, file=sys.stderr)
    if not problems:
        print(f"licence split ok: {sum(p.get('license') == APP for p in crates.values())} app-side, "
              f"{sum(p.get('license') == SERVER for p in crates.values())} server-side crates")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
