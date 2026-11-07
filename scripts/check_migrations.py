#!/usr/bin/env python3
"""Fail when a pull request changes a migration that already exists on its base.

Every directory called `migrations` is covered (the engine's and the key service's). Compared
with the merge base of --base and HEAD, a file there that is modified, renamed, deleted or has
its mode changed is a violation; a new file is fine. An applied migration is never edited.

Run from the repository root:
    python3 scripts/check_migrations.py --base origin/main     # a pull request
    python3 scripts/check_migrations.py --base HEAD~1          # a push to main
"""
import argparse
import subprocess
import sys

MESSAGE = "An applied migration is never edited. Add a new migration for the change."


def in_migrations(path: str) -> bool:
    return "migrations" in path.split("/")[:-1]


def git(*args: str) -> str:
    run = subprocess.run(["git", *args], capture_output=True, text=True)
    if run.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} failed: {run.stderr.strip()}")
    return run.stdout


def ensure_base(base: str) -> None:
    """Make the base commit available: fetch it when the checkout is shallow and lacks it."""
    have = subprocess.run(["git", "cat-file", "-e", f"{base}^{{commit}}"], capture_output=True)
    if have.returncode == 0:
        return
    fetched = subprocess.run(
        ["git", "fetch", "--no-tags", "--quiet", "origin", base], capture_output=True, text=True
    )
    have = subprocess.run(["git", "cat-file", "-e", f"{base}^{{commit}}"], capture_output=True)
    if fetched.returncode != 0 or have.returncode != 0:
        raise RuntimeError(
            f"the base commit {base} is not in this checkout and could not be fetched "
            "(check out with full history, fetch-depth: 0)"
        )


def violations(base: str) -> list[str]:
    """One line per changed existing migration file, between the merge base and HEAD."""
    ensure_base(base)
    if subprocess.run(["git", "merge-base", base, "HEAD"], capture_output=True).returncode != 0:
        # A shallow checkout can hold both commits and still not their fork point: deepen it.
        subprocess.run(["git", "fetch", "--no-tags", "--quiet", "--unshallow", "origin"], capture_output=True)
    fork = git("merge-base", base, "HEAD").strip()
    raw = git("diff", "--raw", "-z", "-M", "--no-abbrev", fork, "HEAD").split("\0")
    found: list[str] = []
    i = 0
    while i + 1 < len(raw) and raw[i].startswith(":"):
        old_mode, new_mode, _, _, status = raw[i][1:].split(" ")
        kind = status[0]
        paths = [raw[i + 1]]
        i += 2
        if kind in "RC":
            paths.append(raw[i])
            i += 1
        if kind == "A" or kind == "C":
            # A new file, or a copy of one: the source is untouched.
            continue
        touched = [p for p in paths if in_migrations(p)]
        if not touched:
            continue
        what = {"M": "changed", "T": "its type changed", "D": "deleted", "R": "renamed"}.get(kind, "changed")
        if kind == "M" and old_mode != new_mode:
            what = "its mode changed"
        shown = " -> ".join(paths) if kind == "R" else paths[0]
        found.append(f"{shown}: {what}. {MESSAGE}")
    return found


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", required=True, help="the revision to compare with")
    base = parser.parse_args().base
    try:
        problems = violations(base)
    except RuntimeError as error:
        print(error, file=sys.stderr)
        return 2
    for problem in problems:
        print(f"error: {problem}", file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
