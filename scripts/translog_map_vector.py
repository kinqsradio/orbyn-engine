#!/usr/bin/env python3
"""Independent reference values for orbyn-translog's fixed vectors (standard library only).

It implements the definitions in the module docs of crates/orbyn-translog/src/map.rs and
src/entry.rs from scratch, so the Rust code is checked against a second implementation rather
than against itself.

    python3 scripts/translog_map_vector.py          # print the values
    python3 scripts/translog_map_vector.py --check  # fail unless the Rust tests hold these values

Run it again, and update the values in the Rust tests (`fixed_vector` in map.rs, and
`the_canonical_bytes_and_hashes_are_fixed` in entry.rs), whenever a tag, a field or an encoding in
those modules changes. `--check` finds each value in the test source, so a stale or hand-edited
vector fails.
"""
import hashlib
import pathlib
import struct
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
H = lambda b: hashlib.sha256(b).digest()

# ---- the map: path-compressed sparse Merkle tree, tags 0x02 (leaf) and 0x03 (branch) ----
EMPTY = H(b"orbyn/map/v1/empty")


def leaf(key, value):
    return H(b"\x02" + key + value)


def branch(index, left, right):
    return H(b"\x03" + struct.pack(">H", index) + left + right)


def bit(key, i):
    return (key[i // 8] >> (7 - i % 8)) & 1


def first_diff(a, b):
    return next(i for i in range(256) if bit(a, i) != bit(b, i))


def node(items):
    """items: sorted [(key, value)]. The first and last key differ first where any two do."""
    if not items:
        return EMPTY
    if len(items) == 1:
        return leaf(*items[0])
    i = first_diff(items[0][0], items[-1][0])
    left = [x for x in items if not bit(x[0], i)]
    right = [x for x in items if bit(x[0], i)]
    return branch(i, node(left), node(right))


def prove(items, key):
    """The proof's canonical bytes: steps root first, then the end."""
    steps = []
    while len(items) > 1:
        i = first_diff(items[0][0], items[-1][0])
        left = [x for x in items if not bit(x[0], i)]
        right = [x for x in items if bit(x[0], i)]
        taken, other = (right, left) if bit(key, i) else (left, right)
        steps.append((i, node(other)))
        items = taken
    out = struct.pack(">H", len(steps)) + b"".join(struct.pack(">H", i) + s for i, s in steps)
    return out + (b"\x01" + items[0][0] + items[0][1] if items else b"\x00")


def key(first=0, last=0):
    k = bytearray(32)
    k[0], k[31] = first, last
    return bytes(k)


# ---- entries (entry.rs) ----
def entry_bytes(kind, map_id, map_key, prev, time_ms, fields):
    return (bytes([1, kind, map_id]) + map_key + prev + struct.pack(">Q", time_ms)
            + struct.pack(">I", len(fields)) + fields)


def entry_hash(encoded):
    return H(b"\x00" + encoded)  # RFC 9162 leaf hash


def map_value(entry_hash_, chain_len):
    return H(b"orbyn/map-value/v1" + entry_hash_ + struct.pack(">Q", chain_len))


def values():
    out = {"empty": EMPTY.hex()}
    letters = {n: H(n.encode()) for n in "abcde"}
    A, B, C, D, E = key(), key(0x80), key(0x40), key(0, 1), key(0x20)
    inserted = []
    for name, k in [("a", A), ("b", B), ("c", C), ("d", D)]:
        inserted.append((k, letters[name]))
        out["after " + name] = node(sorted(inserted)).hex()
    out["proof for e"] = prove(sorted(inserted), E).hex()
    inserted.append((E, letters["e"]))
    out["after e"] = node(sorted(inserted)).hex()
    e = entry_bytes(1, 1, bytes([7]) * 32, bytes(32), 1_700_000_000_123, b"statement")
    out["entry bytes"] = e.hex()
    out["entry hash"] = entry_hash(e).hex()
    out["map value"] = map_value(bytes([1]) * 32, 3).hex()
    return out


def main():
    found = values()
    if "--check" not in sys.argv:
        for name, value in found.items():
            print(f"{name}: {value}")
        return 0
    sources = "".join(
        (ROOT / "crates/orbyn-translog/src" / f).read_text().replace("\\\n", "")
        for f in ("map.rs", "entry.rs")
    )
    sources = "".join(sources.split()).replace('"', "").replace("\\", "")
    missing = [n for n, v in found.items() if n != "empty" and v not in sources]
    if "empty" in found and found["empty"] not in sources:
        missing.append("empty")
    if missing:
        print("not in the Rust tests:", ", ".join(missing))
        return 1
    print("the Rust tests hold every value")
    return 0


if __name__ == "__main__":
    sys.exit(main())
