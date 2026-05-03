
from __future__ import annotations

import re
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Tuple

from graphshield.config import DB_PATH

@dataclass
class VersionRange:

    start: str
    end: str
    start_inclusive: bool
    end_exclusive: bool
    cve_id: str
    cvss_score: float
    package_name: str

@dataclass
class AVLNode:

    version: tuple
    version_str: str
    ranges: List[VersionRange] = field(default_factory=list)
    left: Optional["AVLNode"] = None
    right: Optional["AVLNode"] = None
    height: int = 1

_SEMVER_RE = re.compile(
    r"^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:\.(\d+))?(?:[.-](.+))?$"
)

def parse_semver(version_str: str) -> tuple:
    if not version_str or version_str in ("*", "-", "unknown"):
        return (0, 0, 0)

    m = _SEMVER_RE.match(version_str.strip())
    if not m:
        parts = re.split(r"[.\-]", version_str)
        nums: list = []
        for p in parts:
            if p.isdigit():
                nums.append(int(p))
            else:
                nums.append(p)
                break
        while len(nums) < 3:
            nums.append(0)
        return tuple(nums)

    major = int(m.group(1))
    minor = int(m.group(2)) if m.group(2) is not None else 0
    patch = int(m.group(3)) if m.group(3) is not None else 0
    fourth = int(m.group(4)) if m.group(4) is not None else None
    pre = m.group(5) or None

    if fourth is not None and pre is not None:
        return (major, minor, patch, fourth, pre)
    if fourth is not None:
        return (major, minor, patch, fourth)
    if pre is not None:
        return (major, minor, patch, pre)
    return (major, minor, patch)

def _compare_versions(a: tuple, b: tuple) -> int:
    max_len = max(len(a), len(b))
    a_padded = a + (0,) * (max_len - len(a))
    b_padded = b + (0,) * (max_len - len(b))

    for va, vb in zip(a_padded, b_padded):
        if type(va) != type(vb):
            va, vb = str(va), str(vb)
        try:
            if va < vb:
                return -1
            if va > vb:
                return 1
        except TypeError:
            sa, sb = str(va), str(vb)
            if sa < sb:
                return -1
            if sa > sb:
                return 1
    return 0

def _version_lt(a: tuple, b: tuple) -> bool:
    return _compare_versions(a, b) < 0

def _version_lte(a: tuple, b: tuple) -> bool:
    return _compare_versions(a, b) <= 0

def _version_eq(a: tuple, b: tuple) -> bool:
    return _compare_versions(a, b) == 0

class AVLTree:

    def __init__(self) -> None:
        self.root: Optional[AVLNode] = None
        self._size: int = 0

    def insert(self, vr: VersionRange) -> None:
        index_version = vr.start if vr.start else "0.0.0"
        self.root = self._insert(self.root, vr, parse_semver(index_version))
        self._size += 1

    def query(self, version: str) -> List[VersionRange]:
        v_tuple = parse_semver(version)
        matches: List[VersionRange] = []
        self._collect_matches(self.root, v_tuple, matches)
        matches.sort(key=lambda r: r.cvss_score, reverse=True)
        return matches

    def size(self) -> int:
        return self._size

    def height(self) -> int:
        return self._get_height(self.root)

    def _collect_matches(
        self, node: Optional[AVLNode], v: tuple, acc: List[VersionRange]
    ) -> None:
        if node is None:
            return
        for vr in node.ranges:
            if self._range_contains(vr, v):
                acc.append(vr)
        self._collect_matches(node.left, v, acc)
        self._collect_matches(node.right, v, acc)

    @staticmethod
    def _range_contains(vr: VersionRange, v: tuple) -> bool:
        start_t = parse_semver(vr.start) if vr.start else None
        end_t = parse_semver(vr.end) if vr.end else None

        if start_t is not None:
            if vr.start_inclusive:
                if _version_lt(v, start_t):
                    return False
            else:
                if _version_lte(v, start_t):
                    return False

        if end_t is not None:
            if vr.end_exclusive:
                if not _version_lt(v, end_t):
                    return False
            else:
                if _version_lt(end_t, v):
                    return False

        return True

    def _insert(
        self, node: Optional[AVLNode], vr: VersionRange, index_v: tuple
    ) -> AVLNode:
        if node is None:
            return AVLNode(
                version=index_v,
                version_str=vr.start or "0.0.0",
                ranges=[vr],
            )

        cmp = _compare_versions(index_v, node.version)
        if cmp < 0:
            node.left = self._insert(node.left, vr, index_v)
        elif cmp > 0:
            node.right = self._insert(node.right, vr, index_v)
        else:
            node.ranges.append(vr)
            return node

        node.height = 1 + max(
            self._get_height(node.left), self._get_height(node.right)
        )
        return self._balance(node)

    def _rotate_left(self, z: AVLNode) -> AVLNode:
        y = z.right
        t2 = y.left

        y.left = z
        z.right = t2

        z.height = 1 + max(self._get_height(z.left), self._get_height(z.right))
        y.height = 1 + max(self._get_height(y.left), self._get_height(y.right))
        return y

    def _rotate_right(self, z: AVLNode) -> AVLNode:
        y = z.left
        t3 = y.right

        y.right = z
        z.left = t3

        z.height = 1 + max(self._get_height(z.left), self._get_height(z.right))
        y.height = 1 + max(self._get_height(y.left), self._get_height(y.right))
        return y

    def _get_height(self, node: Optional[AVLNode]) -> int:
        return node.height if node is not None else 0

    def _get_balance(self, node: Optional[AVLNode]) -> int:
        if node is None:
            return 0
        return self._get_height(node.left) - self._get_height(node.right)

    def _balance(self, node: AVLNode) -> AVLNode:
        bf = self._get_balance(node)

        if bf > 1:
            if self._get_balance(node.left) < 0:
                node.left = self._rotate_left(node.left)
            return self._rotate_right(node)

        if bf < -1:
            if self._get_balance(node.right) > 0:
                node.right = self._rotate_right(node.right)
            return self._rotate_left(node)

        return node

def build_version_tree(
    package_name: str,
    db_path: Path = DB_PATH,
) -> AVLTree:
    tree = AVLTree()

    if not db_path.exists():
        return tree

    normalised = package_name.replace("-", "_").lower()
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row

    try:
        rows = conn.execute(
            """
            SELECT c.cve_id, c.version_start, c.version_end,
                   c.version_start_incl, c.version_end_excl,
                   c.cvss_score, c.package_name
            FROM cve_entries c
            JOIN package_index p ON c.cve_id = p.cve_id
            WHERE LOWER(p.package_name) = ?
            """,
            (normalised,),
        ).fetchall()
    finally:
        conn.close()

    for row in rows:
        vr = VersionRange(
            start=row["version_start"] or "",
            end=row["version_end"] or "",
            start_inclusive=bool(row["version_start_incl"]),
            end_exclusive=bool(row["version_end_excl"]),
            cve_id=row["cve_id"],
            cvss_score=float(row["cvss_score"] or 0.0),
            package_name=row["package_name"],
        )
        tree.insert(vr)

    return tree
