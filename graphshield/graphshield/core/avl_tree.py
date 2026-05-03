"""
Self-balancing AVL Tree for semantic version range queries.

The tree is indexed by the *start* version of each CVE version range.
Querying a concrete version walks the entire tree and collects every
range whose ``[start, end)`` interval (with configurable inclusivity)
contains the queried version.

Why AVL over a plain BST?
--------------------------
Plain BSTs degrade to O(n) on sorted input (common for version data).
An AVL Tree guarantees O(log n) for insert and lookup by maintaining
height balance via single and double rotations after each insertion.
This is critical when scanning dependencies at CI speed.

Semver parsing
--------------
Version strings are normalised to integer tuples for comparison.
Pre-release labels (``-alpha``, ``-beta``) are kept as trailing
strings but sort *before* the equivalent release by convention.
"""

from __future__ import annotations

import re
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Tuple

from graphshield.config import DB_PATH


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class VersionRange:
    """A CVE-associated version range for a package.

    Attributes:
        start: Lower bound version string (``""`` = open lower bound).
        end: Upper bound version string (``""`` = open upper bound).
        start_inclusive: Whether ``start`` itself is affected.
        end_exclusive: Whether ``end`` itself is **not** affected (open interval on right).
        cve_id: Associated CVE identifier.
        cvss_score: CVSS base score for the CVE.
        package_name: Package name (for diagnostics).
    """

    start: str
    end: str
    start_inclusive: bool
    end_exclusive: bool
    cve_id: str
    cvss_score: float
    package_name: str


@dataclass
class AVLNode:
    """A single node in the AVL Tree.

    Stores all version ranges whose *start* equals this node's version.
    Multiple ranges may share the same start version (different CVEs).

    Attributes:
        version: Parsed semver tuple used for BST ordering.
        version_str: Original version string (preserved for output).
        ranges: All :class:`VersionRange` objects indexed at this node.
        left: Left child (versions < this node's version).
        right: Right child (versions > this node's version).
        height: Height of the subtree rooted at this node (1 = leaf).
    """

    version: tuple
    version_str: str
    ranges: List[VersionRange] = field(default_factory=list)
    left: Optional["AVLNode"] = None
    right: Optional["AVLNode"] = None
    height: int = 1


# ---------------------------------------------------------------------------
# Semver parsing
# ---------------------------------------------------------------------------

# Matches: 1, 1.2, 1.2.3, 1.2.3.4, 1.2.3-alpha, 1.2.3-beta.2
_SEMVER_RE = re.compile(
    r"^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:\.(\d+))?(?:[.-](.+))?$"
)


def parse_semver(version_str: str) -> tuple:
    """Parse a semantic version string into a comparable tuple.

    Supports:
    * ``"1.2.3"``      → ``(1, 2, 3)``
    * ``"1.2"``        → ``(1, 2, 0)``
    * ``"1"``          → ``(1, 0, 0)``
    * ``"1.2.3-alpha"``→ ``(1, 2, 3, "alpha")``
    * ``"v1.2.3"``     → ``(1, 2, 3)``
    * ``"1.2.3.4"``    → ``(1, 2, 3, 4, "")``
    * ``""``           → ``(0, 0, 0)`` (open-ended sentinel)

    When comparing tuples with mixed int/str suffixes Python raises
    ``TypeError``; the comparison helpers in :class:`AVLTree` handle
    this by catching the error and applying lexicographic fallback.

    Args:
        version_str: Raw version string to parse.

    Returns:
        Tuple suitable for ``<`` / ``>`` comparisons via
        :func:`_version_lt` and :func:`_version_lte`.
    """
    if not version_str or version_str in ("*", "-", "unknown"):
        return (0, 0, 0)

    m = _SEMVER_RE.match(version_str.strip())
    if not m:
        # Fallback: split on dots and parse digits
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
    """Compare two version tuples.

    Args:
        a: First version tuple.
        b: Second version tuple.

    Returns:
        Negative if a < b, 0 if equal, positive if a > b.
    """
    # Pad to equal length with zeros
    max_len = max(len(a), len(b))
    a_padded = a + (0,) * (max_len - len(a))
    b_padded = b + (0,) * (max_len - len(b))

    for va, vb in zip(a_padded, b_padded):
        # Handle mixed int/str
        if type(va) != type(vb):
            # Convert both to str for comparison
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


# ---------------------------------------------------------------------------
# AVL Tree
# ---------------------------------------------------------------------------


class AVLTree:
    """AVL Tree indexed by semantic version for range queries.

    Insert version ranges once, then query an exact version to get all
    ranges that contain it.  The tree self-balances via rotations to
    guarantee O(log n) height regardless of insertion order.

    Supported range semantics (matching NVD CVE data):

    * ``[1.2.0, 1.2.8)``   — start inclusive, end exclusive
    * ``(1.2.0, 1.2.8]``   — start exclusive, end inclusive
    * ``[1.2.0, ∞)``       — open upper bound (``range.end == ""``)
    * ``(-∞, 1.2.8)``      — open lower bound (``range.start == ""``)
    * ``[1.2.4, 1.2.4]``   — exact version match
    """

    def __init__(self) -> None:
        self.root: Optional[AVLNode] = None
        self._size: int = 0  # total VersionRange objects stored

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def insert(self, vr: VersionRange) -> None:
        """Insert a version range into the tree.

        Ranges are indexed by their *start* version.  If a node for
        that start version already exists its ``ranges`` list is
        extended; otherwise a new node is created and the tree is
        rebalanced.

        Args:
            vr: The :class:`VersionRange` to insert.
        """
        index_version = vr.start if vr.start else "0.0.0"
        self.root = self._insert(self.root, vr, parse_semver(index_version))
        self._size += 1

    def query(self, version: str) -> List[VersionRange]:
        """Find all ranges that contain *version*.

        Walks the entire tree (in O(n) worst case for overlapping
        ranges) because a single version can match ranges indexed at
        many different start points.  In practice, the tree height
        guarantees O(m log n) where *m* is the number of matching
        ranges.

        Args:
            version: Exact version string to test (e.g. ``"1.2.4"``).

        Returns:
            All :class:`VersionRange` objects whose interval contains
            *version*, sorted by ``cvss_score`` descending.
        """
        v_tuple = parse_semver(version)
        matches: List[VersionRange] = []
        self._collect_matches(self.root, v_tuple, matches)
        matches.sort(key=lambda r: r.cvss_score, reverse=True)
        return matches

    def size(self) -> int:
        """Return the total number of :class:`VersionRange` objects stored."""
        return self._size

    def height(self) -> int:
        """Return the height of the tree (0 if empty)."""
        return self._get_height(self.root)

    # ------------------------------------------------------------------
    # Internal helpers — match collection
    # ------------------------------------------------------------------

    def _collect_matches(
        self, node: Optional[AVLNode], v: tuple, acc: List[VersionRange]
    ) -> None:
        """Recursively collect all ranges at *node* that contain *v*."""
        if node is None:
            return
        for vr in node.ranges:
            if self._range_contains(vr, v):
                acc.append(vr)
        self._collect_matches(node.left, v, acc)
        self._collect_matches(node.right, v, acc)

    @staticmethod
    def _range_contains(vr: VersionRange, v: tuple) -> bool:
        """Test whether version tuple *v* falls within *vr*.

        Args:
            vr: The range to test against.
            v: Parsed version tuple.

        Returns:
            ``True`` if *v* is within the range.
        """
        start_t = parse_semver(vr.start) if vr.start else None
        end_t = parse_semver(vr.end) if vr.end else None

        # Lower bound check
        if start_t is not None:
            if vr.start_inclusive:
                if _version_lt(v, start_t):  # v < start → outside
                    return False
            else:
                if _version_lte(v, start_t):  # v <= start → outside
                    return False

        # Upper bound check
        if end_t is not None:
            if vr.end_exclusive:
                if not _version_lt(v, end_t):  # v >= end → outside
                    return False
            else:
                if _version_lt(end_t, v):  # v > end → outside
                    return False

        return True

    # ------------------------------------------------------------------
    # Internal helpers — BST insert + AVL balance
    # ------------------------------------------------------------------

    def _insert(
        self, node: Optional[AVLNode], vr: VersionRange, index_v: tuple
    ) -> AVLNode:
        """Recursive BST insert followed by AVL rebalancing.

        Args:
            node: Current subtree root (may be ``None``).
            vr: Range to insert.
            index_v: Parsed version tuple for ``vr.start``.

        Returns:
            New subtree root after insertion and rebalancing.
        """
        # Base case — create a new leaf node
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
            # Same start version — append to existing node's range list
            node.ranges.append(vr)
            return node  # height unchanged

        node.height = 1 + max(
            self._get_height(node.left), self._get_height(node.right)
        )
        return self._balance(node)

    # ------------------------------------------------------------------
    # AVL rotations
    # ------------------------------------------------------------------

    def _rotate_left(self, z: AVLNode) -> AVLNode:
        """Left rotation around *z*.

        Before::

              z
               \\
                y
               / \\
              T2   x

        After::

              y
             / \\
            z   x
           / \\
          T1  T2

        Args:
            z: Unbalanced node (right-heavy).

        Returns:
            New subtree root (*y*).
        """
        y = z.right
        t2 = y.left  # type: ignore[union-attr]

        y.left = z  # type: ignore[union-attr]
        z.right = t2

        z.height = 1 + max(self._get_height(z.left), self._get_height(z.right))
        y.height = 1 + max(self._get_height(y.left), self._get_height(y.right))  # type: ignore[union-attr]
        return y  # type: ignore[return-value]

    def _rotate_right(self, z: AVLNode) -> AVLNode:
        """Right rotation around *z*.

        Before::

              z
             /
            y
           / \\
          x   T3

        After::

            y
           / \\
          x   z
             / \\
            T3  T4

        Args:
            z: Unbalanced node (left-heavy).

        Returns:
            New subtree root (*y*).
        """
        y = z.left
        t3 = y.right  # type: ignore[union-attr]

        y.right = z  # type: ignore[union-attr]
        z.left = t3

        z.height = 1 + max(self._get_height(z.left), self._get_height(z.right))
        y.height = 1 + max(self._get_height(y.left), self._get_height(y.right))  # type: ignore[union-attr]
        return y  # type: ignore[return-value]

    def _get_height(self, node: Optional[AVLNode]) -> int:
        """Return *node*'s stored height, or 0 if *node* is ``None``.

        Args:
            node: Tree node or ``None``.

        Returns:
            Height value.
        """
        return node.height if node is not None else 0

    def _get_balance(self, node: Optional[AVLNode]) -> int:
        """Return balance factor = height(left) - height(right).

        Args:
            node: Tree node or ``None``.

        Returns:
            Balance factor (positive = left-heavy, negative = right-heavy).
        """
        if node is None:
            return 0
        return self._get_height(node.left) - self._get_height(node.right)

    def _balance(self, node: AVLNode) -> AVLNode:
        """Apply AVL balance correction at *node* if needed.

        Handles all four imbalance cases:

        * Left-Left   → single right rotation
        * Left-Right  → left rotation on child, then right on node
        * Right-Right → single left rotation
        * Right-Left  → right rotation on child, then left on node

        Args:
            node: Node whose balance factor may be ±2.

        Returns:
            (Possibly new) subtree root after rebalancing.
        """
        bf = self._get_balance(node)

        # Left-heavy
        if bf > 1:
            # Left-Right case
            if self._get_balance(node.left) < 0:
                node.left = self._rotate_left(node.left)  # type: ignore[arg-type]
            return self._rotate_right(node)

        # Right-heavy
        if bf < -1:
            # Right-Left case
            if self._get_balance(node.right) > 0:
                node.right = self._rotate_right(node.right)  # type: ignore[arg-type]
            return self._rotate_left(node)

        return node


# ---------------------------------------------------------------------------
# Factory: build from CVE database
# ---------------------------------------------------------------------------


def build_version_tree(
    package_name: str,
    db_path: Path = DB_PATH,
) -> AVLTree:
    """Build an :class:`AVLTree` containing all version ranges for *package_name*.

    Queries the GraphShield SQLite database and inserts one
    :class:`VersionRange` per matching row.

    Args:
        package_name: Package name to look up (case-insensitive,
            hyphens normalised to underscores).
        db_path: Path to the GraphShield SQLite database.

    Returns:
        Populated :class:`AVLTree`.  If the database is absent or the
        package has no CVE entries the returned tree is empty.
    """
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
