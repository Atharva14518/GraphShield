"""
Bloom Filter implementation from scratch.

Uses MurmurHash3 (mmh3) to generate *k* independent hash positions
for each inserted item.  Bits are stored compactly in a ``bytearray``
(1 byte = 8 bits), giving roughly 8× space efficiency over a plain
Python list of booleans.

Mathematical foundation
-----------------------
Given *n* expected items and desired false-positive probability *p*:

  Optimal bit-array size:
      m = -(n × ln p) / (ln 2)²

  Optimal number of hash functions:
      k = (m / n) × ln 2

These formulae minimise the false-positive rate for fixed *m* and *n*.

No false negatives are possible by construction — a ``contains`` check
that returns ``False`` is always correct.  A ``True`` result may be a
false positive with probability approximately *p* after *n* insertions.
"""

from __future__ import annotations

import math
import pickle
from pathlib import Path
from typing import List

import mmh3

from graphshield.config import BLOOM_PATH, DB_PATH
from graphshield.exceptions import BloomFilterError


class BloomFilter:
    """Space-efficient probabilistic set membership data structure.

    Supports ``add`` and ``contains`` operations with configurable
    false-positive rate and no false negatives.

    Args:
        expected_items: Number of items you plan to insert.
        false_positive_rate: Target false-positive probability in (0, 1).

    Raises:
        BloomFilterError: If parameters are invalid (n ≤ 0 or p outside (0,1)).

    Example::

        bf = BloomFilter(expected_items=100_000, false_positive_rate=0.01)
        bf.add("lodash@4.17.20")
        bf.contains("lodash@4.17.20")   # True
        bf.contains("lodash@3.0.0")     # False (or rare false positive)
    """

    def __init__(
        self, expected_items: int, false_positive_rate: float = 0.01
    ) -> None:
        if expected_items <= 0:
            raise BloomFilterError(
                f"expected_items must be positive, got {expected_items}"
            )
        if not (0.0 < false_positive_rate < 1.0):
            raise BloomFilterError(
                f"false_positive_rate must be in (0, 1), got {false_positive_rate}"
            )

        self.n: int = expected_items
        self.p: float = false_positive_rate
        self.m: int = self._optimal_m(expected_items, false_positive_rate)
        self.k: int = self._optimal_k(self.m, expected_items)
        # One bit per slot; bytearray uses ceil(m / 8) bytes
        self.bit_array: bytearray = bytearray(math.ceil(self.m / 8))
        self._count: int = 0

    # ------------------------------------------------------------------
    # Internal maths
    # ------------------------------------------------------------------

    @staticmethod
    def _optimal_m(n: int, p: float) -> int:
        """Compute optimal bit-array size *m*.

        Args:
            n: Expected number of insertions.
            p: Desired false-positive probability.

        Returns:
            Minimum number of bits needed to satisfy the FP constraint.
        """
        m = -(n * math.log(p)) / (math.log(2) ** 2)
        return max(1, int(math.ceil(m)))

    @staticmethod
    def _optimal_k(m: int, n: int) -> int:
        """Compute optimal number of hash functions *k*.

        Args:
            m: Bit-array size.
            n: Expected number of insertions.

        Returns:
            Number of hash functions that minimise false-positive rate.
        """
        k = (m / n) * math.log(2)
        return max(1, int(round(k)))

    def _get_hash_positions(self, item: str) -> List[int]:
        """Generate *k* bit positions for *item* using seeded MurmurHash3.

        Each hash seed ``i`` in ``range(k)`` produces an independent
        position via ``abs(mmh3.hash(item, seed=i)) % m``.

        Args:
            item: String to hash.

        Returns:
            List of *k* bit positions, each in ``[0, m)``.
        """
        return [abs(mmh3.hash(item, seed=i)) % self.m for i in range(self.k)]

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def add(self, item: str) -> None:
        """Insert *item* into the filter.

        Sets all *k* corresponding bits to 1.

        Args:
            item: String to insert.
        """
        for pos in self._get_hash_positions(item):
            byte_idx = pos // 8
            bit_idx = pos % 8
            self.bit_array[byte_idx] |= 1 << bit_idx
        self._count += 1

    def contains(self, item: str) -> bool:
        """Test whether *item* is (probably) in the filter.

        Returns:
            ``False`` → *item* is definitely **not** in the set.
            ``True``  → *item* is **probably** in the set (may be FP).

        Args:
            item: String to test.
        """
        for pos in self._get_hash_positions(item):
            byte_idx = pos // 8
            bit_idx = pos % 8
            if not (self.bit_array[byte_idx] & (1 << bit_idx)):
                return False
        return True

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def save(self, path: Path) -> None:
        """Serialize the filter to disk using pickle.

        Args:
            path: Destination file path (created/overwritten).

        Raises:
            BloomFilterError: On I/O failure.
        """
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            with open(path, "wb") as fh:
                pickle.dump(self.__dict__, fh, protocol=pickle.HIGHEST_PROTOCOL)
        except OSError as exc:
            raise BloomFilterError(f"Failed to save Bloom Filter to {path}", cause=exc) from exc

    @classmethod
    def load(cls, path: Path) -> "BloomFilter":
        """Deserialize a filter previously saved with :meth:`save`.

        Args:
            path: Source file path.

        Returns:
            Reconstructed :class:`BloomFilter` instance.

        Raises:
            BloomFilterError: If the file is missing or corrupt.
        """
        if not path.exists():
            raise BloomFilterError(f"Bloom Filter file not found: {path}")
        try:
            instance = cls.__new__(cls)
            with open(path, "rb") as fh:
                instance.__dict__ = pickle.load(fh)
            return instance
        except (OSError, pickle.UnpicklingError, KeyError) as exc:
            raise BloomFilterError(
                f"Failed to load Bloom Filter from {path}", cause=exc
            ) from exc

    # ------------------------------------------------------------------
    # Diagnostics
    # ------------------------------------------------------------------

    def stats(self) -> dict:
        """Return runtime statistics about the filter.

        Returns:
            Dict with keys:

            ``m_bits``
                Total bits in the bit array.
            ``k_hashes``
                Number of hash functions.
            ``items_added``
                Count of items inserted so far.
            ``fill_ratio``
                Fraction of bits currently set to 1.
            ``estimated_fp_rate``
                Estimated current false-positive probability.
        """
        set_bits = sum(bin(byte).count("1") for byte in self.bit_array)
        fill_ratio = set_bits / self.m if self.m > 0 else 0.0
        # Actual FP rate formula: (1 - e^(-k*n/m))^k
        exponent = -self.k * self._count / self.m if self.m > 0 else 0
        estimated_fp = (1 - math.e ** exponent) ** self.k
        return {
            "m_bits": self.m,
            "k_hashes": self.k,
            "items_added": self._count,
            "fill_ratio": round(fill_ratio, 4),
            "estimated_fp_rate": round(estimated_fp, 6),
        }

    def __len__(self) -> int:
        return self._count

    def __repr__(self) -> str:
        s = self.stats()
        return (
            f"BloomFilter(n={self.n}, p={self.p}, "
            f"m={self.m}, k={self.k}, count={self._count}, "
            f"fill={s['fill_ratio']:.3f})"
        )


# ---------------------------------------------------------------------------
# Factory: build from CVE database
# ---------------------------------------------------------------------------


def build_cve_bloom_filter(
    db_path: Path = DB_PATH,
    bloom_path: Path = BLOOM_PATH,
) -> "BloomFilter":
    """Build a :class:`BloomFilter` pre-populated with CVE package keys.

    Each key has the form ``"{package_name}@{version}"`` for both the
    exact version boundaries stored in the database.  Also inserts bare
    ``"{package_name}"`` keys so callers can do a quick name-only check.

    Args:
        db_path: Path to the GraphShield SQLite database.
        bloom_path: Destination path for the serialised filter.

    Returns:
        The populated and saved :class:`BloomFilter`.

    Raises:
        BloomFilterError: If the database does not exist.
    """
    import sqlite3

    if not db_path.exists():
        raise BloomFilterError(
            f"CVE database not found at {db_path}. Run: graphshield init"
        )

    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row

    # Count unique entries for sizing
    total_entries: int = conn.execute("SELECT COUNT(*) FROM cve_entries").fetchone()[0]
    if total_entries == 0:
        conn.close()
        # Return a tiny filter even if DB is empty
        bf = BloomFilter(expected_items=1000, false_positive_rate=0.01)
        bf.save(bloom_path)
        return bf

    # Each entry can produce 2–3 keys; add 20% headroom
    expected_keys = max(1000, total_entries * 3)
    bf = BloomFilter(expected_items=expected_keys, false_positive_rate=0.01)

    rows = conn.execute(
        "SELECT package_name, version_start, version_end FROM cve_entries"
    ).fetchall()
    conn.close()

    for row in rows:
        pkg: str = row["package_name"]
        v_start: str = row["version_start"] or ""
        v_end: str = row["version_end"] or ""

        # Bare package name (useful for quick pre-filter)
        bf.add(pkg)

        # Version-anchored keys
        if v_start:
            bf.add(f"{pkg}@{v_start}")
        if v_end:
            bf.add(f"{pkg}@{v_end}")

    bf.save(bloom_path)
    return bf
