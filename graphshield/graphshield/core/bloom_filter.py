
from __future__ import annotations

import math
import pickle
from pathlib import Path
from typing import List

import mmh3

from graphshield.config import BLOOM_PATH, DB_PATH
from graphshield.exceptions import BloomFilterError

class BloomFilter:

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
        self.bit_array: bytearray = bytearray(math.ceil(self.m / 8))
        self._count: int = 0

    @staticmethod
    def _optimal_m(n: int, p: float) -> int:
        m = -(n * math.log(p)) / (math.log(2) ** 2)
        return max(1, int(math.ceil(m)))

    @staticmethod
    def _optimal_k(m: int, n: int) -> int:
        k = (m / n) * math.log(2)
        return max(1, int(round(k)))

    def _get_hash_positions(self, item: str) -> List[int]:
        return [abs(mmh3.hash(item, seed=i)) % self.m for i in range(self.k)]

    def add(self, item: str) -> None:
        for pos in self._get_hash_positions(item):
            byte_idx = pos // 8
            bit_idx = pos % 8
            self.bit_array[byte_idx] |= 1 << bit_idx
        self._count += 1

    def contains(self, item: str) -> bool:
        for pos in self._get_hash_positions(item):
            byte_idx = pos // 8
            bit_idx = pos % 8
            if not (self.bit_array[byte_idx] & (1 << bit_idx)):
                return False
        return True

    def save(self, path: Path) -> None:
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            with open(path, "wb") as fh:
                pickle.dump(self.__dict__, fh, protocol=pickle.HIGHEST_PROTOCOL)
        except OSError as exc:
            raise BloomFilterError(f"Failed to save Bloom Filter to {path}", cause=exc) from exc

    @classmethod
    def load(cls, path: Path) -> "BloomFilter":
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

    def stats(self) -> dict:
        set_bits = sum(bin(byte).count("1") for byte in self.bit_array)
        fill_ratio = set_bits / self.m if self.m > 0 else 0.0
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

def build_cve_bloom_filter(
    db_path: Path = DB_PATH,
    bloom_path: Path = BLOOM_PATH,
) -> "BloomFilter":
    import sqlite3

    if not db_path.exists():
        raise BloomFilterError(
            f"CVE database not found at {db_path}. Run: graphshield init"
        )

    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row

    total_entries: int = conn.execute("SELECT COUNT(*) FROM cve_entries").fetchone()[0]
    if total_entries == 0:
        conn.close()
        bf = BloomFilter(expected_items=1000, false_positive_rate=0.01)
        bf.save(bloom_path)
        return bf

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

        bf.add(pkg)

        if v_start:
            bf.add(f"{pkg}@{v_start}")
        if v_end:
            bf.add(f"{pkg}@{v_end}")

    bf.save(bloom_path)
    return bf
