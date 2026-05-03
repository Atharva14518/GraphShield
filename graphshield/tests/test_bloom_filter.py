"""
Tests for graphshield.core.bloom_filter.

Test cases:
  - test_no_false_negatives:   10,000 items all return True
  - test_false_positive_rate:  10,000 non-inserted items; FP rate < 2×target
  - test_serialize_deserialize: save → load → items still found
  - test_stats:                 stats() returns valid numeric ranges
  - test_invalid_parameters:    constructor raises BloomFilterError for bad inputs
"""

from __future__ import annotations

import math
import tempfile
from pathlib import Path

import pytest

from graphshield.core.bloom_filter import BloomFilter
from graphshield.exceptions import BloomFilterError


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

N_ITEMS = 10_000
FP_RATE = 0.01


def _insert_items(bf: BloomFilter, prefix: str = "item") -> list[str]:
    """Insert N_ITEMS strings into *bf* and return them."""
    items = [f"{prefix}_{i}" for i in range(N_ITEMS)]
    for item in items:
        bf.add(item)
    return items


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestBloomFilterNoFalseNegatives:
    """Every inserted item must always be found."""

    def test_no_false_negatives(self) -> None:
        bf = BloomFilter(expected_items=N_ITEMS, false_positive_rate=FP_RATE)
        items = _insert_items(bf)
        for item in items:
            assert bf.contains(item), f"False negative for item: {item!r}"

    def test_single_item(self) -> None:
        bf = BloomFilter(expected_items=100, false_positive_rate=0.001)
        bf.add("CVE-2021-44228")
        assert bf.contains("CVE-2021-44228")

    def test_versioned_keys(self) -> None:
        bf = BloomFilter(expected_items=1000, false_positive_rate=0.01)
        keys = ["lodash@4.17.20", "express@4.18.2", "axios@0.21.1"]
        for k in keys:
            bf.add(k)
        for k in keys:
            assert bf.contains(k)


class TestBloomFilterFalsePositiveRate:
    """False positive rate must be ≤ 2× configured target."""

    def test_false_positive_rate(self) -> None:
        bf = BloomFilter(expected_items=N_ITEMS, false_positive_rate=FP_RATE)
        _insert_items(bf, prefix="inserted")

        # Check N_ITEMS distinct items that were never inserted
        probe_items = [f"probe_{i}" for i in range(N_ITEMS)]
        fp_count = sum(1 for x in probe_items if bf.contains(x))
        observed_fp = fp_count / N_ITEMS

        # Allow 2× the configured rate as tolerance
        assert observed_fp <= FP_RATE * 2, (
            f"FP rate {observed_fp:.4f} exceeds 2× target {FP_RATE * 2:.4f}"
        )

    def test_empty_filter_returns_false(self) -> None:
        bf = BloomFilter(expected_items=1000, false_positive_rate=0.01)
        # Nothing inserted — almost certainly False for any query
        fp_count = sum(1 for i in range(1000) if bf.contains(f"pkg_{i}"))
        # With an empty filter fp_count should be essentially 0
        assert fp_count < 10, f"Too many false positives from empty filter: {fp_count}"


class TestBloomFilterSerialization:
    """Serialize ↔ deserialize round-trip."""

    def test_serialize_deserialize(self, tmp_path: Path) -> None:
        bf = BloomFilter(expected_items=N_ITEMS, false_positive_rate=FP_RATE)
        items = _insert_items(bf)

        save_path = tmp_path / "test_bloom.pkl"
        bf.save(save_path)
        assert save_path.exists()

        bf2 = BloomFilter.load(save_path)

        # All previously inserted items must still be found
        for item in items:
            assert bf2.contains(item), f"Item lost after reload: {item!r}"

    def test_stats_preserved_after_reload(self, tmp_path: Path) -> None:
        bf = BloomFilter(expected_items=5000, false_positive_rate=0.005)
        _insert_items(bf, prefix="test")
        path = tmp_path / "bf.pkl"
        bf.save(path)

        bf2 = BloomFilter.load(path)
        assert bf2.stats()["items_added"] == bf.stats()["items_added"]
        assert bf2.m == bf.m
        assert bf2.k == bf.k

    def test_load_missing_file_raises(self, tmp_path: Path) -> None:
        with pytest.raises(BloomFilterError):
            BloomFilter.load(tmp_path / "nonexistent.pkl")


class TestBloomFilterStats:
    """stats() returns meaningful and valid values."""

    def test_stats_structure(self) -> None:
        bf = BloomFilter(expected_items=N_ITEMS, false_positive_rate=FP_RATE)
        _insert_items(bf)
        s = bf.stats()

        required_keys = {"m_bits", "k_hashes", "items_added", "fill_ratio", "estimated_fp_rate"}
        assert required_keys.issubset(set(s.keys()))

    def test_m_bits_correct(self) -> None:
        bf = BloomFilter(expected_items=N_ITEMS, false_positive_rate=FP_RATE)
        # m = -(n * ln(p)) / (ln 2)^2 ≈ 95851 for n=10000, p=0.01
        expected_m = int(math.ceil(-(N_ITEMS * math.log(FP_RATE)) / (math.log(2) ** 2)))
        assert bf.stats()["m_bits"] == expected_m

    def test_k_hashes_correct(self) -> None:
        bf = BloomFilter(expected_items=N_ITEMS, false_positive_rate=FP_RATE)
        # k = (m/n) * ln 2 ≈ 7 for standard params
        s = bf.stats()
        assert 1 <= s["k_hashes"] <= 20

    def test_fill_ratio_increases(self) -> None:
        bf = BloomFilter(expected_items=N_ITEMS, false_positive_rate=FP_RATE)
        s0 = bf.stats()
        _insert_items(bf)
        s1 = bf.stats()
        assert s1["fill_ratio"] > s0["fill_ratio"]

    def test_fill_ratio_in_range(self) -> None:
        bf = BloomFilter(expected_items=N_ITEMS, false_positive_rate=FP_RATE)
        _insert_items(bf)
        s = bf.stats()
        assert 0.0 <= s["fill_ratio"] <= 1.0

    def test_estimated_fp_rate_reasonable(self) -> None:
        bf = BloomFilter(expected_items=N_ITEMS, false_positive_rate=FP_RATE)
        _insert_items(bf)
        s = bf.stats()
        # After inserting exactly n items the estimated FP should be near p
        assert s["estimated_fp_rate"] <= FP_RATE * 3

    def test_items_added_count(self) -> None:
        bf = BloomFilter(expected_items=N_ITEMS, false_positive_rate=FP_RATE)
        items = _insert_items(bf)
        assert bf.stats()["items_added"] == len(items)
        assert len(bf) == len(items)


class TestBloomFilterInvalidParams:
    """Error handling for bad constructor arguments."""

    def test_zero_expected_items_raises(self) -> None:
        with pytest.raises(BloomFilterError):
            BloomFilter(expected_items=0)

    def test_negative_expected_items_raises(self) -> None:
        with pytest.raises(BloomFilterError):
            BloomFilter(expected_items=-100)

    def test_fp_rate_zero_raises(self) -> None:
        with pytest.raises(BloomFilterError):
            BloomFilter(expected_items=100, false_positive_rate=0.0)

    def test_fp_rate_one_raises(self) -> None:
        with pytest.raises(BloomFilterError):
            BloomFilter(expected_items=100, false_positive_rate=1.0)
