
from __future__ import annotations

import math

import pytest

from graphshield.core.avl_tree import (
    AVLTree,
    VersionRange,
    build_version_tree,
    parse_semver,
    _compare_versions,
)

def make_range(
    start: str,
    end: str,
    cve_id: str = "CVE-2021-99999",
    cvss: float = 7.5,
    start_incl: bool = True,
    end_excl: bool = True,
) -> VersionRange:
    return VersionRange(
        start=start,
        end=end,
        start_inclusive=start_incl,
        end_exclusive=end_excl,
        cve_id=cve_id,
        cvss_score=cvss,
        package_name="testpkg",
    )

class TestParseSemver:
    def test_three_part(self) -> None:
        assert parse_semver("1.2.3") == (1, 2, 3)

    def test_two_part(self) -> None:
        assert parse_semver("1.2") == (1, 2, 0)

    def test_one_part(self) -> None:
        assert parse_semver("1") == (1, 0, 0)

    def test_with_v_prefix(self) -> None:
        assert parse_semver("v1.2.3") == (1, 2, 3)

    def test_pre_release(self) -> None:
        result = parse_semver("1.2.3-alpha")
        assert result[:3] == (1, 2, 3)

    def test_empty_string(self) -> None:
        assert parse_semver("") == (0, 0, 0)

    def test_wildcard(self) -> None:
        assert parse_semver("*") == (0, 0, 0)

    def test_ordering(self) -> None:
        assert _compare_versions(parse_semver("1.2.3"), parse_semver("1.2.4")) < 0
        assert _compare_versions(parse_semver("2.0.0"), parse_semver("1.9.9")) > 0
        assert _compare_versions(parse_semver("1.0.0"), parse_semver("1.0.0")) == 0

class TestAVLTreeInsertAndQuery:
    def test_insert_and_query_found(self) -> None:
        tree = AVLTree()
        tree.insert(make_range("1.2.0", "1.2.8"))
        results = tree.query("1.2.4")
        assert len(results) == 1
        assert results[0].cve_id == "CVE-2021-99999"

    def test_exclusive_end_not_found(self) -> None:
        tree = AVLTree()
        tree.insert(make_range("1.2.0", "1.2.8", end_excl=True))
        results = tree.query("1.2.8")
        assert len(results) == 0

    def test_inclusive_end_found(self) -> None:
        tree = AVLTree()
        tree.insert(make_range("1.2.0", "1.2.8", end_excl=False))
        results = tree.query("1.2.8")
        assert len(results) == 1

    def test_below_start_not_found(self) -> None:
        tree = AVLTree()
        tree.insert(make_range("1.0.0", "2.0.0"))
        results = tree.query("0.9.9")
        assert len(results) == 0

    def test_start_inclusive_found(self) -> None:
        tree = AVLTree()
        tree.insert(make_range("1.2.0", "1.2.8", start_incl=True))
        results = tree.query("1.2.0")
        assert len(results) == 1

    def test_start_exclusive_not_found(self) -> None:
        tree = AVLTree()
        tree.insert(make_range("1.2.0", "1.2.8", start_incl=False))
        results = tree.query("1.2.0")
        assert len(results) == 0

class TestAVLTreeOpenEndedRange:
    def test_open_upper_bound(self) -> None:
        tree = AVLTree()
        tree.insert(make_range("2.0.0", ""))
        assert len(tree.query("2.5.0")) == 1
        assert len(tree.query("99.0.0")) == 1

    def test_open_lower_bound(self) -> None:
        tree = AVLTree()
        tree.insert(make_range("", "1.2.0"))
        assert len(tree.query("0.1.0")) == 1
        assert len(tree.query("1.1.9")) == 1
        assert len(tree.query("1.2.0")) == 0

    def test_open_both_bounds_matches_all(self) -> None:
        tree = AVLTree()
        tree.insert(make_range("", ""))
        assert len(tree.query("0.0.1")) == 1
        assert len(tree.query("999.0.0")) == 1

class TestAVLTreeMultipleRanges:
    def test_two_overlapping_ranges_both_returned(self) -> None:
        tree = AVLTree()
        tree.insert(make_range("1.0.0", "2.0.0", cve_id="CVE-A", cvss=8.0))
        tree.insert(make_range("1.5.0", "3.0.0", cve_id="CVE-B", cvss=6.0))
        results = tree.query("1.7.0")
        cve_ids = {r.cve_id for r in results}
        assert "CVE-A" in cve_ids
        assert "CVE-B" in cve_ids

    def test_results_sorted_by_cvss_desc(self) -> None:
        tree = AVLTree()
        tree.insert(make_range("1.0.0", "2.0.0", cve_id="LOW", cvss=3.0))
        tree.insert(make_range("1.0.0", "2.0.0", cve_id="HIGH", cvss=9.5))
        tree.insert(make_range("1.0.0", "2.0.0", cve_id="MED", cvss=6.0))
        results = tree.query("1.5.0")
        scores = [r.cvss_score for r in results]
        assert scores == sorted(scores, reverse=True)

    def test_different_ranges_dont_bleed(self) -> None:
        tree = AVLTree()
        tree.insert(make_range("1.0.0", "1.5.0", cve_id="CVE-A"))
        tree.insert(make_range("2.0.0", "3.0.0", cve_id="CVE-B"))
        assert len(tree.query("1.7.0")) == 0
        assert len(tree.query("1.2.0")) == 1
        assert len(tree.query("2.5.0")) == 1

class TestAVLBalance:
    def test_sorted_insert_height_bounded(self) -> None:
        tree = AVLTree()
        for i in range(1, 101):
            vr = VersionRange(
                start=f"1.0.{i}",
                end=f"1.0.{i + 1}",
                start_inclusive=True,
                end_exclusive=True,
                cve_id=f"CVE-{i:04d}",
                cvss_score=5.0,
                package_name="testpkg",
            )
            tree.insert(vr)

        max_height = 2 * math.log2(100)
        actual_height = tree.height()
        assert actual_height <= math.ceil(max_height), (
            f"Tree height {actual_height} exceeds ceiling {math.ceil(max_height)} "
            f"(2·log₂(100)≈{max_height:.1f})"
        )

    def test_reverse_sorted_insert_height_bounded(self) -> None:
        tree = AVLTree()
        for i in range(100, 0, -1):
            vr = VersionRange(
                start=f"1.0.{i}",
                end="",
                start_inclusive=True,
                end_exclusive=True,
                cve_id=f"CVE-REV-{i:04d}",
                cvss_score=4.0,
                package_name="testpkg",
            )
            tree.insert(vr)

        max_height = math.ceil(2 * math.log2(100))
        assert tree.height() <= max_height

    def test_size_tracking(self) -> None:
        tree = AVLTree()
        for i in range(50):
            tree.insert(make_range(f"1.0.{i}", f"1.0.{i+1}", cve_id=f"CVE-{i}"))
        assert tree.size() == 50

class TestBuildVersionTree:
    def test_empty_tree_no_db(self, tmp_path: Path) -> None:
        tree = build_version_tree("nonexistent_pkg", db_path=tmp_path / "missing.db")
        assert tree.size() == 0
        assert tree.query("1.0.0") == []
