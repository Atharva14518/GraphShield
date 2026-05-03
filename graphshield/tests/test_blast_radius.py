"""
Tests for graphshield.algorithms.blast_radius.

Covers:
  - test_reachable_nodes_correct
  - test_sensitive_sink_detected
  - test_blast_score_formula
  - test_no_sinks_low_sensitivity
  - test_credential_sink_critical_sensitivity
"""

from __future__ import annotations

import math

import pytest

from graphshield.algorithms.blast_radius import (
    SENSITIVE_SINKS,
    SENSITIVITY_MULTIPLIER,
    BlastRadiusResult,
    AttackPath,
    compute_blast_radius,
    compute_all_blast_radii,
    _determine_sensitivity,
)
from graphshield.core.dag_builder import DependencyDAG, NodeMetadata
from graphshield.core.manifest_parser import Dependency


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_dag(*deps_specs) -> DependencyDAG:
    """Quick helper — specs: (name, version, parent_or_None)."""
    deps = []
    for spec in deps_specs:
        name, version, parent = spec
        deps.append(
            Dependency(
                name=name, version=version, ecosystem="npm",
                is_dev=False, is_direct=(parent is None), parent=parent,
            )
        )
    dag = DependencyDAG(ecosystem="npm")
    dag.build_from_dependencies(deps)
    dag.compute_topological_sort()
    return dag


# ---------------------------------------------------------------------------
# _determine_sensitivity
# ---------------------------------------------------------------------------


class TestDetermineSensitivity:
    def test_empty_gives_low(self) -> None:
        assert _determine_sensitivity([]) == "LOW"

    def test_network_gives_medium(self) -> None:
        assert _determine_sensitivity(["network"]) == "MEDIUM"

    def test_database_gives_high(self) -> None:
        assert _determine_sensitivity(["database"]) == "HIGH"

    def test_credential_gives_critical(self) -> None:
        assert _determine_sensitivity(["credential"]) == "CRITICAL"

    def test_crypto_gives_critical(self) -> None:
        assert _determine_sensitivity(["crypto"]) == "CRITICAL"

    def test_mixed_escalates_to_highest(self) -> None:
        assert _determine_sensitivity(["network", "database"]) == "HIGH"
        assert _determine_sensitivity(["network", "credential"]) == "CRITICAL"


# ---------------------------------------------------------------------------
# compute_blast_radius
# ---------------------------------------------------------------------------


class TestComputeBlastRadius:
    def test_reachable_nodes_correct(self, sample_dag: DependencyDAG) -> None:
        """qs has 0 downstream nodes (it's a leaf)."""
        result = compute_blast_radius(
            "qs", sample_dag, "CVE-2022-24999", 7.5
        )
        assert result.reachable_count == 0
        assert result.reachable_nodes == []

    def test_vulnerable_root_reaches_all(self, sample_dag: DependencyDAG) -> None:
        """__root__ reaches all packages in the sample DAG."""
        # Inject a CVE onto __root__ to test
        result = compute_blast_radius(
            "__root__", sample_dag, "CVE-TEST", 9.0
        )
        # __root__ should reach express, lodash, axios, qs, follow-redirects
        assert result.reachable_count >= 5

    def test_sensitive_sink_detected(self) -> None:
        """Verify that 'requests' (a known network sink) is flagged."""
        dag = _make_dag(
            ("vulnerable-pkg", "1.0.0", None),
            ("requests", "2.28.0", "vulnerable-pkg"),
        )
        result = compute_blast_radius(
            "vulnerable-pkg", dag, "CVE-TEST", 7.0
        )
        assert "requests" in result.sensitive_sinks_reachable
        assert "network" in result.sink_types
        assert result.data_sensitivity in ("MEDIUM", "HIGH", "CRITICAL")

    def test_no_sinks_low_sensitivity(self) -> None:
        """A package with no sink descendants → LOW sensitivity."""
        dag = _make_dag(
            ("a", "1.0.0", None),
            ("b", "1.0.0", "a"),   # b is not a known sink
        )
        result = compute_blast_radius("a", dag, "CVE-TEST", 5.0)
        assert result.data_sensitivity == "LOW"
        assert result.sensitive_sinks_reachable == []

    def test_credential_sink_critical_sensitivity(self) -> None:
        """dotenv is a credential sink — should trigger CRITICAL sensitivity."""
        dag = _make_dag(
            ("some-pkg", "1.0.0", None),
            ("python_dotenv", "0.21.0", "some-pkg"),
        )
        result = compute_blast_radius("some-pkg", dag, "CVE-TEST", 8.0)
        assert result.data_sensitivity == "CRITICAL"
        assert "credential" in result.sink_types

    def test_blast_score_formula(self) -> None:
        """Verify score = cvss × log2(1 + reachable) × sensitivity_mult."""
        dag = _make_dag(
            ("vuln", "1.0.0", None),
            ("dep1", "1.0.0", "vuln"),
            ("dep2", "1.0.0", "vuln"),
        )
        cvss = 7.0
        result = compute_blast_radius("vuln", dag, "CVE-TEST", cvss)
        reachable = result.reachable_count
        mult = SENSITIVITY_MULTIPLIER[result.data_sensitivity]
        expected = cvss * math.log2(1 + reachable) * mult
        assert abs(result.blast_radius_score - round(expected, 4)) < 0.01

    def test_blast_score_increases_with_reachable(self) -> None:
        """More reachable nodes → higher blast radius score."""
        dag_small = _make_dag(
            ("v", "1.0.0", None),
            ("d1", "1.0.0", "v"),
        )
        dag_large = _make_dag(
            ("v", "1.0.0", None),
            ("d1", "1.0.0", "v"),
            ("d2", "1.0.0", "v"),
            ("d3", "1.0.0", "v"),
            ("d4", "1.0.0", "v"),
        )
        r1 = compute_blast_radius("v", dag_small, "CVE-A", 7.0)
        r2 = compute_blast_radius("v", dag_large, "CVE-A", 7.0)
        assert r2.blast_radius_score >= r1.blast_radius_score

    def test_topological_rank_captured(self, sample_dag: DependencyDAG) -> None:
        result = compute_blast_radius("qs", sample_dag, "CVE-TEST", 7.5)
        assert result.topological_rank is not None

    def test_attack_paths_found(self) -> None:
        """Verify attack paths are generated when a sink is reachable."""
        dag = _make_dag(
            ("vuln", "1.0.0", None),
            ("sqlalchemy", "1.4.0", "vuln"),  # known DB sink
        )
        result = compute_blast_radius("vuln", dag, "CVE-TEST", 8.0)
        assert len(result.attack_paths) > 0
        ap = result.attack_paths[0]
        assert ap.path[0] == "vuln"
        assert ap.sink_node in {"sqlalchemy"}

    def test_attack_paths_sorted_by_score(self) -> None:
        """attack_paths must be sorted descending by exploit_score."""
        dag = _make_dag(
            ("vuln", "1.0.0", None),
            ("requests", "2.0.0", "vuln"),
            ("sqlalchemy", "1.4.0", "vuln"),
        )
        result = compute_blast_radius("vuln", dag, "CVE-TEST", 8.0)
        if len(result.attack_paths) >= 2:
            for i in range(len(result.attack_paths) - 1):
                assert result.attack_paths[i].exploit_score >= result.attack_paths[i + 1].exploit_score


# ---------------------------------------------------------------------------
# compute_all_blast_radii
# ---------------------------------------------------------------------------


class TestComputeAllBlastRadii:
    def test_only_cve_nodes_scanned(self, sample_dag: DependencyDAG) -> None:
        results = compute_all_blast_radii(sample_dag)
        result_nodes = {r.source_node for r in results}
        # Only qs, lodash, follow-redirects have CVEs in sample_dag
        assert "express" not in result_nodes
        assert "axios" not in result_nodes

    def test_results_sorted_by_blast_score(self, sample_dag: DependencyDAG) -> None:
        results = compute_all_blast_radii(sample_dag)
        if len(results) >= 2:
            for i in range(len(results) - 1):
                assert results[i].blast_radius_score >= results[i + 1].blast_radius_score

    def test_metadata_updated(self, sample_dag: DependencyDAG) -> None:
        """blast_radius_score must be written back to dag.metadata."""
        compute_all_blast_radii(sample_dag)
        for node in ["qs", "lodash", "follow-redirects"]:
            meta = sample_dag.metadata.get(node)
            if meta and meta.cvss_score:
                assert meta.blast_radius_score is not None

    def test_clean_dag_returns_empty(self) -> None:
        """A DAG with no CVEs should return an empty list."""
        dag = _make_dag(
            ("clean-a", "1.0.0", None),
            ("clean-b", "1.0.0", "clean-a"),
        )
        results = compute_all_blast_radii(dag)
        assert results == []
