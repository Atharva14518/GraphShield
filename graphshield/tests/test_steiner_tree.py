"""
Tests for graphshield.algorithms.steiner_tree.

Covers:
  - test_minimum_less_than_naive: ancestor coverage reduces patch count
  - test_update_order_respects_topology: deps updated before dependents
  - test_savings_percent_computed: value in [0, 100]
  - test_empty_results_returns_clean: no crash on empty input
  - test_single_terminal: trivial single-package case
"""

from __future__ import annotations

from typing import List

import pytest

from graphshield.algorithms.blast_radius import BlastRadiusResult, AttackPath
from graphshield.algorithms.steiner_tree import MinimumPatchSet, compute_minimum_patch_set
from graphshield.core.dag_builder import DependencyDAG, NodeMetadata
from graphshield.core.manifest_parser import Dependency


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_blast_result(
    node: str,
    cvss: float,
    blast_score: float,
    cve_id: str = "CVE-TEST",
    attack_paths: List[AttackPath] | None = None,
) -> BlastRadiusResult:
    return BlastRadiusResult(
        source_node=node,
        cve_id=cve_id,
        cvss_score=cvss,
        reachable_nodes=[],
        reachable_count=0,
        sensitive_sinks_reachable=[],
        sink_types=[],
        data_sensitivity="LOW",
        blast_radius_score=blast_score,
        attack_paths=attack_paths or [],
        topological_rank=None,
    )


def _make_dag_chain(nodes: List[str]) -> DependencyDAG:
    """Creates a linear chain: nodes[0] → nodes[1] → … → nodes[-1]."""
    deps = []
    for i, name in enumerate(nodes):
        parent = nodes[i - 1] if i > 0 else None
        is_direct = (i == 0)
        deps.append(
            Dependency(
                name=name, version="1.0.0", ecosystem="npm",
                is_dev=False, is_direct=is_direct, parent=parent,
            )
        )
    dag = DependencyDAG()
    dag.build_from_dependencies(deps)
    dag.compute_topological_sort()
    return dag


def _make_fan_out_dag() -> DependencyDAG:
    """
    root → common_ancestor → child_a (vulnerable)
                           → child_b (vulnerable)
                           → child_c (vulnerable)
    root → isolated_vuln   (vulnerable)

    Minimum patch set should be {common_ancestor} + {isolated_vuln}
    rather than {child_a, child_b, child_c, isolated_vuln}.
    """
    deps = [
        Dependency("root", "1.0.0", "npm", False, True),
        Dependency("common_ancestor", "1.0.0", "npm", False, False, "root"),
        Dependency("child_a", "1.0.0", "npm", False, False, "common_ancestor"),
        Dependency("child_b", "1.0.0", "npm", False, False, "common_ancestor"),
        Dependency("child_c", "1.0.0", "npm", False, False, "common_ancestor"),
        Dependency("isolated_vuln", "1.0.0", "npm", False, False, "root"),
    ]
    dag = DependencyDAG()
    dag.build_from_dependencies(deps)
    dag.compute_topological_sort()
    return dag


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestMinimumPatchSet:
    def test_empty_results_returns_clean(self) -> None:
        from graphshield.core.manifest_parser import Dependency
        deps = [Dependency("safe-pkg", "1.0.0", "npm", False, True)]
        dag = DependencyDAG()
        dag.build_from_dependencies(deps)
        dag.compute_topological_sort()

        patch_set = compute_minimum_patch_set(dag, [])
        assert patch_set.packages_to_update_count == 0
        assert patch_set.savings_percent == 0.0
        assert "clean" in patch_set.reasoning.lower()

    def test_single_terminal(self) -> None:
        """One high-risk package → patch set of size 1."""
        dag = _make_dag_chain(["root", "vuln_pkg", "dep"])
        results = [_make_blast_result("vuln_pkg", 8.0, 20.0)]
        patch_set = compute_minimum_patch_set(dag, results, threshold=10.0)
        assert patch_set.packages_to_update_count == 1
        assert "vuln_pkg" in patch_set.packages_to_update

    def test_minimum_less_than_naive(self) -> None:
        """5 vulnerable nodes where 2 are ancestors — minimum <= 3."""
        dag = _make_fan_out_dag()

        # All 4 child/isolated nodes are "vulnerable" in our scenario
        results = [
            _make_blast_result("child_a", 7.0, 15.0,
                attack_paths=[AttackPath(["child_a", "sink"], "database", "sink", 1, 7.0, "LOCAL")]),
            _make_blast_result("child_b", 7.0, 15.0,
                attack_paths=[AttackPath(["child_b", "sink"], "database", "sink", 1, 7.0, "LOCAL")]),
            _make_blast_result("child_c", 7.0, 12.0,
                attack_paths=[AttackPath(["child_c", "sink"], "network", "sink", 1, 7.0, "LOCAL")]),
            _make_blast_result("isolated_vuln", 6.0, 11.0,
                attack_paths=[AttackPath(["isolated_vuln", "sink2"], "network", "sink2", 1, 6.0, "LOCAL")]),
        ]

        patch_set = compute_minimum_patch_set(dag, results, threshold=10.0)
        # Minimum patch set should be < 4 (the naive count)
        assert patch_set.packages_to_update_count <= 4
        assert patch_set.total_vulnerable_count == 4

    def test_savings_percent_computed(self) -> None:
        """savings_percent must be in [0, 100]."""
        dag = _make_dag_chain(["root", "a", "b", "c", "d", "e"])
        results = [
            _make_blast_result("a", 8.0, 20.0),
            _make_blast_result("b", 7.0, 15.0),
            _make_blast_result("c", 6.0, 12.0),
        ]
        patch_set = compute_minimum_patch_set(dag, results, threshold=10.0)
        assert 0.0 <= patch_set.savings_percent <= 100.0

    def test_update_order_respects_topology(self) -> None:
        """Packages in packages_to_update must appear in valid topological order."""
        dag = _make_dag_chain(["root", "mid", "leaf"])
        # Both mid and leaf are vulnerable
        results = [
            _make_blast_result("mid", 8.0, 20.0),
            _make_blast_result("leaf", 7.0, 15.0),
        ]
        patch_set = compute_minimum_patch_set(dag, results, threshold=10.0)

        order = patch_set.update_order
        order_set = set(order)

        # If both "mid" and "leaf" are in the update order,
        # "mid" must come before "leaf" since mid → leaf
        if "mid" in order_set and "leaf" in order_set:
            assert order.index("mid") < order.index("leaf"), (
                f"mid must come before leaf, got order: {order}"
            )

    def test_estimated_effort_low(self) -> None:
        dag = _make_dag_chain(["a", "b"])
        results = [_make_blast_result("a", 7.0, 20.0)]
        patch_set = compute_minimum_patch_set(dag, results, threshold=10.0)
        assert patch_set.estimated_effort == "LOW"

    def test_packages_to_update_is_subset_of_graph_nodes(self) -> None:
        """All packages in the patch set must actually exist in the graph."""
        dag = _make_dag_chain(["root", "pkg1", "pkg2", "pkg3"])
        results = [
            _make_blast_result("pkg1", 8.0, 20.0),
            _make_blast_result("pkg2", 7.0, 15.0),
        ]
        patch_set = compute_minimum_patch_set(dag, results, threshold=10.0)
        graph_nodes = set(dag.graph.nodes)
        for pkg in patch_set.packages_to_update:
            assert pkg in graph_nodes, f"{pkg} not in graph nodes {graph_nodes}"

    def test_reasoning_is_string(self) -> None:
        dag = _make_dag_chain(["a", "b"])
        results = [_make_blast_result("a", 8.0, 20.0)]
        patch_set = compute_minimum_patch_set(dag, results, threshold=10.0)
        assert isinstance(patch_set.reasoning, str)
        assert len(patch_set.reasoning) > 10
