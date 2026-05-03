"""
Tests for graphshield.algorithms.tarjan_scc.

Covers:
  - test_simple_cycle_detected: A→B→C→A returns [[A,B,C]]
  - test_dag_no_cycles: linear chain returns all size-1 SCCs
  - test_disconnected_components: mixed graph
  - test_classification_thresholds: size 2→LOW, 4→MEDIUM, 7→HIGH, 11→CRITICAL
  - test_cvss_escalation: MEDIUM SCC with CVSS 8.5 → HIGH
"""

from __future__ import annotations

import networkx as nx
import pytest

from graphshield.algorithms.tarjan_scc import (
    CircularTrustCluster,
    classify_circular_trust,
    find_all_circular_trust,
    tarjan_scc,
)
from graphshield.core.dag_builder import DependencyDAG, NodeMetadata


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_dag_with_metadata(nodes: list, edges: list) -> DependencyDAG:
    """Create a DependencyDAG with a given node/edge set."""
    dag = DependencyDAG()
    for n in nodes:
        dag.graph.add_node(n)
        dag.metadata[n] = NodeMetadata(
            name=n, version="1.0.0", ecosystem="npm",
            is_direct=True, is_dev=False
        )
    dag.graph.add_edges_from(edges)
    return dag


# ---------------------------------------------------------------------------
# tarjan_scc correctness
# ---------------------------------------------------------------------------


class TestTarjanSCC:
    def test_simple_cycle_detected(self) -> None:
        """A→B→C→A should produce one SCC of size 3."""
        g = nx.DiGraph([("A", "B"), ("B", "C"), ("C", "A")])
        sccs = tarjan_scc(g)
        # Find the SCC containing A
        cycle_scc = next((s for s in sccs if "A" in s), None)
        assert cycle_scc is not None
        assert set(cycle_scc) == {"A", "B", "C"}

    def test_dag_no_sccs(self) -> None:
        """Linear chain A→B→C — all SCCs should be size 1."""
        g = nx.DiGraph([("A", "B"), ("B", "C")])
        sccs = tarjan_scc(g)
        assert all(len(scc) == 1 for scc in sccs)
        assert len(sccs) == 3

    def test_all_nodes_covered(self) -> None:
        """Every node must appear in exactly one SCC."""
        g = nx.DiGraph([("A", "B"), ("B", "C"), ("C", "A"), ("D", "E")])
        sccs = tarjan_scc(g)
        all_nodes = set()
        for scc in sccs:
            for n in scc:
                assert n not in all_nodes, f"Node {n} appears in multiple SCCs"
                all_nodes.add(n)
        assert all_nodes == {"A", "B", "C", "D", "E"}

    def test_disconnected_mixed_graph(self) -> None:
        """Graph: A→B, C→D→E→C should produce [A],[B],[C,D,E]."""
        g = nx.DiGraph([("A", "B"), ("C", "D"), ("D", "E"), ("E", "C")])
        sccs = tarjan_scc(g)
        scc_sets = [frozenset(s) for s in sccs]
        assert frozenset({"A"}) in scc_sets
        assert frozenset({"B"}) in scc_sets
        assert frozenset({"C", "D", "E"}) in scc_sets

    def test_self_loop_is_cyclic_scc(self) -> None:
        """A node with a self-loop forms an SCC of size 1, but Tarjan returns it."""
        g = nx.DiGraph([("A", "A")])
        sccs = tarjan_scc(g)
        assert len(sccs) == 1
        assert sccs[0] == ["A"]

    def test_two_separate_cycles(self) -> None:
        """Two separate cycles should produce two SCCs of size > 1."""
        g = nx.DiGraph(
            [("A", "B"), ("B", "A"), ("C", "D"), ("D", "C")]
        )
        sccs = tarjan_scc(g)
        multi_node_sccs = [s for s in sccs if len(s) > 1]
        assert len(multi_node_sccs) == 2

    def test_large_graph_no_crash(self) -> None:
        """100-node chain: Tarjan must not hit recursion limit."""
        g = nx.DiGraph()
        for i in range(99):
            g.add_edge(f"pkg_{i}", f"pkg_{i+1}")
        sccs = tarjan_scc(g)
        assert len(sccs) == 100


# ---------------------------------------------------------------------------
# CircularTrustCluster classification
# ---------------------------------------------------------------------------


class TestClassifyCircularTrust:
    def _dag_with_cvss(self, nodes: list, cvss_map: dict) -> DependencyDAG:
        dag = _make_dag_with_metadata(nodes, [])
        for n, score in cvss_map.items():
            if n in dag.metadata:
                dag.metadata[n].cvss_score = score
        return dag

    def test_size_2_is_low(self) -> None:
        dag = self._dag_with_cvss(["A", "B"], {})
        cluster = classify_circular_trust(["A", "B"], dag)
        assert cluster.risk_level == "LOW"

    def test_size_4_is_medium(self) -> None:
        dag = self._dag_with_cvss(["A", "B", "C", "D"], {})
        cluster = classify_circular_trust(["A", "B", "C", "D"], dag)
        assert cluster.risk_level == "MEDIUM"

    def test_size_7_is_high(self) -> None:
        nodes = [f"n{i}" for i in range(7)]
        dag = self._dag_with_cvss(nodes, {})
        cluster = classify_circular_trust(nodes, dag)
        assert cluster.risk_level == "HIGH"

    def test_size_11_is_critical(self) -> None:
        nodes = [f"n{i}" for i in range(11)]
        dag = self._dag_with_cvss(nodes, {})
        cluster = classify_circular_trust(nodes, dag)
        assert cluster.risk_level == "CRITICAL"

    def test_cvss_escalation_medium_to_high(self) -> None:
        """SCC size 3 (normally MEDIUM) with CVSS 8.5 node → HIGH."""
        nodes = ["A", "B", "C"]
        dag = self._dag_with_cvss(nodes, {"A": 8.5})
        cluster = classify_circular_trust(nodes, dag)
        assert cluster.risk_level == "HIGH"

    def test_cvss_critical_jumps_to_critical(self) -> None:
        """SCC size 2 (LOW) with CVSS 9.5 → CRITICAL immediately."""
        dag = self._dag_with_cvss(["A", "B"], {"A": 9.5})
        cluster = classify_circular_trust(["A", "B"], dag)
        assert cluster.risk_level == "CRITICAL"

    def test_max_cvss_captured(self) -> None:
        nodes = ["A", "B", "C"]
        dag = self._dag_with_cvss(nodes, {"A": 5.0, "B": 8.0, "C": 3.0})
        cluster = classify_circular_trust(nodes, dag)
        assert cluster.max_cvss_in_cluster == 8.0


# ---------------------------------------------------------------------------
# find_all_circular_trust
# ---------------------------------------------------------------------------


class TestFindAllCircularTrust:
    def test_no_clusters_clean_dag(self, sample_dag: DependencyDAG) -> None:
        # sample_dag has no cycles
        clusters = find_all_circular_trust(sample_dag)
        assert clusters == []

    def test_finds_cluster_with_injected_cycle(self) -> None:
        dag = _make_dag_with_metadata(
            ["A", "B", "C", "D"],
            [("A", "B"), ("B", "C"), ("C", "A"), ("A", "D")],
        )
        clusters = find_all_circular_trust(dag)
        assert len(clusters) == 1
        assert set(clusters[0].nodes) == {"A", "B", "C"}

    def test_sorted_critical_first(self) -> None:
        """CRITICAL cluster should appear before MEDIUM cluster."""
        dag = _make_dag_with_metadata(
            [f"n{i}" for i in range(15)],
            # Big cycle 0-10
            [(f"n{i}", f"n{i+1}") for i in range(10)] + [("n10", "n0")]
            # Small cycle 11-12
            + [("n11", "n12"), ("n12", "n11")],
        )
        clusters = find_all_circular_trust(dag)
        risk_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        levels = [c.risk_level for c in clusters]
        assert levels == sorted(levels, key=lambda l: risk_order.get(l, 99))
