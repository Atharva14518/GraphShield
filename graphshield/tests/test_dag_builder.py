
from __future__ import annotations

from pathlib import Path
from typing import List

import pytest

from graphshield.core.dag_builder import DependencyDAG, NodeMetadata, find_all_manifests
from graphshield.core.manifest_parser import Dependency

def make_deps(*specs: tuple) -> List[Dependency]:
    result = []
    for name, version, is_direct, parent in specs:
        result.append(
            Dependency(
                name=name,
                version=version,
                ecosystem="npm",
                is_dev=False,
                is_direct=is_direct,
                parent=parent,
            )
        )
    return result

class TestBuildFromDeps:
    def test_node_count(self) -> None:
        deps = make_deps(
            ("express", "4.18.2", True, None),
            ("lodash", "4.17.20", True, None),
            ("qs", "6.5.2", False, "express"),
        )
        dag = DependencyDAG()
        dag.build_from_dependencies(deps)
        assert dag.node_count() == 4

    def test_edges_direction_correct(self) -> None:
        deps = make_deps(
            ("express", "4.18.2", True, None),
            ("qs", "6.5.2", False, "express"),
        )
        dag = DependencyDAG()
        dag.build_from_dependencies(deps)
        assert dag.graph.has_edge("express", "qs")
        assert not dag.graph.has_edge("qs", "express")

    def test_version_stored_in_metadata(self) -> None:
        deps = make_deps(("lodash", "4.17.20", True, None))
        dag = DependencyDAG()
        dag.build_from_dependencies(deps)
        assert dag.metadata["lodash"].version == "4.17.20"

    def test_duplicate_package_higher_version_wins(self) -> None:
        deps = [
            Dependency("lodash", "3.0.0", "npm", is_dev=False, is_direct=True),
            Dependency("lodash", "4.17.20", "npm", is_dev=False, is_direct=False),
        ]
        dag = DependencyDAG()
        dag.build_from_dependencies(deps)
        assert dag.metadata["lodash"].version == "4.17.20"

    def test_ecosystem_detected(self) -> None:
        deps = make_deps(("express", "4.18.2", True, None))
        dag = DependencyDAG()
        dag.build_from_dependencies(deps)
        assert dag.ecosystem == "npm"

class TestTopologicalSort:
    def test_topological_sort_order(self) -> None:
        deps = [
            Dependency("A", "1.0.0", "npm", False, True, None),
            Dependency("B", "1.0.0", "npm", False, False, "A"),
            Dependency("C", "1.0.0", "npm", False, False, "B"),
        ]
        dag = DependencyDAG()
        dag.build_from_dependencies(deps)
        order = dag.compute_topological_sort()
        assert order.index("A") < order.index("B")
        assert order.index("B") < order.index("C")

    def test_topological_rank_assigned(self, sample_dag: DependencyDAG) -> None:
        sample_dag.compute_topological_sort()
        for node in sample_dag.graph.nodes:
            assert sample_dag.metadata[node].topological_rank is not None

    def test_cycle_detection(self) -> None:
        dag = DependencyDAG()
        dag.graph.add_nodes_from(["A", "B", "C"])
        dag.metadata["A"] = NodeMetadata("A", "1.0.0", "npm", True, False)
        dag.metadata["B"] = NodeMetadata("B", "1.0.0", "npm", False, False)
        dag.metadata["C"] = NodeMetadata("C", "1.0.0", "npm", False, False)
        dag.graph.add_edges_from([("A", "B"), ("B", "C"), ("C", "A")])

        order = dag.compute_topological_sort()
        assert set(order) == {"A", "B", "C"}
        assert len(dag._cycles) >= 1

    def test_no_cycles_in_normal_dag(self, sample_dag: DependencyDAG) -> None:
        dag = sample_dag
        dag.compute_topological_sort()
        assert dag._cycles == []

class TestDownstreamNodes:
    def test_downstream_nodes_correct(self, sample_dag: DependencyDAG) -> None:
        downstream = sample_dag.get_downstream_nodes("__root__")
        expected = {"express", "lodash", "axios", "qs", "follow-redirects"}
        assert expected.issubset(downstream)

    def test_leaf_node_no_downstream(self, sample_dag: DependencyDAG) -> None:
        assert sample_dag.get_downstream_nodes("qs") == set()

    def test_upstream_nodes(self, sample_dag: DependencyDAG) -> None:
        upstream = sample_dag.get_upstream_nodes("qs")
        assert "express" in upstream
        assert "__root__" in upstream

    def test_get_downstream_missing_node(self, sample_dag: DependencyDAG) -> None:
        assert sample_dag.get_downstream_nodes("nonexistent") == set()

class TestTopoRiskScores:
    def test_topo_risk_amplified_for_early_nodes(
        self, sample_dag: DependencyDAG
    ) -> None:
        for node in ["lodash", "qs"]:
            meta = sample_dag.metadata[node]
            if meta.cvss_score is not None:
                assert meta.topological_risk_score is not None
                assert meta.topological_risk_score >= meta.cvss_score

    def test_clean_nodes_no_topo_risk(self, sample_dag: DependencyDAG) -> None:
        express_meta = sample_dag.metadata["express"]
        assert express_meta.topological_risk_score is None

    def test_topo_risk_positive(self, sample_dag: DependencyDAG) -> None:
        for node, meta in sample_dag.metadata.items():
            if meta.topological_risk_score is not None:
                assert meta.topological_risk_score > 0

class TestFindAllManifests:
    def test_finds_package_json(self, tmp_path: Path) -> None:
        (tmp_path / "package.json").write_text('{"name":"test"}')
        found = find_all_manifests(tmp_path)
        assert any(p.name == "package.json" for p in found)

    def test_skips_node_modules(self, tmp_path: Path) -> None:
        nm = tmp_path / "node_modules" / "some-pkg"
        nm.mkdir(parents=True)
        (nm / "package.json").write_text('{"name":"hidden"}')
        (tmp_path / "package.json").write_text('{"name":"root"}')
        found = find_all_manifests(tmp_path)
        for p in found:
            assert "node_modules" not in p.parts, (
                f"Expected node_modules to be skipped, got: {p}"
            )

    def test_lock_file_before_package_json_same_dir(self, tmp_path: Path) -> None:
        (tmp_path / "package.json").write_text('{"name":"test"}')
        (tmp_path / "package-lock.json").write_text('{"lockfileVersion":2,"packages":{}}')
        found = find_all_manifests(tmp_path)
        names = [p.name for p in found]
        lock_idx = names.index("package-lock.json")
        pkg_idx = names.index("package.json")
        assert lock_idx < pkg_idx

    def test_multiple_formats_found(self, tmp_path: Path) -> None:
        (tmp_path / "package.json").write_text('{"dependencies":{}}')
        (tmp_path / "requirements.txt").write_text("requests==2.28.0\n")
        found = find_all_manifests(tmp_path)
        names = {p.name for p in found}
        assert "package.json" in names
        assert "requirements.txt" in names
