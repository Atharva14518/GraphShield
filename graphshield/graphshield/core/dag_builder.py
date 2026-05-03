
from __future__ import annotations

import logging
import math
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set

import networkx as nx

from graphshield.config import DB_PATH, MANIFEST_SKIP_DIRS
from graphshield.core.manifest_parser import Dependency, parse_manifest
from graphshield.exceptions import ManifestParseError

logger = logging.getLogger(__name__)

_PREFERRED_ORDER = [
    "package-lock.json",
    "package.json",
    "requirements.txt",
    "Pipfile",
    "pyproject.toml",
    "pom.xml",
]

@dataclass
class NodeMetadata:

    name: str
    version: str
    ecosystem: str
    is_direct: bool
    is_dev: bool
    topological_rank: Optional[int] = None
    cvss_score: Optional[float] = None
    cve_ids: List[str] = field(default_factory=list)
    topological_risk_score: Optional[float] = None
    blast_radius_score: Optional[float] = None

class DependencyDAG:

    def __init__(self, ecosystem: str = "unknown") -> None:
        self.graph: nx.DiGraph = nx.DiGraph()
        self.metadata: Dict[str, NodeMetadata] = {}
        self.ecosystem: str = ecosystem
        self._cycles: List[List[str]] = []
        self._topo_order: List[str] = []

    def build_from_dependencies(self, deps: List[Dependency]) -> None:
        from graphshield.core.avl_tree import parse_semver

        eco_counts: Dict[str, int] = {}
        for d in deps:
            eco_counts[d.ecosystem] = eco_counts.get(d.ecosystem, 0) + 1
        if eco_counts:
            self.ecosystem = max(eco_counts, key=eco_counts.get)

        node_registry: Dict[str, Dependency] = {}
        for dep in deps:
            existing = node_registry.get(dep.name)
            if existing is None:
                node_registry[dep.name] = dep
            else:
                try:
                    existing_t = parse_semver(existing.version)
                    new_t = parse_semver(dep.version)
                    from graphshield.core.avl_tree import _compare_versions
                    if _compare_versions(new_t, existing_t) > 0:
                        node_registry[dep.name] = dep
                except Exception:
                    pass

        for name, dep in node_registry.items():
            self.graph.add_node(name)
            self.metadata[name] = NodeMetadata(
                name=name,
                version=dep.version,
                ecosystem=dep.ecosystem,
                is_direct=dep.is_direct,
                is_dev=dep.is_dev,
            )

        direct_without_parent = [
            d for d in deps if d.is_direct and d.parent is None and d.name != "__root__"
        ]
        if direct_without_parent:
            if "__root__" not in self.graph:
                self.graph.add_node("__root__")
                self.metadata["__root__"] = NodeMetadata(
                    name="__root__",
                    version="0.0.0",
                    ecosystem=self.ecosystem,
                    is_direct=True,
                    is_dev=False,
                )
            for dep in direct_without_parent:
                if dep.name in self.graph and dep.name != "__root__":
                    self.graph.add_edge("__root__", dep.name)

        for dep in deps:
            if dep.parent and dep.parent != dep.name:
                if dep.parent not in self.graph:
                    self.graph.add_node(dep.parent)
                    if dep.parent not in self.metadata:
                        self.metadata[dep.parent] = NodeMetadata(
                            name=dep.parent,
                            version="unknown",
                            ecosystem=self.ecosystem,
                            is_direct=False,
                            is_dev=False,
                        )
                if dep.name not in self.graph:
                    self.graph.add_node(dep.name)
                self.graph.add_edge(dep.parent, dep.name)

    def compute_topological_sort(self) -> List[str]:
        work_graph = self.graph.copy()

        try:
            cycles = list(nx.simple_cycles(work_graph))
        except Exception:
            cycles = []

        self._cycles = cycles
        for cycle in cycles:
            if len(cycle) >= 2:
                edges = [(cycle[i], cycle[(i + 1) % len(cycle)]) for i in range(len(cycle))]
                lowest_edge = min(
                    edges,
                    key=lambda e: work_graph.in_degree(e[0]),
                )
                if work_graph.has_edge(*lowest_edge):
                    work_graph.remove_edge(*lowest_edge)
                    logger.debug("Broke cycle at edge %s → %s", *lowest_edge)

        try:
            order = list(nx.topological_sort(work_graph))
        except nx.NetworkXUnfeasible:
            order = list(work_graph.nodes)

        self._topo_order = order
        for rank, node in enumerate(order):
            if node in self.metadata:
                self.metadata[node].topological_rank = rank

        return order

    def compute_topological_risk_scores(
        self, cve_scores: Dict[str, float]
    ) -> None:
        total = max(1, self.graph.number_of_nodes())

        for node, cvss in cve_scores.items():
            if node not in self.graph:
                continue
            downstream = len(nx.descendants(self.graph, node))
            amplification = math.log(1 + downstream) / math.log(total) if total > 1 else 0
            topo_risk = cvss * (1 + amplification)

            if node in self.metadata:
                self.metadata[node].cvss_score = cvss
                self.metadata[node].topological_risk_score = round(topo_risk, 4)

    def get_downstream_nodes(self, node: str) -> Set[str]:
        if node not in self.graph:
            return set()
        return nx.descendants(self.graph, node)

    def get_upstream_nodes(self, node: str) -> Set[str]:
        if node not in self.graph:
            return set()
        return nx.ancestors(self.graph, node)

    def node_count(self) -> int:
        return self.graph.number_of_nodes()

    def edge_count(self) -> int:
        return self.graph.number_of_edges()

    def __repr__(self) -> str:
        return (
            f"DependencyDAG(ecosystem={self.ecosystem!r}, "
            f"nodes={self.node_count()}, edges={self.edge_count()})"
        )

def build_dag_from_manifest(
    manifest_path: Path,
    db_path: Path = DB_PATH,
) -> "DependencyDAG":
    from graphshield.config import BLOOM_PATH
    from graphshield.core.avl_tree import build_version_tree
    from graphshield.core.bloom_filter import BloomFilter

    deps = parse_manifest(manifest_path)
    dag = DependencyDAG()
    dag.build_from_dependencies(deps)
    dag.compute_topological_sort()

    cve_scores: Dict[str, float] = {}
    bloom: Optional[BloomFilter] = None
    if BLOOM_PATH.exists():
        try:
            bloom = BloomFilter.load(BLOOM_PATH)
        except Exception:
            bloom = None

    for node in list(dag.graph.nodes):
        meta = dag.metadata.get(node)
        if meta is None:
            continue
        key = f"{node}@{meta.version}"
        if bloom is not None and not bloom.contains(node):
            continue
        if db_path.exists():
            tree = build_version_tree(node, db_path)
            if tree.size() > 0:
                matches = tree.query(meta.version)
                if matches:
                    best = max(matches, key=lambda x: x.cvss_score)
                    meta.cvss_score = best.cvss_score
                    meta.cve_ids = [m.cve_id for m in matches]
                    cve_scores[node] = best.cvss_score

    dag.compute_topological_risk_scores(cve_scores)
    return dag

def find_all_manifests(root: Path) -> List[Path]:
    manifests: List[Path] = []
    root = root.resolve()

    for candidate in root.rglob("*"):
        parts_set = set(candidate.parts)
        if parts_set & MANIFEST_SKIP_DIRS:
            continue
        if candidate.name.lower() in {n.lower() for n in _PREFERRED_ORDER}:
            manifests.append(candidate)

    def _sort_key(p: Path) -> tuple:
        name_lower = p.name.lower()
        try:
            priority = [n.lower() for n in _PREFERRED_ORDER].index(name_lower)
        except ValueError:
            priority = 99
        return (str(p.parent), priority)

    manifests.sort(key=_sort_key)
    return manifests
