"""
Dependency DAG builder.

Converts a list of :class:`~graphshield.core.manifest_parser.Dependency`
objects into a :class:`networkx.DiGraph` where:

  * **Nodes** represent packages (key = package name).
  * **Edges** A → B mean: package A *depends on* package B.
  * **Node attributes** include resolved version, ecosystem, CVE data,
    and computed risk scores.

Topological risk scoring
------------------------
Packages that load early (many others depend on them) AND carry a CVE
are amplified beyond their raw CVSS score using the formula::

    topo_risk = cvss × (1 + log(1 + downstream_count) / log(total_nodes))

This captures the graph-structural danger that flat CVSS scanners miss.
"""

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

# Manifest filenames sorted by preference (lock file before declaration file)
_PREFERRED_ORDER = [
    "package-lock.json",
    "package.json",
    "requirements.txt",
    "Pipfile",
    "pyproject.toml",
    "pom.xml",
]


# ---------------------------------------------------------------------------
# Node metadata
# ---------------------------------------------------------------------------


@dataclass
class NodeMetadata:
    """All per-package metadata stored alongside a DAG node.

    Attributes:
        name: Package name (same as the node key).
        version: Resolved version string.
        ecosystem: Ecosystem: ``"npm"`` | ``"pip"`` | ``"maven"`` | ``"unknown"``.
        is_direct: ``True`` if the package appears directly in a manifest.
        is_dev: ``True`` if declared only in a dev/test section.
        topological_rank: Position in topological sort (0 = first loaded).
        cvss_score: Highest CVSS score among the package's confirmed CVEs.
        cve_ids: List of CVE identifiers matching this package/version.
        topological_risk_score: Amplified risk (CVSS × graph-position factor).
        blast_radius_score: Populated later by the blast-radius algorithm.
    """

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


# ---------------------------------------------------------------------------
# DependencyDAG
# ---------------------------------------------------------------------------


class DependencyDAG:
    """Directed Acyclic Graph of package dependencies.

    Each node is identified by the package *name* (version stored in
    :attr:`metadata`).  Edges point from a package to its dependencies
    (A → B means "A requires B").

    Args:
        ecosystem: Primary ecosystem for the graph (informational).
    """

    def __init__(self, ecosystem: str = "unknown") -> None:
        self.graph: nx.DiGraph = nx.DiGraph()
        self.metadata: Dict[str, NodeMetadata] = {}
        self.ecosystem: str = ecosystem
        self._cycles: List[List[str]] = []
        self._topo_order: List[str] = []

    # ------------------------------------------------------------------
    # Construction
    # ------------------------------------------------------------------

    def build_from_dependencies(self, deps: List[Dependency]) -> None:
        """Populate the graph from a flat dependency list.

        Duplicate packages (same name, different versions) are resolved
        by keeping the higher version.  Parent–child edges are added
        when a :class:`Dependency` has a non-``None`` parent field.
        Direct dependencies without a declared parent are connected to
        a synthetic ``__root__`` node.

        Args:
            deps: Output of :func:`~graphshield.core.manifest_parser.parse_manifest`.
        """
        from graphshield.core.avl_tree import parse_semver

        # Choose primary ecosystem from the majority of deps
        eco_counts: Dict[str, int] = {}
        for d in deps:
            eco_counts[d.ecosystem] = eco_counts.get(d.ecosystem, 0) + 1
        if eco_counts:
            self.ecosystem = max(eco_counts, key=eco_counts.get)  # type: ignore[arg-type]

        # Build node set — resolve version conflicts by taking higher version
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
                    pass  # keep existing on parse failure

        # Add nodes
        for name, dep in node_registry.items():
            self.graph.add_node(name)
            self.metadata[name] = NodeMetadata(
                name=name,
                version=dep.version,
                ecosystem=dep.ecosystem,
                is_direct=dep.is_direct,
                is_dev=dep.is_dev,
            )

        # Add root node if there are direct deps without explicit parents
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

        # Add parent → child edges for transitive deps
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

    # ------------------------------------------------------------------
    # Topological analysis
    # ------------------------------------------------------------------

    def compute_topological_sort(self) -> List[str]:
        """Compute and store a topological ordering of the graph.

        Cycles (unusual in valid lockfiles but possible) are handled by:
        1. Detecting them with :func:`networkx.simple_cycles`.
        2. Recording them in :attr:`_cycles`.
        3. Breaking the cycle by removing the edge with the lowest
           in-degree on the source node.
        4. Rerunning the sort on the now-acyclic graph.

        The resulting order is stored in :attr:`_topo_order` and each
        node's :attr:`NodeMetadata.topological_rank` is set (0 = first
        processed = highest structural position risk).

        Returns:
            Ordered list of node names.
        """
        work_graph = self.graph.copy()

        # Detect and break cycles
        try:
            cycles = list(nx.simple_cycles(work_graph))
        except Exception:
            cycles = []

        self._cycles = cycles
        for cycle in cycles:
            if len(cycle) >= 2:
                # Remove the edge from the node with the lowest in-degree
                # to minimise structural distortion
                edges = [(cycle[i], cycle[(i + 1) % len(cycle)]) for i in range(len(cycle))]
                lowest_edge = min(
                    edges,
                    key=lambda e: work_graph.in_degree(e[0]),  # type: ignore[arg-type]
                )
                if work_graph.has_edge(*lowest_edge):
                    work_graph.remove_edge(*lowest_edge)
                    logger.debug("Broke cycle at edge %s → %s", *lowest_edge)

        try:
            order = list(nx.topological_sort(work_graph))
        except nx.NetworkXUnfeasible:
            # Fallback: just return nodes in arbitrary order
            order = list(work_graph.nodes)

        self._topo_order = order
        for rank, node in enumerate(order):
            if node in self.metadata:
                self.metadata[node].topological_rank = rank

        return order

    def compute_topological_risk_scores(
        self, cve_scores: Dict[str, float]
    ) -> None:
        """Assign amplified topological risk scores to vulnerable nodes.

        Formula::

            topo_risk = cvss × (1 + log(1 + downstream) / log(total))

        where *downstream* is the number of nodes reachable from this
        package and *total* is the total node count.  This amplifies
        packages that are both vulnerable AND depended upon by many others.

        Args:
            cve_scores: Mapping of node name → CVSS score for nodes with
                confirmed CVEs.
        """
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

    # ------------------------------------------------------------------
    # Graph traversal helpers
    # ------------------------------------------------------------------

    def get_downstream_nodes(self, node: str) -> Set[str]:
        """All nodes reachable from *node* (direct and transitive dependencies).

        Args:
            node: Source node name.

        Returns:
            Set of reachable node names (not including *node* itself).
        """
        if node not in self.graph:
            return set()
        return nx.descendants(self.graph, node)

    def get_upstream_nodes(self, node: str) -> Set[str]:
        """All nodes that can reach *node* (i.e., packages that depend on it).

        Args:
            node: Target node name.

        Returns:
            Set of ancestor node names.
        """
        if node not in self.graph:
            return set()
        return nx.ancestors(self.graph, node)

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def node_count(self) -> int:
        """Return the number of nodes in the graph."""
        return self.graph.number_of_nodes()

    def edge_count(self) -> int:
        """Return the number of edges in the graph."""
        return self.graph.number_of_edges()

    def __repr__(self) -> str:
        return (
            f"DependencyDAG(ecosystem={self.ecosystem!r}, "
            f"nodes={self.node_count()}, edges={self.edge_count()})"
        )


# ---------------------------------------------------------------------------
# Factory functions
# ---------------------------------------------------------------------------


def build_dag_from_manifest(
    manifest_path: Path,
    db_path: Path = DB_PATH,
) -> "DependencyDAG":
    """Build a fully-populated :class:`DependencyDAG` from a single manifest file.

    Pipeline:
    1. :func:`~graphshield.core.manifest_parser.parse_manifest` → dep list.
    2. :meth:`DependencyDAG.build_from_dependencies`.
    3. :meth:`DependencyDAG.compute_topological_sort`.
    4. CVE bloom-filter pre-check + AVL tree confirmation for each node.
    5. :meth:`DependencyDAG.compute_topological_risk_scores`.

    Args:
        manifest_path: Path to any supported manifest file.
        db_path: Path to the GraphShield SQLite database.

    Returns:
        Populated :class:`DependencyDAG`.

    Raises:
        ManifestParseError: If the manifest cannot be parsed.
    """
    from graphshield.config import BLOOM_PATH
    from graphshield.core.avl_tree import build_version_tree
    from graphshield.core.bloom_filter import BloomFilter

    deps = parse_manifest(manifest_path)
    dag = DependencyDAG()
    dag.build_from_dependencies(deps)
    dag.compute_topological_sort()

    # CVE lookup (best-effort — bloom filter may not exist)
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
        # Quick bloom check; skip if bloom is unavailable (all go through)
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
    """Walk a directory tree and find all supported manifest files.

    Skips directories listed in
    :data:`~graphshield.config.MANIFEST_SKIP_DIRS` (e.g. ``node_modules``,
    ``.git``).

    Sorting priority ensures ``package-lock.json`` is listed before
    ``package.json`` for the same directory, giving the richer lock file
    precedence during batch processing.

    Args:
        root: Root directory to search.

    Returns:
        List of :class:`~pathlib.Path` objects for discovered manifest files.
    """
    manifests: List[Path] = []
    root = root.resolve()

    for candidate in root.rglob("*"):
        # Skip hidden/vendor directories — check every path component
        parts_set = set(candidate.parts)
        if parts_set & MANIFEST_SKIP_DIRS:
            continue
        if candidate.name.lower() in {n.lower() for n in _PREFERRED_ORDER}:
            manifests.append(candidate)

    # Sort: by directory (stable), then by preferred filename order within dir
    def _sort_key(p: Path) -> tuple:
        name_lower = p.name.lower()
        try:
            priority = [n.lower() for n in _PREFERRED_ORDER].index(name_lower)
        except ValueError:
            priority = 99
        return (str(p.parent), priority)

    manifests.sort(key=_sort_key)
    return manifests
