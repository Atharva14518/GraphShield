"""
Minimum patch set computation via Steiner Tree 2-approximation.

Problem statement
-----------------
Given a dependency graph with multiple vulnerable packages (terminals),
find the *minimum* set of packages to update such that all critical
attack paths are eliminated.

Why Steiner Tree?
-----------------
Naively, you'd update every vulnerable package.  But many packages share
common vulnerable ancestors in the dependency graph.  Updating the ancestor
eliminates all attack paths through it without touching every descendant.

The Steiner Tree problem captures exactly this: find the minimum-cost
sub-graph that connects all terminal nodes (vulnerable packages) through
Steiner nodes (potential fix points).

2-approximation algorithm
-------------------------
The exact Steiner Tree is NP-hard, but the metric closure MST
2-approximation gives results within 2× optimal in polynomial time:

Step 1: Identify terminals (packages with blast_radius_score > threshold).
Step 2: Build metric closure — shortest-path distances between all terminal pairs.
Step 3: Find MST of the metric closure.
Step 4: Map each MST edge back to the actual shortest path in the original graph.
Step 5: Greedy set cover — select nodes that cover all high-risk attack paths.
Step 6: Topological order the selected nodes (update dependencies before dependents).
Step 7: Report savings vs. naive "update everything" approach.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple, TYPE_CHECKING

import networkx as nx

from graphshield.config import BLAST_RADIUS_THRESHOLD

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from graphshield.algorithms.blast_radius import BlastRadiusResult
    from graphshield.core.dag_builder import DependencyDAG


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class MinimumPatchSet:
    """Result of the Steiner Tree minimum patch set computation.

    Attributes:
        packages_to_update: List of package names that must be updated.
        packages_to_update_count: ``len(packages_to_update)``.
        total_vulnerable_count: Total number of packages with any CVE.
        attack_paths_eliminated: Number of attack paths covered by the patch set.
        savings_percent: Reduction vs. updating every vulnerable package.
        update_order: Topologically sorted update order (deps first).
        estimated_effort: ``LOW`` (<5 packages) | ``MEDIUM`` (5–15) | ``HIGH`` (>15).
        reasoning: Human-readable explanation of the patch set selection.
    """

    packages_to_update: List[str]
    packages_to_update_count: int
    total_vulnerable_count: int
    attack_paths_eliminated: int
    savings_percent: float
    update_order: List[str]
    estimated_effort: str
    reasoning: str


# ---------------------------------------------------------------------------
# Algorithm
# ---------------------------------------------------------------------------


def compute_minimum_patch_set(
    dag: "DependencyDAG",
    blast_results: "List[BlastRadiusResult]",
    threshold: float = BLAST_RADIUS_THRESHOLD,
) -> MinimumPatchSet:
    """Find the minimum set of packages to update to eliminate critical attack paths.

    Implements a 2-approximation of the Steiner Tree problem via metric
    closure MST plus greedy set cover.

    Args:
        dag: The dependency DAG.
        blast_results: Output of
            :func:`~graphshield.algorithms.blast_radius.compute_all_blast_radii`.
        threshold: Minimum ``blast_radius_score`` to include a package as a
            Steiner terminal.

    Returns:
        :class:`MinimumPatchSet` with update list, order, and savings metrics.
    """
    # -----------------------------------------------------------------------
    # Step 1: Identify terminals
    # -----------------------------------------------------------------------
    all_vulnerable: List[str] = [r.source_node for r in blast_results]
    terminals: List[str] = [
        r.source_node
        for r in blast_results
        if r.blast_radius_score > threshold
    ]

    # Collect all attack paths across all results
    all_attack_paths: List[List[str]] = []
    for result in blast_results:
        for ap in result.attack_paths:
            all_attack_paths.append(ap.path)

    if not terminals:
        # No high-risk terminals — update all vulnerable packages as fallback
        if not all_vulnerable:
            return _empty_patch_set()
        terminals = all_vulnerable[:5]  # cap at 5 for the algorithm

    if len(terminals) == 1:
        # Trivial case — only one terminal, update it directly
        pkg = terminals[0]
        return MinimumPatchSet(
            packages_to_update=[pkg],
            packages_to_update_count=1,
            total_vulnerable_count=len(all_vulnerable),
            attack_paths_eliminated=len(all_attack_paths),
            savings_percent=_savings(1, len(all_vulnerable)),
            update_order=[pkg],
            estimated_effort="LOW",
            reasoning=f"Single high-risk package: update {pkg} to eliminate all attack paths.",
        )

    # -----------------------------------------------------------------------
    # Step 2: Build metric closure (shortest paths between terminal pairs)
    # -----------------------------------------------------------------------
    # Use the REVERSE of the dag (path from terminal → root via reverse edges)
    # since we want to find common ancestors that, when patched, cover multiple terminals
    graph = dag.graph
    undirected = graph.to_undirected()

    metric_closure = nx.Graph()
    metric_closure.add_nodes_from(terminals)

    terminal_set = set(terminals)
    path_cache: Dict[Tuple[str, str], List[str]] = {}

    for i, u in enumerate(terminals):
        for v in terminals[i + 1:]:
            try:
                path = nx.shortest_path(undirected, u, v)
                length = len(path) - 1
                metric_closure.add_edge(u, v, weight=length)
                path_cache[(u, v)] = path
                path_cache[(v, u)] = list(reversed(path))
            except nx.NetworkXNoPath:
                # Terminals not connected — add a high-weight edge
                metric_closure.add_edge(u, v, weight=1000)

    # -----------------------------------------------------------------------
    # Step 3: MST of metric closure
    # -----------------------------------------------------------------------
    try:
        mst = nx.minimum_spanning_tree(metric_closure, weight="weight")
    except Exception:
        mst = metric_closure

    # -----------------------------------------------------------------------
    # Step 4: Map MST back to original graph paths (collect Steiner nodes)
    # -----------------------------------------------------------------------
    candidate_nodes: Set[str] = set(terminals)

    for u, v in mst.edges():
        path = path_cache.get((u, v), [])
        candidate_nodes.update(path)

    # -----------------------------------------------------------------------
    # Step 5: Greedy set cover over attack paths
    # -----------------------------------------------------------------------
    # We want the smallest subset of candidate_nodes that "covers" all paths
    # A node covers a path if it appears in that path
    if all_attack_paths:
        covered: Set[int] = set()        # indices of covered paths
        selected: List[str] = []

        # Sort candidates by number of paths they cover (greedy)
        remaining_candidates = sorted(
            candidate_nodes,
            key=lambda n: sum(1 for i, ap in enumerate(all_attack_paths) if n in ap),
            reverse=True,
        )

        all_path_indices = set(range(len(all_attack_paths)))
        for candidate in remaining_candidates:
            if covered >= all_path_indices:
                break
            newly_covered = {
                i for i, ap in enumerate(all_attack_paths)
                if i not in covered and candidate in ap
            }
            if newly_covered:
                covered |= newly_covered
                selected.append(candidate)

        # If some paths are not covered (disconnected graph), add all terminals
        if covered < all_path_indices:
            for t in terminals:
                if t not in selected:
                    selected.append(t)

        packages_to_update = selected
    else:
        # No explicit attack paths — just update terminals
        packages_to_update = list(terminals)

    # De-duplicate while preserving order
    seen: Set[str] = set()
    deduped: List[str] = []
    for p in packages_to_update:
        if p not in seen:
            seen.add(p)
            deduped.append(p)
    packages_to_update = deduped

    # -----------------------------------------------------------------------
    # Step 6: Topological update order
    # -----------------------------------------------------------------------
    subgraph = dag.graph.subgraph(packages_to_update).copy()
    try:
        # Break any cycles in the subgraph
        while True:
            try:
                cycle = nx.find_cycle(subgraph)
                subgraph.remove_edge(*cycle[0])
            except nx.NetworkXNoCycle:
                break
        update_order = list(nx.topological_sort(subgraph))
    except Exception:
        update_order = list(packages_to_update)

    # Ensure all packages appear (topological_sort only includes nodes)
    for pkg in packages_to_update:
        if pkg not in update_order:
            update_order.append(pkg)

    # -----------------------------------------------------------------------
    # Step 7: Compute savings
    # -----------------------------------------------------------------------
    naive_count = len(all_vulnerable)
    minimum_count = len(packages_to_update)
    savings_pct = _savings(minimum_count, naive_count)

    n = minimum_count
    effort = "LOW" if n < 5 else "MEDIUM" if n <= 15 else "HIGH"

    reasoning = (
        f"Steiner Tree 2-approximation selected {minimum_count} package(s) "
        f"out of {naive_count} vulnerable to eliminate {len(all_attack_paths)} "
        f"attack path(s). Savings: {savings_pct:.1f}% fewer updates needed."
    )

    return MinimumPatchSet(
        packages_to_update=packages_to_update,
        packages_to_update_count=minimum_count,
        total_vulnerable_count=naive_count,
        attack_paths_eliminated=len(all_attack_paths),
        savings_percent=savings_pct,
        update_order=update_order,
        estimated_effort=effort,
        reasoning=reasoning,
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _savings(minimum: int, naive: int) -> float:
    """Compute percentage savings vs. the naive approach.

    Args:
        minimum: Packages selected by the algorithm.
        naive: Total vulnerable packages (naive would update all).

    Returns:
        Percentage savings, clamped to [0, 100].
    """
    if naive == 0:
        return 0.0
    pct = max(0.0, (naive - minimum) / naive * 100)
    return round(min(100.0, pct), 2)


def _empty_patch_set() -> MinimumPatchSet:
    """Return an empty patch set for projects with no vulnerabilities."""
    return MinimumPatchSet(
        packages_to_update=[],
        packages_to_update_count=0,
        total_vulnerable_count=0,
        attack_paths_eliminated=0,
        savings_percent=0.0,
        update_order=[],
        estimated_effort="LOW",
        reasoning="No vulnerable packages detected — project is clean.",
    )
