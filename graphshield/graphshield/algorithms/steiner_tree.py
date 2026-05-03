
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

@dataclass
class MinimumPatchSet:

    packages_to_update: List[str]
    packages_to_update_count: int
    total_vulnerable_count: int
    attack_paths_eliminated: int
    savings_percent: float
    update_order: List[str]
    estimated_effort: str
    reasoning: str

def compute_minimum_patch_set(
    dag: "DependencyDAG",
    blast_results: "List[BlastRadiusResult]",
    threshold: float = BLAST_RADIUS_THRESHOLD,
) -> MinimumPatchSet:
    all_vulnerable: List[str] = [r.source_node for r in blast_results]
    terminals: List[str] = [
        r.source_node
        for r in blast_results
        if r.blast_radius_score > threshold
    ]

    all_attack_paths: List[List[str]] = []
    for result in blast_results:
        for ap in result.attack_paths:
            all_attack_paths.append(ap.path)

    if not terminals:
        if not all_vulnerable:
            return _empty_patch_set()
        terminals = all_vulnerable[:5]

    if len(terminals) == 1:
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
                metric_closure.add_edge(u, v, weight=1000)

    try:
        mst = nx.minimum_spanning_tree(metric_closure, weight="weight")
    except Exception:
        mst = metric_closure

    candidate_nodes: Set[str] = set(terminals)

    for u, v in mst.edges():
        path = path_cache.get((u, v), [])
        candidate_nodes.update(path)

    if all_attack_paths:
        covered: Set[int] = set()
        selected: List[str] = []

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

        if covered < all_path_indices:
            for t in terminals:
                if t not in selected:
                    selected.append(t)

        packages_to_update = selected
    else:
        packages_to_update = list(terminals)

    seen: Set[str] = set()
    deduped: List[str] = []
    for p in packages_to_update:
        if p not in seen:
            seen.add(p)
            deduped.append(p)
    packages_to_update = deduped

    subgraph = dag.graph.subgraph(packages_to_update).copy()
    try:
        while True:
            try:
                cycle = nx.find_cycle(subgraph)
                subgraph.remove_edge(*cycle[0])
            except nx.NetworkXNoCycle:
                break
        update_order = list(nx.topological_sort(subgraph))
    except Exception:
        update_order = list(packages_to_update)

    for pkg in packages_to_update:
        if pkg not in update_order:
            update_order.append(pkg)

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

def _savings(minimum: int, naive: int) -> float:
    if naive == 0:
        return 0.0
    pct = max(0.0, (naive - minimum) / naive * 100)
    return round(min(100.0, pct), 2)

def _empty_patch_set() -> MinimumPatchSet:
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
