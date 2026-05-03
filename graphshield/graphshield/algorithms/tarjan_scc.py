
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

import networkx as nx

from graphshield.config import CVSS_CRITICAL, CVSS_HIGH, SCC_HIGH_MAX, SCC_LOW_MAX, SCC_MEDIUM_MAX

def tarjan_scc(graph: nx.DiGraph) -> List[List[str]]:
    index_counter: list[int] = [0]
    index: Dict[str, int] = {}
    lowlink: Dict[str, int] = {}
    on_stack: Dict[str, bool] = {}
    stack: List[str] = []
    sccs: List[List[str]] = []

    nodes = list(graph.nodes())

    for start_node in nodes:
        if start_node in index:
            continue

        frame_stack: List[tuple] = []
        index[start_node] = lowlink[start_node] = index_counter[0]
        index_counter[0] += 1
        stack.append(start_node)
        on_stack[start_node] = True
        frame_stack.append((start_node, iter(graph.successors(start_node))))

        while frame_stack:
            node, neighbours = frame_stack[-1]

            try:
                w = next(neighbours)

                if w not in index:
                    index[w] = lowlink[w] = index_counter[0]
                    index_counter[0] += 1
                    stack.append(w)
                    on_stack[w] = True
                    frame_stack.append((w, iter(graph.successors(w))))

                elif on_stack.get(w, False):
                    lowlink[node] = min(lowlink[node], index[w])

            except StopIteration:
                frame_stack.pop()

                if frame_stack:
                    parent_node = frame_stack[-1][0]
                    lowlink[parent_node] = min(lowlink[parent_node], lowlink[node])

                if lowlink[node] == index[node]:
                    scc: List[str] = []
                    while True:
                        w = stack.pop()
                        on_stack[w] = False
                        scc.append(w)
                        if w == node:
                            break
                    sccs.append(scc)

    return sccs

@dataclass
class CircularTrustCluster:

    nodes: List[str]
    size: int
    risk_level: str
    max_cvss_in_cluster: float
    combined_blast_radius: int
    description: str

def classify_circular_trust(
    scc: List[str],
    dag: "DependencyDAG",
) -> CircularTrustCluster:
    size = len(scc)

    _levels = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]

    if size <= SCC_LOW_MAX:
        level_idx = 0
    elif size <= SCC_MEDIUM_MAX:
        level_idx = 1
    elif size <= SCC_HIGH_MAX:
        level_idx = 2
    else:
        level_idx = 3

    max_cvss = 0.0
    for node in scc:
        meta = dag.metadata.get(node)
        if meta and meta.cvss_score:
            max_cvss = max(max_cvss, meta.cvss_score)

    if max_cvss >= CVSS_CRITICAL:
        level_idx = 3
    elif max_cvss >= CVSS_HIGH and level_idx < 3:
        level_idx += 1

    risk_level = _levels[level_idx]

    downstream_union: Set[str] = set()
    for node in scc:
        downstream_union |= dag.get_downstream_nodes(node)
    downstream_union -= set(scc)
    combined_blast_radius = len(downstream_union)

    description = (
        f"Circular trust cluster of {size} package(s). "
        f"A single compromise propagates to all {size} packages. "
        f"Max CVSS: {max_cvss:.1f}. "
        f"Combined blast radius: {combined_blast_radius} downstream packages."
    )

    return CircularTrustCluster(
        nodes=scc,
        size=size,
        risk_level=risk_level,
        max_cvss_in_cluster=max_cvss,
        combined_blast_radius=combined_blast_radius,
        description=description,
    )

def find_all_circular_trust(
    dag: "DependencyDAG",
) -> List[CircularTrustCluster]:
    risk_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

    all_sccs = tarjan_scc(dag.graph)
    clusters = []

    for scc in all_sccs:
        if len(scc) < 2:
            continue
        cluster = classify_circular_trust(scc, dag)
        clusters.append(cluster)

    clusters.sort(key=lambda c: (risk_order.get(c.risk_level, 99), -c.size))
    return clusters

from graphshield.core.dag_builder import DependencyDAG
