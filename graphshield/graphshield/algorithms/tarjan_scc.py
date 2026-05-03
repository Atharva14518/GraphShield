"""
Tarjan's Strongly Connected Components — iterative implementation.

Why iterative?
--------------
CPython's default recursion limit is 1000.  Real dependency graphs can
have thousands of nodes.  A naive recursive Tarjan's implementation
would raise ``RecursionError`` on any project with more than ~500
transitively-linked packages.  This implementation uses an explicit
call-stack (a list of frames) to simulate the recursion iteratively,
giving O(V + E) time and O(V) space without touching the system stack.

Why Tarjan's over simple DFS cycle detection?
---------------------------------------------
Simple DFS tells you *if* a cycle exists.  Tarjan's tells you *exactly
which sets of nodes* form cycles — the Strongly Connected Components.
In supply-chain security this distinction matters: if packages A, B, C
form an SCC, compromising *any one* of them gives the attacker control
over *all three*.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

import networkx as nx

from graphshield.config import CVSS_CRITICAL, CVSS_HIGH, SCC_HIGH_MAX, SCC_LOW_MAX, SCC_MEDIUM_MAX


# ---------------------------------------------------------------------------
# Core algorithm
# ---------------------------------------------------------------------------


def tarjan_scc(graph: nx.DiGraph) -> List[List[str]]:
    """Iterative Tarjan's Strongly Connected Components algorithm.

    Finds all SCCs in *graph* in O(V + E) time using an explicit stack
    frame list to avoid Python's recursion limit.

    Args:
        graph: Directed graph to analyse (any node type that is hashable).

    Returns:
        List of SCCs, each SCC being a list of node names.  Includes
        trivial SCCs of size 1 (a single node with no self-loop).
        SCCs of size > 1 represent circular dependency clusters.

    Algorithm outline (Tarjan 1972, iterative variant):

    For each unvisited node *v*:
      1. Assign ``index[v] = lowlink[v] = next_index++``
      2. Push *v* onto the Tarjan stack; mark ``on_stack[v] = True``
      3. For each unvisited neighbour *w*: recurse (iteratively via frame stack)
         For each visited, on-stack neighbour *w*: ``lowlink[v] = min(lowlink[v], index[w])``
      4. After all neighbours processed, if ``lowlink[v] == index[v]``:
         pop all nodes from the Tarjan stack until *v* is popped → one SCC
    """
    index_counter: list[int] = [0]   # mutable int for the frame closures
    index: Dict[str, int] = {}
    lowlink: Dict[str, int] = {}
    on_stack: Dict[str, bool] = {}
    stack: List[str] = []            # Tarjan's node stack
    sccs: List[List[str]] = []

    nodes = list(graph.nodes())

    for start_node in nodes:
        if start_node in index:
            continue  # already visited

        # --- Iterative DFS using explicit frame stack ---
        # Each frame: (node, iterator_over_successors, already_pushed_to_tarjan_stack)
        # We use a list of (node, neighbour_iter) pairs.
        # The first time we process a node we initialise its index/lowlink.
        # Each time we return to a frame we update lowlink from the child.

        frame_stack: List[tuple] = []
        # Bootstrap the first node
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
                    # Tree edge: push new frame for w
                    index[w] = lowlink[w] = index_counter[0]
                    index_counter[0] += 1
                    stack.append(w)
                    on_stack[w] = True
                    frame_stack.append((w, iter(graph.successors(w))))

                elif on_stack.get(w, False):
                    # Back edge: update lowlink
                    lowlink[node] = min(lowlink[node], index[w])

                # Cross/forward edges (w visited but not on stack) are ignored

            except StopIteration:
                # All neighbours of *node* have been processed
                frame_stack.pop()

                # Propagate lowlink to parent frame
                if frame_stack:
                    parent_node = frame_stack[-1][0]
                    lowlink[parent_node] = min(lowlink[parent_node], lowlink[node])

                # Check if *node* is the root of an SCC
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


# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------


@dataclass
class CircularTrustCluster:
    """A circular dependency cluster detected by Tarjan's SCC algorithm.

    Attributes:
        nodes: Package names forming the cluster.
        size: Number of nodes in the cluster.
        risk_level: ``CRITICAL`` | ``HIGH`` | ``MEDIUM`` | ``LOW``.
        max_cvss_in_cluster: Highest CVSS score among all cluster packages.
        combined_blast_radius: Union of all downstream nodes across all
            packages in the SCC.
        description: Human-readable summary of the cluster's risk.
    """

    nodes: List[str]
    size: int
    risk_level: str
    max_cvss_in_cluster: float
    combined_blast_radius: int
    description: str


def classify_circular_trust(
    scc: List[str],
    dag: "DependencyDAG",  # type: ignore[name-defined]  # avoid circular import
) -> CircularTrustCluster:
    """Classify the risk level of a circular dependency cluster.

    Base classification by SCC size:

    ============  ===========
    Size          Risk level
    ============  ===========
    == 2          LOW
    3 – 5         MEDIUM
    6 – 10        HIGH
    > 10          CRITICAL
    ============  ===========

    Escalation rules:
    * Any node with CVSS ≥ *CVSS_HIGH* (7.0) → upgrade one level.
    * Any node with CVSS ≥ *CVSS_CRITICAL* (9.0) → jump straight to CRITICAL.

    Args:
        scc: List of node names in the SCC.
        dag: The :class:`~graphshield.core.dag_builder.DependencyDAG` containing
            metadata and graph structure.

    Returns:
        A :class:`CircularTrustCluster` with risk classification and blast radius.
    """
    size = len(scc)

    # --- Base risk by size ---
    _levels = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]

    if size <= SCC_LOW_MAX:
        level_idx = 0   # LOW
    elif size <= SCC_MEDIUM_MAX:
        level_idx = 1   # MEDIUM
    elif size <= SCC_HIGH_MAX:
        level_idx = 2   # HIGH
    else:
        level_idx = 3   # CRITICAL

    # --- CVSS escalation ---
    max_cvss = 0.0
    for node in scc:
        meta = dag.metadata.get(node)
        if meta and meta.cvss_score:
            max_cvss = max(max_cvss, meta.cvss_score)

    if max_cvss >= CVSS_CRITICAL:
        level_idx = 3  # straight to CRITICAL
    elif max_cvss >= CVSS_HIGH and level_idx < 3:
        level_idx += 1  # upgrade one level

    risk_level = _levels[level_idx]

    # --- Combined blast radius ---
    downstream_union: Set[str] = set()
    for node in scc:
        downstream_union |= dag.get_downstream_nodes(node)
    # Remove nodes inside the SCC itself from the blast radius count
    downstream_union -= set(scc)
    combined_blast_radius = len(downstream_union)

    # --- Description ---
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
    dag: "DependencyDAG",  # type: ignore[name-defined]
) -> List[CircularTrustCluster]:
    """Find and classify all circular dependency clusters in the DAG.

    Runs Tarjan's SCC on ``dag.graph``, filters to multi-node SCCs,
    classifies each, and returns them sorted by risk level (CRITICAL first).

    Args:
        dag: Fully built :class:`~graphshield.core.dag_builder.DependencyDAG`.

    Returns:
        List of :class:`CircularTrustCluster` objects, most critical first.
    """
    risk_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

    all_sccs = tarjan_scc(dag.graph)
    clusters = []

    for scc in all_sccs:
        if len(scc) < 2:
            continue  # trivial SCC — normal node
        cluster = classify_circular_trust(scc, dag)
        clusters.append(cluster)

    clusters.sort(key=lambda c: (risk_order.get(c.risk_level, 99), -c.size))
    return clusters


# Avoid circular import at module level
from graphshield.core.dag_builder import DependencyDAG  # noqa: E402
