"""
Weighted blast radius computation for vulnerable packages.

The blast radius of a vulnerable package is a measure of *how much damage*
its exploitation can cause, weighted by:
  1. How many other packages depend on it (graph reachability).
  2. Which sensitive code sinks are reachable (credential, database, network…).
  3. The CVSS exploitability score of the CVE.

This goes far beyond raw CVSS: a package with CVSS 7.0 that reaches a
credential store is more dangerous than one with CVSS 9.0 in an isolated
utility module.
"""

from __future__ import annotations

import logging
import math
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, TYPE_CHECKING

import networkx as nx

from graphshield.config import BLAST_RADIUS_MAX_PATHS, CVSS_CRITICAL, CVSS_HIGH, CVSS_MEDIUM

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from graphshield.core.dag_builder import DependencyDAG

# ---------------------------------------------------------------------------
# Sensitive sinks dictionary
# ---------------------------------------------------------------------------

SENSITIVE_SINKS: Dict[str, str] = {
    # File-system write
    "fs": "file_write",
    "fs_extra": "file_write",
    "graceful_fs": "file_write",
    "mkdirp": "file_write",
    "rimraf": "file_write",
    "glob": "file_write",
    # Network — JavaScript
    "axios": "network",
    "node_fetch": "network",
    "got": "network",
    "superagent": "network",
    "cross_fetch": "network",
    "isomorphic_fetch": "network",
    "request": "network",
    "needle": "network",
    # Network — Python
    "requests": "network",
    "httpx": "network",
    "urllib3": "network",
    "aiohttp": "network",
    "httplib2": "network",
    # Credentials
    "keytar": "credential",
    "keychain": "credential",
    "dotenv": "credential",
    "python_dotenv": "credential",
    "configparser": "credential",
    "decouple": "credential",
    # Crypto — JavaScript
    "crypto": "crypto",
    "jsonwebtoken": "crypto",
    "bcrypt": "crypto",
    "argon2": "crypto",
    "forge": "crypto",
    "node_rsa": "crypto",
    # Crypto — Python
    "cryptography": "crypto",
    "pyjwt": "crypto",
    "passlib": "crypto",
    "paramiko": "crypto",
    "pyotp": "crypto",
    # Database — JavaScript
    "pg": "database",
    "mysql": "database",
    "mysql2": "database",
    "sqlite3": "database",
    "ioredis": "database",
    "mongoose": "database",
    "sequelize": "database",
    "prisma": "database",
    "typeorm": "database",
    "knex": "database",
    # Database — Python
    "sqlalchemy": "database",
    "pymongo": "database",
    "redis": "database",
    "pymysql": "database",
    "psycopg2": "database",
    "motor": "database",
    "tortoise": "database",
    "peewee": "database",
}

# Sensitivity multiplier by data type
SENSITIVITY_MULTIPLIER: Dict[str, float] = {
    "LOW": 1.0,
    "MEDIUM": 1.5,
    "HIGH": 2.0,
    "CRITICAL": 3.0,
}

# Sink type → sensitivity level
_SINK_SENSITIVITY: Dict[str, str] = {
    "file_write": "HIGH",
    "network": "MEDIUM",
    "credential": "CRITICAL",
    "crypto": "CRITICAL",
    "database": "HIGH",
}


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class AttackPath:
    """A single attack path from a vulnerable node to a sensitive sink.

    Attributes:
        path: Ordered list of package names from source to sink.
        sink_type: Category of the sink (``"database"``, ``"credential"``, …).
        sink_node: Name of the final sink package.
        path_length: Number of hops (len(path) - 1).
        exploit_score: Weighted score = cvss × (1/length) × sensitivity_mult.
        exploitability: Attack vector: ``NETWORK`` | ``ADJACENT`` | ``LOCAL``.
    """

    path: List[str]
    sink_type: str
    sink_node: str
    path_length: int
    exploit_score: float
    exploitability: str


@dataclass
class BlastRadiusResult:
    """Full blast radius analysis for a single vulnerable package.

    Attributes:
        source_node: Name of the vulnerable package.
        cve_id: Primary CVE identifier (highest CVSS among confirmed CVEs).
        cvss_score: CVSS base score of the primary CVE.
        reachable_nodes: All packages reachable from *source_node*.
        reachable_count: ``len(reachable_nodes)``.
        sensitive_sinks_reachable: Names of reachable sensitive sink packages.
        sink_types: Unique sink categories reachable.
        data_sensitivity: Overall sensitivity level of reachable sinks.
        blast_radius_score: Composite score = cvss × log₂(1+reachable) × mult.
        attack_paths: Top attack paths sorted by ``exploit_score`` descending.
        topological_rank: The package's position in topological sort.
    """

    source_node: str
    cve_id: str
    cvss_score: float
    reachable_nodes: List[str]
    reachable_count: int
    sensitive_sinks_reachable: List[str]
    sink_types: List[str]
    data_sensitivity: str
    blast_radius_score: float
    attack_paths: List[AttackPath]
    topological_rank: Optional[int]


# ---------------------------------------------------------------------------
# Core computation
# ---------------------------------------------------------------------------


def _determine_sensitivity(sink_types: List[str]) -> str:
    """Map a list of sink type categories to an overall sensitivity level.

    Priority: credential/crypto > database/file_write > network > empty.

    Args:
        sink_types: List of sink category strings.

    Returns:
        Sensitivity level string: ``"LOW"`` | ``"MEDIUM"`` | ``"HIGH"`` | ``"CRITICAL"``.
    """
    if not sink_types:
        return "LOW"
    type_set = set(sink_types)
    if type_set & {"credential", "crypto"}:
        return "CRITICAL"
    if type_set & {"database", "file_write"}:
        return "HIGH"
    if "network" in type_set:
        return "MEDIUM"
    return "LOW"


def _determine_exploitability(cvss_vector: str) -> str:
    """Extract attack vector from a CVSS vector string.

    Args:
        cvss_vector: CVSS v3 vector string (e.g. ``"CVSS:3.1/AV:N/AC:L/…"``).

    Returns:
        ``"NETWORK"`` | ``"ADJACENT"`` | ``"LOCAL"``.
    """
    v = cvss_vector.upper()
    if "AV:N" in v:
        return "NETWORK"
    if "AV:A" in v:
        return "ADJACENT"
    return "LOCAL"


def _enumerate_attack_paths(
    source: str,
    dag: "DependencyDAG",
    sink_nodes: Set[str],
    cvss: float,
    sensitivity_mult: float,
    max_paths: int = BLAST_RADIUS_MAX_PATHS,
) -> List[AttackPath]:
    """DFS from *source* to collect attack paths that reach a sensitive sink.

    Uses an iterative DFS with path tracking. Stops each branch when it
    reaches a sink node (we want the *first* sink hit along a path, not
    paths that pass through a sink and continue).

    Args:
        source: Starting (vulnerable) node.
        dag: The dependency DAG.
        sink_nodes: Set of reachable sink node names (pre-filtered).
        cvss: CVSS score of the vulnerability.
        sensitivity_mult: Sensitivity multiplier for score calculation.
        max_paths: Maximum number of paths to return.

    Returns:
        List of :class:`AttackPath` objects sorted by ``exploit_score`` descending,
        capped at *max_paths*.
    """
    paths: List[AttackPath] = []
    # Stack items: (current_node, current_path_so_far)
    dfs_stack: List[tuple] = [(source, [source])]
    visited_paths: Set[tuple] = set()

    while dfs_stack and len(paths) < max_paths * 3:  # collect more, trim later
        node, current_path = dfs_stack.pop()

        for neighbour in dag.graph.successors(node):
            new_path = current_path + [neighbour]
            path_key = tuple(new_path)

            if path_key in visited_paths:
                continue
            visited_paths.add(path_key)

            # Normalise neighbour name for sink lookup
            norm = neighbour.replace("-", "_").lower()

            if norm in SENSITIVE_SINKS:
                sink_type = SENSITIVE_SINKS[norm]
                length = len(new_path) - 1
                exploit_score = cvss * (1.0 / max(1, length)) * sensitivity_mult
                exploit_score = round(exploit_score, 4)

                # Attack vector: network if the source has no upstream (directly exposed)
                upstream_count = len(dag.get_upstream_nodes(source))
                exploitability = "NETWORK" if upstream_count == 0 else "LOCAL"

                paths.append(
                    AttackPath(
                        path=new_path,
                        sink_type=sink_type,
                        sink_node=neighbour,
                        path_length=length,
                        exploit_score=exploit_score,
                        exploitability=exploitability,
                    )
                )
            elif len(new_path) < 10:  # depth limit to prevent runaway paths
                dfs_stack.append((neighbour, new_path))

    paths.sort(key=lambda p: p.exploit_score, reverse=True)
    return paths[:max_paths]


def compute_blast_radius(
    node: str,
    dag: "DependencyDAG",
    cve_id: str,
    cvss_score: float,
    cvss_vector: str = "",
) -> BlastRadiusResult:
    """Compute weighted blast radius for a single vulnerable node.

    Steps:
    1. BFS via ``nx.descendants`` to find all reachable nodes.
    2. Filter reachable set against :data:`SENSITIVE_SINKS`.
    3. Determine ``data_sensitivity`` from sink categories present.
    4. Enumerate attack paths via DFS (capped at ``BLAST_RADIUS_MAX_PATHS``).
    5. Compute ``blast_radius_score = cvss × log₂(1 + reachable) × sensitivity_mult``.

    Args:
        node: Name of the vulnerable package.
        dag: The dependency DAG (must have been topologically sorted).
        cve_id: CVE identifier for the vulnerability.
        cvss_score: CVSS base score.
        cvss_vector: CVSS vector string (used to determine exploitability).

    Returns:
        :class:`BlastRadiusResult` with full analysis.
    """
    # Step 1: All reachable nodes
    reachable: Set[str] = dag.get_downstream_nodes(node)
    reachable_list = sorted(reachable)

    # Step 2: Filter for sensitive sinks
    sink_nodes: Set[str] = set()
    sink_types_found: List[str] = []
    sinks_reachable: List[str] = []

    for r_node in reachable_list:
        norm = r_node.replace("-", "_").lower()
        if norm in SENSITIVE_SINKS:
            sink_type = SENSITIVE_SINKS[norm]
            sink_nodes.add(r_node)
            sinks_reachable.append(r_node)
            if sink_type not in sink_types_found:
                sink_types_found.append(sink_type)

    # Also check the node itself
    norm_self = node.replace("-", "_").lower()
    if norm_self in SENSITIVE_SINKS:
        self_sink_type = SENSITIVE_SINKS[norm_self]
        if self_sink_type not in sink_types_found:
            sink_types_found.append(self_sink_type)

    # Step 3: Data sensitivity
    data_sensitivity = _determine_sensitivity(sink_types_found)
    sensitivity_mult = SENSITIVITY_MULTIPLIER[data_sensitivity]

    # Step 4: Attack paths
    attack_paths: List[AttackPath] = []
    if sink_nodes:
        attack_paths = _enumerate_attack_paths(
            node, dag, sink_nodes, cvss_score, sensitivity_mult
        )

    # Step 5: Blast radius score
    blast_score = cvss_score * math.log2(1 + len(reachable)) * sensitivity_mult
    blast_score = round(blast_score, 4)

    topo_rank = dag.metadata.get(node, None)
    rank = topo_rank.topological_rank if topo_rank else None

    return BlastRadiusResult(
        source_node=node,
        cve_id=cve_id,
        cvss_score=cvss_score,
        reachable_nodes=reachable_list,
        reachable_count=len(reachable),
        sensitive_sinks_reachable=sinks_reachable,
        sink_types=sink_types_found,
        data_sensitivity=data_sensitivity,
        blast_radius_score=blast_score,
        attack_paths=attack_paths,
        topological_rank=rank,
    )


def compute_all_blast_radii(
    dag: "DependencyDAG",
) -> List[BlastRadiusResult]:
    """Compute blast radius for every node that has confirmed CVEs.

    Iterates over all nodes in ``dag.metadata`` that have a non-None
    ``cvss_score``, runs :func:`compute_blast_radius` for each, and
    returns results sorted by ``blast_radius_score`` descending (most
    dangerous first).

    Args:
        dag: Fully built and CVE-annotated :class:`~graphshield.core.dag_builder.DependencyDAG`.

    Returns:
        List of :class:`BlastRadiusResult` sorted by blast radius score descending.
    """
    results: List[BlastRadiusResult] = []

    for node, meta in dag.metadata.items():
        if meta.cvss_score is None or meta.cvss_score <= 0:
            continue
        cve_id = meta.cve_ids[0] if meta.cve_ids else "UNKNOWN"
        result = compute_blast_radius(
            node=node,
            dag=dag,
            cve_id=cve_id,
            cvss_score=meta.cvss_score,
        )
        # Write back blast_radius_score to dag metadata for later use
        meta.blast_radius_score = result.blast_radius_score
        results.append(result)

    results.sort(key=lambda r: r.blast_radius_score, reverse=True)
    return results
