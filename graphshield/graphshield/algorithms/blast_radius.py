
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

SENSITIVE_SINKS: Dict[str, str] = {
    "fs": "file_write",
    "fs_extra": "file_write",
    "graceful_fs": "file_write",
    "mkdirp": "file_write",
    "rimraf": "file_write",
    "glob": "file_write",
    "axios": "network",
    "node_fetch": "network",
    "got": "network",
    "superagent": "network",
    "cross_fetch": "network",
    "isomorphic_fetch": "network",
    "request": "network",
    "needle": "network",
    "requests": "network",
    "httpx": "network",
    "urllib3": "network",
    "aiohttp": "network",
    "httplib2": "network",
    "keytar": "credential",
    "keychain": "credential",
    "dotenv": "credential",
    "python_dotenv": "credential",
    "configparser": "credential",
    "decouple": "credential",
    "crypto": "crypto",
    "jsonwebtoken": "crypto",
    "bcrypt": "crypto",
    "argon2": "crypto",
    "forge": "crypto",
    "node_rsa": "crypto",
    "cryptography": "crypto",
    "pyjwt": "crypto",
    "passlib": "crypto",
    "paramiko": "crypto",
    "pyotp": "crypto",
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
    "sqlalchemy": "database",
    "pymongo": "database",
    "redis": "database",
    "pymysql": "database",
    "psycopg2": "database",
    "motor": "database",
    "tortoise": "database",
    "peewee": "database",
}

SENSITIVITY_MULTIPLIER: Dict[str, float] = {
    "LOW": 1.0,
    "MEDIUM": 1.5,
    "HIGH": 2.0,
    "CRITICAL": 3.0,
}

_SINK_SENSITIVITY: Dict[str, str] = {
    "file_write": "HIGH",
    "network": "MEDIUM",
    "credential": "CRITICAL",
    "crypto": "CRITICAL",
    "database": "HIGH",
}

@dataclass
class AttackPath:

    path: List[str]
    sink_type: str
    sink_node: str
    path_length: int
    exploit_score: float
    exploitability: str

@dataclass
class BlastRadiusResult:

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

def _determine_sensitivity(sink_types: List[str]) -> str:
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
    paths: List[AttackPath] = []
    dfs_stack: List[tuple] = [(source, [source])]
    visited_paths: Set[tuple] = set()

    while dfs_stack and len(paths) < max_paths * 3:
        node, current_path = dfs_stack.pop()

        for neighbour in dag.graph.successors(node):
            new_path = current_path + [neighbour]
            path_key = tuple(new_path)

            if path_key in visited_paths:
                continue
            visited_paths.add(path_key)

            norm = neighbour.replace("-", "_").lower()

            if norm in SENSITIVE_SINKS:
                sink_type = SENSITIVE_SINKS[norm]
                length = len(new_path) - 1
                exploit_score = cvss * (1.0 / max(1, length)) * sensitivity_mult
                exploit_score = round(exploit_score, 4)

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
            elif len(new_path) < 10:
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
    reachable: Set[str] = dag.get_downstream_nodes(node)
    reachable_list = sorted(reachable)

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

    norm_self = node.replace("-", "_").lower()
    if norm_self in SENSITIVE_SINKS:
        self_sink_type = SENSITIVE_SINKS[norm_self]
        if self_sink_type not in sink_types_found:
            sink_types_found.append(self_sink_type)

    data_sensitivity = _determine_sensitivity(sink_types_found)
    sensitivity_mult = SENSITIVITY_MULTIPLIER[data_sensitivity]

    attack_paths: List[AttackPath] = []
    if sink_nodes:
        attack_paths = _enumerate_attack_paths(
            node, dag, sink_nodes, cvss_score, sensitivity_mult
        )

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
        meta.blast_radius_score = result.blast_radius_score
        results.append(result)

    results.sort(key=lambda r: r.blast_radius_score, reverse=True)
    return results
