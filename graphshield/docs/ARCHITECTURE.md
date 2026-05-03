# GraphShield Architecture

## System Overview

GraphShield is a production-grade agentic vulnerability intelligence engine
for software supply chain security.  It models package dependencies as a
directed graph and uses classical algorithms to answer questions that flat
CVSS scanners cannot:

| Question | Algorithm |
|---|---|
| Which packages form circular trust chains? | Tarjan's SCC |
| How far does a vulnerability spread? | Weighted Blast Radius |
| What is the minimum set of packages to update? | Steiner Tree 2-approximation |
| Is this CVE actually in scope? | Bloom Filter + AVL Tree |

---

## Directory Structure

```
graphshield/
├── graphshield/
│   ├── config.py              — Centralised configuration (env-driven)
│   ├── exceptions.py          — Custom exception hierarchy
│   ├── data/
│   │   └── nvd_ingestion.py   — NVD CVE feed ingestion → SQLite
│   ├── core/
│   │   ├── bloom_filter.py    — Probabilistic membership (MurmurHash3)
│   │   ├── avl_tree.py        — Self-balancing BST for version range queries
│   │   ├── manifest_parser.py — Multi-format dependency parser
│   │   ├── dag_builder.py     — Dependency DAG construction + topo sort
│   │   └── scanner.py         — Full scan pipeline orchestration
│   ├── algorithms/
│   │   ├── tarjan_scc.py      — Iterative Tarjan's SCC
│   │   ├── blast_radius.py    — Weighted blast radius + attack paths
│   │   └── steiner_tree.py    — Minimum patch set (Steiner 2-approx)
│   ├── agents/
│   │   ├── patch_agent.py     — Groq LLM patch recommendation agent
│   │   └── watchdog_agent.py  — Continuous monitoring daemon
│   └── cli/
│       └── main.py            — Typer CLI (init/scan/watch/status)
├── tests/                     — 146+ pytest tests (all green)
├── .github/workflows/         — CI/CD automation
└── docs/                      — This documentation
```

---

## Data Flow

```
Target (path / GitHub URL)
        │
        ▼
 find_all_manifests()
        │
        ▼
 parse_manifest() ──────► Dependency[]
        │
        ▼
 DependencyDAG.build_from_dependencies()
        │
        ├──► BloomFilter.contains()     ← fast O(k) pre-filter
        │         │
        │         └──► AVLTree.query()  ← O(log n) version range check
        │
        ├──► compute_topological_sort() ← O(V+E)
        │
        ├──► tarjan_scc() ──────────────► CircularTrustCluster[]
        │
        ├──► compute_all_blast_radii() ──► BlastRadiusResult[]
        │
        ├──► compute_minimum_patch_set() ─► MinimumPatchSet
        │
        └──► PatchAgent.analyze_vulnerability() ─► PatchRecommendation[]
                        │
                        ▼
                   ScanReport
```

---

## Component Descriptions

### `bloom_filter.py`

Space-efficient probabilistic set membership using:
- **Bit array**: `bytearray` with individual bit manipulation
- **Hash functions**: MurmurHash3 with independent seeds via `mmh3.hash128`
- **Optimal parameters**: `m = -(n · ln p) / (ln 2)²`, `k = (m/n) · ln 2`
- **Serialisation**: `pickle` for cross-process persistence

### `avl_tree.py`

Self-balancing Binary Search Tree for O(log n) version lookups:
- **Balance factor**: Maintained at each node via left/right rotation
- **Key**: Parsed semantic version tuple `(major, minor, patch)`
- **Query**: Interval query returning all ranges containing the target version
- **Use case**: Confirms Bloom filter positives, eliminating false positives

### `tarjan_scc.py`

Iterative Tarjan's Strongly Connected Components (avoids Python's recursion limit):
- **Complexity**: O(V + E)
- **Frame stack**: Simulates call stack with explicit `(node, iter)` tuples
- **Classification**: Size + CVSS-based escalation to LOW/MEDIUM/HIGH/CRITICAL
- **Use**: Identifies circular dependency trust chains

### `blast_radius.py`

Weighted graph-reachability analysis:
- **Reachability**: `nx.descendants` BFS from the vulnerable node
- **Sink detection**: Dictionary of 60+ sensitive package names
- **Score formula**: `cvss × log₂(1 + reachable) × sensitivity_multiplier`
- **Attack paths**: DFS from source to each reachable sink (capped at 10)

### `steiner_tree.py`

2-approximation minimum patch set via metric closure MST:
1. Identify terminals (packages with blast_radius_score > threshold)
2. Build metric closure (all-pairs shortest paths between terminals)
3. Find MST of metric closure
4. Map MST edges back to Steiner nodes in original graph
5. Greedy set cover to find minimum nodes covering all attack paths
6. Topological sort for safe update ordering

---

## Agent Architecture

### PatchAgent (Groq)

Stateless single-invocation LLM agent:
- **Input**: Full vulnerability context (graph metrics, CVE data, attack paths)
- **Output**: Structured JSON with `recommended_version`, `upgrade_command`, etc.
- **Fallback**: Deterministic heuristic when API unavailable
- **Prompt strategy**: Structured output prompting with JSON schema contract

### WatchdogAgent (Monitoring)

Multi-threaded continuous monitoring:
- **Manifest watcher**: Content-hash polling (SHA-256) every 60s
- **CVE watcher**: SQLite poll every 300s for newly matching CVEs
- **Alert channels**: Console log, webhook, GitHub issues
- **Thread safety**: Each watcher in a daemonised background thread
