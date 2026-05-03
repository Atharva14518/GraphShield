<div align="center">

# 🛡️ GraphShield

**Agentic Vulnerability Intelligence Engine for Software Supply Chain Security**

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-146%20passed-brightgreen)](#testing)

</div>

GraphShield models software dependencies as a **directed graph** and uses classical algorithms to answer security questions that flat CVSS scanners miss:

| Question | Algorithm | Complexity |
|---|---|---|
| Which packages form circular trust chains? | **Tarjan's SCC** (iterative) | O(V + E) |
| How far does a vulnerability spread? | **Weighted Blast Radius** | O(V + E) |
| What is the minimum set of packages to update? | **Steiner Tree 2-approximation** | O(T² · (V log V + E)) |
| Is this CVE actually in scope? | **Bloom Filter + AVL Tree** | O(k) + O(log n) |

---

## Features

- **6 manifest formats**: `package.json`, `package-lock.json`, `requirements.txt`, `Pipfile`, `pyproject.toml`, `pom.xml`
- **Topological risk scoring**: Amplifies CVSS by graph position (early-loading packages carry more weight)
- **Circular trust detection**: Iterative Tarjan's SCC with CVSS-based escalation
- **Attack path enumeration**: DFS from vulnerable package to sensitive sinks (credentials, databases, crypto)
- **Minimum patch set**: Steiner Tree finds the fewest updates to eliminate all critical paths
- **LLM recommendations**: Groq (llama-3.3-70b) generates structured patch advice per vulnerability
- **Continuous monitoring**: Watchdog agent detects manifest changes and new CVEs, dispatches alerts via webhook/GitHub issues
- **CI/CD native**: GitHub Actions workflow with PR comments, artifact upload, and configurable fail thresholds

---

## Quick Start

### 1. Install

```bash
pip install graphshield
# or from source:
git clone https://github.com/graphshield/graphshield
cd graphshield && pip install -e .
```

### 2. Configure

```bash
cp .env.example .env
# Edit .env — add your GROQ_API_KEY
```

### 3. Initialise (downloads NVD CVE data)

```bash
graphshield init
```

### 4. Scan a project

```bash
# Local directory
graphshield scan ./my-project

# GitHub URL (auto-clones)
graphshield scan https://github.com/expressjs/express

# With reports
graphshield scan . --output report.json --markdown report.md

# Fail CI if any HIGH CVE found
graphshield scan . --fail-on HIGH
```

### 5. Check status

```bash
graphshield status
```

---

## CLI Reference

```
graphshield [COMMAND] [OPTIONS]

Commands:
  init    Download NVD CVE feeds and build the Bloom filter
  scan    Scan a project for vulnerable dependencies
  watch   Start the continuous monitoring watchdog daemon
  status  Show database and Bloom filter status

graphshield scan [TARGET] [OPTIONS]
  --output PATH       Write JSON report to file
  --markdown PATH     Write Markdown report to file
  --no-agent          Skip LLM recommendations (faster)
  --fail-on LEVEL     Exit code 1 if risk ≥ LEVEL (MEDIUM|HIGH|CRITICAL)
  --api-key KEY       Groq API key (or set GROQ_API_KEY env var)

graphshield watch [PATH] [OPTIONS]
  --webhook URL       POST alerts to this URL (Slack, Discord, PagerDuty)
  --github-token TOKEN  GitHub PAT for issue creation
  --github-repo REPO  owner/repo for GitHub issues
  --min-severity LVL  Minimum severity to dispatch (INFO|MEDIUM|HIGH|CRITICAL)
```

---

## Example Output

```
  Risk level:  ⬤ HIGH

  ╭────────────────────────────────╮
  │ Metric                │ Value  │
  │ Total packages        │ 142    │
  │ Vulnerable packages   │ 7      │
  │ Critical CVEs         │ 1      │
  │ High CVEs             │ 3      │
  │ Circular clusters     │ 2      │
  │ Min. packages to update │ 3/7  │
  │ Savings               │ 57.1%  │
  ╰────────────────────────────────╯

  Top Vulnerabilities
  ┌─────────────────────┬──────┬──────────────┬─────────────┐
  │ Package             │ CVSS │ Blast Radius │ Sensitivity │
  ├─────────────────────┼──────┼──────────────┼─────────────┤
  │ lodash              │  9.1 │ 87 packages  │ CRITICAL    │
  │ follow-redirects    │  7.4 │ 12 packages  │ MEDIUM      │
  │ qs                  │  7.5 │  3 packages  │ LOW         │
  └─────────────────────┴──────┴──────────────┴─────────────┘
```

---

## GitHub Actions Integration

Add to your repository — GraphShield will scan on every PR that touches dependency files:

```yaml
# .github/workflows/graphshield.yml
name: GraphShield Security Scan
on:
  pull_request:
    paths: [package.json, package-lock.json, requirements.txt]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: pip install graphshield
      - run: graphshield init
      - run: graphshield scan . --fail-on HIGH --markdown report.md
        env:
          GROQ_API_KEY: ${{ secrets.GROQ_API_KEY }}
```

The full workflow (in `.github/workflows/graphshield.yml`) also posts results as PR comments.

---

## Architecture

```
Target (path / GitHub URL)
    │
    ├─► Manifest Parser         (6 formats)
    │       │
    │       ▼
    ├─► Dependency DAG          (networkx DiGraph)
    │       │
    │       ├─► Bloom Filter    (O(k) CVE pre-screen)
    │       ├─► AVL Tree        (O(log n) range confirm)
    │       │
    │       ├─► Tarjan SCC      (circular trust clusters)
    │       ├─► Blast Radius    (attack path enumeration)
    │       └─► Steiner Tree    (minimum patch set)
    │
    └─► PatchAgent (Groq LLM)   (structured recommendations)
            │
            ▼
        ScanReport (JSON + Markdown)
```

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for detailed component descriptions and [`docs/ALGORITHMS.md`](docs/ALGORITHMS.md) for algorithm derivations.

---

## Custom Data Structures

All four required data structures are implemented from scratch (no stdlib shortcuts):

| Structure | File | Key Design |
|---|---|---|
| **Bloom Filter** | `core/bloom_filter.py` | MurmurHash3 + `bytearray` bit array |
| **AVL Tree** | `core/avl_tree.py` | Self-balancing via rotations, semver keys |
| **Tarjan SCC** | `algorithms/tarjan_scc.py` | Iterative (no recursion limit) |
| **Steiner Tree** | `algorithms/steiner_tree.py` | Metric closure MST + greedy set cover |

---

## Testing

```bash
pip install -e ".[dev]"
pytest tests/ -v
# 146 tests — all green in < 1s
```

Test coverage by phase:

| Phase | Tests | Coverage |
|---|---|---|
| Bloom Filter | 19 | FP rate, serialisation, stats, error handling |
| AVL Tree | 24 | Inserts, queries, balance, semver parsing |
| Manifest Parser | 38 | All 6 formats, edge cases, error handling |
| DAG Builder | 20 | Construction, topo sort, cycle detection, scoring |
| Tarjan SCC | 17 | Cycles, classification, CVSS escalation |
| Blast Radius | 17 | Reachability, sinks, score formula, attack paths |
| Steiner Tree | 8 | Min patch set, update order, savings |
| **Total** | **146** | |

---

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `GROQ_API_KEY` | — | Groq API key (required for LLM) |
| `GROQ_MODEL` | `llama-3.3-70b-versatile` | LLM model ID |
| `GRAPHSHIELD_DIR` | `~/.graphshield` | CVE DB and Bloom filter storage |
| `MAX_AGENT_CALLS_PER_SCAN` | `10` | Max LLM calls per scan |
| `WATCHDOG_WEBHOOK_URL` | — | Webhook URL for alerts |
| `GITHUB_TOKEN` | — | GitHub PAT for issue creation |
| `WATCHDOG_MIN_SEVERITY` | `HIGH` | Minimum alert severity |

---

## License

MIT © GraphShield Contributors
