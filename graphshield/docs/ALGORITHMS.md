# GraphShield Algorithm Reference

## 1. Bloom Filter

### Problem
Pre-filtering 300,000+ CVE entries per scan in O(1) without touching disk for every package.

### Implementation
BitArray-backed probabilistic set using `bytearray`:

```
m = -(n · ln p) / (ln 2)²   # bit array size
k = (m / n) · ln 2           # number of hash functions
```

For n=100,000 entries, p=0.001 → m ≈ 1,437,759 bits (≈ 175 KB), k = 10 hash functions.

Membership test: Set k bits, check all k. False positives possible; false negatives impossible.

**Why MurmurHash3?** Better distribution than MD5/SHA for non-cryptographic use; `mmh3.hash128` provides high-quality 128-bit output which we slice into k independent seeds.

---

## 2. AVL Tree

### Problem
Confirm Bloom filter positives by checking whether a resolved version falls within a CVE's affected version range, in O(log n) worst case even for sorted inputs.

### Implementation
Height-balanced BST with balance factor ∈ {-1, 0, 1} at every node:

```
Left rotation:           Right rotation:
    x                        y
   / \                      / \
  a   y       ←→           x   c
     / \                  / \
    b   c                a   b
```

Rotations are triggered whenever `|height(left) - height(right)| > 1`.

**Version key**: Tuple `(major, minor, patch)` with lexicographic comparison, allowing interval queries like `[1.2.0, 1.2.8)`.

**Why not a Red-Black Tree?** AVL trees have stricter balance guarantees (height ≤ 1.44·log₂(n) vs 2·log₂(n) for Red-Black), making their O(log n) constant factor smaller — critical for tight version range checks.

---

## 3. Tarjan's Strongly Connected Components

### Problem
Detect circular dependency chains where compromising one package transitively compromises all others in the chain.

### Algorithm (Tarjan 1972, iterative variant)

```
For each unvisited node v:
  index[v] = lowlink[v] = next_index++
  Push v onto stack; on_stack[v] = True

  For each successor w of v:
    If w not visited: recurse on w; lowlink[v] = min(lowlink[v], lowlink[w])
    If w on stack:    lowlink[v] = min(lowlink[v], index[w])

  If lowlink[v] == index[v]:  ← v is SCC root
    Pop stack until v → this is one SCC
```

**Why iterative?** CPython default recursion limit = 1000. A 2,000-node npm transitive dependency tree would raise `RecursionError`. Our implementation uses an explicit frame stack to simulate DFS without consuming the Python call stack.

**Complexity**: O(V + E) time, O(V) space.

---

## 4. Weighted Blast Radius

### Problem
CVSS scores measure vulnerability intrinsic severity but ignore graph position. A CVSS 7.0 in `lodash` (used by 50% of the JS ecosystem) is more dangerous than CVSS 9.0 in an isolated CLI utility.

### Formula

```
blast_radius_score = cvss × log₂(1 + reachable_count) × sensitivity_multiplier
```

Where:
- `reachable_count` = nodes reachable via BFS from the vulnerable package
- `sensitivity_multiplier` ∈ {1.0 (LOW), 1.5 (MEDIUM), 2.0 (HIGH), 3.0 (CRITICAL)}

Sensitivity is determined by the *type* of downstream sinks reachable:

| Sink type | Examples | Multiplier |
|-----------|----------|------------|
| credential | dotenv, keytar | CRITICAL (×3) |
| crypto | jsonwebtoken, cryptography | CRITICAL (×3) |
| database | sqlalchemy, pg, mongoose | HIGH (×2) |
| file_write | fs, rimraf, glob | HIGH (×2) |
| network | requests, axios, fetch | MEDIUM (×1.5) |

**Topological amplification** (applied separately):

```
topo_risk = cvss × (1 + log(1 + downstream) / log(total_nodes))
```

This double-amplifies packages that are both vulnerable and load early in the dependency chain.

---

## 5. Steiner Tree Minimum Patch Set

### Problem
Naively, update all vulnerable packages. This is O(n) updates — often unnecessary because updating a common ancestor eliminates multiple descendants.

The **Steiner Tree problem**: Find the minimum-cost connected subgraph spanning a set of required terminal nodes.

### 2-Approximation Algorithm (Kou, Markowsky, Berman 1981)

```
Step 1: Identify terminals T ⊆ V (packages with blast_radius_score > threshold)

Step 2: Build metric closure G' = (T, E')
        where w(u,v) = shortest_path_length(u, v) in G

Step 3: Find MST M' of G'

Step 4: Map each M' edge back to the actual shortest path in G
        → collect all intermediate (Steiner) nodes

Step 5: Greedy set cover
        For each attack path ap:
          Select the candidate node covering the most uncovered paths

Step 6: Topological sort of selected nodes
        → safe update order (update dependencies before dependents)
```

**Approximation ratio**: ≤ 2(1 - 1/|T|) ≤ 2 × OPT

**Complexity**: O(|T|² · (V log V + E)) for metric closure + O(|T|² log |T|) for MST.

---

## 6. Patch Agent Prompt Strategy

The LLM agent uses **structured output prompting** with a JSON schema contract:

1. System prompt establishes expertise role + strict JSON-only output rule
2. User prompt provides: package name, ecosystem, version, CVE IDs, CVSS, reachable count, data sensitivity, topological rank, attack path
3. Response is parsed with regex JSON extraction (handles markdown code fence wrapping)
4. Missing keys trigger the deterministic heuristic fallback

Temperature = 0.1 ensures near-deterministic output for reproducible recommendations.
