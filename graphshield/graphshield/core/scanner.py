"""
GraphShield main scan pipeline.

:class:`GraphShieldScanner` orchestrates every sub-system:
  DAG build → CVE lookup → Tarjan SCC → Blast Radius → Steiner Tree → LLM Agent

:class:`ScanReport` is the single output artifact — fully serialisable
to JSON and Markdown for CI/CD integration.
"""

from __future__ import annotations

import dataclasses
import json
import logging
import os
import shutil
import subprocess
import tarfile
import tempfile
import time
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Any

from graphshield.algorithms.blast_radius import (
    BlastRadiusResult,
    compute_all_blast_radii,
)
from graphshield.algorithms.steiner_tree import MinimumPatchSet, compute_minimum_patch_set
from graphshield.algorithms.tarjan_scc import CircularTrustCluster, find_all_circular_trust
from graphshield.config import (
    BLOOM_PATH,
    CVSS_CRITICAL,
    CVSS_HIGH,
    CVSS_MEDIUM,
    DB_PATH,
    GRAPHSHIELD_DIR,
    MAX_AGENT_CALLS_PER_SCAN,
)
from graphshield.core.avl_tree import build_version_tree
from graphshield.core.bloom_filter import BloomFilter
from graphshield.core.dag_builder import DependencyDAG, find_all_manifests
from graphshield.core.manifest_parser import parse_manifest
from graphshield.exceptions import ManifestParseError, ScanError

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Temp helpers
# ---------------------------------------------------------------------------


def _safe_clone_tmpdir() -> Path:
    """Return a writable temp directory for repository clones.

    Preference order:
    1) ~/.graphshield/tmp
    2) <current working dir>/.graphshield_tmp
    3) system temp directory
    """
    candidates = [
        GRAPHSHIELD_DIR / "tmp",
        Path.cwd() / ".graphshield_tmp",
    ]
    for base in candidates:
        try:
            base.mkdir(parents=True, exist_ok=True)
            probe = base / ".write_test"
            probe.write_text("ok", encoding="utf-8")
            probe.unlink(missing_ok=True)
            return Path(tempfile.mkdtemp(prefix="graphshield_", dir=str(base)))
        except OSError:
            continue
    return Path(tempfile.mkdtemp(prefix="graphshield_"))


def _extract_github_owner_repo(target: str) -> tuple[str, str] | None:
    """Parse owner/repo from GitHub SSH or HTTPS target."""
    cleaned = target.strip()
    if cleaned.endswith(".git"):
        cleaned = cleaned[:-4]
    if cleaned.startswith("git@github.com:"):
        repo_path = cleaned.split("git@github.com:", 1)[1]
    elif cleaned.startswith("https://github.com/"):
        repo_path = cleaned.split("https://github.com/", 1)[1]
    else:
        return None
    parts = [p for p in repo_path.split("/") if p]
    if len(parts) < 2:
        return None
    return parts[0], parts[1]


def _download_github_archive(target: str, dest_dir: Path) -> Path:
    """Download and extract a GitHub tarball archive as clone fallback."""
    parsed = _extract_github_owner_repo(target)
    if not parsed:
        raise ScanError(f"Unsupported GitHub target for archive fallback: {target}")
    owner, repo = parsed

    archive_candidates = [
        f"https://codeload.github.com/{owner}/{repo}/tar.gz/refs/heads/main",
        f"https://codeload.github.com/{owner}/{repo}/tar.gz/refs/heads/master",
    ]
    last_error: Optional[Exception] = None

    for archive_url in archive_candidates:
        tar_path = dest_dir / "repo.tar.gz"
        try:
            urllib.request.urlretrieve(archive_url, str(tar_path))
            with tarfile.open(tar_path, "r:gz") as tf:
                tf.extractall(path=dest_dir)
            extracted_dirs = [p for p in dest_dir.iterdir() if p.is_dir()]
            if not extracted_dirs:
                raise ScanError("GitHub archive extracted no directory")
            return extracted_dirs[0]
        except Exception as exc:
            last_error = exc
            continue

    raise ScanError(
        f"Failed GitHub archive fallback for {target}: {last_error}"
    )


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class PatchRecommendation:
    """LLM-generated patch recommendation for a single vulnerable package.

    Attributes:
        package_name: Name of the vulnerable package.
        current_version: Installed version.
        cve_ids: Associated CVE identifiers.
        cvss_score: CVSS base score.
        recommended_version: Specific safe version to upgrade to.
        threat_explanation: 3-sentence plain-English explanation.
        breaking_changes: Known breaking changes or "None detected".
        upgrade_command: Exact shell command to perform the upgrade.
        confidence: ``HIGH`` | ``MEDIUM`` | ``LOW``.
        attack_path_summary: One-sentence worst-path description.
        blast_radius_score: Composite blast radius score.
    """

    package_name: str
    current_version: str
    cve_ids: List[str]
    cvss_score: float
    recommended_version: str
    threat_explanation: str
    breaking_changes: str
    upgrade_command: str
    confidence: str
    attack_path_summary: str
    blast_radius_score: float


@dataclass
class ScanReport:
    """Complete scan result for a project.

    All fields are fully serialisable via :meth:`to_json`.
    """

    manifest_path: str
    target: str
    ecosystem: str
    total_packages: int
    vulnerable_packages: int
    critical_count: int
    high_count: int
    medium_count: int
    circular_trust_clusters: List[CircularTrustCluster]
    blast_radius_results: List[BlastRadiusResult]
    minimum_patch_set: MinimumPatchSet
    patch_recommendations: List[PatchRecommendation]
    scan_duration_seconds: float
    timestamp: str
    risk_summary: str   # CLEAN | LOW | MEDIUM | HIGH | CRITICAL

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------

    def to_dict(self) -> Dict[str, Any]:
        """Recursively serialise all dataclass fields to a plain dict."""
        return _dc_to_dict(self)

    def to_json(self) -> str:
        """Serialise report to a compact JSON string."""
        return json.dumps(self.to_dict(), indent=2, default=str)

    def to_markdown(self) -> str:
        """Render report as a GitHub PR comment in Markdown."""
        risk_badge = {
            "CLEAN": "🟢 CLEAN",
            "LOW": "🔵 LOW",
            "MEDIUM": "🟡 MEDIUM",
            "HIGH": "🟠 HIGH",
            "CRITICAL": "🔴 CRITICAL",
        }.get(self.risk_summary, self.risk_summary)

        lines: List[str] = [
            "## 🛡️ GraphShield Security Report",
            "",
            f"**Risk Level: {risk_badge}**  ",
            f"**Target:** `{self.target}`  ",
            f"**Scanned:** {self.timestamp}",
            "",
            "### Summary",
            "",
            "| Metric | Value |",
            "|--------|-------|",
            f"| Total Packages | {self.total_packages} |",
            f"| Vulnerable | {self.vulnerable_packages} |",
            f"| Critical CVEs | {self.critical_count} |",
            f"| High CVEs | {self.high_count} |",
            f"| Medium CVEs | {self.medium_count} |",
            f"| Circular Trust Clusters | {len(self.circular_trust_clusters)} |",
            f"| Minimum Updates Needed | {self.minimum_patch_set.packages_to_update_count} |",
            f"| Scan Duration | {self.scan_duration_seconds}s |",
            "",
        ]

        if self.blast_radius_results:
            lines += [
                "### Top Vulnerabilities",
                "",
                "| Package | CVSS | Topo Rank | Blast Radius | Sensitivity |",
                "|---------|------|-----------|--------------|-------------|",
            ]
            for r in self.blast_radius_results[:5]:
                lines.append(
                    f"| `{r.source_node}` | {r.cvss_score} | "
                    f"{r.topological_rank or 'N/A'} | {r.reachable_count} | "
                    f"{r.data_sensitivity} |"
                )
            lines.append("")

        mps = self.minimum_patch_set
        if mps.packages_to_update:
            lines += [
                "### 🔧 Minimum Patch Set",
                "",
                f"Update **{mps.packages_to_update_count}** package(s) "
                f"(instead of {mps.total_vulnerable_count}) to eliminate "
                f"**{mps.attack_paths_eliminated}** attack path(s).  ",
                f"Savings: **{mps.savings_percent:.1f}%** fewer updates.",
                "",
                "Update order:",
                "",
            ]
            for i, pkg in enumerate(mps.update_order):
                lines.append(f"{i + 1}. `{pkg}`")
            lines.append("")

        if self.circular_trust_clusters:
            lines += [
                "### ⚠️ Circular Trust Clusters",
                "",
                "| Risk | Size | Packages |",
                "|------|------|----------|",
            ]
            for c in self.circular_trust_clusters:
                pkg_str = ", ".join(f"`{n}`" for n in c.nodes[:4])
                if c.size > 4:
                    pkg_str += "…"
                lines.append(f"| **{c.risk_level}** | {c.size} | {pkg_str} |")
            lines.append("")

        if self.patch_recommendations:
            lines += ["### 🤖 AI Patch Recommendations", ""]
            for rec in self.patch_recommendations[:5]:
                lines += [
                    f"#### `{rec.package_name}` {rec.current_version} → {rec.recommended_version}",
                    "",
                    f"{rec.threat_explanation}",
                    "",
                    f"- **Breaking changes:** {rec.breaking_changes}",
                    f"- **Command:** `{rec.upgrade_command}`",
                    f"- **Confidence:** {rec.confidence}",
                    "",
                ]

        lines += [
            "---",
            "*Generated by [GraphShield](https://github.com/graphshield/graphshield)*",
        ]
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Serialisation helpers
# ---------------------------------------------------------------------------


def _dc_to_dict(obj: Any) -> Any:
    """Recursively convert dataclass instances to plain dicts/lists/primitives."""
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return {k: _dc_to_dict(v) for k, v in dataclasses.asdict(obj).items()}
    if isinstance(obj, list):
        return [_dc_to_dict(i) for i in obj]
    if isinstance(obj, dict):
        return {k: _dc_to_dict(v) for k, v in obj.items()}
    if isinstance(obj, set):
        return sorted(_dc_to_dict(i) for i in obj)
    return obj


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------


class GraphShieldScanner:
    """Orchestrates the full GraphShield vulnerability scan pipeline.

    Args:
        groq_api_key: Groq API key for LLM patch recommendations.
            If empty, the agent step is skipped.
        db_path: Path to the GraphShield SQLite CVE database.
        bloom_path: Path to the serialised Bloom Filter.
        use_agent: Whether to run the LLM patch agent.
    """

    def __init__(
        self,
        groq_api_key: str = "",
        db_path: Path = DB_PATH,
        bloom_path: Path = BLOOM_PATH,
        use_agent: bool = True,
    ) -> None:
        self.groq_api_key = groq_api_key
        self.db_path = db_path
        self.bloom_path = bloom_path
        self.use_agent = use_agent
        self._bloom: Optional[BloomFilter] = None

    def _load_bloom(self) -> Optional[BloomFilter]:
        """Lazily load the Bloom Filter from disk.

        Returns:
            Loaded :class:`BloomFilter` or ``None`` if not found.
        """
        if self._bloom is None:
            if not self.bloom_path.exists():
                logger.warning(
                    "Bloom filter not found at %s. CVE pre-screening disabled.",
                    self.bloom_path,
                )
                return None
            try:
                self._bloom = BloomFilter.load(self.bloom_path)
            except Exception as exc:
                logger.warning("Failed to load bloom filter: %s", exc)
                return None
        return self._bloom

    def _resolve_target(self, target: str) -> tuple[Path, bool]:
        """Resolve a scan target to a local filesystem path.

        If *target* is a GitHub URL (starts with ``https://github.com``),
        the repository is shallow-cloned into a temporary directory.

        Args:
            target: GitHub URL or local filesystem path.

        Returns:
            Tuple of *(path, is_temp)* where *is_temp* indicates the
            directory should be deleted after scanning.

        Raises:
            ScanError: If cloning fails.
        """
        if target.startswith("https://github.com") or target.startswith("git@github.com"):
            tmp = _safe_clone_tmpdir()
            try:
                subprocess.run(
                    ["git", "clone", "--depth=1", target, str(tmp)],
                    check=True,
                    capture_output=True,
                    timeout=120,
                )
            except subprocess.CalledProcessError as exc:
                stderr = exc.stderr.decode(errors="ignore") if exc.stderr else ""
                logger.warning("git clone failed for %s: %s. Trying archive fallback.", target, stderr)
                try:
                    archive_root = _download_github_archive(target, tmp)
                    return archive_root, True
                except Exception as fallback_exc:
                    shutil.rmtree(tmp, ignore_errors=True)
                    raise ScanError(
                        f"Failed to clone {target}: {stderr}", cause=fallback_exc
                    ) from fallback_exc
            except subprocess.TimeoutExpired as exc:
                shutil.rmtree(tmp, ignore_errors=True)
                raise ScanError(f"Clone timed out for {target}", cause=exc) from exc
            return tmp, True

        local = Path(target).expanduser().resolve()
        if not local.exists():
            raise ScanError(f"Path does not exist: {target}")
        return local, False

    def scan(self, target: str) -> ScanReport:
        """Run a full vulnerability scan on a project.

        Pipeline:
        1. Resolve target (clone GitHub URL if needed).
        2. Discover all manifest files.
        3. Parse manifests → unified dependency list.
        4. Build :class:`DependencyDAG`.
        5. CVE lookup: Bloom filter pre-screen → AVL tree confirmation.
        6. Topological risk scoring.
        7. Tarjan's SCC → circular trust clusters.
        8. Blast radius computation.
        9. Steiner Tree → minimum patch set.
        10. LLM patch agent (top N by blast radius).
        11. Build and return :class:`ScanReport`.

        Args:
            target: GitHub URL (``https://github.com/…``) or local path.

        Returns:
            Populated :class:`ScanReport`.

        Raises:
            ScanError: If no manifests found or the scan otherwise fails.
        """
        start = time.time()
        tmp_path: Optional[Path] = None

        try:
            # Step 1: Resolve target
            path, is_temp = self._resolve_target(target)
            if is_temp:
                tmp_path = path

            # Step 2: Find manifests
            manifests = find_all_manifests(path)
            if not manifests:
                raise ScanError(f"No manifest files found in {target}")

            # Step 3: Parse all manifests
            all_deps = []
            for manifest in manifests:
                try:
                    all_deps.extend(parse_manifest(manifest))
                except ManifestParseError as exc:
                    logger.warning("Skipping %s: %s", manifest.name, exc)

            if not all_deps:
                raise ScanError(f"No dependencies found in any manifest in {target}")

            # Step 4: Build DAG
            dag = DependencyDAG()
            dag.build_from_dependencies(all_deps)
            dag.compute_topological_sort()

            # Step 5: CVE lookup
            bloom = self._load_bloom()
            cve_scores: Dict[str, float] = {}

            for node in list(dag.graph.nodes):
                meta = dag.metadata.get(node)
                if meta is None:
                    continue
                # Bloom filter pre-check (skip if bloom unavailable)
                if bloom is not None and not bloom.contains(node.replace("-", "_").lower()):
                    continue
                if self.db_path.exists():
                    try:
                        tree = build_version_tree(node, self.db_path)
                        if tree.size() > 0:
                            matches = tree.query(meta.version)
                            if matches:
                                best = max(matches, key=lambda x: x.cvss_score)
                                meta.cvss_score = best.cvss_score
                                meta.cve_ids = [m.cve_id for m in matches]
                                cve_scores[node] = best.cvss_score
                    except Exception as exc:
                        logger.debug("CVE lookup failed for %s: %s", node, exc)

            # Step 6: Topological risk
            dag.compute_topological_risk_scores(cve_scores)

            # Step 7: Circular trust detection
            clusters = find_all_circular_trust(dag)

            # Step 8: Blast radius
            blast_results = compute_all_blast_radii(dag)

            # Step 9: Minimum patch set
            patch_set = compute_minimum_patch_set(dag, blast_results)

            # Step 10: LLM agent
            recommendations: List[PatchRecommendation] = []
            if self.use_agent and self.groq_api_key:
                try:
                    from graphshield.agents.patch_agent import PatchAgent
                    agent = PatchAgent(self.groq_api_key)
                    for result in blast_results[:MAX_AGENT_CALLS_PER_SCAN]:
                        try:
                            rec = agent.analyze_vulnerability(result, dag)
                            recommendations.append(rec)
                        except Exception as exc:
                            logger.warning(
                                "Agent failed for %s: %s", result.source_node, exc
                            )
                except Exception as exc:
                    logger.warning("Agent initialisation failed: %s", exc)

            # Step 11: Build report
            risk = self._compute_risk_summary(blast_results, clusters)
            duration = round(time.time() - start, 2)

            return ScanReport(
                manifest_path=str(manifests[0]),
                target=target,
                ecosystem=dag.ecosystem,
                total_packages=dag.node_count(),
                vulnerable_packages=len(blast_results),
                critical_count=sum(
                    1 for r in blast_results if r.cvss_score >= CVSS_CRITICAL
                ),
                high_count=sum(
                    1 for r in blast_results
                    if CVSS_HIGH <= r.cvss_score < CVSS_CRITICAL
                ),
                medium_count=sum(
                    1 for r in blast_results
                    if CVSS_MEDIUM <= r.cvss_score < CVSS_HIGH
                ),
                circular_trust_clusters=clusters,
                blast_radius_results=blast_results,
                minimum_patch_set=patch_set,
                patch_recommendations=recommendations,
                scan_duration_seconds=duration,
                timestamp=datetime.now(timezone.utc).isoformat(),
                risk_summary=risk,
            )

        finally:
            if tmp_path and tmp_path.exists():
                shutil.rmtree(tmp_path, ignore_errors=True)

    @staticmethod
    def _compute_risk_summary(
        blast_results: List[BlastRadiusResult],
        clusters: List[CircularTrustCluster],
    ) -> str:
        """Derive an overall risk label from scan results.

        Args:
            blast_results: CVE blast radius results.
            clusters: Circular trust clusters.

        Returns:
            ``"CLEAN"`` | ``"LOW"`` | ``"MEDIUM"`` | ``"HIGH"`` | ``"CRITICAL"``.
        """
        if not blast_results and not clusters:
            return "CLEAN"

        max_cvss = max((r.cvss_score for r in blast_results), default=0.0)
        has_critical_cluster = any(c.risk_level == "CRITICAL" for c in clusters)

        if max_cvss >= CVSS_CRITICAL or has_critical_cluster:
            return "CRITICAL"
        if max_cvss >= CVSS_HIGH:
            return "HIGH"
        if max_cvss >= CVSS_MEDIUM:
            return "MEDIUM"
        if max_cvss > 0:
            return "LOW"
        return "CLEAN"
