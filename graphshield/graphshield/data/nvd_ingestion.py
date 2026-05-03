"""
NVD (National Vulnerability Database) feed ingestion pipeline.

Downloads NVD JSON 1.1 feeds (gzip-compressed), parses CVE entries,
extracts package names from CPE URIs, version ranges, and CVSS scores,
then stores everything in a local SQLite database for fast offline
lookups during scans.

Supports:
  - Full refresh (all years 2018–2024)
  - Incremental refresh (modified feed only when DB is fresh enough)
  - Exponential-backoff retries on network errors
  - Rich progress bars
"""

from __future__ import annotations

import gzip
import json
import logging
import sqlite3
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

import requests
from rich.progress import (
    BarColumn,
    DownloadColumn,
    Progress,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
    TransferSpeedColumn,
)

from graphshield.config import (
    BLOOM_PATH,
    DB_PATH,
    NVD_BASE_URL,
    NVD_MODIFIED_URL,
    NVD_REFRESH_HOURS,
    NVD_RETRY_ATTEMPTS,
    NVD_RETRY_BACKOFF,
    NVD_YEARS,
)
from graphshield.exceptions import CVEFetchError

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class CVEEntry:
    """A single CVE record extracted from an NVD feed.

    Attributes:
        cve_id: CVE identifier, e.g. ``CVE-2021-44228``.
        package_name: Normalised product name from the CPE string.
        ecosystem: Broad ecosystem hint derived from vendor/CPE data.
        version_start: Lower bound of the affected version range.
        version_end: Upper bound of the affected version range.
        version_start_incl: Whether *version_start* is inclusive.
        version_end_excl: Whether *version_end* is exclusive (open on right).
        cvss_score: CVSS v3 base score, falling back to v2 when v3 is absent.
        cvss_vector: Raw CVSS vector string.
        description: English description of the vulnerability.
        published_date: ISO-8601 publication date string.
    """

    cve_id: str
    package_name: str
    ecosystem: str
    version_start: str
    version_end: str
    version_start_incl: bool
    version_end_excl: bool
    cvss_score: float
    cvss_vector: str
    description: str
    published_date: str


# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------

_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS cve_entries (
    cve_id              TEXT PRIMARY KEY,
    package_name        TEXT NOT NULL,
    ecosystem           TEXT DEFAULT 'unknown',
    version_start       TEXT,
    version_end         TEXT,
    version_start_incl  INTEGER DEFAULT 1,
    version_end_excl    INTEGER DEFAULT 1,
    cvss_score          REAL DEFAULT 0.0,
    cvss_vector         TEXT,
    description         TEXT,
    published_date      TEXT
);

CREATE TABLE IF NOT EXISTS package_index (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    package_name TEXT NOT NULL,
    ecosystem    TEXT,
    cve_id       TEXT NOT NULL,
    FOREIGN KEY(cve_id) REFERENCES cve_entries(cve_id)
);

CREATE TABLE IF NOT EXISTS metadata (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_pkg_name
    ON package_index(package_name);
CREATE INDEX IF NOT EXISTS idx_pkg_eco
    ON package_index(package_name, ecosystem);
"""


def _get_connection(db_path: Path = DB_PATH) -> sqlite3.Connection:
    """Open (or create) the SQLite database and ensure the schema exists."""
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    conn.executescript(_SCHEMA_SQL)
    conn.commit()
    return conn


def _get_last_modified(conn: sqlite3.Connection) -> datetime | None:
    """Return the stored last-modified timestamp, or None if not set."""
    row = conn.execute(
        "SELECT value FROM metadata WHERE key = 'last_modified'"
    ).fetchone()
    if row is None:
        return None
    try:
        return datetime.fromisoformat(row["value"])
    except ValueError:
        return None


def _set_last_modified(conn: sqlite3.Connection) -> None:
    """Persist the current UTC timestamp as last-modified."""
    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        "INSERT OR REPLACE INTO metadata (key, value) VALUES ('last_modified', ?)",
        (now,),
    )
    conn.commit()


# ---------------------------------------------------------------------------
# Network helpers
# ---------------------------------------------------------------------------


def _download_with_retry(url: str) -> bytes:
    """Download *url* with exponential-backoff retry.

    Args:
        url: Full URL of the resource to fetch.

    Returns:
        Raw bytes of the HTTP response body.

    Raises:
        CVEFetchError: If all retry attempts are exhausted.
    """
    last_exc: Exception | None = None
    for attempt in range(NVD_RETRY_ATTEMPTS):
        try:
            response = requests.get(url, timeout=60, stream=True)
            response.raise_for_status()
            return response.content
        except requests.RequestException as exc:
            last_exc = exc
            if attempt < NVD_RETRY_ATTEMPTS - 1:
                wait = NVD_RETRY_BACKOFF[attempt]
                logger.warning(
                    "Download attempt %d/%d failed (%s). Retrying in %ds…",
                    attempt + 1,
                    NVD_RETRY_ATTEMPTS,
                    exc,
                    wait,
                )
                time.sleep(wait)

    raise CVEFetchError(
        f"Failed to download {url} after {NVD_RETRY_ATTEMPTS} attempts",
        cause=last_exc,
    )


def _stream_download_with_retry(url: str) -> Iterator[bytes]:
    """Stream-download *url* in chunks with retry.

    Yields raw byte chunks suitable for reassembly or progress tracking.

    Args:
        url: Full URL of the resource to stream.

    Yields:
        Raw byte chunks.

    Raises:
        CVEFetchError: If all retry attempts are exhausted.
    """
    last_exc: Exception | None = None
    for attempt in range(NVD_RETRY_ATTEMPTS):
        try:
            response = requests.get(url, timeout=60, stream=True)
            response.raise_for_status()
            yield from response.iter_content(chunk_size=65536)
            return
        except requests.RequestException as exc:
            last_exc = exc
            if attempt < NVD_RETRY_ATTEMPTS - 1:
                wait = NVD_RETRY_BACKOFF[attempt]
                logger.warning("Stream attempt %d failed. Retrying in %ds…", attempt + 1, wait)
                time.sleep(wait)

    raise CVEFetchError(
        f"Failed to stream {url} after {NVD_RETRY_ATTEMPTS} attempts",
        cause=last_exc,
    )


# ---------------------------------------------------------------------------
# CVE parsing helpers
# ---------------------------------------------------------------------------


def _extract_cvss(item: dict[str, Any]) -> tuple[float, str]:
    """Extract the best available CVSS score and vector from a CVE item.

    Prefers CVSS v3; falls back to v2.

    Args:
        item: A single NVD CVE item dict.

    Returns:
        Tuple of *(base_score, vector_string)*.
    """
    impact = item.get("impact", {})

    # Try CVSS v3
    v3 = impact.get("baseMetricV3", {}).get("cvssV3", {})
    if v3:
        return float(v3.get("baseScore", 0.0)), v3.get("vectorString", "")

    # Fall back to CVSS v2
    v2 = impact.get("baseMetricV2", {}).get("cvssV2", {})
    if v2:
        return float(v2.get("baseScore", 0.0)), v2.get("vectorString", "")

    return 0.0, ""


def _extract_description(item: dict[str, Any]) -> str:
    """Return the English description for a CVE item.

    Args:
        item: A single NVD CVE item dict.

    Returns:
        English description string, or empty string if absent.
    """
    for desc in item.get("cve", {}).get("description", {}).get("description_data", []):
        if desc.get("lang") == "en":
            return desc.get("value", "")[:2000]  # cap at 2 KB
    return ""


def _guess_ecosystem(vendor: str, product: str) -> str:
    """Guess the package ecosystem from vendor/product strings.

    Args:
        vendor: CPE vendor field.
        product: CPE product field.

    Returns:
        Ecosystem label: ``"npm"`` | ``"pip"`` | ``"maven"`` | ``"unknown"``.
    """
    vendor_l = vendor.lower()
    product_l = product.lower()

    npm_hints = {"node", "nodejs", "npm", "javascript", "js"}
    pip_hints = {"python", "pypi", "pip"}
    maven_hints = {"apache", "maven", "gradle", "java", "springframework"}

    if any(h in vendor_l or h in product_l for h in npm_hints):
        return "npm"
    if any(h in vendor_l or h in product_l for h in pip_hints):
        return "pip"
    if any(h in vendor_l or h in product_l for h in maven_hints):
        return "maven"
    return "unknown"


def _parse_cve_items(items: list[dict[str, Any]]) -> list[CVEEntry]:
    """Parse a list of raw NVD CVE item dicts into :class:`CVEEntry` objects.

    Extracts one :class:`CVEEntry` per unique (CVE, package, version_range)
    triple.  A single CVE may produce multiple entries when it affects
    several packages or has multiple version ranges.

    Args:
        items: Raw ``CVE_Items`` list from an NVD feed JSON.

    Returns:
        List of parsed :class:`CVEEntry` instances.
    """
    entries: list[CVEEntry] = []

    for item in items:
        cve_id: str = item.get("cve", {}).get("CVE_data_meta", {}).get("ID", "")
        if not cve_id:
            continue

        published_date: str = item.get("publishedDate", "")
        description: str = _extract_description(item)
        cvss_score, cvss_vector = _extract_cvss(item)

        # Walk every configuration node looking for CPE/version nodes
        configurations = item.get("configurations", {})
        nodes: list[dict] = configurations.get("nodes", [])

        # Flatten nested node children
        all_nodes: list[dict] = []
        stack = list(nodes)
        while stack:
            n = stack.pop()
            all_nodes.append(n)
            stack.extend(n.get("children", []))

        seen_packages: set[str] = set()

        for node in all_nodes:
            for cpe_match in node.get("cpe_match", []):
                if not cpe_match.get("vulnerable", False):
                    continue

                cpe_uri: str = cpe_match.get("cpe23Uri", "")
                parts = cpe_uri.split(":")
                # cpe:2.3:a:{vendor}:{product}:{version}:…
                if len(parts) < 5 or parts[2] != "a":
                    continue

                vendor = parts[3]
                product = parts[4]
                if vendor in ("*", "-") or product in ("*", "-"):
                    continue

                package_name = product.replace("-", "_").lower()
                ecosystem = _guess_ecosystem(vendor, product)

                version_start: str = (
                    cpe_match.get("versionStartIncluding", "")
                    or cpe_match.get("versionStartExcluding", "")
                )
                version_end: str = (
                    cpe_match.get("versionEndExcluding", "")
                    or cpe_match.get("versionEndIncluding", "")
                )
                version_start_incl: bool = bool(
                    cpe_match.get("versionStartIncluding", "")
                )
                version_end_excl: bool = bool(
                    cpe_match.get("versionEndExcluding", "")
                )

                dedup_key = f"{cve_id}:{package_name}:{version_start}:{version_end}"
                if dedup_key in seen_packages:
                    continue
                seen_packages.add(dedup_key)

                entries.append(
                    CVEEntry(
                        cve_id=cve_id,
                        package_name=package_name,
                        ecosystem=ecosystem,
                        version_start=version_start,
                        version_end=version_end,
                        version_start_incl=version_start_incl,
                        version_end_excl=version_end_excl,
                        cvss_score=cvss_score,
                        cvss_vector=cvss_vector,
                        description=description,
                        published_date=published_date,
                    )
                )

    return entries


# ---------------------------------------------------------------------------
# Database write helpers
# ---------------------------------------------------------------------------


def _upsert_entries(conn: sqlite3.Connection, entries: list[CVEEntry]) -> int:
    """Insert or replace CVE entries into the database.

    Args:
        conn: Open SQLite connection with the GraphShield schema.
        entries: Parsed :class:`CVEEntry` objects to persist.

    Returns:
        Number of new rows inserted/replaced.
    """
    count = 0
    for entry in entries:
        conn.execute(
            """
            INSERT OR REPLACE INTO cve_entries
              (cve_id, package_name, ecosystem, version_start, version_end,
               version_start_incl, version_end_excl, cvss_score, cvss_vector,
               description, published_date)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                entry.cve_id,
                entry.package_name,
                entry.ecosystem,
                entry.version_start,
                entry.version_end,
                int(entry.version_start_incl),
                int(entry.version_end_excl),
                entry.cvss_score,
                entry.cvss_vector,
                entry.description,
                entry.published_date,
            ),
        )
        # Index by package name
        conn.execute(
            """
            INSERT OR IGNORE INTO package_index (package_name, ecosystem, cve_id)
            VALUES (?, ?, ?)
            """,
            (entry.package_name, entry.ecosystem, entry.cve_id),
        )
        count += 1
    conn.commit()
    return count


# ---------------------------------------------------------------------------
# Feed download + parse
# ---------------------------------------------------------------------------


def _fetch_and_parse_feed(url: str, label: str, progress: Progress) -> list[CVEEntry]:
    """Download, decompress, and parse a single NVD JSON.gz feed.

    Args:
        url: URL of the gzip-compressed NVD JSON feed.
        label: Short label shown in the Rich progress bar.
        progress: Active Rich :class:`~rich.progress.Progress` instance.

    Returns:
        List of parsed :class:`CVEEntry` objects.
    """
    # --- Download phase ---
    dl_task = progress.add_task(f"[cyan]Downloading {label}…", total=None)
    raw_bytes = b""
    try:
        for chunk in _stream_download_with_retry(url):
            raw_bytes += chunk
        progress.update(
            dl_task,
            total=len(raw_bytes),
            completed=len(raw_bytes),
            description=f"[green]✓ {label} ({len(raw_bytes) // 1024:,} KB)",
        )
    except CVEFetchError:
        progress.update(dl_task, description=f"[red]✗ {label} (failed)")
        raise

    # --- Parse phase ---
    parse_task = progress.add_task(f"[yellow]Parsing {label}…", total=None)
    try:
        decompressed = gzip.decompress(raw_bytes)
        data = json.loads(decompressed.decode("utf-8"))
        items: list[dict] = data.get("CVE_Items", [])
        entries = _parse_cve_items(items)
        progress.update(
            parse_task,
            total=len(items),
            completed=len(items),
            description=f"[green]✓ Parsed {label}: {len(entries):,} CVEs",
        )
        return entries
    except (gzip.BadGzipFile, json.JSONDecodeError, KeyError) as exc:
        progress.update(parse_task, description=f"[red]✗ Parse error: {exc}")
        raise CVEFetchError(f"Failed to parse {label}", cause=exc) from exc


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def ingest_nvd_feeds(
    full_refresh: bool = False,
    db_path: Path = DB_PATH,
    years: list[int] | None = None,
) -> int:
    """Download and ingest NVD CVE feeds into the local SQLite database.

    Decision logic:

    * **No DB** → perform full download of all configured years.
    * **DB exists, age < NVD_REFRESH_HOURS** → skip entirely (return 0).
    * **DB exists, age >= NVD_REFRESH_HOURS** → download modified feed only.
    * *full_refresh=True* → always download all years (ignores age check).

    Args:
        full_refresh: Force re-ingestion of all yearly feeds.
        db_path: Path to the SQLite database file.
        years: Override which years to download (default: ``NVD_YEARS``).

    Returns:
        Total number of CVE entries inserted or replaced.
    """
    if years is None:
        years = NVD_YEARS

    conn = _get_connection(db_path)
    total_ingested = 0

    last_modified = _get_last_modified(conn)
    db_exists = db_path.exists() and last_modified is not None

    now = datetime.now(timezone.utc)
    age_hours: float = (
        (now - last_modified).total_seconds() / 3600
        if last_modified and last_modified.tzinfo
        else float("inf")
    )

    with Progress(
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        transient=False,
    ) as progress:

        if full_refresh or not db_exists:
            # Full download
            for year in years:
                url = f"{NVD_BASE_URL}nvdcve-1.1-{year}.json.gz"
                label = f"nvdcve-1.1-{year}.json.gz"
                try:
                    entries = _fetch_and_parse_feed(url, label, progress)
                    total_ingested += _upsert_entries(conn, entries)
                except CVEFetchError as exc:
                    logger.error("Skipping year %d: %s", year, exc)
                    continue
        elif age_hours < NVD_REFRESH_HOURS:
            progress.add_task(
                f"[dim]Database is fresh ({age_hours:.1f}h old < {NVD_REFRESH_HOURS}h). Skipping.",
                total=1,
                completed=1,
            )
        else:
            # Incremental — modified feed only
            try:
                entries = _fetch_and_parse_feed(
                    NVD_MODIFIED_URL, "nvdcve-1.1-modified.json.gz", progress
                )
                total_ingested += _upsert_entries(conn, entries)
            except CVEFetchError as exc:
                logger.error("Modified feed failed: %s", exc)

    if total_ingested > 0:
        _set_last_modified(conn)

    conn.close()
    return total_ingested


def get_cves_for_package(
    package_name: str,
    ecosystem: str = "unknown",
    db_path: Path = DB_PATH,
) -> list[CVEEntry]:
    """Retrieve all CVE entries for a given package name.

    The lookup is case-insensitive and normalises hyphens to underscores
    (matching the normalisation applied during ingestion).

    Args:
        package_name: Name of the package to look up.
        ecosystem: Optional ecosystem filter (``"npm"``, ``"pip"``, …).
            When ``"unknown"`` all ecosystems are searched.
        db_path: Path to the SQLite database file.

    Returns:
        List of matching :class:`CVEEntry` objects sorted by
        *cvss_score* descending (highest severity first).
    """
    if not db_path.exists():
        return []

    normalised = package_name.replace("-", "_").lower()
    conn = _get_connection(db_path)

    try:
        if ecosystem == "unknown":
            rows = conn.execute(
                """
                SELECT c.*
                FROM cve_entries c
                JOIN package_index p ON c.cve_id = p.cve_id
                WHERE LOWER(p.package_name) = ?
                ORDER BY c.cvss_score DESC
                """,
                (normalised,),
            ).fetchall()
        else:
            rows = conn.execute(
                """
                SELECT c.*
                FROM cve_entries c
                JOIN package_index p ON c.cve_id = p.cve_id
                WHERE LOWER(p.package_name) = ?
                  AND (p.ecosystem = ? OR p.ecosystem = 'unknown')
                ORDER BY c.cvss_score DESC
                """,
                (normalised, ecosystem),
            ).fetchall()
    finally:
        conn.close()

    return [
        CVEEntry(
            cve_id=row["cve_id"],
            package_name=row["package_name"],
            ecosystem=row["ecosystem"] or "unknown",
            version_start=row["version_start"] or "",
            version_end=row["version_end"] or "",
            version_start_incl=bool(row["version_start_incl"]),
            version_end_excl=bool(row["version_end_excl"]),
            cvss_score=float(row["cvss_score"] or 0.0),
            cvss_vector=row["cvss_vector"] or "",
            description=row["description"] or "",
            published_date=row["published_date"] or "",
        )
        for row in rows
    ]
