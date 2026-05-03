
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

@dataclass
class CVEEntry:

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
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    conn.executescript(_SCHEMA_SQL)
    conn.commit()
    return conn

def _get_last_modified(conn: sqlite3.Connection) -> datetime | None:
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
    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        "INSERT OR REPLACE INTO metadata (key, value) VALUES ('last_modified', ?)",
        (now,),
    )
    conn.commit()

def _download_with_retry(url: str) -> bytes:
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

def _extract_cvss(item: dict[str, Any]) -> tuple[float, str]:
    impact = item.get("impact", {})

    v3 = impact.get("baseMetricV3", {}).get("cvssV3", {})
    if v3:
        return float(v3.get("baseScore", 0.0)), v3.get("vectorString", "")

    v2 = impact.get("baseMetricV2", {}).get("cvssV2", {})
    if v2:
        return float(v2.get("baseScore", 0.0)), v2.get("vectorString", "")

    return 0.0, ""

def _extract_description(item: dict[str, Any]) -> str:
    for desc in item.get("cve", {}).get("description", {}).get("description_data", []):
        if desc.get("lang") == "en":
            return desc.get("value", "")[:2000]
    return ""

def _guess_ecosystem(vendor: str, product: str) -> str:
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
    entries: list[CVEEntry] = []

    for item in items:
        cve_id: str = item.get("cve", {}).get("CVE_data_meta", {}).get("ID", "")
        if not cve_id:
            continue

        published_date: str = item.get("publishedDate", "")
        description: str = _extract_description(item)
        cvss_score, cvss_vector = _extract_cvss(item)

        configurations = item.get("configurations", {})
        nodes: list[dict] = configurations.get("nodes", [])

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

def _upsert_entries(conn: sqlite3.Connection, entries: list[CVEEntry]) -> int:
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

def _fetch_and_parse_feed(url: str, label: str, progress: Progress) -> list[CVEEntry]:
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

def ingest_nvd_feeds(
    full_refresh: bool = False,
    db_path: Path = DB_PATH,
    years: list[int] | None = None,
) -> int:
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
