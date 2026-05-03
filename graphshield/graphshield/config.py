"""
GraphShield central configuration.

All settings are defined here and can be overridden via environment
variables loaded from a .env file (or the process environment).
Import this module everywhere a config value is needed — never hard-code
paths or constants elsewhere.
"""

from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv

# Load the repo-level .env regardless of the process launch directory.
PACKAGE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = PACKAGE_DIR.parent
load_dotenv(PROJECT_ROOT / ".env")

# ---------------------------------------------------------------------------
# Filesystem paths
# ---------------------------------------------------------------------------

GRAPHSHIELD_DIR: Path = Path(
    os.getenv("GRAPHSHIELD_DIR", str(Path.home() / ".graphshield"))
)
DB_PATH: Path = Path(os.getenv("GRAPHSHIELD_DB_PATH", str(GRAPHSHIELD_DIR / "cve.db")))
BLOOM_PATH: Path = Path(
    os.getenv("GRAPHSHIELD_BLOOM_PATH", str(GRAPHSHIELD_DIR / "cve_bloom.pkl"))
)
CACHE_DIR: Path = GRAPHSHIELD_DIR / "cache"

# Ensure required directories exist on first import
GRAPHSHIELD_DIR.mkdir(parents=True, exist_ok=True)
CACHE_DIR.mkdir(parents=True, exist_ok=True)

# ---------------------------------------------------------------------------
# NVD feed settings
# ---------------------------------------------------------------------------

NVD_BASE_URL: str = "https://nvd.nist.gov/feeds/json/cve/1.1/"
NVD_YEARS: list[int] = list(range(2018, 2025))          # 2018 – 2024 inclusive
NVD_MODIFIED_URL: str = NVD_BASE_URL + "nvdcve-1.1-modified.json.gz"
NVD_RETRY_ATTEMPTS: int = 3
NVD_RETRY_BACKOFF: list[int] = [1, 2, 4]                # seconds between retries
NVD_REFRESH_HOURS: int = 24                              # hours before re-checking modified feed

# ---------------------------------------------------------------------------
# Groq / LLM settings
# ---------------------------------------------------------------------------

GROQ_API_KEY: str = os.getenv("GROQ_API_KEY", "")
GROQ_MODEL: str = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")
MAX_AGENT_CALLS_PER_SCAN: int = int(os.getenv("MAX_AGENT_CALLS_PER_SCAN", "10"))

# ---------------------------------------------------------------------------
# CVSS severity thresholds
# ---------------------------------------------------------------------------

CVSS_CRITICAL: float = 9.0
CVSS_HIGH: float = 7.0
CVSS_MEDIUM: float = 4.0
CVSS_LOW: float = 0.1   # anything above 0 but below MEDIUM

# ---------------------------------------------------------------------------
# SCC (Strongly Connected Component) cluster size thresholds
# ---------------------------------------------------------------------------

SCC_LOW_MAX: int = 2         # size == 2  → LOW
SCC_MEDIUM_MAX: int = 5      # size 3–5   → MEDIUM
SCC_HIGH_MAX: int = 10       # size 6–10  → HIGH
                              # size > 10  → CRITICAL

# ---------------------------------------------------------------------------
# Blast radius / Steiner Tree thresholds
# ---------------------------------------------------------------------------

BLAST_RADIUS_THRESHOLD: float = 5.0   # min score to count as a Steiner terminal
BLAST_RADIUS_MAX_PATHS: int = 10      # top N attack paths to keep per node

# ---------------------------------------------------------------------------
# Manifest scanning
# ---------------------------------------------------------------------------

MANIFEST_SKIP_DIRS: frozenset[str] = frozenset(
    {"node_modules", ".git", "__pycache__", ".venv", "venv", "dist", "build"}
)
