
from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv

PACKAGE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = PACKAGE_DIR.parent
load_dotenv(PROJECT_ROOT / ".env")

GRAPHSHIELD_DIR: Path = Path(
    os.getenv("GRAPHSHIELD_DIR", str(Path.home() / ".graphshield"))
)
DB_PATH: Path = Path(os.getenv("GRAPHSHIELD_DB_PATH", str(GRAPHSHIELD_DIR / "cve.db")))
BLOOM_PATH: Path = Path(
    os.getenv("GRAPHSHIELD_BLOOM_PATH", str(GRAPHSHIELD_DIR / "cve_bloom.pkl"))
)
CACHE_DIR: Path = GRAPHSHIELD_DIR / "cache"

GRAPHSHIELD_DIR.mkdir(parents=True, exist_ok=True)
CACHE_DIR.mkdir(parents=True, exist_ok=True)

NVD_BASE_URL: str = "https://nvd.nist.gov/feeds/json/cve/1.1/"
NVD_YEARS: list[int] = list(range(2018, 2025))
NVD_MODIFIED_URL: str = NVD_BASE_URL + "nvdcve-1.1-modified.json.gz"
NVD_RETRY_ATTEMPTS: int = 3
NVD_RETRY_BACKOFF: list[int] = [1, 2, 4]
NVD_REFRESH_HOURS: int = 24

GROQ_API_KEY: str = os.getenv("GROQ_API_KEY", "")
GROQ_MODEL: str = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")
MAX_AGENT_CALLS_PER_SCAN: int = int(os.getenv("MAX_AGENT_CALLS_PER_SCAN", "10"))

CVSS_CRITICAL: float = 9.0
CVSS_HIGH: float = 7.0
CVSS_MEDIUM: float = 4.0
CVSS_LOW: float = 0.1

SCC_LOW_MAX: int = 2
SCC_MEDIUM_MAX: int = 5
SCC_HIGH_MAX: int = 10

BLAST_RADIUS_THRESHOLD: float = 5.0
BLAST_RADIUS_MAX_PATHS: int = 10

MANIFEST_SKIP_DIRS: frozenset[str] = frozenset(
    {"node_modules", ".git", "__pycache__", ".venv", "venv", "dist", "build"}
)
