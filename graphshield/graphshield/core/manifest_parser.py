"""
Package manifest parser — unified dependency extraction.

Supports:
  - package.json          (npm direct deps + devDeps)
  - package-lock.json     (npm all deps, lockfileVersion 2 & 3)
  - requirements.txt      (pip, handles extras, comments, -r includes)
  - Pipfile               (pip with dev-packages separation)
  - pyproject.toml        (poetry and PEP 621 formats)
  - pom.xml               (Maven, basic <dependencies> parsing)

All parsers normalise package names for their ecosystem and return
a flat list of :class:`Dependency` dataclasses. Version strings are
stored as-is (resolution happens later in the DAG builder).
"""

from __future__ import annotations

import json
import logging
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

from graphshield.exceptions import ManifestParseError

logger = logging.getLogger(__name__)

# Manifest filenames the parser recognises, in priority order.
_MANIFEST_FILENAMES = (
    "package-lock.json",  # More info than package.json → check first
    "package.json",
    "requirements.txt",
    "Pipfile",
    "pyproject.toml",
    "pom.xml",
)


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class Dependency:
    """A normalised package dependency extracted from any manifest format.

    Attributes:
        name: Canonical package name (lowercase, hyphens-as-underscores where applicable).
        version: Resolved or declared version string (``"unknown"`` when absent).
        ecosystem: Package ecosystem: ``"npm"`` | ``"pip"`` | ``"maven"``.
        is_dev: ``True`` if declared in a dev/test dependency section.
        is_direct: ``True`` if present directly in the manifest (vs. transitive).
        parent: Name of the direct package that requires this dependency (or ``None``).
    """

    name: str
    version: str
    ecosystem: str
    is_dev: bool
    is_direct: bool
    parent: Optional[str] = None


# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------


def parse_manifest(path: Path) -> List[Dependency]:
    """Auto-detect manifest type and parse it into a unified dep list.

    Args:
        path: Path to the manifest file.

    Returns:
        List of :class:`Dependency` objects.

    Raises:
        ManifestParseError: If the file type is unrecognised or parsing fails.
    """
    if not path.exists():
        raise ManifestParseError(f"File not found: {path}")

    name = path.name.lower()
    try:
        if name == "package-lock.json":
            return _parse_package_lock(path)
        if name == "package.json":
            return _parse_package_json(path)
        if name == "requirements.txt":
            return _parse_requirements_txt(path)
        if name == "pipfile":
            return _parse_pipfile(path)
        if name == "pyproject.toml":
            return _parse_pyproject_toml(path)
        if name == "pom.xml":
            return _parse_pom_xml(path)
    except ManifestParseError:
        raise
    except Exception as exc:
        raise ManifestParseError(f"Unexpected error parsing {path.name}", cause=exc) from exc

    raise ManifestParseError(
        f"Unrecognised manifest type: {path.name}. "
        f"Supported: {', '.join(_MANIFEST_FILENAMES)}"
    )


# ---------------------------------------------------------------------------
# npm — package.json
# ---------------------------------------------------------------------------


def _parse_package_json(path: Path) -> List[Dependency]:
    """Parse a ``package.json`` file for direct npm dependencies.

    Reads ``dependencies`` (production) and ``devDependencies``.
    Skips local-path entries (starting with ``file:``, ``.``, or ``/``).
    Git-URL entries (``github:``, ``git+``, ``git://``) are included with
    version ``"git"``.

    Args:
        path: Path to ``package.json``.

    Returns:
        List of direct :class:`Dependency` objects.
    """
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ManifestParseError(f"Invalid JSON in {path.name}", cause=exc) from exc

    deps: List[Dependency] = []

    def _process_block(block: dict, is_dev: bool) -> None:
        for pkg_name, version_spec in block.items():
            if not isinstance(version_spec, str):
                continue
            # Skip local paths
            if version_spec.startswith(("file:", ".", "/")):
                continue
            # Git URL → sentinel version
            if any(
                version_spec.startswith(p)
                for p in ("git+", "git://", "github:", "bitbucket:", "gitlab:")
            ):
                version = "git"
            else:
                version = version_spec.lstrip("^~>=<").split(" ")[0] or "unknown"
                if not version:
                    version = "unknown"

            deps.append(
                Dependency(
                    name=pkg_name,
                    version=version,
                    ecosystem="npm",
                    is_dev=is_dev,
                    is_direct=True,
                    parent="__root__",
                )
            )

    _process_block(raw.get("dependencies", {}), is_dev=False)
    _process_block(raw.get("devDependencies", {}), is_dev=True)
    _process_block(raw.get("peerDependencies", {}), is_dev=False)

    return deps


# ---------------------------------------------------------------------------
# npm — package-lock.json (lockfileVersion 2 and 3)
# ---------------------------------------------------------------------------


def _parse_package_lock(path: Path) -> List[Dependency]:
    """Parse a ``package-lock.json`` to get all resolved npm dependencies.

    Supports lockfileVersion 2 (``packages`` dict with optional ``node_modules``
    prefix) and lockfileVersion 3.  Also falls back to lockfileVersion 1
    (``dependencies`` dict).

    Args:
        path: Path to ``package-lock.json``.

    Returns:
        List of :class:`Dependency` objects with resolved versions.
    """
    try:
        lock = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ManifestParseError(f"Invalid JSON in {path.name}", cause=exc) from exc

    deps: List[Dependency] = []
    lockfile_version = lock.get("lockfileVersion", 1)

    # Determine set of direct dependencies from root metadata
    root_pkg = lock.get("packages", {}).get("", {})
    direct_prod = set(root_pkg.get("dependencies", {}).keys())
    direct_dev = set(root_pkg.get("devDependencies", {}).keys())
    direct_all = direct_prod | direct_dev

    if lockfile_version >= 2 and "packages" in lock:
        packages: dict = lock["packages"]
        # First pass: materialize package nodes with resolved versions.
        for raw_key, meta in packages.items():
            if raw_key == "":
                continue  # root package
            # Strip the node_modules/ prefix if present
            pkg_name = re.sub(r"^node_modules/", "", raw_key)
            pkg_name = re.sub(r".*/node_modules/", "", pkg_name)

            version: str = meta.get("version", "unknown") or "unknown"
            is_dev: bool = bool(meta.get("dev", False))
            is_direct: bool = pkg_name in direct_all

            deps.append(
                Dependency(
                    name=pkg_name,
                    version=version,
                    ecosystem="npm",
                    is_dev=is_dev,
                    is_direct=is_direct,
                    parent="__root__" if is_direct else None,
                )
            )

        # Second pass: materialize parent->child relationships from each package block.
        for raw_key, meta in packages.items():
            if raw_key == "":
                parent_name = "__root__"
            else:
                parent_name = re.sub(r"^node_modules/", "", raw_key)
                parent_name = re.sub(r".*/node_modules/", "", parent_name)
            dep_map = meta.get("dependencies", {})
            if not isinstance(dep_map, dict):
                continue
            for child_name, child_version in dep_map.items():
                version = (
                    str(child_version).lstrip("^~>=<").split(" ")[0]
                    if isinstance(child_version, str)
                    else "unknown"
                ) or "unknown"
                deps.append(
                    Dependency(
                        name=child_name,
                        version=version,
                        ecosystem="npm",
                        is_dev=bool(meta.get("dev", False)),
                        is_direct=False,
                        parent=parent_name,
                    )
                )
    else:
        # lockfileVersion 1 — flat "dependencies" dict
        def _walk_v1(dep_dict: dict, parent: Optional[str] = None) -> None:
            for pkg_name, meta in dep_dict.items():
                version = meta.get("version", "unknown")
                is_dev = bool(meta.get("dev", False))
                is_direct = pkg_name in direct_all
                deps.append(
                    Dependency(
                        name=pkg_name,
                        version=version,
                        ecosystem="npm",
                        is_dev=is_dev,
                        is_direct=is_direct,
                        parent=parent,
                    )
                )
                if "dependencies" in meta:
                    _walk_v1(meta["dependencies"], parent=pkg_name)

        _walk_v1(lock.get("dependencies", {}))

    return deps


# ---------------------------------------------------------------------------
# pip — requirements.txt
# ---------------------------------------------------------------------------

# Pattern: package_name[extra,extra], optionally followed by version specifiers
_REQ_PATTERN = re.compile(
    r"^([A-Za-z0-9_.\-]+)(?:\[[^\]]+\])?(?:\s*[><=!~^]+\s*([^\s#;,]+))?",
    re.ASCII,
)


def _parse_requirements_txt(path: Path) -> List[Dependency]:
    """Parse a ``requirements.txt`` file for pip dependencies.

    Handles:
    * ``package==1.2.3``
    * ``package>=1.2,<2.0`` — stores first specifier version
    * ``package[extra]==1.2.3``
    * ``package`` (no version)
    * ``# comment`` lines → skipped
    * ``-r other_file.txt`` → skipped
    * ``-e ...`` editable installs → skipped

    Args:
        path: Path to ``requirements.txt``.

    Returns:
        Flat list of :class:`Dependency` objects.
    """
    deps: List[Dependency] = []

    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise ManifestParseError(f"Cannot read {path.name}", cause=exc) from exc

    for raw_line in lines:
        line = raw_line.strip()
        # Skip blank, comments, flags (-r, -e, --index-url, etc.)
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        # Split inline comments
        line = line.split("#")[0].strip()
        if not line:
            continue

        m = _REQ_PATTERN.match(line)
        if not m:
            logger.debug("requirements.txt: skipping unrecognised line: %r", line)
            continue

        pkg_name = _normalise_pip(m.group(1))
        # Extract exact version from ==specifier, else use the best specifier
        raw_spec = line[len(m.group(1)):]
        version = _extract_pip_version(raw_spec)

        deps.append(
            Dependency(
                name=pkg_name,
                version=version,
                ecosystem="pip",
                is_dev=False,
                is_direct=True,
                parent="__root__",
            )
        )

    return deps


def _normalise_pip(name: str) -> str:
    """Normalise a pip package name to lowercase with underscores.

    Args:
        name: Raw package name.

    Returns:
        Normalised name.
    """
    return re.sub(r"[-. ]", "_", name).lower()


def _extract_pip_version(spec: str) -> str:
    """Extract a single representative version from a pip version specifier.

    Prefers ``==`` exact pins, then ``>=``, then any numeric part found.

    Args:
        spec: Version specifier string (e.g. ``">=1.2,<2.0"``).

    Returns:
        Version string or ``"unknown"``.
    """
    spec = spec.strip()
    if not spec:
        return "unknown"
    # Prefer exact pin
    exact = re.search(r"==\s*([^\s,;]+)", spec)
    if exact:
        return exact.group(1)
    # Take first >= bound
    gte = re.search(r">=\s*([^\s,;]+)", spec)
    if gte:
        return gte.group(1)
    # Any version-like number
    any_ver = re.search(r"([0-9][0-9A-Za-z.]*)", spec)
    if any_ver:
        return any_ver.group(1)
    return "unknown"


# ---------------------------------------------------------------------------
# pip — Pipfile
# ---------------------------------------------------------------------------


def _parse_pipfile(path: Path) -> List[Dependency]:
    """Parse a ``Pipfile`` (TOML format) for pip dependencies.

    Reads ``[packages]`` (production) and ``[dev-packages]`` (dev).
    Uses ``tomllib`` (Python 3.11 stdlib) or falls back to ``tomli``.

    Args:
        path: Path to ``Pipfile``.

    Returns:
        List of :class:`Dependency` objects.
    """
    try:
        import tomllib  # Python 3.11+
    except ImportError:
        try:
            import tomli as tomllib  # type: ignore[no-redef]
        except ImportError as exc:
            raise ManifestParseError(
                "tomllib unavailable (need Python 3.11+) and tomli not installed", cause=exc
            ) from exc

    try:
        with open(path, "rb") as fh:
            data = tomllib.load(fh)
    except Exception as exc:
        raise ManifestParseError(f"Failed to parse {path.name}", cause=exc) from exc

    deps: List[Dependency] = []

    def _process_block(block: dict, is_dev: bool) -> None:
        for pkg_name, spec in block.items():
            if pkg_name.lower() == "python_version":
                continue
            if isinstance(spec, str):
                version = _extract_pip_version(spec)
            elif isinstance(spec, dict):
                version = _extract_pip_version(spec.get("version", "*"))
            else:
                version = "unknown"
            deps.append(
                Dependency(
                    name=_normalise_pip(pkg_name),
                    version=version,
                    ecosystem="pip",
                    is_dev=is_dev,
                    is_direct=True,
                    parent="__root__",
                )
            )

    _process_block(data.get("packages", {}), is_dev=False)
    _process_block(data.get("dev-packages", {}), is_dev=True)

    return deps


# ---------------------------------------------------------------------------
# pip — pyproject.toml (poetry and PEP 621)
# ---------------------------------------------------------------------------


def _parse_pyproject_toml(path: Path) -> List[Dependency]:
    """Parse a ``pyproject.toml`` file for pip dependencies.

    Supports:
    * **Poetry** format: ``[tool.poetry.dependencies]``
    * **PEP 621** format: ``[project.dependencies]`` (list of PEP 508 strings)

    Args:
        path: Path to ``pyproject.toml``.

    Returns:
        List of :class:`Dependency` objects.
    """
    try:
        import tomllib
    except ImportError:
        try:
            import tomli as tomllib  # type: ignore[no-redef]
        except ImportError as exc:
            raise ManifestParseError("tomllib/tomli not available", cause=exc) from exc

    try:
        with open(path, "rb") as fh:
            data = tomllib.load(fh)
    except Exception as exc:
        raise ManifestParseError(f"Failed to parse {path.name}", cause=exc) from exc

    deps: List[Dependency] = []

    # ---- Poetry format ----
    tool_poetry = data.get("tool", {}).get("poetry", {})
    if tool_poetry:
        for is_dev, section_key in [(False, "dependencies"), (True, "dev-dependencies")]:
            for pkg_name, spec in tool_poetry.get(section_key, {}).items():
                if pkg_name.lower() in ("python",):
                    continue
                if isinstance(spec, str):
                    version = _extract_pip_version(spec)
                elif isinstance(spec, dict):
                    version = _extract_pip_version(spec.get("version", "*"))
                else:
                    version = "unknown"
                deps.append(
                    Dependency(
                        name=_normalise_pip(pkg_name),
                        version=version,
                        ecosystem="pip",
                        is_dev=is_dev,
                        is_direct=True,
                        parent="__root__",
                    )
                )
        # Optional dependencies (poetry extras)
        for _group_name, group_list in tool_poetry.get("extras", {}).items():
            for pkg_name in group_list:
                deps.append(
                    Dependency(
                        name=_normalise_pip(pkg_name),
                        version="unknown",
                        ecosystem="pip",
                        is_dev=False,
                        is_direct=True,
                        parent="__root__",
                    )
                )

    # ---- PEP 621 format ----
    project_deps = data.get("project", {}).get("dependencies", [])
    if isinstance(project_deps, list):
        for dep_str in project_deps:
            m = _REQ_PATTERN.match(dep_str)
            if m:
                pkg_name = _normalise_pip(m.group(1))
                version = _extract_pip_version(dep_str[len(m.group(1)):])
                deps.append(
                    Dependency(
                        name=pkg_name,
                        version=version,
                        ecosystem="pip",
                        is_dev=False,
                        is_direct=True,
                        parent="__root__",
                    )
                )

    # Optional dependency groups (PEP 621 style)
    optional_deps = data.get("project", {}).get("optional-dependencies", {})
    for _group, dep_list in optional_deps.items():
        for dep_str in dep_list:
            m = _REQ_PATTERN.match(dep_str)
            if m:
                deps.append(
                    Dependency(
                        name=_normalise_pip(m.group(1)),
                        version=_extract_pip_version(dep_str[len(m.group(1)):]),
                        ecosystem="pip",
                        is_dev=False,
                        is_direct=True,
                        parent="__root__",
                    )
                )

    return deps


# ---------------------------------------------------------------------------
# Maven — pom.xml
# ---------------------------------------------------------------------------

# Maven XML namespace
_MVN_NS = {
    "mvn": "http://maven.apache.org/POM/4.0.0",
}


def _parse_pom_xml(path: Path) -> List[Dependency]:
    """Parse a Maven ``pom.xml`` for project dependencies.

    Extracts ``<dependency>`` elements from ``<dependencies>`` sections.
    Dependency name is ``"{groupId}:{artifactId}"``.
    Skips entries where ``<scope>`` is ``"test"`` (marks them as dev).

    Args:
        path: Path to ``pom.xml``.

    Returns:
        List of :class:`Dependency` objects with ecosystem ``"maven"``.
    """
    try:
        tree = ET.parse(str(path))
    except ET.ParseError as exc:
        raise ManifestParseError(f"Invalid XML in {path.name}", cause=exc) from exc

    root = tree.getroot()
    deps: List[Dependency] = []

    # Handle both namespaced and non-namespaced POMs
    def _find_all(element: ET.Element, tag: str) -> list:
        # Try with namespace first
        result = element.findall(f"mvn:{tag}", _MVN_NS)
        if not result:
            result = element.findall(tag)
        return result

    def _find_text(element: ET.Element, tag: str) -> str:
        # Try with namespace first
        node = element.find(f"mvn:{tag}", _MVN_NS)
        if node is None:
            node = element.find(tag)
        return (node.text or "").strip() if node is not None else ""

    # Walk all <dependencies> sections (could be inside <dependencyManagement>)
    for deps_block in root.iter():
        local_tag = deps_block.tag.split("}")[-1] if "}" in deps_block.tag else deps_block.tag
        if local_tag != "dependencies":
            continue

        for dep_el in deps_block:
            local_dep_tag = dep_el.tag.split("}")[-1] if "}" in dep_el.tag else dep_el.tag
            if local_dep_tag != "dependency":
                continue

            group_id = _find_text(dep_el, "groupId")
            artifact_id = _find_text(dep_el, "artifactId")
            version = _find_text(dep_el, "version") or "unknown"
            scope = _find_text(dep_el, "scope") or "compile"

            if not group_id or not artifact_id:
                continue

            is_dev = scope.lower() in ("test", "provided", "system")
            pkg_name = f"{group_id}:{artifact_id}"

            deps.append(
                Dependency(
                    name=pkg_name,
                    version=version,
                    ecosystem="maven",
                    is_dev=is_dev,
                    is_direct=True,
                )
            )

    return deps
