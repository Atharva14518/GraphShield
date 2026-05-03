
from __future__ import annotations

import json
from pathlib import Path
from typing import List

import pytest

from graphshield.core.dag_builder import DependencyDAG, NodeMetadata
from graphshield.core.manifest_parser import Dependency

@pytest.fixture()
def sample_package_json(tmp_path: Path) -> Path:
    content = {
        "name": "test-app",
        "version": "1.0.0",
        "dependencies": {
            "express": "4.18.2",
            "lodash": "4.17.20",
            "axios": "0.21.1",
        },
        "devDependencies": {
            "jest": "29.0.0",
        },
    }
    p = tmp_path / "package.json"
    p.write_text(json.dumps(content))
    return p

@pytest.fixture()
def sample_requirements_txt(tmp_path: Path) -> Path:
    content = (
        "# Production deps\n"
        "requests==2.28.0\n"
        "flask>=2.0.0\n"
        "numpy\n"
        "sqlalchemy==2.0.5\n"
        "  # blank line below\n"
        "\n"
        "pyjwt[crypto]==2.6.0\n"
    )
    p = tmp_path / "requirements.txt"
    p.write_text(content)
    return p

@pytest.fixture()
def sample_pipfile(tmp_path: Path) -> Path:
    content = """
[requires]
python_version = "3.11"

[packages]
requests = "==2.28.0"
flask = ">=2.0.0"

[dev-packages]
pytest = ">=7.0"
black = "*"
"""
    p = tmp_path / "Pipfile"
    p.write_text(content)
    return p

@pytest.fixture()
def sample_pyproject_poetry(tmp_path: Path) -> Path:
    content = """
[tool.poetry]
name = "myapp"
version = "0.1.0"

[tool.poetry.dependencies]
python = "^3.11"
fastapi = ">=0.100.0"
pydantic = "^2.0"
httpx = "==0.24.0"

[tool.poetry.dev-dependencies]
pytest = ">=7.0"
"""
    p = tmp_path / "pyproject.toml"
    p.write_text(content)
    return p

@pytest.fixture()
def sample_pyproject_pep621(tmp_path: Path) -> Path:
    content = """
[project]
name = "myapp"
version = "0.1.0"
requires-python = ">=3.11"
dependencies = [
    "fastapi>=0.100.0",
    "pydantic==2.0.3",
    "httpx==0.24.0",
]

[project.optional-dependencies]
dev = [
    "pytest>=7.0",
]
"""
    p = tmp_path / "pyproject.toml"
    p.write_text(content)
    return p

@pytest.fixture()
def sample_pom_xml(tmp_path: Path) -> Path:
    content = """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <groupId>com.example</groupId>
  <artifactId>myapp</artifactId>
  <version>1.0</version>
  <dependencies>
    <dependency>
      <groupId>org.springframework</groupId>
      <artifactId>spring-core</artifactId>
      <version>5.3.20</version>
    </dependency>
    <dependency>
      <groupId>junit</groupId>
      <artifactId>junit</artifactId>
      <version>4.13.2</version>
      <scope>test</scope>
    </dependency>
  </dependencies>
</project>
"""
    p = tmp_path / "pom.xml"
    p.write_text(content)
    return p

@pytest.fixture()
def sample_dag() -> DependencyDAG:
    deps: List[Dependency] = [
        Dependency("express", "4.18.2", "npm", is_dev=False, is_direct=True),
        Dependency("lodash", "4.17.20", "npm", is_dev=False, is_direct=True),
        Dependency("axios", "0.21.1", "npm", is_dev=False, is_direct=True),
        Dependency(
            "qs", "6.5.2", "npm", is_dev=False, is_direct=False, parent="express"
        ),
        Dependency(
            "follow-redirects",
            "1.14.8",
            "npm",
            is_dev=False,
            is_direct=False,
            parent="axios",
        ),
    ]

    dag = DependencyDAG(ecosystem="npm")
    dag.build_from_dependencies(deps)
    dag.compute_topological_sort()

    cve_map = {
        "qs": ("CVE-2022-24999", 7.5),
        "lodash": ("CVE-2021-23337", 7.2),
        "follow-redirects": ("CVE-2023-26159", 6.1),
    }
    cve_scores: dict[str, float] = {}
    for node, (cve_id, score) in cve_map.items():
        if node in dag.metadata:
            dag.metadata[node].cve_ids = [cve_id]
            dag.metadata[node].cvss_score = score
            cve_scores[node] = score

    dag.compute_topological_risk_scores(cve_scores)
    return dag
