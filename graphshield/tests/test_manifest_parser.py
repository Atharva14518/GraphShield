
from __future__ import annotations

import json
from pathlib import Path

import pytest

from graphshield.core.manifest_parser import (
    Dependency,
    parse_manifest,
    _normalise_pip,
    _extract_pip_version,
)
from graphshield.exceptions import ManifestParseError

class TestParsePackageJson:
    def test_parse_package_json(self, sample_package_json: Path) -> None:
        deps = parse_manifest(sample_package_json)
        names = {d.name for d in deps}
        assert "express" in names
        assert "lodash" in names
        assert "axios" in names
        assert "jest" in names

    def test_all_npm_ecosystem(self, sample_package_json: Path) -> None:
        deps = parse_manifest(sample_package_json)
        assert all(d.ecosystem == "npm" for d in deps)

    def test_dev_dep_marked(self, sample_package_json: Path) -> None:
        deps = parse_manifest(sample_package_json)
        jest = next(d for d in deps if d.name == "jest")
        assert jest.is_dev is True

    def test_prod_dep_not_dev(self, sample_package_json: Path) -> None:
        deps = parse_manifest(sample_package_json)
        express = next(d for d in deps if d.name == "express")
        assert express.is_dev is False

    def test_direct_flag_set(self, sample_package_json: Path) -> None:
        deps = parse_manifest(sample_package_json)
        assert all(d.is_direct for d in deps)

    def test_version_extracted(self, sample_package_json: Path) -> None:
        deps = parse_manifest(sample_package_json)
        express = next(d for d in deps if d.name == "express")
        assert express.version == "4.18.2"

    def test_git_dep_handled(self, tmp_path: Path) -> None:
        content = {
            "dependencies": {
                "my-pkg": "git+https://github.com/org/repo.git#main",
            }
        }
        p = tmp_path / "package.json"
        p.write_text(json.dumps(content))
        deps = parse_manifest(p)
        assert deps[0].version == "git"

    def test_local_path_skipped(self, tmp_path: Path) -> None:
        content = {
            "dependencies": {
                "local-pkg": "file:../local-pkg",
                "express": "4.18.2",
            }
        }
        p = tmp_path / "package.json"
        p.write_text(json.dumps(content))
        deps = parse_manifest(p)
        names = {d.name for d in deps}
        assert "local-pkg" not in names
        assert "express" in names

    def test_caret_version_stripped(self, tmp_path: Path) -> None:
        content = {"dependencies": {"react": "^18.2.0"}}
        p = tmp_path / "package.json"
        p.write_text(json.dumps(content))
        deps = parse_manifest(p)
        assert deps[0].version == "18.2.0"

class TestParseRequirementsTxt:
    def test_parse_requirements_txt(self, sample_requirements_txt: Path) -> None:
        deps = parse_manifest(sample_requirements_txt)
        names = {d.name for d in deps}
        assert "requests" in names
        assert "flask" in names
        assert "numpy" in names
        assert "sqlalchemy" in names

    def test_exact_version_extracted(self, sample_requirements_txt: Path) -> None:
        deps = parse_manifest(sample_requirements_txt)
        requests = next(d for d in deps if d.name == "requests")
        assert requests.version == "2.28.0"

    def test_gte_version_extracted(self, sample_requirements_txt: Path) -> None:
        deps = parse_manifest(sample_requirements_txt)
        flask = next(d for d in deps if d.name == "flask")
        assert flask.version == "2.0.0"

    def test_unknown_version_handled(self, sample_requirements_txt: Path) -> None:
        deps = parse_manifest(sample_requirements_txt)
        numpy = next(d for d in deps if d.name == "numpy")
        assert numpy.version == "unknown"

    def test_extras_stripped(self, sample_requirements_txt: Path) -> None:
        deps = parse_manifest(sample_requirements_txt)
        jwt = next((d for d in deps if "jwt" in d.name), None)
        assert jwt is not None
        assert "[" not in jwt.name

    def test_all_pip_ecosystem(self, sample_requirements_txt: Path) -> None:
        deps = parse_manifest(sample_requirements_txt)
        assert all(d.ecosystem == "pip" for d in deps)

    def test_comments_skipped(self, tmp_path: Path) -> None:
        content = "# this is a comment\nrequests==2.28.0\n"
        p = tmp_path / "requirements.txt"
        p.write_text(content)
        deps = parse_manifest(p)
        assert len(deps) == 1

    def test_empty_file(self, tmp_path: Path) -> None:
        p = tmp_path / "requirements.txt"
        p.write_text("\n# only comments\n")
        deps = parse_manifest(p)
        assert deps == []

class TestParsePipfile:
    def test_parse_pipfile(self, sample_pipfile: Path) -> None:
        deps = parse_manifest(sample_pipfile)
        names = {d.name for d in deps}
        assert "requests" in names
        assert "flask" in names

    def test_dev_packages_marked(self, sample_pipfile: Path) -> None:
        deps = parse_manifest(sample_pipfile)
        pytest_dep = next(d for d in deps if d.name == "pytest")
        assert pytest_dep.is_dev is True

    def test_prod_packages_not_dev(self, sample_pipfile: Path) -> None:
        deps = parse_manifest(sample_pipfile)
        requests = next(d for d in deps if d.name == "requests")
        assert requests.is_dev is False

class TestParsePyprojectPoetry:
    def test_parse_pyproject_toml_poetry(self, sample_pyproject_poetry: Path) -> None:
        deps = parse_manifest(sample_pyproject_poetry)
        names = {d.name for d in deps}
        assert "fastapi" in names
        assert "pydantic" in names
        assert "httpx" in names

    def test_dev_dep_marked_poetry(self, sample_pyproject_poetry: Path) -> None:
        deps = parse_manifest(sample_pyproject_poetry)
        pt = next((d for d in deps if d.name == "pytest"), None)
        if pt:
            assert pt.is_dev is True

    def test_version_extracted_poetry(self, sample_pyproject_poetry: Path) -> None:
        deps = parse_manifest(sample_pyproject_poetry)
        httpx = next(d for d in deps if d.name == "httpx")
        assert httpx.version == "0.24.0"

class TestParsePyprojectPEP621:
    def test_parse_pyproject_toml_pep621(self, sample_pyproject_pep621: Path) -> None:
        deps = parse_manifest(sample_pyproject_pep621)
        names = {d.name for d in deps}
        assert "fastapi" in names
        assert "pydantic" in names
        assert "httpx" in names

    def test_version_extracted_pep621(self, sample_pyproject_pep621: Path) -> None:
        deps = parse_manifest(sample_pyproject_pep621)
        pydantic = next(d for d in deps if d.name == "pydantic")
        assert pydantic.version == "2.0.3"

class TestParsePomXml:
    def test_parse_pom_xml(self, sample_pom_xml: Path) -> None:
        deps = parse_manifest(sample_pom_xml)
        names = {d.name for d in deps}
        assert "org.springframework:spring-core" in names

    def test_maven_ecosystem(self, sample_pom_xml: Path) -> None:
        deps = parse_manifest(sample_pom_xml)
        assert all(d.ecosystem == "maven" for d in deps)

    def test_test_scope_is_dev(self, sample_pom_xml: Path) -> None:
        deps = parse_manifest(sample_pom_xml)
        junit = next(d for d in deps if "junit" in d.name)
        assert junit.is_dev is True

    def test_version_extracted_maven(self, sample_pom_xml: Path) -> None:
        deps = parse_manifest(sample_pom_xml)
        spring = next(d for d in deps if "spring-core" in d.name)
        assert spring.version == "5.3.20"

class TestManifestParseErrors:
    def test_missing_file_raises(self, tmp_path: Path) -> None:
        with pytest.raises(ManifestParseError):
            parse_manifest(tmp_path / "nonexistent.json")

    def test_invalid_json_raises(self, tmp_path: Path) -> None:
        p = tmp_path / "package.json"
        p.write_text("not valid json{{{")
        with pytest.raises(ManifestParseError):
            parse_manifest(p)

    def test_unrecognised_manifest_raises(self, tmp_path: Path) -> None:
        p = tmp_path / "Cargo.toml"
        p.write_text("[package]\nname = 'mypkg'\n")
        with pytest.raises(ManifestParseError):
            parse_manifest(p)

class TestUtilityFunctions:
    def test_normalise_pip_lowercase(self) -> None:
        assert _normalise_pip("Flask") == "flask"

    def test_normalise_pip_hyphens(self) -> None:
        assert _normalise_pip("Flask-SQLAlchemy") == "flask_sqlalchemy"

    def test_extract_pip_exact(self) -> None:
        assert _extract_pip_version("==1.2.3") == "1.2.3"

    def test_extract_pip_gte(self) -> None:
        assert _extract_pip_version(">=2.0.0") == "2.0.0"

    def test_extract_pip_empty(self) -> None:
        assert _extract_pip_version("") == "unknown"

    def test_extract_pip_wildcard(self) -> None:
        assert _extract_pip_version("*") == "unknown"
