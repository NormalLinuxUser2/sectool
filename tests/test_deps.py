import json

from sectool.modules import deps


def test_parse_requirements(tmp_path):
    path = tmp_path / "requirements.txt"
    path.write_text(
        "requests==2.0.0\n"
        "# a comment\n"
        "flask>=1.0\n"
        "django==3.2.1  # pinned\n"
        "-r other.txt\n"
        "uvicorn[standard]==0.20.0\n",
        encoding="utf-8",
    )
    parsed = {name: version for name, version, _ in deps.parse_requirements(str(path))}
    assert parsed["requests"] == "2.0.0"
    assert parsed["django"] == "3.2.1"
    assert parsed["uvicorn"] == "0.20.0"
    assert parsed["flask"] is None


def test_parse_package_json(tmp_path):
    path = tmp_path / "package.json"
    path.write_text(
        json.dumps({
            "dependencies": {"lodash": "^4.17.0"},
            "devDependencies": {"jest": "~29.1.2"},
        }),
        encoding="utf-8",
    )
    parsed = {name: version for name, version, _ in deps.parse_package_json(str(path))}
    assert parsed["lodash"] == "4.17.0"
    assert parsed["jest"] == "29.1.2"


def test_resolve_targets_directory(tmp_path):
    (tmp_path / "requirements.txt").write_text("requests==2.0.0\n", encoding="utf-8")
    (tmp_path / "package.json").write_text("{}", encoding="utf-8")
    targets = deps._resolve_targets(str(tmp_path))
    names = {__import__("os").path.basename(source) for source, _ in targets}
    assert names == {"requirements.txt", "package.json"}


def test_severity_from_label():
    assert deps._severity_from_vuln({"database_specific": {"severity": "CRITICAL"}}).name == "CRITICAL"
    assert deps._severity_from_vuln({"database_specific": {"severity": "MODERATE"}}).name == "MEDIUM"


def test_severity_from_cvss_score():
    data = {"severity": [{"type": "CVSS_V3", "score": "9.8"}]}
    assert deps._severity_from_vuln(data).name == "CRITICAL"


def test_fixed_versions_extraction():
    data = {
        "affected": [
            {
                "package": {"name": "requests", "ecosystem": "PyPI"},
                "ranges": [
                    {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.31.0"}]}
                ],
            }
        ]
    }
    assert deps._fixed_versions(data, "requests") == ["2.31.0"]
