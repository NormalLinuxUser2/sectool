from sectool.core.codescan import scan_tree
from sectool.modules import scan


def _write(directory, name, content):
    path = directory / name
    path.write_text(content, encoding="utf-8")
    return path


def _categories(findings):
    return {finding.category for finding in findings}


def test_detects_sql_injection_fstring(tmp_path):
    _write(tmp_path, "db.py", 'cursor.execute(f"SELECT * FROM users WHERE id = {uid}")\n')
    findings = scan_tree(str(tmp_path), scan.RULES)
    assert "sql-injection" in _categories(findings)


def test_detects_command_injection(tmp_path):
    _write(tmp_path, "run.py", "import os\nos.system('rm -rf ' + path)\n")
    findings = scan_tree(str(tmp_path), scan.RULES)
    assert "command-injection" in _categories(findings)


def test_detects_subprocess_shell_true(tmp_path):
    _write(tmp_path, "sp.py", "subprocess.run(cmd, shell=True)\n")
    findings = scan_tree(str(tmp_path), scan.RULES)
    assert any(f.metadata.get("rule") == "PY-CMD-SHELL-TRUE" for f in findings)


def test_detects_hardcoded_secret(tmp_path):
    _write(tmp_path, "conf.py", 'api_key = "sk_live_abcDEF0123456789ABCDEFxyz"\n')
    findings = scan_tree(str(tmp_path), scan.RULES)
    assert "secret" in _categories(findings)


def test_detects_aws_access_key(tmp_path):
    _write(tmp_path, "creds.py", 'value = "AKIAIOSFODNN7EXAMPLE"\n')
    findings = scan_tree(str(tmp_path), scan.RULES)
    assert any(f.metadata.get("rule") == "SECRET-AWS-AKID" for f in findings)


def test_placeholder_secret_is_ignored(tmp_path):
    _write(tmp_path, "conf.py", 'password = "changeme_please"\n')
    findings = scan_tree(str(tmp_path), scan.RULES)
    assert "secret" not in _categories(findings)


def test_ignore_marker_suppresses_finding(tmp_path):
    _write(tmp_path, "i.py", "os.system(cmd)  # sectool:ignore\n")
    findings = scan_tree(str(tmp_path), scan.RULES)
    assert findings == []


def test_clean_file_has_no_findings(tmp_path):
    _write(tmp_path, "ok.py", "def add(a, b):\n    return a + b\n")
    findings = scan_tree(str(tmp_path), scan.RULES)
    assert findings == []


def test_extension_filter(tmp_path):
    _write(tmp_path, "x.txt", "os.system(cmd)\n")
    findings = scan_tree(str(tmp_path), scan.RULES, include_extensions={".py"})
    assert findings == []
