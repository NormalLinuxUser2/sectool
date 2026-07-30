from sectool.cli import EXIT_ERROR, EXIT_FINDINGS, EXIT_OK, build_parser, main


def test_parser_builds_all_commands():
    parser = build_parser()
    needs_arg = ("scan", "ssl", "crypto", "fuzz", "headers")
    for command in ("scan", "ssl", "deps", "packets", "pass", "crypto", "fuzz", "headers"):
        args = parser.parse_args([command] + (["x"] if command in needs_arg else []))
        assert args.command == command


def test_sarif_flag_is_accepted():
    parser = build_parser()
    args = parser.parse_args(["scan", "--sarif", "x"])
    assert args.sarif is True


def test_scan_clean_directory_exits_ok(tmp_path):
    (tmp_path / "ok.py").write_text("x = 1\n", encoding="utf-8")
    assert main(["scan", str(tmp_path)]) == EXIT_OK


def test_scan_with_findings_exits_nonzero(tmp_path):
    (tmp_path / "bad.py").write_text("import os\nos.system('rm ' + x)\n", encoding="utf-8")
    assert main(["scan", str(tmp_path)]) == EXIT_FINDINGS


def test_scan_missing_path_exits_error():
    assert main(["scan", "this/path/does/not/exist"]) == EXIT_ERROR


def test_json_output(tmp_path, capsys):
    (tmp_path / "bad.py").write_text("import os\nos.system('rm ' + x)\n", encoding="utf-8")
    main(["scan", "--json", str(tmp_path)])
    captured = capsys.readouterr()
    import json

    payload = json.loads(captured.out)
    assert payload["total"] >= 1


def test_sarif_output(tmp_path, capsys):
    (tmp_path / "bad.py").write_text("import os\nos.system('rm ' + x)\n", encoding="utf-8")
    main(["scan", "--sarif", str(tmp_path)])
    captured = capsys.readouterr()
    import json

    doc = json.loads(captured.out)
    assert doc["version"] == "2.1.0"
    assert doc["runs"][0]["tool"]["driver"]["name"] == "sectool"
    assert doc["runs"][0]["results"]


def test_fail_on_threshold(tmp_path):
    (tmp_path / "weak.py").write_text("import hashlib\nhashlib.sha1(b'x')\n", encoding="utf-8")
    assert main(["scan", "--fail-on", "critical", str(tmp_path)]) == EXIT_OK
    assert main(["scan", "--fail-on", "medium", str(tmp_path)]) == EXIT_FINDINGS
