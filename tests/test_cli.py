from sectool.cli import EXIT_ERROR, EXIT_FINDINGS, EXIT_OK, build_parser, main


def test_parser_builds_all_commands():
    parser = build_parser()
    for command in ("scan", "ssl", "deps", "packets", "pass", "crypto"):
        args = parser.parse_args([command] + (["x"] if command in ("scan", "ssl", "crypto") else []))
        assert args.command == command


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


def test_fail_on_threshold(tmp_path):
    (tmp_path / "weak.py").write_text("import hashlib\nhashlib.sha1(b'x')\n", encoding="utf-8")
    assert main(["scan", "--fail-on", "critical", str(tmp_path)]) == EXIT_OK
    assert main(["scan", "--fail-on", "medium", str(tmp_path)]) == EXIT_FINDINGS
