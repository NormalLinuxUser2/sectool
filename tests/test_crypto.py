from sectool.core.codescan import scan_tree
from sectool.modules import crypto


def _write(directory, name, content):
    path = directory / name
    path.write_text(content, encoding="utf-8")
    return path


def _categories(findings):
    return {finding.category for finding in findings}


def test_detects_md5(tmp_path):
    _write(tmp_path, "h.py", "import hashlib\nh = hashlib.md5(data).hexdigest()\n")
    findings = scan_tree(str(tmp_path), crypto.RULES)
    assert "weak-hash" in _categories(findings)


def test_detects_des(tmp_path):
    _write(tmp_path, "c.py", 'algorithm = "DES"\n')
    findings = scan_tree(str(tmp_path), crypto.RULES)
    assert "weak-cipher" in _categories(findings)


def test_detects_insecure_random(tmp_path):
    _write(tmp_path, "r.py", "import random\ntoken = random.randint(0, 9999)\n")
    findings = scan_tree(str(tmp_path), crypto.RULES)
    assert "weak-random" in _categories(findings)


def test_detects_disabled_verification(tmp_path):
    _write(tmp_path, "v.py", "requests.get(url, verify=False)\n")
    findings = scan_tree(str(tmp_path), crypto.RULES)
    assert "cert-validation" in _categories(findings)


def test_detects_small_rsa_key(tmp_path):
    _write(tmp_path, "k.py", "key = rsa.generate_private_key(public_exponent=65537, key_size=1024)\n")
    findings = scan_tree(str(tmp_path), crypto.RULES)
    assert "weak-keysize" in _categories(findings)


def test_detects_algorithm_string(tmp_path):
    _write(tmp_path, "j.py", 'digest = MessageDigest.getInstance("MD5")\n')
    findings = scan_tree(str(tmp_path), crypto.RULES)
    assert "weak-hash" in _categories(findings)


def test_prose_mention_not_flagged(tmp_path):
    _write(tmp_path, "doc.py", 'note = "We migrated away from MD5 and DES years ago"\n')
    findings = scan_tree(str(tmp_path), crypto.RULES)
    categories = _categories(findings)
    assert "weak-hash" not in categories
    assert "weak-cipher" not in categories
