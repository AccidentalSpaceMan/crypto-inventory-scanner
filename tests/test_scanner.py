"""Scanner behaviour beyond the sample files: folders, bad files, edge cases."""
import pytest

from cryptoinv import load_rules
from cryptoinv.scanner import scan_path, scan_source

RULES = load_rules()


def ids(source: str) -> list[str]:
    return [f.algorithm.id for f in scan_source(source, "x.py", RULES)]


def test_clean_code_has_no_findings():
    assert ids("import os\nprint(os.getcwd())\n") == []


def test_one_finding_per_algorithm_per_line():
    assert ids("import hashlib\nhashlib.md5(hashlib.md5(b'x').digest())\n") == ["MD5"]


def test_star_imports_and_relative_imports_are_ignored_safely():
    assert ids("from hashlib import *\nfrom . import md5\nmd5(b'x')\n") == []


def test_import_of_whole_module_path():
    assert ids("import cryptography.hazmat.primitives.asymmetric.rsa\n") == ["RSA"]


def test_code_snippet_and_location_are_recorded():
    [f] = scan_source("import hashlib\n\nx = hashlib.sha1(b'a')\n", "app/x.py", RULES)
    assert (f.path, f.line, f.code) == ("app/x.py", 3, "x = hashlib.sha1(b'a')")


def test_secret_context_from_keyword_argument():
    assert ids("import random\nconnect(password=random.random())\n") == ["INSECURE_RANDOM"]


def test_random_outside_secret_context_is_ignored():
    assert ids("import random\nx = random.random()\n") == []


def test_skips_virtualenvs_and_caches(tmp_path):
    (tmp_path / "app.py").write_text("import hashlib\nhashlib.md5(b'x')\n")
    for skipped in (".venv", "node_modules", "__pycache__"):
        (tmp_path / skipped).mkdir()
        (tmp_path / skipped / "lib.py").write_text("import hashlib\nhashlib.sha1(b'x')\n")
    result = scan_path(tmp_path)
    assert result.files_scanned == 1
    assert [f.algorithm.id for f in result.findings] == ["MD5"]


def test_unparseable_file_is_reported_not_fatal(tmp_path):
    (tmp_path / "good.py").write_text("import hashlib\nhashlib.md5(b'x')\n")
    (tmp_path / "bad.py").write_text("def broken(:\n")
    (tmp_path / "nulls.py").write_bytes(b"x = 1\0\n")
    result = scan_path(tmp_path)
    assert result.files_scanned == 1
    assert sorted(path for path, _ in result.errors) == ["bad.py", "nulls.py"]
    assert [f.algorithm.id for f in result.findings] == ["MD5"]


def test_non_utf8_file_does_not_crash(tmp_path):
    (tmp_path / "latin.py").write_bytes(b"# -*- coding: latin-1 -*-\nimport hashlib\ns = '\xe9'\nhashlib.md5(b'x')\n")
    result = scan_path(tmp_path)
    assert [f.algorithm.id for f in result.findings] == ["MD5"]


def test_scan_single_file(tmp_path):
    target = tmp_path / "one.py"
    target.write_text("import hashlib\nhashlib.sha256(b'x')\n")
    result = scan_path(target)
    assert result.files_scanned == 1
    assert result.findings[0].path.endswith("one.py")


def test_missing_path_raises():
    with pytest.raises(FileNotFoundError):
        scan_path("definitely/not/here")
