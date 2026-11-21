"""Each sample file says what the scanner should find, line by line, in "# expect:" comments.

The test checks the scanner finds exactly that: nothing missing (a false negative) and nothing
extra (a false positive).
"""
import re
from pathlib import Path

import pytest

from cryptoinv import load_rules
from cryptoinv.scanner import scan_path

SAMPLES = Path(__file__).parent / "samples"
EXPECT = re.compile(r"#\s*expect:\s*(.+)$")


def expected_findings(path: Path) -> set[tuple[int, str]]:
    expected = set()
    for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        m = EXPECT.search(line)
        if m:
            expected |= {(lineno, alg.strip()) for alg in m.group(1).split(",")}
    return expected


@pytest.mark.parametrize("sample", sorted(SAMPLES.glob("*.py")), ids=lambda p: p.name)
def test_sample_findings_match_expectations(sample):
    result = scan_path(sample)
    found = {(f.line, f.algorithm.id) for f in result.findings}
    expected = expected_findings(sample)
    assert expected, f"{sample.name} has no '# expect:' comments"
    missing, extra = expected - found, found - expected
    assert not missing and not extra, f"missing: {sorted(missing)}  unexpected: {sorted(extra)}"


def test_every_expected_id_is_a_real_algorithm():
    rules = load_rules()
    for sample in SAMPLES.glob("*.py"):
        for _, alg in expected_findings(sample):
            assert alg in rules.algorithms, f"{sample.name}: unknown id {alg}"


def test_details_are_read_from_the_code():
    by_line = {(f.path, f.line): f for f in scan_path(SAMPLES).findings}
    weak_rsa = next(f for f in by_line.values() if f.algorithm.id == "RSA_WEAK" and f.path == "asymmetric.py")
    assert weak_rsa.detail == "key_size=1,024"
    pbkdf2 = next(f for f in by_line.values() if f.algorithm.id == "PBKDF2")
    assert pbkdf2.detail == "iterations=1,000, hash: SHA-256"
    hmac_sha1 = next(f for f in by_line.values() if f.algorithm.id == "HMAC_SHA1")
    assert hmac_sha1.detail == "hash: SHA-1"
    marked = [f for f in by_line.values() if "usedforsecurity=False" in f.detail]
    assert len(marked) == 1 and marked[0].algorithm.id == "MD5"


def test_scanning_the_folder_covers_every_sample():
    result = scan_path(SAMPLES)
    assert result.files_scanned == len(list(SAMPLES.glob("*.py")))
    assert result.errors == []
    assert {f.path for f in result.findings} == {p.name for p in SAMPLES.glob("*.py")}
