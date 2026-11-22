"""Comparing two CBOMs: cryptoinv diff OLD NEW"""
import json

import pytest

from cryptoinv.cbom import write_cbom
from cryptoinv.cli import main
from cryptoinv.diff import CbomError, diff_files, load_cbom, render_diff
from cryptoinv.scanner import scan_path


def cbom_of(tmp_path, name, files):
    """Write the given source files to a folder, scan it, and return the CBOM's path."""
    app = tmp_path / name / "app"
    app.mkdir(parents=True)
    for filename, code in files.items():
        (app / filename).write_text(code)
    out = tmp_path / f"{name}.json"
    write_cbom(scan_path(app), out)
    return out


OLD = {"a.py": "import hashlib\nhashlib.md5(b'x')\nhashlib.sha1(b'x')\nhashlib.sha256(b'x')\n"}
NEW = {"a.py": "import hashlib\nhashlib.sha256(b'x')\nhashlib.sha1(b'x')\n",
       "b.py": "import hashlib\nhashlib.sha1(b'y')\nhashlib.sha3_256(b'y')\n"}


@pytest.fixture
def pair(tmp_path):
    return cbom_of(tmp_path, "old", OLD), cbom_of(tmp_path, "new", NEW)


def effects(diff):
    return {c.asset.key: c.effect for c in diff.changes}


def test_sorts_changes_into_worse_better_other(pair):
    diff = diff_files(*pair)
    assert effects(diff) == {"MD5": "better", "SHA1": "worse", "SHA3": "other"}
    assert diff.verdict == "MIXED"


def test_unchanged_algorithms_are_left_out(pair):
    assert "SHA256" not in effects(diff_files(*pair))


def test_moving_lines_within_a_file_is_not_a_change(tmp_path):
    old = cbom_of(tmp_path, "old", {"a.py": "import hashlib\nhashlib.md5(b'x')\n"})
    new = cbom_of(tmp_path, "new", {"a.py": "import hashlib\n\n\n# moved down\nhashlib.md5(b'x')\n"})
    diff = diff_files(old, new)
    assert diff.changes == [] and diff.verdict == "NO CHANGE"


def test_same_count_in_a_different_file_is_other(tmp_path):
    old = cbom_of(tmp_path, "old", {"a.py": "import hashlib\nhashlib.md5(b'x')\n"})
    new = cbom_of(tmp_path, "new", {"b.py": "import hashlib\nhashlib.md5(b'x')\n"})
    diff = diff_files(old, new)
    assert effects(diff) == {"MD5": "other"} and diff.verdict == "SAME RISK"
    out = render_diff(diff)
    assert "now also in: b.py" in out and "no longer in: a.py" in out


def test_report_text(pair):
    out = render_diff(diff_files(*pair))
    assert out.index("Worse - ") < out.index("Better - ") < out.index("Other changes")
    assert "^ SHA-1 (BROKEN)  1 -> 2 places" in out
    assert "now also in: b.py" in out
    assert "- MD5 (BROKEN)  gone (was 1 place)" in out
    assert "+ SHA-3 / SHAKE (CURRENT)  new: 1 place" in out
    assert "BROKEN 2 -> 1 algorithm (2 -> 2 places)" in out
    assert "Verdict: MIXED (1 thing worse, 1 thing better)" in out
    assert "\033[" not in out


def test_quantum_vulnerable_places_are_counted(tmp_path):
    rsa = "from cryptography.hazmat.primitives.asymmetric import rsa\n"
    old = cbom_of(tmp_path, "old", {"a.py": rsa, "b.py": rsa})
    new = cbom_of(tmp_path, "new", {"a.py": rsa})
    diff = diff_files(old, new)
    assert diff.verdict == "BETTER"
    out = render_diff(diff)
    assert "quantum-vulnerable 2 -> 1 place" in out
    assert "[quantum-vulnerable]" in out


def _cbom(components):
    return {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": components}


def _alg(id_, grade, places, name=None):
    return {"type": "cryptographic-asset", "bom-ref": f"crypto:{id_}", "name": name or id_,
            "cryptoProperties": {"assetType": "algorithm", "algorithmProperties": {"primitive": "hash"}},
            "evidence": {"occurrences": [{"location": "a.py", "line": i + 1} for i in range(places)]},
            "properties": [{"name": "cryptoinv:id", "value": id_},
                           {"name": "cryptoinv:grade", "value": grade}]}


def write(tmp_path, name, data):
    path = tmp_path / name
    path.write_text(json.dumps(data))
    return path


def test_regrade_after_rules_change(tmp_path):
    old = write(tmp_path, "old.json", _cbom([_alg("SHA1", "LEGACY", 1), _alg("X", "LEGACY", 1)]))
    new = write(tmp_path, "new.json", _cbom([_alg("SHA1", "BROKEN", 1), _alg("X", "CURRENT", 1)]))
    diff = diff_files(old, new)
    assert effects(diff) == {"SHA1": "worse", "X": "better"}
    assert "regraded LEGACY -> BROKEN (the grading rules changed)" in render_diff(diff)


def test_reads_cboms_from_other_tools(tmp_path):
    """No cryptoinv properties: key on bom-ref, no grade, quantum from the NIST level."""
    other = {"type": "cryptographic-asset", "bom-ref": "rsa-2048", "name": "RSA-2048",
             "cryptoProperties": {"assetType": "algorithm",
                                  "algorithmProperties": {"nistQuantumSecurityLevel": 0}}}
    old = write(tmp_path, "old.json", _cbom([]))
    new = write(tmp_path, "new.json", _cbom([other]))
    (change,) = diff_files(old, new).changes
    assert change.asset.key == "rsa-2048"
    assert change.asset.grade is None and change.asset.quantum_vulnerable
    assert change.effect == "other"          # without a grade we can't call it worse


def test_certificates_match_by_identity_not_file(tmp_path):
    def cert(path, expiry):
        return {"type": "cryptographic-asset", "bom-ref": f"certificate:{path}:1", "name": "CN=app",
                "cryptoProperties": {"assetType": "certificate", "certificateProperties": {
                    "subjectName": "CN=app", "issuerName": "CN=ca", "notValidAfter": expiry}},
                "evidence": {"occurrences": [{"location": path, "line": 1}]}}
    old = load_cbom(write(tmp_path, "old.json", _cbom([cert("certs/a.pem", "2027-01-01T00:00:00Z")])))
    renamed = load_cbom(write(tmp_path, "r.json", _cbom([cert("certs/b.pem", "2027-01-01T00:00:00Z")])))
    renewed = load_cbom(write(tmp_path, "n.json", _cbom([cert("certs/a.pem", "2028-01-01T00:00:00Z")])))
    assert list(old.assets) == list(renamed.assets)          # same certificate, moved file
    assert list(old.assets) != list(renewed.assets)          # renewed = a different certificate


@pytest.mark.parametrize("content, message", [
    ("not json", "isn't a readable JSON file"),
    ('{"hello": 1}', "isn't a CycloneDX file"),
    ("[1, 2]", "isn't a CycloneDX file"),
])
def test_rejects_files_that_are_not_cboms(tmp_path, content, message):
    path = tmp_path / "bad.json"
    path.write_text(content)
    with pytest.raises(CbomError, match=message):
        load_cbom(path)


# ----- command line -----

def run(capsys, *argv):
    code = main(["diff", *map(str, argv), "--no-color"])
    return code, capsys.readouterr().out


def test_cli_prints_report(pair, capsys):
    code, out = run(capsys, *pair)
    assert code == 0
    assert "Verdict: MIXED" in out


@pytest.mark.parametrize("fail_on, expected", [("broken", 1), ("legacy", 1)])
def test_cli_fail_on_when_things_get_worse(pair, capsys, fail_on, expected):
    code, _ = run(capsys, *pair, "--fail-on", fail_on)
    assert code == expected


def test_cli_fail_on_ignores_improvements(pair, capsys):
    old, _ = pair
    clean = old.parent / "clean.json"           # everything removed
    clean.write_text(json.dumps(_cbom([])))
    code, out = run(capsys, old, clean, "--fail-on", "broken")
    assert code == 0 and "Verdict: BETTER" in out


def test_cli_fail_on_only_counts_bad_enough_grades(tmp_path, capsys):
    old = write(tmp_path, "old.json", _cbom([]))
    new = write(tmp_path, "new.json", _cbom([_alg("RSA", "LEGACY", 1)]))
    assert run(capsys, old, new, "--fail-on", "broken")[0] == 0
    assert run(capsys, old, new, "--fail-on", "legacy")[0] == 1


def test_cli_missing_file(pair, capsys):
    with pytest.raises(SystemExit) as e:
        main(["diff", str(pair[0]), "nope.json"])
    assert e.value.code == 2
    assert "nope.json does not exist" in capsys.readouterr().err


def test_cli_bad_file(tmp_path, pair, capsys):
    bad = tmp_path / "bad.json"
    bad.write_text("{}")
    with pytest.raises(SystemExit) as e:
        main(["diff", str(pair[0]), str(bad)])
    assert e.value.code == 2
    assert "isn't a CycloneDX file" in capsys.readouterr().err
