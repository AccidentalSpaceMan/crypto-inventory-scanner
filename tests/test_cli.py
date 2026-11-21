"""The command-line interface and the terminal report."""
import json
from pathlib import Path

import pytest

from cryptoinv.cli import main
from cryptoinv.rules import DEFAULT_RULES

SAMPLES = Path(__file__).parent / "samples"


def run(capsys, *argv):
    code = main(["scan", *map(str, argv), "--no-color"])
    return code, capsys.readouterr().out


def test_report_lists_grades_worst_first_with_locations(capsys):
    code, out = run(capsys, SAMPLES)
    assert code == 0
    assert out.index("BROKEN - fix now") < out.index("LEGACY - ") < out.index("CURRENT - ")
    assert "hashes.py:13" in out                      # file:line for MD5
    assert "hashlib.md5(data).hexdigest()" in out     # the code itself
    assert "[key_size=1,024]" in out                  # details read from the code
    assert "[quantum-vulnerable]" in out
    assert "Summary: BROKEN" in out
    assert "\033[" not in out                         # --no-color means no color codes


def test_quantum_readiness_spots_hybrid_partners(capsys):
    _, out = run(capsys, SAMPLES / "asymmetric.py")
    assert "X25519: ML-KEM (FIPS 203) is also used" in out
    assert "Ed25519: ML-DSA (FIPS 204) is also used" in out


def test_quantum_readiness_flags_missing_partner(tmp_path, capsys):
    app = tmp_path / "app.py"
    app.write_text("from cryptography.hazmat.primitives.asymmetric import rsa\n")
    _, out = run(capsys, app)
    assert "RSA: no ML-KEM (FIPS 203) found yet" in out


def test_clean_folder(tmp_path, capsys):
    (tmp_path / "app.py").write_text("print('hello')\n")
    code, out = run(capsys, tmp_path)
    assert code == 0
    assert "No cryptography found." in out


@pytest.mark.parametrize("target, fail_on, expected", [
    ("hashes.py", "broken", 1),      # MD5 is BROKEN
    ("asymmetric.py", "broken", 1),  # RSA-1024
    ("macs_kdfs.py", "broken", 0),   # worst is LEGACY (HMAC-SHA1, low PBKDF2)
    ("macs_kdfs.py", "legacy", 1),
])
def test_fail_on_sets_exit_code_for_ci(capsys, target, fail_on, expected):
    code, _ = run(capsys, SAMPLES / target, "--fail-on", fail_on)
    assert code == expected


def test_missing_path_is_a_usage_error(capsys):
    with pytest.raises(SystemExit) as e:
        main(["scan", "no/such/folder"])
    assert e.value.code == 2
    assert "does not exist" in capsys.readouterr().err


def test_custom_rules_option(tmp_path, capsys):
    data = json.loads(DEFAULT_RULES.read_text(encoding="utf-8"))
    data["algorithms"]["MD5"]["name"] = "MD5 (custom rules)"
    custom = tmp_path / "rules.json"
    custom.write_text(json.dumps(data))
    _, out = run(capsys, SAMPLES / "hashes.py", "--rules", custom)
    assert "MD5 (custom rules)" in out


def test_bad_rules_file_is_a_usage_error(tmp_path, capsys):
    bad = tmp_path / "rules.json"
    bad.write_text("[]")
    with pytest.raises(SystemExit) as e:
        main(["scan", str(SAMPLES), "--rules", str(bad)])
    assert e.value.code == 2
    assert "rules must be a JSON object" in capsys.readouterr().err
