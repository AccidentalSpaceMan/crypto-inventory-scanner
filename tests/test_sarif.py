"""SARIF output, --exclude and 'cryptoinv: ignore' comments."""
import json
from pathlib import Path

import jsonschema
import pytest

from cryptoinv.cli import main
from cryptoinv.sarif import build_sarif
from cryptoinv.scanner import scan_path

TESTS = Path(__file__).parent
SAMPLES = TESTS / "samples"
# The official OASIS SARIF 2.1.0 schema, from github.com/oasis-tcs/sarif-spec
SCHEMA = json.loads((TESTS / "schemas" / "sarif-schema-2.1.0.json").read_text(encoding="utf-8"))
VALIDATOR = jsonschema.Draft4Validator(SCHEMA)


def schema_errors(sarif: dict) -> list[str]:
    return [e.message for e in VALIDATOR.iter_errors(sarif)]


@pytest.fixture(scope="module")
def sarif():
    return build_sarif(scan_path(SAMPLES))


def run_of(sarif: dict) -> dict:
    return sarif["runs"][0]


# -- validity

def test_passes_the_official_sarif_schema(sarif):
    assert schema_errors(sarif) == []


def test_every_grade_and_an_empty_scan_are_valid(tmp_path):
    assert schema_errors(build_sarif(scan_path(TESTS / "samples_js"), min_grade="current")) == []
    (tmp_path / "app.py").write_text("print('hi')\n")
    empty = build_sarif(scan_path(tmp_path))
    assert run_of(empty)["results"] == [] and schema_errors(empty) == []


def test_the_validator_really_rejects_bad_output(sarif):
    bad = json.loads(json.dumps(sarif))
    bad["runs"][0]["results"][0]["level"] = "catastrophic"
    assert schema_errors(bad)


# -- content

def test_levels_follow_grades_and_current_is_left_out_by_default(sarif):
    levels = {r["ruleId"]: r["level"] for r in run_of(sarif)["results"]}
    assert levels["crypto/MD5"] == "error"
    assert levels["crypto/ED25519"] == "warning"
    assert "crypto/SHA256" not in levels


def test_min_grade_option():
    result = scan_path(SAMPLES)
    broken_only = {r["level"] for r in run_of(build_sarif(result, "broken"))["results"]}
    everything = {r["level"] for r in run_of(build_sarif(result, "current"))["results"]}
    assert broken_only == {"error"} and everything == {"error", "warning", "note"}


def test_one_rule_per_algorithm_with_matching_indexes(sarif):
    run = run_of(sarif)
    rules = run["tool"]["driver"]["rules"]
    assert len({r["id"] for r in rules}) == len(rules)
    for result in run["results"]:
        assert rules[result["ruleIndex"]]["id"] == result["ruleId"]


def test_rule_help_severity_and_tags(sarif):
    rules = {r["id"]: r for r in run_of(sarif)["tool"]["driver"]["rules"]}
    md5, x25519 = rules["crypto/MD5"], rules["crypto/X25519"]
    assert md5["properties"]["security-severity"] == "8.0"
    assert x25519["properties"]["security-severity"] == "5.0"
    assert "security" in md5["properties"]["tags"]
    assert "quantum-vulnerable" in x25519["properties"]["tags"]
    assert "Fix:" in md5["help"]["text"] and "**Fix:**" in md5["help"]["markdown"]


def test_results_point_at_file_and_line(sarif):
    md5 = next(r for r in run_of(sarif)["results"] if r["ruleId"] == "crypto/MD5"
               and r["locations"][0]["physicalLocation"]["region"]["startLine"] == 13)
    assert md5["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "hashes.py"
    assert "`hashlib.md5`" in md5["message"]["text"] and "Fix:" in md5["message"]["text"]


def test_details_and_quantum_flag_in_messages(sarif):
    texts = [r["message"]["text"] for r in run_of(sarif)["results"]]
    assert any("[key_size=1,024]" in t for t in texts)
    assert any("quantum-vulnerable" in t for t in texts)


def test_paths_with_spaces_are_valid_uris(tmp_path):
    folder = tmp_path / "my app"
    folder.mkdir()
    (folder / "old code.py").write_text("import hashlib\nhashlib.md5(b'x')\n")
    [result] = run_of(build_sarif(scan_path(tmp_path)))["results"]
    assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "my%20app/old%20code.py"


def test_cli_writes_sarif(tmp_path, capsys):
    out = tmp_path / "results.sarif"
    assert main(["scan", str(SAMPLES / "hashes.py"), "--no-color", "--sarif", str(out)]) == 0
    assert "Wrote SARIF (" in capsys.readouterr().out
    assert schema_errors(json.loads(out.read_text(encoding="utf-8"))) == []


def test_cli_reports_unwritable_sarif_path(tmp_path, capsys):
    with pytest.raises(SystemExit) as e:
        main(["scan", str(SAMPLES / "hashes.py"), "--sarif", str(tmp_path / "no" / "dir" / "x.sarif")])
    assert e.value.code == 2 and "can't write SARIF" in capsys.readouterr().err


# -- --exclude

@pytest.fixture
def project(tmp_path):
    for rel in ("app/main.py", "tests/test_x.py", "tests/fixtures/weak.py", "vendor_lib/a.py", "web/app.min.js"):
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("import hashlib\nhashlib.md5(b'x')\n" if rel.endswith(".py")
                        else "crypto.createHash('md5');\n")
    (tmp_path / "web" / "app.js").write_text("crypto.createHash('sha1');\n")
    return tmp_path


@pytest.mark.parametrize("patterns, expected", [
    ([], {"app/main.py", "tests/test_x.py", "tests/fixtures/weak.py", "vendor_lib/a.py", "web/app.js"}),
    (["tests"], {"app/main.py", "vendor_lib/a.py", "web/app.js"}),
    (["tests/fixtures"], {"app/main.py", "tests/test_x.py", "vendor_lib/a.py", "web/app.js"}),
    (["vendor_*", "*.js"], {"app/main.py", "tests/test_x.py", "tests/fixtures/weak.py"}),
    (["test_*.py"], {"app/main.py", "tests/fixtures/weak.py", "vendor_lib/a.py", "web/app.js"}),
])
def test_exclude_patterns(project, patterns, expected):
    assert {f.path for f in scan_path(project, exclude=patterns).findings} == expected


def test_exclude_from_the_command_line(project, capsys):
    main(["scan", str(project), "--no-color", "--exclude", "tests", "--exclude", "web"])
    assert "2 file(s) scanned (2 Python)" in capsys.readouterr().out


# -- cryptoinv: ignore

def test_ignore_comment_in_each_language(tmp_path, capsys):
    (tmp_path / "a.py").write_text("import hashlib\n"
                                   "hashlib.md5(b'x')  # cryptoinv: ignore (cache key, not security)\n"
                                   "hashlib.sha1(b'x')\n")
    (tmp_path / "B.java").write_text('MessageDigest.getInstance("MD5"); // CryptoInv:Ignore\n')
    (tmp_path / "c.js").write_text("crypto.createHash('md5'); // cryptoinv: ignore\n")
    (tmp_path / "d.go").write_text('import "crypto/md5" // cryptoinv: ignore\n')
    result = scan_path(tmp_path)
    assert [(f.path, f.algorithm.id) for f in result.findings] == [("a.py", "SHA1")]
    assert result.ignored == 4
    main(["scan", str(tmp_path), "--no-color"])
    assert "4 finding(s) left out by 'cryptoinv: ignore' comments" in capsys.readouterr().out


def test_ignored_findings_stay_out_of_sarif_and_cbom(tmp_path):
    from cryptoinv.cbom import build_cbom
    (tmp_path / "a.py").write_text("import hashlib\nhashlib.md5(b'x')  # cryptoinv: ignore\n")
    result = scan_path(tmp_path)
    assert run_of(build_sarif(result))["results"] == []
    assert build_cbom(result)["components"] == []


def test_scanner_source_is_clean_apart_from_reviewed_lines():
    result = scan_path(TESTS.parent / "cryptoinv")
    assert result.findings == [] and result.ignored > 0
