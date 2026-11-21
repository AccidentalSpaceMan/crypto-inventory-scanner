"""CBOM output: valid CycloneDX 1.6, and faithful to what the scan found."""
import json
from pathlib import Path

import pytest
from cyclonedx.schema import SchemaVersion
from cyclonedx.validation.json import JsonStrictValidator

from cryptoinv.cbom import build_cbom
from cryptoinv.cli import main
from cryptoinv.scanner import scan_path

SAMPLES = Path(__file__).parent / "samples"
VALIDATOR = JsonStrictValidator(SchemaVersion.V1_6)


def schema_errors(cbom: dict):
    return VALIDATOR.validate_str(json.dumps(cbom))


@pytest.fixture(scope="module")
def cbom():
    return build_cbom(scan_path(SAMPLES))


def component(cbom, alg_id):
    return next(c for c in cbom["components"] if c["bom-ref"] == f"crypto:{alg_id}")


def prop(comp, name):
    return next(p["value"] for p in comp["properties"] if p["name"] == f"cryptoinv:{name}")


def test_passes_the_official_cyclonedx_1_6_schema(cbom):
    assert schema_errors(cbom) is None


def test_the_validator_really_rejects_bad_output(cbom):
    """Guard against a validator that says yes to everything."""
    bad = json.loads(json.dumps(cbom))
    bad["components"][0]["cryptoProperties"]["assetType"] = "magic"
    assert schema_errors(bad) is not None


def test_empty_scan_is_still_valid(tmp_path):
    (tmp_path / "app.py").write_text("print('hi')\n")
    empty = build_cbom(scan_path(tmp_path))
    assert empty["components"] == []
    assert schema_errors(empty) is None


def test_one_component_per_algorithm_with_every_occurrence(cbom):
    result = scan_path(SAMPLES)
    assert {c["bom-ref"] for c in cbom["components"]} == {f"crypto:{f.algorithm.id}" for f in result.findings}
    total = sum(len(c["evidence"]["occurrences"]) for c in cbom["components"])
    assert total == len(result.findings)


def test_occurrences_record_file_line_symbol_and_details(cbom):
    md5 = component(cbom, "MD5")
    assert {"location": "hashes.py", "line": 13, "symbol": "hashlib.md5",
            "additionalContext": "return hashlib.md5(data).hexdigest()  # expect: MD5"} in md5["evidence"]["occurrences"]
    weak_rsa = component(cbom, "RSA_WEAK")
    assert any("[key_size=1,024]" in o["additionalContext"] for o in weak_rsa["evidence"]["occurrences"])


def test_grades_and_advice_are_kept_as_properties(cbom):
    md5 = component(cbom, "MD5")
    assert prop(md5, "grade") == "BROKEN"
    assert prop(md5, "quantumVulnerable") == "false"
    assert "SHA-256" in prop(md5, "fix")


def test_quantum_vulnerable_algorithms_get_nist_level_0(cbom):
    x25519 = component(cbom, "X25519")
    assert x25519["cryptoProperties"]["algorithmProperties"] == {"primitive": "key-agree", "nistQuantumSecurityLevel": 0}
    assert prop(x25519, "postQuantumReplacement") == "MLKEM"
    mlkem = component(cbom, "MLKEM")
    assert "nistQuantumSecurityLevel" not in mlkem["cryptoProperties"]["algorithmProperties"]


def test_cipher_modes_and_protocols(cbom):
    assert component(cbom, "ECB")["cryptoProperties"]["algorithmProperties"]["mode"] == "ecb"
    assert component(cbom, "AES_GCM")["cryptoProperties"]["algorithmProperties"]["mode"] == "gcm"
    tls = component(cbom, "TLS_OLD")["cryptoProperties"]
    assert tls == {"assetType": "protocol", "protocolProperties": {"type": "tls"}}


def test_components_ordered_worst_first(cbom):
    grades = [prop(c, "grade") for c in cbom["components"]]
    assert grades == sorted(grades, key=["BROKEN", "LEGACY", "CURRENT"].index)


def test_metadata_and_dependencies(cbom):
    assert cbom["bomFormat"] == "CycloneDX" and cbom["specVersion"] == "1.6"
    assert cbom["serialNumber"].startswith("urn:uuid:")
    assert cbom["metadata"]["tools"]["components"][0]["name"] == "crypto-inventory-scanner"
    assert cbom["metadata"]["component"]["name"] == "samples"
    [dep] = cbom["dependencies"]
    assert dep["dependsOn"] == [c["bom-ref"] for c in cbom["components"]]


def test_skipped_files_are_recorded(tmp_path):
    (tmp_path / "bad.py").write_text("def broken(:\n")
    out = build_cbom(scan_path(tmp_path))
    skipped = [p["value"] for p in out["metadata"]["properties"] if p["name"] == "cryptoinv:skippedFile"]
    assert len(skipped) == 1 and skipped[0].startswith("bad.py:")
    assert schema_errors(out) is None


def test_fixed_timestamp_and_serial_make_output_reproducible():
    result = scan_path(SAMPLES / "hashes.py")
    a = build_cbom(result, timestamp="2026-01-01T00:00:00Z", serial_number="urn:uuid:00000000-0000-4000-8000-000000000000")
    b = build_cbom(result, timestamp="2026-01-01T00:00:00Z", serial_number="urn:uuid:00000000-0000-4000-8000-000000000000")
    assert a == b


def test_cli_writes_cbom_file(tmp_path, capsys):
    out = tmp_path / "inventory.cbom.json"
    assert main(["scan", str(SAMPLES / "asymmetric.py"), "--no-color", "--cbom", str(out)]) == 0
    assert "Wrote CBOM" in capsys.readouterr().out
    written = json.loads(out.read_text(encoding="utf-8"))
    assert schema_errors(written) is None
    assert component(written, "RSA_WEAK")


def test_cli_reports_unwritable_cbom_path(tmp_path, capsys):
    with pytest.raises(SystemExit) as e:
        main(["scan", str(SAMPLES / "hashes.py"), "--cbom", str(tmp_path / "no" / "such" / "dir" / "x.json")])
    assert e.value.code == 2
    assert "can't write CBOM" in capsys.readouterr().err
