"""Write scan results as a CycloneDX 1.6 CBOM (cryptographic bill of materials).

A software bill of materials (SBOM) is an ingredients list for software: every library it
contains. A CBOM does the same for cryptography: every algorithm and protocol, and where each one
is used. CycloneDX is a widely used open standard for these lists (an OWASP project). Version 1.6
added the "cryptographic-asset" component type that a CBOM is built from. Because it's a
standard, other tools (dashboards, compliance checkers, migration planners) can read our output
without knowing anything about this scanner.

Each algorithm found becomes one component. Every place it was found becomes an "occurrence" in
that component's evidence. Our BROKEN / LEGACY / CURRENT grade and the why/fix advice aren't
part of the standard, so they go in namespaced "cryptoinv:" properties, which CycloneDX allows.
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .rules import Algorithm
from .scanner import Finding, ScanResult

SPEC_VERSION = "1.6"
TOOL_NAME = "crypto-inventory-scanner"
APP_REF = "application"


def _component(alg: Algorithm, findings: list[Finding]) -> dict:
    if alg.primitive == "protocol":
        crypto = {"assetType": "protocol", "protocolProperties": {"type": "tls"}}
    else:
        props: dict = {"primitive": alg.primitive}
        if alg.mode:
            props["mode"] = alg.mode
        if alg.quantum_vulnerable:
            # Level 0 = no security against a quantum computer (Shor's algorithm breaks it).
            props["nistQuantumSecurityLevel"] = 0
        crypto = {"assetType": "algorithm", "algorithmProperties": props}

    occurrences = []
    for f in findings:
        context = f"{f.code}  [{f.detail}]" if f.detail else f.code
        occurrences.append({"location": f.path, "line": f.line, "symbol": f.symbol,
                            "additionalContext": context})

    properties = [
        {"name": "cryptoinv:id", "value": alg.id},
        {"name": "cryptoinv:grade", "value": alg.grade},
        {"name": "cryptoinv:quantumVulnerable", "value": str(alg.quantum_vulnerable).lower()},
        {"name": "cryptoinv:why", "value": alg.why},
    ]
    if alg.fix:
        properties.append({"name": "cryptoinv:fix", "value": alg.fix})
    if alg.pq_partner:
        properties.append({"name": "cryptoinv:postQuantumReplacement", "value": alg.pq_partner})

    return {
        "type": "cryptographic-asset",
        "bom-ref": f"crypto:{alg.id}",
        "name": alg.name,
        "cryptoProperties": crypto,
        "evidence": {"occurrences": occurrences},
        "properties": properties,
    }


def build_cbom(result: ScanResult, *, timestamp: str | None = None,
               serial_number: str | None = None) -> dict:
    """Build the CBOM as a plain dict (ready for json.dump)."""
    timestamp = timestamp or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    serial_number = serial_number or f"urn:uuid:{uuid.uuid4()}"

    by_alg: dict[str, list[Finding]] = {}
    algorithms: dict[str, Algorithm] = {}
    for f in result.findings:
        by_alg.setdefault(f.algorithm.id, []).append(f)
        algorithms[f.algorithm.id] = f.algorithm
    # Worst grade first, then by name: the same order as the terminal report.
    order = {"BROKEN": 0, "LEGACY": 1, "CURRENT": 2}
    ids = sorted(algorithms, key=lambda i: (order[algorithms[i].grade], algorithms[i].name))
    components = [_component(algorithms[i], by_alg[i]) for i in ids]

    app_name = Path(result.root).resolve().name or result.root
    metadata_props = [
        {"name": "cryptoinv:rulesVersion", "value": result.rules.version if result.rules else "unknown"},
        {"name": "cryptoinv:filesScanned", "value": str(result.files_scanned)},
    ]
    metadata_props += [{"name": "cryptoinv:skippedFile", "value": f"{path}: {why}"}
                       for path, why in result.errors]

    return {
        "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": SPEC_VERSION,
        "serialNumber": serial_number,
        "version": 1,
        "metadata": {
            "timestamp": timestamp,
            "tools": {"components": [{"type": "application", "name": TOOL_NAME,
                                      "version": __version__}]},
            "component": {"type": "application", "bom-ref": APP_REF, "name": app_name},
            "properties": metadata_props,
        },
        "components": components,
        # "The scanned application depends on these cryptographic assets."
        "dependencies": [{"ref": APP_REF, "dependsOn": [c["bom-ref"] for c in components]}],
    }


def write_cbom(result: ScanResult, path: str | Path) -> dict:
    """Build the CBOM and write it to a JSON file. Returns the CBOM dict."""
    cbom = build_cbom(result)
    Path(path).write_text(json.dumps(cbom, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return cbom
