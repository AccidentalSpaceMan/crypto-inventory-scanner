"""Write scan results as SARIF 2.1.0, the standard format for static-analysis findings.

SARIF (Static Analysis Results Interchange Format) is an OASIS standard that GitHub, GitLab, Azure
DevOps and many IDEs read. Uploading a SARIF file to GitHub code scanning puts each finding in the
repository's Security tab and as a warning on the exact line of a pull request, so weak crypto
is caught while code is being reviewed, not months later.

How the inventory maps onto SARIF:
- each algorithm becomes a *rule*, with the why/fix advice as its help text;
- each place it was found becomes a *result* at that file and line;
- BROKEN -> "error", LEGACY -> "warning", CURRENT -> "note" (CURRENT is left out by default:
  it's fine, and listing it in a security tab would only be noise);
- each rule gets a "security-severity" score that GitHub turns into Critical/High/Medium/Low.
"""
from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import quote

from . import __version__
from .rules import GRADES, Algorithm
from .scanner import Finding, ScanResult

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
INFORMATION_URI = "https://github.com/AccidentalSpaceMan/crypto-inventory-scanner"
LEVELS = {"BROKEN": "error", "LEGACY": "warning", "CURRENT": "note"}
# GitHub reads this 0.0-10.0 score: 7.0+ is High, 4.0-6.9 Medium, 0.1-3.9 Low.
SEVERITY = {"BROKEN": "8.0", "LEGACY": "5.0", "CURRENT": "1.0"}


def _rule(alg: Algorithm) -> dict:
    tags = ["security", "cryptography", alg.primitive]
    if alg.quantum_vulnerable:
        tags.append("quantum-vulnerable")
    help_text = alg.why + (f" Fix: {alg.fix}" if alg.fix else "")
    help_md = f"**{alg.grade}**: {alg.why}" + (f"\n\n**Fix:** {alg.fix}" if alg.fix else "")
    if alg.quantum_vulnerable:
        help_md += "\n\n*Quantum-vulnerable: broken by Shor's algorithm on a large quantum computer.*"
    return {
        "id": f"crypto/{alg.id}",
        "name": alg.id.title().replace("_", ""),
        "shortDescription": {"text": f"{alg.name} ({alg.grade})"},
        "fullDescription": {"text": alg.why},
        "help": {"text": help_text, "markdown": help_md},
        "defaultConfiguration": {"level": LEVELS[alg.grade]},
        "properties": {"tags": tags, "security-severity": SEVERITY[alg.grade], "precision": "high"},
    }


def _result(f: Finding, rule_index: int) -> dict:
    alg = f.algorithm
    text = f"{alg.name} ({alg.grade}"
    text += ", quantum-vulnerable)" if alg.quantum_vulnerable else ")"
    text += f" found as `{f.symbol}`"
    if f.detail:
        text += f" [{f.detail}]"
    text += f". {alg.why}"
    if alg.fix:
        text += f" Fix: {alg.fix}"
    return {
        "ruleId": f"crypto/{alg.id}",
        "ruleIndex": rule_index,
        "level": LEVELS[alg.grade],
        "message": {"text": text},
        "locations": [{"physicalLocation": {
            "artifactLocation": {"uri": quote(f.path)},
            "region": {"startLine": max(f.line, 1)},
        }}],
    }


def build_sarif(result: ScanResult, min_grade: str = "LEGACY") -> dict:
    """Build a SARIF log. Findings less severe than min_grade are left out."""
    keep = set(GRADES[:GRADES.index(min_grade.upper()) + 1])
    findings = [f for f in result.findings if f.grade in keep]
    algorithms: dict[str, Algorithm] = {}
    for f in findings:
        algorithms.setdefault(f.algorithm.id, f.algorithm)
    order = sorted(algorithms.values(), key=lambda a: (GRADES.index(a.grade), a.name))
    index = {alg.id: i for i, alg in enumerate(order)}
    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "crypto-inventory-scanner",
                "version": __version__,
                "informationUri": INFORMATION_URI,
                "rules": [_rule(alg) for alg in order],
            }},
            "results": [_result(f, index[f.algorithm.id]) for f in findings],
            "properties": {"filesScanned": result.files_scanned,
                           "rulesVersion": result.rules.version if result.rules else "unknown"},
        }],
    }


def write_sarif(result: ScanResult, path: str | Path, min_grade: str = "LEGACY") -> dict:
    sarif = build_sarif(result, min_grade)
    Path(path).write_text(json.dumps(sarif, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return sarif
