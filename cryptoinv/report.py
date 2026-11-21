"""Turn scan results into a human-readable terminal report."""
from __future__ import annotations

import textwrap

from .rules import GRADES
from .scanner import Finding, ScanResult

GRADE_HEADINGS = {
    "BROKEN": "BROKEN - fix now",
    "LEGACY": "LEGACY - works today, plan a migration",
    "CURRENT": "CURRENT - fine today",
}
_COLORS = {"BROKEN": "\033[31m", "LEGACY": "\033[33m", "CURRENT": "\033[32m",
           "quantum": "\033[35m", "bold": "\033[1m", "dim": "\033[2m"}
_RESET = "\033[0m"
_CODE_WIDTH = 70


def render(result: ScanResult, color: bool = False) -> str:
    """Build the full report as one string."""
    def paint(style: str, text: str) -> str:
        return f"{_COLORS[style]}{text}{_RESET}" if color else text

    out = [paint("bold", f"Crypto inventory: {result.root}"),
           f"{result.files_scanned} Python file(s) scanned, {len(result.findings)} finding(s)"]
    if result.errors:
        out.append(f"Skipped {len(result.errors)} file(s) that couldn't be parsed:")
        out += [f"  {path}: {why}" for path, why in result.errors]
    if not result.findings:
        out.append("\nNo cryptography found.")
        return "\n".join(out)

    by_alg: dict[str, list[Finding]] = {}
    for f in result.findings:
        by_alg.setdefault(f.algorithm.id, []).append(f)
    algorithms = {f.algorithm.id: f.algorithm for f in result.findings}

    for grade in GRADES:
        in_grade = sorted((a for a in algorithms.values() if a.grade == grade), key=lambda a: a.name)
        if not in_grade:
            continue
        out += ["", paint(grade, paint("bold", GRADE_HEADINGS[grade]))]
        for alg in in_grade:
            places = by_alg[alg.id]
            quantum = paint("quantum", "  [quantum-vulnerable]") if alg.quantum_vulnerable else ""
            count = f"{len(places)} place{'s' if len(places) != 1 else ''}"
            out.append(f"  {paint(grade, alg.name)} ({alg.primitive}){quantum}  - {count}")
            out += _wrap("why: ", alg.why)
            if alg.fix:
                out += _wrap("fix: ", alg.fix)
            width = max(len(f"{f.path}:{f.line}") for f in places)
            for f in places:
                code = f.code if len(f.code) <= _CODE_WIDTH else f.code[:_CODE_WIDTH - 3] + "..."
                detail = f"  [{f.detail}]" if f.detail else ""
                out.append(f"      {f'{f.path}:{f.line}':<{width}}  {paint('dim', code)}{detail}")

    out += ["", *_quantum_section(algorithms, by_alg, paint, result.rules), "",
            _summary(algorithms, by_alg)]
    return "\n".join(out)


def _wrap(label: str, text: str) -> list[str]:
    return textwrap.wrap(text, width=100, initial_indent="      " + label,
                         subsequent_indent="      " + " " * len(label))


def _quantum_section(algorithms, by_alg, paint, rules) -> list[str]:
    """Which quantum-vulnerable algorithms are used, and is their post-quantum partner present?"""
    lines = [paint("bold", "Quantum readiness")]
    vulnerable = sorted((a for a in algorithms.values() if a.quantum_vulnerable), key=lambda a: a.name)
    if not vulnerable:
        lines.append("  No quantum-vulnerable public-key crypto found.")
        return lines
    for alg in vulnerable:
        partner_id = alg.pq_partner
        if partner_id and partner_id in by_alg:
            partner = algorithms[partner_id]
            files = sorted({f.path for f in by_alg[partner_id]})
            text = (f"{alg.name}: {partner.name} is also used ({', '.join(files)}). "
                    "Possibly a hybrid: check that the two are combined.")
        elif partner_id:
            partner_name = rules.algorithms[partner_id].name if rules else partner_id
            text = f"{alg.name}: no {partner_name} found yet. Plan a move to it, usually as a hybrid first."
        else:
            text = f"{alg.name}: quantum-vulnerable. Plan a post-quantum replacement."
        lines += textwrap.wrap(text, width=100, initial_indent="  ", subsequent_indent="    ")
    return lines


def _summary(algorithms, by_alg) -> str:
    parts = []
    for grade in GRADES:
        ids = [a.id for a in algorithms.values() if a.grade == grade]
        places = sum(len(by_alg[i]) for i in ids)
        part = f"{grade} {len(ids)} algorithm{'s' if len(ids) != 1 else ''} ({places} place{'s' if places != 1 else ''})"
        if grade != "CURRENT":
            q = sum(1 for i in ids if algorithms[i].quantum_vulnerable)
            if q:
                part += f", {q} quantum-vulnerable"
        parts.append(part)
    return "Summary: " + " | ".join(parts)
