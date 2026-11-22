"""Compare two CBOMs: what cryptography got better or worse between two scans.

One scan is a snapshot, like a single report card. Moving to quantum-safe crypto takes months, so
teams need to see the trend: which weak algorithms are gone, which crept back in, and whether the
count of quantum-vulnerable places is going down. This module reads two CBOM files (written by
`cryptoinv scan --cbom`) and lines them up.

It compares algorithms, not exact lines. Editing a file shifts line numbers, so a line-by-line
comparison would report noise. Instead, for each algorithm it compares how many places use it and
which files they're in.

What counts as worse: a BROKEN or LEGACY algorithm that's new, used in more places, or regraded to
a worse grade. Better is the opposite. Changes to CURRENT algorithms are listed but are neither.
(Every quantum-vulnerable algorithm is graded LEGACY or BROKEN, so quantum risk is covered.)
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from .rules import GRADES

_BAD = ("BROKEN", "LEGACY")


class CbomError(ValueError):
    """The file isn't a CBOM we can read."""


@dataclass
class Asset:
    """One algorithm, protocol or certificate as recorded in a CBOM."""
    key: str
    name: str
    kind: str                       # "algorithm", "protocol" or "certificate"
    grade: str | None = None        # None if the CBOM didn't come from cryptoinv
    quantum_vulnerable: bool = False
    files: dict[str, int] = field(default_factory=dict)   # file -> number of places in it

    @property
    def places(self) -> int:
        return sum(self.files.values())


@dataclass
class Cbom:
    path: str
    app: str
    timestamp: str
    files_scanned: str
    assets: dict[str, Asset]


@dataclass
class Change:
    """How one asset differs between the old and new CBOM. old or new is None if it's absent."""
    old: Asset | None
    new: Asset | None

    @property
    def asset(self) -> Asset:
        return self.new or self.old

    @property
    def effect(self) -> str:
        """'worse', 'better' or 'other'."""
        old, new = self.old, self.new
        if old and new and old.grade != new.grade and old.grade in GRADES and new.grade in GRADES:
            return "worse" if GRADES.index(new.grade) < GRADES.index(old.grade) else "better"
        if self.asset.grade not in _BAD:
            return "other"
        if new and (not old or new.places > old.places):
            return "worse"
        if old and (not new or new.places < old.places):
            return "better"
        return "other"


@dataclass
class CbomDiff:
    old: Cbom
    new: Cbom
    changes: list[Change]           # only assets that differ in some way

    def by_effect(self, effect: str) -> list[Change]:
        return [c for c in self.changes if c.effect == effect]

    @property
    def verdict(self) -> str:
        worse, better = self.by_effect("worse"), self.by_effect("better")
        if worse and better:
            return "MIXED"
        if worse:
            return "WORSE"
        if better:
            return "BETTER"
        return "NO CHANGE" if not self.changes else "SAME RISK"


def _prop(component: dict, name: str) -> str | None:
    for p in component.get("properties") or []:
        if p.get("name") == name:
            return p.get("value")
    return None


def _asset(component: dict) -> Asset | None:
    crypto = component.get("cryptoProperties") or {}
    asset_type = crypto.get("assetType")
    files: dict[str, int] = {}
    for occ in (component.get("evidence") or {}).get("occurrences") or []:
        location = occ.get("location", "?")
        files[location] = files.get(location, 0) + 1

    if asset_type == "certificate":
        cert = crypto.get("certificateProperties") or {}
        subject = cert.get("subjectName") or component.get("name", "?")
        # The same certificate keeps its subject, issuer and expiry even if the file moves.
        key = f"certificate:{subject}|{cert.get('issuerName')}|{cert.get('notValidAfter')}"
        return Asset(key, subject, "certificate", files=files)
    if asset_type not in ("algorithm", "protocol"):
        return None

    grade = _prop(component, "cryptoinv:grade")
    quantum = _prop(component, "cryptoinv:quantumVulnerable")
    if quantum is None:     # CBOMs from other tools: NIST level 0 means no quantum security
        quantum = str((crypto.get("algorithmProperties") or {}).get("nistQuantumSecurityLevel") == 0)
    key = _prop(component, "cryptoinv:id") or component.get("bom-ref") or component.get("name", "?")
    return Asset(key, component.get("name", key), asset_type,
                 grade if grade in GRADES else None, quantum.lower() == "true", files)


def load_cbom(path: str | Path) -> Cbom:
    """Read a CycloneDX CBOM. Raises FileNotFoundError or CbomError."""
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as e:
        raise CbomError(f"{path} isn't a readable JSON file ({e})") from None
    if not isinstance(data, dict) or data.get("bomFormat") != "CycloneDX":
        raise CbomError(f"{path} isn't a CycloneDX file (no \"bomFormat\": \"CycloneDX\")")

    assets: dict[str, Asset] = {}
    for component in data.get("components") or []:
        if isinstance(component, dict) and component.get("type") == "cryptographic-asset":
            asset = _asset(component)
            if asset:
                assets[asset.key] = asset
    metadata = data.get("metadata") or {}
    return Cbom(str(path), (metadata.get("component") or {}).get("name", "?"),
                metadata.get("timestamp", "unknown time"),
                _prop(metadata, "cryptoinv:filesScanned") or "?", assets)


def compare(old: Cbom, new: Cbom) -> CbomDiff:
    changes = []
    for key in list(old.assets) + [k for k in new.assets if k not in old.assets]:
        a, b = old.assets.get(key), new.assets.get(key)
        if a and b and a.files == b.files and a.grade == b.grade:
            continue
        changes.append(Change(a, b))
    order = {g: i for i, g in enumerate(GRADES)}
    changes.sort(key=lambda c: (order.get(c.asset.grade, len(GRADES)), c.asset.name.lower()))
    return CbomDiff(old, new, changes)


def diff_files(old_path: str | Path, new_path: str | Path) -> CbomDiff:
    return compare(load_cbom(old_path), load_cbom(new_path))


# ----- terminal report -----

_COLORS = {"worse": "\033[31m", "better": "\033[32m", "quantum": "\033[35m",
           "bold": "\033[1m", "dim": "\033[2m"}
_RESET = "\033[0m"
_HEADINGS = {"worse": "Worse - new or growing BROKEN / LEGACY crypto",
             "better": "Better - BROKEN / LEGACY crypto removed or shrinking",
             "other": "Other changes (CURRENT crypto, certificates, moved code)"}


def _plural(n: int, word: str) -> str:
    return f"{n} {word}{'s' if n != 1 else ''}"


def _files(names) -> str:
    names = sorted(names)
    shown = ", ".join(names[:5])
    return shown + (f" and {len(names) - 5} more" if len(names) > 5 else "")


def _describe(change: Change, paint) -> list[str]:
    old, new = change.old, change.new
    asset = change.asset
    label = asset.name
    if asset.grade:
        label += f" ({asset.grade})"
    if asset.quantum_vulnerable:
        label += paint("quantum", " [quantum-vulnerable]")

    if not old:
        lines = [f"  + {label}  new: {_plural(new.places, 'place')}",
                 f"      in: {_files(new.files)}"]
    elif not new:
        lines = [f"  - {label}  gone (was {_plural(old.places, 'place')})"]
    else:
        arrow = "^" if new.places > old.places else "v" if new.places < old.places else "="
        lines = [f"  {arrow} {label}  {old.places} -> {_plural(new.places, 'place')}"]
        if old.grade != new.grade:
            lines.append(f"      regraded {old.grade} -> {new.grade} (the grading rules changed)")
        added = set(new.files) - set(old.files)
        gone = set(old.files) - set(new.files)
        if added:
            lines.append(f"      now also in: {_files(added)}")
        if gone:
            lines.append(f"      no longer in: {_files(gone)}")
    return lines


def _totals(cbom: Cbom, grade: str) -> tuple[int, int]:
    assets = [a for a in cbom.assets.values() if a.grade == grade]
    return len(assets), sum(a.places for a in assets)


def render_diff(diff: CbomDiff, color: bool = False) -> str:
    def paint(style: str, text: str) -> str:
        return f"{_COLORS[style]}{text}{_RESET}" if color else text

    out = [paint("bold", f"Crypto inventory changes: {diff.old.path} -> {diff.new.path}")]
    for label, cbom in (("old", diff.old), ("new", diff.new)):
        out.append(f"  {label}: {cbom.app}, scanned {cbom.timestamp}, {cbom.files_scanned} file(s)")

    if not diff.changes:
        out.append("\nNo changes: the same cryptography is used in the same files.")
    for effect in ("worse", "better", "other"):
        changes = diff.by_effect(effect)
        if not changes:
            continue
        heading = _HEADINGS[effect]
        out += ["", paint(effect, paint("bold", heading)) if effect != "other" else paint("bold", heading)]
        for change in changes:
            out += _describe(change, paint)

    parts = []
    for grade in GRADES:
        (a1, p1), (a2, p2) = _totals(diff.old, grade), _totals(diff.new, grade)
        parts.append(f"{grade} {a1} -> {_plural(a2, 'algorithm')} ({p1} -> {_plural(p2, 'place')})")
    q1 = sum(a.places for a in diff.old.assets.values() if a.quantum_vulnerable)
    q2 = sum(a.places for a in diff.new.assets.values() if a.quantum_vulnerable)
    parts.append(f"quantum-vulnerable {q1} -> {_plural(q2, 'place')}")
    worse, better = len(diff.by_effect("worse")), len(diff.by_effect("better"))
    style = {"WORSE": "worse", "BETTER": "better"}.get(diff.verdict, "bold")
    out += ["", "Summary: " + " | ".join(parts),
            paint(style, f"Verdict: {diff.verdict}") +
            f" ({_plural(worse, 'thing')} worse, {_plural(better, 'thing')} better)"]
    return "\n".join(out)
