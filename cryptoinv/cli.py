"""Command-line interface: python -m cryptoinv scan PATH"""
from __future__ import annotations

import argparse
import os
import sys

from .cbom import write_cbom
from .report import render
from .rules import GRADES, RulesError, load_rules
from .sarif import write_sarif
from .scanner import scan_path

_WHAT = "code (Python, Java, JavaScript, TypeScript, Go) and certificate/key files"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cryptoinv",
        description=f"Inventory the cryptography in {_WHAT} and grade each algorithm "
                    "BROKEN / LEGACY / CURRENT. The scanner reads files; it never runs code.")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help=f"scan {_WHAT}",
                          description=f"Scan {_WHAT}. Only scan code you own or have permission "
                                      "to scan. Add the comment 'cryptoinv: ignore' to a line to "
                                      "leave its findings out.")
    scan.add_argument("path", help="file or folder to scan")
    scan.add_argument("--exclude", metavar="PATTERN", action="append", default=[],
                      help="skip files or folders matching this pattern, relative to PATH "
                           "(e.g. tests, 'tests/*', '*.min.js'); can be repeated")
    scan.add_argument("--rules", metavar="FILE",
                      help="use a different grading rules file (default: the built-in rules.json)")
    scan.add_argument("--fail-on", choices=["broken", "legacy"],
                      help="exit with code 1 if anything this bad or worse is found (useful in CI)")
    scan.add_argument("--cbom", metavar="FILE",
                      help="also write a CycloneDX 1.6 CBOM (cryptographic bill of materials) "
                           "as JSON to FILE")
    scan.add_argument("--sarif", metavar="FILE",
                      help="also write SARIF 2.1.0 to FILE, e.g. for GitHub code scanning")
    scan.add_argument("--sarif-min-grade", choices=["broken", "legacy", "current"], default="legacy",
                      help="least severe grade to include in the SARIF file (default: legacy)")
    scan.add_argument("--no-color", action="store_true", help="plain text output")
    return parser


def _enable_windows_colors() -> None:
    """Older Windows consoles need to be told to understand color codes."""
    if os.name != "nt":
        return
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11)  # standard output
        mode = ctypes.c_uint32()
        if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            kernel32.SetConsoleMode(handle, mode.value | 0x0004)  # ENABLE_VIRTUAL_TERMINAL_PROCESSING
    except Exception:
        pass


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        rules = load_rules(args.rules)
    except RulesError as e:
        parser.error(str(e))
    try:
        result = scan_path(args.path, rules, exclude=args.exclude)
    except FileNotFoundError:
        parser.error(f"{args.path} does not exist")

    # Scanned code can contain any characters; never crash printing one the console can't show.
    try:
        sys.stdout.reconfigure(errors="replace")
    except (AttributeError, ValueError):
        pass
    color = not args.no_color and "NO_COLOR" not in os.environ and sys.stdout.isatty()
    if color:
        _enable_windows_colors()
    print(render(result, color=color))

    if args.cbom:
        try:
            cbom = write_cbom(result, args.cbom)
        except OSError as e:
            parser.error(f"can't write CBOM to {args.cbom}: {e.strerror or e}")
        print(f"\nWrote CBOM ({len(cbom['components'])} cryptographic assets, "
              f"CycloneDX {cbom['specVersion']}) to {args.cbom}")

    if args.sarif:
        try:
            sarif = write_sarif(result, args.sarif, args.sarif_min_grade)
        except OSError as e:
            parser.error(f"can't write SARIF to {args.sarif}: {e.strerror or e}")
        run = sarif["runs"][0]
        print(f"\nWrote SARIF ({len(run['results'])} results for {len(run['tool']['driver']['rules'])} "
              f"rules, {args.sarif_min_grade.upper()} and worse) to {args.sarif}")

    if args.fail_on:
        limit = GRADES.index(args.fail_on.upper())
        if any(GRADES.index(f.grade) <= limit for f in result.findings):
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
