"""Command-line interface: python -m cryptoinv scan PATH"""
from __future__ import annotations

import argparse
import os
import sys

from .cbom import write_cbom
from .report import render
from .rules import GRADES, RulesError, load_rules
from .scanner import scan_path


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cryptoinv",
        description="Inventory the cryptography a Python, Java, JavaScript or TypeScript codebase uses and grade each algorithm "
                    "BROKEN / LEGACY / CURRENT. The scanner reads code; it never runs it.")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="scan a file or folder of Python, Java, JavaScript or TypeScript code",
                          description="Scan a file or folder of Python, Java, JavaScript or TypeScript code. Only scan code you own or "
                                      "have permission to scan.")
    scan.add_argument("path", help="file or folder to scan")
    scan.add_argument("--rules", metavar="FILE",
                      help="use a different grading rules file (default: the built-in rules.json)")
    scan.add_argument("--fail-on", choices=["broken", "legacy"],
                      help="exit with code 1 if anything this bad or worse is found (useful in CI)")
    scan.add_argument("--cbom", metavar="FILE",
                      help="also write a CycloneDX 1.6 CBOM (cryptographic bill of materials) "
                           "as JSON to FILE")
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
        result = scan_path(args.path, rules)
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

    if args.fail_on:
        limit = GRADES.index(args.fail_on.upper())
        if any(GRADES.index(f.grade) <= limit for f in result.findings):
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
