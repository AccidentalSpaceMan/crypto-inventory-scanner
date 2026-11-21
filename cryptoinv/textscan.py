"""Shared machinery for scanning languages Python has no built-in parser for (Java, JavaScript).

The idea, in two steps:

1. **Mask.** Make a copy of the file with comments blanked out, and a second copy with the inside
   of every string blanked too. Each blanked character becomes a space, so every offset and line
   number stays the same as the original. Searching the masked copy means a comment or string
   that merely *mentions* "MD5" can never match.
2. **Match.** Find crypto calls in the masked copy with regular expressions, then read the real
   string arguments from the comment-free copy at the same positions.
"""
from __future__ import annotations

import bisect
import re

from .rules import Rules
from .scanner import SECRET_WORDS, Finding, _words

IDENT = r"[A-Za-z_$][\w$]*"
STRING = r"(?:\"[^\"\n]*\"|'[^'\n]*'|`[^`]*`)"
INT_OR_NAME = rf"(\d[\d_]*|{IDENT})"
_TYPE = r"(?:\s*:\s*[\w$<>\[\]|.]+)?"   # optional TypeScript annotation: const ALG: string = ...
STRING_CONST = re.compile(rf"(?<![\w$.])({IDENT}){_TYPE}\s*=\s*({STRING})\s*(?=[;,)\n])")
INT_CONST = re.compile(rf"(?<![\w$.])({IDENT}){_TYPE}\s*=\s*(\d[\d_]*)\s*(?=[;,)\n])")

# After one of these, a "/" in JavaScript starts a regex literal rather than meaning "divide".
_REGEX_AFTER_CHARS = set("(,=:[!&|?{};+-*%<>~^")
_REGEX_AFTER_WORDS = {"return", "typeof", "case", "do", "else", "in", "of", "new", "delete",
                      "void", "throw", "yield", "await"}


def mask(source: str, js: bool = False) -> tuple[str, str]:
    """Return (source without comments, source without comments or string contents).

    Both keep exactly the same length and line breaks as the original. With js=True, backtick
    template strings and regex literals (/.../) are treated as strings too.
    """
    no_comments, masked = list(source), list(source)
    n, i = len(source), 0
    last_char, last_word = "", ""   # what came before, to tell a regex "/" from division

    def blank(chars, start, end):
        for k in range(start, end):
            if chars[k] != "\n":
                chars[k] = " "

    while i < n:
        c = source[i]
        if source.startswith("//", i):
            end = source.find("\n", i)
            end = n if end < 0 else end
            blank(no_comments, i, end), blank(masked, i, end)
            i = end
        elif source.startswith("/*", i):
            end = source.find("*/", i + 2)
            end = n if end < 0 else end + 2
            blank(no_comments, i, end), blank(masked, i, end)
            i = end
        elif not js and source.startswith('"""', i):            # Java text block
            end = source.find('"""', i + 3)
            end = n if end < 0 else end
            blank(masked, i + 3, end)
            i, last_char = end + 3, '"'
        elif c in "\"'" or (js and c == "`"):                   # string (or Java char literal)
            j = i + 1
            while j < n and source[j] != c and (c == "`" or source[j] != "\n"):
                j += 2 if source[j] == "\\" else 1
            j = min(j, n)
            blank(masked, i + 1, j)
            i, last_char = j + 1, c
        elif js and c == "/" and (last_char == "" or last_char in _REGEX_AFTER_CHARS
                                  or (last_word in _REGEX_AFTER_WORDS and last_char == last_word[-1:])):
            j, in_class = i + 1, False                          # regex literal /.../flags
            while j < n and source[j] != "\n":
                if source[j] == "\\":
                    j += 2
                    continue
                if source[j] == "[":
                    in_class = True
                elif source[j] == "]":
                    in_class = False
                elif source[j] == "/" and not in_class:
                    break
                j += 1
            j = min(j, n)
            blank(masked, i + 1, j)
            i, last_char = j + 1, "/"
        elif c.isalnum() or c in "_$":
            j = i
            while j < n and (source[j].isalnum() or source[j] in "_$"):
                j += 1
            last_word, last_char = source[i:j], source[j - 1]
            i = j
        else:
            if not c.isspace():
                last_char = c
            i += 1
    return "".join(no_comments), "".join(masked)


def split_args(text: str, open_paren: int) -> list[tuple[int, int]]:
    """Spans of the top-level arguments of the call whose "(" is at open_paren."""
    depth, start, spans = 0, open_paren + 1, []
    for i in range(open_paren, len(text)):
        c = text[i]
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
            if depth == 0:
                if text[start:i].strip():
                    spans.append((start, i))
                return spans
        elif c == "," and depth == 1:
            spans.append((start, i))
            start = i + 1
    return spans


def closing_paren(text: str, open_paren: int) -> int | None:
    """Offset of the ")" matching the "(" at open_paren, or None."""
    depth = 0
    for i in range(open_paren, len(text)):
        if text[i] in "([{":
            depth += 1
        elif text[i] in ")]}":
            depth -= 1
            if depth == 0:
                return i
    return None


def enclosing_braces(text: str, offset: int) -> tuple[int, int] | None:
    """Span of the innermost {...} around offset, or None."""
    depth = 0
    for i in range(offset - 1, -1, -1):
        if text[i] == "}":
            depth += 1
        elif text[i] == "{":
            if depth == 0:
                start = i
                break
            depth -= 1
    else:
        return None
    depth = 0
    for j in range(start, len(text)):
        if text[j] == "{":
            depth += 1
        elif text[j] == "}":
            depth -= 1
            if depth == 0:
                return start, j + 1
    return start, len(text)


class TextScanner:
    """Base class: masking, line numbers, constants, reporting and secret-context checks."""
    js = False

    def __init__(self, rules: Rules, path: str, source: str):
        self.rules, self.path = rules, path
        self.text, self.masked = mask(source, js=self.js)
        self.lines = source.splitlines()
        self.line_starts = [0] + [m.end() for m in re.finditer("\n", source)]
        self.findings: list[Finding] = []
        self._seen: set[tuple[int, str]] = set()
        self.strings = {m.group(1): self.literal(m.span(2)) for m in STRING_CONST.finditer(self.masked)}
        self.ints = {m.group(1): int(m.group(2).replace("_", "")) for m in INT_CONST.finditer(self.masked)}
        self.functions = sorted(self.function_names())

    def function_names(self) -> list[tuple[int, str]]:
        """(offset, name) of each function/method declaration, for secret-context checks."""
        return []

    def line_of(self, offset: int) -> int:
        return bisect.bisect_right(self.line_starts, offset)

    def literal(self, span: tuple[int, int]) -> str:
        """A string literal's real contents (from the comment-free text), by its span."""
        return self.text[span[0] + 1:span[1] - 1]

    def string_value(self, token: str, span: tuple[int, int]) -> str | None:
        """A string literal, or the name of a string constant defined in this file."""
        token = token.strip()
        if token[:1] in ("\"", "'", "`"):
            start = span[0] + (len(self.masked[span[0]:span[1]]) - len(self.masked[span[0]:span[1]].lstrip()))
            return self.literal((start, start + len(token)))
        return self.strings.get(token.rsplit(".", 1)[-1])

    def arg_string(self, span: tuple[int, int]) -> str | None:
        """The string value of a call argument, if it is a literal or a known constant."""
        token = self.masked[span[0]:span[1]].strip()
        if re.fullmatch(rf"{STRING}|{IDENT}(?:\.{IDENT})*", token):
            return self.string_value(token, span)
        return None

    def int_value(self, token: str) -> int | None:
        token = token.strip()
        if token[:1].isdigit():
            try:
                return int(token.replace("_", ""))
            except ValueError:
                return None
        return self.ints.get(token)

    def arg_int(self, span: tuple[int, int]) -> int | None:
        token = self.masked[span[0]:span[1]].strip()
        return self.int_value(token) if re.fullmatch(INT_OR_NAME, token) else None

    def report(self, offset: int, alg_id: str, symbol: str, detail: str = "") -> None:
        line = self.line_of(offset)
        if (line, alg_id) in self._seen:
            return
        self._seen.add((line, alg_id))
        code = self.lines[line - 1].strip() if line <= len(self.lines) else ""
        self.findings.append(Finding(self.path, line, self.rules.algorithms[alg_id], symbol, detail, code))

    def in_secret_context(self, offset: int) -> bool:
        """Do the names on this line, or the enclosing function's name, sound like a secret?"""
        line = self.line_of(offset)
        start = self.line_starts[line - 1]
        end = self.line_starts[line] if line < len(self.line_starts) else len(self.masked)
        names = re.findall(IDENT, self.masked[start:end])
        i = bisect.bisect_right(self.functions, (offset, "￿")) - 1
        if i >= 0:
            names.append(self.functions[i][1])
        return any(w in SECRET_WORDS for n in names for w in _words(n))

    def sorted_findings(self) -> list[Finding]:
        return sorted(self.findings, key=lambda f: (f.line, f.algorithm.id))
