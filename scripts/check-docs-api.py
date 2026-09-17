#!/usr/bin/env python3
"""Check that the client calls in the documentation name real methods with the
right number of arguments.

The guides are prose, not compiled, so nothing else notices when they drift.
Before this existed they had accumulated 48 call sites naming methods that were
never written, plus two calls with the wrong arity, and the drift was only
found by hand.

What is checked, for every `l.X(...)`, `client.X(...)` and `ldapClient.X(...)`
call in docs/*.md and README.md:

  1. X is a real exported method on *LDAP, per `go doc -all`.
  2. The call passes a number of arguments the signature accepts.

A symbol a document defines in its own snippets is exempt only when it is not
a real method: a guide may write `func (l *LDAP) StreamUsers(...)` as an
illustration and call it two lines later, which is self-consistent rather than
drift. When the name *is* a real method, the calls are checked against the real
signature — a guide that redefines a real method with different parameters is
itself drift, and exempting it hides exactly the arity defects this catches.

Usage:  python3 scripts/check-docs-api.py [--verbose]
Exit:   0 clean, 1 findings, 2 could not run (e.g. `go doc` failed).
"""

from __future__ import annotations

import pathlib
import re
import subprocess
import sys

RECEIVERS = r"l|client|ldapClient"
CALL = re.compile(
    rf"\b(?:{RECEIVERS})\.([A-Z][A-Za-z0-9]{{2,}})\(([^()]*(?:\([^()]*\)[^()]*)*)\)"
)
SIGNATURE = re.compile(
    r"^func \(l \*LDAP\) ([A-Z][A-Za-z0-9]*)\((.*?)\)(?: |$)", re.MULTILINE
)
SELF_DEFINED = (
    re.compile(r"func \(\w+ \*LDAP\) ([A-Z][A-Za-z0-9]*)"),
    re.compile(r"func ([A-Z][A-Za-z0-9]*)\("),
)
UNBOUNDED = 10**6


def split_top_level(text: str) -> list[str]:
    """Split on commas that are not inside brackets or a string literal.

    Naive splitting counts the commas in "cn=a,dc=b,dc=c" as argument
    separators and reports arity mismatches that are not there.
    """
    parts: list[str] = []
    current = ""
    depth = 0
    quote = ""
    i = 0
    while i < len(text):
        char = text[i]
        if quote:
            current += char
            if char == "\\" and i + 1 < len(text):
                current += text[i + 1]
                i += 2
                continue
            if char == quote:
                quote = ""
            i += 1
            continue
        if char in "\"'`":
            quote = char
            current += char
            i += 1
            continue
        if char in "([{":
            depth += 1
        elif char in ")]}":
            depth -= 1
        if char == "," and depth == 0:
            parts.append(current)
            current = ""
        else:
            current += char
        i += 1
    parts.append(current)
    return [p for p in parts if p.strip()]


def arity(params: str) -> tuple[int, int]:
    """Minimum and maximum argument count a parameter list accepts."""
    if not params.strip():
        return (0, 0)
    parts = split_top_level(params)
    count = len(parts)
    if any("..." in p for p in parts):
        return (count - 1, UNBOUNDED)
    return (count, count)


def real_signatures(repo: pathlib.Path) -> dict[str, tuple[str, tuple[int, int]]]:
    result = subprocess.run(
        ["go", "doc", "-all", "."],
        cwd=repo,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        print(f"go doc failed: {result.stderr.strip()}", file=sys.stderr)
        sys.exit(2)
    return {
        m.group(1): (m.group(2), arity(m.group(2)))
        for m in SIGNATURE.finditer(result.stdout)
    }


def documents(repo: pathlib.Path) -> list[pathlib.Path]:
    return sorted(repo.glob("docs/*.md")) + [repo / "README.md"]


def main() -> int:
    verbose = "--verbose" in sys.argv
    repo = pathlib.Path(__file__).resolve().parent.parent
    signatures = real_signatures(repo)

    findings: list[str] = []
    checked = 0

    for doc in documents(repo):
        if not doc.exists():
            continue
        text = doc.read_text()
        local = set()
        for pattern in SELF_DEFINED:
            local |= set(pattern.findall(text))
        # Only shadow names that are not part of the real API; see the note in
        # the module docstring.
        local -= signatures.keys()

        for lineno, line in enumerate(text.splitlines(), 1):
            for match in CALL.finditer(line):
                name, args = match.group(1), match.group(2)
                if name in local:
                    continue
                checked += 1
                where = f"{doc.relative_to(repo)}:{lineno}"
                if name not in signatures:
                    findings.append(f"{where}: {name} is not a method on *LDAP")
                    continue
                params, (low, high) = signatures[name]
                given = len(split_top_level(args))
                if not low <= given <= high:
                    wanted = f"{low}" if high != UNBOUNDED else f"{low} or more"
                    findings.append(
                        f"{where}: {name} called with {given} argument(s), "
                        f"signature takes {wanted} ({params})"
                    )

    if verbose:
        print(
            f"checked {checked} call site(s) against "
            f"{len(signatures)} exported *LDAP methods"
        )

    if findings:
        print(f"{len(findings)} documentation/API mismatch(es):")
        for finding in findings:
            print(f"  {finding}")
        return 1

    print(f"documentation matches the API ({checked} call sites checked)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
