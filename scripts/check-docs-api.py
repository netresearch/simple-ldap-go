#!/usr/bin/env python3
"""Check that the client calls in the documentation name real methods with the
right number of arguments.

The guides are prose, not compiled, so nothing else notices when they drift.
Before this existed they had accumulated 48 call sites naming methods that were
never written, plus two calls with the wrong arity, and the drift was only
found by hand.

Two things are checked in docs/*.md and README.md, both against `go doc -all`.

Client calls — every `l.X(...)`, `client.X(...)` and `ldapClient.X(...)`:

  1. X is a real exported method on *LDAP.
  2. The call passes a number of arguments the signature accepts.

Result members — every `user.X`, `group.X` and `computer.X`:

  3. X is a real field or method on User / Group / Computer.
  4. A method is called and a field is not: `user.DN` is a method value, not
     the DN, and `user.MustChangePassword()` does not compile. Both shapes were
     in the guides — 26 and 1 respectively — and read as correct until copied.

Package-level calls — every `ldap.X(`:

  5. X is a real exported function, type or variable in the package. A guide
     that calls `ldap.WithRetry(...)` names something this library does not
     have, and the receiver checks above never see it.

Configuration literals — every `ldap.T{...}` and `&ldap.T{...}` for a struct
type T the package exports, plus the bare `T{...}` form the older guides use:

  6. Each `Field:` key in the literal is a field T actually has. This is the
     check that was missing when `PoolConfig` was documented with
     `MinIdleConnections` and `MaxLifetime`, neither of which ever existed:
     the call checks could not see a struct literal at all, so the guides
     drifted for a year with the gate green.

  A type the package does not export is skipped, so a snippet may declare and
  fill its own struct without tripping this.

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
CALL_HEAD = re.compile(rf"\b(?:{RECEIVERS})\.([A-Z][A-Za-z0-9]{{2,}})\(")
SIGNATURE = re.compile(
    r"^func \(l \*LDAP\) ([A-Z][A-Za-z0-9]*)\((.*?)\)(?: |$)", re.MULTILINE
)
# Only a receiver-style declaration shadows a name. A free `func SyncUsers(...)`
# in a snippet must not exempt `client.SyncUsers(...)` from the existence check —
# that is a call on the client, not on whatever the free function belongs to.
SELF_DEFINED = (re.compile(r"func \(\w+ \*LDAP\) ([A-Z][A-Za-z0-9]*)"),)
UNBOUNDED = 10**6

# Result types the guides bind to conventionally named variables.
RESULT_VARS = {"user": "User", "group": "Group", "computer": "Computer"}
MEMBER = re.compile(rf"\b(?:{'|'.join(RESULT_VARS)})\.([A-Z][A-Za-z0-9]*)(\s*\()?")
MEMBER_VAR = re.compile(rf"\b({'|'.join(RESULT_VARS)})\.")
STRUCT_FIELDS = re.compile(r"^\t([A-Z][A-Za-z0-9]*)\s+\S", re.MULTILINE)

# Package-qualified references: ldap.New(...), ldap.ErrUserNotFound, ldap.Config{…}
PKG_CALL = re.compile(r"(?<![\w.])ldap\.([A-Z][A-Za-z0-9]*)\(")
# A composite literal, qualified by OUR package or unqualified. The lookbehind
# is what keeps `tls.Config{…}` from being read as this package's Config: any
# other qualifier in front of the type name means the type is not ours.
LITERAL = re.compile(r"(?<![\w.])(?:ldap\.)?([A-Z][A-Za-z0-9]*)\{")
# A key at the top level of a literal: "\tField: value" or "Field: value,".
LITERAL_KEY = re.compile(r"(?:^|[,{]\s*|\n\s*)([A-Z][A-Za-z0-9]*)\s*:(?!=)")

# go doc surfaces, for the package-level checks.
PKG_FUNC = re.compile(r"^func ([A-Z][A-Za-z0-9]*)[\[(]", re.MULTILINE)
PKG_TYPE = re.compile(r"^type ([A-Z][A-Za-z0-9]*)[\[ ]", re.MULTILINE)
# A package-level value, in any shape go doc prints: a standalone
# `var Name = …` or `const Name = …`, a typed `const Name uint32 = …`, and the
# tab-indented members of a grouped var/const block.
PKG_VALUE = re.compile(
    r"^(?:\t|(?:var|const)\s+)([A-Z][A-Za-z0-9]*)(?:\s+[\w\.\[\]\*]+)?\s*=", re.MULTILINE
)
# go-ldap is imported as `ldap` too, so `ldap.` in a snippet may address either
# package. Its exported names are read from its own go doc rather than listed
# here, so the check stays right when that dependency moves.
FOREIGN_PACKAGE = "github.com/go-ldap/ldap/v3"


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


def skip_string(text: str, i: int) -> int:
    """Index just past the string literal that opens at `text[i]`."""
    quote = text[i]
    i += 1
    while i < len(text):
        if text[i] == "\\":
            i += 2
            continue
        if text[i] == quote:
            return i + 1
        i += 1
    return i


def balanced_span(text: str, start: int, closer: str) -> str | None:
    """Text between the bracket at `text[start]` and its matching `closer`.

    Walks the whole document rather than a single line, so a construct split
    across lines or nested to any depth is read in full. String literals are
    stepped over, so a bracket inside one does not shift the depth. Returns None
    on an unbalanced run (a snippet cut off mid-call), which is skipped rather
    than guessed at.

    Comments are stepped over before quotes are considered. An apostrophe in
    prose ("the pool's capacity") is not a rune literal, but it opens one as far
    as skip_string is concerned, and everything up to the next apostrophe —
    closing braces included — then disappears from the count. The literal being
    read runs past its own end, swallows the next one, and the mismatch is
    reported against a line nobody touched.
    """
    depth = 0
    i = start
    while i < len(text):
        char = text[i]
        if text.startswith("//", i):
            newline = text.find("\n", i)
            i = len(text) if newline == -1 else newline + 1
            continue
        if text.startswith("/*", i):
            end = text.find("*/", i + 2)
            i = len(text) if end == -1 else end + 2
            continue
        if char in "\"'`":
            i = skip_string(text, i)
            continue
        if char in "([{":
            depth += 1
        elif char in ")]}":
            depth -= 1
            if depth == 0:
                return text[start + 1 : i] if char == closer else None
        i += 1
    return None


def argument_text(text: str, open_paren: int) -> str | None:
    """Text between `text[open_paren]` == "(" and its matching ")"."""
    return balanced_span(text, open_paren, ")")


def go_doc(repo: pathlib.Path, package: str = ".") -> str:
    """`go doc -all` for a package, or exit 2 if it cannot be produced."""
    result = subprocess.run(
        ["go", "doc", "-all", package],
        cwd=repo,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        print(f"go doc {package} failed: {result.stderr.strip()}", file=sys.stderr)
        sys.exit(2)
    return result.stdout


def real_signatures(doc: str) -> dict[str, tuple[str, tuple[int, int]]]:
    return {
        m.group(1): (m.group(2), arity(m.group(2))) for m in SIGNATURE.finditer(doc)
    }


def type_surface(doc: str, typ: str) -> tuple[set[str], set[str]]:
    """(fields, methods) of `typ`, with Object's promoted methods folded in."""
    body = re.search(rf"^type {typ} struct \{{(.*?)^\}}", doc, re.MULTILINE | re.DOTALL)
    fields = set(STRUCT_FIELDS.findall(body.group(1))) if body else set()
    methods = set(
        re.findall(rf"^func \(\w+ \*?{typ}\) ([A-Z][A-Za-z0-9]*)", doc, re.MULTILINE)
    )
    promoted = set(
        re.findall(r"^func \(\w+ \*?Object\) ([A-Z][A-Za-z0-9]*)", doc, re.MULTILINE)
    )
    return fields, methods | promoted


def struct_fields(doc: str) -> dict[str, set[str]]:
    """Exported struct type -> its field names, from `go doc -all`."""
    out: dict[str, set[str]] = {}
    for match in re.finditer(
        r"^type ([A-Z][A-Za-z0-9]*)(?:\[[^\]]*\])? struct \{(.*?)^\}",
        doc,
        re.MULTILINE | re.DOTALL,
    ):
        out[match.group(1)] = set(STRUCT_FIELDS.findall(match.group(2)))
    return out


def package_names(doc: str) -> set[str]:
    """Every exported package-level name: functions, types and values."""
    return (
        set(PKG_FUNC.findall(doc)) | set(PKG_TYPE.findall(doc)) | set(PKG_VALUE.findall(doc))
    )


def literal_body(text: str, open_brace: int) -> str | None:
    """Text between `text[open_brace]` == "{" and its matching "}"."""
    return balanced_span(text, open_brace, "}")


def top_level_keys(body: str) -> list[str]:
    """Field keys at depth 0 of a literal body, skipping nested literals.

    Comments and string literals are stepped over for the same reason
    balanced_span does it: a brace in prose is not a brace. `// } in a comment`
    inside a literal otherwise drops the depth and every key after it goes
    unchecked — which is a wrong field passing review, not a false alarm.
    """
    depth = 0
    segment = []
    i = 0
    while i < len(body):
        if body.startswith("//", i):
            newline = body.find("\n", i)
            i = len(body) if newline == -1 else newline
            continue
        if body.startswith("/*", i):
            end = body.find("*/", i + 2)
            i = len(body) if end == -1 else end + 2
            continue
        char = body[i]
        if char in "\"'`":
            i = skip_string(body, i)
            continue
        if char in "([{":
            depth += 1
        elif char in ")]}":
            depth -= 1
        if depth == 0:
            segment.append(char)
        i += 1
    return [m.group(1) for m in LITERAL_KEY.finditer("".join(segment))]


def documents(repo: pathlib.Path) -> list[pathlib.Path]:
    return sorted(repo.glob("docs/*.md")) + [repo / "README.md"]


def main() -> int:
    verbose = "--verbose" in sys.argv
    repo = pathlib.Path(__file__).resolve().parent.parent
    doc = go_doc(repo)
    signatures = real_signatures(doc)
    surfaces = {var: type_surface(doc, typ) for var, typ in RESULT_VARS.items()}
    fields_by_type = struct_fields(doc)
    exported = package_names(doc) | package_names(go_doc(repo, FOREIGN_PACKAGE))

    findings: list[str] = []
    checked = 0

    for doc_path in documents(repo):
        if not doc_path.exists():
            continue
        text = doc_path.read_text()
        local = set()
        for pattern in SELF_DEFINED:
            local |= set(pattern.findall(text))
        # Only shadow names that are not part of the real API; see the note in
        # the module docstring.
        local -= signatures.keys()

        for match in CALL_HEAD.finditer(text):
            name = match.group(1)
            if name in local:
                continue
            args = argument_text(text, match.end() - 1)
            if args is None:
                continue
            checked += 1
            lineno = text.count("\n", 0, match.start()) + 1
            where = f"{doc_path.relative_to(repo)}:{lineno}"
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

        # Result members: user.X / group.X / computer.X
        for match in MEMBER.finditer(text):
            name, called = match.group(1), bool(match.group(2))
            var = MEMBER_VAR.match(text, match.start()).group(1)
            typ = RESULT_VARS[var]
            fields, methods = surfaces[var]
            lineno = text.count("\n", 0, match.start()) + 1
            where = f"{doc_path.relative_to(repo)}:{lineno}"
            checked += 1
            if name not in fields and name not in methods:
                findings.append(f"{where}: {var}.{name} is not on {typ}")
            elif name in methods and name not in fields and not called:
                findings.append(
                    f"{where}: {var}.{name} is a method — it needs () to be called"
                )
            elif name in fields and name not in methods and called:
                findings.append(
                    f"{where}: {var}.{name} is a field — it cannot be called"
                )

        # Package-level references: ldap.X(...)
        for match in PKG_CALL.finditer(text):
            name = match.group(1)
            if name in local:
                continue
            checked += 1
            if name not in exported:
                lineno = text.count("\n", 0, match.start()) + 1
                findings.append(
                    f"{doc_path.relative_to(repo)}:{lineno}: "
                    f"ldap.{name} is not exported by this package"
                )

        # Configuration literals: ldap.T{...}, &T{...}
        for match in LITERAL.finditer(text):
            typ = match.group(1)
            known = fields_by_type.get(typ)
            if known is None:
                continue
            body = literal_body(text, match.end() - 1)
            if body is None:
                continue
            lineno = text.count("\n", 0, match.start()) + 1
            where = f"{doc_path.relative_to(repo)}:{lineno}"
            for key in top_level_keys(body):
                checked += 1
                if key not in known:
                    findings.append(f"{where}: {typ} has no field {key}")

    if verbose:
        print(
            f"checked {checked} reference(s) against "
            f"{len(signatures)} exported *LDAP methods "
            f"and {len(surfaces)} result types"
        )

    if findings:
        print(f"{len(findings)} documentation/API mismatch(es):")
        for finding in findings:
            print(f"  {finding}")
        return 1

    print(f"documentation matches the API ({checked} references checked)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
