#!/usr/bin/env python3
"""pagination_guard.py - fail on list fetches that can silently stop at page one.

Rule (convention_pagination_no_silent_caps.md): every GraphQL connection taking
`first:`/`last:` must either
  * take an `after:`/`before:` cursor argument (it is the page of a cursor loop), or
  * select `pageInfo { hasNextPage ... }` at its own level (so overflow is detected
    and followed up / failed closed by the caller); a `last:` connection pages
    backwards, so it needs `pageInfo { hasPreviousPage ... }` instead -- backward
    metadata never satisfies a forward (`first:`) connection, nor the reverse,
unless the line (or one of the 3 lines above it) carries an explicit marker:
    # BOUNDED: <reason>      (Python / shell / YAML)
    // BOUNDED: <reason>     (JS / TS)
Paginated REST calls (limit=/per_page=/maxResults=/pageSize=/page_size=/$top=) are
flagged when the same file shows no paging follow-up at all (page_info, Link header,
next/nextPageToken/cursor/offset/page=/skip).

KNOWN LIMITS (deliberate; this is a tripwire, not a proof -- review still owns correctness):
  * the REST rule is FILE-level: one paging token anywhere in the file silences every limit= in it;
  * helper-call names (paginate/drain/walk/...) count as "pageInfo consumed";
  * queries assembled from string constants are only seen where the literal text is present;
  * `first:` + `before:` (or `last:` + `after:`) is accepted as "has a cursor" without checking the direction;
  * a commented-out `pageInfo { hasNextPage }` inside a selection set still counts as selected
    (`# comments` are stripped from the ARGUMENT list only, so a commented `after:` is not a cursor;
    in host-language code a comment ends at a newline or a `\n`/`\r` escape, in .graphql/.gql at a newline;
    the same rule applies to comments before a selection set, where host-code `\n`/`\r`/`\t` escapes count
    as whitespace);
  * `pageInfo, { hasNextPage }` (a comma before pageInfo's selection set, legal GraphQL) is rejected on
    purpose: file-wide text cannot tell it from a JS call `f(pageInfo, { hasNextPage })`, so the guard
    fails closed (a false finding; drop the comma) rather than read JS objects as satisfied queries;
  * "pageInfo is read" is a text match: `.hasNextPage`, `["hasNextPage"]`, `.get("hasNextPage")` and a
    destructuring pattern naming hasNextPage/endCursor followed by `=` all count; only the forward
    (`hasNextPage`) request is checked for being read.

A BOUNDED marker is only honest when the user-visible output says it is a top-N
slice, or the collection is provably smaller than the page (say why).

Usage:
  pagination_guard.py [paths...]          scan files/dirs (default: .)
  pagination_guard.py --git-staged        scan staged files only, as staged in the index (pre-commit;
                                          added/copied/modified/renamed/type-changed)
  pagination_guard.py --json              machine-readable findings
  pagination_guard.py --version           print GUARD_VERSION and exit
Exit 1 when any unmarked finding exists; exit 2 when git cannot be queried (--git-staged).
--git-staged scans the staged (index) content and the staged repo-root .pagination-guard-ignore,
reporting repo-root-relative names from any directory; path arguments are ignored in that mode.

SYNC: pagination_guard - canonical copy is Fuzzywumpets/claude-bootstrap scripts/pagination_guard.py;
vendored copies live in each repo at scripts/pagination_guard.py (or tools/). Update all
together; `diff` them against the canonical copy. Stdlib only, Python 3.8+.
Tests: tests/test_pagination_guard.py in the canonical repo (`python3 -m unittest discover -s tests`).
"""
import json
import os
import re
import subprocess
import sys

GUARD_VERSION = "2026-11-09.1"   # bump on every behaviour change; `--version` prints it

SKIP_DIRS = {
    "node_modules", ".git", ".venv", "venv", "env", "__pycache__", "dist", "build",
    ".next", ".wrangler", ".svelte-kit", "coverage", "vendor", "site-packages",
    ".mypy_cache", ".pytest_cache", "out", ".turbo", ".cache", "bower_components",
}
EXTS = {".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".graphql", ".gql", ".sh",
        ".liquid", ".rb", ".php", ".go"}
MAX_BYTES = 1_500_000
MARKER_RE = re.compile(r"BOUNDED\s*:")
IGNORE_FILE = ".pagination-guard-ignore"   # glob-ish path prefixes, one per line

# connectionName(... first: N ...)  - args may span lines, no nested parens.
CONN_RE = re.compile(
    r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(([^()]{0,400}?\b(first|last)\s*:\s*"
    r"(\d+|\$[A-Za-z_]\w*|\$\{[^}]{1,60}\}|\"?\s*\+?\s*[A-Za-z_][\w.]*)[^()]{0,400}?)\)",
    re.S)
CURSOR_ARG_RE = re.compile(r"\b(after|before)\s*:")
# String values inside the argument list (`query: "after:foo"`) are data, not arguments. They are
# blanked before looking for cursor names. Block strings, then strings whose quotes are escaped
# because the whole query sits inside a JS/Python string (`\\"..\\"`), then plain strings.
STRING_VALUE_RE = re.compile(
    r'"""(?:[^"\\]|\\.|"(?!""))*"""|\\"(?:[^"\\]|\\(?!")|\\.)*?\\"|"(?:[^"\\\n]|\\.)*"', re.S)
# How `#` and backslash escapes read depends on where the GraphQL text sits (source_mode()):
#   "native": a .graphql/.gql document. A `# comment` runs to the newline; `\n` is just text.
#   "host":   a query inside JS/TS/Python/... code. On one line inside a string, the GraphQL line ends at a
#             `\n`/`\r` escape, and `\n`/`\r`/`\t` escapes are GraphQL whitespace. `this.#field` (a JS
#             private field) is not a comment.
#   "ruby":   like "host", and `#{expr}` is Ruby string interpolation, not a comment.
# Each comment must run to its line end (the lookahead): backtracking may never end it early, before a
# `{` or a cursor name later on the same line.
MODES = ("native", "host", "ruby")
NATIVE_GRAPHQL_EXTS = {".graphql", ".gql"}


def source_mode(path):
    ext = os.path.splitext(path)[1].lower()
    return "native" if ext in NATIVE_GRAPHQL_EXTS else "ruby" if ext == ".rb" else "host"


def _comment(mode):
    if mode == "native":
        return r"#[^\n]*(?=\n|\Z)"
    head = r"(?<!\.)#(?!\{)" if mode == "ruby" else r"(?<!\.)#"
    return head + r"(?:(?!\\[nr])[^\n])*(?=\n|\\[nr]|\Z)"


COMMENT_RE = {m: re.compile(_comment(m)) for m in MODES}
# One left-to-right pass: whichever starts first wins, so `"#tag"` stays a string and a quote inside a
# comment never opens one.
_STRING_OR_COMMENT_RE = {m: re.compile("(%s)|%s" % (STRING_VALUE_RE.pattern, _comment(m)), re.S) for m in MODES}
# Nested input objects / lists (`filter: { after: "x" }`) hold properties, not connection arguments.
_NESTED_RE = re.compile(r"\{[^{}]*\}|\[[^\[\]]*\]")


def top_level_args(args, mode="host"):
    """Argument text with string values, `# comments` and nested input objects/lists blanked out, so
    only the connection's own arguments (first/last/after/before) are visible."""
    s = _STRING_OR_COMMENT_RE[mode].sub(lambda m: '""' if m.group(1) is not None else "", args)
    prev = None
    while prev != s:
        prev, s = s, _NESTED_RE.sub("", s)
    return s


FIRST_ARG_RE = re.compile(r"\bfirst\s*:")
LAST_ARG_RE = re.compile(r"\blast\s*:")
# Escapes that a one-line query string in host code uses for GraphQL whitespace.
_ESCAPED_WS = r"\\[nrt]"


def _ws(mode, commas=False):
    """One ignored whitespace token (no comments)."""
    ws = r"[\s,]" if commas else r"\s"
    return ws if mode == "native" else r"(?:%s|%s)" % (ws, _ESCAPED_WS)


def _ignored(mode, commas):
    """Ignored tokens between a field and its selection set: whitespace, `# comments`, host escapes."""
    return r"(?:%s|%s)*" % (_ws(mode, commas), _comment(mode))


def _name_start(mode):
    """A field name starts here: no word character before it, except the letter of a host `\n` escape."""
    return r"(?<!\w)" if mode == "native" else r"(?:(?<!\w)|(?<=\\[nrt]))"


def _directives(mode, ign):
    return r"(?:@[A-Za-z_]\w*(?:%s*\([^()]*\))?" % _ws(mode) + ign + r")*"


# Between the arguments and the selection set GraphQL allows directives (`@include(if: $x)`,
# `@live`) and ignored tokens. Keyed by source mode.
DIRECTIVES_RE = {m: re.compile(_ignored(m, True) + _directives(m, _ignored(m, True))) for m in MODES}
# Own-level pageInfo, per paging direction: forward needs hasNextPage, backward hasPreviousPage.
# `pageInfo` must be the whole field name (`custompageInfo` is another field) and may carry directives
# (`pageInfo @include(if: $x) { ... }`) just like any field.
# No bare commas here (unlike DIRECTIVES_RE): `pageInfo, { hasNextPage: ... }` is a JS object literal.
_PI_HEAD = {m: _name_start(m) + r"pageInfo" + _ignored(m, False) + _directives(m, _ignored(m, False)) + r"\{"
            for m in MODES}


def _pi_field(mode, field):
    # The field must be selected under its own name: `hasNextPage: hasPreviousPage` is an alias.
    return (_PI_HEAD[mode] + r"[^{}]*" + _name_start(mode) + field + r"\b(?!%s*:)" % _ws(mode))


PAGEINFO_NEXT_RE = {m: re.compile(_pi_field(m, "hasNextPage"), re.S) for m in MODES}
PAGEINFO_PREV_RE = {m: re.compile(_pi_field(m, "hasPreviousPage"), re.S) for m in MODES}
# Things that look like connections but are not (JS/Python call sites etc).
NOT_GQL_NAMES = {"print", "console", "log", "range", "len", "dict", "list", "slice", "items",
                 "get", "post", "fetch", "query", "gql", "graphql", "json", "format"}

REST_LIMIT_RE = re.compile(
    r"(?<![\w.])(limit|per_page|perPage|maxResults|pageSize|page_size|\$top|max_results|"
    r"page\[size\])\s*[=:]\s*[\"']?(\d{2,4})\b")
REST_URLISH_RE = re.compile(r"(https?://|\.json\b|/api/|/v\d|[?&])")
REST_FOLLOW_RE = re.compile(
    r"page_info|pageInfo|[Ll]ink\b|rel=\"?next|next_?[Pp]age|nextPageToken|pageToken|"
    r"next_?[Cc]ursor|cursor|offset|starting_after|continuation|\bpage\s*[=:+]|"
    r"page\s*\+=|skip|has_more|hasMore|truncated|list_complete|@odata\.nextLink|"
    r"total_pages|totalPages|[\"']next[\"']|\.next\b(?!\s*\()|\bnext_?(?:url|link|page|cursor|token)\b")


def parse_ignores(text):
    out = []
    for ln in text.splitlines():
        ln = ln.strip()
        if ln and not ln.startswith("#"):
            out.append(ln.replace("\\", "/").rstrip("/"))
    return out


def load_ignores(root):
    p = os.path.join(root, IGNORE_FILE)
    if os.path.isfile(p):
        with open(p, encoding="utf-8", errors="replace") as fh:
            return parse_ignores(fh.read())
    return []


def ignored(rel, ignores):
    rel = rel.replace("\\", "/")
    return any(rel == i or rel.startswith(i + "/") or (i.startswith("*") and rel.endswith(i[1:]))
               for i in ignores)


def iter_files(paths):
    for p in paths:
        if os.path.isfile(p):
            yield p
            continue
        for dp, dns, fns in os.walk(p):
            dns[:] = [d for d in dns if d not in SKIP_DIRS and not d.startswith(".")]
            for fn in fns:
                if os.path.splitext(fn)[1].lower() in EXTS and not fn.endswith(".min.js"):
                    yield os.path.join(dp, fn)


def line_of(text, idx):
    return text.count("\n", 0, idx) + 1


def has_marker(lines, lineno, span_end_line=None):
    lo = max(0, lineno - 4)
    hi = (span_end_line or lineno)
    return any(MARKER_RE.search(l) for l in lines[lo:hi])


def selection_block(text, start):
    """Return the depth-1 text of the `{...}` selection following `start`, or None."""
    i = start
    n = len(text)
    while i < n and text[i] in " \t\r\n":
        i += 1
    if i >= n or text[i] != "{":
        return None
    depth = 0
    top = []
    j = i
    limit = min(n, i + 20000)
    while j < limit:
        c = text[j]
        if c == "{":
            depth += 1
            if depth == 2:
                top.append("{")  # keep pageInfo{...} detectable: record nested opener
        elif c == "}":
            depth -= 1
            if depth == 1:
                top.append("}")
            if depth == 0:
                return "".join(top)
        if depth == 1 or (depth == 2 and c not in "{}"):
            # depth-2 text is kept so `pageInfo{hasNextPage}` survives; deeper is dropped
            if c not in "{}":
                top.append(c)
        j += 1
    return None


def direct_pageinfo(block, forward=True, backward=False, mode="host"):
    """Paging metadata selected at this connection's own level, for its own direction:
    `first:` (forward) needs pageInfo{hasNextPage}, `last:` (backward) needs
    pageInfo{hasPreviousPage}. Metadata for the other direction does not count."""
    if block is None:
        return False
    if forward and PAGEINFO_NEXT_RE[mode].search(block):
        return True
    if backward and PAGEINFO_PREV_RE[mode].search(block):
        return True
    return False


def scan_text(path, text):
    findings = []
    lines = text.splitlines()
    mode = source_mode(path)
    for m in CONN_RE.finditer(text):
        name, args = m.group(1), m.group(2)
        if name in NOT_GQL_NAMES or name[0].isupper():
            # Upper-case names are types/classes, never GraphQL connection fields.
            continue
        # Python/JS kwargs `func(first=..)` use '=' so they never match ':'; JS object
        # literals `fn({first: 10})` contain '{' and are excluded by [^()]. Require
        # GraphQL-ish context: after optional directives/comments the next token is '{'.
        k = DIRECTIVES_RE[mode].match(text, m.end()).end()
        if k >= len(text) or text[k] != "{":
            continue
        lineno = line_of(text, m.start())
        top = top_level_args(args, mode)
        if CURSOR_ARG_RE.search(top):
            continue
        backward = bool(LAST_ARG_RE.search(top))
        forward = bool(FIRST_ARG_RE.search(top)) or not backward
        block = selection_block(text, k)
        if direct_pageinfo(block, forward, backward, mode):
            continue
        if has_marker(lines, lineno, line_of(text, m.end())):
            continue
        need = "pageInfo{hasNextPage}" if forward else "pageInfo{hasPreviousPage}"
        if forward and backward:
            need = "pageInfo{hasNextPage} / pageInfo{hasPreviousPage}"
        wrong_way = ""
        if block is not None and not (forward and backward):
            other = PAGEINFO_PREV_RE if forward else PAGEINFO_NEXT_RE
            if other[mode].search(block):
                wrong_way = (" (the pageInfo selected here pages the other direction and cannot "
                             "detect overflow for %s:)" % m.group(3))
        findings.append({
            "file": path, "line": lineno, "kind": "graphql-connection",
            "detail": "%s(%s:%s) has no %s cursor and no %s%s "
                      "(plain Shopify list fields like fulfillments/refunds/transactions/trackingInfo: "
                      "drop the first: arg to get every item)" % (
                name, m.group(3), m.group(4).strip(),
                "after:" if forward else "before:", need, wrong_way),
            "snippet": lines[lineno - 1].strip()[:200] if lineno - 1 < len(lines) else "",
        })
    findings.extend(scan_unread_pageinfo(path, text, lines))
    has_follow = bool(REST_FOLLOW_RE.search(text))
    if not has_follow:
        for m in REST_LIMIT_RE.finditer(text):
            lineno = line_of(text, m.start())
            ln = lines[lineno - 1] if lineno - 1 < len(lines) else ""
            if not REST_URLISH_RE.search(ln):
                continue
            if has_marker(lines, lineno):
                continue
            findings.append({
                "file": path, "line": lineno, "kind": "rest-limit",
                "detail": "%s=%s with no paging follow-up anywhere in file" % (m.group(1), m.group(2)),
                "snippet": ln.strip()[:200],
            })
    return findings


PAGEINFO_REQ_RE = PAGEINFO_NEXT_RE   # one definition of "pageInfo{hasNextPage} requested"
# Code that actually reads the cursor state (not the query text itself).
PAGEINFO_READ_RE = re.compile(
    r"\.hasNextPage|\[\s*[\"']hasNextPage[\"']\s*\]|get\(\s*[\"']hasNextPage|"
    r"\.endCursor|\[\s*[\"']endCursor[\"']\s*\]|get\(\s*[\"']endCursor|"
    r"hasNextPage\s*[:,]\s*(?!hasPreviousPage|hasNextPage|startCursor|endCursor)(has|next|more|hn)|\bhasNextPage\s*\}\s*=|"
    # Destructuring: `const { hasNextPage, endCursor } = conn.pageInfo`,
    # `const { pageInfo: { hasNextPage, endCursor } } = data.things`, `({ hasNextPage } = pi)`:
    # a pattern naming the field whose closing brace(s) are followed by `=` (not `==`).
    r"\b(?:hasNextPage|endCursor)\b[^{}]*\}(?:\s*,?\s*\})*\s*\)?\s*=(?!=)")
HELPER_CALL_RE = re.compile(r"(?i)\b\w*(paginat|drain|walk_?pages|all_?pages|each_?page|iter_?pages|"
                            r"fetch_?all|page_?through|follow_?pages|hydrate)\w*\s*\(")


def scan_unread_pageinfo(path, text, lines):
    """Query asks for pageInfo{hasNextPage} but nothing in the file reads it."""
    reqs = list(PAGEINFO_REQ_RE[source_mode(path)].finditer(text))
    if not reqs or PAGEINFO_READ_RE.search(text) or HELPER_CALL_RE.search(text):
        return []
    out = []
    for m in reqs:
        lineno = line_of(text, m.start())
        if has_marker(lines, lineno):
            continue
        out.append({"file": path, "line": lineno, "kind": "pageinfo-unread",
                    "detail": "pageInfo{hasNextPage} requested but never read in this file "
                              "(no cursor loop / overflow check)",
                    "snippet": lines[lineno - 1].strip()[:200] if lineno - 1 < len(lines) else ""})
    return out


class GitError(Exception):
    """git could not be queried; a staged scan must fail, not pass as clean."""


def _git(args):
    try:
        r = subprocess.run(["git"] + args, capture_output=True, check=False)
    except OSError as e:
        raise GitError("cannot run git: %s" % e)
    if r.returncode != 0:
        raise GitError("git %s failed (exit %d): %s" % (
            " ".join(args[:2]), r.returncode, r.stderr.decode("utf-8", "replace").strip()))
    return r.stdout


def _universal_newlines(s):
    return s.replace("\r\n", "\n").replace("\r", "\n")    # what text-mode open() does


def staged_files():
    """Staged added/copied/modified/renamed/type-changed code files, as repo-root-relative names.
    `-z` keeps git from quoting non-ASCII or special names."""
    out = _git(["diff", "--cached", "--name-only", "-z", "--diff-filter=ACMRT"])
    names = [os.fsdecode(n) for n in out.split(b"\0") if n]
    return [n for n in names if os.path.splitext(n)[1].lower() in EXTS]


def git_toplevel():
    top = os.fsdecode(_git(["rev-parse", "--show-toplevel"])).strip()
    if not top:
        raise GitError("git rev-parse --show-toplevel returned nothing")
    return top


def staged_text(name):
    """The file as staged in the index (not the working tree), or None if too big.
    `:0:` is the stage-0 index entry; `name` is repo-root-relative."""
    data = _git(["cat-file", "blob", ":0:" + name])
    if len(data) > MAX_BYTES:
        return None
    return _universal_newlines(data.decode("utf-8", errors="replace"))


def staged_ignores(top):
    """The repo-root .pagination-guard-ignore as staged (an unstaged one is not part of the commit).
    Pathspecs are cwd-relative, hence -C <top>; `:0:` blob names are always repo-root-relative."""
    if not _git(["-C", top, "--literal-pathspecs", "ls-files", "-z", "--cached", "--", IGNORE_FILE]):
        return []
    return parse_ignores(staged_text(IGNORE_FILE) or "")


def main(argv):
    if "--version" in argv:
        print(GUARD_VERSION)
        return 0
    try:
        return run(argv)
    except GitError as e:
        print("pagination_guard: %s" % e, file=sys.stderr)
        return 2


def run(argv):
    as_json = "--json" in argv
    args = [a for a in argv if not a.startswith("--")]
    root = os.getcwd()
    staged = "--git-staged" in argv
    if staged:
        # Staged files are identified, ignored and reported by repo-root-relative name, whatever the
        # cwd is; the ignore file is the staged repo-root one. Path arguments are ignored.
        ignores = staged_ignores(git_toplevel())    # exit 2 here when this is not a git work tree
        files = [(n, n) for n in staged_files()]
    else:
        ignores = load_ignores(root)
        files = [(f, os.path.relpath(f, root)) for f in iter_files(args or ["."])]
    findings = []
    for f, rel in files:
        if ignored(rel, ignores):
            continue
        if staged:
            text = staged_text(f)         # scan what will be committed, not the working tree
            if text is None:
                continue
        else:
            try:
                if os.path.getsize(f) > MAX_BYTES:
                    continue
                with open(f, encoding="utf-8", errors="replace") as fh:
                    text = fh.read()
            except OSError:
                continue
        low = text.lower()
        # cheap prefilter; SYNC: must cover every token CONN_RE / REST_LIMIT_RE can match
        if not any(t in low for t in ("first", "last", "limit", "page", "maxresults", "max_results",
                                       "$top", "per_page", "perpage")):
            continue
        for x in scan_text(rel, text):
            findings.append(x)
    if as_json:
        print(json.dumps(findings, indent=1))
    else:
        for x in findings:
            print("%s:%d: [%s] %s\n    %s" % (x["file"], x["line"], x["kind"], x["detail"], x["snippet"]))
        if findings:
            print("\npagination_guard: %d unbounded list fetch(es). Page them (cursor loop / "
                  "pageInfo follow-up) or mark an honest top-N with `# BOUNDED: <reason>` "
                  "(`// BOUNDED:` in JS). See convention_pagination_no_silent_caps.md" % len(findings),
                  file=sys.stderr)
        else:
            print("pagination_guard: OK (%d files)" % len(files), file=sys.stderr)
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
