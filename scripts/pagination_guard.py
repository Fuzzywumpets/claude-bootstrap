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
  * a commented-out `pageInfo { hasNextPage }` inside a selection set still counts as selected;
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
--git-staged scans the staged (index) content and the staged .pagination-guard-ignore; path
arguments are ignored in that mode.

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

GUARD_VERSION = "2026-11-08"   # bump on every behaviour change; `--version` prints it

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
FIRST_ARG_RE = re.compile(r"\bfirst\s*:")
LAST_ARG_RE = re.compile(r"\blast\s*:")
# Between the arguments and the selection set GraphQL allows directives (`@include(if: $x)`,
# `@live`) and ignored tokens: whitespace and `# comments` up to the end of the line.
_IGNORED = r"(?:\s|#[^\n]*)*"
DIRECTIVES_RE = re.compile(_IGNORED + r"(?:@[A-Za-z_]\w*(?:\s*\([^()]*\))?" + _IGNORED + r")*")
# Own-level pageInfo, per paging direction: forward needs hasNextPage, backward hasPreviousPage.
PAGEINFO_NEXT_RE = re.compile(r"pageInfo\s*\{[^{}]*hasNextPage", re.S)
PAGEINFO_PREV_RE = re.compile(r"pageInfo\s*\{[^{}]*hasPreviousPage", re.S)
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


def direct_pageinfo(block, forward=True, backward=False):
    """Paging metadata selected at this connection's own level, for its own direction:
    `first:` (forward) needs pageInfo{hasNextPage}, `last:` (backward) needs
    pageInfo{hasPreviousPage}. Metadata for the other direction does not count."""
    if block is None:
        return False
    if forward and PAGEINFO_NEXT_RE.search(block):
        return True
    if backward and PAGEINFO_PREV_RE.search(block):
        return True
    return False


def scan_text(path, text):
    findings = []
    lines = text.splitlines()
    for m in CONN_RE.finditer(text):
        name, args = m.group(1), m.group(2)
        if name in NOT_GQL_NAMES or name[0].isupper():
            # Upper-case names are types/classes, never GraphQL connection fields.
            continue
        # Python/JS kwargs `func(first=..)` use '=' so they never match ':'; JS object
        # literals `fn({first: 10})` contain '{' and are excluded by [^()]. Require
        # GraphQL-ish context: after optional directives/comments the next token is '{'.
        k = DIRECTIVES_RE.match(text, m.end()).end()
        if k >= len(text) or text[k] != "{":
            continue
        lineno = line_of(text, m.start())
        if CURSOR_ARG_RE.search(args):
            continue
        backward = bool(LAST_ARG_RE.search(args))
        forward = bool(FIRST_ARG_RE.search(args)) or not backward
        block = selection_block(text, k)
        if direct_pageinfo(block, forward, backward):
            continue
        if has_marker(lines, lineno, line_of(text, m.end())):
            continue
        need = "pageInfo{hasNextPage}" if forward else "pageInfo{hasPreviousPage}"
        if forward and backward:
            need = "pageInfo{hasNextPage} / pageInfo{hasPreviousPage}"
        wrong_way = ""
        if block is not None and not (forward and backward):
            other = PAGEINFO_PREV_RE if forward else PAGEINFO_NEXT_RE
            if other.search(block):
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


PAGEINFO_REQ_RE = re.compile(r"pageInfo\s*\{[^{}]*hasNextPage")
# Code that actually reads the cursor state (not the query text itself).
PAGEINFO_READ_RE = re.compile(
    r"\.hasNextPage|\[\s*[\"']hasNextPage[\"']\s*\]|get\(\s*[\"']hasNextPage|"
    r"\.endCursor|\[\s*[\"']endCursor[\"']\s*\]|get\(\s*[\"']endCursor|"
    r"hasNextPage\s*[:,]\s*(has|next|more|hn)|\bhasNextPage\s*\}\s*=|"
    # Destructuring: `const { hasNextPage, endCursor } = conn.pageInfo`,
    # `const { pageInfo: { hasNextPage, endCursor } } = data.things`, `({ hasNextPage } = pi)`:
    # a pattern naming the field whose closing brace(s) are followed by `=` (not `==`).
    r"\b(?:hasNextPage|endCursor)\b[^{}]*\}(?:\s*,?\s*\})*\s*\)?\s*=(?!=)")
HELPER_CALL_RE = re.compile(r"(?i)\b\w*(paginat|drain|walk_?pages|all_?pages|each_?page|iter_?pages|"
                            r"fetch_?all|page_?through|follow_?pages|hydrate)\w*\s*\(")


def scan_unread_pageinfo(path, text, lines):
    """Query asks for pageInfo{hasNextPage} but nothing in the file reads it."""
    reqs = list(PAGEINFO_REQ_RE.finditer(text))
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


def staged_ignores(root, top):
    """.pagination-guard-ignore as staged (an unstaged one is not part of the commit)."""
    name = os.path.relpath(os.path.join(root, IGNORE_FILE), top).replace(os.sep, "/")
    if not _git(["--literal-pathspecs", "ls-files", "-z", "--cached", "--", name]):
        return []
    return parse_ignores(staged_text(name) or "")


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
        # (name in the index, path used for display/ignore matching relative to the cwd);
        # path arguments are ignored in this mode
        top = git_toplevel()
        ignores = staged_ignores(root, top)
        files = [(n, os.path.join(top, n)) for n in staged_files()]
    else:
        ignores = load_ignores(root)
        files = [(f, f) for f in iter_files(args or ["."])]
    findings = []
    for name, f in files:
        rel = os.path.relpath(f, root)
        if ignored(rel, ignores):
            continue
        if staged:
            text = staged_text(name)      # scan what will be committed, not the working tree
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
