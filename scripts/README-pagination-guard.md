# pagination_guard.py

Canonical copy of the Fuzzywumpets pagination tripwire: it fails on list fetches that can silently stop at page one.
Stdlib-only Python 3.8+. Rule text: `convention_pagination_no_silent_caps.md` (canonical memory).

## What it flags

- `graphql-connection`: `field(first:N ...)` / `last:N` with no `after:`/`before:` cursor and no own-level `pageInfo` for its paging direction.
- `pageinfo-unread`: the query asks for `pageInfo { hasNextPage ... }` but nothing in the file reads the paging state and no paginate/drain helper is called.
- `rest-limit`: `limit=`, `per_page=`, `maxResults=`, `$top=` ... in a file with no paging follow-up at all.

An honest top-N or a single-record lookup is exempted with `# BOUNDED: <reason>` (`// BOUNDED:` in JS/TS) on the same line or up to 3 lines above.

## Usage

```
python3 scripts/pagination_guard.py [paths...]   # scan files/dirs (default: .)
python3 scripts/pagination_guard.py --git-staged # staged (index) content only, for pre-commit; exit 2 if git fails
python3 scripts/pagination_guard.py --json       # machine-readable findings
python3 scripts/pagination_guard.py --version    # print GUARD_VERSION
```

Exit 1 when any unmarked finding exists. Exemptions: `.pagination-guard-ignore` at the repo root (one path prefix or `*suffix` per line, each with a reason comment).

## Vendoring

Each repo that needs the guard vendors this file **byte-identically** (LF line endings; `.gitattributes` here pins that) at `scripts/pagination_guard.py` (or `tools/`). The file carries a `SYNC:` header naming this repo as canonical. Check a vendored copy with:

```
diff <(curl -fsSL https://raw.githubusercontent.com/Fuzzywumpets/claude-bootstrap/main/scripts/pagination_guard.py) scripts/pagination_guard.py
```

Never edit a vendored copy in place; change it here (with a test in `tests/test_pagination_guard.py`) and re-copy it to every repo in the same change. `--version` shows which generation a repo carries.

## Known limits (accepted by Alex, 2026-11-08)

This is a **regex tripwire, not a GraphQL parser**. It catches the common "first page only" mistakes cheaply; it is not a proof that every list fetch pages. Seven DeepReview rounds keep finding new ways to fool a regex scanner, none of them a regression, so the limits are documented instead of chased. A clean run means "nothing obvious", not "all paging verified".

Known gaps (each can give a missed finding, `m`, or a false finding, `f`):

- `m` Upper-case field names are skipped (so TS/JS types and classes are not read as connections), and a few common names (`items`, `list`, `get`, `query`, ...) are skipped.
- `m` A commented-out `pageInfo { hasNextPage }` inside a selection set still counts as selected. (`#` comments in the argument list are stripped since 2026-11-08.4, so a commented-out `after:`/`before:` no longer counts as a cursor.)
- `m` Parentheses inside a string argument hide the connection (arguments are matched without nested parens).
- `m` `.html` files are not scanned, so inline browser JavaScript is not covered.
- `f` Aliased paging-state reads (`hasNextPage: more`) in consumer code can produce a false `pageinfo-unread`.
- `f` A `BOUNDED:` marker is not honoured for the unread-`pageInfo` check in every layout; JS destructured parameters can look like connections.
- `f` A comma before pageInfo's selection set (`pageInfo, { hasNextPage }`, legal GraphQL) is rejected on purpose: file-wide text cannot tell it from a JS call `f(pageInfo, { hasNextPage })`, so the guard fails closed. Drop the comma.

When a case matters, add a `BOUNDED:` marker with the reason, or fix the query. Fix the guard here, with a test, and re-sync every vendored copy in the same change.

## Tests

```
python3 -m unittest discover -s tests -v
python3 -m pytest tests            # also works
PAGINATION_GUARD_PATH=/path/to/copy.py python3 -m unittest discover -s tests   # test another copy
```
