"""Tests for scripts/pagination_guard.py (stdlib unittest; also collected by pytest).

    python3 -m unittest discover -s tests -v
    python3 -m pytest tests

Set PAGINATION_GUARD_PATH to run the same tests against another copy of the script
(for example a vendored copy, or an older canonical copy to see the tests fail).
"""
import ast
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.environ.get("PAGINATION_GUARD_PATH") or os.path.join(
    HERE, "..", "scripts", "pagination_guard.py")
SCRIPT = os.path.abspath(SCRIPT)

_spec = importlib.util.spec_from_file_location("pagination_guard_under_test", SCRIPT)
guard = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(guard)


def scan(text, name="x.js"):
    """All findings for one in-memory file."""
    return guard.scan_text(name, textwrap.dedent(text))


def conn(text, name="x.js"):
    return [f for f in scan(text, name) if f["kind"] == "graphql-connection"]


def unread(text, name="x.js"):
    return [f for f in scan(text, name) if f["kind"] == "pageinfo-unread"]


def clean_env():
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env["GIT_CONFIG_NOSYSTEM"] = "1"
    return env


def run_guard(args, cwd, env_extra=None):
    env = clean_env()
    env.update(env_extra or {})
    return subprocess.run([sys.executable, SCRIPT] + list(args), cwd=cwd, env=env,
                          capture_output=True, text=True)


class TempDirCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="pgguard-test-")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def write(self, rel, text):
        path = os.path.join(self.tmp, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(textwrap.dedent(text))
        return path


UNBOUNDED_JS = """\
    const QUERY = `{ things(first: 10) { nodes { id } } }`;
    module.exports = { QUERY };
"""


# --------------------------------------------------------------------------------------
# Behaviour that already existed and must keep working
# --------------------------------------------------------------------------------------
class ExistingBehaviour(unittest.TestCase):
    def test_unbounded_first_is_flagged(self):
        found = conn("const q = `{ things(first: 10) { nodes { id } } }`;")
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["line"], 1)
        self.assertIn("things", found[0]["detail"])

    def test_after_cursor_satisfies(self):
        self.assertEqual(conn("const q = `{ things(first: 10, after: $c) { nodes { id } } }`;"), [])

    def test_before_cursor_satisfies_backward(self):
        self.assertEqual(conn("const q = `{ things(last: 10, before: $c) { nodes { id } } }`;"), [])

    def test_own_level_pageinfo_satisfies(self):
        src = "const q = `{ things(first: 10) { nodes { id } pageInfo { hasNextPage endCursor } } }`;"
        self.assertEqual(conn(src), [])

    def test_nested_pageinfo_does_not_satisfy_outer(self):
        src = ("const q = `{ things(first: 10) { nodes { kids(first: 5) "
               "{ pageInfo { hasNextPage } nodes { id } } } } }`;")
        found = conn(src)
        self.assertEqual([f["detail"].split("(")[0] for f in found], ["things"])

    def test_multiline_args_report_first_line(self):
        found = conn("""\
            const q = `{
              things(
                first: 10
              ) { nodes { id } }
            }`;
        """)
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["line"], 2)

    def test_variable_and_interpolated_first(self):
        self.assertEqual(len(conn("const q = `{ things(first: $n) { nodes { id } } }`;")), 1)
        self.assertEqual(len(conn("const q = `{ things(first: ${PAGE}) { nodes { id } } }`;")), 1)

    def test_bounded_marker_same_line(self):
        self.assertEqual(conn("q = '{ things(first: 1) { nodes { id } } }'  # BOUNDED: single lookup"), [])

    def test_bounded_marker_up_to_three_lines_above(self):
        for gap in (0, 1, 2):
            with self.subTest(blank_lines_between=gap):
                src = "// BOUNDED: top 10 by design\n" + "\n" * gap + \
                      "const q = `{ things(first: 10) { nodes { id } } }`;\n"
                self.assertEqual(conn(src), [])

    def test_bounded_marker_four_lines_above_is_too_far(self):
        src = "// BOUNDED: too far away\n\n\n\nconst q = `{ things(first: 10) { nodes { id } } }`;\n"
        self.assertEqual(len(conn(src)), 1)

    def test_bounded_marker_inside_graphql_string(self):
        src = "const q = `{\n  # BOUNDED: top 10 only\n  things(first: 10) { nodes { id } }\n}`;"
        self.assertEqual(conn(src), [])

    def test_python_kwargs_and_js_object_args_are_not_connections(self):
        self.assertEqual(conn("rows = client.list(first=10)\nbucket(first, 3)", "x.py"), [])
        self.assertEqual(conn("call({first: 10})\nfoo(first: 10)\n;", "x.js"), [])

    def test_uppercase_names_are_not_connections(self):
        self.assertEqual(conn("class Foo(first: 10) { }"), [])

    def test_rest_limit_without_followup_is_flagged(self):
        src = 'const r = await fetch("https://shop.example.com/admin/api/orders.json?limit=250");'
        found = [f for f in scan(src) if f["kind"] == "rest-limit"]
        self.assertEqual(len(found), 1)
        self.assertIn("limit=250", found[0]["detail"])

    def test_rest_limit_with_followup_in_file_is_ok(self):
        src = ('const r = await fetch("https://shop.example.com/admin/api/orders.json?limit=250");\n'
               'const more = r.headers.get("Link");\n')
        self.assertEqual([f for f in scan(src) if f["kind"] == "rest-limit"], [])

    def test_rest_limit_bounded_marker(self):
        src = ('// BOUNDED: dashboard shows the latest 50\n'
               'const r = await fetch("https://shop.example.com/admin/api/orders.json?limit=50");')
        self.assertEqual([f for f in scan(src) if f["kind"] == "rest-limit"], [])

    def test_rest_small_limit_not_flagged(self):
        src = 'const r = await fetch("https://shop.example.com/admin/api/orders.json?limit=5");'
        self.assertEqual([f for f in scan(src) if f["kind"] == "rest-limit"], [])

    def test_unread_pageinfo_is_flagged(self):
        src = ("const Q = `query($after: String) { things(first: 50, after: $after) "
               "{ nodes { id } pageInfo { hasNextPage endCursor } } }`;\n"
               "async function once(gql) { return (await gql(Q, {})).things.nodes; }\n")
        found = unread(src)
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["line"], 1)

    def test_unread_pageinfo_dot_access_counts_as_read(self):
        src = ("const Q = `query($after: String) { things(first: 50, after: $after) "
               "{ nodes { id } pageInfo { hasNextPage endCursor } } }`;\n"
               "async function load(gql) { const d = await gql(Q, {});\n"
               "  if (d.things.pageInfo.hasNextPage) throw new Error('truncated'); }\n")
        self.assertEqual(unread(src), [])

    def test_unread_pageinfo_helper_call_counts(self):
        src = ("const Q = `query($after: String) { things(first: 50, after: $after) "
               "{ nodes { id } pageInfo { hasNextPage endCursor } } }`;\n"
               "const rows = await paginate(Q);\n")
        self.assertEqual(unread(src), [])

    def test_unread_pageinfo_bounded_marker(self):
        src = ("// BOUNDED: only the first page is wanted here\n"
               "const Q = `query { things(first: 5) { pageInfo { hasNextPage } } }`;\n")
        self.assertEqual(unread(src), [])

    def test_python_bracket_and_get_reads(self):
        src = ('QUERY = """\nquery($after: String) {\n  things(first: 50, after: $after) {\n'
               '    nodes { id }\n    pageInfo { hasNextPage endCursor }\n  }\n}\n"""\n'
               'def more(conn):\n    return conn["pageInfo"].get("hasNextPage")\n')
        self.assertEqual(unread(src, "x.py"), [])


class WellFormedLoopsStayClean(unittest.TestCase):
    """No new false positives on correct paging code."""

    def test_js_cursor_loop(self):
        src = """\
            const QUERY = `
              query Things($after: String) {
                things(first: 50, after: $after) {
                  nodes { id title }
                  pageInfo { hasNextPage endCursor }
                }
              }
            `;
            async function loadThings(gql) {
              const out = [];
              let after = null;
              for (;;) {
                const data = await gql(QUERY, { after });
                const page = data.things;
                out.push(...page.nodes);
                if (!page.pageInfo.hasNextPage) break;
                after = page.pageInfo.endCursor;
              }
              return out;
            }
        """
        self.assertEqual(scan(src), [])

    def test_python_cursor_loop(self):
        src = '''\
            QUERY = """
            query Things($after: String) {
              things(first: 50, after: $after) {
                nodes { id }
                pageInfo { hasNextPage endCursor }
              }
            }
            """

            def load_things(gql):
                out, after = [], None
                while True:
                    data = gql(QUERY, {"after": after})
                    page = data["things"]
                    out.extend(page["nodes"])
                    info = page["pageInfo"]
                    if not info["hasNextPage"]:
                        break
                    after = info["endCursor"]
                return out
        '''
        self.assertEqual(scan(src, "x.py"), [])

    def test_js_fail_closed_single_page(self):
        src = """\
            const QUERY = `{ things(first: 250) { nodes { id } pageInfo { hasNextPage } } }`;
            async function load(gql) {
              const data = await gql(QUERY);
              if (data.things.pageInfo.hasNextPage) throw new Error("more than 250 things");
              return data.things.nodes;
            }
        """
        self.assertEqual(scan(src), [])

    def test_backward_cursor_loop(self):
        src = """\
            const QUERY = `
              query Things($before: String) {
                things(last: 50, before: $before) {
                  nodes { id }
                  pageInfo { hasPreviousPage startCursor }
                }
              }
            `;
            async function loadBackwards(gql) {
              const out = [];
              let before = null;
              for (;;) {
                const data = await gql(QUERY, { before });
                out.push(...data.things.nodes);
                if (!data.things.pageInfo.hasPreviousPage) break;
                before = data.things.pageInfo.startCursor;
              }
              return out;
            }
        """
        self.assertEqual(scan(src), [])

    def test_directive_on_a_correct_cursor_loop(self):
        src = """\
            const QUERY = `
              query Things($after: String, $withTags: Boolean!) {
                things(first: 50, after: $after) @include(if: $withTags) {
                  nodes { id }
                  pageInfo { hasNextPage endCursor }
                }
              }
            `;
            async function loadThings(gql) {
              let after = null;
              for (;;) {
                const data = await gql(QUERY, { after, withTags: true });
                if (!data.things.pageInfo.hasNextPage) return;
                after = data.things.pageInfo.endCursor;
              }
            }
        """
        self.assertEqual(scan(src), [])


# --------------------------------------------------------------------------------------
# Defect (a): directives between the arguments and the selection set
# --------------------------------------------------------------------------------------
class DirectivesBeforeSelectionSet(unittest.TestCase):
    def test_include_directive_is_still_checked(self):
        found = conn("const q = `query($x: Boolean!) { things(first: 10) @include(if: $x) "
                     "{ nodes { id } } }`;")
        self.assertEqual(len(found), 1)
        self.assertIn("things", found[0]["detail"])

    def test_directive_without_arguments(self):
        self.assertEqual(len(conn("const q = `{ things(first: 10) @live { nodes { id } } }`;")), 1)

    def test_several_directives(self):
        src = "const q = `{ things(first: 10) @include(if: $x) @skip(if: $y) { nodes { id } } }`;"
        self.assertEqual(len(conn(src)), 1)

    def test_directive_on_its_own_line(self):
        found = conn("""\
            const q = `query($x: Boolean!) {
              things(first: 10)
                @include(if: $x)
              {
                nodes { id }
              }
            }`;
        """)
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["line"], 2)

    def test_directive_with_after_cursor_is_fine(self):
        src = "const q = `{ things(first: 10, after: $c) @include(if: $x) { nodes { id } } }`;"
        self.assertEqual(conn(src), [])

    def test_directive_with_own_level_pageinfo_is_fine(self):
        src = ("const q = `{ things(first: 10) @include(if: $x) "
               "{ nodes { id } pageInfo { hasNextPage endCursor } } }`;")
        self.assertEqual(conn(src), [])

    def test_directive_with_bounded_marker_is_fine(self):
        src = "// BOUNDED: top 10 tags\nconst q = `{ things(first: 10) @include(if: $x) { nodes { id } } }`;"
        self.assertEqual(conn(src), [])

    def test_directive_child_pageinfo_does_not_hide_outer(self):
        src = ("const q = `{ things(first: 10) @include(if: $x) { nodes { kids(first: 5) "
               "{ pageInfo { hasNextPage } nodes { id } } } } }`;")
        self.assertEqual([f["detail"].split("(")[0] for f in conn(src)], ["things"])

    def test_directive_in_graphql_file(self):
        found = conn("query Q($x: Boolean!) {\n  things(first: 10) @include(if: $x) {\n    nodes { id }\n  }\n}\n",
                     "q.graphql")
        self.assertEqual([f["line"] for f in found], [2])

    def test_at_sign_after_call_without_selection_is_not_a_connection(self):
        # a decorator-like token that is not followed by a selection set stays ignored
        self.assertEqual(conn("rows = load(first: 10) @cached\n"), [])


class CommentsBeforeSelectionSet(unittest.TestCase):
    """GraphQL comments (`# ...`) are ignored tokens between the arguments and the selection set."""

    def test_comment_between_args_and_selection_set(self):
        found = conn("query { things(first: 10) # fetch things\n { nodes { id } } }", "q.graphql")
        self.assertEqual([f["line"] for f in found], [1])

    def test_comment_on_its_own_line(self):
        found = conn("""\
            query {
              things(first: 10)
              # the selection set follows
              { nodes { id } }
            }
        """, "q.graphql")
        self.assertEqual([f["line"] for f in found], [2])

    def test_comments_and_directives_interleaved(self):
        src = ("const q = `{ things(first: 10) # a\n @include(if: $x) # b\n @skip(if: $y) # c\n"
               " { nodes { id } } }`;")
        self.assertEqual(len(conn(src)), 1)

    def test_brace_inside_comment_is_not_the_selection_set(self):
        src = "const q = `{ things(first: 10) # not { this }\n { nodes { id } pageInfo { hasNextPage } } }`;"
        self.assertEqual(conn(src), [])
        src = "const q = `{ things(first: 10) # not { this }\n { nodes { id } } }`;"
        self.assertEqual(len(conn(src)), 1)

    def test_comment_with_after_cursor_is_fine(self):
        self.assertEqual(conn("query { things(first: 10, after: $c) # page\n { nodes { id } } }", "q.graphql"), [])

    def test_comment_with_own_level_pageinfo_is_fine(self):
        src = "query { things(first: 10) # page\n { nodes { id } pageInfo { hasNextPage endCursor } } }"
        self.assertEqual(conn(src, "q.graphql"), [])

    def test_bounded_marker_in_the_comment(self):
        self.assertEqual(conn("query { things(first: 10) # BOUNDED: top 10\n { nodes { id } } }", "q.graphql"), [])


class CommasBeforeSelectionSet(unittest.TestCase):
    """Commas are ignored tokens in GraphQL, like whitespace and comments."""

    def test_comma_between_args_and_selection_set(self):
        found = conn("query { things(first: 10), { nodes { id } } }", "q.graphql")
        self.assertEqual([f["line"] for f in found], [1])

    def test_comma_before_a_directive(self):
        self.assertEqual(len(conn("query { things(first: 10), @include(if: $x) { nodes { id } } }", "q.graphql")), 1)

    def test_commas_comments_and_directives_mixed(self):
        src = "query { things(first: 10) , # c\n , @include(if: $x) , @skip(if: $y)\n , { nodes { id } } }"
        self.assertEqual(len(conn(src, "q.graphql")), 1)

    def test_comma_with_own_level_pageinfo_or_cursor_is_fine(self):
        self.assertEqual(conn("query { things(first: 10), { nodes { id } pageInfo { hasNextPage } } }", "q.graphql"), [])
        self.assertEqual(conn("query { things(first: 10, after: $c), { nodes { id } } }", "q.graphql"), [])

    def test_comma_then_non_selection_is_not_a_connection(self):
        self.assertEqual(conn("rows = [load(first: 10), other]\n", "x.js"), [])


# --------------------------------------------------------------------------------------
# Defect (b): backward pagination metadata must not satisfy a forward connection
# --------------------------------------------------------------------------------------
class PagingDirection(unittest.TestCase):
    def test_forward_connection_with_only_backward_pageinfo_is_a_finding(self):
        src = "const q = `{ things(first: 10) { pageInfo { hasPreviousPage startCursor } nodes { id } } }`;"
        found = conn(src)
        self.assertEqual(len(found), 1)
        self.assertIn("things", found[0]["detail"])

    def test_forward_connection_with_backward_pageinfo_multiline(self):
        found = conn("""\
            const q = `{
              things(first: 10) {
                nodes { id }
                pageInfo {
                  hasPreviousPage
                  startCursor
                }
              }
            }`;
        """)
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["line"], 2)

    def test_forward_connection_with_only_cursors_is_a_finding(self):
        self.assertEqual(len(conn("const q = `{ things(first: 10) { nodes { id } pageInfo { endCursor } } }`;")), 1)
        self.assertEqual(len(conn("const q = `{ things(first: 10) { nodes { id } pageInfo { startCursor } } }`;")), 1)

    def test_forward_connection_with_forward_pageinfo_ok(self):
        self.assertEqual(
            conn("const q = `{ things(first: 10) { nodes { id } pageInfo { hasNextPage endCursor } } }`;"), [])

    def test_forward_connection_with_both_directions_ok(self):
        src = ("const q = `{ things(first: 10) { nodes { id } "
               "pageInfo { hasNextPage hasPreviousPage startCursor endCursor } } }`;")
        self.assertEqual(conn(src), [])

    def test_backward_connection_with_backward_pageinfo_ok(self):
        self.assertEqual(
            conn("const q = `{ things(last: 10) { nodes { id } pageInfo { hasPreviousPage startCursor } } }`;"), [])

    def test_backward_connection_with_only_forward_pageinfo_is_a_finding(self):
        found = conn("const q = `{ things(last: 10) { nodes { id } pageInfo { hasNextPage endCursor } } }`;")
        self.assertEqual(len(found), 1)
        self.assertIn("things", found[0]["detail"])

    def test_backward_connection_without_pageinfo_is_a_finding(self):
        self.assertEqual(len(conn("const q = `{ things(last: 10) { nodes { id } } }`;")), 1)

    def test_backward_connection_with_before_cursor_ok(self):
        self.assertEqual(conn("const q = `{ things(last: 10, before: $c) { nodes { id } } }`;"), [])

    def test_backward_pageinfo_does_not_hide_forward_connection_in_a_real_file(self):
        src = """\
            const QUERY = `
              query {
                things(first: 10) {
                  nodes { id }
                  pageInfo { hasPreviousPage startCursor }
                }
              }
            `;
            async function load(gql) {
              const data = await gql(QUERY);
              return data.things.nodes;
            }
        """
        self.assertEqual(len(conn(src)), 1)

    def test_backward_marker_still_exempts(self):
        src = "// BOUNDED: newest 10\nconst q = `{ things(last: 10) { nodes { id } } }`;"
        self.assertEqual(conn(src), [])


# --------------------------------------------------------------------------------------
# Defect (c): destructuring reads the paging state
# --------------------------------------------------------------------------------------
JS_LOOP = (
    "const QUERY = `query($after: String) { things(first: 50, after: $after) "
    "{ nodes { id } pageInfo { hasNextPage endCursor } } }`;\n"
    "async function loadThings(gql) {\n"
    "  let after = null;\n"
    "  for (;;) {\n"
    "    const data = await gql(QUERY, { after });\n"
    "@@READ@@\n"
    "    if (!hasNextPage) break;\n"
    "    after = endCursor;\n"
    "  }\n"
    "}\n"
)


def js_loop(read_lines):
    """A cursor loop whose paging state is read by `read_lines` (source text)."""
    body = textwrap.indent(textwrap.dedent(read_lines).strip("\n"), "    ")
    return JS_LOOP.replace("@@READ@@", body)


class DestructuringCountsAsReading(unittest.TestCase):
    def check_read(self, read_lines):
        src = js_loop(read_lines)
        self.assertEqual(unread(src), [], msg="false pageinfo-unread for:\n" + src)

    def test_nested_pageinfo_destructuring(self):
        self.check_read("const { pageInfo: { hasNextPage, endCursor } } = data.things;")

    def test_flat_destructuring_from_pageinfo(self):
        self.check_read("const { hasNextPage, endCursor } = data.things.pageInfo;")

    def test_flat_destructuring_from_alias(self):
        self.check_read("const { hasNextPage, endCursor } = conn.pageInfo;")

    def test_multi_property_destructuring(self):
        self.check_read("const { hasNextPage, endCursor, hasPreviousPage, startCursor } = conn.pageInfo;")

    def test_multi_property_destructuring_cursor_last(self):
        self.check_read("const { startCursor, hasNextPage, endCursor } = conn.pageInfo;")

    def test_multiline_nested_destructuring(self):
        self.check_read("""\
            const {
              pageInfo: {
                startCursor,
                hasNextPage,
                endCursor,
              },
            } = data.things;
        """)

    def test_destructuring_with_defaults(self):
        self.check_read("const { hasNextPage = false, endCursor = null } = conn.pageInfo;")

    def test_assignment_destructuring(self):
        self.check_read("let hasNextPage, endCursor;\n({ hasNextPage, endCursor } = conn.pageInfo);")

    def test_cursor_only_destructuring(self):
        src = js_loop("const { endCursor } = conn.pageInfo;\nconst hasNextPage = endCursor !== null;")
        self.assertEqual(unread(src), [])

    def test_python_subscript_style(self):
        src = '''\
            QUERY = """
            query($after: String) {
              things(first: 50, after: $after) { nodes { id } pageInfo { hasNextPage endCursor } }
            }
            """

            def load(gql):
                d = gql(QUERY, {"after": None})["things"]
                page_info = d["pageInfo"]
                if page_info["hasNextPage"]:
                    return d["nodes"], page_info["endCursor"]
                return d["nodes"], None
        '''
        self.assertEqual(unread(src, "x.py"), [])

    def test_unrelated_destructuring_is_not_a_read(self):
        src = js_loop("const { foo, bar } = other;")
        self.assertEqual(len(unread(src)), 1)

    def test_query_text_alone_is_not_a_read(self):
        src = ("const Q = `query($after: String) { things(first: 50, after: $after) "
               "{ nodes { id } pageInfo { hasNextPage endCursor } } }`;\n"
               "const rows = (await gql(Q)).things.nodes;\n"
               "const total = rows.length;\n")
        self.assertEqual(len(unread(src)), 1)

    def test_plain_object_literal_is_not_a_read(self):
        src = ("const Q = `query($after: String) { things(first: 50, after: $after) "
               "{ nodes { id } pageInfo { hasNextPage endCursor } } }`;\n"
               "const initial = { hasNextPage: false, endCursor: null };\n"
               "const rows = (await gql(Q)).things.nodes;\n")
        self.assertEqual(len(unread(src)), 1)


# --------------------------------------------------------------------------------------
# CLI behaviour: exit codes, --json, ignore file, skip dirs, version, header
# --------------------------------------------------------------------------------------
class Cli(TempDirCase):
    def test_exit_1_on_unbounded_finding(self):
        self.write("a.js", UNBOUNDED_JS)
        r = run_guard(["."], self.tmp)
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("a.js:1: [graphql-connection]", r.stdout)

    def test_exit_0_when_clean(self):
        self.write("a.js", "const q = `{ things(first: 10, after: $c) { nodes { id } } }`;\n")
        r = run_guard(["."], self.tmp)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("OK (1 files)", r.stderr)

    def test_exit_0_when_bounded(self):
        self.write("a.js", "// BOUNDED: lookup\nconst q = `{ things(first: 1) { nodes { id } } }`;\n")
        self.assertEqual(run_guard(["."], self.tmp).returncode, 0)

    def test_json_output(self):
        self.write("a.js", UNBOUNDED_JS)
        r = run_guard(["--json", "."], self.tmp)
        self.assertEqual(r.returncode, 1)
        data = json.loads(r.stdout)
        self.assertEqual(len(data), 1)
        self.assertEqual(sorted(data[0]), ["detail", "file", "kind", "line", "snippet"])
        self.assertEqual((data[0]["file"], data[0]["line"], data[0]["kind"]), ("a.js", 1, "graphql-connection"))

    def test_json_output_when_clean_is_empty_list(self):
        self.write("a.js", "const x = 1;\n")
        r = run_guard(["--json", "."], self.tmp)
        self.assertEqual(r.returncode, 0)
        self.assertEqual(json.loads(r.stdout), [])

    def test_ignore_file_exact_and_prefix_and_suffix(self):
        self.write("a.js", UNBOUNDED_JS)
        self.write("legacy/b.js", UNBOUNDED_JS)
        self.write("c.test.js", UNBOUNDED_JS)
        self.write("keep.js", UNBOUNDED_JS)
        self.write(".pagination-guard-ignore", "# reasons\na.js\nlegacy\n*.test.js\n")
        r = run_guard(["--json", "."], self.tmp)
        self.assertEqual([f["file"] for f in json.loads(r.stdout)], ["keep.js"])

    def test_skip_dirs_and_extensions(self):
        self.write("node_modules/dep/index.js", UNBOUNDED_JS)
        self.write("dist/out.js", UNBOUNDED_JS)
        self.write("notes.txt", UNBOUNDED_JS)
        self.write("app.min.js", UNBOUNDED_JS)
        r = run_guard(["--json", "."], self.tmp)
        self.assertEqual(json.loads(r.stdout), [])

    def test_scans_explicit_file_argument(self):
        path = self.write("a.js", UNBOUNDED_JS)
        r = run_guard(["--json", path], self.tmp)
        self.assertEqual(len(json.loads(r.stdout)), 1)

    def test_version_flag_prints_guard_version(self):
        r = run_guard(["--version"], self.tmp)
        self.assertEqual(r.returncode, 0, r.stderr)
        version = r.stdout.strip()
        self.assertRegex(version, r"^\d{4}-\d{2}-\d{2}(\.\d+)?$")
        self.assertEqual(version, guard.GUARD_VERSION)

    def test_version_flag_does_not_scan(self):
        self.write("a.js", UNBOUNDED_JS)
        r = run_guard(["--version"], self.tmp)
        self.assertEqual(r.returncode, 0)
        self.assertNotIn("graphql-connection", r.stdout)

    def test_sync_header_names_the_canonical_location(self):
        with open(SCRIPT, encoding="utf-8") as fh:
            head = fh.read(4000)
        self.assertIn("SYNC: pagination_guard", head)
        self.assertIn("Fuzzywumpets/claude-bootstrap scripts/pagination_guard.py", head)
        self.assertNotIn("C:/Users/AlexLass", head)

    def test_stdlib_only(self):
        with open(SCRIPT, encoding="utf-8") as fh:
            tree = ast.parse(fh.read())
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(a.name.split(".")[0] for a in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".")[0])
        allowed = set(getattr(sys, "stdlib_module_names", ())) or {"json", "os", "re", "subprocess", "sys"}
        self.assertLessEqual(imported, allowed)


# --------------------------------------------------------------------------------------
# Defect (d): --git-staged must include renamed (and copied) files
# --------------------------------------------------------------------------------------
class GitStaged(TempDirCase):
    def git(self, *args):
        r = subprocess.run(["git"] + list(args), cwd=self.tmp, env=clean_env(),
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, "git %s failed: %s" % (" ".join(args), r.stderr))
        return r.stdout

    def init_repo(self, renames="true"):
        self.git("init", "-q")
        self.git("config", "user.email", "t@example.invalid")
        self.git("config", "user.name", "test")
        self.git("config", "commit.gpgsign", "false")
        self.git("config", "diff.renames", renames)
        self.git("config", "core.hooksPath", os.devnull)

    CODE = ("// helpers shared by the order screens\n"
            "const A = 1;\nconst B = 2;\nconst C = 3;\nconst D = 4;\n"
            "const QUERY = `{ things(first: 10) { nodes { id } } }`;\n"
            "module.exports = { QUERY, A, B, C, D };\n")

    def test_staged_rename_is_scanned(self):
        self.init_repo()
        self.write("old_name.js", self.CODE)
        self.git("add", "old_name.js")
        self.git("commit", "-q", "-m", "init")
        self.git("mv", "old_name.js", "new_name.js")
        status = self.git("diff", "--cached", "--name-status")
        self.assertTrue(status.startswith("R"), "fixture is not a rename: %r" % status)
        r = run_guard(["--git-staged", "--json"], self.tmp)
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        found = json.loads(r.stdout)
        self.assertEqual([(f["file"], f["kind"]) for f in found], [("new_name.js", "graphql-connection")])

    def test_staged_rename_with_small_edit_is_scanned(self):
        self.init_repo()
        self.write("old_name.js", self.CODE)
        self.git("add", "old_name.js")
        self.git("commit", "-q", "-m", "init")
        self.git("mv", "old_name.js", "new_name.js")
        self.write("new_name.js", self.CODE + "const E = 5;\n")
        self.git("add", "new_name.js")
        r = run_guard(["--git-staged", "--json"], self.tmp)
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertEqual([f["file"] for f in json.loads(r.stdout)], ["new_name.js"])

    def test_staged_rename_into_subdirectory_is_scanned(self):
        self.init_repo()
        self.write("old_name.js", self.CODE)
        self.git("add", "old_name.js")
        self.git("commit", "-q", "-m", "init")
        os.makedirs(os.path.join(self.tmp, "src"))
        self.git("mv", "old_name.js", "src/new_name.js")
        r = run_guard(["--git-staged", "--json"], self.tmp)
        self.assertEqual([f["file"] for f in json.loads(r.stdout)], ["src/new_name.js"])

    def test_staged_added_and_modified_files_are_scanned(self):
        self.init_repo()
        self.write("mod.js", "const x = 1;\n")
        self.git("add", "mod.js")
        self.git("commit", "-q", "-m", "init")
        self.write("mod.js", self.CODE)
        self.write("added.js", self.CODE)
        self.git("add", "mod.js", "added.js")
        r = run_guard(["--git-staged", "--json"], self.tmp)
        self.assertEqual(sorted(f["file"] for f in json.loads(r.stdout)), ["added.js", "mod.js"])

    def test_staged_copy_is_scanned(self):
        self.init_repo(renames="copies")
        self.write("orig.js", self.CODE)
        self.git("add", "orig.js")
        self.git("commit", "-q", "-m", "init")
        self.write("orig.js", self.CODE + "const E = 5;\n")
        self.write("copy.js", self.CODE)
        self.git("add", "orig.js", "copy.js")
        r = run_guard(["--git-staged", "--json"], self.tmp)
        self.assertEqual(sorted(f["file"] for f in json.loads(r.stdout)), ["copy.js", "orig.js"])

    def test_unstaged_and_deleted_files_are_not_scanned(self):
        self.init_repo()
        self.write("gone.js", self.CODE)
        self.write("kept.js", "const x = 1;\n")
        self.git("add", "gone.js", "kept.js")
        self.git("commit", "-q", "-m", "init")
        self.git("rm", "-q", "gone.js")
        self.write("kept.js", self.CODE)          # modified but not staged
        r = run_guard(["--git-staged", "--json"], self.tmp)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual(json.loads(r.stdout), [])

    def test_staged_non_code_files_are_not_scanned(self):
        self.init_repo()
        self.write("notes.txt", self.CODE)
        self.git("add", "notes.txt")
        r = run_guard(["--git-staged", "--json"], self.tmp)
        self.assertEqual(json.loads(r.stdout), [])

    def test_staged_content_is_scanned_not_the_working_tree(self):
        self.init_repo()
        self.write("a.js", UNBOUNDED_JS)
        self.git("add", "a.js")
        self.write("a.js", "const x = 1;\n")           # clean, but NOT staged
        r = run_guard(["--git-staged", "--json"], self.tmp)
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertEqual([f["file"] for f in json.loads(r.stdout)], ["a.js"])

    def test_staged_file_deleted_from_working_tree_is_still_scanned(self):
        self.init_repo()
        self.write("a.js", UNBOUNDED_JS)
        self.git("add", "a.js")
        os.remove(os.path.join(self.tmp, "a.js"))      # still in the index
        r = run_guard(["--git-staged", "--json"], self.tmp)
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertEqual([f["file"] for f in json.loads(r.stdout)], ["a.js"])

    def test_clean_staged_content_passes_even_if_working_tree_is_dirty(self):
        self.init_repo()
        self.write("a.js", "const x = 1;\n")
        self.git("add", "a.js")
        self.write("a.js", UNBOUNDED_JS)               # dirty, but NOT staged
        r = run_guard(["--git-staged", "--json"], self.tmp)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual(json.loads(r.stdout), [])

    def test_staged_non_ascii_and_spaced_filenames_are_scanned(self):
        self.init_repo()
        self.git("config", "core.quotePath", "true")   # git's default: non-ASCII names come back quoted
        self.write(u"caf\u00e9.js", UNBOUNDED_JS)
        self.write("with space.js", UNBOUNDED_JS)
        self.git("add", "--all")
        r = run_guard(["--git-staged", "--json"], self.tmp)
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertEqual(sorted(f["file"] for f in json.loads(r.stdout)), sorted([u"caf\u00e9.js", "with space.js"]))

    def test_staged_scan_from_a_subdirectory_uses_repo_relative_names(self):
        self.init_repo()
        self.write("sub/inner.js", UNBOUNDED_JS)
        self.write("outer.js", UNBOUNDED_JS)
        self.git("add", "--all")
        r = run_guard(["--git-staged", "--json"], os.path.join(self.tmp, "sub"))
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertEqual(sorted(f["file"] for f in json.loads(r.stdout)), ["outer.js", "sub/inner.js"])

    def test_staged_scan_from_a_subdirectory_honours_the_repo_root_ignore_file(self):
        self.init_repo()
        self.write("sub/inner.js", UNBOUNDED_JS)
        self.write("sub/other.js", UNBOUNDED_JS)
        self.write(".pagination-guard-ignore", "sub/inner.js\n")
        self.git("add", "--all")
        from_root = run_guard(["--git-staged", "--json"], self.tmp)
        from_sub = run_guard(["--git-staged", "--json"], os.path.join(self.tmp, "sub"))
        self.assertEqual([f["file"] for f in json.loads(from_root.stdout)], ["sub/other.js"])
        self.assertEqual(from_sub.stdout, from_root.stdout)
        self.assertEqual(from_sub.returncode, 1)

    def test_git_failure_is_an_error_not_a_clean_scan(self):
        # not a git repository (GIT_CEILING_DIRECTORIES stops git from finding one in a parent)
        r = run_guard(["--git-staged", "--json"], self.tmp,
                      env_extra={"GIT_CEILING_DIRECTORIES": os.path.dirname(self.tmp)})
        self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
        self.assertEqual(r.stdout.strip(), "")
        self.assertIn("git", r.stderr)

    def test_unstaged_ignore_file_does_not_exempt_staged_code(self):
        self.init_repo()
        self.write("a.js", UNBOUNDED_JS)
        self.git("add", "a.js")
        self.write(".pagination-guard-ignore", "a.js\n")       # not staged: will not be committed
        r = run_guard(["--git-staged", "--json"], self.tmp)
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertEqual([f["file"] for f in json.loads(r.stdout)], ["a.js"])

    def test_staged_ignore_file_exempts_staged_code(self):
        self.init_repo()
        self.write("a.js", UNBOUNDED_JS)
        self.write("b.js", UNBOUNDED_JS)
        self.write(".pagination-guard-ignore", "# reasons\na.js\n")
        self.git("add", "a.js", "b.js", ".pagination-guard-ignore")
        r = run_guard(["--git-staged", "--json"], self.tmp)
        self.assertEqual([f["file"] for f in json.loads(r.stdout)], ["b.js"])

    def test_staged_ignore_file_is_read_from_the_index(self):
        self.init_repo()
        self.write("a.js", UNBOUNDED_JS)
        self.write(".pagination-guard-ignore", "a.js\n")
        self.git("add", "a.js", ".pagination-guard-ignore")
        self.write(".pagination-guard-ignore", "# emptied but not staged\n")
        r = run_guard(["--git-staged", "--json"], self.tmp)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual(json.loads(r.stdout), [])


    def test_staged_type_change_to_regular_file_is_scanned(self):
        self.init_repo()
        link = os.path.join(self.tmp, "a.js")
        try:
            os.symlink("target.txt", link)
        except (AttributeError, NotImplementedError, OSError):
            self.skipTest("symlinks unavailable")
        self.git("add", "a.js")
        self.git("commit", "-q", "-m", "symlink")
        os.remove(link)
        self.write("a.js", UNBOUNDED_JS)               # now a regular file: git status type T
        self.git("add", "a.js")
        self.assertTrue(self.git("diff", "--cached", "--name-status").startswith("T"))
        r = run_guard(["--git-staged", "--json"], self.tmp)
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertEqual([f["file"] for f in json.loads(r.stdout)], ["a.js"])


# --------------------------------------------------------------------------------------
# DeepReview round 4: cursor-like text inside string values, directives on pageInfo
# --------------------------------------------------------------------------------------
class CursorTextInsideStrings(unittest.TestCase):
    def test_after_text_in_a_string_argument_is_not_a_cursor(self):
        self.assertEqual(len(conn('const q = `{ things(first: 10, query: "after:foo") { nodes { id } } }`;')), 1)

    def test_before_text_in_a_string_argument_is_not_a_cursor(self):
        self.assertEqual(len(conn('const q = `{ things(last: 10, query: "created before: 2024") { nodes { id } } }`;')), 1)

    def test_block_string_argument_is_not_a_cursor(self):
        self.assertEqual(len(conn('const q = `{ things(first: 10, query: """x after: y""") { nodes { id } } }`;')), 1)

    def test_escaped_quote_string_inside_a_js_string_is_not_a_cursor(self):
        self.assertEqual(len(conn('const q = "{ things(first: 10, query: \\"after:foo\\") { nodes { id } } }";')), 1)

    def test_real_cursor_next_to_a_string_argument_still_satisfies(self):
        self.assertEqual(conn('const q = `{ things(first: 10, query: "status:open", after: $cursor) { nodes { id } } }`;'), [])

    def test_cursor_argument_after_a_string_containing_a_quote(self):
        self.assertEqual(conn('const q = `{ things(first: 10, query: "a \\" b", after: $c) { nodes { id } } }`;'), [])


class DirectivesOnPageInfo(unittest.TestCase):
    OK = ("const q = `{ things(first: 10) { nodes { id } pageInfo %s { hasNextPage endCursor } } }`;\n"
          "const more = res.data.things.pageInfo.hasNextPage;")

    def test_directive_with_arguments_on_pageinfo_satisfies(self):
        self.assertEqual(scan(self.OK % "@include(if: true)"), [])

    def test_directive_without_arguments_on_pageinfo_satisfies(self):
        self.assertEqual(scan(self.OK % "@live"), [])

    def test_several_directives_and_a_comment_on_pageinfo(self):
        self.assertEqual(scan(self.OK % "@a @b(x: 1) # note\n"), [])

    def test_backward_pageinfo_with_directive_satisfies_last(self):
        self.assertEqual(conn("const q = `{ things(last: 10) { nodes { id } pageInfo @live { hasPreviousPage } } }`;"), [])

    def test_directive_on_pageinfo_with_wrong_direction_is_still_flagged(self):
        self.assertEqual(len(conn("const q = `{ things(first: 10) { nodes { id } pageInfo @live { hasPreviousPage } } }`;")), 1)

    def test_js_object_literal_after_pageinfo_is_not_a_query(self):
        src = "assert.deepEqual(state.pageInfo, { hasNextPage: false, endCursor: null });"
        self.assertEqual(scan(src), [])

    def test_unread_pageinfo_with_directive_is_still_flagged(self):
        found = unread("const q = `{ things(first: 10) { nodes { id } pageInfo @live { hasNextPage } } }`;")
        self.assertEqual(len(found), 1)


# --------------------------------------------------------------------------------------
# DeepReview round 5: direction from string contents, nested input properties, aliases
# --------------------------------------------------------------------------------------
class ArgumentsAreReadAtTopLevelOnly(unittest.TestCase):
    def test_first_inside_a_string_does_not_change_the_direction(self):
        src = ('const q = `{ things(last: 10, query: "first:foo") { nodes { id } '
               'pageInfo { hasNextPage } } }`;\nconst more = data.things.pageInfo.hasNextPage;')
        self.assertEqual(len(conn(src)), 1)

    def test_nested_after_in_an_input_object_is_not_a_cursor(self):
        self.assertEqual(len(conn('const q = `{ things(first: 10, filter: { after: "2024-01-01" }) { nodes { id } } }`;')), 1)

    def test_nested_before_in_a_list_of_inputs_is_not_a_cursor(self):
        self.assertEqual(len(conn('const q = `{ things(last: 10, filters: [{ before: 3 }]) { nodes { id } } }`;')), 1)

    def test_top_level_cursor_next_to_a_nested_input_still_satisfies(self):
        self.assertEqual(conn('const q = `{ things(first: 10, filter: { status: "open" }, after: $c) { nodes { id } } }`;'), [])


class AliasesAreNotFields(unittest.TestCase):
    TAIL = "\nconst more = result.things.pageInfo.hasNextPage;"

    def test_alias_named_hasnextpage_for_haspreviouspage_does_not_satisfy_forward(self):
        src = "const q = `{ things(first: 10) { nodes { id } pageInfo { hasNextPage: hasPreviousPage } } }`;" + self.TAIL
        self.assertEqual(len(conn(src)), 1)

    def test_alias_does_not_suppress_the_unread_warning(self):
        src = "const q = `{ things(first: 10) { nodes { id } pageInfo { hasNextPage: hasPreviousPage } } }`;"
        self.assertEqual(len(conn(src)), 1)
        self.assertEqual(len(unread("const q = `{ x { pageInfo { hasNextPage: hasPreviousPage } } }`;")), 0)  # not a hasNextPage request at all

    def test_real_field_under_an_alias_still_satisfies(self):
        src = "const q = `{ things(first: 10) { nodes { id } pageInfo { more: hasNextPage } } }`;" + self.TAIL.replace("hasNextPage", "more")
        self.assertEqual(conn(src), [])

    def test_alias_for_the_right_field_next_to_the_real_one(self):
        src = "const q = `{ things(first: 10) { nodes { id } pageInfo { hasNextPage hasPreviousPage: hasNextPage } } }`;" + self.TAIL
        self.assertEqual(conn(src), [])



# --------------------------------------------------------------------------------------
# DeepReview (tools-mcp #5, 2026-11-08): commented arguments; the comma-before-pageInfo rule
# --------------------------------------------------------------------------------------
class CommentedArgumentsAreNotArguments(unittest.TestCase):
    """`# comments` inside the argument list are ignored tokens, never cursor or direction arguments."""

    def test_commented_after_is_not_a_cursor(self):
        # the exact DeepReview case: the cursor was commented out, the query reads page one only
        found = conn("query { orders(first: 100 # after: $cursor\n) { nodes { id } } }", "q.graphql")
        self.assertEqual([f["line"] for f in found], [1])

    def test_commented_before_is_not_a_cursor_for_last(self):
        self.assertEqual(len(conn("query { orders(last: 5 # before: $c\n) { nodes { id } } }", "q.graphql")), 1)

    def test_commented_cursor_in_a_one_line_js_string(self):
        # inside a JS string the GraphQL line ends at the `\n` escape
        self.assertEqual(len(conn('const q = "query { orders(first: 100 # after: $c\\n) { nodes { id } } }";')), 1)

    def test_comment_ends_at_a_newline_escape_so_the_real_cursor_counts(self):
        self.assertEqual(conn('const q = "query { orders(first: 100 # page\\n after: $c) { nodes { id } } }";'), [])

    def test_real_cursor_after_a_comment_on_its_own_line(self):
        src = "query {\n  orders(\n    first: 10, # page size\n    after: $c\n  ) { nodes { id } }\n}"
        self.assertEqual(conn(src, "q.graphql"), [])

    def test_hash_inside_a_string_value_is_not_a_comment(self):
        self.assertEqual(conn('const q = `{ orders(first: 10, query: "tag:#x", after: $c) { nodes { id } } }`;'), [])

    def test_block_string_quotes_inside_a_comment_do_not_hide_the_cursor(self):
        src = 'query { orders(first: 10 # no """ here\n after: $c, query: """x""") { nodes { id } } }'
        self.assertEqual(conn(src, "q.graphql"), [])

    def test_js_private_field_is_not_a_comment(self):
        self.assertEqual(conn("const q = `{ orders(first: ${this.#n}, after: $c) { nodes { id } } }`;"), [])

    def test_ruby_interpolation_is_not_a_comment(self):
        self.assertEqual(conn('q = "{ orders(first: 10, query: #{q}, after: $c) { nodes { id } } }"\n', "x.rb"), [])

    def test_commented_last_does_not_change_the_direction(self):
        # forward connection whose only metadata is backward: a commented `last:` must not make it "both ways"
        src = "query { orders(first: 10 # last: 5\n) { nodes { id } pageInfo { hasPreviousPage } } }"
        self.assertEqual(len(conn(src, "q.graphql")), 1)


class CommaBeforePageInfoSelectionFailsClosed(unittest.TestCase):
    """Documented rule (KNOWN LIMITS): `pageInfo, { ... }` is not read as a pageInfo selection."""

    def test_comma_before_pageinfo_selection_is_a_finding(self):
        src = ("query { orders(first: 10) { nodes { id } pageInfo, { hasNextPage } } }\n"
               "if (result.orders.pageInfo.hasNextPage) throw Error('overflow');")
        found = conn(src)
        self.assertEqual([f["line"] for f in found], [1])

    def test_without_the_comma_the_same_query_passes(self):
        src = ("query { orders(first: 10) { nodes { id } pageInfo { hasNextPage } } }\n"
               "if (result.orders.pageInfo.hasNextPage) throw Error('overflow');")
        self.assertEqual(scan(src), [])

    def test_js_call_with_shorthand_object_is_not_a_pageinfo_request(self):
        # the reason for the rule: with commas allowed this JS would read as an unread pageInfo request
        self.assertEqual(scan("assert.deepEqual(pageInfo, { hasNextPage, endCursor });\n"), [])

    def test_version_was_bumped(self):
        self.assertEqual(guard.GUARD_VERSION, "2026-11-08.4")


if __name__ == "__main__":
    unittest.main()
