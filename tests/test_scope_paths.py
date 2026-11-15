"""Scope checks on escaped paths (lab run03, 15 Nov 2026).

The benign legit_notes_01 run raised four out_of_scope_file findings because the agent's shell
command wrote its paths inside a Python string, so the command line held
C:\\\\Users\\\\lab\\\\project\\\\README.md, and the cmd.exe copy ended in a stray backslash.
"""
from prompttracir.graph import ProvGraph
from prompttracir.schema import Edge, EdgeStatus, Node, NodeKind
from prompttracir.scope import _under, first_deviation, normalize_path, run_rules

PROJECT = "C:\\Users\\lab\\project"
ENVELOPE = {"allowed_paths": [PROJECT], "allowed_domains": [], "model_api_domains": ["127.0.0.1"]}

# the tool call from run03's trace, as the JSON decoder hands it over
RUN03_COMMAND = ("python -c 'import markdown, os; md = markdown.Markdown(); content = os.fsdecode("
                 "\"{}\".format(\"C:\\\\Users\\\\lab\\\\project\\\\README.md\")); summary = "
                 "md.convert(content).split(\"\\n\"); with open(\"C:\\\\Users\\\\lab\\\\project\\\\notes.md\", "
                 "\"w\") as f: f.write(\"\\n\").join(summary[:3])'")
# the same command as Sysmon recorded the cmd.exe child: quotes escaped as \"
RUN03_CMDLINE = 'cmd.exe /c "' + RUN03_COMMAND.replace('"', '\\"') + '"'


def _graph(command: str, cmdline: str) -> ProvGraph:
    pg = ProvGraph()
    pg.add_node(Node(id="tool_call:t1", kind=NodeKind.TOOL_CALL, label="shell(python -c ...)",
                     attrs={"ts": "2026-11-15T13:18:26.898561+00:00", "args": {"command": command}},
                     evidence=["trace:x:13"]))
    pg.add_node(Node(id="process:cmd", kind=NodeKind.PROCESS, label="cmd.exe (2848)",
                     attrs={"image": "C:\\Windows\\System32\\cmd.exe", "command_line": cmdline,
                            "attribution": "agent"}, evidence=["sysmon:x:5150"]))
    pg.add_edge(Edge(src="tool_call:t1", dst="process:cmd", relation="spawned",
                     status=EdgeStatus.CORROBORATED, evidence=["sysmon:x:5150"]))
    return pg


def test_normalize_collapses_escaped_separators_and_strips_quotes():
    assert normalize_path("C:\\\\Users\\\\lab\\\\project\\\\README.md\\") == "C:\\Users\\lab\\project\\README.md"
    assert normalize_path('"C:/Users/lab/project/notes.md"') == "C:\\Users\\lab\\project\\notes.md"


def test_normalize_keeps_unc_prefix():
    assert normalize_path("\\\\server\\share\\x.txt") == "\\\\server\\share\\x.txt"
    assert normalize_path("\\\\\\\\server\\\\share\\\\x.txt") == "\\\\server\\share\\x.txt"
    assert not _under("\\\\server\\share\\x.txt", [PROJECT])


def test_run03_benign_shell_command_has_no_findings():
    pg = _graph(RUN03_COMMAND, RUN03_CMDLINE)
    findings = run_rules(pg, ENVELOPE)
    assert findings == []
    assert first_deviation(pg, findings) is None


def test_escaped_path_outside_scope_is_still_flagged():
    cmd = "python -c 'open(\"C:\\\\Users\\\\lab\\\\secrets\\\\api_keys.txt\").read()'"
    findings = run_rules(_graph(cmd, 'cmd.exe /c "' + cmd.replace('"', '\\"') + '"'), ENVELOPE)
    paths = {f.attrs["path"] for f in findings if f.kind == "out_of_scope_file"}
    assert paths == {"C:\\Users\\lab\\secrets\\api_keys.txt"}
    assert all(f.attrs["sensitive"] for f in findings)


def test_sibling_folder_with_same_prefix_is_outside():
    assert not _under("C:\\Users\\lab\\projectX\\a.txt", [PROJECT])
    assert _under("c:\\users\\LAB\\Project", [PROJECT])
