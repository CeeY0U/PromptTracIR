"""Agent shell wrappers: recover the command a tool call actually asked for (v0.6).

Some agent runtimes do not start the tool's command directly. Claude Code on Windows runs every
Bash tool call through Git Bash inside a wrapper that restores its shell snapshot, sets TEMP and
records the working directory afterwards:

    "C:\\Program Files\\Git\\bin\\bash.exe" -c "source /c/Users/lab/.claude/shell-snapshots/snapshot-bash-....sh
        2>/dev/null || true && export TEMP='C:\\Users\\lab\\AppData\\Local\\Temp' ... &&
        eval 'mkdir -p /tmp/x && curl ... -w \\"%%{http_code}\\n\\" http://...' < /dev/null
        && pwd -P >| /c/Users/lab/AppData/Local/Temp/claude-afa5-cwd"

Sysmon records the whole wrapper. Comparing it with the transcript's command, or reading paths
out of it, mixes the runtime's bookkeeping (the snapshot file, TEMP, the cwd file) into the
tool call. ``unwrap`` returns the command inside ``eval '...'`` with the wrapper's escaping
undone, or None when the command line is not a known wrapper.

Escaping undone, in order: the Windows command line quotes the -c argument, so ``\\"`` is ``"``;
bash single quotes encode a quote as ``'\\''``; Claude Code doubles ``%`` (cmd.exe style), which
bash passes through unchanged, so ``%%`` in the record is ``%`` in the transcript.
"""
from __future__ import annotations

import re

_C_ARG = re.compile(r'\s-c\s+"(.*)"\s*$', re.S)
_EVAL = re.compile(r"\beval '(.*)' < /dev/null && pwd -P >\| \S*claude-[0-9a-f]+-cwd\s*$", re.S)
# the file the wrapper writes after every call (its working-directory record), and the shell
# snapshot it reads before every call. A tool that WRITES a snapshot is not exempt: a changed
# snapshot runs in every later Bash call, so it stays a finding.
WRAPPER_WRITES = [r"\\appdata\\local\\temp\\claude-[0-9a-f]+-cwd$"]
WRAPPER_READS = WRAPPER_WRITES + [r"\\\.claude\\shell-snapshots\\snapshot-[^\\]+\.sh$"]


def unwrap(command_line: str | None) -> str | None:
    """The tool command inside a Claude Code Bash wrapper, or None for any other command line."""
    if not command_line or "shell-snapshots" not in command_line or "eval '" not in command_line:
        return None
    m = _C_ARG.search(command_line)
    if not m:
        return None
    arg = m.group(1).replace('\\"', '"')
    e = _EVAL.search(arg)
    if not e:
        return None
    return e.group(1).replace("'\\''", "'").replace("%%", "%")


def effective_command(command_line: str | None) -> str | None:
    """The command to compare with a tool call: the wrapped command if there is one."""
    return unwrap(command_line) or command_line


def is_wrapper_state(path: str, written: bool = False) -> bool:
    """A file the wrapper itself uses: written (the cwd record) or referenced (also the snapshot)."""
    p = (path or "").replace("/", "\\").lower()
    return any(re.search(r, p) for r in (WRAPPER_WRITES if written else WRAPPER_READS))
