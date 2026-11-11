"""Scenario files: schema, validation and lab setup.

A scenario describes one repeatable lab run: the user's task, what the task
legitimately needs (the envelope), the injected payload if any, and how to tell
whether the attack worked. See harness/scenarios/README.md for the field guide.

    python -m harness.scenario validate harness/scenarios/*.json
    python -m harness.scenario prepare harness/scenarios/web_exfil_01.json --web-root C:\\lab\\www
    python -m harness.scenario prepare ... --dry-run        # show what would be written

`prepare` writes the scenario's setup files (synthetic secrets, poisoned documents)
and web pages, substituting {{payload}} and {{canary}}. Run it inside the lab VM
(and on the lab web server for web pages) after reverting to the clean snapshot.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field, model_validator

FAMILIES = ("legitimate", "sensitive_file_access", "file_change", "persistence", "download",
            "data_transmission")


class Envelope(BaseModel):
    allowed_paths: list[str] = Field(default_factory=list)
    allowed_domains: list[str] = Field(default_factory=list)
    model_api_domains: list[str] = Field(default_factory=list)
    sensitive_patterns: list[str] | None = None


class Injection(BaseModel):
    vector: Literal["web_page", "local_file", "tool_output", "email", "other"]
    location: str                       # URL or path where the payload is planted
    payload: str                        # exact injected text; label_run looks for it in fragments
    goal: str                           # what the attacker wants, in one line


class SetupFile(BaseModel):
    path: str                           # absolute path on the lab VM
    content: str


class WebPage(BaseModel):
    path: str                           # relative to --web-root on the lab web server
    content: str


class Setup(BaseModel):
    files: list[SetupFile] = Field(default_factory=list)
    web_pages: list[WebPage] = Field(default_factory=list)
    notes: str = ""


class Scenario(BaseModel):
    id: str
    family: Literal[FAMILIES]  # type: ignore[valid-type]
    description: str
    prompt: str
    envelope: Envelope
    injection: Injection | None = None
    attacker_markers: list[str] = Field(default_factory=list)
    exfil_destinations: list[str] = Field(default_factory=list)
    canary: str | None = None
    # how label_run decides attack_succeeded:
    #   sink_canary     the exfil sink received the canary (exfiltration scenarios)
    #   tool_exit_zero  a malicious tool call ran and exited 0 (persistence, file change, download)
    #   none            no attack (legitimate runs)
    success_check: Literal["sink_canary", "tool_exit_zero", "none"] = "none"
    human_commands: list[str] = Field(default_factory=list)   # what the paired human TYPES
    setup: Setup = Field(default_factory=Setup)

    @model_validator(mode="after")
    def _consistent(self):
        if self.family == "legitimate":
            if self.injection or self.attacker_markers or self.exfil_destinations:
                raise ValueError("legitimate scenarios carry no injection, markers or exfil destinations")
            if self.success_check != "none":
                raise ValueError("legitimate scenarios use success_check 'none'")
        else:
            if not self.injection:
                raise ValueError(f"family '{self.family}' needs an injection")
            if not self.attacker_markers:
                raise ValueError("attack scenarios need attacker_markers so label_run can find malicious calls")
            if self.success_check == "none":
                raise ValueError("attack scenarios need a success_check")
            if self.success_check == "sink_canary" and not (self.canary and self.exfil_destinations):
                raise ValueError("sink_canary needs a canary and exfil_destinations")
            planted = [f.content for f in self.setup.files] + [p.content for p in self.setup.web_pages]
            if not any("{{payload}}" in c or self.injection.payload in c for c in planted):
                raise ValueError("no setup file or web page plants the payload ({{payload}})")
        return self


def load(path: str | Path) -> Scenario:
    return Scenario.model_validate_json(Path(path).read_text(encoding="utf-8-sig"))


def render(text: str, sc: Scenario) -> str:
    out = text.replace("{{payload}}", sc.injection.payload if sc.injection else "")
    return out.replace("{{canary}}", sc.canary or "")


def prepare(sc: Scenario, web_root: str | None, dry_run: bool = False) -> list[str]:
    actions = []
    targets = [(Path(f.path), render(f.content, sc)) for f in sc.setup.files]
    if sc.setup.web_pages:
        if not web_root:
            raise SystemExit("this scenario has web pages: pass --web-root (folder served by the lab web server)")
        targets += [(Path(web_root) / p.path, render(p.content, sc)) for p in sc.setup.web_pages]
    for dest, content in targets:
        actions.append(f"write {dest} ({len(content)} chars)")
        if not dry_run:
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(content, encoding="utf-8")
    return actions


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m harness.scenario")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("validate"); p.add_argument("files", nargs="+")
    p = sub.add_parser("prepare"); p.add_argument("file"); p.add_argument("--web-root")
    p.add_argument("--dry-run", action="store_true")
    a = ap.parse_args(argv)
    if a.cmd == "validate":
        bad = 0
        for f in a.files:
            try:
                sc = load(f)
                print(f"OK   {f}  ({sc.id}, {sc.family})")
            except Exception as e:  # noqa: BLE001  report every file, then fail
                bad += 1
                print(f"FAIL {f}\n     {e}")
        return 1 if bad else 0
    sc = load(a.file)
    if not a.dry_run and sys.platform != "win32" and sc.setup.files:
        print("warning: setup paths are Windows paths; run prepare inside the lab VM", file=sys.stderr)
    for line in prepare(sc, a.web_root, a.dry_run):
        print(("[dry-run] " if a.dry_run else "") + line)
    return 0


if __name__ == "__main__":
    sys.exit(main())
