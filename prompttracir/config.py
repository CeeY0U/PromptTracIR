"""Attribution and correlation settings (v0.4).

Every weight, threshold and time window the attribution engine uses lives here, so they can
be tuned on the training runs and the values used for a result can be reported with it.

    ptir config > attribution.json          # write the defaults, then edit
    ptir analyze CASE --config attribution.json
    ptir eval-batch runs --reanalyze --config attribution.json --families ...   # tuning loop

A config file only needs the keys it changes; everything else keeps its default. Unknown
keys are rejected so a typo cannot silently fall back to a default. `ptir analyze` writes the
merged settings it used to CASE/output/config.json.

Tune on the training split only (split by attack family, ROADMAP.md section 5) and commit the
final file under configs/ so the report can cite it.
"""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

DEFAULTS: dict = {
    "weights": {
        # agent side
        "linked_tool_call": 3.0,        # created by a linked tool call
        "descendant_of_linked": 2.5,    # below a process a tool call created
        "descendant_of_runtime": 2.0,   # below the agent runtime (python.exe, claude.exe, ...)
        "noninteractive_flags": 0.5,    # -NonInteractive and similar (weak)
        # human side
        "interactive_root": 2.0,        # explorer / terminal ancestor not passing through a runtime
        "psreadline_match": 1.0,        # command appears in PSReadLine history (weak: no timestamps)
        "userassist_launch": 2.0,       # UserAssist says the image was started from the Explorer shell
        "shell_file_open": 1.5,         # a file in the command line was opened through Explorer (LNK / Jump List)
        "shellbag_folder": 0.5,         # the working directory was browsed in Explorer shortly before (weak)
        "outside_agent_session": 1.0,   # started while no agent session was running (weak)
    },
    "decision_margin": 1.5,             # |agent - human| needed for a label; both >= margin is "mixed"
    # agent_probability = 1 / (1 + exp(-(agent - human) / temperature)); tune for calibration
    "calibration_temperature": 1.5,
    "link": {
        "min_score": 0.5,               # tool-call-to-process links below this are dropped
        "window_before_s": 1.0,         # clock-drift tolerance before the tool call
        "window_after_s": 1.0,          # ... and after its result
        "estimate_clock_offset": True,  # learn the trace-to-host clock offset from child PIDs
        "max_clock_offset_s": 120.0,    # ignore PID matches further apart than this
        "assumed_clock_offset_s": 0.0,  # used when no child PID is available (Claude Code)
        "script_block_similarity": 0.8,  # 4104 text vs tool command, to count as a match
    },
    "human": {
        "userassist_window_s": 5.0,     # UserAssist last-executed vs process start
        "shell_open_window_s": 120.0,   # LNK / Jump List open time vs process start
        "shellbag_window_s": 600.0,     # ShellBags interaction vs process start
        "session_margin_s": 5.0,        # slack around an agent session for "outside" checks
        "interactive_logon_types": [2, 7, 10, 11],   # interactive, unlock, remote, cached
    },
    "process": {
        "dedupe_window_s": 2.0,         # a 4688 within this of a Sysmon event 1 (same PID, image) is the same process
    },
    "runtime_identification": {
        # Used when the trace records no runtime PID (Claude Code transcripts).
        "images": ["claude.exe", "node.exe", "bun.exe"],
        "max_age_s": 86400.0,           # candidate runtimes started at most this long before the session
        "min_score": 1.0,
    },
}


class ConfigError(ValueError):
    pass


def _merge(base: dict, override: dict, path: str = "") -> dict:
    out = copy.deepcopy(base)
    for k, v in override.items():
        where = f"{path}.{k}" if path else k
        if k.startswith("_"):            # comments such as "_note"
            continue
        if k not in base:
            raise ConfigError(f"unknown setting '{where}' (see `ptir config` for the valid keys)")
        if isinstance(base[k], dict):
            if not isinstance(v, dict):
                raise ConfigError(f"'{where}' must be an object")
            out[k] = _merge(base[k], v, where)
        else:
            if isinstance(base[k], (int, float)) and not isinstance(base[k], bool):
                if isinstance(v, bool) or not isinstance(v, (int, float)):
                    raise ConfigError(f"'{where}' must be a number")
            elif isinstance(base[k], bool) and not isinstance(v, bool):
                raise ConfigError(f"'{where}' must be true or false")
            elif isinstance(base[k], list) and not isinstance(v, list):
                raise ConfigError(f"'{where}' must be a list")
            out[k] = v
    return out


def load(path: str | Path | None = None, override: dict | None = None) -> dict:
    """Defaults, then the JSON file at `path`, then `override` (each only needs changed keys)."""
    cfg = copy.deepcopy(DEFAULTS)
    if path:
        try:
            data = json.loads(Path(path).read_text(encoding="utf-8-sig"))
        except json.JSONDecodeError as e:
            raise ConfigError(f"{path}: not valid JSON ({e})") from e
        cfg = _merge(cfg, data)
    if override:
        cfg = _merge(cfg, override)
    return cfg


def fingerprint(cfg: dict) -> str:
    """Short hash of the settings, so results can say exactly which settings produced them."""
    return hashlib.sha256(json.dumps(cfg, sort_keys=True).encode()).hexdigest()[:12]
