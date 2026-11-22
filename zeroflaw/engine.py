"""Adapter between the CLI and your backend."""
from __future__ import annotations

import ast
import logging
import time
from dataclasses import asdict
from pathlib import Path
from typing import Callable

OnStep = Callable[[int, str, str], None]
OnNote = Callable[[str], None]


def model_name(demo: bool = False) -> str:
    if demo:
        return "demo"
    from backend.reviewer import MODEL

    return MODEL


# ---------- real ----------

def real_static(target: Path) -> list:
    from backend.static_analyzer import run_semgrep

    return run_semgrep(str(target))


def _describe(name: str, rest: str) -> str:
    if name == "submit_report":
        return "submitting report"
    try:
        args = ast.literal_eval(rest)
    except (ValueError, SyntaxError):
        return rest[:60]
    if name == "read_lines":
        return f"{args.get('path')}:{args.get('start_line')}-{args.get('end_line')}"
    if name == "search":
        return repr(args.get("query"))
    if name == "list_files":
        return args.get("path") or "all files"
    return rest[:60]

def _code_around(target: Path, f) -> tuple[str | None, int]:
    """The cited lines plus one line of context, for the finding panel."""
    try:
        lines = (target / f.file).read_text(errors="replace").splitlines()
    except OSError:
        return None, f.start_line
    start = max(1, f.start_line - 1)
    return "\n".join(lines[start - 1 : min(len(lines), f.end_line + 1)]), start

def real_review(target: Path, leads: list, max_steps: int, on_step: OnStep, on_note: OnNote) -> dict:
    from backend.reviewer import review_repo

    class Bridge(logging.Handler):
        """Turns the agent's log lines into live UI updates."""

        def emit(self, record: logging.LogRecord) -> None:
            if record.levelno >= logging.WARNING:
                on_note(record.getMessage())
                return
            if isinstance(record.args, tuple) and len(record.args) == 3:
                step, type_, text = record.args
                if type_ == "tool_call":
                    name, _, rest = str(text).partition("(")
                    on_step(step, name, _describe(name, rest.rstrip(")")))
                elif type_ in ("error", "limit"):
                    on_note(str(text))

    logger = logging.getLogger("backend.reviewer")
    old_level, old_propagate = logger.level, logger.propagate
    handler = Bridge()
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    logger.propagate = False
    try:
        result = review_repo(str(target), leads, max_steps)
    finally:
        logger.removeHandler(handler)
        logger.setLevel(old_level)
        logger.propagate = old_propagate

    findings = []
    for f in result.findings:
        d = f.model_dump(mode="json")
        d["line"], d["description"] = f.start_line, f.explanation  # names the panel code expects
        d["code"], d["code_start"] = _code_around(target, f)
        findings.append(d)

    return {
        "steps": result.steps_used,
        "complete": result.complete,
        "text": result.final_text,
        "findings": findings,
        "rejected": result.rejected,
        "files_read": result.files_read,
        "structured": result.structured,
        "trace": [asdict(e) for e in result.trace],
    }


# ---------- demo (sample data) ----------

DEMO_STEPS = [
    ("list_files", "6 files"),
    ("read_lines", "views.py:38-60"),
    ("read_lines", "utils.py:1-40"),
    ("search", "'os.system'"),
    ("read_lines", "views.py:40-44"),
]

DEMO_FINDINGS = [
    {
        "severity": "high",
        "title": "Command injection",
        "file": "views.py",
        "line": 42,
        "code_start": 40,
        "code": 'def ping(request):\n    host = request.POST["host"]\n    os.system("ping -c 1 " + host)\n    return render(request, "result.html")',
        "description": "User input flows into a shell command without sanitizing.\nAn attacker can append `; <cmd>` to run arbitrary commands.",
        "fix": {"old": 'os.system("ping -c 1 " + host)', "new": 'subprocess.run(["ping", "-c", "1", host], check=True)'},
        "cwe": "CWE-78",
        "confidence": "high",
    },
    {"severity": "medium", "title": "Missing input validation", "file": "views.py", "line": 51,
     "description": "The host parameter is used without checking its format.", "cwe": "CWE-20", "confidence": "medium"},
    {"severity": "medium", "title": "Verbose error messages", "file": "utils.py", "line": 18,
     "description": "Exceptions are returned to the client with stack details.", "cwe": "CWE-209", "confidence": "medium"},
    {"severity": "low", "title": "Debug mode enabled", "file": "settings.py", "line": 9,
     "description": "DEBUG is set to True.", "cwe": "CWE-489", "confidence": "high"},
]


def demo_static(target: Path) -> list:
    time.sleep(0.8)
    return [None] * 4  # four placeholder leads


def demo_review(target: Path, leads: list, max_steps: int, on_step: OnStep, on_note: OnNote) -> dict:
    for i, (tool, detail) in enumerate(DEMO_STEPS, start=1):
        time.sleep(1.0)
        on_step(i, tool, detail)
    return {"steps": len(DEMO_STEPS), "complete": True, "text": "", "findings": DEMO_FINDINGS, "trace": []}

def model_name(demo: bool = False) -> str:
    if demo:
        return "demo"
    from backend.reviewer import MODEL

    return MODEL