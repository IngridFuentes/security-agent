"""ZeroFlaw command-line interface."""
from __future__ import annotations

import json
import time
from pathlib import Path

import typer
from rich.markdown import Markdown
from rich.panel import Panel
from rich.text import Text

from . import __version__, engine, ui

app = typer.Typer(add_completion=False, no_args_is_help=True, help="ZeroFlaw: AI security code review for your terminal.")

SKIP_DIRS = {".venv", "venv", "node_modules", ".git", "__pycache__"}


def _py_files(target: Path) -> list[Path]:
    if target.is_file():
        return [target]
    return [p for p in sorted(target.rglob("*.py")) if not SKIP_DIRS & set(p.parts)]


def _fail(message: str) -> None:
    ui.console.print(Text(f"\n  ✗ {message}", style="red"))
    raise typer.Exit(2)


@app.command()
def version() -> None:
    """Show the ZeroFlaw version."""
    typer.echo(f"zeroflaw {__version__}")


@app.command()
def scan(
    target: Path = typer.Argument(..., exists=True, help="Folder to review."),
    max_steps: int = typer.Option(10, "--max-steps", help="Maximum agent steps."),
    report: Path = typer.Option(Path("zeroflaw-report.json"), "--report", help="Where to save the JSON report."),
    no_banner: bool = typer.Option(False, "--no-banner", help="Skip the logo."),
    demo: bool = typer.Option(False, "--demo", help="Use sample data to preview the interface."),
) -> None:
    """Review code for security issues."""
    if not demo and not target.is_dir():
        _fail("Pass a folder to scan, for example: zeroflaw scan backend")

    run_static = engine.demo_static if demo else engine.real_static
    run_review = engine.demo_review if demo else engine.real_review
    model = engine.model_name(demo)

    files = _py_files(target)
    loc = sum(len(p.read_text(errors="ignore").splitlines()) for p in files)

    ui.print_banner(__version__, show=not no_banner)
    ui.print_target_box(str(target), len(files), loc, model, max_steps)

    ui.section("Static analysis (Semgrep)")
    try:
        with ui.working("Running Semgrep..."):
            leads = run_static(target)
    except Exception as e:
        _fail(f"Semgrep failed: {e}")
    ui.note(f"{len(leads)} leads")
    ui.console.print()

    ui.section("Reviewing with agent")
    started = time.time()
    try:
        with ui.working("Starting agent...") as status:

            def on_step(n: int, tool: str, detail: str) -> None:
                ui.step_done(n, tool, detail)
                status.update("Writing final answer..." if n >= max_steps else f"Step {n + 1}/{max_steps} thinking...")

            result = run_review(target, leads, max_steps, on_step, ui.note)
    except Exception as e:
        _fail(f"Agent failed: {e}")
    elapsed = time.time() - started

    ui.console.print()
    ui.section(f"Review complete · {result['steps']} steps · {elapsed:.1f}s")
    if not result["complete"]:
        ui.console.print(Text("  ⚠ Stopped early (step limit or error): results may be incomplete", style="yellow"))
    ui.console.print()

    findings = result["findings"]
    if findings:
        order = {"high": 0, "medium": 1, "low": 2}
        for f in sorted(findings, key=lambda f: order.get(str(f.get("severity")).lower(), 3)):
            ui.console.print(ui.finding_panel(f))
            ui.console.print()
        ui.print_summary(findings)
    elif result.get("text"):
        ui.console.print(
            Panel(
                Markdown(result["text"]),
                title=Text(" Findings ", style="bold"),
                title_align="left",
                border_style=ui.PURPLE,
                padding=(1, 2),
                width=min(ui.console.width, 90),
            )
        )

    report.write_text(json.dumps({"target": str(target), "model": model, **result}, indent=2, default=str))
    ui.console.print(f"\n  Report saved → {report}", style=ui.MUTED)

    has_high = any(str(f.get("severity")).lower() == "high" for f in findings)
    raise typer.Exit(1 if has_high else (0 if result["complete"] else 2))