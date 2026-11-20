"""Terminal presentation for ZeroFlaw, built on Rich."""
from __future__ import annotations

from pathlib import Path

from rich import box
from rich.console import Console, Group
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text

console = Console()

ACCENT = "#fb923c"
PURPLE = "#818cf8"
MUTED = "#8b949e"
SEVERITY_STYLE = {"high": "red", "medium": "yellow", "low": "blue"}

LOGO = [
    "███████╗███████╗██████╗  ██████╗ ███████╗██╗      █████╗ ██╗    ██╗",
    "╚══███╔╝██╔════╝██╔══██╗██╔═══██╗██╔════╝██║     ██╔══██╗██║    ██║",
    "  ███╔╝ █████╗  ██████╔╝██║   ██║█████╗  ██║     ███████║██║ █╗ ██║",
    " ███╔╝  ██╔══╝  ██╔══██╗██║   ██║██╔══╝  ██║     ██╔══██║██║███╗██║",
    "███████╗███████╗██║  ██║╚██████╔╝██║     ███████╗██║  ██║╚███╔███╔╝",
    "╚══════╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝     ╚══════╝╚═╝  ╚═╝ ╚══╝╚══╝",
]
LOGO_COLORS = ["#22d3ee", "#38bdf8", "#818cf8", "#a78bfa", "#f472b6", ACCENT]
LOGO_WIDTH = 68


def print_banner(version: str, show: bool = True) -> None:
    """Colored logo on wide terminals, one line on narrow ones, nothing when piped."""
    if not show or not console.is_terminal:
        return
    console.print()
    if console.width < LOGO_WIDTH + 4:
        console.print(Text.assemble(("✻ ", ACCENT), ("ZeroFlaw", "bold")))
    else:
        for row, color in zip(LOGO, LOGO_COLORS):
            console.print(Text(row, style=color))
    console.print(
        Text.assemble(
            ("✻ ", ACCENT),
            "AI security code review",
            (" · ", MUTED),
            ("ship it with zero flaws", MUTED),
            (f"   v{version}", MUTED),
        )
    )
    console.print()


def print_target_box(target: str, files: int, lines: int, model: str, max_steps: int) -> None:
    grid = Table.grid(padding=(0, 3))
    grid.add_column(style=MUTED)
    grid.add_column()
    grid.add_row("target", Text(target))
    grid.add_row("files", Text(f"{files} Python files · {lines} lines"))
    grid.add_row("model", Text(f"{model}   (max steps {max_steps})"))
    console.print(
        Panel(grid, box=box.ROUNDED, border_style=PURPLE, padding=(0, 2), width=min(console.width, 68))
    )
    console.print()


def section(title: str) -> None:
    console.print(Text.assemble(("● ", ACCENT), (title, "bold")))


def note(text: str) -> None:
    console.print(Text(f"  ⎿ {text}", style=MUTED))


def step_done(n: int, tool: str, detail: str) -> None:
    console.print(Text.assemble(("  ✓ ", "green"), (f"Step {n}  {tool:<12} {detail}", MUTED)))


def working(message: str):
    """Spinner context manager. Call .update(...) on it as the agent progresses."""
    return console.status(Text(message), spinner="dots", spinner_style=ACCENT)


def _snippet(finding: dict) -> Syntax | None:
    line = finding.get("line")
    code = finding.get("code")
    start = finding.get("code_start", line)
    if code is None and finding.get("file") and line:
        try:
            all_lines = Path(finding["file"]).read_text().splitlines()
        except OSError:
            return None
        start = max(1, line - 2)
        code = "\n".join(all_lines[start - 1 : min(len(all_lines), line + 2)])
    if not code:
        return None
    return Syntax(
        code,
        "python",
        line_numbers=True,
        start_line=start,
        highlight_lines={line} if line else None,
        theme="ansi_dark",
        background_color="default",
    )


def finding_panel(finding: dict) -> Panel:
    sev = str(finding.get("severity", "low")).lower()
    color = SEVERITY_STYLE.get(sev, "white")
    parts: list = []

    snippet = _snippet(finding)
    if snippet:
        parts += [snippet, Text()]

    parts.append(Text(finding.get("description", "")))

    fix = finding.get("fix")
    if fix:
        parts += [Text(), Text("Suggested fix", style="bold")]
        parts.append(Text(f"- {fix['old']}", style="red"))
        parts.append(Text(f"+ {fix['new']}", style="green"))

    meta = " · ".join(
        x for x in (finding.get("cwe"), f"confidence: {finding['confidence']}" if finding.get("confidence") else None) if x
    )
    if meta:
        parts += [Text(), Text(meta, style=MUTED)]

    location = f"{Path(finding.get('file', '')).name}:{finding.get('line', '')}"
    return Panel(
        Group(*parts),
        title=Text.assemble((f" {sev.upper()} ", f"bold black on {color}"), (f" {finding.get('title', '')} ", "bold")),
        title_align="left",
        subtitle=Text(location, style=MUTED),
        subtitle_align="right",
        border_style=color,
        padding=(1, 2),
        width=min(console.width, 72),
    )


def print_summary(findings: list[dict]) -> None:
    table = Table(box=box.HEAVY_HEAD, header_style="bold")
    table.add_column("Severity")
    table.add_column("Count", justify="right")
    for sev in ("high", "medium", "low"):
        count = sum(1 for f in findings if str(f.get("severity", "")).lower() == sev)
        table.add_row(Text.assemble(("● ", SEVERITY_STYLE[sev]), sev.capitalize()), str(count))
    console.print(table)