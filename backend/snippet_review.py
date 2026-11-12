import tempfile
from pathlib import Path

from backend.reviewer import AgentResult, review_repo
from backend.snippet_scan import EXTENSIONS, MAX_SNIPPET_CHARS
from backend.static_analyzer import run_semgrep


def review_snippet(code: str, language: str) -> AgentResult:
    ext = EXTENSIONS.get(language.lower())
    if ext is None:
        raise ValueError(f"Unsupported language: {language}")
    if len(code) > MAX_SNIPPET_CHARS:
        raise ValueError("Snippet too large")

    # The folder must stay alive while the agent reads it, so the
    # whole review happens inside the `with` block.
    with tempfile.TemporaryDirectory() as tmp:
        (Path(tmp) / f"snippet{ext}").write_text(code, encoding="utf-8")
        leads = run_semgrep(tmp)
        return review_repo(tmp, leads)
