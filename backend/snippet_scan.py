import tempfile
from pathlib import Path

from backend.schemas import Lead
from backend.static_analyzer import run_semgrep

# Keys match the <option value="..."> entries in index.html
EXTENSIONS = {
    "python": ".py",
    "javascript": ".js",
    "java": ".java",
    "cpp": ".cpp",
    "go": ".go",
}
MAX_SNIPPET_CHARS = 50_000


def scan_snippet(code: str, language: str) -> list[Lead]:
    ext = EXTENSIONS.get(language.lower())
    if ext is None:
        raise ValueError(f"Unsupported language: {language}")
    if len(code) > MAX_SNIPPET_CHARS:
        raise ValueError("Snippet too large")

    # Write the snippet to a throwaway folder, scan it, and delete the folder.
    # The user never chooses a path or filename.
    with tempfile.TemporaryDirectory() as tmp:
        (Path(tmp) / f"snippet{ext}").write_text(code, encoding="utf-8")
        return run_semgrep(tmp)