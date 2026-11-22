import functools
import os
from pathlib import Path
import re

MAX_LINES_PER_READ = 200
MAX_READ_CHARS = 8_000
MAX_FILE_BYTES = 1_000_000
MAX_SEARCH_RESULTS = 20
MAX_LINE_CHARS = 300
MAX_LIST_RESULTS = 200
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", ".mypy_cache"}


class ToolError(Exception):
    """A problem the LLM should see and can recover from."""


def tool_errors(fn):
    """Turn ToolError into a plain 'ERROR: ...' string for the LLM."""
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except ToolError as e:
            return f"ERROR: {e}"
    return wrapper


class RepoTools:
    def __init__(self, repo_path: str):
        self.root = Path(repo_path).resolve()
        if not self.root.is_dir():
            raise ValueError(f"Not a directory: {self.root}")

    def _resolve_file(self, rel_path: str) -> Path:
        if not isinstance(rel_path, str) or not rel_path.strip() or "\x00" in rel_path:
            raise ToolError("path must be a non-empty string")
        candidate = (self.root / rel_path).resolve()  # follows symlinks, collapses ..
        if not candidate.is_relative_to(self.root):
            raise ToolError("path is outside the repository")
        if any(p in SKIP_DIRS for p in candidate.relative_to(self.root).parts):
            raise ToolError("path is in an excluded directory")
        if not candidate.is_file():
            raise ToolError(f"file not found: {rel_path}")
        if candidate.stat().st_size > MAX_FILE_BYTES:
            raise ToolError("file is too large to read")
        return candidate

    @staticmethod
    def _read_text(path: Path) -> str:
        data = path.read_bytes()
        if b"\x00" in data[:8192]:
            raise ToolError("binary file")
        return data.decode("utf-8", errors="replace")

    def _resolve_dir(self, rel_path: str) -> Path:
        if not isinstance(rel_path, str) or "\x00" in rel_path:
            raise ToolError("path must be a string")
        candidate = (self.root / (rel_path.strip() or ".")).resolve()
        if not candidate.is_relative_to(self.root):
            raise ToolError("path is outside the repository")
        if any(p in SKIP_DIRS for p in candidate.relative_to(self.root).parts):
            raise ToolError("path is in an excluded directory")
        if not candidate.is_dir():
            raise ToolError(f"directory not found: {rel_path}")
        return candidate

    @tool_errors
    def list_files(self, path: str = ".", extension: str = "") -> str:
        """List readable text files, with line counts.

        Args:
            path: Folder relative to the repo root (default: the whole repo).
            extension: Only include files ending with this, e.g. ".py".
        """
        if not isinstance(extension, str):
            raise ToolError("extension must be a string")
        base = self._resolve_dir(path)

        rows = []
        for dirpath, dirnames, filenames in os.walk(base):
            dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
            for name in sorted(filenames):
                if extension and not name.endswith(extension):
                    continue
                try:
                    real = (Path(dirpath) / name).resolve()
                    if not real.is_relative_to(self.root) or real.stat().st_size > MAX_FILE_BYTES:
                        continue
                    text = self._read_text(real)
                except (ToolError, OSError):
                    continue
                rows.append(f"{real.relative_to(self.root)} ({len(text.splitlines())} lines)")
                if len(rows) >= MAX_LIST_RESULTS:
                    return "\n".join(rows) + f"\n[stopped at {MAX_LIST_RESULTS} files; narrow with path or extension]"
        return "\n".join(rows) if rows else "no files"


    def check_evidence(self, file: str, start_line: int, end_line: int, evidence: str) -> str | None:
        """None if the quoted evidence is really in the file, at or within 3 lines of the cited lines; else the reason."""
        try:
            lines = self._read_text(self._resolve_file(file)).splitlines()
        except ToolError as e:
            return str(e)
        squash = lambda s: re.sub(r"\s+", "", s)
        wanted = squash(evidence)
        if not wanted:
            return "evidence is empty; copy one line of code from the file"
        if wanted not in squash("".join(lines)):
            return "evidence not found in the file; copy the code exactly"
        near = lines[max(0, start_line - 4) : end_line + 3]
        if wanted not in squash("".join(near)):
            return "evidence exists in the file but not near the cited lines; fix the line numbers"
        return None

    @tool_errors
    def read_lines(self, path: str, start_line: int, end_line: int) -> str:
        """Read a range of lines from a file in the repo.

        Args:
            path: File path relative to the repo root.
            start_line: First line to read (1-based).
            end_line: Last line to read (inclusive). At most 200 lines per call.
        """
        if not isinstance(start_line, int) or not isinstance(end_line, int):
            raise ToolError("line numbers must be integers")
        if start_line < 1 or end_line < start_line:
            raise ToolError("need 1 <= start_line <= end_line")

        lines = self._read_text(self._resolve_file(path)).splitlines()
        total = len(lines)
        if start_line > total:
            raise ToolError(f"file has only {total} lines")

        end = min(end_line, start_line + MAX_LINES_PER_READ - 1, total)
        out, size, last = [], 0, start_line - 1
        for n in range(start_line, end + 1):
            row = f"{n}: {lines[n - 1][:MAX_LINE_CHARS]}"
            if size + len(row) > MAX_READ_CHARS:
                break
            out.append(row)
            size += len(row)
            last = n

        note = "" if last == end_line else f"\n[output limited; showed lines {start_line}-{last}]"
        return f'<file path="{path}" lines="{start_line}-{last}" total_lines="{total}">\n' \
               + "\n".join(out) + "\n</file>" + note

    @tool_errors
    def search(self, query: str, max_results: int = 20) -> str:
        """Find lines containing an exact text string across the repo.

        Args:
            query: Literal text to look for (not a regex), at least 2 characters.
            max_results: Maximum matches to return (capped at 20).
        """
        if not isinstance(query, str) or len(query) < 2:
            raise ToolError("query must be a string of at least 2 characters")
        limit = min(max(1, int(max_results)), MAX_SEARCH_RESULTS)

        hits = []
        for dirpath, dirnames, filenames in os.walk(self.root):
            dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
            for name in sorted(filenames):
                try:
                    real = (Path(dirpath) / name).resolve()
                    if not real.is_relative_to(self.root) or real.stat().st_size > MAX_FILE_BYTES:
                        continue
                    text = self._read_text(real)
                except (ToolError, OSError):
                    continue
                for n, line in enumerate(text.splitlines(), start=1):
                    if query in line:
                        hits.append(f"{real.relative_to(self.root)}:{n}: {line.strip()[:MAX_LINE_CHARS]}")
                        if len(hits) >= limit:
                            return "\n".join(hits) + f"\n[stopped at {limit} results]"
        return "\n".join(hits) if hits else "no matches"