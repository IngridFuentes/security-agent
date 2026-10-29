import os
from backend.tools import RepoTools


def make_repo(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "a.py").write_text("import os\nx = eval(input())\n")
    secret = tmp_path / "secret.txt"          # outside the repo
    secret.write_text("TOP SECRET")
    return repo, secret


def test_reads_lines(tmp_path):
    repo, _ = make_repo(tmp_path)
    assert "eval" in RepoTools(repo).read_lines("a.py", 2, 2)


def test_blocks_dotdot_traversal(tmp_path):
    repo, _ = make_repo(tmp_path)
    out = RepoTools(repo).read_lines("../secret.txt", 1, 1)
    assert out.startswith("ERROR") and "TOP SECRET" not in out


def test_blocks_absolute_path(tmp_path):
    repo, secret = make_repo(tmp_path)
    out = RepoTools(repo).read_lines(str(secret), 1, 1)
    assert out.startswith("ERROR") and "TOP SECRET" not in out


def test_blocks_symlink_escape(tmp_path):
    repo, secret = make_repo(tmp_path)
    os.symlink(secret, repo / "link.txt")
    out = RepoTools(repo).read_lines("link.txt", 1, 1)
    assert out.startswith("ERROR") and "TOP SECRET" not in out


def test_search_ignores_symlink_escape(tmp_path):
    repo, secret = make_repo(tmp_path)
    os.symlink(secret, repo / "link.txt")
    assert "TOP SECRET" not in RepoTools(repo).search("SECRET")