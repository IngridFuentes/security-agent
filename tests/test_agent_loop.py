"""Tests for the agent loop. No API calls: the model is replaced by a script."""
from types import SimpleNamespace

import pytest
from google.genai import errors, types

from backend import reviewer
from backend.schemas import Lead
from backend.tools import RepoTools


def call(name, **args):
    return types.FunctionCall(name=name, args=args)


def reply(*calls, text=""):
    """A fake model response: either tool calls or a final text answer."""
    parts = [types.Part(function_call=c) for c in calls] or [types.Part(text=text)]
    return SimpleNamespace(
        function_calls=list(calls),
        text=text,
        candidates=[SimpleNamespace(content=types.Content(role="model", parts=parts))],
    )


class ScriptedModel:
    """Returns the scripted replies in order (the last one repeats) and records what it was sent."""

    def __init__(self, *replies):
        self.replies = list(replies)
        self.sent = []
        self.configs = []

    def __call__(self, contents, config=None):
        self.sent.append(list(contents))
        self.configs.append(config)
        return self.replies.pop(0) if len(self.replies) > 1 else self.replies[0]

@pytest.fixture
def repo(tmp_path):
    (tmp_path / "views.py").write_text('import os\n\ndef ping(host):\n    os.system("ping " + host)\n')
    return str(tmp_path)


def run(monkeypatch, repo, model, max_steps=5):
    monkeypatch.setattr(reviewer, "_generate", model)
    return reviewer.review_repo(repo, [], max_steps=max_steps)


def tool_results(result):
    return [e.data for e in result.trace if e.type == "tool_result"]


# ---------- the loop ----------

def test_finishes_with_final_answer(monkeypatch, repo):
    model = ScriptedModel(
        reply(call("read_lines", path="views.py", start_line=1, end_line=4)),
        reply(text="views.py:4 command injection"),
    )
    result = run(monkeypatch, repo, model)
    assert result.complete is True
    assert result.steps_used == 2
    assert "command injection" in result.final_text
    assert [e.type for e in result.trace] == ["tool_call", "tool_result", "model_text"]


def test_tool_output_is_sent_back_to_the_model(monkeypatch, repo):
    model = ScriptedModel(
        reply(call("read_lines", path="views.py", start_line=1, end_line=4)),
        reply(text="done"),
    )
    run(monkeypatch, repo, model)
    last_message = model.sent[1][-1]  # what the model saw on its second call
    assert "os.system" in last_message.parts[0].function_response.response["result"]


def test_stops_at_max_steps(monkeypatch, repo):
    model = ScriptedModel(reply(call("search", query="os.system")))  # never finishes
    result = run(monkeypatch, repo, model, max_steps=3)
    assert result.complete is False
    assert result.steps_used == 3
    assert len(model.sent) == 4  # 3 steps + 1 wrap-up call
    assert any(e.type == "limit" for e in result.trace)


def test_empty_model_response_ends_cleanly(monkeypatch, repo):
    empty = SimpleNamespace(function_calls=[], text="", candidates=[])
    result = run(monkeypatch, repo, ScriptedModel(empty))
    assert result.complete is False
    assert result.trace[-1].type == "error"


# ---------- bad tool calls ----------

def test_unknown_tool_is_reported_not_crashed(monkeypatch, repo):
    model = ScriptedModel(reply(call("delete_file", path="views.py")), reply(text="ok"))
    result = run(monkeypatch, repo, model)
    assert result.complete is True
    assert any("unknown tool" in r for r in tool_results(result))


def test_bad_arguments_do_not_crash(monkeypatch, repo):
    model = ScriptedModel(reply(call("read_lines", path="views.py")), reply(text="ok"))  # no line numbers
    result = run(monkeypatch, repo, model)
    assert result.complete is True
    assert any(r.startswith("ERROR") for r in tool_results(result))


def test_too_many_calls_in_one_step_are_refused(monkeypatch, repo):
    calls = [call("search", query="os") for _ in range(reviewer.MAX_CALLS_PER_STEP + 2)]
    result = run(monkeypatch, repo, ScriptedModel(reply(*calls), reply(text="ok")))
    refused = [r for r in tool_results(result) if "too many tool calls" in r]
    assert len(refused) == 2


def test_path_traversal_is_blocked(monkeypatch, repo):
    model = ScriptedModel(
        reply(call("read_lines", path="../../../../etc/passwd", start_line=1, end_line=5)),
        reply(text="ok"),
    )
    result = run(monkeypatch, repo, model)
    assert "root:" not in " ".join(tool_results(result))


# ---------- prompt ----------

def test_prompt_lists_leads():
    lead = Lead(id="L1", rule_id="r", severity="ERROR", file="views.py", start_line=4, end_line=4, message="m")
    assert "L1" in reviewer.build_prompt([lead])
    assert "views.py:4-4" in reviewer.build_prompt([lead])
    assert "no leads" in reviewer.build_prompt([])


# ---------- retries and fallback (needs the fallback patch in reviewer.py) ----------

class Rate429(errors.ClientError):
    def __init__(self):
        Exception.__init__(self, "429 RESOURCE_EXHAUSTED. Please retry in 1s")
        self.code = 429


class FakeClient:
    def __init__(self, outcomes):
        self.models = self
        self.outcomes = outcomes  # model name -> exception to raise, or value to return
        self.tried = []

    def generate_content(self, model, contents, config):
        self.tried.append(model)
        outcome = self.outcomes[model]
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


@pytest.fixture
def no_waiting(monkeypatch):
    monkeypatch.setattr(reviewer, "MIN_INTERVAL", 0)
    monkeypatch.setattr(reviewer.time, "sleep", lambda s: None)


def test_falls_back_to_next_model_on_429(monkeypatch, no_waiting):
    fake = FakeClient({reviewer.MODEL: Rate429(), "backup-model": "ok"})
    monkeypatch.setattr(reviewer, "client", fake)
    monkeypatch.setattr(reviewer, "FALLBACK_MODELS", ["backup-model"])
    assert reviewer._generate([]) == "ok"
    assert fake.tried == [reviewer.MODEL, "backup-model"]


def test_gives_up_when_every_model_is_rate_limited(monkeypatch, no_waiting):
    monkeypatch.setattr(reviewer, "client", FakeClient({reviewer.MODEL: Rate429()}))
    monkeypatch.setattr(reviewer, "FALLBACK_MODELS", [])
    with pytest.raises(errors.ClientError):
        reviewer._generate([])


def test_list_files_shows_files_and_skips_excluded_dirs(tmp_path):
    (tmp_path / "a.py").write_text("x = 1\ny = 2\n")
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "b.py").write_text("z = 3\n")
    (tmp_path / ".venv").mkdir()
    (tmp_path / ".venv" / "skip.py").write_text("no\n")
    out = RepoTools(str(tmp_path)).list_files()
    assert "a.py (2 lines)" in out
    assert "b.py (1 lines)" in out
    assert "skip.py" not in out


def test_list_files_filters_by_extension(tmp_path):
    (tmp_path / "a.py").write_text("x = 1\n")
    (tmp_path / "notes.md").write_text("hi\n")
    out = RepoTools(str(tmp_path)).list_files(extension=".py")
    assert "a.py" in out and "notes.md" not in out


def test_list_files_cannot_leave_the_repo(tmp_path):
    assert RepoTools(str(tmp_path)).list_files("../").startswith("ERROR")

def test_wrap_up_gives_an_answer_when_steps_run_out(monkeypatch, repo):
    model = ScriptedModel(
        reply(call("search", query="os.system")),
        reply(call("search", query="os.system")),
        reply(text="INCOMPLETE REVIEW: views.py:4 command injection"),
    )
    result = run(monkeypatch, repo, model, max_steps=2)
    assert result.complete is False
    assert result.steps_used == 2
    assert "command injection" in result.final_text


def test_wrap_up_call_forbids_tools_and_asks_for_an_answer(monkeypatch, repo):
    model = ScriptedModel(reply(call("search", query="os.system")), reply(text="INCOMPLETE REVIEW: none"))
    run(monkeypatch, repo, model, max_steps=1)
    assert model.configs[-1] is reviewer.WRAPUP_CONFIG
    assert "STEP LIMIT REACHED" in model.sent[-1][-1].parts[-1].text


def test_wrap_up_failure_still_returns_a_result(monkeypatch, repo):
    def model(contents, config=None):
        if config is reviewer.WRAPUP_CONFIG:
            raise RuntimeError("boom")
        return reply(call("search", query="os.system"))

    result = run(monkeypatch, repo, model, max_steps=2)
    assert result.complete is False
    assert result.final_text == ""
    assert result.trace[-1].type == "error"