<p align="center"> 
   <img width="515" height="121" alt="Screenshot 2026-11-23 at 6 45 42 PM" src="https://github.com/user-attachments/assets/e05a5d34-7a30-45b9-b0e5-0b2cc8cce01e" />
</p>

<p align="center">
  <b>AI security code review for the command line.</b><br>
  Semgrep finds the leads. An LLM agent investigates them. Only findings backed by real code make it to the report.
</p>

<p align="center">
  <img alt="Python 3.14+" src="https://img.shields.io/badge/python-3.14%2B-3776AB?logo=python&logoColor=white">
  <img alt="Powered by Gemini" src="https://img.shields.io/badge/LLM-Gemini-8E75B2">
  <img alt="Static analysis: Semgrep" src="https://img.shields.io/badge/static%20analysis-Semgrep-1B9E77">
  <img alt="Status: prototype" src="https://img.shields.io/badge/status-prototype-orange">
</p>

---

## Contents

- [Why ZeroFlaw](#why-zeroflaw)
- [Features](#features)
- [How it works](#how-it-works)
- [Quick start](#quick-start)
- [Usage](#usage)
- [Example output](#example-output)
- [Configuration](#configuration)
- [Project structure](#project-structure)
- [Testing](#testing)
- [What it has been tried on](#what-it-has-been-tried-on)
- [Known limitations and roadmap](#known-limitations-and-roadmap)
- [Responsible use](#responsible-use)
- [Acknowledgments](#acknowledgments)

## Why ZeroFlaw

Static analyzers are fast but noisy, and they miss anything that does not match a rule. LLM reviewers read code like a person does, but they can also invent bugs that are not there.

ZeroFlaw combines the two and puts a checking step between the model and the report:

1. **Semgrep** produces *leads*: hints about where problems might be, not verdicts.
2. An **agent** (Gemini) investigates the leads by reading the actual code with read-only tools, and looks for issues the leads missed.
3. Every finding must quote the exact line of code it is about. If that code is not in the file, near the cited lines, the finding is sent back for correction or dropped.

The result is a short, verifiable list of issues in your terminal, designed to be run while you write code.

## Features

- **Terminal-first.** Live agent trace, colour-coded finding panels with the offending code, a severity summary and exit codes suitable for pre-commit hooks and CI.
- **Evidence-checked findings.** Findings follow a strict schema and are verified against the real file before they are shown.
- **Honest coverage.** The "files read" count comes from the tool log, not from what the model says it reviewed. A scan that did not read everything says so and exits with a distinct code.
- **Consistent severity.** Severity is assigned from a CWE table in code, so the same kind of issue gets the same severity on every run.
- **Sandboxed tools.** The agent can only list, read and search files inside the target folder. Path traversal, absolute paths, symlink escapes and directories such as `.git` and `.venv` are blocked.
- **Rate-limit aware.** Request throttling, retries that honour the API's retry delay, and optional fallback models.
- **Always ends with an answer.** If the step limit is reached, a final call forces a report from what has been read so far, clearly marked as incomplete.
- **Saved reports.** Every scan writes a JSON report (findings, rejected findings, files read and the full step trace) to `reports/`.
- **Demo mode.** `--demo` previews the whole interface with sample data and makes no API calls.

## How it works

**The agent loop** (`backend/reviewer.py`) is a plain loop that runs the model one step at a time. The tools are `list_files`, `read_lines` and `search`, each with strict limits on output size. The agent finishes by calling `submit_report` with structured findings.

**Verification** (`_check_report`) runs locally, with no API calls. Each finding must match the `Finding` schema (valid severity, `CWE-123` format, confidence between 0 and 1) and its quoted `evidence` must really exist in the cited file near the cited lines. Rejections go back to the agent with the reason so it can correct them.

**Step limit.** After the last step, one extra call with tools disabled asks the model to submit what it has verified. The report is marked incomplete.

## Quick start

**Requirements:** Python 3.14+, a [Gemini API key](https://aistudio.google.com/), and [Semgrep](https://semgrep.dev/).

```bash
git clone https://github.com/IngridFuentes/security-agent.git
cd security-agent

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Semgrep can live in its own environment; ZeroFlaw finds it through SEMGREP_BIN
python3 -m venv ~/.venvs/semgrep
~/.venvs/semgrep/bin/pip install semgrep
```

Create a `.env` file in the repository root:

```bash
GEMINI_API_KEY=
SEMGREP_BIN=
```

Preview the interface without spending any API calls:

```bash
python3 -m zeroflaw scan snippets --demo
```

Then run a real scan on the bundled examples:

```bash
python3 -m zeroflaw scan snippets
```

The Semgrep rule pack (`p/owasp-top-ten`) is downloaded on first use, so the first run needs internet access.

## Usage

```bash
python3 -m zeroflaw scan <folder> [options]
```

| Option | Default | Description |
|---|---|---|
| `--max-steps N` | `10` | Maximum agent steps before the wrap-up call |
| `--report-dir PATH` | `reports` | Folder where the JSON report is saved |
| `--no-report` | off | Do not save a report |
| `--no-banner` | off | Skip the logo (it is also skipped automatically when output is piped) |
| `--demo` | off | Use sample data instead of calling Semgrep and the model |

`python3 -m zeroflaw version` prints the version.

**Exit codes**

| Code | Meaning |
|---|---|
| `0` | Review finished and read every Python file, with no high or critical findings |
| `1` | At least one high or critical finding |
| `2` | Review incomplete (step limit or error) or only part of the code was read |

**Reports.** Each scan saves `reports/<date>_<time>_<target>.json` with: `target`, `model`, `created`, `steps`, `complete`, `findings`, `rejected`, `files_read`, the agent's `text` note, and the full `trace` of every tool call and result. `reports/` is git-ignored because reports contain code from the scanned repositories.

## Example output

Each finding shows the code with the vulnerable line marked, why it is exploitable, a suggested fix, the CWE and the model's confidence.
<img width="848" height="502" alt="Screenshot 2026-11-23 at 7 04 14 PM" src="https://github.com/user-attachments/assets/6c4a7e23-2a6c-49bd-be44-2b5aba7bce16" />



When the step limit is reached, ZeroFlaw still returns what was verified, says what was not read, and warns that the review is incomplete.

<img width="774" height="508" alt="Screenshot 2026-11-23 at 7 05 24 PM" src="https://github.com/user-attachments/assets/a95164b9-c7c4-44f7-88d1-0742eda3039a" />


## Configuration

Settings are read from the environment or from `.env`.

| Variable | Default | Description |
|---|---|---|
| `GEMINI_API_KEY` | none | API key for Gemini |
| `GEMINI_MODEL` | `gemini-3.5-flash-lite` | Model used by the agent loop |
| `GEMINI_FALLBACK_MODELS` | empty (for now - testing purposes) | Comma-separated backup models, tried in order when a model is rate-limited |
| `GEMINI_MIN_INTERVAL` | `4.5` | Minimum seconds between requests, to stay under free-tier per-minute limits |
| `SEMGREP_BIN` | `semgrep` | Path to the Semgrep executable |

When you are measuring results, leave `GEMINI_FALLBACK_MODELS` empty so every run comes from one model.

## Project structure

```
.
├── zeroflaw/                # the command-line tool
│   ├── cli.py               # `scan` command and options
│   ├── engine.py            # connects the CLI to the backend (plus demo data)
│   ├── ui.py                # banner, live trace, finding panels (Rich)
│   └── report.py            # saves JSON reports to reports/
├── backend/
│   ├── reviewer.py          # agent loop, prompt, retries, wrap-up, report validation
│   ├── tools.py             # sandboxed read-only tools: list_files, read_lines, search
│   ├── static_analyzer.py   # runs Semgrep and returns prioritized leads
│   ├── schemas.py           # Lead, Finding and Report models
│   └── ...                  # earlier prototypes (web UI server, single-snippet review)
├── tests/                   # loop, tool sandbox and report tests (no API calls)
├── snippets/                # small vulnerable examples
├── experiments/             # notes from early experiments
└── reports/                 # created at runtime, git-ignored
```

The original web UI and single-snippet prototypes are still in the repository for reference. The command line is the main interface.

## Testing

```bash
python3 -m pytest tests -v
```

## What it has been tried on

Results come from single manual runs. They show the agent works end to end on real code, not how accurate it is in general.

| Target | What is in it | Result |
|---|---|---|
| `snippets/` (3 files) | command injection, SQL injection, MD5 password hashing, hardcoded secret | all four reported, at the right lines |
| [PyGoat](https://github.com/adeyosemanputra/pygoat) `command_injection_lab` | `shell=True` command injection, `eval()` of user input | both reported at the right lines, plus debug mode and root-container findings |
| PyGoat `sql_injection_lab` | SQL injection in a login form | reported at the right line, plus debug mode and root-container findings. A hardcoded password hash in the seed data was not reported |
| PyGoat `introduction/` | routing and page views | no issues reported; a manual search found no dangerous calls in it |

## Known limitations and roadmap

**Limitations**

- **The false-positive rate has not been measured.** There is no labeled set of safe code yet, so the results above say little about precision.
- **Only small targets have been tried.** Large repositories hit the step limit. "Read" means a file was opened, not that every line was read.
- **Semgrep sometimes returns no leads**, so the agent has to explore without hints on those targets.
- **Wording varies between runs.** Severity is stable only for CWEs in the table; for other CWEs the model decides.
- **Files are counted by `.py` extension** in the coverage line, although the agent also reads files such as Dockerfiles.
- **Free-tier API limits** make long scans slow.

**Roadmap**

- An evaluation suite with labeled vulnerable and safe code, measuring recall, false positives and run-to-run consistency.
- Line-level coverage tracking.
- Markdown report formats.
- Support for other model providers.
- A pre-commit hook and CI examples.

## Responsible use

- ZeroFlaw sends the code it reads to the model provider's API. Do not scan code you are not allowed to share, and review the provider's data terms before scanning private or work code.
- It is a review aid, not a replacement for human review or a full security audit. A clean report does not prove the code is safe.
- Only scan code you own or have permission to test. The PyGoat labs used in testing are intentionally vulnerable training applications.

## Acknowledgments

- [Semgrep](https://semgrep.dev/) for static analysis.
- [PyGoat](https://github.com/adeyosemanputra/pygoat), an intentionally vulnerable Django application, used as a test target.
- [Gemini](https://ai.google.dev/) for the agent model.
