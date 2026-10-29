Security Code Review Agent

An AI agent that reviews a codebase for security vulnerabilities. It combines a deterministic static analyzer (Semgrep) with an LLM reviewer (Gemini) that investigates the analyzer's leads, explains them, and submits a validated report.

Status: work in progress.

Why this design

Each part of the system does only what it is good at:

Component	                Type	            Job	                            Why

Static analyzer (Semgrep)	Deterministic	    Find leads	                    Fast, cheap, reproducible. Narrows the search so the LLM doesn't   read the whole repo.

LLM reviewer (Gemini)	    Non-deterministic	Investigate and explain	        Can follow code paths and judge whether a lead is real. Static tools can't.

Tools (read_lines, search)	Deterministic	    Let the LLM look at the repo	The LLM can only see what the tools return, so the tools are the security boundary.
submit_report	            Deterministic	    Validate the final answer	    LLMs invent line numbers and code. Real code checks the claims and sends errors back to be fixed.

Two ideas run through everything:

- The repo is untrusted input. It can contain prompt injection (e.g. a comment saying "ignore previous instructions"). Repo content is treated as data, never as instructions.

- Leads, not verdicts. The analyzer's output is a hint. A file with no leads is not a clean file, and a lead is not a confirmed bug.

What's built so far

Step 1: Schemas (backend/schemas.py)

The data contracts between components, defined with Pydantic:

- Lead: output of the static analyzer (id, rule_id, file, start_line, end_line, message). Intentionally contains no code snippet, since code is untrusted text and the LLM must request it through a tool.
- Finding: what the LLM claims after investigating (file, line range, severity, optional CWE, title, explanation, exact code evidence, confidence, and the lead_ids it came from; empty means the LLM found it on its own).
- Report: a list of findings plus complete: bool, which is False if the agent hit its step limit.

Pydantic checks the shape (types, ranges, CWE format). Checking claims against the real repo (does the file exist, does the evidence appear on those lines) happens later in submit_report.

Step 2: Static analyzer wrapper (backend/static_analyzer.py)

run_semgrep(repo_path) runs Semgrep and returns list[Lead].

- Calls Semgrep with subprocess.run and an argument list (never shell=True), so odd file or folder names can't become commands.
- Uses a timeout, --metrics=off, and caps results at MAX_LEADS = 50.
- Converts file paths to repo-relative paths.
- The Semgrep binary is configurable via SEMGREP_BIN, so Semgrep can live in its own isolated virtualenv.

Things learned along the way

- Semgrep doesn't run the code it scans. It parses and pattern-matches. Still, never run, build, or pip install anything from a repo under review.
- No leads ≠ no bugs. On snippets/, Semgrep scanned all 3 files but only 1 matched a rule in p/owasp-top-ten. The other two have vulnerabilities the ruleset doesn't catch, so they are useful test cases for the LLM reviewer later.
- Rulesets matter. p/owasp-top-ten is narrow. Try p/python or p/security-audit for broader coverage.
- Duplicate leads are normal. Two rules flagged the same line. Merging duplicates is part of the LLM's triage job.
- Semgrep only scans git-tracked files in a git repo. If a new file produces no leads, git add it first.
- Registry rulesets (p/...) download over the network. Before scanning untrusted repos, pin rules locally and run the scanner in Docker with --network none.