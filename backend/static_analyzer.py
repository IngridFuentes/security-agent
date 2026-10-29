import json
import logging
import os
import subprocess
from pathlib import Path

from dotenv import load_dotenv

from backend.schemas import Lead

load_dotenv()

log = logging.getLogger(__name__)

SEMGREP_BIN = os.getenv("SEMGREP_BIN", "semgrep")
MAX_LEADS = 50      # total leads handed to the LLM
MAX_PER_RULE = 3    # so one noisy rule can't crowd out everything else
SEVERITY_ORDER = {"ERROR": 0, "WARNING": 1, "INFO": 2}


def run_semgrep(
    repo_path: str,
    config: str = "p/owasp-top-ten",
    timeout: int = 300,
) -> list[Lead]:
    repo = Path(repo_path).resolve()
    if not repo.is_dir():
        raise ValueError(f"Not a directory: {repo}")

    cmd = [
        SEMGREP_BIN, "scan",
        "--config", config,
        "--json",
        "--metrics=off",
        "--quiet",
        str(repo),
    ]
    proc = subprocess.run(
        cmd, capture_output=True, text=True, timeout=timeout, check=False
    )
    if proc.returncode != 0:
        raise RuntimeError(f"semgrep failed ({proc.returncode}): {proc.stderr[:500]}")

    results = json.loads(proc.stdout).get("results", [])

    # Most severe first
    results.sort(
        key=lambda r: (
            SEVERITY_ORDER.get(r["extra"].get("severity"), 3),
            r["path"],
            r["start"]["line"],
        )
    )

    # At most MAX_PER_RULE leads per rule, so one noisy rule
    # (e.g. 30 Dockerfiles) can't crowd out everything else
    per_rule: dict[str, int] = {}
    selected = []
    for r in results:
        rule = r["check_id"]
        if per_rule.get(rule, 0) >= MAX_PER_RULE:
            continue
        per_rule[rule] = per_rule.get(rule, 0) + 1
        selected.append(r)
    selected = selected[:MAX_LEADS]

    dropped = len(results) - len(selected)
    if dropped:
        log.warning(
            "Dropping %d of %d leads (cap=%d, per-rule cap=%d)",
            dropped, len(results), MAX_LEADS, MAX_PER_RULE,
        )

    leads = []
    for i, r in enumerate(selected, start=1):
        leads.append(
            Lead(
                id=f"L{i}",
                rule_id=r["check_id"],
                severity=r["extra"].get("severity", "INFO"),
                file=str(Path(r["path"]).resolve().relative_to(repo)),
                start_line=r["start"]["line"],
                end_line=r["end"]["line"],
                message=r["extra"]["message"],
            )
        )
    return leads


if __name__ == "__main__":
    import sys

    logging.basicConfig(level=logging.INFO)
    for lead in run_semgrep(sys.argv[1]):
        print(lead.model_dump_json())