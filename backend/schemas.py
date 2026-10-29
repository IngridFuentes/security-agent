from enum import Enum
from pydantic import BaseModel, Field, model_validator


class Severity(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class Lead(BaseModel):
    """Output of the static analyzer: a hint, NOT a verdict."""
    id: str
    rule_id: str
    severity: str = "INFO"
    file: str
    start_line: int
    end_line: int
    message: str


class Finding(BaseModel):
    """What the LLM claims after investigating. Must be verifiable."""
    file: str
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)
    severity: Severity
    cwe: str | None = Field(default=None, pattern=r"^CWE-\d+$")
    title: str
    explanation: str
    evidence: str = Field(description="Exact code copied from the file")
    confidence: float = Field(ge=0, le=1)
    lead_ids: list[str] = []  # empty = LLM found it on its own

    @model_validator(mode="after")
    def lines_in_order(self):
        if self.end_line < self.start_line:
            raise ValueError("end_line must be >= start_line")
        return self


class Report(BaseModel):
    findings: list[Finding]
    complete: bool = True  # False if we hit the max-steps cutoff