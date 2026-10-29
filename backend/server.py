from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
import logging

from backend.snippet_scan import scan_snippet
log = logging.getLogger(__name__)

from backend.agent import review_code
from pathlib import Path

from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

BASE_DIR = Path(__file__).resolve().parent.parent  # the project root

app = FastAPI(title="Security Code Review API")
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")


@app.get("/")
def index():
    return FileResponse(BASE_DIR / "templates" / "index.html")

class ReviewRequest(BaseModel):
    code: str = Field(min_length=1, max_length=5000)


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/api/review")
def review(req: ReviewRequest):
    try:
        result = review_code(req.code)
    except Exception:
        raise HTTPException(
            status_code=502,
            detail="Gemini request failed. Check your quota and try again later.",
        )
    return {"review": result}


class LeadsRequest(BaseModel):
    code: str = Field(min_length=1, max_length=5000)
    language: str = "python"


@app.post("/api/leads")
def leads(req: LeadsRequest):
    try:
        found = scan_snippet(req.code, req.language)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception:
        log.exception("Static analysis failed")
        raise HTTPException(status_code=500, detail="Static analysis failed.")
    return {"leads": [lead.model_dump() for lead in found]}