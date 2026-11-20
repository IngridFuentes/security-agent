from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
import threading
from dataclasses import asdict

from backend.snippet_review import review_snippet
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

# import threading
# from dataclasses import asdict

# from backend.snippet_review import review_snippet

agent_slot = threading.Semaphore(1)  # one agent run at a time (protects my quota)


@app.post("/api/agent-review")
def agent_review(req: LeadsRequest):
    if not agent_slot.acquire(blocking=False):
        raise HTTPException(status_code=429, detail="Another review is running. Try again in a moment.")
    try:
        result = review_snippet(req.code, req.language)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception:
        log.exception("Agent review failed")
        raise HTTPException(status_code=502, detail="Agent review failed. Check the server log.") #change to a better error after testing
    finally:
        agent_slot.release()
    return {
        "review": result.final_text,
        "complete": result.complete,
        "steps_used": result.steps_used,
        "trace": [asdict(e) for e in result.trace],
    }
