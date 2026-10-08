from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from agent import review_code

app = FastAPI(title="Security Code Review API")


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