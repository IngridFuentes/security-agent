from dotenv import load_dotenv
load_dotenv()

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from google import genai

MODEL = "gemini-3.5-flash-lite"

app = FastAPI(title="Code Review Agent")

# Mount the static directory for CSS/JS files
app.mount("/static", StaticFiles(directory="static"), name="static")

client = genai.Client()

class CodeReviewRequest(BaseModel):
    code: str
    language: str

# Serve the HTML file from templates directory
@app.get("/", response_class=HTMLResponse)
async def read_root():
    with open("templates/index.html", "r", encoding="utf-8") as f:
        return f.read()

@app.post("/api/review")
async def review_code(request: CodeReviewRequest):
    if not request.code.strip():
        raise HTTPException(status_code=400, detail="Code snippet cannot be empty.")

    prompt = f"""You are a security reviewer. Review this {request.language} code.
List any vulnerabilities, explain each one briefly, and suggest a fix.

{request.code}"""

    try:
        response = client.models.generate_content(model=MODEL, contents=prompt)
        return {"review": response.text}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))