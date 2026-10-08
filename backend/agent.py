from dotenv import load_dotenv
from google import genai

load_dotenv() 

MODEL = "gemini-3.5-flash-lite"  # same model as main.py (free version)

client = genai.Client()


def review_code(code: str) -> str:
    prompt = f"""You are a security reviewer. Review this Python code.
List any vulnerabilities, explain each one briefly, and suggest a fix.

{code}"""
    response = client.models.generate_content(model=MODEL, contents=prompt)
    return response.text