# Gemini Security Code Review Experiment

A small experiment using the Gemini API (Python, `google-genai`) to review
code snippets for security vulnerabilities and check how accurate it is.

## Setup

1. Clone the repo and enter the folder.
2. Create and activate a virtual environment:
   `python3 -m venv .venv` then `source .venv/bin/activate`
   (Windows: `.venv\Scripts\activate`)
3. Install dependencies: `pip install -r requirements.txt`
4. Get a key from Google AI Studio and create a `.env` file:
   `GEMINI_API_KEY=your-key-here`
5. Run the terminal version: `python3 main.py`


## Model

`gemini-3.5-flash-lite`

## Experiments

### 1. SQL injection
- **Expectation:**
- **Prompt:**
- **Response (summary):**
- **Got right / missed / unsupported claims:**

### 2. (second input)
...

### 3. (third input)
...

## Claim I verified

Gemini said ___. I checked it using ___ and found ___.

## Reflection

What Gemini did well, what it got wrong, and whether I would trust it for
security reviews.
