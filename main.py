from dotenv import load_dotenv
load_dotenv()
from google import genai
from pathlib import Path
import time
from google.genai import errors #added this line to import errors module after receiving high demand error from Gemini

MODEL = "gemini-3.5-flash-lite"

#finds the snippets directory relative to this file
snippets_dir = Path(__file__).parent / "snippets"

client = genai.Client() 

results = []

for file_path in sorted(snippets_dir.glob("*.py")):
    #stem is used to get the filename without the extension
    name = file_path.stem
    snippet = file_path.read_text(encoding="utf-8")

    prompt = f"""You are a security reviewer. Review this code.
List any vulnerabilities, explain each one briefly, and suggest a fix.

```python
{snippet}
```"""

    for attempt in range(3):
        try:
            response = client.models.generate_content(
                model=MODEL,
                contents=prompt
            )
            break

        except errors.ServerError as e:
            if attempt == 2:
                raise

            print("Gemini is temporarily unavailable. Retrying...")
            time.sleep(2 ** (attempt + 1))

    print(f"\n=== {name} ===")
    print(response.text)

    results.append(
        f"## {name}\n\n"
        f"### Prompt\n{prompt}\n\n"
        f"### Response\n{response.text}\n"
    )

#save the results in results.md

results_path = Path(__file__).parent / "results.md"
results_path.write_text("\n".join(results), encoding="utf-8")

print(f"\nResults saved to {results_path}")