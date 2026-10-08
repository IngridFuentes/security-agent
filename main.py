from dotenv import load_dotenv
load_dotenv()
from google import genai

MODEL = "gemini-3.5-flash-lite"


snippets = {
    "sql_injection": '''
def get_user(db, username):
    query = "SELECT * FROM users WHERE name = '" + username + "'"
    return db.execute(query)
''',

    "command_injection": '''
import os

def ping_host(user_input):
    os.system("ping -c 1 " + user_input)
    return "Ping sent"
''',

    "weak_hash_and_secret": '''
import hashlib

API_SECRET = "sk-live-12345abcde"

def store_password(password):
    hashed = hashlib.md5(password.encode()).hexdigest()
    return hashed
''',
}

client = genai.Client() 

results = []

for name, snippet in snippets.items():
    prompt = f"""You are a security reviewer. Review this Python code.
List any vulnerabilities, explain each one briefly, and suggest a fix.

{snippet}"""

    response = client.models.generate_content(model=MODEL, contents=prompt)

    print(f"\n=== {name} ===")
    print(response.text)

    results.append(
        f"## {name}\n\n### Prompt\n{prompt}\n\n### Response\n{response.text}\n"
    )

with open("results.md", "w") as f:
    f.write("\n".join(results))