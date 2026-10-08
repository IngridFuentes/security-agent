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

What this does:
   It looks up a user by name in a database. If someone types maria, the code builds this query:
   sql
   SELECT * FROM users WHERE name = 'maria'

That means "give me every column for the user named maria."

The problem: The code uses the user's text straight into the query, and the database can't tell the difference between data (the name) and instructions (the SQL). A user can type something that breaks out of the quotes:

   ' OR '1'='1

Now the query becomes:

   sql
   SELECT * FROM users WHERE name = '' OR '1'='1'

Because '1'='1' is always true, the database returns every user, not just one.

The fix: Use a parameterized query. You send the SQL and the user's text separately, so the database always treats the text as data, never as a command.

**Snippet:**
```python
def get_user(db, username):
    query = "SELECT * FROM users WHERE name = '" + username + "'"
    return db.execute(query)
```

- **My expectation:** 
   I expect Gemini to say this is SQL injection, because the username is added directly into the query string.
- **Prompt:** 
   "You are a security reviewer. Review this Python code. List any vulnerabilities, explain each one briefly, and suggest a fix."
- **Response (summary):**
   The code constructs a SQL query by directly concatenating the user-supplied `username` variable into the SQL string. If an attacker inputs a malicious string (e.g., `' OR '1'='1`), they can manipulate the query logic, bypass authentication, or extract, modify, or delete data from the database.
- **Got right:**
   The response is right.
- **Missed:**

- **Claimed without evidence:**

### 2. Command injection

It takes text from a user, like 8.8.8.8, and pings that address. It does this by building a command and handing it to the computer's terminal.

The problem: The code trusts the user's text completely. The terminal treats ; as "end this command, start another one." So a user could type:

8.8.8.8; cat /etc/passwd

The computer runs ping -c 1 8.8.8.8, then runs cat /etc/passwd, which prints a private system file. The attacker is now running their own commands on your server.

**Snippet:**

```python
import os

def ping_host(user_input):
    os.system("ping -c 1 " + user_input)
    return "Ping sent"
```

- **My expectation:**
I expect Gemini to say this is command injection, explain that ; or && can add commands, and suggest subprocess.run with a list of arguments.
- **Response (summary):**
   The function `ping_host` takes `user_input` directly and concatenates it into a string executed by `os.system()`, which passes the command to the underlying shell. Because there is no input validation or sanitization, an attacker can supply malicious payloads (e.g., using command separators like `;`, `&&`, or `|`) to execute arbitrary system commands with the privileges of the Python process.
- **Got right:**  
   The explanation seems right.
- **Missed:** 

- **Claimed without evidence:**



### 3. Weak password hashing and hardcoded secret

This snippet has two separate problems.

Problem A: MD5 for passwords
What this code does: It turns a password into a scrambled string (a "hash"), so the database doesn't store the real password.
What's the problem: MD5 is very fast, and that's bad. If hackers steal the database, they can try billions of guesses per second until one produces the same hash. There's also no salt (a random extra value added to each password). Without it, two users with the same password get the same hash, and attackers can use precomputed lists of common passwords.

The fix: Use a slow hash made for passwords, like bcrypt or Argon2. They add a salt automatically.

Problem B: Hardcoded secret

What this code does: API_SECRET = "sk-live-..." writes a secret key straight into the code.

What's the problem: Anyone who sees the code sees the key. If it's pushed to GitHub, bots find it within minutes. That's a vulnerability.

The fix: Read it from the environment: os.getenv("API_SECRET").

**Snippet:**

```python
import hashlib

API_SECRET = "sk-live-12345abcde"

def store_password(password):
    hashed = hashlib.md5(password.encode()).hexdigest()
    return hashed
```

- **My expectation:**
   I expect Gemini to find both problems. I'm not sure whether it will mention the missing salt.
- **Response (summary):**
   The variable `API_SECRET` contains a live secret key stored directly in the source code. Anyone with access to the repository (developers, malicious actors, or automated scanners) can extract this key, leading to unauthorized access to the underlying service.

   The code uses `hashlib.md5()` to hash passwords. MD5 is cryptographically broken and extremely fast to compute. Attackers can use modern GPUs and rainbow tables to quickly reverse MD5 hashes or perform brute-force attacks to recover the original passwords. Passwords should never be hashed with fast, non-salted algorithms like MD5 or SHA-256.

- **Got right:**
   The answer seems right.
- **Missed:**

- **Claimed without evidence:**

Full prompts and responses are in [`results.md`](results.md).

## Claim I verified

Gemini said ___. I checked it using ___ and found ___.

## Reflection

Gemini correctly identified the vulnerability in all three snippets: SQL injection, command injection, and weak password hashing with a hardcoded secret. For each one it explained the risk and suggested a fix.

I would trust Gemini as a first pass, but not as the only reviewer. These snippets were short and well-known, so they are easy cases. Real code is longer and more complex, and the model could miss a vulnerability or state something wrong with confidence. I would always verify its claims against sources like OWASP and review the code myself before relying on it.
