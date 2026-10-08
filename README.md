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
- **Response (summary):** (2-3 sentences of what Gemini said)
- **Got right:**
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
- **Response (summary):** TODO
- **Got right:** TODO
- **Missed:** TODO
- **Claimed without evidence:** TODO


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
- **Response (summary):** TODO
- **Got right:** TODO
- **Missed:** TODO
- **Claimed without evidence:** TODO

Full prompts and responses are in [`results.md`](results.md).

## Claim I verified

Gemini said ___. I checked it using ___ and found ___.

## Reflection

What Gemini did well, what it got wrong, and whether I would trust it for
security reviews.
