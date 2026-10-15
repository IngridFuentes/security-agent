## sql_injection

### Prompt
You are a security reviewer. Review this Python code.
List any vulnerabilities, explain each one briefly, and suggest a fix.


def get_user(db, username):
    query = "SELECT * FROM users WHERE name = '" + username + "'"
    return db.execute(query)


### Response
As a security reviewer, here is my assessment of the provided Python code.

### Vulnerability: SQL Injection (SQLi)

*   **Explanation:** The code constructs a SQL query by directly concatenating the `username` variable into the SQL string using standard string formatting (`+`). If an attacker inputs malicious SQL commands (e.g., `' OR '1'='1`), the structure of the query changes, allowing them to bypass authentication, access unauthorized data, or even modify/delete the database.

*   **Suggested Fix:** Use parameterized queries (prepared statements). This ensures that the database driver treats the user input strictly as data, not as executable code.

#### Secure Code Example:

Depending on the database library you are using (e.g., `sqlite3`, `psycopg2`, `mysql-connector`), the syntax for placeholders might vary slightly (usually `?` or `%s`), but the principle remains the same:

```python
def get_user(db, username):
    # Using '?' as a placeholder for parameterized queries (standard for SQLite)
    query = "SELECT * FROM users WHERE name = ?"
    
    # Pass the parameters as a tuple or list in the execute method
    return db.execute(query, (username,))
```

*(Note: If you are using a library like `psycopg2` for PostgreSQL, the placeholder would be `%s`: `db.execute("SELECT * FROM users WHERE name = %s", (username,))`)*

## command_injection

### Prompt
You are a security reviewer. Review this Python code.
List any vulnerabilities, explain each one briefly, and suggest a fix.


import os

def ping_host(user_input):
    os.system("ping -c 1 " + user_input)
    return "Ping sent"


### Response
As a security reviewer, here is my assessment of the provided Python code:

### Vulnerability: Command Injection (CWE-78)

**Explanation:**
The function `ping_host` takes `user_input` directly and concatenates it into a string executed by `os.system()`, which passes the command to the underlying shell. Because there is no input validation or sanitization, an attacker can supply malicious payloads (e.g., using command separators like `;`, `&&`, or `|`) to execute arbitrary system commands with the privileges of the Python process. 

*Example malicious input:* `8.8.8.8; cat /etc/passwd`

---

### Suggested Fixes

#### Option 1: Use the `subprocess` module with a list of arguments (Recommended)
By using `subprocess.run()` and passing the command and arguments as a list (with `shell=False`, which is the default), Python passes the arguments directly to the OS without invoking a shell. This completely neutralizes command injection because shell metacharacters are treated as literal strings rather than command separators.

```python
import subprocess

def ping_host(user_input):
    try:
        # shell=False ensures user_input is treated strictly as an argument, not shell code
        subprocess.run(["ping", "-c", "1", user_input], check=True)
        return "Ping sent"
    except subprocess.CalledProcessError:
        return "Ping failed"
```

#### Option 2: Input Validation (Whitelist approach)
If you must use shell execution, you should strictly validate that the input matches expected formats (such as a valid IPv4/IPv6 address or a fully qualified domain name) using Regular Expressions before passing it to the system.

```python
import os
import re

def ping_host(user_input):
    # Simple regex to allow only valid IP addresses or standard hostnames
    # (Adjust regex depending on strict requirements)
    if not re.match(r"^[a-zA-Z0-9.-]+$", user_input):
        raise ValueError("Invalid host input")
        
    os.system(f"ping -c 1 {user_input}")
    return "Ping sent"
```
*(Note: Option 1 is heavily preferred over Option 2 for preventing command injection).*

## weak_hash_and_secret

### Prompt
You are a security reviewer. Review this Python code.
List any vulnerabilities, explain each one briefly, and suggest a fix.


import hashlib

API_SECRET = "sk-live-12345abcde"

def store_password(password):
    hashed = hashlib.md5(password.encode()).hexdigest()
    return hashed


### Response
As a security reviewer, I have examined the provided Python code. Here is the review detailing the vulnerabilities found, their explanations, and the suggested fixes.

---

### 1. Hardcoded API Secret
* **Vulnerability:** **Hardcoded Credentials / Sensitive Data Exposure**
* **Explanation:** The variable `API_SECRET` contains a live secret key stored directly in the source code. Anyone with access to the repository (developers, malicious actors, or automated scanners) can extract this key, leading to unauthorized access to the underlying service.
* **Fix:** Remove the secret from the code. Load it securely from an environment variable using Python's `os` module or a dedicated secrets manager.

### 2. Weak Password Hashing Algorithm
* **Vulnerability:** **Cryptographic Failure (Use of Broken/Insecure Hash Function)**
* **Explanation:** The code uses `hashlib.md5()` to hash passwords. MD5 is cryptographically broken and extremely fast to compute. Attackers can use modern GPUs and rainbow tables to quickly reverse MD5 hashes or perform brute-force attacks to recover the original passwords. Passwords should never be hashed with fast, non-salted algorithms like MD5 or SHA-256.
* **Fix:** Use a slow, salted password-hashing algorithm specifically designed for password security, such as **Argon2**, **bcrypt**, or **PBKDF2**. In Python, the `bcrypt` library or the built-in `hashlib.scrypt` are standard choices.

---

### Recommended Secure Code

Here is how the code should be rewritten to address both security issues:

```python
import os
import bcrypt

# FIX 1: Load the secret from the environment instead of hardcoding it
API_SECRET = os.environ.get("API_SECRET")

def store_password(password: str) -> str:
    """
    Securely hash a password using bcrypt, which automatically handles 
    salting and is computationally expensive to resist brute-force attacks.
    """
    # Convert password to bytes
    password_bytes = password.encode('utf-8')
    
    # Generate a secure salt and hash the password
    hashed = bcrypt.hashpw(password_bytes, bcrypt.gensalt())
    
    # Return the hash as a decoded string for storage
    return hashed.decode('utf-8')
```

*(Note: To use `bcrypt`, you will need to install the library via `pip install bcrypt`)*.
