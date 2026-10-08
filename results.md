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

**Explanation:**
The code constructs an SQL query by directly concatenating the user-supplied `username` variable into the SQL string. If an attacker inputs a specially crafted string (e.g., `' OR '1'='1`), they can alter the structure of the query, bypass authentication, extract unauthorized data, or potentially modify/delete data in the database.

**Fix:**
Use parameterized queries (prepared statements). This ensures that the database driver treats the user input strictly as data, not as executable SQL code.

**Secure Code Example:**

```python
def get_user(db, username):
    # Use parameterized query (syntax may vary slightly depending on the database library, 
    # e.g., '?' for SQLite, '%s' or '?' for MySQL/PostgreSQL)
    query = "SELECT * FROM users WHERE name = %s"
    return db.execute(query, (username,))
```

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

### Vulnerability: Command Injection

**Explanation:**
The function `ping_host` takes direct `user_input` and concatenates it into a string passed to `os.system()`. This function executes the command in a system shell. Because the input is not sanitized or validated, an attacker can input malicious shell commands alongside (or instead of) a hostname. 

For example, if the user inputs `8.8.8.8; cat /etc/passwd`, the resulting command executed by the OS will be:
`ping -c 1 8.8.8.8; cat /etc/passwd`
This allows an attacker to execute arbitrary system commands with the privileges of the running Python process.

**Suggested Fix:**
Avoid using `os.system()` with shell-based string concatenation. Instead, use the `subprocess` module and pass arguments as a list. By setting `shell=False` (the default), the operating system will treat the input strictly as an argument to the `ping` command rather than interpreting shell metacharacters (like `;`, `&`, or `|`).

**Secure Code Example:**

```python
import subprocess

def ping_host(user_input):
    # Pass the command and arguments as a list. 
    # shell=False (default) prevents shell injection.
    try:
        subprocess.run(["ping", "-c", "1", user_input], check=True, shell=False)
        return "Ping sent"
    except subprocess.CalledProcessError:
        return "Ping failed"
```

*Additional Best Practice:* Even with `subprocess` (when `shell=False`), it is still recommended to validate `user_input` using a regular expression to ensure it conforms to a valid IPv4/IPv6 address or a standard domain name format before passing it to the system.

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
As a security reviewer, here is my assessment of the provided Python code. I have identified two primary security vulnerabilities.

---

### 1. Hardcoded API Secret
* **Vulnerability:** **Hardcoded Credentials / Sensitive Data Exposure**
* **Explanation:** The variable `API_SECRET = "sk-live-12345abcde"` is stored in plain text directly within the source code. If this code is committed to a Version Control System (like Git)—especially a public repository—anyone can extract this secret and gain unauthorized access to the live service.
* **Fix:** Remove the secret from the source code. Load it securely using environment variables or a dedicated secrets manager (e.g., AWS Secrets Manager, HashiCorp Vault).

  ```python
  import os

  API_SECRET = os.environ.get("API_SECRET")
  ```

---

### 2. Insecure Hashing Algorithm for Passwords
* **Vulnerability:** **Use of Broken/Insecure Cryptographic Hash Function (MD5)**
* **Explanation:** `hashlib.md5` is cryptographically broken and exceptionally fast to compute. Attackers can use modern GPUs and precomputed rainbow tables to reverse or brute-force MD5 hashes of passwords almost instantly. Passwords require a slow, salted hashing algorithm.
* **Fix:** Use a modern, computationally expensive password-hashing algorithm designed specifically for credentials, such as **Argon2**, **bcrypt**, or **PBKDF2**. In Python, the `bcrypt` or `argon2-cffi` libraries are standard. Using Python's built-in `hashlib.pbkdf2_hmac` is also acceptable if external libraries cannot be installed.

  *Example using `bcrypt`:*
  ```python
  import bcrypt

  def store_password(password: str) -> str:
      # Generate a salt and hash the password securely
      salt = bcrypt.gensalt()
      hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
      return hashed.decode('utf-8')
  ```

---

### Summary of Fixed Code

```python
import os
import bcrypt

# Load sensitive config from environment variables
API_SECRET = os.environ.get("API_SECRET")

def store_password(password: str) -> str:
    # Use bcrypt with an automatic salt for secure password hashing
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed.decode('utf-8')
```
