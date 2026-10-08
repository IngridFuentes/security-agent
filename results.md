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

*   **Explanation:** The code constructs a SQL query by directly concatenating the user-supplied `username` variable into the SQL string. If an attacker inputs a malicious string (e.g., `' OR '1'='1`), they can alter the structure of the query, potentially bypassing authentication, viewing unauthorized data, modifying, or deleting the database contents.
*   **Suggested Fix:** Use parameterized queries (prepared statements). This ensures that the database driver treats the user input strictly as data, not as executable SQL code.

#### Secure Code Example:

Depending on the database library you are using (e.g., `sqlite3`, `psycopg2`, `mysql.connector`), the syntax for placeholders might vary slightly (usually `?` or `%s`), but the concept remains the same:

```python
def get_user(db, username):
    # Using '?' as a placeholder (standard for sqlite3)
    query = "SELECT * FROM users WHERE name = ?"
    
    # Pass the parameters as a tuple/list to the execute method
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

### Vulnerability: Command Injection (RCE - Remote Code Execution)

*   **Explanation:** The function directly concatenates `user_input` into a string passed to `os.system()`, which executes shell commands. If a malicious user supplies input like `8.8.8.8; rm -rf /` or uses pipe characters (`|`), the underlying operating system will execute the injected command with the privileges of the Python process.
*   **Fix:** Avoid using `os.system()` with shell-based string concatenation. Instead, use the `subprocess` module with a list of arguments, and ideally, validate that the input conforms to a valid IP address or hostname format before executing.

### Secure Code Example:

```python
import subprocess
import ipaddress

def ping_host(user_input):
    # Option 1: Validate that the input is a valid IPv4 or IPv6 address
    try:
        ipaddress.ip_address(user_input)
    except ValueError:
        return "Invalid IP address provided."

    # Option 2: Use subprocess with a list of arguments (prevents shell injection)
    # shell=False (default) ensures the arguments are passed directly to the binary, not a shell.
    try:
        subprocess.run(["ping", "-c", "1", user_input], check=True)
        return "Ping sent"
    except subprocess.CalledProcessError:
        return "Ping failed"
```

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
As a security reviewer, I have examined the provided Python code. Here is the review detailing the vulnerabilities found, along with brief explanations and suggested fixes.

---

### 1. Hardcoded API Secret
* **Vulnerability:** **Hardcoded Credentials / Secrets Management**
* **Explanation:** The variable `API_SECRET = "sk-live-12345abcde"` is stored in plain text directly in the source code. If this code is committed to a Version Control System (like Git), the secret is exposed to anyone with access to the repository, including malicious actors if the repo is public.
* **Fix:** Remove the hardcoded secret from the code and load it dynamically from an environment variable or a secure secret management service (e.g., AWS Secrets Manager, HashiCorp Vault).

  ```python
  import os

  API_SECRET = os.environ.get("API_SECRET")
  if not API_SECRET:
      raise ValueError("API_SECRET environment variable is not set.")
```

---

### 2. Use of Cryptographically Broken Hashing Algorithm (MD5)
* **Vulnerability:** **Use of a Broken or Risky Cryptographic Algorithm**
* **Explanation:** The code uses `hashlib.md5()` to hash passwords. MD5 is cryptographically broken and extremely fast to compute. Attackers can easily use modern GPUs, rainbow tables, or brute-force methods to crack MD5 hashes and recover the original plain-text passwords. Furthermore, it lacks "salt" (random data added to each password before hashing), which leaves it vulnerable to pre-computed rainbow table attacks.
* **Fix:** Use a modern, slow, salted password-hashing algorithm designed specifically for password storage, such as **Argon2**, **bcrypt**, or **PBKDF2**. In Python, the `bcrypt` or `argon2-cffi` libraries are standard choices. If sticking to the standard library, `hashlib.pbkdf2_hmac` can be used.

  *Example using `hashlib.pbkdf2_hmac` (Standard Library):*
  ```python
  import hashlib
  import os


  def store_password(password):
      # Generate a random 16-byte salt
      salt = os.urandom(16)

      # Use PBKDF2 with SHA-256 and 100,000 iterations
      hashed = hashlib.pbkdf2_hmac(
          "sha256", password.encode("utf-8"), salt, 100000
      )

      # Store both the salt and the hash (e.g., encoded in hex)
      return salt.hex() + ":" + hashed.hex()
```

  *(Even better: Use the third-party `bcrypt` library, which handles salting and work-factors automatically).*
