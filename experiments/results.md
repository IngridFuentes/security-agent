## command_injection

### Prompt
You are a security reviewer. Review this code.
List any vulnerabilities, explain each one briefly, and suggest a fix.

```python
import os

def ping_host(user_input):
    os.system("ping -c 1 " + user_input)
    return "Ping sent"
```

### Response
As a security reviewer, here is my assessment of the provided code:

### Vulnerability: Command Injection

*   **Explanation:** 
    The function directly concatenates `user_input` into a string and passes it to `os.system()`, which executes the command in the underlying operating system shell. If an attacker supplies malicious input containing shell metacharacters (such as `;`, `&&`, or `|`), they can execute arbitrary system commands with the privileges of the application. 
    
    *Example of an attack:* If `user_input` is set to `8.8.8.8; cat /etc/passwd`, the system will execute both the ping command and the command to read sensitive system files.

*   **Suggested Fix:** 
    Avoid using `os.system()` with shell interpretation. Instead, use the `subprocess` module and pass the command and its arguments as a list. This ensures the input is treated strictly as an argument, not as executable shell code, even if it contains shell metacharacters.

#### Secure Code Example:
```python
import subprocess

def ping_host(user_input):
    try:
        # Pass the command and arguments as a list. 
        # shell=False (default) prevents shell injection.
        subprocess.run(["ping", "-c", "1", user_input], check=True)
        return "Ping sent"
    except subprocess.CalledProcessError:
        return "Ping failed"
```

## sql_injection

### Prompt
You are a security reviewer. Review this code.
List any vulnerabilities, explain each one briefly, and suggest a fix.

```python
def get_user(db, username):
    query = "SELECT * FROM users WHERE name = '" + username + "'"
    return db.execute(query)
```

### Response
As a security reviewer, here is my assessment of the provided code:

### Vulnerability: SQL Injection (SQLi)

**Explanation:**
The function directly concatenates the user-supplied `username` parameter into the SQL query string. If an attacker inputs a maliciously crafted string (e.g., `' OR '1'== '1`), they can alter the structure of the query. This may allow them to bypass authentication, access unauthorized data, modify the database, or even execute administrative commands depending on the database permissions.

**Suggested Fix:**
Use parameterized queries (prepared statements). This ensures that the database engine treats the `username` strictly as data, not as executable SQL code, regardless of its content.

```python
def get_user(db, username):
    query = "SELECT * FROM users WHERE name = ?"
    # Note: Depending on the database library you use (e.g., Psycopg2, PyMySQL, sqlite3), 
    # the placeholder might be %s, ?, or :name.
    return db.execute(query, (username,))
```

## weak_password

### Prompt
You are a security reviewer. Review this code.
List any vulnerabilities, explain each one briefly, and suggest a fix.

```python
import hashlib

API_SECRET = "sk-live-12345abcde"

def store_password(password):
    hashed = hashlib.md5(password.encode()).hexdigest()
    return hashed
```

### Response
As a security reviewer, I have examined the provided code. Here are the vulnerabilities identified, along with explanations and suggested fixes:

### 1. Hardcoded API Secret (Credential Exposure)
* **Vulnerability:** The variable `API_SECRET` is hardcoded directly into the source code. If this code is committed to a Version Control System (like Git), the secret will be exposed to anyone who has access to the repository.
* **Fix:** Remove hardcoded secrets from the source code. Load sensitive values using environment variables or a secure secrets manager.

### 2. Use of Cryptographically Weak Hashing Algorithm (MD5)
* **Vulnerability:** The function uses `hashlib.md5()` to hash passwords. MD5 is cryptographically broken and extremely fast to compute, making it vulnerable to brute-force and rainbow table attacks. It should never be used for password hashing.
* **Fix:** Use a slow, salted hashing algorithm specifically designed for passwords, such as `bcrypt`, `argon2`, or `pbkdf2`.

---

### Secure Code Example

Here is how the code should be refactored to address these vulnerabilities:

```python
import os
import bcrypt

# Load the secret from the environment instead of hardcoding it
API_SECRET = os.environ.get("API_SECRET")

def store_password(password: str) -> str:
    """
    Hashes a password securely using bcrypt with an automatically generated salt.
    """
    # Encode the password to bytes
    password_bytes = password.encode('utf-8')
    
    # Generate a secure salt and hash the password
    hashed = bcrypt.hashpw(password_bytes, bcrypt.gensalt())
    
    # Return the hashed password as a string for storage
    return hashed.decode('utf-8')
```

*(Note: You will need to install the `bcrypt` library via `pip install bcrypt` for this fix to work.)*
