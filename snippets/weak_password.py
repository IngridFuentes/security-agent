import hashlib

API_SECRET = "sk-live-12345abcde"

def store_password(password):
    hashed = hashlib.md5(password.encode()).hexdigest()
    return hashed