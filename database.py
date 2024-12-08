"""Database functions for the JWKS server"""

from datetime import datetime, timezone
import os
import sqlite3
from dotenv import load_dotenv
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

DATABASE_FILE = 'totally_not_my_privateKeys.db'


# Load environment variables assuming its a hex 16-byte key
load_dotenv()
encryption_key = os.getenv("NOT_MY_KEY")
if encryption_key is None:
    raise ValueError("The environment variable 'NOT_MY_KEY' is not set.")
encryption_key = bytes.fromhex(encryption_key)


def init_db():
    """Initialize the database of keys, users, and authentication logs"""
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS keys(
            kid INTEGER PRIMARY KEY AUTOINCREMENT,
            key BLOB NOT NULL,
            exp INTEGER NOT NULL
        )
    """)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        email TEXT UNIQUE,
        date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_login TIMESTAMP
    )
    """)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS auth_logs(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        request_ip TEXT NOT NULL,
        request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        user_id INTEGER,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )
    """)
    conn.commit()
    conn.close()

def encrypt_key(key: bytes) -> bytes:
    """Encrypt the private key using AES encryption with CBC mode and padding"""
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(encryption_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padding_length = 16 - (len(key) % 16)
    padded_key = key + bytes([padding_length] * padding_length)
    encrypted_key = encryptor.update(padded_key) + encryptor.finalize()
    return iv + encrypted_key

def decrypt_key(encrypted_key: bytes) -> bytes:
    """Decrypt the private key using AES encryption with CBC mode and padding"""
    iv = encrypted_key[:16]
    encrypted_key = encrypted_key[16:]
    cipher = Cipher(algorithms.AES(encryption_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_key = decryptor.update(encrypted_key) + decryptor.finalize()
    padding_length = decrypted_key[-1]
    return decrypted_key[:-padding_length]

def save_key(key, exp):
    """Save an encrypted key to the database"""
    encrypted_key = encrypt_key(key)
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (encrypted_key, exp))
    conn.commit()
    conn.close()

def get_key(expired=False):
    """Retrieve a private key from the database"""
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    if expired:
        query = "SELECT key FROM keys WHERE exp <= ? LIMIT 1"
    else:
        query = "SELECT key FROM keys WHERE exp > ? LIMIT 1"
    expiration_time = int(datetime.now(tz=timezone.utc).timestamp())
    cursor.execute(query, (expiration_time,))
    result = cursor.fetchone()
    conn.close()

    if result:
        encrypted_key = result[0]
        key = decrypt_key(encrypted_key)
        print("Key found in the database.")
        return key
    return None

def save_user(username, email, password_hash):
    """Save a user to the database"""
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    cursor.execute("""
    INSERT INTO users (username, email, password_hash)
    VALUES (?, ?, ?)
    """, (username, email, password_hash))
    conn.commit()
    conn.close()

def log_auth_request(request_ip, user_id=None):
    """Log authentication request to the database"""
    request_timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    cursor.execute("""
    INSERT INTO auth_logs (request_ip, request_timestamp, user_id) 
    VALUES (?, ?, ?)
    """, (request_ip, request_timestamp, user_id))
    conn.commit()
    conn.close()
