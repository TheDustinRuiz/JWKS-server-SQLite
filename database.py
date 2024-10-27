"""Database helper functions for the JWKS server"""

from datetime import datetime, timezone
import sqlite3
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

DATABASE_FILE = 'totally_not_my_privateKeys.db'

def init_db():
    """Initialize the database"""
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS keys(
            kid INTEGER PRIMARY KEY AUTOINCREMENT,
            key BLOB NOT NULL,
            exp INTEGER NOT NULL
        )
    """)
    cursor.execute("DELETE FROM keys")
    conn.commit()
    conn.close()

def save_key(key, exp):
    """Save a private key to the database"""
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (key, exp))
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
        key = serialization.load_pem_private_key(
            result[0],
            password=None,
            backend=default_backend()
        )
        print("Key found in the database.")
        return key
    return None
