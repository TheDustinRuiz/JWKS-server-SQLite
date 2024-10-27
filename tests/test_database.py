"""Database tests for the JWKS server"""
from datetime import datetime, timezone
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from database import init_db, save_key, get_key

def generate_private_key():
    """Generates a private RSA key in PEM format for testing."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    return pem

@pytest.fixture(scope="function", autouse=True)
def setup_database():
    """Setup a temporary database and clear it for each test."""
    init_db()

def test_save_key():
    """Test saving a key to the database"""
    # Generate a private key in PEM format
    key = generate_private_key()
    exp = int(datetime.now(timezone.utc).timestamp()) + 3600
    save_key(key, exp)
    # Retrieve the key and deserialize it within the test
    retrieved_key = get_key(expired=False)
    if retrieved_key:
        retrieved_key_data = retrieved_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
    else:
        retrieved_key_data = None
    assert retrieved_key_data == key

def test_expired_key_retrieval():
    """Test retrieving an expired key from the database"""
    # Generate a private key in PEM format
    key = generate_private_key()
    expired_exp = int(datetime.now(timezone.utc).timestamp()) - 3600
    save_key(key, expired_exp)
    # Retrieve the expired key and deserialize it within the test
    retrieved_key = get_key(expired=True)
    if retrieved_key:
        retrieved_key_data = retrieved_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
    else:
        retrieved_key_data = None
    assert retrieved_key_data == key
