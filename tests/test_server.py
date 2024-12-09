"""
This module tests a JWKS server for authentication and key management.
"""

import unittest
import os
from http.server import HTTPServer
from datetime import datetime, timezone, timedelta
from main import MyServer, rate_limiter
from database import encrypt_key, decrypt_key, init_db, save_key, get_key



class TestJWKSAuthServer(unittest.TestCase):
    """Test suite for the JWKS server."""
    @classmethod
    def setUpClass(cls):
        """Setup the database and keys."""
        init_db()
        expired_timestamp = int((datetime.now(timezone.utc) - timedelta(hours=2)).timestamp())
        valid_timestamp = int((datetime.now(timezone.utc) + timedelta(days=1)).timestamp())
        cls.sample_key = b"test_key_1234567890123456"
        save_key(cls.sample_key, valid_timestamp)
        save_key(cls.sample_key, expired_timestamp)
        return cls.sample_key, expired_timestamp, valid_timestamp

    def setUp(self):
        """Setup the HTTP server for tests."""
        server_address = ("localhost", 0)  # Use port 0 to auto-assign
        self.httpd = HTTPServer(server_address, MyServer)
        self.server_port = self.httpd.server_address[1]

    def tearDown(self):
        """Stop the server after tests."""
        self.httpd.server_close()

    def test_database_initialization(self):
        """Test if the database is initialized correctly."""
        init_db()
        encrypted_key = get_key(expired=False)

        self.assertIsNotNone(encrypted_key, "Key should be saved in the database")

    def test_key_format(self):
        """Ensure the retrieved key has the correct format."""
        encrypted_key = get_key(expired=False)
        self.assertTrue(isinstance(encrypted_key, bytes))
        self.assertGreater(len(encrypted_key), 0, "Key should not be empty")

    def test_encrypt_decrypt_key(self):
        """Test key encryption and decryption."""
        encrypted = encrypt_key(self.sample_key)
        decrypted = decrypt_key(encrypted)
        self.assertEqual(self.sample_key, decrypted)

    def test_rate_limiter(self):
        """Test rate limiting functionality."""
        ip = "192.168.1.1"
        for _ in range(10):
            self.assertTrue(rate_limiter.is_allowed(ip))
        self.assertFalse(rate_limiter.is_allowed(ip))

    @classmethod
    def tearDownClass(cls):
        """Cleanup the database after tests."""
        os.remove("totally_not_my_privateKeys.db")


if __name__ == "__main__":
    unittest.main()
