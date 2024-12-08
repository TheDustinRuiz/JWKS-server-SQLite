"""
This module implements a simple HTTP server that handles registration and authentication 
requests, generates JWT tokens, and provides a JWKS (JSON Web Key Set) 
for token verification.
"""

# Standard library imports
import base64
import datetime
from collections import defaultdict
import time
import json
import uuid
from urllib.parse import urlparse, parse_qs
import sqlite3
from datetime import datetime, timezone, timedelta

# HTTP server imports
from http.server import BaseHTTPRequestHandler, HTTPServer

# Third-party imports
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from argon2 import PasswordHasher

from database import init_db, save_key, get_key, save_user, log_auth_request

HOST_NAME = "localhost"
SERVER_PORT = 8080
DATABASE_FILE = "totally_not_my_privateKeys.db"

private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
expired_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)
expired_pem = expired_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)

numbers = private_key.private_numbers()


def int_to_base64(value):
    """Convert an integer to a Base64URL-encoded string"""
    value_hex = format(value, 'x')
    # Ensure even length
    if len(value_hex) % 2 == 1:
        value_hex = '0' + value_hex
    value_bytes = bytes.fromhex(value_hex)
    encoded = base64.urlsafe_b64encode(value_bytes).rstrip(b'=')
    return encoded.decode('utf-8')

class RateLimiter:
    """Rate limiter implementation"""
    def __init__(self, max_requests, window_seconds):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests = defaultdict(list)

    def is_allowed(self, ip_address):
        """Check if the IP address is allowed to make a request."""
        current_time = time.time()
        if ip_address not in self.requests:
            self.requests[ip_address] = []
        self.requests[ip_address] = [
            t for t in self.requests[ip_address] if current_time - t <= self.window_seconds
        ]
        if len(self.requests[ip_address]) < self.max_requests:
            self.requests[ip_address].append(current_time)
            return True
        return False

rate_limiter = RateLimiter(max_requests=10, window_seconds=1)

# pylint: disable=invalid-name
class MyServer(BaseHTTPRequestHandler):
    """HTTP server to handle authentication requests and provide JWKS."""
    def __init__(self, *args, **kwargs):
        self.ph = PasswordHasher()
        super().__init__(*args, **kwargs)

    def handle_register(self):
        """Handle user registration."""
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length)
        try:
            data = json.loads(body)
            username = data.get("username")
            email = data.get("email")

            if not username or not email:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b"Missing username or email in request body.")
                return


            password = str(uuid.uuid4())
            password_hash = self.ph.hash(password)
            save_user(username, email, password_hash)

            self.send_response(201)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            response = {"password": password}
            self.wfile.write(bytes(json.dumps(response), "utf-8"))

        except json.JSONDecodeError:
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b"Invalid JSON format.")
        except sqlite3.IntegrityError:
            self.send_response(409)
            self.end_headers()
            self.wfile.write(b"Username or email already exists.")

    def do_PUT(self):
        """Handle HTTP PUT requests (not allowed)."""
        self.send_response(405)
        self.end_headers()

    def do_PATCH(self):
        """Handle HTTP PATCH requests (not allowed)."""
        self.send_response(405)
        self.end_headers()

    def do_DELETE(self):
        """Handle HTTP DELETE requests (not allowed)."""
        self.send_response(405)
        self.end_headers()

    def do_HEAD(self):
        """Handle HTTP HEAD requests (not allowed)."""
        self.send_response(405)
        self.end_headers()

    def do_POST(self):
        """Handle HTTP POST requests for registration and authentication."""
        parsed_path = urlparse(self.path)
        params = parse_qs(parsed_path.query)
        if parsed_path.path == "/register":
            self.handle_register()
            return
        elif parsed_path.path == "/auth":
            client_ip = self.client_address[0]
            if not rate_limiter.is_allowed(client_ip):
                self.send_response(429)
                self.end_headers()
                self.wfile.write(b"Too Many Requests")
                return
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length)

            try:
                data = json.loads(body)
                username = data.get("username")
                password = data.get("password")

                if not username or not password:
                    self.send_response(400)
                    self.end_headers()
                    self.wfile.write(b"Missing username or password in request body.")
                    return

                user_id = self.get_user_id_by_username(username)

                if not user_id:
                    self.send_response(401)
                    self.end_headers()
                    self.wfile.write(b"Invalid username or password.")
                    return

                headers = {
                    "kid": "goodKID"
                }
                token_payload = {
                    "user": "username",
                    "exp": int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp())
                }
                if 'expired' in params:
                    headers["kid"] = "expiredKID"
                    token_payload["exp"] = int((datetime.now(timezone.utc)
                                                - timedelta(hours=1)).timestamp())
                encoded_jwt = jwt.encode(token_payload, get_key(),
                                         algorithm="RS256", headers=headers)

                request_ip = self.client_address[0]
                log_auth_request(request_ip, user_id)

                self.send_response(200)
                self.end_headers()
                self.wfile.write(bytes(encoded_jwt, "utf-8"))
            except json.JSONDecodeError:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b"Invalid JSON format.")

            return
        else:
            self.send_response(405)
            self.end_headers()
            return

    def get_user_id_by_username(self, username):
        """Fetch the user ID from the database based on the username."""
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()
        conn.close()

        if result:
            return result[0]
        else:
            return None

    def do_GET(self):
        """Handle HTTP GET requests for JWKS retrieval."""
        if self.path == "/.well-known/jwks.json":
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            keys = {
                "keys": [
                    {
                        "alg": "RS256",
                        "kty": "RSA",
                        "use": "sig",
                        "kid": "goodKID",
                        "n": int_to_base64(numbers.public_numbers.n),
                        "e": int_to_base64(numbers.public_numbers.e),
                    }
                ]
            }
            self.wfile.write(bytes(json.dumps(keys), "utf-8"))
            return

        self.send_response(405)
        self.end_headers()
        return


if __name__ == "__main__":
    init_db()
    try:
        save_key(pem, int((datetime.now(timezone.utc) + timedelta(days=1)).timestamp()))
        save_key(expired_pem, int((datetime.now(timezone.utc) - timedelta(hours=2)).timestamp()))
    except sqlite3.OperationalError as e:
        print("Error saving key:", e)
    webServer = HTTPServer((HOST_NAME, SERVER_PORT), MyServer)
    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass

    webServer.server_close()
