"""
This module implements a simple HTTP server that handles authentication 
requests, generates JWT tokens, and provides a JWKS (JSON Web Key Set) 
for token verification.
"""

# Standard library imports
import base64
import datetime
import json
from urllib.parse import urlparse, parse_qs

# HTTP server imports
from http.server import BaseHTTPRequestHandler, HTTPServer

# Third-party imports
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

HOST_NAME = "localhost"
SERVER_PORT = 8080

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

# pylint: disable=invalid-name
class MyServer(BaseHTTPRequestHandler):
    """HTTP server to handle authentication requests and provide JWKS."""
    def do_PUT(self):
        """Handle HTTP PUT requests (not allowed)."""
        self.send_response(405)
        self.end_headers()
        return

    def do_PATCH(self):
        """Handle HTTP PATCH requests (not allowed)."""
        self.send_response(405)
        self.end_headers()
        return

    def do_DELETE(self):
        """Handle HTTP DELETE requests (not allowed)."""
        self.send_response(405)
        self.end_headers()
        return

    def do_HEAD(self):
        """Handle HTTP HEAD requests (not allowed)."""
        self.send_response(405)
        self.end_headers()
        return

    def do_POST(self):
        """Handle HTTP POST requests for token generation."""
        parsed_path = urlparse(self.path)
        params = parse_qs(parsed_path.query)
        if parsed_path.path == "/auth":
            headers = {
                "kid": "goodKID"
            }
            token_payload = {
                "user": "username",
                "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)
            }
            if 'expired' in params:
                headers["kid"] = "expiredKID"
                token_payload["exp"] = datetime.datetime.utcnow() - datetime.timedelta(hours=1)
            encoded_jwt = jwt.encode(token_payload, pem, algorithm="RS256", headers=headers)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(bytes(encoded_jwt, "utf-8"))
            return

        self.send_response(405)
        self.end_headers()
        return

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
    webServer = HTTPServer((HOST_NAME, SERVER_PORT), MyServer)
    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass

    webServer.server_close()
