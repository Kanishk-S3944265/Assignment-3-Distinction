
import jwt
import datetime
import os
import secrets
from src.database import Database

# Use env var if present; else generate a strong random secret for demo
SECRET_KEY = os.environ.get("JWT_SECRET_KEY", secrets.token_hex(32))
print(f"[DEBUG] JWT secret key (masked): {SECRET_KEY[:6]}...{SECRET_KEY[-6:]}")

class VotingSystem:
    """Electronic voting system with hashed passwords and JWT-based sessions."""

    def __init__(self, db):
        self.db = db

    def register_voter(self, username, password):
        """Register a voter. Password is stored as salted PBKDF2-HMAC hash."""
        self.db.add_voter(username, password)
        print(f"[+] Voter '{username}' registered successfully.")

    def login(self, username, password):
        """Verify password and issue a short-lived JWT token."""
        voter = self.db.get_voter(username)
        if voter and self.db.verify_password(username, password):
            payload = {
                "username": username,
                "iat": datetime.datetime.utcnow(),
                "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=5)
            }
            token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")
            print(f"[+] Login successful for '{username}'. JWT issued.")
            print(f"[DEBUG] JWT (masked): {token[:25]}...")
            return token
        print("[-] Invalid username or password.")
        return None

    def verify_token(self, token):
        """Decode/verify a JWT. Returns username if valid, else None."""
        try:
            decoded = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            return decoded["username"]
        except jwt.ExpiredSignatureError:
            print("[-] Token expired. Please log in again.")
        except jwt.InvalidTokenError:
            print("[-] Invalid or tampered token.")
        return None

    def submit_vote(self, token, candidate):
        """Submit a vote if the JWT is valid."""
        username = self.verify_token(token)
        if username:
            self.db.add_vote(username, candidate)
            print(f"[+] Vote submitted by '{username}' for candidate '{candidate}'.")
            return True
        print("[-] Vote failed. Invalid or expired session.")
        return False

    def show_results(self):
        """Print vote tally by candidate."""
        results = self.db.get_results()
        print("\nVoting Results:")
        for candidate, count in results.items():
            print(f"  - {candidate}: {count} vote(s)")

