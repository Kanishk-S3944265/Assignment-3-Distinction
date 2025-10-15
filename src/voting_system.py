import jwt
import datetime
import os
import secrets
from src.database import Database

# Generate/read signing key and print a masked preview 
SECRET_KEY = os.environ.get("JWT_SECRET_KEY", secrets.token_hex(32))
print(f"[DEBUG] JWT secret key (masked): {SECRET_KEY[:6]}...{SECRET_KEY[-6:]}")

class VotingSystem:
    """Voting system that supports password hashing, optional MFA, and JWT sessions."""

    def __init__(self, db):
        """Accept a Database instance for persistence."""
        self.db = db

    def register_voter(self, username, password):
        """Register a voter using salted, hashed password storage."""
        self.db.add_voter(username, password)
        print(f"[+] Voter '{username}' registered successfully.")

    def login(self, username, password, mfa_code: str | None = None):
        """
        Authenticate a user with password and (if configured) a TOTP code.
        Return a signed JWT on success; otherwise return None.
        """
        voter = self.db.get_voter(username)
        if voter and self.db.verify_password(username, password):
            if self.db.mfa_enabled(username):
                if not mfa_code or not self.db.verify_mfa(username, mfa_code):
                    print("[-] MFA verification failed or missing.")
                    return None

            payload = {
                "username": username,
                "iat": datetime.datetime.utcnow(),
                "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=5)
            }
            token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")
            print(f"[+] Login successful for '{username}'. JWT issued.")
            # Keep the exact masked line style you wanted
            print("[DEBUG] JWT (masked): ***")
            return token

        print("[-] Invalid username or password.")
        return None

    def verify_token(self, token):
        """Decode and validate a JWT. Return the username if valid; else None."""
        try:
            decoded = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            return decoded["username"]
        except jwt.ExpiredSignatureError:
            print("[-] Token expired.")
        except jwt.InvalidTokenError:
            print("[-] Invalid token.")
        return None

    def submit_vote(self, token, candidate):
        """Record a vote if the provided JWT is valid."""
        username = self.verify_token(token)
        if username:
            self.db.add_vote(username, candidate)
            print(f"[+] Vote submitted by '{username}' for candidate '{candidate}'.")
            return True
        print("[-] Vote failed. Invalid or expired session.")
        return False

    def show_results(self):
        """Print the total votes for each candidate."""
        results = self.db.get_results()
        print("\nVoting Results:")
        for candidate, count in results.items():
            print(f"  - {candidate}: {count} vote(s)")

    def show_results_secure(self, token):
        """Print results only if the caller is an admin (RBAC check)."""
        user = self.verify_token(token)
        if not user or not self.db.has_role(user, "admin"):
            print("[-] Forbidden: admin only.")
            return
        self.show_results()

