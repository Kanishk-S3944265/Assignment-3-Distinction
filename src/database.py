import hashlib
import os
import pyotp

class Database:
    """In-memory storage for voters and votes with password hashing and MFA data."""

    def __init__(self):
        """Initialise in-memory voter and vote stores."""
        self.voters = {}  # {username: {"salt": bytes, "password": bytes, "mfa_secret": str|None, "role": str}}
        self.votes = []   # [{"user": str, "candidate": str}]

    def hash_password(self, password, salt=None):
        """Return (salt, hashed) using PBKDF2-HMAC-SHA256."""
        if not salt:
            salt = os.urandom(16)
        hashed = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
        return salt, hashed

    def add_voter(self, username, password, role="voter"):
        """Create a voter with salted, hashed password and optional role."""
        if username in self.voters:
            raise ValueError("Voter already registered.")
        salt, hashed_pw = self.hash_password(password)
        # Always show for demo
        print(f"[DEBUG] Created salt for {username}: {salt.hex()}")
        print(f"[DEBUG] Hashed password for {username}: {hashed_pw.hex()}")
        self.voters[username] = {
            "salt": salt,
            "password": hashed_pw,
            "mfa_secret": None,
            "role": role
        }

    def verify_password(self, username, password):
        """Return True if provided password matches stored hash for the user."""
        voter = self.voters.get(username)
        if not voter:
            return False
        salt = voter["salt"]
        _, hashed_input = self.hash_password(password, salt)
        return hashed_input == voter["password"]

    # ---------- MFA ----------
    def enable_mfa(self, username) -> str:
        """Create and store a per-user TOTP secret; return the secret."""
        voter = self.voters.get(username)
        if not voter:
            raise ValueError("User not found")
        if voter.get("mfa_secret"):
            return voter["mfa_secret"]
        secret = pyotp.random_base32()
        voter["mfa_secret"] = secret
        return secret

    def mfa_enabled(self, username) -> bool:
        """Return True if the user has MFA configured."""
        voter = self.voters.get(username)
        return bool(voter and voter.get("mfa_secret"))

    def verify_mfa(self, username, code: str) -> bool:
        """Return True if the provided 6-digit TOTP code is valid for the user."""
        voter = self.voters.get(username)
        if not voter or not voter.get("mfa_secret"):
            return False
        totp = pyotp.TOTP(voter["mfa_secret"])
        return bool(totp.verify(code, valid_window=1))  # small skew allowed

    # ---------- Roles / RBAC ----------
    def has_role(self, username, role) -> bool:
        """Return True if the user has the specified role (e.g., 'admin')."""
        voter = self.voters.get(username)
        return bool(voter and voter.get("role") == role)

    def set_role(self, username, role: str) -> None:
        """Set the role for an existing user."""
        voter = self.voters.get(username)
        if not voter:
            raise ValueError("User not found")
        voter["role"] = role

    # ---------- Voting ----------
    def get_voter(self, username):
        """Return the voter record dict for a username, or None."""
        return self.voters.get(username)

    def add_vote(self, username, candidate):
        """Append a vote record for the given user and candidate."""
        self.votes.append({"user": username, "candidate": candidate})

    def get_results(self):
        """Return a dict of candidate -> vote count."""
        results = {}
        for v in self.votes:
            results[v["candidate"]] = results.get(v["candidate"], 0) + 1
        return results
