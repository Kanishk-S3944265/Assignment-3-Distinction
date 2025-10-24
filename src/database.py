import hashlib, os, hmac, time
from cryptography.fernet import Fernet
from typing import Optional



class Database:
    """
    In-memory DB: voters + votes.
    - Passwords stored as PBKDF2-HMAC(SHA-256) with per-user random salt.
    - Voter profile includes first_name, last_name, dob, address.
    - Optional MFA secret + simple role.
    """

    def __init__(self):
        self.voters = {}   # username -> {...}
        self.votes = []    # {"user": "...", "candidate": "..."}
        # rate-limit store: username -> [(ts1, ts2, ...)]
        self.login_attempts = {}

    # --- password hashing ---
    def hash_password(self, password: str, salt: Optional[bytes] = None):
        if not salt:
            salt = os.urandom(16)
            print(f"[DEBUG] Created salt: {salt.hex()}")
        hashed = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100_000)
        print(f"[DEBUG] Hashed password: {hashed.hex()}")
        return salt, hashed

    def add_voter(self, username: str, password: str, *, first_name: str, last_name: str, dob: str, address: str):
        if username in self.voters:
            raise ValueError("Voter already registered.")
        salt, hashed_pw = self.hash_password(password)
        self.voters[username] = {
            "salt": salt,
            "password": hashed_pw,
            "first_name": first_name.strip(),
            "last_name": last_name.strip(),
            "dob": dob.strip(),          # store as string; can validate format upstream
            "address": address.strip(),
            "mfa_secret": None,
            "role": "voter"
        }

    def verify_password(self, username: str, password: str) -> bool:
        voter = self.voters.get(username)
        if not voter:
            return False
        salt = voter["salt"]
        _, hashed_input = self.hash_password(password, salt)
        return hmac.compare_digest(hashed_input, voter["password"])

    def get_voter(self, username: str):
        return self.voters.get(username)

    def set_role(self, username: str, role: str):
        if username not in self.voters:
            raise ValueError("User not found.")
        if role not in ("admin", "voter"):
            raise ValueError("Role must be 'admin' or 'voter'.")
        self.voters[username]["role"] = role

    def has_role(self, username: str, role: str) -> bool:
        v = self.voters.get(username)
        return bool(v and v.get("role") == role)

    # --- MFA (TOTP) helpers ---
    def enable_mfa(self, username: str):
        if username not in self.voters:
            raise ValueError("User not found.")
        try:
            import pyotp
        except ImportError:
            raise ValueError("pyotp not installed. Add 'pyotp' to requirements.txt")
        secret = pyotp.random_base32()
        self.voters[username]["mfa_secret"] = secret
        return secret

    def mfa_enabled(self, username: str) -> bool:
        v = self.voters.get(username)
        return bool(v and v.get("mfa_secret"))

    def verify_mfa(self, username: str, code: str) -> bool:
        v = self.voters.get(username)
        if not v or not v.get("mfa_secret"):
            return False
        try:
            import pyotp
        except ImportError:
            return False
        totp = pyotp.TOTP(v["mfa_secret"])
        try:
            return bool(totp.verify(code, valid_window=1))
        except Exception:
            return False

    # --- votes ---
    def add_vote(self, username: str, candidate: str):
        self.votes.append({"user": username, "candidate": candidate})

    def get_results(self):
        out = {}
        for v in self.votes:
            out[v["candidate"]] = out.get(v["candidate"], 0) + 1
        return out
