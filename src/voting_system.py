import jwt
import datetime
import os
import secrets
import time
from src.database import Database

# Generate/read signing key 
SECRET_KEY = os.environ.get("JWT_SECRET_KEY", secrets.token_hex(32))
print(f"[DEBUG] JWT secret key (masked): {SECRET_KEY[:6]}...{SECRET_KEY[-6:]}")

# Rate limiting config
MAX_ATTEMPTS = 5           # allowed failed attempts
WINDOW_SECONDS = 10 * 60   # rolling window (10 minutes)

class VotingSystem:
    """Voting system that supports password hashing, optional MFA, and JWT sessions."""

    def __init__(self, db):
        """Accept a Database instance """
        self.db = db
        # username -> [timestamps of failed attempts]
        self._failed_logins = {}

    def _audit(self, event: str, **kv):
        """Append an audit log line with timestamp and key=value pairs."""
        ts = datetime.datetime.utcnow().isoformat() + "Z"
        line = ts + " event=" + event + " " + " ".join(f"{k}={v}" for k, v in kv.items())
        with open("audit.log", "a", encoding="utf-8") as f:
            f.write(line + "\n")

    # ---------- rate limiting helpers ----------
    def _prune_attempts(self, username: str):
        """Remove failure timestamps older than the rolling window."""
        now = time.time()
        attempts = self._failed_logins.get(username, [])
        self._failed_logins[username] = [t for t in attempts if now - t <= WINDOW_SECONDS]

    def _record_failure(self, username: str):
        """Record a failed login attempt for the user."""
        self._prune_attempts(username)
        self._failed_logins.setdefault(username, []).append(time.time())

    def _too_many_failures(self, username: str) -> bool:
        """Return True if user exceeded MAX_ATTEMPTS within WINDOW_SECONDS."""
        self._prune_attempts(username)
        return len(self._failed_logins.get(username, [])) >= MAX_ATTEMPTS

    def register_voter(self, username, password):
        """Register a voter using salted, hashed password storage."""
        self.db.add_voter(username, password)
        print(f"[+] Voter '{username}' registered successfully.")
        self._audit("register_success", user=username)

    def login(self, username, password, mfa_code: str | None = None):
        """
        Authenticate a user with password and (if configured) a TOTP code.
        Return a signed JWT on success; otherwise return None.
        """
        if self._too_many_failures(username):
            print("[-] Too many failed attempts. Please try again later.")
            self._audit("login_rate_limited", user=username)
            return None

        voter = self.db.get_voter(username)
        if voter and self.db.verify_password(username, password):
            if self.db.mfa_enabled(username):
                self._audit("mfa_required", user=username)
                if not mfa_code or not self.db.verify_mfa(username, mfa_code):
                    print("[-] MFA verification failed or missing.")
                    self._record_failure(username)
                    self._audit("mfa_failure", user=username)
                    return None

            payload = {
                "username": username,
                "iat": datetime.datetime.utcnow(),
                "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=5)
            }
            token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")
            print(f"[+] Login successful for '{username}'. JWT issued.")
            print("[DEBUG] JWT (masked): ***")
            self._audit("login_success", user=username)
            # reset failures on success
            self._failed_logins.pop(username, None)
            return token

        print("[-] Invalid username or password.")
        self._record_failure(username)
        self._audit("login_failure", user=username)
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
            self._audit("vote_success", user=username, candidate=candidate)
            return True
        print("[-] Vote failed. Invalid or expired session.")
        self._audit("vote_failure", candidate=candidate)
        return False

    def show_results(self):
        """Print the total votes for each candidate."""
        results = self.db.get_results()
        print("\nVoting Results:")
        for candidate, count in results.items():
            print(f"  - {candidate}: {count} vote(s)")
        self._audit("results_viewed", total_candidates=len(results))

    def show_results_secure(self, token):
        """Print results only if the caller is an admin (RBAC check)."""
        user = self.verify_token(token)
        if not user or not self.db.has_role(user, "admin"):
            print("[-] Forbidden: admin only.")
            self._audit("results_forbidden", user=(user or "unknown"))
            return
        self._audit("results_viewed_admin", user=user)
        self.show_results()



