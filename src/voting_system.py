import jwt
import datetime
import os
import secrets
from src.database import Database

# shared JWT signing key (env or random)
SECRET_KEY = os.environ.get("JWT_SECRET_KEY", secrets.token_hex(32))
print(f"[DEBUG] JWT secret key (masked): {SECRET_KEY[:6]}...{SECRET_KEY[-6:]}")

class VotingSystem:
    """Voting system with password hashing, optional MFA, JWT sessions, audit + rate-limit hooks."""

    WINDOW_SECONDS = 10 * 60
    MAX_ATTEMPTS = 5

    def __init__(self, db: Database):
        self.db = db

    def _audit(self, event: str, **kv):
        ts = datetime.datetime.utcnow().isoformat() + "Z"
        line = ts + " event=" + event + " " + " ".join(f"{k}={v}" for k, v in kv.items())
        with open("audit.log", "a", encoding="utf-8") as f:
            f.write(line + "\n")

    # --- Registration now takes profile fields ---
    def register_voter(self, username, password, *, first_name, last_name, dob, address):
        self.db.add_voter(username, password,
                          first_name=first_name, last_name=last_name, dob=dob, address=address)
        print(f"[+] Voter '{username}' registered successfully.")
        self._audit("register_success", user=username)

    # --- Simple per-user login rate limiting ---
    def _allow_login(self, username: str) -> bool:
        from time import time
        bucket = self.db.login_attempts.setdefault(username, [])
        now = time()
        # drop old attempts
        self.db.login_attempts[username] = [t for t in bucket if now - t <= self.WINDOW_SECONDS]
        if len(self.db.login_attempts[username]) >= self.MAX_ATTEMPTS:
            return False
        self.db.login_attempts[username].append(now)
        return True

    def login(self, username, password, mfa_code: str | None = None):
        if not self._allow_login(username):
            print("[-] Rate limit reached. Try again later.")
            self._audit("login_rate_limited", user=username)
            return None

        voter = self.db.get_voter(username)
        if voter and self.db.verify_password(username, password):
            if self.db.mfa_enabled(username):
                self._audit("mfa_required", user=username)
                if not mfa_code or not self.db.verify_mfa(username, mfa_code):
                    print("[-] MFA verification failed or missing.")
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
            return token

        print("[-] Invalid username or password.")
        self._audit("login_failure", user=username)
        return None

    def verify_token(self, token):
        try:
            decoded = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            return decoded["username"]
        except jwt.ExpiredSignatureError:
            print("[-] Token expired.")
        except jwt.InvalidTokenError:
            print("[-] Invalid token.")
        return None

    def submit_vote(self, token, candidate):
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
        results = self.db.get_results()
        print("\nVoting Results:")
        for candidate, count in results.items():
            print(f"  - {candidate}: {count} vote(s)")
        self._audit("results_viewed", total_candidates=len(results))

    def show_results_secure(self, token):
        user = self.verify_token(token)
        if not user or not self.db.has_role(user, "admin"):
            print("[-] Forbidden: admin only.")
            self._audit("results_forbidden", user=(user or "unknown"))
            return
        self._audit("results_viewed_admin", user=user)
        self.show_results()
