import sys
import getpass
from src.database import Database
from src.voting_system import VotingSystem

def main():
    """Interactive CLI for the voting system (register, MFA, login, vote, RBAC)."""
    db = Database()
    app = VotingSystem(db)
    tokens = {}  # username -> latest JWT (simulates client-side storage)

    print("\n=== Online Voting System (CLI) ===")
    print("Type 'help' for commands. Ctrl+C to exit.\n")

    while True:
        try:
            cmd = input("> ").strip().lower()

            if cmd in ("help", "?"):
                print(
                    "Commands:\n"
                    "  register                - create a voter account\n"
                    "  enable_mfa              - enable TOTP MFA for a user\n"
                    "  login                   - login (prompts for MFA if enabled)\n"
                    "  vote                    - submit a vote using your JWT\n"
                    "  results                 - show results (no RBAC)\n"
                    "  results_admin           - show results (admin-only via RBAC)\n"
                    "  setrole                 - set a user's role (admin/voter)\n"
                    "  whoami                  - decode your token and show username\n"
                    "  logout                  - forget local token for a user\n"
                    "  exit                    - quit"
                )

            elif cmd == "register":
                """Create a new voter with a hashed password."""
                username = input("username: ").strip()
                password = getpass.getpass("password: ")
                try:
                    app.register_voter(username, password)
                except ValueError as e:
                    print(f"[-] {e}")

            elif cmd == "enable_mfa":
                """Enable TOTP MFA for an existing user and print the current code."""
                username = input("username: ").strip()
                try:
                    import pyotp
                    secret = db.enable_mfa(username)
                    print(f"[DEBUG] MFA enabled for '{username}'.")
                    # Show the current valid TOTP code for demo (changes every ~30s)
                    code = pyotp.TOTP(secret).now()
                    print(f"[DEBUG] Current TOTP code for '{username}': {code}")
                    print("[DEBUG] You can also enrol this secret in an authenticator app.")
                except ValueError as e:
                    print(f"[-] {e}")
                except Exception as ex:
                    print(f"[-] MFA enable failed: {ex}")

            elif cmd == "login":
                """Authenticate a user; prompt for MFA code if enabled; store JWT locally."""
                username = input("username: ").strip()
                password = getpass.getpass("password: ")
                mfa_code = None
                if db.mfa_enabled(username):
                    mfa_code = input("MFA code (6 digits): ").strip()
                token = app.login(username, password, mfa_code=mfa_code)
                if token:
                    tokens[username] = token
                    print("[+] Token stored locally for this session.")

            elif cmd == "vote":
                """Submit a vote using the caller's stored JWT token."""
                username = input("username: ").strip()
                token = tokens.get(username)
                if not token:
                    print("[-] No token found. Please login first.")
                    continue
                candidate = input("candidate: ").strip()
                app.submit_vote(token, candidate)

            elif cmd == "results":
                """Show vote tally without RBAC (open view)."""
                app.show_results()

            elif cmd == "results_admin":
                """Show vote tally with RBAC (admin-only)."""
                username = input("admin username: ").strip()
                token = tokens.get(username)
                if not token:
                    print("[-] No token found. Please login first.")
                    continue
                app.show_results_secure(token)

            elif cmd == "setrole":
                """Set a user's role to 'admin' or 'voter'."""
                username = input("username to update: ").strip()
                role = input("role (admin|voter): ").strip().lower()
                try:
                    db.set_role(username, role)
                    print(f"[+] Role for '{username}' set to '{role}'.")
                except ValueError as e:
                    print(f"[-] {e}")

            elif cmd == "whoami":
                """Decode the caller's token and print the username it belongs to."""
                username = input("username: ").strip()
                token = tokens.get(username)
                if not token:
                    print("[-] No token found. Please login first.")
                    continue
                u = app.verify_token(token)
                if u:
                    print(f"[+] Token belongs to: {u}")

            elif cmd == "logout":
                """Forget the locally stored token for a user."""
                username = input("username: ").strip()
                if tokens.pop(username, None):
                    print("[+] Local token cleared.")
                else:
                    print("[-] No token found for that user.")

            elif cmd in ("exit", "quit"):
                print("bye!")
                sys.exit(0)

            elif cmd == "":
                continue
            else:
                print("[-] unknown command. type 'help'.")

        except KeyboardInterrupt:
            print("\nEvery Vote Counts Bye!")
            sys.exit(0)

if __name__ == "__main__":
    main()

