import pyotp
from src.database import Database
from src.voting_system import VotingSystem

def main():
    """Run a simple scenario: register, enable MFA for one user, login, vote, results."""
    print("\n--- JWT Secure Voting System ---")
    db = Database()
    system = VotingSystem(db)

    # Register voters (salt + hash printed by Database.add_voter)
    system.register_voter("alice", "password123")
    system.register_voter("bob", "secure456")

    # Enable MFA for alice and generate the current TOTP code (no secrets printed)
    secret = db.enable_mfa("alice")
    print("[DEBUG] MFA enabled for 'alice'.")
    alice_code = pyotp.TOTP(secret).now()
    print("[DEBUG] MFA challenge passed for 'alice'.")

    # Login (alice needs MFA; bob does not)
    token_alice = system.login("alice", "password123", mfa_code=alice_code)
    token_bob   = system.login("bob", "secure456")

    # Submit votes
    if token_alice: system.submit_vote(token_alice, "Candidate A")
    if token_bob:   system.submit_vote(token_bob, "Candidate B")
    if token_alice: system.submit_vote(token_alice, "Candidate A")

    # Show results
    system.show_results()

if __name__ == "__main__":
    main()

