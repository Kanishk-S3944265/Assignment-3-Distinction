import pyotp
from src.database import Database
from src.voting_system import VotingSystem

def main():
    """Run an end-to-end test: registration, MFA, login, voting, and results."""
    print("\n--- JWT Secure Voting System ---")
    db = Database()
    system = VotingSystem(db)

    # Register voters with required profile fields
    system.register_voter(
        "alice", "password123",
        first_name="Alice", last_name="Lee",
        dob="1995-01-01", address="1 King St, Melbourne"
    )
    system.register_voter(
        "bob", "secure456",
        first_name="Bob", last_name="Ng",
        dob="1994-02-02", address="2 Queen St, Melbourne"
    )

    # Enable MFA for Alice and simulate a valid 6-digit code
    secret = db.enable_mfa("alice")
    print("[DEBUG] MFA enabled for 'alice'.")
    alice_code = pyotp.TOTP(secret).now()
    print(f"[DEBUG] MFA challenge passed for 'alice'. Current code: {alice_code}")

    # Login (Alice with MFA, Bob without)
    token_alice = system.login("alice", "password123", mfa_code=alice_code)
    token_bob = system.login("bob", "secure456")

    # Simulate voting actions
    if token_alice:
        system.submit_vote(token_alice, "Candidate A")
    if token_bob:
        system.submit_vote(token_bob, "Candidate B")
    if token_alice:
        system.submit_vote(token_alice, "Candidate A")

    # Display final vote counts
    system.show_results()


if __name__ == "__main__":
    main()


