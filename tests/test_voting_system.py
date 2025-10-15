from src.database import Database
from src.voting_system import VotingSystem

def main():
    print("\n--- JWT Secure Voting System ---")
    db = Database()
    system = VotingSystem(db)

    system.register_voter("alice", "password123")
    system.register_voter("bob", "secure456")

    token_alice = system.login("alice", "password123")
    token_bob   = system.login("bob", "secure456")

    if token_alice: system.submit_vote(token_alice, "Candidate A")
    if token_bob:   system.submit_vote(token_bob, "Candidate B")
    if token_alice: system.submit_vote(token_alice, "Candidate A")

    system.show_results()

if __name__ == "__main__":
    main()

