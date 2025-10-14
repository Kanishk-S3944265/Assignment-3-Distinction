from src.database import Database
from src.voting_system import VotingSystem

if __name__ == "__main__":
    print("\n--- JWT Secure Voting System ---")
    db = Database()
    voting_system = VotingSystem(db)

    # Register voters
    voting_system.register_voter("alice", "password123")
    voting_system.register_voter("bob", "secure456")

    # Login to get JWT tokens
    token1 = voting_system.login("alice", "password123")
    token2 = voting_system.login("bob", "secure456")

    # Submit votes
    if token1: voting_system.submit_vote(token1, "Candidate A")
    if token2: voting_system.submit_vote(token2, "Candidate B")
    if token1: voting_system.submit_vote(token1, "Candidate A")

    # Show results
    voting_system.show_results()
