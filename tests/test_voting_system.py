from src.database import Database
from src.voting_system import VotingSystem

def main():
    db = Database()
    system = VotingSystem(db)

    print("\n--- Online Voting System ---")
    # 1. Register voters
    system.register_voter("alice", "1234")
    system.register_voter("bob", "5678")

    # 2. Login and get session IDs
    session_alice = system.login("alice", "1234")
    session_bob = system.login("bob", "5678")

    # 3. Submit votes
    system.submit_vote(session_alice, "Candidate A")
    system.submit_vote(session_bob, "Candidate B")
    system.submit_vote(session_alice, "Candidate A")  # Alice votes twice for demo

    # 4. Display results
    system.show_results()

if __name__ == "__main__":
    main()