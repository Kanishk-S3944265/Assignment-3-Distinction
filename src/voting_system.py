import uuid
from src.database import Database

class VotingSystem:
    """
    Base online voting system.
    Handles registration, login, and voting before security features are added.
    """

    def __init__(self, db: Database):
        self.db = db
        self.sessions = {}  # {session_id: username}

    def register_voter(self, username, password):
        """Registers a new voter."""
        self.db.add_voter(username, password)
        print(f"[+] Voter '{username}' registered successfully.")

    def login(self, username, password):
        """Logs in the voter and returns a new session ID."""
        voter = self.db.get_voter(username)
        if voter and voter["password"] == password:
            session_id = str(uuid.uuid4())
            self.sessions[session_id] = username
            print(f"[+] Login successful for '{username}'. Session ID: {session_id}")
            return session_id
        else:
            print("[!] Invalid username or password.")
            return None

    def submit_vote(self, session_id, candidate):
        """Allows an authenticated voter to submit a vote."""
        if session_id in self.sessions:
            user = self.sessions[session_id]
            self.db.add_vote(user, candidate)
            print(f"[+] Vote submitted by '{user}' for candidate '{candidate}'.")
            return True
        else:
            print("[!] Invalid session. Please log in again.")
            return False

    def show_results(self):
        """Displays total votes for each candidate (admin feature)."""
        results = self.db.get_results()
        print("\nVoting Results:")
        for candidate, count in results.items():
            print(f"  - {candidate}: {count} vote(s)")