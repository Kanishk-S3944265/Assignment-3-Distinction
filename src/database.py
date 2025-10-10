import hashlib, os
class Database:
    """
    Simple in-memory database for storing voters and votes.
   
    """
    def __init__(self):
        self.voters = {}   # {username: {"salt": bytes, "password": bytes}}
        self.votes = []    # [{"user": "alice", "candidate": "X"}]
    
    def hash_password(self, password, salt=None):
        if not salt:
            salt = os.urandom(16)
        hashed = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
        return salt, hashed
    
    def add_voter(self, username, password):
        if username in self.voters:
            raise ValueError("Voter already registered.")
        salt, hashed_pw = self.hash_password(password)
        print(f"[DEBUG] Created salt for {username}: {salt.hex()}")
        print(f"[DEBUG] Hashed password for {username}: {hashed_pw.hex()}")
        self.voters[username] = {"salt": salt, "password": hashed_pw}
        
    def verify_password(self, username, password):
        voter = self.voters.get(username)
        if not voter:
            return False
        salt = voter["salt"]
        _, hashed_input = self.hash_password(password, salt)
        return hashed_input == voter["password"]

    def get_voter(self, username):
        return self.voters.get(username)

    def add_vote(self, username, candidate):
        self.votes.append({"user": username, "candidate": candidate})

    def get_results(self):
        results = {}
        for v in self.votes:
            results[v["candidate"]] = results.get(v["candidate"], 0) + 1
        return results