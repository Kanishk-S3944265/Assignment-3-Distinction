class Database:
    """
    Simple in-memory database for storing voters and votes.
   
    """
    def __init__(self):
        self.voters = {}   # {username: {"password": "1234"}}
        self.votes = []    # [{"user": "alice", "candidate": "X"}]

    def add_voter(self, username, password):
        if username in self.voters:
            raise ValueError("Voter already registered.")
        self.voters[username] = {"password": password}

    def get_voter(self, username):
        return self.voters.get(username)

    def add_vote(self, username, candidate):
        self.votes.append({"user": username, "candidate": candidate})

    def get_results(self):
        results = {}
        for v in self.votes:
            results[v["candidate"]] = results.get(v["candidate"], 0) + 1
        return results