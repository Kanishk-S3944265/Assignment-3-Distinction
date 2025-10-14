import jwt
import datetime

SECRET_KEY = "supersecretkey"  

class VotingSystem:
    def __init__(self, db):
        self.db = db

    def register_voter(self, username, password):
        self.db.add_voter(username, password)
        print(f"[+] Voter '{username}' registered successfully.")

    def login(self, username, password):
        voter = self.db.get_voter(username)
        if voter and self.db.verify_password(username, password):
            payload = {
                "username": username,
                "exp": datetime.datetime.now() + datetime.timedelta(minutes=5)
            }
            token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")
            print(f"[+] Login successful for '{username}'. JWT issued.")
            return token
        print("[-] Invalid username or password.")
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
            return True
        print("[-] Vote failed. Invalid or expired session.")
        return False

    def show_results(self):
        results = self.db.get_results()
        print("\nVoting Results:")
        for candidate, count in results.items():
            print(f"  - {candidate}: {count} vote(s)")
