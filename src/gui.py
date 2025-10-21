import tkinter as tk
from tkinter import ttk, messagebox
import os, sys
from src.database import Database
from src.voting_system import VotingSystem

"""
Desktop GUI for the Electronic Voting Platform.
Adds profile fields on registration: first name, last name, DOB, address.
Security features remain: PBKDF2 hashing, JWT, MFA, RBAC, audit, rate-limiting.
"""

class VotingApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Electronic Voting Platform (Desktop)")
        self.geometry("880x660")
        self.minsize(780, 600)

        self.db = Database()
        self.vs = VotingSystem(self.db)

        self.current_user = None
        self.jwt_token = None

        self._build_ui()

    def _build_ui(self):
        top = ttk.Frame(self, padding=(12, 8))
        top.pack(fill="x")
        ttk.Label(top, text="🗳️ Electronic Voting Platform", font=("Segoe UI", 14, "bold")).pack(side="left")
        self.user_label = ttk.Label(top, text="Not signed in", foreground="#64748b")
        self.user_label.pack(side="right")

        self.tabs = ttk.Notebook(self)
        self.tabs.pack(fill="both", expand=True, padx=10, pady=10)

        self._register_tab()
        self._login_tab()
        self._vote_tab()
        self._results_tab()
        self._admin_results_tab()
        self._security_tab()

        footer = ttk.Frame(self, padding=(12, 8))
        footer.pack(fill="x")
        ttk.Label(footer, text="Disclaimer: Coursework prototype only. Do not interact with AEC operational systems.",
                  foreground="#0e7490").pack(side="left")

    # ----------------- Tabs -----------------
    def _register_tab(self):
        frm = ttk.Frame(self.tabs, padding=16)
        self.tabs.add(frm, text="Register")

        ttk.Label(frm, text="Create account", font=("Segoe UI", 12, "bold")).grid(row=0, column=0, sticky="w", pady=(0,6))

        # Profile grid
        ttk.Label(frm, text="First name").grid(row=1, column=0, sticky="w")
        self.reg_first = ttk.Entry(frm, width=32)
        self.reg_first.grid(row=2, column=0, sticky="w")

        ttk.Label(frm, text="Last name").grid(row=1, column=1, sticky="w")
        self.reg_last = ttk.Entry(frm, width=32)
        self.reg_last.grid(row=2, column=1, sticky="w")

        ttk.Label(frm, text="Date of birth (YYYY-MM-DD)").grid(row=3, column=0, sticky="w", pady=(8,0))
        self.reg_dob = ttk.Entry(frm, width=32)
        self.reg_dob.grid(row=4, column=0, sticky="w")

        ttk.Label(frm, text="Address").grid(row=3, column=1, sticky="w", pady=(8,0))
        self.reg_address = ttk.Entry(frm, width=40)
        self.reg_address.grid(row=4, column=1, sticky="we")

        ttk.Label(frm, text="Username").grid(row=5, column=0, sticky="w", pady=(10,0))
        self.reg_username = ttk.Entry(frm, width=32)
        self.reg_username.grid(row=6, column=0, sticky="w")

        ttk.Label(frm, text="Password").grid(row=5, column=1, sticky="w", pady=(10,0))
        self.reg_password = ttk.Entry(frm, show="*", width=32)
        self.reg_password.grid(row=6, column=1, sticky="w")

        ttk.Button(frm, text="Register", command=self.register_user).grid(row=7, column=0, pady=12, sticky="w")

        info = ("Passwords are stored with salted PBKDF2-HMAC (SHA-256). "
                "Enable TOTP MFA after your first login. Debug salt/hash will print in terminal.")
        ttk.Label(frm, text=info, wraplength=700, foreground="#64748b").grid(row=8, column=0, columnspan=2, sticky="w", pady=(6,0))

        frm.grid_columnconfigure(1, weight=1)

    def _login_tab(self):
        frm = ttk.Frame(self.tabs, padding=16)
        self.tabs.add(frm, text="Login")

        ttk.Label(frm, text="Sign in", font=("Segoe UI", 12, "bold")).grid(row=0, column=0, sticky="w", pady=(0,6))

        ttk.Label(frm, text="Username").grid(row=1, column=0, sticky="w")
        self.login_username = ttk.Entry(frm, width=32)
        self.login_username.grid(row=2, column=0, sticky="w")

        ttk.Label(frm, text="Password").grid(row=3, column=0, sticky="w", pady=(8,0))
        self.login_password = ttk.Entry(frm, show="*", width=32)
        self.login_password.grid(row=4, column=0, sticky="w")

        ttk.Label(frm, text="MFA code (if enabled)").grid(row=5, column=0, sticky="w", pady=(8,0))
        self.login_mfa = ttk.Entry(frm, width=12)
        self.login_mfa.grid(row=6, column=0, sticky="w")

        ttk.Button(frm, text="Login", command=self.login_user).grid(row=7, column=0, pady=12, sticky="w")

        tips = ("If your account has MFA enabled, enter your 6-digit TOTP. "
                "On success, a short-lived JWT session is stored in memory.")
        ttk.Label(frm, text=tips, wraplength=600, foreground="#64748b").grid(row=8, column=0, sticky="w", pady=(6,0))

    def _vote_tab(self):
        frm = ttk.Frame(self.tabs, padding=16)
        self.tabs.add(frm, text="Vote")

        ttk.Label(frm, text="Cast your vote", font=("Segoe UI", 12, "bold")).grid(row=0, column=0, sticky="w", pady=(0,6))

        ttk.Label(frm, text="Candidate").grid(row=1, column=0, sticky="w")
        self.vote_candidate = ttk.Entry(frm, width=40)
        self.vote_candidate.grid(row=2, column=0, sticky="w")

        ttk.Button(frm, text="Submit Vote", command=self.submit_vote).grid(row=3, column=0, pady=10, sticky="w")

        ttk.Separator(frm, orient="horizontal").grid(row=4, column=0, sticky="ew", pady=10)

        ttk.Button(frm, text="Refresh Results (public)", command=self.refresh_results_list).grid(row=5, column=0, sticky="w")
        self.vote_results = tk.Text(frm, width=60, height=10, state="disabled")
        self.vote_results.grid(row=6, column=0, sticky="w", pady=(6,0))

    def _results_tab(self):
        frm = ttk.Frame(self.tabs, padding=16)
        self.tabs.add(frm, text="Results")

        ttk.Label(frm, text="Public Results", font=("Segoe UI", 12, "bold")).pack(anchor="w")
        self.pub_results = tk.Text(frm, width=60, height=16, state="disabled")
        self.pub_results.pack(anchor="w", pady=(6,0))
        ttk.Button(frm, text="Refresh", command=self.refresh_public_results).pack(anchor="w", pady=(10,0))

    def _admin_results_tab(self):
        frm = ttk.Frame(self.tabs, padding=16)
        self.tabs.add(frm, text="Admin Results")

        ttk.Label(frm, text="Admin-only Results", font=("Segoe UI", 12, "bold")).grid(row=0, column=0, sticky="w")
        ttk.Label(frm, text="Requires role=admin. Use Security tab to set role.", foreground="#64748b").grid(row=1, column=0, sticky="w", pady=(6,8))
        ttk.Button(frm, text="Show Admin Results", command=self.show_admin_results).grid(row=2, column=0, sticky="w")
        self.admin_results_box = tk.Text(frm, width=60, height=16, state="disabled")
        self.admin_results_box.grid(row=3, column=0, sticky="w", pady=(6,0))

    def _security_tab(self):
        frm = ttk.Frame(self.tabs, padding=16)
        self.tabs.add(frm, text="Security")

        ttk.Label(frm, text="Security Controls", font=("Segoe UI", 12, "bold")).grid(row=0, column=0, sticky="w")

        ttk.Label(frm, text="Enable MFA (TOTP) for current user").grid(row=1, column=0, sticky="w", pady=(8,0))
        ttk.Button(frm, text="Enable MFA", command=self.enable_mfa).grid(row=2, column=0, sticky="w")

        ttk.Label(frm, text="Set my role (admin | voter)").grid(row=3, column=0, sticky="w", pady=(14,0))
        role_row = ttk.Frame(frm); role_row.grid(row=4, column=0, sticky="w")
        self.role_entry = ttk.Entry(role_row, width=16); self.role_entry.grid(row=0, column=0)
        ttk.Button(role_row, text="Update Role", command=self.set_role).grid(row=0, column=1, padx=(8,0))

        ttk.Label(frm, text="View latest audit lines").grid(row=5, column=0, sticky="w", pady=(14,4))
        ttk.Button(frm, text="Open audit.log", command=self.open_audit).grid(row=6, column=0, sticky="w")

    # ----------------- Actions -----------------
    def register_user(self):
        data = {
            "first_name": self.reg_first.get().strip(),
            "last_name":  self.reg_last.get().strip(),
            "dob":        self.reg_dob.get().strip(),
            "address":    self.reg_address.get().strip(),
            "username":   self.reg_username.get().strip(),
            "password":   self.reg_password.get()
        }
        if not all([data["first_name"], data["last_name"], data["dob"], data["address"], data["username"], data["password"]]):
            messagebox.showwarning("Register", "Please fill all fields.")
            return
        try:
            self.vs.register_voter(
                data["username"], data["password"],
                first_name=data["first_name"],
                last_name=data["last_name"],
                dob=data["dob"],
                address=data["address"]
            )
            messagebox.showinfo("Register", f"Registered '{data['username']}'. You can login now.")
            for w in (self.reg_first, self.reg_last, self.reg_dob, self.reg_address, self.reg_username, self.reg_password):
                w.delete(0, "end")
        except ValueError as e:
            messagebox.showerror("Register", str(e))

    def login_user(self):
        u = self.login_username.get().strip()
        p = self.login_password.get()
        code = (self.login_mfa.get().strip() or None)
        token = self.vs.login(u, p, mfa_code=code)
        if token:
            self.current_user = u
            self.jwt_token = token
            self.user_label.config(text=f"Signed in as: {u}")
            messagebox.showinfo("Login", f"Welcome, {u}")
            self.login_password.delete(0, "end"); self.login_mfa.delete(0, "end")
            self.tabs.select(2)  # switch to Vote tab
        else:
            messagebox.showerror("Login", "Invalid credentials or MFA required/incorrect.")

    def submit_vote(self):
        if not self.jwt_token:
            messagebox.showwarning("Vote", "Please login first.")
            return
        cand = self.vote_candidate.get().strip()
        if not cand:
            messagebox.showwarning("Vote", "Enter a candidate.")
            return
        ok = self.vs.submit_vote(self.jwt_token, cand)
        if ok:
            messagebox.showinfo("Vote", f"Vote recorded for '{cand}'.")
            self.vote_candidate.delete(0, "end")
            self.refresh_results_list()
        else:
            messagebox.showerror("Vote", "Vote failed. Token invalid/expired. Please login again.")
            self.current_user = None; self.jwt_token = None
            self.user_label.config(text="Not signed in")

    def refresh_results_list(self):
        self._fill_text(self.vote_results, self.db.get_results())

    def refresh_public_results(self):
        self._fill_text(self.pub_results, self.db.get_results())

    def show_admin_results(self):
        if not self.jwt_token:
            messagebox.showwarning("Admin Results", "Please login first.")
            return
        user = self.vs.verify_token(self.jwt_token)
        if not user or not self.db.has_role(user, "admin"):
            messagebox.showerror("Admin Results", "Forbidden: admin only.")
            return
        self._fill_text(self.admin_results_box, self.db.get_results())

    def enable_mfa(self):
        if not self.current_user:
            messagebox.showwarning("Enable MFA", "Login first.")
            return
        try:
            secret = self.db.enable_mfa(self.current_user)
            try:
                import pyotp
                code_now = pyotp.TOTP(secret).now()
                messagebox.showinfo("MFA enabled", f"MFA enabled for '{self.current_user}'.\nCurrent TOTP: {code_now}")
            except Exception:
                messagebox.showinfo("MFA enabled", f"MFA enabled for '{self.current_user}'.")
        except ValueError as e:
            messagebox.showerror("Enable MFA", str(e))

    def set_role(self):
        if not self.current_user:
            messagebox.showwarning("Set Role", "Login first.")
            return
        role = (self.role_entry.get() or "").strip().lower()
        if role not in ("admin", "voter"):
            messagebox.showwarning("Set Role", "Role must be 'admin' or 'voter'.")
            return
        try:
            self.db.set_role(self.current_user, role)
            messagebox.showinfo("Set Role", f"Role for '{self.current_user}' set to '{role}'.")
        except ValueError as e:
            messagebox.showerror("Set Role", str(e))

    def open_audit(self):
        path = os.path.abspath("audit.log")
        if not os.path.exists(path):
            messagebox.showinfo("Audit", "audit.log not found yet.")
            return
        try:
            if os.name == "nt":
                os.startfile(path)  # type: ignore
            elif sys.platform == "darwin":
                os.system(f"open '{path}'")
            else:
                os.system(f"xdg-open '{path}'")
        except Exception as e:
            messagebox.showerror("Audit", f"Failed to open audit.log: {e}")

    @staticmethod
    def _fill_text(widget: tk.Text, results: dict):
        widget.config(state="normal")
        widget.delete("1.0", "end")
        if results:
            for name, count in results.items():
                widget.insert("end", f"{name}: {count}\n")
        else:
            widget.insert("end", "No votes yet.\n")
        widget.config(state="disabled")


if __name__ == "__main__":
    app = VotingApp()
    app.mainloop()
