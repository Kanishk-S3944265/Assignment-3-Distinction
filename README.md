# Assignment-3
A security-focused online voting system prototype built in Python.
Implements core flows (register → login → vote → results) and layers on security controls used in industry.

Features (implemented):

- Password storage: PBKDF2-HMAC (SHA-256) with per-user random salt.

- Authentication: JWT (HS256) with 5-minute expiry.

- MFA: TOTP (time-based one-time codes) via pyotp (per-user secret).

- RBAC hooks: user roles (voter, admin) + admin-only results method.

- Audit logging: append-only audit.log (UTC ISO timestamp + key=value).

- Rate limiting (login): blocks after 5 failed attempts within 10 minutes (rolling window).

- Interactive CLI: register, enable MFA, login, vote, show results (open/admin).

Quick start
1) Install dependencies
python -m pip install --upgrade pip
pip install -r requirements.txt

2) Run the interactive CLI
python -m src.cli

Type help to see commands:

register, enable_mfa, login, vote, results, results_admin, setrole, whoami, logout, exit

