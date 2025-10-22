# Assignment-3
A security-focused online voting system prototype built in Python.
Implements core flows (register → login → vote → results) and layers on security controls used in industry.

Features (implemented):

- Password storage: PBKDF2-HMAC (SHA-256) with per-user random salt.

- Authentication: JWT (HS256) with 5-minute expiry.

- MFA (Multi Factor Authentication): TOTP (time-based one-time codes) via pyotp (per-user secret).

- RBAC hooks: user roles (voter, admin) + admin-only results method.

- Audit logging (To keep track of whatever has done): append-only audit.log (UTC ISO timestamp + key=value).

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

Typical flow:

register alice → prints salt+hash

enable_mfa alice → prints current 6-digit TOTP (for demo)

login alice → enter password + the printed TOTP

register bob → (optional)

login bob` → (no MFA unless enabled)

vote as alice and bob

results → open tally

setrole bob → admin

results_admin (as bob) → RBAC-gated tally


Security notes (prototype):

Passwords are never stored in plaintext (PBKDF2-HMAC + per-user salt).

JWTs expire after 5 minutes; refresh is out-of-scope for the prototype.

MFA secrets are per-user; TOTP codes change every ~30s.

Rate limit is in-memory and per-process (sufficient for a single-process demo).

CLI prints demo-friendly details (salt/hash, masked JWT secret, masked JWT).

