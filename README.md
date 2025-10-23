# Assignment-3
Secure Electronic Voting (Web Prototype)
A security-focused online voting system prototype built with Flask. It implements the core flows
(register to  login to  vote to results) and layers on multiple security controls.

What’s included (implemented)
App/UI
Responsive web UI (blue theme, AEC-style hero).


Top-right auth status: “Not signed in” → “<user> signed in” + Logout button.


Pages: Home, Register, Login, Vote, Results (public), Admin (RBAC), Security (MFA/role), Audit.


Authentication & Sessions
JWT auth (HS256) issued on login and stored in a HttpOnly cookie with SameSite=Lax.


Logout route that clears the JWT cookie (ends the session immediately).


Auth gating: /vote and /security require a valid JWT; /admin requires admin role.


MFA
TOTP-based MFA via pyotp. Users can enable MFA on /security.


On enable, a demo toast (“MFA enabled”) appears and the current TOTP code is printed to the terminal for evidence.


CSRF
Global CSRF protection (Flask-WTF): hidden csrf_token on all POST forms.


Friendly CSRF error handler that flashes an error and redirects.


RBAC
Role-Based Access Control: voters vs. admins.
 /admin shows admin-only results; roles can be set on /security.


Passwords
PBKDF2-HMAC (SHA-256) with per-user random salt for password storage (handled in backend).


Debug shows “Created salt / Hashed password” during registration (for demo transparency).


Audit & Evidence
Audit log viewer /audit renders the last ~200 lines of audit.log.


JWT secrets/tokens are masked in debug logs.


All responses send Cache-Control: no-store to avoid caching sensitive pages.


Brute-force protection
Login lockout: 3 failed attempts in 5 minutes (per username+IP) → 10-minute lock.
Resets on successful login.






Quick start
1) Install dependencies
python -m pip install --upgrade pip
pip install -r requirements.txt

2) Run the web app
python -m src.web_app

By default it starts on http://127.0.0.1:5000 (and your container/LAN IP).
On restart you may see “Invalid token” in the terminal, which just means your browser still had an old JWT cookie. Use Logout or clear the cookie.
3) Typical web flow
Home → “Start enrolment” → Register


Login (username + password; add MFA code if you enabled it)


Vote (submit a candidate)


Results (public tally)


Security (enable MFA, update your role)


Admin (requires admin role)


Audit (view recent audit lines)


Logout


Routes overview
/ — Home (hero + CTA to Register)


/register — Create account (first/last, DOB, address, username, password) [CSRF]


/login — Authenticate (username, password, optional TOTP) [CSRF + lockout]


/vote — Cast vote (JWT required) [CSRF]


/results — Public tally


/admin — Admin-only results (JWT + admin role required)


/security — Enable MFA / change role [CSRF]


/audit — Show last 200 lines of audit.log


/logout — Clear JWT cookie and redirect home


Configuration
Flask secret: FLASK_SECRET_KEY (used for sessions/CSRF).


JWT secret: provided/loaded within the backend (VotingSystem); check that module for the exact env var name used in your repo (commonly JWT_SECRET).


Dev cookie flags: in src/web_app.py the app sets SESSION_COOKIE_SECURE=False and SameSite=Lax for local testing. Use stricter settings in production.


Rate-limiting / lockout details
3 failed logins within a 5-minute sliding window (per username+IP) trigger a 10-minute lock.


The counter resets after a successful login.


This is in-memory / per-process (sufficient for the prototype).


