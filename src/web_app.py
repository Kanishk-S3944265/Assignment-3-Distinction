# --- Electronic Voting Platform (Enhanced Web UI) ---
from flask import (
    Flask, request, redirect, make_response, render_template_string,
    url_for, flash
)
from markupsafe import escape
import os
from functools import wraps

# CSRF
from flask_wtf.csrf import CSRFProtect, generate_csrf, CSRFError

from src.database import Database
from src.voting_system import VotingSystem

# -------------------- App setup --------------------
app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev-flask-secret")

# Dev-safe cookie/CSRF settings (tighten in prod)
app.config.update(
    SESSION_COOKIE_SECURE=False,      # http in dev; set True behind TLS in prod
    SESSION_COOKIE_SAMESITE="Lax",
    WTF_CSRF_TIME_LIMIT=None
)

# Enable CSRF globally
CSRFProtect(app)

db = Database()
vs = VotingSystem(db)

# -------------------- Base HTML --------------------
BASE = """<!doctype html>
<html lang='en'>
<head>
<meta charset='utf-8'>
<title>Electronic Voting Platform</title>
<meta name="viewport" content="width=device-width, initial-scale=1" />
<style>
  :root{ --bg1:#2563eb; --bg2:#0ea5e9; --ink:#0f172a; --white:#ffffff; --muted:#64748b; --accent:#0ea5e9; --accent-dark:#0b83bb; }
  *{box-sizing:border-box}
  body { margin:0; font-family: system-ui,-apple-system,Segoe UI,Roboto,sans-serif; background: linear-gradient(120deg,var(--bg1),var(--bg2)); color: var(--ink); }
  .wrap { max-width: 1100px; margin: 40px auto; padding: 0 16px; }

  /* Top bar */
  .top { display:flex; justify-content:space-between; align-items:center; margin-bottom:12px; color:#fff; }
  .status { font-weight:600; opacity:.95; }
  .logout-btn {
    margin-left:10px; padding:6px 10px; border:0; border-radius:8px;
    background:rgba(255,255,255,.22); color:#fff; cursor:pointer; text-decoration:none;
  }
  .logout-btn:hover { background:rgba(255,255,255,.34); }

  /* Nav */
  nav { display:flex; gap:8px; flex-wrap:wrap; align-items:center; margin-bottom:16px; }
  nav a { display:inline-block; padding:8px 12px; color:#fff; background:rgba(255,255,255,.20); border-radius:10px; text-decoration:none; font-weight:600; backdrop-filter:saturate(130%) blur(2px); }
  nav a.active { background:rgba(255,255,255,.35); }
  nav a:hover { background:rgba(255,255,255,.45); }

  .card { background:#fff; border-radius:18px; padding:24px; box-shadow:0 10px 25px rgba(0,0,0,.15); }

  /* hero */
  .hero { background: linear-gradient(90deg,#eef6ff,#f7fbff); border-radius:18px; box-shadow:0 10px 25px rgba(0,0,0,.12); overflow:hidden; }
  .hero-grid{ display:grid; grid-template-columns:1.1fr 0.9fr; gap:28px; padding:40px 32px; }
  @media (max-width: 840px){ .hero-grid{ grid-template-columns:1fr; padding:28px 20px; } }
  .hero h2{ margin:0 0 10px 0; font-size:2.2rem; color:#0b2a55; }
  .hero p{ margin:0 0 22px 0; color:var(--muted); font-size:1.1rem; line-height:1.5; }
  .cta { display:inline-flex; align-items:center; gap:10px; background:var(--accent); color:#fff; border:0; border-radius:10px; padding:12px 18px; font-weight:700; text-decoration:none; cursor:pointer; transition:transform .06s ease, background .2s ease; box-shadow:0 6px 18px rgba(14,165,233,.35); }
  .cta:hover{ background:var(--accent-dark); transform: translateY(-1px); }
  .hero-art{ background: radial-gradient(1200px 400px at 60% -200px, rgba(37,99,235,.2), transparent 55%), radial-gradient(600px 220px at 100% 100%, rgba(14,165,233,.18), transparent 60%); border-radius:14px; min-height:260px; display:flex; align-items:center; justify-content:center; }
  .hero-card{ background:#fff; border:1px solid #e2e8f0; border-radius:12px; padding:16px 18px; width:min(420px,92%); box-shadow:0 12px 30px rgba(0,0,0,.10); }
  .hero-card h3{ margin:0 0 8px 0; font-size:1.1rem; color:#0b2a55; }
  .hero-card ul{ margin:0; padding-left:18px; color:#334155; }

  .msg-ok { background:#dcfce7; color:#166534; padding:10px; border-radius:8px; }
  .msg-bad { background:#fee2e2; color:#7f1d1d; padding:10px; border-radius:8px; }
  input,button { padding:8px 10px; border-radius:8px; border:1px solid #cbd5e1; margin-top:4px; width:100%; }
  button { background:#0ea5e9; color:#fff; font-weight:600; border:0; cursor:pointer; }
  pre { background:#0b1220; color:#e2e8f0; padding:10px; border-radius:8px; overflow:auto; }

  /* simple toast */
  .toast{ position:fixed; top:16px; right:16px; background:#0ea5e9; color:#fff; padding:10px 14px; border-radius:10px; box-shadow:0 8px 20px rgba(0,0,0,.2); opacity:0; transform:translateY(-8px); transition:.25s; z-index:9999; font-weight:700; }
  .toast.show{ opacity:1; transform:translateY(0); }
</style>
</head>
<body>
<div class='wrap'>

  <div class="top">
    <div style="font-weight:800;color:#fff;">SecureVote</div>
    <div class="status">
      {% if current_user %}
        {{ current_user }} signed in
        <a class="logout-btn" href="{{ url_for('logout') }}">Logout</a>
      {% else %}
        Not signed in
      {% endif %}
    </div>
  </div>

  <nav>
    <a href='{{ url_for("home") }}' class='{% if active=="home" %}active{% endif %}'>Home</a>
    <a href='{{ url_for("register") }}' class='{% if active=="register" %}active{% endif %}'>Register</a>
    <a href='{{ url_for("login") }}' class='{% if active=="login" %}active{% endif %}'>Login</a>
    <a href='{{ url_for("vote") }}' class='{% if active=="vote" %}active{% endif %}'>Vote</a>
    <a href='{{ url_for("results") }}' class='{% if active=="results" %}active{% endif %}'>Results</a>
    <a href='{{ url_for("admin_results") }}' class='{% if active=="admin" %}active{% endif %}'>Admin</a>
    <a href='{{ url_for("security") }}' class='{% if active=="security" %}active{% endif %}'>Security</a>
    <a href='{{ url_for("audit") }}' class='{% if active=="audit" %}active{% endif %}'>Audit</a>
  </nav>

  {% with msgs = get_flashed_messages(with_categories=true) %}
    {% for cat,m in msgs %}
      <div class='{{ "msg-ok" if cat=="ok" else "msg-bad" }}'>{{ m|safe }}</div>
    {% endfor %}
  {% endwith %}

  <div class='card'>
    <h2 style="margin-top:0;">{{ title }}</h2>
    {{ body|safe }}
  </div>
</div>

<script>
window.addEventListener('DOMContentLoaded', ()=>{
  const msgs = Array.from(document.querySelectorAll('.msg-ok')).map(e=>e.textContent.trim());
  if (msgs.some(m => m.toLowerCase().includes('mfa enabled'))) {
    const t = document.createElement('div');
    t.className = 'toast';
    t.textContent = 'MFA enabled';
    document.body.appendChild(t);
    requestAnimationFrame(()=> t.classList.add('show'));
    setTimeout(()=> t.classList.remove('show'), 2500);
    setTimeout(()=> t.remove(), 3000);
  }
});
</script>

</body></html>"""

# -------------------- Helpers --------------------
def _render(title, body, active=""):
    # figure out current user for top-right status
    t = request.cookies.get("jwt")
    current_user = vs.verify_token(t) if t else None
    # pre-render the body so Jinja in body (e.g., tokens) works
    rendered_body = render_template_string(body)
    return render_template_string(
        BASE, title=title, body=rendered_body, active=active, current_user=current_user
    )

def _get_user_and_token():
    t = request.cookies.get("jwt")
    return (vs.verify_token(t) if t else None, t)

def require_role(role):
    def deco(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            user, _ = _get_user_and_token()
            if not user or not db.has_role(user, role):
                flash("Forbidden: insufficient privileges.", "bad")
                return redirect(url_for("login"))
            return fn(*args, **kwargs)
        return wrapper
    return deco

@app.after_request
def no_store(resp):
    resp.headers["Cache-Control"] = "no-store"
    return resp

# -------------------- Routes --------------------
@app.route("/")
def home():
    body = f"""
    <section class="hero">
      <div class="hero-grid">
        <div>
          <h2>Enrol to vote</h2>
          <p>To participate in secure online elections and mock referendums, start your enrolment now.</p>
          <a class="cta" href="{url_for('register')}">Start enrolment →</a>
        </div>
        <div class="hero-art">
          <div class="hero-card">
            <h3>What you'll need</h3>
            <ul>
              <li>First &amp; last name, DOB, address</li>
              <li>Username &amp; strong password</li>
              <li>(Optional) Enable MFA after enrolment</li>
            </ul>
          </div>
        </div>
      </div>
    </section>
    """
    return _render("Welcome to Secure Electronic Voting", body, "home")

@app.route("/register", methods=["GET","POST"])
def register():
    if request.method=="GET":
        token = generate_csrf()
        body = f"""<form method='post'>
        <input type="hidden" name="csrf_token" value="{token}">
        <p><input name='first_name' placeholder='First name' required></p>
        <p><input name='last_name' placeholder='Last name' required></p>
        <p><input name='dob' placeholder='DOB (YYYY-MM-DD)' required></p>
        <p><input name='address' placeholder='Address' required></p>
        <p><input name='username' placeholder='Username' required></p>
        <p><input type='password' name='password' placeholder='Password' required></p>
        <p><button>Register</button></p></form>"""
        return _render("Register", body, "register")
    try:
        vs.register_voter(
            request.form["username"], request.form["password"],
            first_name=request.form["first_name"], last_name=request.form["last_name"],
            dob=request.form["dob"], address=request.form["address"]
        )
        flash("Registration successful.", "ok")
        return redirect("/login")
    except Exception as e:
        flash(f"Error: {escape(str(e))}", "bad")
        return redirect("/register")

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method=="GET":
        token = generate_csrf()
        body = f"""<form method='post'>
        <input type="hidden" name="csrf_token" value="{token}">
        <p><input name='username' placeholder='Username' required></p>
        <p><input type='password' name='password' placeholder='Password' required></p>
        <p><input name='mfa_code' placeholder='MFA code (if enabled)'></p>
        <p><button>Login</button></p></form>"""
        return _render("Login", body, "login")
    token_val = vs.login(
        request.form.get("username","").strip(),
        request.form.get("password",""),
        mfa_code=(request.form.get("mfa_code") or None)
    )
    if not token_val:
        flash("Login failed (bad credentials or MFA missing).","bad")
        return redirect("/login")
    resp = make_response(redirect("/vote"))
    resp.set_cookie("jwt", token_val, httponly=True, samesite="Lax")
    flash("Signed in successfully.","ok")
    return resp

@app.route("/logout")
def logout():
    resp = make_response(redirect(url_for("home")))
    # clear the JWT cookie (session ends)
    resp.set_cookie("jwt", "", expires=0, httponly=True, samesite="Lax")
    flash("You have been logged out.","ok")
    return resp

@app.route("/vote", methods=["GET","POST"])
def vote():
    user, token = _get_user_and_token()
    if not user:
        flash("Please login first.","bad")
        return redirect("/login")
    if request.method=="GET":
        csrf = generate_csrf()
        body = f"<p>Signed in as <b>{escape(user)}</b></p><form method='post'><input type='hidden' name='csrf_token' value='{csrf}'><p><input name='candidate' placeholder='Candidate' required></p><p><button>Submit Vote</button></p></form>"
        return _render("Vote", body, "vote")
    ok = vs.submit_vote(token, request.form.get("candidate",""))
    flash("Vote recorded." if ok else "Vote failed (expired/invalid token).","ok" if ok else "bad")
    return redirect("/results")

@app.route("/results")
def results():
    res = db.get_results()
    if not res: body="<p>No votes yet.</p>"
    else: body="<ul>"+"".join(f"<li>{escape(k)}: {v}</li>" for k,v in res.items())+"</ul>"
    return _render("Public Results", body, "results")

@app.route("/admin")
def admin_results():
    user, _ = _get_user_and_token()
    if not user or not db.has_role(user,"admin"):
        flash("Forbidden: admin only.","bad")
        return redirect("/login")
    res = db.get_results()
    body = "<h3>Admin-only Results</h3><ul>"+"".join(f"<li>{escape(k)}: {v}</li>" for k,v in res.items())+"</ul>"
    return _render("Admin Results", body, "admin")

@app.route("/security", methods=["GET","POST"])
def security():
    user, _ = _get_user_and_token()
    if not user:
        flash("Login required.","bad")
        return redirect("/login")
    if request.method=="POST":
        act = request.form.get("action")
        if act=="enable_mfa":
            try:
                secret = db.enable_mfa(user)
                import pyotp; code = pyotp.TOTP(secret).now()
                flash(f"MFA enabled. Current test code: {escape(code)}","ok")
                # Also print to terminal for evidence
                print(f"[SECURITY] MFA enabled for user='{user}'. Current test TOTP code: {code}")
            except Exception as e:
                flash(f"Error: {escape(str(e))}","bad")
        elif act=="set_role":
            role=request.form.get("role","").lower().strip()
            try:
                db.set_role(user,role)
                flash(f"Role updated to {escape(role)}.","ok")
            except Exception as e:
                flash(f"Error: {escape(str(e))}","bad")
        return redirect("/security")
    csrf = generate_csrf()
    body=f"<p>Signed in as {escape(user)}</p>" \
         f"<form method='post'><input type='hidden' name='csrf_token' value='{csrf}'><input type='hidden' name='action' value='enable_mfa'><button>Enable MFA</button></form>" \
         f"<form method='post' style='margin-top:10px;'><input type='hidden' name='csrf_token' value='{csrf}'><input type='hidden' name='action' value='set_role'><p><input name='role' placeholder='admin | voter'></p><p><button>Update Role</button></p></form>"
    return _render("Security", body, "security")

@app.route("/audit")
def audit():
    path="audit.log"
    if not os.path.exists(path): return _render("Audit Log","<p>No audit.log yet.</p>","audit")
    with open(path,"r",encoding="utf-8") as f: lines=f.readlines()[-200:]
    body=f"<p>Last 200 audit lines:</p><pre>{escape(''.join(lines))}</pre>"
    return _render("Audit Log", body, "audit")

# ---- Errors ----
@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    flash(f"CSRF failed: {e.description}", "bad")
    return redirect(request.referrer or url_for("home"))

# -------------------- Run --------------------
if __name__=="__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
