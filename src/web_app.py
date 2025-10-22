# --- Electronic Voting Platform (Enhanced Web UI) ---
from flask import (
    Flask, request, redirect, make_response, render_template_string,
    url_for, flash, send_file
)
from markupsafe import escape
import os, html
from src.database import Database
from src.voting_system import VotingSystem

# -------------------- App setup --------------------
app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev-flask-secret")

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
  :root{
    --bg1:#2563eb;   /* blue-600 */
    --bg2:#0ea5e9;   /* cyan-500 */
    --ink:#0f172a;   /* slate-900 */
    --white:#ffffff;
    --muted:#64748b; /* slate-500 */
    --accent:#0ea5e9;/* cyan-500 */
    --accent-dark:#0b83bb;
  }
  *{box-sizing:border-box}
  body {
    margin: 0;
    font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif;
    background: linear-gradient(120deg,var(--bg1),var(--bg2));
    color: var(--ink);
  }
  .wrap { max-width: 1100px; margin: 40px auto; padding: 0 16px; }

  /* Top nav */
  nav {
    display:flex; gap:8px; flex-wrap:wrap; align-items:center; margin-bottom:16px;
  }
  nav a {
    display:inline-block; padding:8px 12px;
    color:#fff; background:rgba(255,255,255,.20);
    border-radius:10px; text-decoration:none; font-weight:600;
    backdrop-filter:saturate(130%) blur(2px);
  }
  nav a.active { background:rgba(255,255,255,.35); }
  nav a:hover { background:rgba(255,255,255,.45); }

  .card {
    background: #fff; border-radius: 18px; padding: 24px;
    box-shadow: 0 10px 25px rgba(0,0,0,.15);
  }

  /* hero section (AEC-style) */
  .hero {
    background: linear-gradient(90deg,#eef6ff,#f7fbff);
    border-radius: 18px;
    box-shadow: 0 10px 25px rgba(0,0,0,.12);
    overflow:hidden;
  }
  .hero-grid{
    display:grid;
    grid-template-columns: 1.1fr 0.9fr;
    gap: 28px;
    padding: 40px 32px;
  }
  @media (max-width: 840px){
    .hero-grid{ grid-template-columns:1fr; padding:28px 20px; }
  }
  .hero h2{
    margin:0 0 10px 0; font-size: 2.2rem; color:#0b2a55;
  }
  .hero p{
    margin:0 0 22px 0; color: var(--muted); font-size:1.1rem; line-height:1.5;
  }
  .cta {
    display:inline-flex; align-items:center; gap:10px;
    background: var(--accent); color:var(--white);
    border:0; border-radius:10px; padding:12px 18px;
    font-weight:700; cursor:pointer; text-decoration:none;
    transition: transform .06s ease, background .2s ease;
    box-shadow: 0 6px 18px rgba(14,165,233,.35);
  }
  .cta:hover{ background: var(--accent-dark); transform: translateY(-1px); }
  .cta:active{ transform: translateY(0); }
  .hero-art{
    background: radial-gradient(1200px 400px at 60% -200px, rgba(37,99,235,.2), transparent 55%),
                radial-gradient(600px 220px at 100% 100%, rgba(14,165,233,.18), transparent 60%);
    border-radius: 14px;
    min-height: 260px;
    display:flex; align-items:center; justify-content:center;
  }
  .hero-card{
    background:#fff; border:1px solid #e2e8f0;
    border-radius:12px; padding:16px 18px; width:min(420px, 92%);
    box-shadow: 0 12px 30px rgba(0,0,0,.10);
  }
  .hero-card h3{ margin:0 0 8px 0; font-size:1.1rem; color:#0b2a55; }
  .hero-card ul{ margin:0; padding-left:18px; color:#334155; }
  .hero-card li{ margin:6px 0; }

  .msg-ok { background:#dcfce7; color:#166534; padding:10px; border-radius:8px; }
  .msg-bad { background:#fee2e2; color:#7f1d1d; padding:10px; border-radius:8px; }
  input,button { padding:8px 10px; border-radius:8px; border:1px solid #cbd5e1; margin-top:4px; width:100%; }
  button { background:#0ea5e9; color:#fff; font-weight:600; border:0; cursor:pointer; }
  pre { background:#0b1220; color:#e2e8f0; padding:10px; border-radius:8px; overflow:auto; }
</style>
</head>
<body>
<div class='wrap'>
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
</body></html>"""

# -------------------- Helpers --------------------
def _render(title, body, active=""): 
    return render_template_string(BASE, title=title, body=body, active=active)

def _get_user_and_token():
    t = request.cookies.get("jwt")
    return (vs.verify_token(t) if t else None, t)

# -------------------- Routes --------------------
@app.route("/")
def home():
    # AEC-like hero with a single CTA to /register
    body = f"""
    <section class="hero">
      <div class="hero-grid">
        <div>
          <h2>Enrol to vote</h2>
          <p>To participate in secure online elections and mock referendums, start your enrolment now.
             It only takes a moment and helps us verify you before you cast your ballot.</p>
          <a class="cta" href="{url_for('register')}">Start enrolment →
          </a>
        </div>
        <div class="hero-art">
          <div class="hero-card">
            <h3>What you'll need</h3>
            <ul>
              <li>Basic details (first &amp; last name, DOB, address)</li>
              <li>A username &amp; strong password</li>
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
        body = """<form method='post'>
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
        body = """<form method='post'>
        <p><input name='username' placeholder='Username' required></p>
        <p><input type='password' name='password' placeholder='Password' required></p>
        <p><input name='mfa_code' placeholder='MFA code (if enabled)'></p>
        <p><button>Login</button></p></form>"""
        return _render("Login", body, "login")
    token = vs.login(
        request.form.get("username","").strip(),
        request.form.get("password",""),
        mfa_code=(request.form.get("mfa_code") or None)
    )
    if not token:
        flash("Login failed (rate-limited, bad credentials, or MFA missing).","bad")
        return redirect("/login")
    resp = make_response(redirect("/vote"))
    resp.set_cookie("jwt", token, httponly=True, samesite="Lax")
    flash("Signed in successfully.","ok")
    return resp

@app.route("/vote", methods=["GET","POST"])
def vote():
    user, token = _get_user_and_token()
    if not user:
        flash("Please login first.","bad")
        return redirect("/login")
    if request.method=="GET":
        body = f"<p>Signed in as <b>{escape(user)}</b></p><form method='post'><p><input name='candidate' placeholder='Candidate' required></p><p><button>Submit Vote</button></p></form>"
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
    body=f"<p>Signed in as {escape(user)}</p><form method='post'><input type='hidden' name='action' value='enable_mfa'><button>Enable MFA</button></form><form method='post'><input type='hidden' name='action' value='set_role'><p><input name='role' placeholder='admin | voter'></p><p><button>Update Role</button></p></form>"
    return _render("Security", body, "security")

@app.route("/audit")
def audit():
    path="audit.log"
    if not os.path.exists(path): return _render("Audit Log","<p>No audit.log yet.</p>","audit")
    with open(path,"r",encoding="utf-8") as f: lines=f.readlines()[-200:]
    body=f"<p>Last 200 audit lines:</p><pre>{escape(''.join(lines))}</pre>"
    return _render("Audit Log", body, "audit")

# -------------------- Run --------------------
if __name__=="__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)

