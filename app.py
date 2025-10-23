from datetime import datetime, timedelta
import jwt
import os
from flask import Flask, render_template, request, redirect, url_for, make_response, flash
from flask_wtf import CSRFProtect
from wtforms import Form, StringField, PasswordField, validators

from src.database import Database
from src.voting_system import VotingSystem, SECRET_KEY as VS_SECRET  # import shared signing key

app = Flask(__name__, template_folder="templates", static_folder="static")
app.config["SECRET_KEY"] = os.environ.get("FLASK_SECRET_KEY", "change-this-for-demo")
app.config["WTF_CSRF_TIME_LIMIT"] = None
CSRFProtect(app)

db = Database()
vs = VotingSystem(db)

# Use the SAME signing key as the business layer everywhere in web routes
JWT_SECRET = VS_SECRET

class RegisterForm(Form):
    username = StringField("Username", [validators.InputRequired(), validators.Length(min=3, max=32)])
    password = PasswordField("Password", [validators.InputRequired(), validators.Length(min=6, max=128)])

class LoginForm(Form):
    username = StringField("Username", [validators.InputRequired()])
    password = PasswordField("Password", [validators.InputRequired()])

class MFAForm(Form):
    code = StringField("MFA code (6 digits)", [validators.InputRequired(), validators.Length(min=6, max=6)])

class VoteForm(Form):
    candidate = StringField("Candidate", [validators.InputRequired(), validators.Length(min=1, max=64)])

class RoleForm(Form):
    role = StringField("Role (admin|voter)", [validators.InputRequired(), validators.AnyOf(values=["admin","voter"])])

def current_user():
    """Return username from JWT cookie if valid, else None."""
    token = request.cookies.get("session")
    if not token:
        return None
    return vs.verify_token(token)

def set_session_cookie(resp, token):
    """Set HttpOnly cookie for session JWT."""
    resp.set_cookie("session", token, httponly=True, secure=False, samesite="Lax", max_age=5*60)

@app.get("/")
def home():
    return redirect(url_for("results"))

@app.route("/register", methods=["GET", "POST"])
def register():
    form = RegisterForm(request.form)
    if request.method == "POST" and form.validate():
        try:
            vs.register_voter(form.username.data.strip(), form.password.data)
            flash("Registered successfully. You can login now.", "success")
            return redirect(url_for("login"))
        except ValueError as e:
            flash(str(e), "danger")
    return render_template("register.html", form=form, user=current_user())

@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm(request.form)
    if request.method == "POST" and form.validate():
        username = form.username.data.strip()
        password = form.password.data

        # If MFA is enabled, set a short-lived step token for /mfa
        voter = db.get_voter(username)
        if voter and db.verify_password(username, password) and db.mfa_enabled(username):
            payload = {"username": username, "step": "mfa", "exp": datetime.utcnow() + timedelta(minutes=2)}
            step_token = jwt.encode(payload, JWT_SECRET, algorithm="HS256")
            resp = make_response(redirect(url_for("mfa")))
            set_session_cookie(resp, step_token)
            return resp

        # No MFA → normal login (VotingSystem handles audit + rate limiting)
        token = vs.login(username, password, mfa_code=None)
        if token:
            resp = make_response(redirect(url_for("vote")))
            set_session_cookie(resp, token)
            return resp

        flash("Invalid credentials or MFA required.", "danger")
    return render_template("login.html", form=form, user=current_user())

@app.route("/mfa", methods=["GET", "POST"])
def mfa():
    form = MFAForm(request.form)
    step_token = request.cookies.get("session")
    username = None

    if step_token:
        try:
            data = jwt.decode(step_token, JWT_SECRET, algorithms=["HS256"])
            if data.get("step") == "mfa":
                username = data.get("username")
        except Exception:
            pass

    if not username:
        flash("MFA session not found or expired. Please login again.", "warning")
        return redirect(url_for("login"))

    if request.method == "POST" and form.validate():
        code = form.code.data.strip()
        if db.verify_mfa(username, code):
            payload = {"username": username, "iat": datetime.utcnow(), "exp": datetime.utcnow() + timedelta(minutes=5)}
            token = jwt.encode(payload, JWT_SECRET, algorithm="HS256")
            vs._audit("login_success", user=username)
            resp = make_response(redirect(url_for("vote")))
            set_session_cookie(resp, token)
            return resp
        flash("MFA code invalid or expired.", "danger")

    return render_template("mfa.html", form=form, username=username, user=None)

@app.get("/logout")
def logout():
    resp = make_response(redirect(url_for("login")))
    resp.delete_cookie("session")
    flash("Logged out.", "info")
    return resp

@app.route("/vote", methods=["GET", "POST"])
def vote():
    user = current_user()
    if not user:
        flash("Please login first.", "warning")
        return redirect(url_for("login"))

    vote_form = VoteForm(request.form)
    role_form = RoleForm(request.form)

    if request.method == "POST" and "candidate" in request.form and vote_form.validate():
        token = request.cookies.get("session")
        if vs.submit_vote(token, vote_form.candidate.data.strip()):
            flash("Vote recorded.", "success")
            return redirect(url_for("vote"))
        flash("Vote failed. Please login again.", "danger")
        return redirect(url_for("login"))

    if request.method == "POST" and "role" in request.form and role_form.validate():
        try:
            db.set_role(user, role_form.role.data.strip().lower())
            flash(f"Role updated to {role_form.role.data}.", "info")
            return redirect(url_for("vote"))
        except ValueError as e:
            flash(str(e), "danger")

    return render_template("vote.html", form=vote_form, role_form=role_form, user=user, results=db.get_results())

@app.get("/results")
def results():
    return render_template("results.html", results=db.get_results(), user=current_user())

@app.get("/admin/results")
def admin_results():
    user = current_user()
    if not user:
        flash("Please login first.", "warning")
        return redirect(url_for("login"))
    if not db.has_role(user, "admin"):
        flash("Forbidden: admin only.", "danger")
        return redirect(url_for("results"))
    return render_template("admin_results.html", results=db.get_results(), user=user)

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
