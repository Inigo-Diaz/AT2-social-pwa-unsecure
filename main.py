import os
import sys
import sqlite3
import subprocess
from flask import Flask, render_template, request, redirect, session
from flask_cors import CORS
import user_management as db

from flask_wtf.csrf import CSRFProtect

# ── Auto-bootstrap the database on every startup ──────────────────────────────
# This ensures students never see "no such table" even if setup_db.py
# was never manually run, or if the .db file is missing / corrupted.
BASE_DIR     = os.path.dirname(os.path.abspath(__file__))
DB_PATH      = os.path.join(BASE_DIR, "database_files", "database.db")
SETUP_SCRIPT = os.path.join(BASE_DIR, "database_files", "setup_db.py")

def _tables_exist():
    """Return True if the required tables are all present."""
    try:
        con = sqlite3.connect(DB_PATH)
        cur = con.cursor()
        tables = {r[0] for r in cur.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()}
        con.close()
        return {"users", "posts", "messages"}.issubset(tables)
    except Exception:
        return False

def init_db():
    os.makedirs(os.path.join(BASE_DIR, "database_files"), exist_ok=True)
    if not os.path.exists(DB_PATH) or not _tables_exist():
        print("[SocialPWA] Setting up database...")
        result = subprocess.run(
            [sys.executable, SETUP_SCRIPT],
            capture_output=True, text=True
        )
        print(result.stdout)
        if result.returncode != 0:
            print("[SocialPWA] WARNING: setup_db failed:", result.stderr)
    else:
        print("[SocialPWA] Database already exists — skipping setup.")

init_db()

# ─────────────────────────────────────────────────────────────────────────────

app = Flask(__name__)

CORS(app, origins=["https://shiny-space-chainsaw-97w5wp5465r537xwr-5000.app.github.dev/"])

app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
app.config['SESSION_COOKIE_SECURE'] = True  # Only send cookie over HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevent JavaScript access
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # CSRF protection

csrf = CSRFProtect(app)

# Ensure csrf_token is available in all templates
@app.context_processor
def inject_csrf_token():
    from flask_wtf.csrf import generate_csrf
    return dict(csrf_token=generate_csrf)


# ── Home / Login ──────────────────────────────────────────────────────────────

@app.route("/", methods=["POST", "GET"])
@app.route("/index.html", methods=["POST", "GET"])
def home():
    # VULNERABILITY: Open Redirect — blindly follows 'url' query parameter
    if request.method == "GET" and request.args.get("url"):
        return redirect(request.args.get("url"), code=302)

    if request.method == "GET":
        msg = request.args.get("msg", "")
        return render_template("index.html", msg=msg)

    elif request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        isLoggedIn = db.retrieveUsers(username, password)
        if isLoggedIn:
            session['username'] = username
            posts = db.getPosts()
            return render_template("feed.html", username=username, state=isLoggedIn, posts=posts)
        else:
            return render_template("index.html", msg="Invalid credentials. Please try again.")


# ── Sign Up ───────────────────────────────────────────────────────────────────

@app.route("/signup.html", methods=["POST", "GET"])
def signup():
    if request.method == "GET" and request.args.get("url"):
        return redirect(request.args.get("url"), code=302)

    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        DoB      = request.form["dob"]
        bio      = request.form.get("bio", "")
        # VULNERABILITY: No duplicate username check
        # VULNERABILITY: No input validation or password strength enforcement
        db.insertUser(username, password, DoB, bio)
        return render_template("index.html", msg="Account created! Please log in.")
    else:
        return render_template("signup.html")


# ── Social Feed ───────────────────────────────────────────────────────────────

@app.route("/feed.html", methods=["POST", "GET"])
def feed():
    if request.method == "GET" and request.args.get("url"):
        return redirect(request.args.get("url"), code=302)

    if request.method == "POST":
        if 'username' not in session:
            return redirect("/")
        username = session['username']
        post_content = request.form["content"]
        db.insertPost(username, post_content)
        posts = db.getPosts()
        return render_template("feed.html", username=username, state=True, posts=posts)
    else:
        if 'username' not in session:
            return redirect("/")
        username = session['username']
        posts = db.getPosts()
        return render_template("feed.html", username=username, state=True, posts=posts)


# ── User Profile ──────────────────────────────────────────────────────────────

@app.route("/profile")
def profile():
    # FIXED: IDOR — require authentication to view profiles
    if 'username' not in session:
        return redirect("/")
    
    if request.args.get("url"):
        return redirect(request.args.get("url"), code=302)
    
    # FIXED: Only allow users to view their own profile (or implement proper authorization)
    requested_user = request.args.get("user", "")
    current_user = session['username']
    
    if requested_user != current_user:
        return render_template("profile.html", profile=None, username=current_user)
    
    profile_data = db.getUserProfile(requested_user)
    return render_template("profile.html", profile=profile_data, username=current_user)


# ── Direct Messages ───────────────────────────────────────────────────────────

@app.route("/messages", methods=["POST", "GET"])
def messages():
    # VULNERABILITY: No authentication — change ?user= to read anyone's inbox
    # FIXED: Require authentication to access messages
    if 'username' not in session:
        return redirect("/")
    
    current_user = session['username']
    
    if request.method == "POST":
        # FIXED: IDOR — get sender from session instead of form field
        sender = current_user
        recipient = request.form.get("recipient", "")
        body = request.form.get("body", "")
        db.sendMessage(sender, recipient, body)
        msgs = db.getMessages(current_user)
        return render_template("messages.html", messages=msgs, username=current_user, recipient=recipient)
    else:
        # FIXED: Only allow users to view their own messages
        requested_user = request.args.get("user", "")
        if requested_user != current_user:
            return redirect(f"/messages?user={current_user}")
        
        msgs = db.getMessages(current_user)
        return render_template("messages.html", messages=msgs, username=current_user, recipient=current_user)


# ── Logout ────────────────────────────────────────────────────────────────────

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


# ── Success Page ──────────────────────────────────────────────────────────────

@app.route("/success.html")
def success():
    msg = request.args.get("msg", "Your action was completed successfully.")
    return render_template("success.html", msg=msg)


# ── Run ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    app.config["TEMPLATES_AUTO_RELOAD"] = True
    app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 0
    app.run(debug=True, host="0.0.0.0", port=5000)
