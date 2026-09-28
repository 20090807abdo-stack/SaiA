"""SaiA - System AI Assistant: download site + admin dashboard (Flask, SQLAlchemy, SQLite)."""
import csv
import html
import io
import os
import re
import secrets
import time
from datetime import datetime, timedelta
from functools import wraps

from flask import (Flask, Response, abort, flash, redirect, render_template,
                   request, send_file, session, url_for)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
# On Render, point DATA_DIR at a persistent disk (e.g. /var/data) or data is lost on redeploy.
DATA_DIR = os.environ.get("DATA_DIR", os.path.join(BASE_DIR, "data"))
UPLOAD_DIR = os.path.join(DATA_DIR, "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)

IS_PROD = bool(os.environ.get("RENDER"))
SECRET_FILE = os.path.join(DATA_DIR, ".secret_key")


def _secret_key():
    if os.environ.get("SECRET_KEY"):
        return os.environ["SECRET_KEY"]
    if os.path.exists(SECRET_FILE):
        return open(SECRET_FILE).read().strip()
    key = secrets.token_hex(32)
    with open(SECRET_FILE, "w") as f:
        f.write(key)
    return key


app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
app.config.update(
    SECRET_KEY=_secret_key(),
    SQLALCHEMY_DATABASE_URI="sqlite:///" + os.path.join(DATA_DIR, "saia.db"),
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
    MAX_CONTENT_LENGTH=int(os.environ.get("MAX_UPLOAD_MB", 300)) * 1024 * 1024,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=IS_PROD,
    PERMANENT_SESSION_LIFETIME=timedelta(days=30),
)
db = SQLAlchemy(app)


# ---------------------------------------------------------------- models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class DownloadAnalytics(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(64))
    user_agent = db.Column(db.String(512))
    country_code = db.Column(db.String(8))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)


class AppVersion(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    version_number = db.Column(db.String(32), nullable=False)
    filename = db.Column(db.String(255), nullable=False)
    file_path = db.Column(db.String(512), nullable=False)
    upload_date = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=False, index=True)

    @property
    def size_mb(self):
        try:
            return f"{os.path.getsize(self.file_path) / 1048576:.1f} MB"
        except OSError:
            return "file missing"


# ---------------------------------------------------------------- setup
def ensure_admin():
    if User.query.first():
        return
    username = os.environ.get("ADMIN_USERNAME", "admin")
    password = os.environ.get("ADMIN_PASSWORD")
    generated = not password
    if generated:
        password = secrets.token_urlsafe(12)
    db.session.add(User(username=username, password_hash=generate_password_hash(password)))
    db.session.commit()
    if generated:
        print(f"[SaiA] Admin created. username={username} password={password} (change ASAP)", flush=True)


with app.app_context():
    db.create_all()
    ensure_admin()


@app.cli.command("set-password")
def set_password():
    """Reset or create an admin: flask --app app set-password"""
    import getpass
    username = input("Username: ").strip()
    pw = getpass.getpass("New password (min 10 chars): ")
    if len(pw) < 10:
        raise SystemExit("Password too short.")
    user = User.query.filter_by(username=username).first() or User(username=username)
    user.password_hash = generate_password_hash(pw)
    db.session.add(user)
    db.session.commit()
    print("Saved.")


# ---------------------------------------------------------------- security helpers
@app.before_request
def csrf_protect():
    if "csrf" not in session:
        session["csrf"] = secrets.token_hex(16)
    if request.method == "POST":
        sent = request.form.get("csrf_token", "")
        if not secrets.compare_digest(sent, session["csrf"]):
            abort(400, "Invalid CSRF token")


@app.context_processor
def inject_csrf():
    return {"csrf_token": session.get("csrf", ""), "now_year": datetime.utcnow().year}


@app.after_request
def security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "same-origin"
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src https://fonts.gstatic.com; script-src 'self' 'unsafe-inline'; img-src 'self' data:; "
        "frame-ancestors 'none'")
    return resp


def login_required(view):
    @wraps(view)
    def wrapped(*a, **kw):
        if not session.get("uid"):
            return redirect(url_for("login"))
        return view(*a, **kw)
    return wrapped


_fails = {}  # ip -> [timestamps]; in-memory (run one Gunicorn worker)


def _blocked(ip):
    now = time.time()
    _fails[ip] = [t for t in _fails.get(ip, []) if now - t < 600]
    return len(_fails[ip]) >= 5


# ---------------------------------------------------------------- public routes
@app.route("/")
def index():
    return render_template("index.html", latest=AppVersion.query.filter_by(is_active=True).first())


@app.route("/download/latest")
def download_latest():
    ver = AppVersion.query.filter_by(is_active=True).first()
    if not ver or not os.path.isfile(ver.file_path):
        flash("The installer isn't available right now. Please check back soon.", "error")
        return redirect(url_for("index") + "#top")
    db.session.add(DownloadAnalytics(
        ip_address=request.remote_addr,
        user_agent=(request.user_agent.string or "")[:512],
        country_code=(request.headers.get("CF-IPCountry")
                      or request.headers.get("X-Country-Code") or "--")[:8]))
    db.session.commit()
    return send_file(ver.file_path, as_attachment=True,
                     download_name=f"SaiA_Setup_v{ver.version_number}.exe",
                     mimetype="application/octet-stream")


# ---------------------------------------------------------------- auth
@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("uid"):
        return redirect(url_for("dashboard"))
    error = None
    if request.method == "POST":
        ip = request.remote_addr
        if _blocked(ip):
            error = "Too many attempts. Try again in a few minutes."
        else:
            user = User.query.filter_by(username=request.form.get("username", "").strip()).first()
            if user and check_password_hash(user.password_hash, request.form.get("password", "")):
                csrf = session.get("csrf")
                session.clear()
                session["csrf"] = csrf
                session["uid"] = user.id
                session.permanent = bool(request.form.get("remember"))
                return redirect(url_for("dashboard"))
            _fails.setdefault(ip, []).append(time.time())
            error = "Incorrect username or password."
    return render_template("login.html", error=error)


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))


# ---------------------------------------------------------------- admin
@app.route("/admin/dashboard")
@login_required
def dashboard():
    now = datetime.utcnow()
    today = now.replace(hour=0, minute=0, second=0, microsecond=0)
    q = DownloadAnalytics.query
    stats = {
        "total": q.count(),
        "today": q.filter(DownloadAnalytics.timestamp >= today).count(),
        "week": q.filter(DownloadAnalytics.timestamp >= now - timedelta(days=7)).count(),
    }
    logs = q.order_by(DownloadAnalytics.timestamp.desc()).limit(200).all()
    return render_template("dashboard.html", stats=stats, logs=logs,
                           active=AppVersion.query.filter_by(is_active=True).first())


@app.route("/admin/upload", methods=["POST"])
@login_required
def upload():
    f = request.files.get("file")
    version = request.form.get("version", "").strip()
    if not f or not f.filename:
        flash("Choose an .exe file to upload.", "error")
    elif not re.fullmatch(r"\d+(\.\d+){1,3}", version):
        flash("Version must look like 1.0.0.", "error")
    elif not f.filename.lower().endswith(".exe"):
        flash("Only .exe files are accepted.", "error")
    elif f.stream.read(2) != b"MZ":  # Windows executable header
        flash("That file isn't a valid Windows executable.", "error")
    else:
        f.stream.seek(0)
        name = secure_filename(f"SaiA_Setup_v{version}.exe")
        path = os.path.join(UPLOAD_DIR, name)
        f.save(path)
        for old in AppVersion.query.filter_by(is_active=True).all():
            old.is_active = False
            if old.file_path != path and os.path.isfile(old.file_path):
                os.remove(old.file_path)  # replace: free disk space
        db.session.add(AppVersion(version_number=version, filename=name, file_path=path, is_active=True))
        db.session.commit()
        flash(f"Version {version} is now live.", "ok")
    return redirect(url_for("dashboard"))


def _safe_cell(v):
    v = "" if v is None else str(v)
    return "'" + v if v[:1] in "=+-@\t\r" else v  # block spreadsheet formula injection


def _rows():
    for r in DownloadAnalytics.query.order_by(DownloadAnalytics.timestamp.desc()).all():
        yield [r.id, _safe_cell(r.ip_address), _safe_cell(r.country_code),
               _safe_cell(r.user_agent), r.timestamp.strftime("%Y-%m-%d %H:%M:%S")]


HEAD = ["ID", "IP address", "Country", "Browser", "Timestamp (UTC)"]


@app.route("/admin/export/<fmt>")
@login_required
def export(fmt):
    stamp = datetime.utcnow().strftime("%Y%m%d")
    if fmt == "csv":
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(HEAD)
        w.writerows(_rows())
        return Response("\ufeff" + buf.getvalue(), mimetype="text/csv",
                        headers={"Content-Disposition": f"attachment; filename=saia_downloads_{stamp}.csv"})
    if fmt == "xlsx":
        from openpyxl import Workbook
        wb = Workbook()
        ws = wb.active
        ws.title = "Downloads"
        ws.append(HEAD)
        for row in _rows():
            ws.append(row)
        for col, width in zip("ABCDE", (8, 20, 10, 70, 22)):
            ws.column_dimensions[col].width = width
        out = io.BytesIO()
        wb.save(out)
        out.seek(0)
        return send_file(out, as_attachment=True, download_name=f"saia_downloads_{stamp}.xlsx",
                         mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
    if fmt == "html":
        body = "".join("<tr>" + "".join(f"<td>{html.escape(str(c))}</td>" for c in r) + "</tr>" for r in _rows())
        head = "".join(f"<th>{h}</th>" for h in HEAD)
        page = (f"<!doctype html><meta charset='utf-8'><title>SaiA download report</title>"
                "<style>body{font:15px Georgia,serif;background:#faf8f4;color:#1a1a1a;margin:40px}"
                "table{border-collapse:collapse;width:100%}th,td{border:1px solid #1a1a1a33;padding:8px 10px;"
                "text-align:left;font-size:13px}th{background:#efece5}</style>"
                f"<h1>SaiA download report</h1><p>Generated {datetime.utcnow():%Y-%m-%d %H:%M} UTC. "
                f"Total downloads: {DownloadAnalytics.query.count()}</p>"
                f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>")
        return Response(page, mimetype="text/html",
                        headers={"Content-Disposition": f"attachment; filename=saia_report_{stamp}.html"})
    abort(404)


@app.errorhandler(413)
def too_large(_):
    flash("That file is too large.", "error")
    return redirect(url_for("dashboard"))


if __name__ == "__main__":
    app.run(debug=False, port=int(os.environ.get("PORT", 5000)),host="0.0.0.0")
