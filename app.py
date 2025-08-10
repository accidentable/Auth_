import os, datetime, uuid
from functools import wraps
from dotenv import load_dotenv
from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import bcrypt
import jwt

load_dotenv()

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "dev-secret")
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL", "sqlite:///auth.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

# rate limit (기본: IP 기준)
limiter = Limiter(get_remote_address, app=app, default_limits=["200/hour"])

JWT_SECRET = os.getenv("JWT_SECRET", "dev-jwt")
ACCESS_TTL = datetime.timedelta(minutes=15)
REFRESH_TTL = datetime.timedelta(days=7)

# ---- Models ----
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, index=True, nullable=False)
    pw_hash = db.Column(db.LargeBinary(60), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

class RefreshToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    jti = db.Column(db.String(64), unique=True, index=True, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    revoked = db.Column(db.Boolean, default=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

with app.app_context():
    db.create_all()

# ---- Helpers ----
def create_access_token(user_id):
    now = datetime.datetime.utcnow()
    payload = {
        "sub": str(user_id),
        "iat": now,
        "exp": now + ACCESS_TTL,
        "type": "access",
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")

def create_refresh_token(user_id):
    now = datetime.datetime.utcnow()
    jti = uuid.uuid4().hex
    payload = {
        "sub": str(user_id),
        "iat": now,
        "exp": now + REFRESH_TTL,
        "jti": jti,
        "type": "refresh",
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm="HS256")
    db.session.add(RefreshToken(
        jti=jti, user_id=user_id, expires_at=now + REFRESH_TTL
    ))
    db.session.commit()
    return token

def set_auth_cookies(resp, access_token, refresh_token=None):
    # Secure 배포 시: secure=True, samesite="None" (HTTPS 필요)
    resp.set_cookie("access_token", access_token, httponly=True, samesite="Lax", secure=False, max_age=int(ACCESS_TTL.total_seconds()))
    if refresh_token:
        resp.set_cookie("refresh_token", refresh_token, httponly=True, samesite="Lax", secure=False, max_age=int(REFRESH_TTL.total_seconds()))
    return resp

def clear_auth_cookies(resp):
    resp.delete_cookie("access_token")
    resp.delete_cookie("refresh_token")
    return resp

def auth_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        token = request.cookies.get("access_token")
        if not token:
            return jsonify({"error": "Unauthorized"}), 401
        try:
            payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
            if payload.get("type") != "access":
                raise jwt.InvalidTokenError("Not access token")
            request.user_id = int(payload["sub"])
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Access token expired"}), 401
        except Exception:
            return jsonify({"error": "Invalid token"}), 401
        return fn(*args, **kwargs)
    return wrapper

# ---- Routes ----
@app.post("/api/auth/register")
@limiter.limit("5/minute")
def register():
    data = request.get_json(force=True, silent=True) or request.form
    username = (data.get("username") or "").strip()
    password = (data.get("password") or "").encode()

    if not username or not password:
        return jsonify({"error": "username and password required"}), 400

    if User.query.filter_by(username=username).first():
        return jsonify({"error": "username already exists"}), 409

    pw_hash = bcrypt.hashpw(password, bcrypt.gensalt())
    user = User(username=username, pw_hash=pw_hash)
    db.session.add(user)
    db.session.commit()

    return jsonify({"ok": True}), 201

@app.post("/api/auth/login")
@limiter.limit("10/minute")
def login():
    data = request.get_json(force=True, silent=True) or request.form
    username = (data.get("username") or "").strip()
    password = (data.get("password") or "").encode()

    user = User.query.filter_by(username=username).first()
    if not user or not bcrypt.checkpw(password, user.pw_hash):
        return jsonify({"error": "invalid credentials"}), 401

    access = create_access_token(user.id)
    refresh = create_refresh_token(user.id)

    resp = make_response(jsonify({"ok": True}))
    return set_auth_cookies(resp, access, refresh)

@app.post("/api/auth/refresh")
@limiter.limit("10/minute")
def refresh():
    token = request.cookies.get("refresh_token")
    if not token:
        return jsonify({"error": "no refresh token"}), 401
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        if payload.get("type") != "refresh":
            raise jwt.InvalidTokenError("Not refresh token")

        jti = payload["jti"]
        rec = RefreshToken.query.filter_by(jti=jti).first()
        if not rec or rec.revoked or rec.expires_at < datetime.datetime.utcnow():
            return jsonify({"error": "refresh revoked/expired"}), 401

        # refresh rotation: 기존 토큰 폐기하고 새로 발급
        rec.revoked = True
        db.session.commit()

        user_id = int(payload["sub"])
        new_access = create_access_token(user_id)
        new_refresh = create_refresh_token(user_id)

        resp = make_response(jsonify({"ok": True}))
        return set_auth_cookies(resp, new_access, new_refresh)

    except jwt.ExpiredSignatureError:
        return jsonify({"error": "refresh expired"}), 401
    except Exception:
        return jsonify({"error": "invalid refresh"}), 401

@app.post("/api/auth/logout")
def logout():
    # refresh 쿠키가 있으면 DB에서 해당 jti revoke (best-effort)
    token = request.cookies.get("refresh_token")
    if token:
        try:
            payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"], options={"verify_exp": False})
            rec = RefreshToken.query.filter_by(jti=payload.get("jti")).first()
            if rec and not rec.revoked:
                rec.revoked = True
                db.session.commit()
        except Exception:
            pass
    resp = make_response(jsonify({"ok": True}))
    return clear_auth_cookies(resp)

@app.get("/api/me")
@auth_required
def me():
    user = User.query.get(request.user_id)
    return jsonify({"id": user.id, "username": user.username})
    
@app.get("/")
def health():
    return jsonify({"status": "ok"})
    
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
