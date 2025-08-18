python -m venv .venv
source .venv/bin/activate   # (Windows는 .venv\Scripts\activate)
pip install -r requirements.txt
python app.py

//로그인 요청 테스트
$ curl -X POST http://127.0.0.1:5000/api/auth/login \
-H "Content-Type: application/json" \
-d '{"username": "testuser", "password": "testpassword"}'

//데이터 베이스
$ curl -X GET http://127.0.0.1:5000/api/auth/users 
//Reset
$ curl -X POST http://127.0.0.1:5000/api/auth/reset
