from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime
import sqlite3
import os
from scanner_all import run_scan

ADMIN_EMAILS = ["msooyou090112@gmail.com"]

app = Flask(__name__)
# 세션(로그인 정보)용 나중에 랜덤 문자열로 바꿔야함
app.secret_key = "haeckingban-secret-key-change-me"

DB_PATH = "users.db"

# 업로드 폴더 설정 (Showtime 게시판용)
UPLOAD_FOLDER = "static/uploads"
ALLOWED_EXT = {"png", "jpg", "jpeg", "gif", "webp"}
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


# ---------------------------------------------------------------------------
# DB 초기화 — users 테이블 만들기
# ---------------------------------------------------------------------------
def init_user_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            nickname TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            is_approved INTEGER DEFAULT 0,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
# DB 초기화 — posts 테이블 만들기 (Showtime 게시판)
# ---------------------------------------------------------------------------
def init_posts_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            nickname TEXT NOT NULL,
            image_path TEXT NOT NULL,
            description TEXT NOT NULL,
            is_official INTEGER DEFAULT 0,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()


init_user_db()
init_posts_db()


# ---------------------------------------------------------------------------
# 라우트
# ---------------------------------------------------------------------------
@app.route('/')
def index():
    return render_template('index.html')


# ---------- 회원가입 ----------
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        name = request.form['name'].strip()
        email = request.form['email'].strip().lower()
        nickname = request.form['nickname'].strip()
        password = request.form['password']
        password_confirm = request.form['password_confirm']

        # 기본 검증
        if not all([name, email, nickname, password, password_confirm]):
            return "모든 항목을 입력해주세요.", 400
        if password != password_confirm:
            return "비밀번호가 일치하지 않습니다.", 400
        if len(password) < 8:
            return "비밀번호는 8자 이상이어야 합니다.", 400

        # DB 저장
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        try:
            cursor.execute("""
                INSERT INTO users (name, email, nickname, password_hash)
                VALUES (?, ?, ?, ?)
            """, (name, email, nickname, generate_password_hash(password)))
            conn.commit()
        except sqlite3.IntegrityError as e:
            conn.close()
            if "email" in str(e):
                return "이미 사용 중인 이메일입니다.", 400
            if "nickname" in str(e):
                return "이미 사용 중인 닉네임입니다.", 400
            return "가입 실패", 400
        conn.close()

        return render_template('signup_done.html')

    return render_template('signup.html')


# ---------- 로그인 ----------
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email'].strip().lower()
        password = request.form['password']

        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, name, email, nickname, password_hash, is_approved FROM users WHERE email = ?",
            (email,)
        )
        user = cursor.fetchone()
        conn.close()

        if user is None or not check_password_hash(user[4], password):
            return "이메일 또는 비밀번호가 올바르지 않습니다.", 401

        # 승인 확인 (관리자는 예외)
        if user[2] not in ADMIN_EMAILS and user[5] == 0:
            return "관리자 승인 대기 중입니다.", 403

        session['user_id'] = user[0]
        session['name'] = user[1]
        session['email'] = user[2]
        session['nickname'] = user[3]
        session['is_admin'] = (user[2] in ADMIN_EMAILS)

        return redirect(url_for('index'))

    return render_template('login.html')


# ---------- 로그아웃 ----------
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))


# ---------- 관리자 페이지 ----------
@app.route('/admin')
def admin():
    if not session.get('is_admin'):
        return "접근 권한이 없습니다.", 403

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT id, name, email, nickname, is_approved, created_at FROM users ORDER BY created_at DESC")
    users = cursor.fetchall()
    conn.close()

    return render_template('admin.html', users=users)


@app.route('/admin/approve/<int:user_id>', methods=['POST'])
def approve_user(user_id):
    if not session.get('is_admin'):
        return "권한 없음", 403

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET is_approved = 1 WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()
    return redirect(url_for('admin'))


@app.route('/admin/reject/<int:user_id>', methods=['POST'])
def reject_user(user_id):
    if not session.get('is_admin'):
        return "권한 없음", 403

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()
    return redirect(url_for('admin'))


@app.route('/admin/unapprove/<int:user_id>', methods=['POST'])
def unapprove_user(user_id):
    if not session.get('is_admin'):
        return "권한 없음", 403

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET is_approved = 0 WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()
    return redirect(url_for('admin'))


# ---------- 나머지 페이지들 ----------
@app.route('/scanner')
def scanner():
    return render_template('scanner.html')


@app.route('/feedback')
def feedback():
    return render_template('feedback.html')


@app.route('/scan', methods=['POST'])
def scan():
    target = request.form['url']
    findings = run_scan(target)
    return render_template('result.html', findings=findings)


# ---------- 게시판 (Showtime) ----------
@app.route('/showtime', methods=['GET', 'POST'])
def showtime():
    # 게시물 작성 (로그인 필요)
    if request.method == 'POST':
        if not session.get('email'):
            return redirect(url_for('login'))

        description = request.form['description'].strip()
        image = request.files.get('image')

        if not description or not image or image.filename == '':
            return "이미지와 설명을 모두 입력해주세요.", 400

        ext = image.filename.rsplit('.', 1)[-1].lower()
        if ext not in ALLOWED_EXT:
            return "이미지 파일만 업로드 가능합니다.", 400

        filename = f"{datetime.now().strftime('%Y%m%d%H%M%S')}_{secure_filename(image.filename)}"
        image.save(os.path.join(UPLOAD_FOLDER, filename))

        is_official = 1 if session.get('is_admin') and request.form.get('is_official') else 0

        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO posts (user_id, nickname, image_path, description, is_official)
            VALUES (?, ?, ?, ?, ?)
        """, (session['user_id'], session['nickname'], filename, description, is_official))
        conn.commit()
        conn.close()

        return redirect(url_for('showtime'))

    # 게시물 목록
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, nickname, image_path, description, is_official, created_at
        FROM posts
        ORDER BY is_official DESC, created_at DESC
    """)
    posts = cursor.fetchall()
    conn.close()
    return render_template('showtime.html', posts=posts)


@app.route('/showtime/delete/<int:post_id>', methods=['POST'])
def showtime_delete(post_id):
    if not session.get('is_admin'):
        return "권한 없음", 403

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT image_path FROM posts WHERE id = ?", (post_id,))
    row = cursor.fetchone()
    if row:
        try:
            os.remove(os.path.join(UPLOAD_FOLDER, row[0]))
        except OSError:
            pass
    cursor.execute("DELETE FROM posts WHERE id = ?", (post_id,))
    conn.commit()
    conn.close()
    return redirect(url_for('showtime'))


if __name__ == '__main__':
    app.run(debug=True)