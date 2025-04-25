import sqlite3
import uuid
import time

from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, render_template, request, redirect, url_for, session, flash, g
from flask_socketio import SocketIO, send
from markupsafe import escape

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'
DATABASE = 'market.db'
socketio = SocketIO(app)

# 로그인 실패 제한 저장소 (IP 기준)
login_failures = {}

# DB 연결 및 해제
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

# 안전한 DB 쿼리 함수 (예외 처리 포함)
def query_db(query, args=(), one=False):
    db = get_db()
    try:
        cur = db.execute(query, args)
        rv = cur.fetchall()
        cur.close()
        return (rv[0] if rv else None) if one else rv
    except sqlite3.Error as e:
        app.logger.error(f'Database error: {e}')
        return None

# DB 초기화 함수 (최초 1회 실행)
def init_db():
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS user (
                id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                bio TEXT
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS product (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                price TEXT NOT NULL,
                seller_id TEXT NOT NULL
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS report (
                id TEXT PRIMARY KEY,
                reporter_id TEXT NOT NULL,
                target_id TEXT NOT NULL,
                target_type TEXT NOT NULL,
                reason TEXT NOT NULL
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS chat (
                id TEXT PRIMARY KEY,
                sender_id TEXT NOT NULL,
                message TEXT NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        db.commit()

# 기본 라우트
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

# 회원가입
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = escape(request.form['username'])
        password = request.form['password']

        db = get_db()
        cursor = db.cursor()

        cursor.execute("SELECT * FROM user WHERE username = ?", (username,))
        if cursor.fetchone() is not None:
            flash('이미 존재하는 사용자명입니다.')
            return redirect(url_for('register'))

        user_id = str(uuid.uuid4())
        # 비밀번호 해시 생성 시 알고리즘 명시
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

        cursor.execute(
            "INSERT INTO user (id, username, password) VALUES (?, ?, ?)",
            (user_id, username, hashed_password)
        )
        db.commit()

        flash('회원가입이 완료되었습니다. 로그인 해주세요.')
        return redirect(url_for('login'))

    return render_template('register.html')

# 로그인 (IP 기준 실패 제한 포함)
@app.route('/login', methods=['GET', 'POST'])
def login():
    ip = request.remote_addr
    now = time.time()

    # 실패 기록 초기화 또는 확인
    failure = login_failures.get(ip)
    if failure:
        count = failure['count']
        last_failed = failure['last_failed']
        if count >= 5:
            elapsed = now - last_failed
            if elapsed < 5:
                wait_time = int(5 - elapsed)
                flash(f'로그인 시도 횟수가 초과되었습니다. {wait_time}초 후 다시 시도해주세요.')
                return redirect(url_for('login'))
            else:
                # 5초 지났으면 초기화
                login_failures.pop(ip)

    if request.method == 'POST':
        username = escape(request.form['username'])
        password = request.form['password']

        db = get_db()
        cursor = db.cursor()

        cursor.execute("SELECT * FROM user WHERE username = ?", (username,))
        user = cursor.fetchone()

        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            login_failures.pop(ip, None)  # 실패 기록 초기화
            flash('로그인 성공!')
            return redirect(url_for('dashboard'))
        else:
            # 실패 기록 갱신
            if ip not in login_failures:
                login_failures[ip] = {'count': 1, 'last_failed': now}
            else:
                login_failures[ip]['count'] += 1
                login_failures[ip]['last_failed'] = now
            flash('아이디 또는 비밀번호가 올바르지 않습니다.')
            return redirect(url_for('login'))

    return render_template('login.html')

# 로그아웃
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('로그아웃되었습니다.')
    return redirect(url_for('index'))

# 대시보드
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()

    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    current_user = cursor.fetchone()

    cursor.execute("SELECT * FROM product")
    all_products = cursor.fetchall()

    return render_template('dashboard.html', products=all_products, user=current_user)

# 프로필 (bio 업데이트, 입력값 escape 적용)
@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()

    if request.method == 'POST':
        bio = escape(request.form.get('bio', ''))
        cursor.execute("UPDATE user SET bio = ? WHERE id = ?", (bio, session['user_id']))
        db.commit()
        flash('프로필이 업데이트되었습니다.')
        return redirect(url_for('profile'))

    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    current_user = cursor.fetchone()

    return render_template('profile.html', user=current_user)

# 상품 등록
@app.route('/product/new', methods=['GET', 'POST'])
def new_product():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        title = escape(request.form['title'])
        description = escape(request.form['description'])
        price = escape(request.form['price'])

        db = get_db()
        cursor = db.cursor()
        product_id = str(uuid.uuid4())

        cursor.execute(
            "INSERT INTO product (id, title, description, price, seller_id) VALUES (?, ?, ?, ?, ?)",
            (product_id, title, description, price, session['user_id'])
        )
        db.commit()
        flash('상품이 등록되었습니다.')
        return redirect(url_for('dashboard'))

    return render_template('new_product.html')

# 상품 상세보기
@app.route('/product/<product_id>')
def view_product(product_id):
    db = get_db()
    cursor = db.cursor()

    cursor.execute("SELECT * FROM product WHERE id = ?", (product_id,))
    product = cursor.fetchone()

    if not product:
        flash('상품을 찾을 수 없습니다.')
        return redirect(url_for('dashboard'))

    cursor.execute("SELECT * FROM user WHERE id = ?", (product['seller_id'],))
    seller = cursor.fetchone()

    return render_template('view_product.html', product=product, seller=seller)

# 신고하기
@app.route('/report', methods=['GET', 'POST'])
def report():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()

    if request.method == 'POST':
        target_id = escape(request.form['target_id'])
        target_type = escape(request.form['target_type'])
        reason = escape(request.form['reason'])
        report_id = str(uuid.uuid4())

        cursor.execute(
            "INSERT INTO report (id, reporter_id, target_id, target_type, reason) VALUES (?, ?, ?, ?, ?)",
            (report_id, session['user_id'], target_id, target_type, reason)
        )
        db.commit()
        flash('신고가 접수되었습니다.')
        return redirect(url_for('dashboard'))

    return render_template('report.html')

# 실시간 채팅 (브로드캐스트)
@socketio.on('send_message')
def handle_send_message_event(data):
    message_id = str(uuid.uuid4())
    user_id = session.get('user_id', 'anonymous')
    message_text = data.get('message', '')

    db = get_db()
    cursor = db.cursor()
    cursor.execute(
        "INSERT INTO chat (id, sender_id, message) VALUES (?, ?, ?)",
        (message_id, user_id, message_text)
    )
    db.commit()

    data['message_id'] = message_id
    send(data, broadcast=True)


if __name__ == '__main__':
    init_db()
    socketio.run(app, debug=True)
