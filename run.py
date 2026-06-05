import sqlite3
import csv
import io
import os
import logging
from dotenv import load_dotenv
from flask import Flask, request, render_template, session, redirect, url_for, flash
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf.csrf import CSRFProtect
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from flasgger import Swagger

from core.blockchain import EduBlockchain

# Nạp cấu hình từ .env
load_dotenv()

# Cấu hình Hệ thống Logging
if not os.path.exists('data'):
    os.makedirs('data', exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler('data/system.log', encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Đọc cấu hình DB từ .env
DB_PATH = os.environ.get('DB_PATH', 'users.db')

app = Flask(__name__)

# Cấu hình Swagger UI (Tài liệu API tự động)
swagger = Swagger(app, template={
    "swagger": "2.0",
    "info": {
        "title": "EduBlockchain API",
        "description": "Tài liệu kỹ thuật API cho Hệ thống Văn Bằng Blockchain (Tích hợp Smart Contract & Merkle Tree)",
        "version": "1.0.0"
    }
})

# [BẢO MẬT] 1. Tránh hardcode Secret Key, ưu tiên dùng biến môi trường (fallback ngẫu nhiên)
app.secret_key = os.environ.get('SECRET_KEY', 'default-secret-key-for-dev-12345')

# [BẢO MẬT] 2. Cấu hình an toàn cho Session Cookie và giới hạn dung lượng upload
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,  # Chống XSS đọc Cookie
    SESSION_COOKIE_SAMESITE='Lax', # Chống CSRF qua Cookie
    MAX_CONTENT_LENGTH=5 * 1024 * 1024 # Chống DoS: Tối đa 5MB cho file tải lên
)

# [BẢO MẬT] 3. Bật tính năng chống CSRF cho toàn bộ ứng dụng
csrf = CSRFProtect(app)

edu_chain = EduBlockchain()

def generate_rsa_keypair(username):
    if not os.path.exists('keys'):
        os.makedirs('keys', exist_ok=True)
    private_key_path = f'keys/{username}_private.pem'
    
    try:
        # Tạo key mới
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pem_private = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        # Ghi file nguyên tử: chỉ ghi nếu file CHƯA tồn tại (tránh ghi đè do worker khác)
        with open(private_key_path, 'xb') as f:
            f.write(pem_private)
    except FileExistsError:
        # Nếu worker khác đã tạo file rồi, ta chỉ việc đọc file đó lên thay vì dùng key vừa sinh
        with open(private_key_path, 'rb') as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)
            
    public_key = private_key.public_key()
    pem_public = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return pem_public.decode('utf-8')

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT, role TEXT, university_name TEXT, public_key TEXT)''')
    c.execute("SELECT * FROM users")
    if not c.fetchone():
        try:
            hashed_pw = generate_password_hash("123456")
            
            pub_bachkhoa = generate_rsa_keypair("bachkhoa")
            pub_kinhte = generate_rsa_keypair("kinhte")
            pub_hubt = generate_rsa_keypair("hubt")

            c.execute("INSERT INTO users (username, password, role, university_name, public_key) VALUES (?, ?, ?, ?, ?)",
                      ("bachkhoa", hashed_pw, "university", "Đại học Bách Khoa Hà Nội", pub_bachkhoa))
            c.execute("INSERT INTO users (username, password, role, university_name, public_key) VALUES (?, ?, ?, ?, ?)",
                      ("kinhte", hashed_pw, "university", "Đại học Kinh tế Quốc dân", pub_kinhte))
            c.execute("INSERT INTO users (username, password, role, university_name, public_key) VALUES (?, ?, ?, ?, ?)",
                      ("hubt", hashed_pw, "university", "Đại học Kinh doanh và Công nghệ Hà Nội", pub_hubt))
            conn.commit()
        except sqlite3.IntegrityError:
            conn.rollback()
    else:
        conn.commit()
    conn.close()

init_db()

@app.route('/')
def index():
    edu_chain.load_chain() # Nạp lại chuỗi khối mới nhất để giao diện Sổ cái luôn được cập nhật
    return render_template('index.html', chain=edu_chain.chain, verify_result=None)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username, password = request.form['username'], request.form['password']
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT password, role, university_name FROM users WHERE username=?", (username,))
        user = c.fetchone()
        conn.close()
        if user and check_password_hash(user[0], password):
            # [BẢO MẬT] 4. Xóa session cũ trước khi đăng nhập để phòng chống Session Fixation
            session.clear()
            session['username'] = username
            session['role'] = user[1]
            session['university_name'] = user[2]
            return redirect(url_for('index'))
        else:
            flash("Sai tài khoản hoặc mật khẩu!", "error")
            return redirect(url_for('login'))
    return render_template('index.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

@app.route('/issue', methods=['POST'])
def issue_and_mine():
    """
    Cấp phát văn bằng (Yêu cầu quyền Đại học)
    Hệ thống sẽ lấy Private Key của trường hiện tại để Ký số điện tử (Digital Signature) lên dữ liệu văn bằng và lưu vào chuỗi khối.
    ---
    tags:
      - 🎓 Quản lý Văn bằng (Admin)
    parameters:
      - name: student_id
        in: formData
        type: string
        required: true
        description: Mã sinh viên (VD - SV001)
      - name: student_name
        in: formData
        type: string
        required: true
        description: Họ và Tên sinh viên
      - name: dob
        in: formData
        type: string
        required: true
        description: Ngày tháng năm sinh
      - name: degree_info
        in: formData
        type: string
        required: true
        description: Tên văn bằng (VD - Kỹ sư phần mềm)
      - name: graduation_year
        in: formData
        type: string
        required: true
        description: Năm tốt nghiệp
    responses:
      302:
        description: Chuyển hướng trang chủ sau khi cấp bằng.
      400:
        description: Lỗi thiếu CSRF Token hoặc lỗi dữ liệu đầu vào.
    """
    if session.get('role') != 'university':
        return redirect(url_for('index'))
    success, result = edu_chain.issue_certificate(
        session.get('university_name'), request.form.get('student_id'),
        request.form.get('student_name'), request.form.get('dob'),
        request.form.get('degree_info'), request.form.get('graduation_year'),
        session.get('username')
    )
    if success:
        edu_chain.mine_pending_certificates(difficulty=3)
        flash(f"Cấp phát thành công! Số hiệu: {result}", "success")
        logger.info(f"ISSUE: {session.get('university_name')} đã cấp bằng cho {request.form.get('student_id')} (Mã: {result})")
    else:
        flash(result, "error")
        logger.warning(f"ISSUE_FAILED: {session.get('university_name')} cấp bằng thất bại. Lỗi: {result}")
    return redirect(url_for('index'))

@app.route('/issue_bulk', methods=['POST'])
def issue_bulk():
    if session.get('role') != 'university':
        return redirect(url_for('index'))
    file = request.files.get('file')
    if not file or not file.filename.endswith('.csv'):
        return redirect(url_for('index'))
    stream = io.StringIO(file.stream.read().decode("UTF8"), newline=None)
    csv_input = csv.reader(stream)
    count = 0
    for row in csv_input:
        if len(row) >= 3:
            grad_year = row[3].strip() if len(row) > 3 else "2026"
            dob = row[4].strip() if len(row) > 4 else "01/01/2000"
            success, _ = edu_chain.issue_certificate(
                session.get('university_name'), row[0].strip(), row[1].strip(),
                dob, row[2].strip(), grad_year,
                session.get('username')
            )
            if success:
                count += 1
    if count > 0:
        edu_chain.mine_pending_certificates(difficulty=3)
        flash(f"Đã đóng gói {count} bằng vào 1 Block duy nhất.", "success")
        logger.info(f"ISSUE_BULK: {session.get('university_name')} đã cấp hàng loạt {count} bằng trong 1 Block.")
    return redirect(url_for('index'))

@app.route('/revoke', methods=['POST'])
def revoke():
    if session.get('role') != 'university':
        return redirect(url_for('index'))
    cert_id_to_revoke = request.form.get('cert_id').strip().upper()
    revoke_reason = request.form.get('reason')
    edu_chain.revoke_certificate(session.get('university_name'), cert_id_to_revoke, revoke_reason)
    edu_chain.mine_pending_certificates(difficulty=3)
    flash("Đã ghi lệnh THU HỒI vĩnh viễn lên Blockchain!", "success")
    logger.info(f"REVOKE: {session.get('university_name')} đã THU HỒI bằng {cert_id_to_revoke}. Lý do: {revoke_reason}")
    return redirect(url_for('index'))

@app.route('/verify', methods=['GET'])
def verify():
    """
    Tra cứu và Xác minh văn bằng trên chuỗi khối
    Truy vấn số hiệu văn bằng để giải mã Chữ ký số (RSA) và kiểm tra đối chiếu mã băm Merkle Root trên Sổ cái.
    ---
    tags:
      - 🔎 Khách (Public API)
    parameters:
      - name: cert_id
        in: query
        type: string
        required: true
        description: Số hiệu văn bằng mã hóa (Ví dụ - A7B2C9F1)
    responses:
      200:
        description: Trả về trang HTML với kết quả HỢP LỆ, ĐÃ THU HỒI hoặc BẰNG GIẢ.
    """
    result = edu_chain.verify_certificate(request.args.get('cert_id'))
    return render_template('index.html', chain=edu_chain.chain, verify_result=result)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
