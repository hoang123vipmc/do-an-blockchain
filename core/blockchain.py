import hashlib
import json
import os
import sqlite3
import base64
from time import time
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

def calculate_merkle_root(transactions):
    if not transactions:
        return hashlib.sha256(b"empty_block").hexdigest()
    
    # Băm từng transaction (văn bằng) để tạo các lá của cây (leaf nodes)
    hashes = []
    for tx in transactions:
        tx_string = json.dumps(tx, sort_keys=True).encode()
        hashes.append(hashlib.sha256(tx_string).hexdigest())
    
    # Lặp lại việc ghép đôi và băm cho đến khi chỉ còn 1 root
    while len(hashes) > 1:
        if len(hashes) % 2 != 0:
            hashes.append(hashes[-1]) # Nhân đôi node cuối nếu số lượng lẻ
        
        new_level = []
        for i in range(0, len(hashes), 2):
            combined = (hashes[i] + hashes[i+1]).encode()
            new_level.append(hashlib.sha256(combined).hexdigest())
        hashes = new_level
        
    return hashes[0]

class Block:
    def __init__(self, index, timestamp, certificates, previous_hash, nonce=0, hash_val=None, merkle_root=None):
        self.index = index
        self.timestamp = timestamp
        self.certificates = certificates
        self.previous_hash = previous_hash
        self.nonce = nonce
        self.merkle_root = merkle_root if merkle_root else calculate_merkle_root(certificates)
        self.hash = hash_val if hash_val else self.calculate_hash()

    def calculate_hash(self):
        # Header block giờ chỉ lưu merkle_root thay vì băm trực tiếp mảng certificates
        block_string = json.dumps({
            "index": self.index, "timestamp": self.timestamp,
            "merkle_root": self.merkle_root, "previous_hash": self.previous_hash, "nonce": self.nonce
        }, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

class EduBlockchain:
    def __init__(self):
        self.chain = []
        self.pending_certificates = []
        self.db_file = os.environ.get('BLOCKCHAIN_DB_PATH', 'blockchain_data.json')
        if not self.load_chain(): self.create_genesis_block()

    def create_genesis_block(self):
        self.chain.append(Block(0, time(), [], "0"))
        self.save_chain()

    def save_chain(self):
        chain_data = [{'index': b.index, 'timestamp': b.timestamp, 'certificates': b.certificates,
                       'previous_hash': b.previous_hash, 'nonce': b.nonce, 'hash': b.hash, 'merkle_root': b.merkle_root} for b in self.chain]
        with open(self.db_file, 'w', encoding='utf-8') as f:
            json.dump(chain_data, f, ensure_ascii=False, indent=4)

    def load_chain(self):
        if os.path.exists(self.db_file):
            with open(self.db_file, 'r', encoding='utf-8') as f:
                try:
                    chain_data = json.load(f)
                    self.chain = [] # Xóa dữ liệu cũ trên RAM để nạp lại bản mới nhất từ ổ cứng
                    for b in chain_data:
                        self.chain.append(
                            Block(b['index'], b['timestamp'], b['certificates'], b['previous_hash'], b['nonce'],
                                  b['hash'], b.get('merkle_root')))
                    return True
                except:
                    pass
        return False

    def issue_certificate(self, university, student_id, student_name, dob, degree_info, graduation_year, username=None):
        unique_string = f"{university}-{student_id}-{degree_info}-{graduation_year}-{time()}".encode()
        cert_id = hashlib.md5(unique_string).hexdigest()[:8].upper()
        
        cert_data = {
            'action': 'ISSUE', 'cert_id': cert_id, 'university': university,
            'student_id': student_id, 'student_name': student_name,
            'dob': dob, 'degree_info': degree_info, 'graduation_year': graduation_year
        }

        # Ký số nếu có truyền username và tìm thấy file Private Key
        if username and os.path.exists(f"keys/{username}_private.pem"):
            with open(f"keys/{username}_private.pem", "rb") as key_file:
                private_key = serialization.load_pem_private_key(key_file.read(), password=None)
            
            data_to_sign = json.dumps(cert_data, sort_keys=True).encode()
            signature = private_key.sign(
                data_to_sign,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256()
            )
            cert_data['signature'] = base64.b64encode(signature).decode('utf-8')

        self.pending_certificates.append(cert_data)
        return True, cert_id

    def revoke_certificate(self, university, cert_id, reason):
        self.pending_certificates.append({
            'action': 'REVOKE', 'cert_id': cert_id, 'university': university, 'reason': reason, 'timestamp': time()
        })
        return True

    def mine_pending_certificates(self, difficulty=3):
        if not self.pending_certificates: return False
        self.load_chain() # Nạp lại chuỗi khối mới nhất trước khi đào để tránh ghi đè block của worker khác
        new_block = Block(len(self.chain), time(), self.pending_certificates, self.chain[-1].hash)
        target = "0" * difficulty
        while new_block.hash[:difficulty] != target:
            new_block.nonce += 1
            new_block.hash = new_block.calculate_hash()
        self.chain.append(new_block)
        self.pending_certificates = []
        self.save_chain()
        return new_block

    def verify_certificate(self, search_cert_id):
        self.load_chain() # Luôn tải dữ liệu mới nhất từ ổ cứng trước khi tra cứu
        if not search_cert_id: return None
        search_cert_id = search_cert_id.strip().upper()
        cert_data = None
        is_revoked = False
        revoke_reason = ""

        for block in self.chain:
            for cert in block.certificates:
                if cert.get('cert_id') == search_cert_id:
                    if cert.get('action', 'ISSUE') == 'ISSUE':
                        cert_data = cert
                        cert_data['block_index'] = block.index
                        cert_data['hash'] = block.hash
                    elif cert.get('action') == 'REVOKE':
                        is_revoked = True
                        revoke_reason = cert.get('reason', 'Phát hiện sai phạm')

        if not cert_data: return {"status": "INVALID"}
        
        # Xác minh chữ ký số (Digital Signature)
        signature_b64 = cert_data.get('signature')
        cert_data['signature_valid'] = False
        if signature_b64:
            try:
                db_path = os.environ.get('DB_PATH', 'users.db')
                conn = sqlite3.connect(db_path)
                c = conn.cursor()
                c.execute("SELECT public_key FROM users WHERE university_name=?", (cert_data['university'],))
                row = c.fetchone()
                conn.close()
                if row and row[0]:
                    public_key = serialization.load_pem_public_key(row[0].encode('utf-8'))
                    verify_data = {k: v for k, v in cert_data.items() if k not in ['block_index', 'hash', 'signature', 'signature_valid']}
                    data_to_verify = json.dumps(verify_data, sort_keys=True).encode()
                    
                    public_key.verify(
                        base64.b64decode(signature_b64),
                        data_to_verify,
                        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                        hashes.SHA256()
                    )
                    cert_data['signature_valid'] = True
            except InvalidSignature:
                return {"status": "FORGED", "data": cert_data, "reason": "Chữ ký số RSA bị sai lệch. Cảnh báo dữ liệu giả mạo!"}
            except Exception:
                pass # Lỗi đọc key thì coi như unverified

        if is_revoked: return {"status": "REVOKED", "data": cert_data, "reason": revoke_reason}
        return {"status": "VALID", "data": cert_data}
