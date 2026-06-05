# EduBlockchain - AI Coding Agent Instructions

## Project Overview
EduBlockchain is a Flask-based educational certificate management system using blockchain technology for issuing, verifying, and revoking university certificates with cryptographic security (RSA digital signatures + Merkle trees).

## Architecture & Key Components

### Core Blockchain Layer (`core/blockchain.py`)
- **`EduBlockchain` class**: Main blockchain manager
  - Persistence: JSON-based (`blockchain_data.json` via `BLOCKCHAIN_DB_PATH` env var)
  - Genesis block auto-creation on first run
  - Merkle tree implementation for certificate transactions (`calculate_merkle_root()`)
  - Proof-of-Work mining with configurable difficulty (default=3)
- **`Block` class**: Individual blocks contain certificate transactions + merkle_root
- **Key methods**:
  - `issue_certificate()`: Creates ISSUE transactions, signs with RSA private key from `keys/{username}_private.pem`
  - `revoke_certificate()`: Creates REVOKE transactions
  - `mine_pending_certificates()`: Mines pending transactions (increments nonce until hash matches difficulty target)
  - `verify_certificate()`: Validates certificate existence, checks RSA signature against DB public key, returns status (VALID/REVOKED/FORGED/INVALID)

### Flask Web Layer (`run.py`)
- **Authentication**: SQLite users table (`users.db`) with role-based access (university admins vs verifiers)
- **Routes**:
  - `POST /issue`: Issue certificate (university role only) - auto-mines after adding transaction
  - `POST /verify`: Search & verify certificate by cert_id - validates digital signature
  - `/login`, `/logout`: Session-based auth (username/role/university_name in session)
- **Security practices documented in code**:
  - Secret key from env var `SECRET_KEY` (fallbacks to random)
  - Session fixation prevention (`session.clear()` before login)
  - CSRF protection via Flask-WTF
  - Password hashing with werkzeug

## Developer Workflows

### Running the Application
```bash
# Install dependencies
pip install flask flask-wtf flasgger cryptography python-dotenv werkzeug

# Configure environment (.env file)
BLOCKCHAIN_DB_PATH=blockchain_data.json
DB_PATH=users.db
SECRET_KEY=your-secret-here

# Start Flask server
python run.py
```

### Testing Certificate Verification
1. Navigate to `/` to view blockchain
2. Login with pre-populated credentials (admin/verifypass)
3. Issue certificate via `/issue` endpoint
4. Verify at `/verify` endpoint - check digital signature validation

### Key File Structure
- `blockchain_data.json`: Persistent blockchain state (auto-created)
- `users.db`: User credentials, roles, university public keys
- `keys/`: RSA key pairs (`{username}_private.pem`, `{username}_public.pem`)
- `templates/index.html`: Frontend
- `data/system.log`: Application logs (enabled at startup)

## Project-Specific Patterns & Conventions

### Certificate Data Structure
```python
{
    'action': 'ISSUE|REVOKE',
    'cert_id': str,           # 8-char uppercase MD5-based ID
    'university': str,
    'student_id': str,
    'student_name': str,
    'dob': str,
    'degree_info': str,
    'graduation_year': str,
    'signature': str,         # Base64-encoded RSA signature (if issued by university)
    'timestamp': float        # Unix timestamp
}
```

### Naming Conventions
- Transaction types: UPPERCASE (`ISSUE`, `REVOKE`)
- Certificate IDs: UPPERCASE hex (`CERT_ID` examples: A1B2C3D4)
- Status responses: UPPERCASE (`VALID`, `REVOKED`, `FORGED`, `INVALID`)

### Error Handling Patterns
- Blockchain methods return `(bool, data)` tuples for success/failure
- `verify_certificate()` returns dict with `{"status": "...", "data": ..., "reason": ...}` structure
- Failed cryptographic operations logged silently; unverified certificates treated as unsigned (not failures)

### Database Interactions
- SQLite only; single connection per query (no connection pooling)
- Public keys stored as PEM strings in users table
- Always query by username or university_name for credential/key lookup

## Critical Integration Points

### RSA Digital Signature Flow
1. University issues certificate with username → loads private key from `keys/{username}_private.pem`
2. Signs certificate JSON (excluding signature field) with RSA-PSS (SHA256)
3. Base64-encodes signature, stores in transaction
4. Verification: loads public key from users.db → verifies signature against original JSON

### Merkle Tree Verification
- Each block's merkle_root computed from all certificates in that block
- Block hash includes merkle_root (not individual certificate hashes)
- Supports efficient certificate membership proofs

### Mining Process
- Pending certificates accumulate until `mine_pending_certificates()` called
- Difficulty hardcoded or passed as parameter; increases hash computation time
- Current nonce approach: linear search (consider optimizing for production)

## Common Tasks & Patterns

### Adding New Certificate Field
1. Update `issue_certificate()` signature + cert_data dict
2. Update Block serialization/deserialization in `save_chain()` / `load_chain()`
3. Update `verify_certificate()` signature exclusion filter to include new field if needed

### Extending Verification Logic
- Modify `verify_certificate()` to add new status types or validation rules
- Ensure signature verification happens before business logic
- Return early on FORGED status (security priority)

## Dependencies & Versions
- Flask, Flask-WTF, Flasgger (API docs), cryptography, python-dotenv, werkzeug
- No requirements.txt present; maintain manually or generate from imports
