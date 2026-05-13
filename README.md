# Secure File Management System

A Flask-based secure file management system with AES-256 encryption, RSA key wrapping, SHA-256 hashing, and PKI (Public Key Infrastructure).

## Features

- **AES-256 Encryption**: Military-grade symmetric encryption for file data
- **RSA-2048 Key Wrapping**: Asymmetric encryption to protect AES keys
- **SHA-256 Hashing**: Cryptographic hash for file integrity verification
- **PKI (Public Key Infrastructure)**:
  - Self-signed Certificate Authority (CA)
  - User X.509 certificates
  - Digital signatures for files
  - Certificate revocation support
  - Audit logging

## Security Workflow

### Encryption Flow
\`\`\`
Upload → SHA-256 Hash → AES Encrypt → RSA Wrap Key → Digital Sign → Store
\`\`\`

### Decryption Flow
\`\`\`
Load → RSA Unwrap Key → AES Decrypt → Verify Signature → Verify Hash → Download
\`\`\`

## Installation

1. **Clone the repository**
\`\`\`bash
git clone <repository-url>
cd secure-file-management
\`\`\`

2. **Create virtual environment**
\`\`\`bash
python -m venv venv
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows
\`\`\`

3. **Install dependencies**
\`\`\`bash
pip install -r requirements.txt
\`\`\`

4. **Setup MySQL Database** (Optional - works without database for basic encryption)
\`\`\`bash
# Create the database
mysql -u root -p < scripts/create_database.sql

# Set environment variables
export MYSQL_HOST=localhost
export MYSQL_DATABASE=secure_file_db
export MYSQL_USER=root
export MYSQL_PASSWORD=your_password
\`\`\`

5. **Run the application**
\`\`\`bash
python app.py
\`\`\`

6. **Access the application**
Open your browser and go to: http://localhost:5000

## Project Structure

\`\`\`
secure-file-management/
├── app.py                    # Main Flask application
├── requirements.txt          # Python dependencies
├── models/
│   ├── __init__.py
│   ├── aes_model.py         # AES encryption/decryption
│   ├── rsa_model.py         # RSA key operations
│   ├── hash_model.py        # SHA-256 hashing
│   ├── pki_model.py         # PKI/Certificate operations
│   └── database.py          # MySQL database operations
├── controllers/
│   ├── __init__.py
│   ├── file_controller.py   # File encryption/decryption logic
│   └── pki_controller.py    # User/Certificate management
├── templates/               # HTML templates
├── uploads/                 # Uploaded files (temporary)
├── encrypted/               # Encrypted files + keys + hashes
├── processed/               # Decrypted files
├── certs/                   # CA and user certificates
└── scripts/
    └── create_database.sql  # Database schema
\`\`\`

## Usage

### Without Database (Basic Mode)
The system works without MySQL for basic encryption/decryption. PKI features will be limited.

### With Database (Full Mode)
1. Register a user account (generates X.509 certificate)
2. Login to access dashboard
3. Upload files for encryption (automatically signed if you have a certificate)
4. Download encrypted files
5. Upload encrypted files for decryption (signature and hash verified)

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| SECRET_KEY | your_super_secret_key | Flask session secret |
| MYSQL_HOST | localhost | MySQL server host |
| MYSQL_DATABASE | secure_file_db | Database name |
| MYSQL_USER | root | MySQL username |
| MYSQL_PASSWORD | (empty) | MySQL password |
| MYSQL_PORT | 3306 | MySQL port |

## License

MIT License
