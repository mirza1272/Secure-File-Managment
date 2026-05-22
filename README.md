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

2. **Create virtual environment inside project folder**
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
# Secure File Management System

A Flask-based secure file management system that provides strong file confidentiality, integrity, and non-repudiation. The project uses AES-256 for file encryption, RSA for key wrapping and signatures, SHA-256 for hashing, and a simple JSON-backed local datastore for metadata (no external RDBMS required).

## Features

- **AES-256 Encryption**: Symmetric encryption for file data
- **RSA Key Wrapping & Signatures**: Protect AES keys and sign files
- **SHA-256 Hashing**: Integrity verification for stored files
- **PKI (Public Key Infrastructure)**:
  - Local Certificate Authority (CA) and user X.509 certificates
  - Digital signatures for files
  - Certificate revocation support
  - Audit logging
- **JSON-backed Local Database**: User, certificate, file metadata and audit logs are stored as JSON files in `data/` (no MySQL required)

## Security Workflow

### Encryption Flow
```
Upload → SHA-256 Hash → AES Encrypt → RSA Wrap Key → Digital Sign → Store
```

### Decryption Flow
```
Load → RSA Unwrap Key → AES Decrypt → Verify Signature → Verify Hash → Download
```

## Installation & Run (Local, JSON DB)

1. Clone the repository
```
git clone <repository-url>
cd secure-file-management
```

2. Create and activate a virtual environment

Windows (PowerShell / cmd):
```powershell
python -m venv venv
venv\Scripts\Activate.ps1    # PowerShell
venv\Scripts\activate.bat     # cmd
```

Linux / macOS:
```bash
python -m venv venv
source venv/bin/activate
```

3. Install dependencies
```bash
pip install -r requirements.txt
```

4. Run the application
```bash
python app.py
```

5. Open the app in your browser:

http://localhost:5000

Note: This repository was converted to use JSON files under the `data/` folder (for example `data/users.json`, `data/certificates.json`, `data/files.json`, and `data/audit_log.json`). No MySQL server is required for normal operation.

## Project Structure

```
secure-file-management/
├── app.py                    # Main Flask application
├── requirements.txt          # Python dependencies
├── models/
│   ├── __init__.py
│   ├── aes_model.py          # AES encryption/decryption
│   ├── rsa_model.py          # RSA key operations
│   ├── hash_model.py         # SHA-256 hash functions
│   ├── pki_model.py          # PKI/Certificate operations
│   └── local_database.py     # JSON-backed local datastore operations
├── controllers/
│   ├── __init__.py
│   ├── file_controller.py    # File encryption/decryption logic
│   └── pki_controller.py     # User/Certificate management
├── templates/                # HTML templates
├── uploads/                  # Uploaded files (temporary)
├── encrypted/                # Encrypted files + keys + hashes
├── processed/                # Decrypted files
├── certs/                    # CA and user certificates
├── data/                     # JSON files used as local DB
└── scripts/                  # Misc scripts (some SQL scripts are included but not required)
```

## Usage Notes

- Basic mode (no external DB): the app uses `data/*.json` as its datastore. PKI features (certificate generation, signatures) work with the files in `certs/`.
- If you previously used MySQL, note that this repository now uses JSON files for storage; any MySQL-specific scripts are optional and not required for normal operation.

## Environment Variables

| Variable   | Default                     | Description                  |
|------------|-----------------------------|------------------------------|
| SECRET_KEY | your_super_secret_key       | Flask session secret         |
| PORT       | 5000                        | Port the app will bind to    |

## Troubleshooting

- Ensure `data/` and `certs/` directories exist and are writable by the app.
- If you see issues with certificates or keys, check the `certs/` folder and `data/certificates.json` for malformed entries.


## Author

Haseeb ur Rahman

## License

MIT License
