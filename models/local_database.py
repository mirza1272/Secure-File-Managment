"""
Local File-Based Database
Stores all data in JSON files in the 'data' folder - NO MySQL required
"""
import os
import json
import hashlib
from datetime import datetime
from pathlib import Path


class LocalDatabase:
    def __init__(self):
        self.data_dir = Path("data")
        self.users_file = self.data_dir / "users.json"
        self.certificates_file = self.data_dir / "certificates.json"
        self.files_file = self.data_dir / "files.json"
        self.audit_file = self.data_dir / "audit_log.json"
        self.ca_info_file = self.data_dir / "ca_info.json"
        
        # Initialize data directory and files
        self._initialize()
    
    def _initialize(self):
        """Create data directory and initialize empty JSON files if they don't exist"""
        self.data_dir.mkdir(exist_ok=True)
        
        # Initialize each file if it doesn't exist
        for file_path in [self.users_file, self.certificates_file, 
                         self.files_file, self.audit_file, self.ca_info_file]:
            if not file_path.exists():
                self._write_json(file_path, [])
    
    def _read_json(self, file_path: Path) -> list:
        """Read JSON file and return data"""
        try:
            if file_path.exists():
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read().strip()
                    if content:
                        return json.loads(content)
            return []
        except (json.JSONDecodeError, Exception) as e:
            print(f"Error reading {file_path}: {e}")
            return []
    
    def _write_json(self, file_path: Path, data):
        """Write data to JSON file"""
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, default=str)
        except Exception as e:
            print(f"Error writing {file_path}: {e}")
    
    def _generate_id(self, data: list) -> int:
        """Generate next ID for a list of records"""
        if not data:
            return 1
        return max(item.get('id', 0) for item in data) + 1

    # ==================== USER OPERATIONS ====================

    def create_user(self, email: str, name: str, password_hash: str) -> int:
        """Create a new user and return user ID"""
        users = self._read_json(self.users_file)
        
        # Check if user already exists
        for user in users:
            if user['email'] == email:
                return None  # User already exists
        
        user_id = self._generate_id(users)
        new_user = {
            'id': user_id,
            'email': email,
            'name': name,
            'password_hash': password_hash,
            'created_at': datetime.now().isoformat(),
            'updated_at': datetime.now().isoformat()
        }
        
        users.append(new_user)
        self._write_json(self.users_file, users)
        return user_id

    def get_user_by_email(self, email: str) -> dict:
        """Get user by email"""
        users = self._read_json(self.users_file)
        for user in users:
            if user['email'] == email:
                return user
        return None

    def get_user_by_id(self, user_id: int) -> dict:
        """Get user by ID"""
        users = self._read_json(self.users_file)
        for user in users:
            if user['id'] == user_id:
                return user
        return None
    
    def verify_password(self, user_id: int, password: str) -> bool:
        """Verify user password"""
        user = self.get_user_by_id(user_id)
        if not user:
            return False
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        return user['password_hash'] == password_hash

    # ==================== CERTIFICATE OPERATIONS ====================

    def store_certificate(self, user_id: int, cert_info: dict) -> int:
        """Store certificate information"""
        certs = self._read_json(self.certificates_file)
        
        cert_id = self._generate_id(certs)
        new_cert = {
            'id': cert_id,
            'user_id': user_id,
            'serial_number': cert_info.get('serial_number', ''),
            'fingerprint': cert_info.get('fingerprint', ''),
            'subject': cert_info.get('subject', ''),
            'issuer': cert_info.get('issuer', 'SecureFile CA'),
            'not_valid_before': cert_info.get('not_valid_before', ''),
            'not_valid_after': cert_info.get('not_valid_after', ''),
            'cert_path': cert_info.get('cert_path', ''),
            'key_path': cert_info.get('key_path', ''),
            'public_key_path': cert_info.get('public_key_path', ''),
            'status': 'active',
            'created_at': datetime.now().isoformat()
        }
        
        certs.append(new_cert)
        self._write_json(self.certificates_file, certs)
        return cert_id

    def get_user_certificates(self, user_id: int) -> list:
        """Get all certificates for a user"""
        certs = self._read_json(self.certificates_file)
        user_certs = [c for c in certs if c['user_id'] == user_id]
        # Sort by created_at descending
        user_certs.sort(key=lambda x: x.get('created_at', ''), reverse=True)
        return user_certs

    def get_certificate_by_id(self, cert_id: int) -> dict:
        """Get certificate by ID"""
        certs = self._read_json(self.certificates_file)
        for cert in certs:
            if cert['id'] == cert_id:
                return cert
        return None

    def get_active_certificate(self, user_id: int) -> dict:
        """Get user's active certificate"""
        certs = self.get_user_certificates(user_id)
        for cert in certs:
            if cert.get('status') == 'active':
                return cert
        return None

    # ==================== CA OPERATIONS ====================

    def store_ca_info(self, ca_info: dict):
        """Store CA certificate information"""
        self._write_json(self.ca_info_file, ca_info)

    def get_ca_info(self) -> dict:
        """Get CA certificate information"""
        data = self._read_json(self.ca_info_file)
        if isinstance(data, list):
            return data[0] if data else {}
        return data if data else {}

    # ==================== FILE OPERATIONS ====================

    def store_encrypted_file(self, user_id: int, file_info: dict) -> int:
        """Store encrypted file metadata"""
        files = self._read_json(self.files_file)
        
        file_id = self._generate_id(files)
        new_file = {
            'id': file_id,
            'user_id': user_id,
            'original_filename': file_info.get('original_filename', ''),
            'encrypted_filename': file_info.get('encrypted_filename', ''),
            'original_hash': file_info.get('original_hash', ''),
            'encrypted_hash': file_info.get('encrypted_hash', ''),
            'file_size': file_info.get('file_size', 0),
            'certificate_id': file_info.get('certificate_id'),
            'created_at': datetime.now().isoformat()
        }
        
        files.append(new_file)
        self._write_json(self.files_file, files)
        return file_id

    def get_user_files(self, user_id: int) -> list:
        """Get all encrypted files for a user"""
        files = self._read_json(self.files_file)
        user_files = [f for f in files if f['user_id'] == user_id]
        user_files.sort(key=lambda x: x.get('created_at', ''), reverse=True)
        return user_files

    def get_file_by_name(self, encrypted_filename: str) -> dict:
        """Get file info by encrypted filename"""
        files = self._read_json(self.files_file)
        for f in files:
            if f['encrypted_filename'] == encrypted_filename:
                return f
        return None

    # ==================== AUDIT OPERATIONS ====================

    def log_action(self, user_id: int, action: str, resource_type: str = None,
                   resource_id: int = None, details: str = None, ip_address: str = None):
        """Log an action for audit trail"""
        logs = self._read_json(self.audit_file)
        
        log_entry = {
            'id': self._generate_id(logs),
            'user_id': user_id,
            'action': action,
            'resource_type': resource_type,
            'resource_id': resource_id,
            'details': details,
            'ip_address': ip_address,
            'created_at': datetime.now().isoformat()
        }
        
        logs.append(log_entry)
        self._write_json(self.audit_file, logs)

    def get_audit_log(self, user_id: int = None, limit: int = 100) -> list:
        """Get audit log entries"""
        logs = self._read_json(self.audit_file)
        
        if user_id:
            logs = [l for l in logs if l.get('user_id') == user_id]
        
        # Sort by created_at descending and limit
        logs.sort(key=lambda x: x.get('created_at', ''), reverse=True)
        return logs[:limit]
