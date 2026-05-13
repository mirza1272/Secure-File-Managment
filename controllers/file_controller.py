"""
File Controller
Handles file upload, encryption, decryption with hashing and PKI
Uses local file-based storage
"""
import os
import time
from flask import flash, render_template, request, redirect, url_for, session
from models.aes_model import AESModel
from models.rsa_model import RSAModel
from models.hash_model import HashModel
from models.pki_model import PKIModel
from models.local_database import LocalDatabase

UPLOAD_FOLDER = "uploads"
ENCRYPTED_FOLDER = "encrypted"
PROCESSED_FOLDER = "processed"

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(ENCRYPTED_FOLDER, exist_ok=True)
os.makedirs(PROCESSED_FOLDER, exist_ok=True)

# Initialize models
rsa_model = RSAModel()
hash_model = HashModel()
pki_model = PKIModel()
db = LocalDatabase()

# Generate RSA keys for session
public_key, private_key = rsa_model.generate_keys()


def upload_and_encrypt():
    """
    Enhanced workflow with hashing:
    Upload -> Hash (SHA-256) -> Encrypt (AES) -> Encrypt AES Key (RSA) -> 
    Sign with Certificate -> Store
    """
    if "file" not in request.files:
        flash("No file uploaded", "error")
        return redirect(url_for("index"))

    file = request.files["file"]
    if file.filename == "":
        flash("No selected file", "error")
        return redirect(url_for("index"))

    # Get user ID from session (default to 0 for anonymous)
    user_id = session.get('user_id', 0)

    # Save uploaded file
    file_path = os.path.join(UPLOAD_FOLDER, file.filename)
    file.save(file_path)

    try:
        # Step 1: Generate SHA-256 hash of original file
        original_hash = hash_model.hash_file(file_path)

        # Step 2: Generate random AES key and encrypt file
        aes_key = os.urandom(32)
        aes_model = AESModel(key=aes_key)
        encrypted_data = aes_model.encrypt(file_path)

        # Step 3: Save encrypted file with timestamp
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        base_name, ext = os.path.splitext(file.filename)
        encrypted_filename = f"encrypted_{base_name}_{timestamp}{ext}"
        encrypted_file_path = os.path.join(ENCRYPTED_FOLDER, encrypted_filename)
        
        with open(encrypted_file_path, "wb") as enc_file:
            enc_file.write(encrypted_data)

        # Step 4: Encrypt AES key with RSA and save
        key_filename = f"{base_name}_{timestamp}_key.bin"
        encrypted_key_path = os.path.join(ENCRYPTED_FOLDER, key_filename)
        with open(encrypted_key_path, "wb") as key_file:
            key_file.write(rsa_model.encrypt_key(aes_key, public_key))

        # Step 5: Store hash for verification
        hash_filename = f"{base_name}_{timestamp}_hash.txt"
        hash_file_path = os.path.join(ENCRYPTED_FOLDER, hash_filename)
        with open(hash_file_path, "w") as hash_file:
            hash_file.write(original_hash)

        # Step 6: Digital signature (if user has certificate)
        signature = None
        certificate_id = None
        
        if user_id > 0:
            cert = db.get_active_certificate(user_id)
            if cert and cert.get('key_path') and os.path.exists(cert['key_path']):
                try:
                    signature = pki_model.sign_data(encrypted_data, cert['key_path'])
                    certificate_id = cert.get('id')
                    # Save signature
                    sig_filename = f"{base_name}_{timestamp}_sig.bin"
                    sig_path = os.path.join(ENCRYPTED_FOLDER, sig_filename)
                    with open(sig_path, "wb") as sig_file:
                        sig_file.write(signature)
                except Exception as e:
                    print(f"Signature error: {e}")

        # Step 7: Store file metadata in local database
        if user_id > 0:
            file_info = {
                'original_filename': file.filename,
                'encrypted_filename': encrypted_filename,
                'original_hash': original_hash,
                'encrypted_hash': hash_model.hash_data(encrypted_data),
                'file_size': os.path.getsize(file_path),
                'certificate_id': certificate_id
            }
            db.store_encrypted_file(user_id, file_info)
            db.log_action(user_id, 'ENCRYPT_FILE', 'file', None,
                         f"Encrypted file: {file.filename}", request.remote_addr)

        # Clean up original file
        try:
            os.remove(file_path)
        except:
            pass

        flash("File encrypted successfully!", "success")
        return render_template(
            "result.html",
            file_name=encrypted_filename,
            action="Encryption",
            key_file=key_filename,
            original_hash=original_hash,
            signed=certificate_id is not None,
            folder="encrypted"
        )

    except Exception as e:
        import traceback
        traceback.print_exc()
        flash(f"Encryption error: {e}", "error")
        return redirect(url_for("index"))


def download_and_decrypt():
    """
    Enhanced workflow with hash verification:
    Download -> Decrypt AES Key (RSA) -> Decrypt File (AES) -> 
    Verify Signature -> Verify Hash -> Download
    """
    if "file" not in request.files:
        flash("No file uploaded", "error")
        return redirect(url_for("index"))

    file = request.files["file"]
    if file.filename == "":
        flash("No selected file", "error")
        return redirect(url_for("index"))

    user_id = session.get('user_id', 0)

    # Save uploaded encrypted file
    file_path = os.path.join(UPLOAD_FOLDER, file.filename)
    file.save(file_path)

    # Parse filename to find associated files
    # Format: encrypted_{base_name}_{timestamp}.ext
    filename = file.filename
    if filename.startswith("encrypted_"):
        filename = filename[10:]  # Remove "encrypted_" prefix
    
    # Extract base name and timestamp
    base_name, ext = os.path.splitext(filename)
    parts = base_name.rsplit("_", 2)
    
    if len(parts) >= 3:
        original_base = "_".join(parts[:-2])
        timestamp = f"{parts[-2]}_{parts[-1]}"
    elif len(parts) == 2:
        original_base = parts[0]
        timestamp = parts[1]
    else:
        original_base = base_name
        timestamp = ""

    try:
        # Step 1: Find and load encrypted AES key
        key_file_path = None
        possible_key_names = [
            f"{original_base}_{timestamp}_key.bin" if timestamp else f"{original_base}_key.bin",
            f"{base_name}_key.bin",
        ]
        
        for key_name in possible_key_names:
            test_path = os.path.join(ENCRYPTED_FOLDER, key_name)
            if os.path.exists(test_path):
                key_file_path = test_path
                break
        
        if not key_file_path:
            available_keys = [f for f in os.listdir(ENCRYPTED_FOLDER) if f.endswith('_key.bin')]
            flash(f"Encrypted AES key not found. Available keys: {available_keys}", "error")
            return redirect(url_for("index"))

        with open(key_file_path, "rb") as key_file:
            encrypted_aes_key = key_file.read()

        # Step 2: Decrypt AES key with RSA
        decrypted_aes_key = rsa_model.decrypt_key(encrypted_aes_key, private_key)

        # Step 3: Load encrypted data
        with open(file_path, "rb") as enc_file:
            encrypted_data = enc_file.read()

        # Step 4: Verify digital signature (if exists)
        signature_valid = None
        possible_sig_names = [
            f"{original_base}_{timestamp}_sig.bin" if timestamp else f"{original_base}_sig.bin",
            f"{base_name}_sig.bin",
        ]
        
        for sig_name in possible_sig_names:
            sig_path = os.path.join(ENCRYPTED_FOLDER, sig_name)
            if os.path.exists(sig_path):
                try:
                    file_info = db.get_file_by_name(file.filename)
                    if file_info and file_info.get('certificate_id'):
                        cert = db.get_certificate_by_id(file_info['certificate_id'])
                        if cert and os.path.exists(cert['cert_path']):
                            with open(sig_path, "rb") as sig_file:
                                signature = sig_file.read()
                            signature_valid = pki_model.verify_signature(
                                encrypted_data, signature, cert['cert_path']
                            )
                except Exception as e:
                    print(f"Signature verification error: {e}")
                break

        # Step 5: Decrypt file with AES
        aes_model = AESModel(key=decrypted_aes_key)
        decrypted_data = aes_model.decrypt(encrypted_data)

        # Step 6: Verify hash
        hash_file_path = None
        possible_hash_names = [
            f"{original_base}_{timestamp}_hash.txt" if timestamp else f"{original_base}_hash.txt",
            f"{base_name}_hash.txt",
        ]
        
        for hash_name in possible_hash_names:
            test_path = os.path.join(ENCRYPTED_FOLDER, hash_name)
            if os.path.exists(test_path):
                hash_file_path = test_path
                break
        
        hash_valid = False
        original_hash = None
        if hash_file_path:
            with open(hash_file_path, "r") as hash_file:
                original_hash = hash_file.read().strip()
            hash_valid = hash_model.verify_hash(decrypted_data, original_hash)

        # Step 7: Save decrypted file
        decrypted_filename = f"decrypted_{original_base}{ext}"
        decrypted_file_path = os.path.join(PROCESSED_FOLDER, decrypted_filename)
        with open(decrypted_file_path, "wb") as dec_file:
            dec_file.write(decrypted_data)

        # Log action
        if user_id > 0:
            db.log_action(user_id, 'DECRYPT_FILE', 'file', None,
                         f"Decrypted file: {file.filename}", request.remote_addr)

        # Clean up uploaded file
        try:
            os.remove(file_path)
        except:
            pass

        if hash_valid:
            flash("File decrypted and integrity verified successfully!", "success")
        else:
            flash("File decrypted but hash verification failed - file may be corrupted!", "warning")

        return render_template(
            "result.html",
            file_name=decrypted_filename,
            action="Decryption",
            hash_valid=hash_valid,
            original_hash=original_hash,
            signature_valid=signature_valid,
            folder="processed"
        )

    except Exception as e:
        import traceback
        traceback.print_exc()
        flash(f"Decryption error: {e}", "error")
        return redirect(url_for("index"))
