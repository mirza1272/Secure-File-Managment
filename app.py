"""
Secure File Management System
Main Flask Application with AES, RSA, SHA-256 Hashing, and PKI
Uses local file-based storage (JSON files in 'data' folder)
"""
import os
from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory, session
from controllers.file_controller import upload_and_encrypt, download_and_decrypt
from controllers.pki_controller import (
    register_user, login_user, logout_user, dashboard,
    view_certificate, view_public_key, view_ca_certificate, audit_log
)

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'your_super_secret_key_change_in_production')

UPLOAD_FOLDER = "uploads"
ENCRYPTED_FOLDER = "encrypted"
PROCESSED_FOLDER = "processed"

# Ensure folders exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(ENCRYPTED_FOLDER, exist_ok=True)
os.makedirs(PROCESSED_FOLDER, exist_ok=True)
os.makedirs("data", exist_ok=True)
os.makedirs("certs", exist_ok=True)


# ==================== MAIN ROUTES ====================

@app.route("/")
def index():
    """Home page - redirect to login if not logged in"""
    if 'user_id' not in session:
        return redirect(url_for("login"))
    return render_template("index.html")


@app.route("/upload", methods=["POST"])
def upload_file():
    """Handle file upload - encryption or decryption"""
    if 'user_id' not in session:
        flash("Please login first", "error")
        return redirect(url_for("login"))
    
    action = request.form.get("action")
    if action == "encrypt":
        return upload_and_encrypt()
    elif action == "decrypt":
        return download_and_decrypt()
    else:
        flash("Invalid action", "error")
        return redirect(url_for("index"))


@app.route("/download/<filename>")
def download_file(filename):
    """Download encrypted or decrypted file"""
    # Get absolute paths
    encrypted_path = os.path.abspath(ENCRYPTED_FOLDER)
    processed_path = os.path.abspath(PROCESSED_FOLDER)
    
    # Check in encrypted folder first
    encrypted_file = os.path.join(encrypted_path, filename)
    if os.path.exists(encrypted_file) and os.path.isfile(encrypted_file):
        return send_from_directory(
            encrypted_path, 
            filename, 
            as_attachment=True,
            download_name=filename
        )
    
    # Check in processed folder
    processed_file = os.path.join(processed_path, filename)
    if os.path.exists(processed_file) and os.path.isfile(processed_file):
        return send_from_directory(
            processed_path, 
            filename, 
            as_attachment=True,
            download_name=filename
        )
    
    flash(f"File not found: {filename}", "error")
    return redirect(url_for("index"))


# ==================== AUTH ROUTES ====================

@app.route("/register", methods=["GET", "POST"])
def register():
    """User registration"""
    if 'user_id' in session:
        return redirect(url_for("user_dashboard"))
    return register_user()


@app.route("/login", methods=["GET", "POST"])
def login():
    """User login"""
    if 'user_id' in session:
        return redirect(url_for("user_dashboard"))
    return login_user()


@app.route("/logout")
def logout():
    """User logout"""
    return logout_user()


# ==================== DASHBOARD ROUTES ====================

@app.route("/dashboard")
def user_dashboard():
    """User dashboard"""
    return dashboard()


@app.route("/certificate/<int:cert_id>")
def certificate_detail(cert_id):
    """View certificate details"""
    return view_certificate(cert_id)


@app.route("/view-public-key", methods=["GET", "POST"])
def view_public_key_page():
    """View public key (requires password verification)"""
    return view_public_key()


@app.route("/ca-certificate")
def ca_certificate():
    """View CA certificate"""
    return view_ca_certificate()


@app.route("/audit-log")
def view_audit_log():
    """View audit log"""
    return audit_log()


# ==================== ERROR HANDLERS ====================

@app.errorhandler(404)
def not_found(e):
    return render_template("error.html", error="Page not found"), 404


@app.errorhandler(500)
def server_error(e):
    return render_template("error.html", error="Internal server error"), 500


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
