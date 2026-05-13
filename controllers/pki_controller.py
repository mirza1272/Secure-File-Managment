"""
PKI Controller
Handles certificate management, user registration, login, and PKI operations
Uses local file-based storage instead of MySQL
"""
import os
import hashlib
from flask import flash, render_template, request, redirect, url_for, session
from models.pki_model import PKIModel
from models.local_database import LocalDatabase

pki_model = PKIModel()
db = LocalDatabase()


def register_user():
    """Register a new user and generate their X.509 certificate"""
    if request.method == "POST":
        email = request.form.get("email", "").strip()
        name = request.form.get("name", "").strip()
        password = request.form.get("password", "")
        organization = request.form.get("organization", "SecureFile User").strip()

        # Validation
        if not all([email, name, password]):
            flash("All fields are required", "error")
            return redirect(url_for("register"))
        
        if len(password) < 6:
            flash("Password must be at least 6 characters", "error")
            return redirect(url_for("register"))

        # Check if user exists
        existing_user = db.get_user_by_email(email)
        if existing_user:
            flash("User with this email already exists", "error")
            return redirect(url_for("register"))

        # Hash password with SHA-256
        password_hash = hashlib.sha256(password.encode()).hexdigest()

        # Create user
        user_id = db.create_user(email, name, password_hash)
        if not user_id:
            flash("Failed to create user account", "error")
            return redirect(url_for("register"))

        try:
            # Generate X.509 certificate for user (signed by CA)
            cert_info = pki_model.generate_user_certificate(
                user_id=user_id,
                email=email,
                common_name=name,
                organization=organization
            )

            # Store certificate info in local database
            db.store_certificate(user_id, cert_info)
            
            # Log the registration
            db.log_action(user_id, 'USER_REGISTERED', 'user', user_id,
                         f"User registered: {email}", request.remote_addr)
            db.log_action(user_id, 'CERT_GENERATED', 'certificate', None,
                         f"X.509 certificate generated for: {email}", request.remote_addr)

            # Store CA info if not already stored
            ca_info = pki_model.get_ca_info()
            db.store_ca_info(ca_info)

            flash("Registration successful! Your X.509 certificate has been generated.", "success")
            
            return render_template(
                "registration_success.html",
                user_name=name,
                email=email,
                cert_info=cert_info,
                ca_info=ca_info
            )
            
        except Exception as e:
            flash(f"Certificate generation error: {e}", "error")
            return redirect(url_for("register"))

    return render_template("register.html")


def login_user():
    """User login"""
    if request.method == "POST":
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")

        if not all([email, password]):
            flash("Email and password are required", "error")
            return redirect(url_for("login"))

        # Get user from local database
        user = db.get_user_by_email(email)
        if not user:
            flash("Invalid email or password", "error")
            return redirect(url_for("login"))

        # Verify password
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        if user['password_hash'] != password_hash:
            flash("Invalid email or password", "error")
            return redirect(url_for("login"))

        # Set session
        session['user_id'] = user['id']
        session['user_email'] = user['email']
        session['user_name'] = user['name']

        # Log the login
        db.log_action(user['id'], 'USER_LOGIN', 'user', user['id'],
                     f"User logged in: {email}", request.remote_addr)

        flash(f"Welcome back, {user['name']}!", "success")
        return redirect(url_for("user_dashboard"))

    return render_template("login.html")


def logout_user():
    """User logout"""
    user_id = session.get('user_id')
    if user_id:
        db.log_action(user_id, 'USER_LOGOUT', 'user', user_id,
                     "User logged out", request.remote_addr)
    session.clear()
    flash("You have been logged out", "info")
    return redirect(url_for("login"))


def dashboard():
    """User dashboard - shows certificates and encrypted files"""
    if 'user_id' not in session:
        flash("Please login first", "error")
        return redirect(url_for("login"))

    user_id = session['user_id']
    
    # Get user info
    user = db.get_user_by_id(user_id)
    if not user:
        user = {
            'id': user_id,
            'name': session.get('user_name', 'User'),
            'email': session.get('user_email', 'N/A')
        }
    
    # Get user's certificates
    certificates = db.get_user_certificates(user_id)
    
    # Get user's encrypted files
    files = db.get_user_files(user_id)
    
    # Get CA info
    ca_info = db.get_ca_info()

    return render_template(
        "dashboard.html",
        user=user,
        certificates=certificates,
        files=files,
        ca_info=ca_info
    )


def view_certificate(cert_id):
    """View certificate details"""
    if 'user_id' not in session:
        flash("Please login first", "error")
        return redirect(url_for("login"))

    cert = db.get_certificate_by_id(cert_id)
    if not cert:
        flash("Certificate not found", "error")
        return redirect(url_for("user_dashboard"))
    
    # Ensure user owns this certificate
    if cert['user_id'] != session['user_id']:
        flash("Access denied", "error")
        return redirect(url_for("user_dashboard"))

    # Get detailed info from PKI model
    cert_details = None
    verification = None
    
    if os.path.exists(cert['cert_path']):
        cert_details = pki_model.get_certificate_info(cert['cert_path'])
        verification = pki_model.verify_certificate(cert['cert_path'])

    return render_template(
        "certificate_detail.html",
        cert=cert,
        cert_details=cert_details,
        verification=verification
    )


def view_public_key():
    """View public key - requires password verification"""
    if 'user_id' not in session:
        flash("Please login first", "error")
        return redirect(url_for("login"))

    user_id = session['user_id']

    if request.method == "POST":
        password = request.form.get("password", "")
        
        # Verify password
        if not db.verify_password(user_id, password):
            flash("Invalid password", "error")
            return redirect(url_for("view_public_key_page"))
        
        # Get active certificate
        cert = db.get_active_certificate(user_id)
        if not cert:
            flash("No active certificate found", "error")
            return redirect(url_for("user_dashboard"))
        
        # Get public key content
        public_key_content = None
        if cert.get('public_key_path') and os.path.exists(cert['public_key_path']):
            public_key_content = pki_model.get_public_key(cert['public_key_path'])
        
        # Also get certificate content
        cert_content = None
        if cert.get('cert_path') and os.path.exists(cert['cert_path']):
            with open(cert['cert_path'], 'r') as f:
                cert_content = f.read()
        
        # Log the action
        db.log_action(user_id, 'VIEW_PUBLIC_KEY', 'certificate', cert.get('id'),
                     "User viewed public key", request.remote_addr)

        return render_template(
            "view_public_key.html",
            cert=cert,
            public_key_content=public_key_content,
            cert_content=cert_content,
            verified=True
        )
    
    # GET request - show password form
    return render_template("verify_password_for_key.html")


def view_ca_certificate():
    """View the CA certificate"""
    try:
        ca_info = pki_model.get_ca_info()
        
        # Get CA certificate content
        ca_cert_content = None
        if os.path.exists(pki_model.ca_cert_path):
            with open(pki_model.ca_cert_path, 'r') as f:
                ca_cert_content = f.read()
        
        # Get CA public key content
        ca_public_key_content = None
        if os.path.exists(pki_model.ca_public_key_path):
            with open(pki_model.ca_public_key_path, 'r') as f:
                ca_public_key_content = f.read()
        
        return render_template(
            "ca_certificate.html",
            ca_info=ca_info,
            ca_cert_content=ca_cert_content,
            ca_public_key_content=ca_public_key_content
        )
    except Exception as e:
        flash(f"Error loading CA certificate: {e}", "error")
        return redirect(url_for("index"))


def audit_log():
    """View audit log"""
    if 'user_id' not in session:
        flash("Please login first", "error")
        return redirect(url_for("login"))

    user_id = session['user_id']
    logs = db.get_audit_log(user_id=user_id, limit=50)

    return render_template("audit_log.html", logs=logs)
