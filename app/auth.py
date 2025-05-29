from flask import Blueprint, request, jsonify, session, g, current_app
from .models import db, User, UserKeys, Nonce
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.exceptions import InvalidSignature
import json
import time
from datetime import datetime, timedelta, timezone
import secrets
import os

NONCE_LIFESPAN = int(os.getenv('NONCE_LIFESPAN', 300)) 
TIMESTAMP_TOLERANCE = int(os.getenv('TIMESTAMP_TOLERANCE', 10)) 

auth_bp = Blueprint('auth', __name__)

def cleanup_old_nonces():
    """Remove nonces older than NONCE_LIFESPAN seconds"""
    cutoff_time = datetime.now() - timedelta(seconds=NONCE_LIFESPAN)
    Nonce.query.filter(Nonce.timestamp < cutoff_time).delete()
    db.session.commit()

def verify_request_auth():
    """Verify the authentication of a request by checking nonce and signature.
    Reads authentication data from headers.
    Returns (success, user, error_message, status_code) tuple."""
    
    # Get authentication data from headers
    user_id = request.headers.get('X-User-ID')
    nonce = request.headers.get('X-Nonce')
    signature_hex = request.headers.get('X-Signature')

    if not user_id or not nonce or not signature_hex:
        return False, None, 'Authentication required: Missing X-User-ID, X-Nonce, or X-Signature headers', 401

    # Get the request payload for signature verification
    payload = request.get_data()
    if not payload:
        return False, None, 'Authentication failed: Request payload is required for signature verification', 401

    # Verify the nonce
    db_nonce = Nonce.query.filter_by(username=user_id, nonce=nonce, used=False).first()
    if not db_nonce:
        return False, None, 'Authentication failed: Invalid or expired nonce', 401

    # Check if nonce is within the acceptable freshness window
    current_time_utc = datetime.now(timezone.utc)
    time_difference = abs((current_time_utc - db_nonce.timestamp).total_seconds())

    if time_difference > TIMESTAMP_TOLERANCE or (current_time_utc - db_nonce.timestamp).total_seconds() > NONCE_LIFESPAN + TIMESTAMP_TOLERANCE:
        # Mark nonce as used if it's outside the freshness window or overall lifespan
        db_nonce.used = True
        db.session.commit()
        return False, None, 'Authentication failed: Nonce expired or outside freshness window', 401

    # Verify the signature
    try:
        signature = bytes.fromhex(signature_hex)
    except ValueError:
        # Mark nonce as used and reject if signature format is invalid
        db_nonce.used = True
        db.session.commit()
        return False, None, 'Authentication failed: Invalid signature format', 401

    # Verify the signature using the request payload
    if not verify_signature_authorization(user_id, payload, signature):
        # Mark nonce as used and reject
        db_nonce.used = True
        db.session.commit()
        return False, None, 'Authentication failed: Invalid signature', 401

    # Mark nonce as used
    db_nonce.used = True
    db.session.commit()

    # Fetch the user
    user = User.query.filter_by(username=user_id).first()
    if not user:
        current_app.logger.error(f"Anomaly: Signature valid for user {user_id} but user not found in DB.")
        return False, None, 'Authentication failed: User data inconsistency', 500

    return True, user, None, None

def login_required(f):
    def decorated_function(*args, **kwargs):
        success, user, error_message, status_code = verify_request_auth()
        if not success:
            return jsonify({'error': error_message}), status_code

        g.user = user
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function

def verify_signature_authorization(username, payload, signature):
    """Verify the signature of a request payload.
    Args:
        username: The username of the user
        payload: The raw request payload (bytes)
        signature: The signature to verify (bytes)
    Returns:
        bool: True if signature is valid, False otherwise
    """
    user = User.query.filter_by(username=username).first()
    if not user or not user.keys or not user.keys.identity_key_public:
        return False

    try:
        public_key = serialization.load_public_key(
            user.keys.identity_key_public,
            backend=None
        )
        
        public_key.verify(
            signature,
            payload,
            padding.PSS(
                mgf=padding.MGF1(SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            SHA256()
        )
        return True
    except InvalidSignature:
        return False
    except Exception as e:
        current_app.logger.error(f"Error during signature verification: {e}")
        return False

@auth_bp.route('/register', methods=['POST'])
def register():
    """Expected JSON input body structure:
    {
        "username": str,
        "email": str,
        "identity_key_public": str,
        "signed_prekey_public": str,
        "signed_prekey_signature": str,
        "opks": dict (may not use these)
    }
    """
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    identity_key = data.get('identity_key_public')
    signed_prekey = data.get('signed_prekey_public')
    opks = data.get('opks')

    if not username or not email or not identity_key or not signed_prekey:
        return jsonify({'error': 'Missing required fields (username, email, identity_key, signed_prekey)'}), 400

    existing_user = User.query.filter((User.username == username) | (User.email == email)).first()
    if existing_user:
        if existing_user.username == username:
            return jsonify({'error': 'Username already exists'}), 400
        else:
            return jsonify({'error': 'Email already exists'}), 400

    # Password is not stored, authentication is key-based
    new_user = User(username=username, email=email)
    db.session.add(new_user)
    db.session.commit()

    try:
        identity_key_bytes = bytes.fromhex(identity_key) if isinstance(identity_key, str) else identity_key
        signed_prekey_bytes = bytes.fromhex(signed_prekey) if isinstance(signed_prekey, str) else signed_prekey
    except ValueError:
        # Clean up the user if key format is invalid after user creation
        db.session.delete(new_user)
        db.session.commit()
        return jsonify({'error': 'Invalid key format (expected hex string or bytes)'}), 400

    new_user_keys = UserKeys(
        user_id=new_user.id,
        identity_key=identity_key_bytes,
        signed_prekey=signed_prekey_bytes,
        opks=opks
    )
    db.session.add(new_user_keys)
    db.session.commit()

    return jsonify({'message': 'User and keys registered successfully'}), 201

@auth_bp.route('/login', methods=['POST'])
def login():
    # Authenticate user using signature verification and nonce validation
    success, user, error_message, status_code = verify_request_auth()
    if not success:
        return jsonify({'error': error_message}), status_code

    # Set session for browser-based authentication
    session['username'] = user.username # NOTE dont think we should be using session as this is a rest API
    # Dont even think we need a login endpoint, as the client should be able to authenticate with the signature and nonce
    return jsonify({'message': 'Authentication successful'}), 200

@auth_bp.route('/logout', methods=['POST'])
def logout():
    # see login() comments
    session.pop('username', None)
    return jsonify({'message': 'Logged out successfully'}), 200

@auth_bp.route('/nonce', methods=['POST'])
def get_nonce():
    """Generate a new nonce for a user"""
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Request body missing'}), 400

    # this should be a user id not username
    user_id = data.get('user_id')
    if not user_id:
        return jsonify({'error': 'User ID required'}), 400

    user = User.query.filter_by(user_id=user_id).first()
    if not user:
        return jsonify({'error': 'User not found'}), 404

    nonce = secrets.token_hex(32) 
    
    new_nonce = Nonce(
        user_id=user_id,
        nonce=nonce,
    )
    db.session.add(new_nonce)
    db.session.commit()
    
    return jsonify({
        'nonce': nonce,
    }), 200 