from flask import Blueprint, request, jsonify, g, current_app
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
import base64
from .. import limiter

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
    user_uuid = request.headers.get('X-User-UUID')
    nonce = request.headers.get('X-Nonce')
    signature_hex = request.headers.get('X-Signature')

    if not user_uuid or not nonce or not signature_hex:
        return False, None, 'Authentication required: Missing X-User-UUID, X-Nonce, or X-Signature headers', 401

    # Get the request payload for signature verification
    payload = request.get_data()
    if not payload:
        return False, None, 'Authentication failed: Request payload is required for signature verification', 401

    # Verify the nonce
    db_nonce = Nonce.query.filter_by(user_uuid=user_uuid, nonce=nonce, used=False).first()
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
    if not verify_signature_authorization(user_uuid, payload, signature):
        # Mark nonce as used and reject
        db_nonce.used = True
        db.session.commit()
        return False, None, 'Authentication failed: Invalid signature', 401

    # Mark nonce as used
    db_nonce.used = True
    db.session.commit()

    # Fetch the user
    user = User.query.filter_by(uuid=user_uuid).first()
    if not user:
        current_app.logger.error(f"Anomaly: Signature valid for user {user_uuid} but user not found in DB.")
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

def verify_signature_authorization(user_uuid, payload, signature):
    """Verify the signature of a request payload.
    Args:
        user_uuid: The UUID of the user
        payload: The raw request payload (bytes)
        signature: The signature to verify (bytes)
    Returns:
        bool: True if signature is valid, False otherwise
    """
    user = User.query.filter_by(uuid=user_uuid).first()
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
@limiter.limit("5 per minute")
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
    Returns:
    {
        "message": "User and keys registered successfully",
        "user_uuid": "generated UUID"
    }
    """
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    salt = data.get('salt') 
    identity_key = data.get('identity_key_public')
    signed_prekey = data.get('signed_prekey_public')
    signed_prekey_signature = data.get('signed_prekey_signature')
    opks = data.get('opks')

    if not username or not email or not identity_key or not signed_prekey:
        return jsonify({'error': 'Missing required fields (username, email, identity_key, signed_prekey)'}), 400

    existing_user = User.query.filter((User.username == username) | (User.email == email)).first()
    if existing_user:
        if existing_user.username == username:
            return jsonify({'error': 'Username already exists'}), 400
        else:
            return jsonify({'error': 'Email already exists'}), 400

    # Create new user with UUID
    new_user = User(username=username, email=email, salt=salt)
    db.session.add(new_user)
    db.session.commit()

    try:
        identity_key_bytes = base64.b64decode(identity_key) if isinstance(identity_key, str) else identity_key
        signed_prekey_bytes = base64.b64decode(signed_prekey) if isinstance(signed_prekey, str) else signed_prekey
        signed_prekey_signature_bytes = base64.b64decode(signed_prekey_signature) if isinstance(signed_prekey_signature, str) else signed_prekey_signature
    except (ValueError, base64.binascii.Error):
        # Clean up the user if key format is invalid after user creation
        db.session.delete(new_user)
        db.session.commit()
        return jsonify({'error': 'Invalid key format (expected base64 string or bytes)'}), 400

    new_user_keys = UserKeys(
        user_id=new_user.id,
        identity_key_public=identity_key_bytes,
        signed_prekey_public=signed_prekey_bytes,
        signed_prekey_signature=signed_prekey_signature_bytes,
        opks=opks
    )
    db.session.add(new_user_keys)
    db.session.commit()

    return jsonify({
        'message': 'User and keys registered successfully',
        'user_uuid': new_user.uuid
    }), 201

@auth_bp.route('/login', methods=['POST'])
@limiter.limit("5 per minute")
def login():
    # Authenticate user using signature verification and nonce validation
    success, user, error_message, status_code = verify_request_auth()
    if not success:
        return jsonify({'error': error_message}), status_code

    return jsonify({
        'message': 'Authentication successful',
        'user_uuid': user.uuid
    }), 200

@auth_bp.route('/nonce', methods=['POST'])
@limiter.limit("30 per minute")
def get_nonce():
    """Generate a new nonce for a user.
    Expected JSON input:
    {
        "user_uuid": "user's UUID"
    }
    Returns:
    {
        "nonce": "generated nonce",
        "timestamp": "ISO format timestamp"
    }
    """
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Request body missing'}), 400

    user_uuid = data.get('user_uuid')
    if not user_uuid:
        return jsonify({'error': 'User UUID required'}), 400

    user = User.query.filter_by(uuid=user_uuid).first()
    if not user:
        return jsonify({'error': 'User not found'}), 404

    nonce = secrets.token_hex(32)
    timestamp = datetime.now(timezone.utc)
    
    new_nonce = Nonce(
        user_uuid=user_uuid,
        nonce=nonce,
        timestamp=timestamp,
        used=False
    )
    db.session.add(new_nonce)
    db.session.commit()
    
    return jsonify({
        'nonce': nonce,
    }), 200

# @auth_bp.route('/user/<username>', methods=['GET'])
# @login_required
# def get_user_by_username(username):
#     """Get user information by username.
#     """
#     user = User.query.filter_by(username=username).first()
    
#     if not user:
#         return jsonify({'error': 'User not found'}), 404
        
#     if not user.keys:
#         return jsonify({'error': 'User has no keys registered'}), 404
    
#     try:
#         response = {
#             'uuid': user.uuid,
#             'username': user.username,
#             'email': user.email,
#             'identity_key_public': base64.b64encode(user.keys.identity_key_public).decode('utf-8'),
#             'signed_prekey_public': base64.b64encode(user.keys.signed_prekey_public).decode('utf-8'),
#             'signed_prekey_signature': base64.b64encode(user.keys.signed_prekey_signature).decode('utf-8'),
#             'opks': user.keys.opks
#         }
#         return jsonify(response), 200
#     except Exception as e:
#         return jsonify({'error': f'Error encoding user keys: {str(e)}'}), 500