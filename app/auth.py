from flask import Blueprint, request, jsonify, session, g, current_app
import bcrypt
from .models import db, User, UserKeys, Nonce
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.exceptions import InvalidSignature
import json
import time
from datetime import datetime, timedelta
import secrets

# Configure nonce lifespan (in seconds)
NONCE_LIFESPAN = 300

auth_bp = Blueprint('auth', __name__)

def cleanup_old_nonces():
    """Remove nonces older than NONCE_LIFESPAN seconds"""
    cutoff_time = datetime.utcnow() - timedelta(seconds=NONCE_LIFESPAN)
    Nonce.query.filter(Nonce.timestamp < cutoff_time).delete()
    db.session.commit()

def verify_request_auth():
    """Verify the authentication of a request by checking nonce and signature.
    Returns (success, user, error_message, status_code) tuple."""
    data = request.get_json()
    if not data:
        return False, None, 'Authentication required: Request body missing', 401

    username = data.get('username')
    original_message_str = data.get('original_message')
    signature_hex = data.get('signature')

    if not username or not original_message_str or not signature_hex:
        return False, None, 'Authentication required: Missing signature data in request', 401

    try:
        original_message = json.loads(original_message_str)
        nonce = original_message.get('nonce')
        timestamp = original_message.get('timestamp')
    except (json.JSONDecodeError, AttributeError):
        return False, None, 'Authentication failed: Invalid original message format', 401

    if not nonce or timestamp is None:
        return False, None, 'Authentication failed: Nonce or timestamp missing in original message', 401

    # Clean up old nonces periodically
    cleanup_old_nonces()

    # Nonce validation
    db_nonce = Nonce.query.filter_by(username=username, nonce=nonce, used=False).first()
    if not db_nonce:
        return False, None, 'Authentication failed: Invalid or expired nonce', 401

    # Check if nonce is too old
    if (datetime.utcnow() - db_nonce.timestamp).total_seconds() > NONCE_LIFESPAN:
        db.session.delete(db_nonce)
        db.session.commit()
        return False, None, 'Authentication failed: Nonce expired', 401

    # Nonce is valid and fresh, now verify signature
    try:
        signature = bytes.fromhex(signature_hex)
    except ValueError:
        return False, None, 'Authentication failed: Invalid signature format', 401

    # Verify the signature using the extracted original message bytes
    if not verify_signature_authorization(username, original_message_str, signature):
        # Mark nonce as used and reject
        db_nonce.used = True
        db.session.commit()
        return False, None, 'Authentication failed: Invalid signature', 401

    # If both nonce and signature are valid:
    # Mark nonce as used
    db_nonce.used = True
    db.session.commit()

    # Fetch the user
    user = User.query.filter_by(username=username).first()
    if not user:
        current_app.logger.error(f"Anomaly: Signature valid for user {username} but user not found in DB.")
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

def verify_signature_authorization(username, original_message, signature):
    user = User.query.filter_by(username=username).first()
    if not user or not user.keys or not user.keys.identity_key:
        return False

    try:
        public_key = serialization.load_public_key(
            user.keys.identity_key,
            backend=None
        )
        
        public_key.verify(
            signature,
            original_message.encode('utf-8'),
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
        print(f"Error during signature verification in verify_signature_authorization: {e}")
        return False

@auth_bp.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    email = data.get('email')
    identity_key = data.get('identity_key')
    signed_prekey = data.get('signed_prekey')
    opks = data.get('opks')

    if not username or not password or not email or not identity_key or not signed_prekey:
        return jsonify({'error': 'Missing required fields (username, password, email, identity_key, signed_prekey)'}), 400

    existing_user = User.query.filter((User.username == username) | (User.email == email)).first()
    if existing_user:
        if existing_user.username == username:
            return jsonify({'error': 'Username already exists'}), 400
        else:
            return jsonify({'error': 'Email already exists'}), 400

    hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    new_user = User(username=username, password=hashed.decode('utf-8'), email=email)
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
    # If successful, set a session cookie for browser-based authentication
    success, user, error_message, status_code = verify_request_auth()
    if not success:
        return jsonify({'error': error_message}), status_code

    # Set session for browser-based authentication
    session['username'] = user.username
    return jsonify({'message': 'Authentication successful'}), 200

@auth_bp.route('/logout', methods=['POST'])
def logout():
    session.pop('username', None)
    return jsonify({'message': 'Logged out successfully'}), 200

@auth_bp.route('/nonce', methods=['POST'])
def get_nonce():
    """Generate a new nonce for a user"""
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Request body missing'}), 400

    username = data.get('username')
    if not username:
        return jsonify({'error': 'Username required'}), 400

    # Verify user exists
    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({'error': 'User not found'}), 404

    # Generate a random nonce
    nonce = secrets.token_hex(32)  # 64 character hex string
    
    # Store in database
    new_nonce = Nonce(
        username=username,
        nonce=nonce,
        timestamp=datetime.utcnow()
    )
    db.session.add(new_nonce)
    db.session.commit()
    
    return jsonify({
        'nonce': nonce,
        'timestamp': new_nonce.timestamp.isoformat()
    }), 200 