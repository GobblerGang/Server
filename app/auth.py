from flask import Blueprint, request, jsonify, g, current_app
from .models import db, User, UserKeys, Nonce, KeyEncryptionKey
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.exceptions import InvalidSignature
from datetime import datetime, timedelta, timezone
import secrets
import os
import base64
import uuid

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

def create_kek(user, kek_data):
    """Create a Key Encryption Key (KEK) for a user.
    
    Args:
        user: User object
        kek_data: dict containing:
            - enc_kek_cyphertext: str (base64 encoded)
            - nonce: str (base64 encoded)
            - updated_at: str (ISO format timestamp)
    
    Returns:
        tuple: (success: bool, error_message: str or None, status_code: int or None)
    """
    if not all([kek_data.get('enc_kek_cyphertext'), kek_data.get('nonce'), kek_data.get('updated_at')]):
        return False, 'Missing required KEK fields: enc_kek_cyphertext, nonce, updated_at', 400
        
    try:
        # Parse the timestamp
        updated_at = datetime.fromisoformat(kek_data['updated_at'].replace('Z', '+00:00'))
    except ValueError:
        return False, 'Invalid timestamp format (expected ISO 8601)', 400
        
    try:
        # Decode base64 strings to bytes
        enc_kek_cyphertext_bytes = base64.b64decode(kek_data['enc_kek_cyphertext'])
        nonce_bytes = base64.b64decode(kek_data['nonce'])
    except Exception as e:
        return False, f'Invalid base64 encoding: {str(e)}', 400
        
    try:
        # Create new KEK record
        new_kek = KeyEncryptionKey(
            user=user,
            enc_kek_cyphertext=enc_kek_cyphertext_bytes,
            nonce=nonce_bytes,
            updated_at=updated_at
        )
        
        db.session.add(new_kek)
        return True, None, None
        
    except Exception as e:
        current_app.logger.error(f"Error creating KEK: {e}")
        return False, 'Failed to create KEK', 500

@auth_bp.route('/register', methods=['POST'])
def register():
    """Expected JSON input body structure:
    {
        "user": {
            "uuid": str,
            "username": str,
            "email": str,
            "salt": str (16 bytes)
        },
        "keys": {
            "identity_key_public": str (base64 encoded),
            "signed_prekey_public": str (base64 encoded),
            "signed_prekey_signature": str (base64 encoded),
            "opks": dict
        },
        "kek": {
            "enc_kek_cyphertext": str (base64 encoded),
            "nonce": str (base64 encoded),
            "updated_at": str (ISO format timestamp)
        }
    }
    Returns:
    {
        "message": "User, keys, and KEK registered successfully",
        "user_uuid": "provided UUID"
    }
    """
    data = request.get_json()
    
    if not data:
        return jsonify({'error': 'No JSON data provided'}), 400
        
    # Extract the three main objects
    user_data = data.get('user')
    keys_data = data.get('keys')
    kek_data = data.get('kek')
    
    if not all([user_data, keys_data, kek_data]):
        return jsonify({'error': 'Missing required objects: user, keys, or kek'}), 400
        
    # Validate user data
    user_uuid = user_data.get('uuid')
    username = user_data.get('username')
    email = user_data.get('email')
    salt = user_data.get('salt')
    
    if not all([user_uuid, username, email, salt]):
        return jsonify({'error': 'Missing required user fields: uuid, username, email, salt'}), 400
        
    # Validate keys data
    identity_key = keys_data.get('identity_key_public')
    signed_prekey = keys_data.get('signed_prekey_public')
    signed_prekey_signature = keys_data.get('signed_prekey_signature')
    opks = keys_data.get('opks')
    
    if not all([identity_key, signed_prekey, signed_prekey_signature]):
        return jsonify({'error': 'Missing required keys fields: identity_key_public, signed_prekey_public, signed_prekey_signature'}), 400

    # Validate UUID format
    try:
        uuid_obj = uuid.UUID(user_uuid)
        if str(uuid_obj) != user_uuid:  # Ensure canonical format
            return jsonify({'error': 'Invalid UUID format'}), 400
    except ValueError:
        return jsonify({'error': 'Invalid UUID format'}), 400

    # Check if UUID already exists
    existing_uuid = User.query.filter_by(uuid=user_uuid).first()
    if existing_uuid:
        return jsonify({'error': 'UUID already exists'}), 400

    # Check if username or email exists
    existing_user = User.query.filter((User.username == username) | (User.email == email)).first()
    if existing_user:
        if existing_user.username == username:
            return jsonify({'error': 'Username already exists'}), 400
        else:
            return jsonify({'error': 'Email already exists'}), 400

    # Validate base64 encoding for all keys and salt
    try:
        # Decode all keys
        identity_key_bytes = base64.b64decode(identity_key)
        signed_prekey_bytes = base64.b64decode(signed_prekey)
        signed_prekey_signature_bytes = base64.b64decode(signed_prekey_signature)
        
        # Validate KEK data
        enc_kek_cyphertext_bytes = base64.b64decode(kek_data['enc_kek_cyphertext'])
        nonce_bytes = base64.b64decode(kek_data['nonce'])
        
    except (ValueError, base64.binascii.Error) as e:
        return jsonify({'error': f'Invalid base64 encoding: {str(e)}'}), 400

    # Create new user with provided UUID
    new_user = User(
        uuid=user_uuid,
        username=username,
        email=email,
        salt=salt  # Store the base64 encoded salt string
    )
    db.session.add(new_user)
    db.session.commit()

    new_user_keys = UserKeys(
        user_id=new_user.id,
        identity_key_public=identity_key_bytes,
        signed_prekey_public=signed_prekey_bytes,
        signed_prekey_signature=signed_prekey_signature_bytes,
        opks=opks
    )
    db.session.add(new_user_keys)

    # Create KEK with decoded values
    kek_data['enc_kek_cyphertext'] = enc_kek_cyphertext_bytes
    kek_data['nonce'] = nonce_bytes
    success, error_message, status_code = create_kek(new_user, kek_data)
    if not success:
        # Clean up user and keys if KEK creation fails
        db.session.delete(new_user)
        db.session.commit()
        return jsonify({'error': error_message}), status_code

    db.session.commit()

    return jsonify({
        'message': 'User, keys, and KEK registered successfully',
        'user_uuid': new_user.uuid
    }), 201

@auth_bp.route('/nonce', methods=['POST'])
def get_nonce():
    """Generate a new nonce for a user.
    Expected JSON input:
    {
        "user_uuid": "user's UUID"
    }
    Returns:
    {
        "nonce": "base64 encoded nonce",
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

    # Generate random bytes and encode as base64
    nonce_bytes = secrets.token_bytes(32)  # 32 bytes = 256 bits
    nonce = base64.b64encode(nonce_bytes).decode('utf-8')
    timestamp = datetime.now(timezone.utc)
    
    new_nonce = Nonce(
        user_uuid=user_uuid,
        nonce=nonce_bytes,  # Store the raw bytes in the database
        timestamp=timestamp,
        used=False
    )
    db.session.add(new_nonce)
    db.session.commit()
    
    return jsonify({
        'nonce': nonce,  # Return base64 encoded nonce
        'timestamp': timestamp.isoformat()
    }), 200

@auth_bp.route('/generate-uuid', methods=['GET'])
def generate_uuid():
    """Generate a unique UUID for user registration.
    
    Returns:
        JSON response with a unique UUID:
        {
            "uuid": str,
            "message": "UUID generated successfully"
        }
        
    Error Responses:
        500: Failed to generate unique UUID after maximum attempts
    """
    max_attempts = 5  # Prevent infinite loops
    
    for _ in range(max_attempts):
        # Generate new UUID
        new_uuid = str(uuid.uuid4())
        
        # Check if UUID exists in any relevant tables
        user_exists = User.query.filter_by(uuid=new_uuid).first()
        if not user_exists:
            return jsonify({
                'uuid': new_uuid,
                'message': 'UUID generated successfully'
            }), 200
    
    # If we couldn't generate a unique UUID after max attempts
    current_app.logger.error("Failed to generate unique UUID after maximum attempts")
    return jsonify({
        'error': 'Failed to generate unique UUID'
    }), 500

@auth_bp.route('/change-password', methods=['PUT'])
@login_required
def change_password():
    """Update user's Key Encryption Key (KEK) after password change.
    
    Expected JSON payload:
    {
        "enc_kek_cyphertext": str (base64 encoded),
        "nonce": str (base64 encoded),
        "updated_at": str (ISO format timestamp)
    }
    
    Returns:
        JSON response with updated KEK information:
        {
            "uuid": str,
            "user_uuid": str,
            "enc_kek_cyphertext": str (base64 encoded),
            "nonce": str (base64 encoded),
            "updated_at": str (ISO format)
        }
    """
    current_user = g.user
    data = request.get_json()
    
    if not data:
        return jsonify({'error': 'No JSON data provided'}), 400
        
    # Extract and validate required fields
    enc_kek_cyphertext = data.get('enc_kek_cyphertext')
    nonce = data.get('nonce')
    updated_at_str = data.get('updated_at')
    
    if not all([enc_kek_cyphertext, nonce, updated_at_str]):
        return jsonify({'error': 'Missing required fields: enc_kek_cyphertext, nonce, updated_at'}), 400
        
    try:
        # Parse the timestamp
        updated_at = datetime.fromisoformat(updated_at_str.replace('Z', '+00:00'))
    except ValueError:
        return jsonify({'error': 'Invalid timestamp format (expected ISO 8601)'}), 400
        
    try:
        # Decode base64 strings to bytes
        enc_kek_cyphertext_bytes = base64.b64decode(enc_kek_cyphertext)
        nonce_bytes = base64.b64decode(nonce)
    except Exception as e:
        return jsonify({'error': f'Invalid base64 encoding: {str(e)}'}), 400
        
    try:
        # Find user's existing KEK
        existing_kek = KeyEncryptionKey.query.filter_by(user_id=current_user.id).first()
        if not existing_kek:
            return jsonify({'error': 'No KEK found for user'}), 404
            
        # Update KEK with new values
        existing_kek.enc_kek_cyphertext = enc_kek_cyphertext_bytes
        existing_kek.nonce = nonce_bytes
        existing_kek.updated_at = updated_at
        
        db.session.commit()
        
        # Encode the stored bytes back to base64 for the response
        return jsonify({
            'uuid': existing_kek.uuid,
            'user_uuid': current_user.uuid,
            'enc_kek_cyphertext': base64.b64encode(existing_kek.enc_kek_cyphertext).decode('utf-8'),
            'nonce': base64.b64encode(existing_kek.nonce).decode('utf-8'),
            'updated_at': existing_kek.updated_at.isoformat()
        }), 200
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error updating KEK: {e}")
        return jsonify({'error': 'Failed to update KEK'}), 500

@auth_bp.route('/kek/<user_uuid>', methods=['GET'])
def get_kek(user_uuid):
    """Get the user's Key Encryption Key (KEK).
    
    URL Parameters:
        user_uuid: str - The UUID of the user whose KEK to retrieve
        
    Returns:
        JSON response with KEK information:
        {
            "uuid": str,
            "user_uuid": str,
            "enc_kek_cyphertext": str (base64 encoded),
            "nonce": str (base64 encoded),
            "updated_at": str (ISO format)
        }
        
    Error Responses:
        400: Invalid UUID format
        404: User not found
        404: No KEK found for user
        500: Failed to retrieve KEK
    """
    try:
        # Validate UUID format
        uuid_obj = uuid.UUID(user_uuid)
        if str(uuid_obj) != user_uuid:  # Ensure canonical format
            return jsonify({'error': 'Invalid UUID format'}), 400
    except ValueError:
        return jsonify({'error': 'Invalid UUID format'}), 400
    
    try:
        # Find user and their KEK
        user = User.query.filter_by(uuid=user_uuid).first()
        if not user:
            return jsonify({'error': 'User not found'}), 404
            
        kek = KeyEncryptionKey.query.filter_by(user_id=user.id).first()
        if not kek:
            return jsonify({'error': 'No KEK found for user'}), 404
            
        return jsonify({
            'uuid': kek.uuid,
            'user_uuid': user.uuid,
            'enc_kek_cyphertext': base64.b64encode(kek.enc_kek_cyphertext).decode('utf-8'),
            'nonce': base64.b64encode(kek.nonce).decode('utf-8'),
            'updated_at': kek.updated_at.isoformat()
        }), 200
        
    except Exception as e:
        current_app.logger.error(f"Error retrieving KEK: {e}")
        return jsonify({'error': 'Failed to retrieve KEK'}), 500

