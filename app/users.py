from flask import Blueprint, request, jsonify, current_app, g
from .auth import login_required
from .models import db, User
import base64

users_bp = Blueprint('users', __name__)

@users_bp.route('/<username>', methods=['GET'])
def get_user_by_username(username):
    """Get user information by username.
    
    Returns:
        JSON response with user information:
        {
            "uuid": str,
            "username": str,
            "email": str,
            "identity_key_public": str (base64 encoded),
            "signed_prekey_public": str (base64 encoded),
            "signed_prekey_signature": str (base64 encoded),
            "opks": dict
        }
    """
    user = User.query.filter_by(username=username).first()
    
    if not user:
        return jsonify({'error': 'User not found'}), 404
        
    if not user.keys:
        return jsonify({'error': 'User has no keys registered'}), 404
    
    try:
        response = {
            'uuid': user.uuid,
            'username': user.username,
            'email': user.email,
            'salt': user.salt,
            'identity_key_public': base64.b64encode(user.keys.identity_key_public).decode('utf-8'),
            'signed_prekey_public': base64.b64encode(user.keys.signed_prekey_public).decode('utf-8'),
            'signed_prekey_signature': base64.b64encode(user.keys.signed_prekey_signature).decode('utf-8'),
            'opks': user.keys.opks
        }
        return jsonify(response), 200
    except Exception as e:
        current_app.logger.error(f"Error encoding user keys: {e}")
        return jsonify({'error': 'Error encoding user keys'}), 500

@users_bp.route('/keys/<user_uuid>', methods=['GET'])
@login_required
def get_user_keys(user_uuid):
    """Get user's public keys by UUID.
    
    Returns:
        JSON response with user's public keys:
        {
            "identity_key_public": str (base64 encoded),
            "signed_prekey_public": str (base64 encoded),
            "signed_prekey_signature": str (base64 encoded),
            "opks": dict
        }
    """
    user = User.query.filter_by(uuid=user_uuid).first()
    
    if not user:
        return jsonify({'error': 'User not found'}), 404
        
    if not user.keys:
        return jsonify({'error': 'User has no keys registered'}), 404
    
    try:
        response = {
            'identity_key_public': base64.b64encode(user.keys.identity_key_public).decode('utf-8'),
            'signed_prekey_public': base64.b64encode(user.keys.signed_prekey_public).decode('utf-8'),
            'signed_prekey_signature': base64.b64encode(user.keys.signed_prekey_signature).decode('utf-8'),
            'opks': user.keys.opks
        }
        return jsonify(response), 200
    except Exception as e:
        current_app.logger.error(f"Error encoding user keys: {e}")
        return jsonify({'error': 'Error encoding user keys'}), 500 