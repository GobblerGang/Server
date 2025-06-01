from flask import Blueprint, request, jsonify, send_file, current_app, session, g
import os
from werkzeug.utils import secure_filename
from .auth import login_required
from .models import db, User, File, PAC
from datetime import datetime
import base64
from .. import limiter

files_bp = Blueprint('files', __name__)

# Constants
ENCRYPTED_FILES_DIR = 'encrypted_file_blobs'


def save_encrypted_file(encrypted_blob: bytes, file_uuid: str) -> bool:
    """Save an encrypted file to the filesystem.
    
    Args:
        encrypted_blob: The encrypted file data
        file_uuid: The UUID to use as the filename
        
    Returns:
        bool: True if successful, False otherwise
        
    Raises:
        OSError: If there's an error creating directories or writing the file
    """
    # Ensure the encrypted_file_blobs directory exists
    encrypted_files_dir = os.path.join(current_app.config['UPLOAD_FOLDER'], ENCRYPTED_FILES_DIR)
    os.makedirs(encrypted_files_dir, exist_ok=True)

    # Save the encrypted file to disk using the UUID as filename
    file_path = os.path.join(encrypted_files_dir, file_uuid)
    with open(file_path, 'wb') as f:
        f.write(encrypted_blob)
    
    return True

@files_bp.route('/upload', methods=['POST'])
@login_required
@limiter.limit("10 per minute")
def upload_file():
    current_user = g.user
    data = request.get_json()
    
    if not data:
        return jsonify({'error': 'No JSON data provided'}), 400

    # Extract and validate required fields
    filename = data.get('file_name')
    enc_file_ciphertext = data.get('enc_file_ciphertext')
    mime_type = data.get('mime_type')
    file_nonce = data.get('file_nonce')
    enc_file_k = data.get('enc_file_k')
    k_file_nonce = data.get('k_file_nonce')

    # Validate all required fields are present
    required_fields = {
        'file_name': filename,
        'enc_file_ciphertext': enc_file_ciphertext,
        'mime_type': mime_type,
        'file_nonce': file_nonce,
        'enc_file_k': enc_file_k,
        'k_file_nonce': k_file_nonce
    }

    missing_fields = [field for field, value in required_fields.items() if not value]
    if missing_fields:
        return jsonify({'error': f'Missing required fields: {", ".join(missing_fields)}'}), 400

    # Check if user already has a file with this name
    existing_filename = File.query.filter_by(owner=current_user, filename=filename).first()
    if existing_filename:
        return jsonify({'error': f'File with name \'{filename}\' already exists for this user'}), 400

    try:
        # Decode base64 strings to bytes
        encrypted_blob = base64.b64decode(enc_file_ciphertext)
        file_nonce_bytes = base64.b64decode(file_nonce)
        k_file_encrypted = base64.b64decode(enc_file_k)
        k_file_nonce_bytes = base64.b64decode(k_file_nonce)
    except Exception as e:
        return jsonify({'error': f'Invalid base64 encoding: {str(e)}'}), 400

    # Create new file record first to get the UUID
    new_file = File(
        filename=filename,
        file_nonce=file_nonce_bytes,
        k_file_encrypted=k_file_encrypted,
        k_file_nonce=k_file_nonce_bytes,
        owner=current_user,
        mime_type=mime_type
    )
    
    db.session.add(new_file)
    db.session.commit()

    try:
        save_encrypted_file(encrypted_blob, new_file.uuid)
    except Exception as e:
        # If file saving fails, clean up the database record
        db.session.delete(new_file)
        db.session.commit()
        return jsonify({'error': f'Failed to save encrypted file: {str(e)}'}), 500
    
    return jsonify({
        'message': 'File uploaded successfully',
        'file_uuid': new_file.uuid
    }), 201

@files_bp.route('/download/<file_uuid>', methods=['GET'])
@login_required
@limiter.limit("30 per minute")
def download_file(file_uuid):
    current_user = g.user

    # Find the file and verify access
    file_to_download = File.query.filter_by(uuid=file_uuid).first()
    
    if not file_to_download:
        return jsonify({'error': 'File not found'}), 404
        
    # Check if user is owner or has valid PAC
    is_owner = (file_to_download.owner == current_user)
    has_valid_pac = PAC.query.filter_by(
        file=file_to_download,
        recipient=current_user,
        revoked=False
    ).first() is not None

    if not is_owner and not has_valid_pac:
        return jsonify({'error': 'Access denied'}), 403
    
    # Get the encrypted file from filesystem
    encrypted_files_dir = os.path.join(current_app.config['UPLOAD_FOLDER'], ENCRYPTED_FILES_DIR)
    file_path = os.path.join(encrypted_files_dir, file_uuid)
    
    if not os.path.exists(file_path):
        return jsonify({'error': 'Encrypted file not found'}), 404
        
    try:
        with open(file_path, 'rb') as f:
            encrypted_blob = f.read()
            
        return jsonify({
            'encrypted_blob': base64.b64encode(encrypted_blob).decode('utf-8')
        }), 200
    except Exception as e:
        current_app.logger.error(f"Error reading encrypted file: {e}")
        return jsonify({'error': 'Failed to read encrypted file'}), 500

@files_bp.route('/share', methods=['POST'])
@login_required
@limiter.limit("20 per minute")
def share_file():
    issuer_user = g.user
    data = request.get_json()

    # Extract and validate required fields
    recipient_uuid = data.get('recipient_uuid')
    file_uuid = data.get('file_uuid')
    valid_until_str = data.get('valid_until')
    encrypted_file_key = data.get('encrypted_file_key')
    signature = data.get('signature')
    sender_ephemeral_public = data.get('sender_ephemeral_public')
    k_file_nonce = data.get('k_file_nonce')

    # Validate all required fields are present
    required_fields = {
        'recipient_uuid': recipient_uuid,
        'file_uuid': file_uuid,
        'encrypted_file_key': encrypted_file_key,
        'signature': signature,
        'sender_ephemeral_public': sender_ephemeral_public,
        'k_file_nonce': k_file_nonce
    }

    missing_fields = [field for field, value in required_fields.items() if not value]
    if missing_fields:
        return jsonify({'error': f'Missing required fields: {", ".join(missing_fields)}'}), 400

    # Get the file and recipient
    file_to_share = File.query.filter_by(uuid=file_uuid).first()
    if not file_to_share:
        return jsonify({'error': 'File not found'}), 404

    if file_to_share.owner != issuer_user:
        return jsonify({'error': 'You can only share files you own'}), 403

    recipient_user = User.query.filter_by(uuid=recipient_uuid).first()
    if not recipient_user:
        return jsonify({'error': 'Recipient user not found'}), 404

    try:
        # Convert hex strings to bytes
        encrypted_file_key_bytes = bytes.fromhex(encrypted_file_key)
        sender_ephemeral_public_bytes = bytes.fromhex(sender_ephemeral_public)
        signature_bytes = bytes.fromhex(signature)
        k_file_nonce_bytes = bytes.fromhex(k_file_nonce)
    except ValueError:
        return jsonify({'error': 'Invalid hex format for key, signature, or nonce'}), 400

    valid_until_dt = None
    if valid_until_str:
        try:
            valid_until_dt = datetime.fromisoformat(valid_until_str)
        except ValueError:
            return jsonify({'error': 'Invalid date format for valid_until (expected ISO 8601)'}), 400

    new_pac = PAC(
        file=file_to_share,
        recipient=recipient_user,
        issuer=issuer_user,
        encrypted_file_key=encrypted_file_key_bytes,
        k_file_nonce=k_file_nonce_bytes,
        sender_ephemeral_public_key=sender_ephemeral_public_bytes,
        valid_until=valid_until_dt,
        revoked=False,
        signature=signature_bytes
    )

    db.session.add(new_pac)
    db.session.commit()
    
    return jsonify({
        'message': 'File shared successfully',
    }), 201

@files_bp.route('/revoke/<pac_id>', methods=['POST'])
@login_required
@limiter.limit("20 per minute")
def revoke_access(pac_id):
    current_user_uuid = g.user

    # Find the PAC and verify the issuer is the current user
    pac_to_revoke = PAC.query.filter_by(id=pac_id, issuer=current_user_uuid).first()
    
    if not pac_to_revoke:
        return jsonify({'error': 'PAC not found or you are not the issuer'}), 404

    if pac_to_revoke.revoked:
        return jsonify({'error': 'PAC is already revoked'}), 400

    try:
        pac_to_revoke.revoked = True
        db.session.commit()
        return jsonify({'message': 'Access revoked successfully'}), 200
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error revoking PAC: {e}")
        return jsonify({'error': 'Failed to revoke access'}), 500

@files_bp.route('/delete/<file_uuid>', methods=['DELETE'])
@login_required
def delete_file(file_uuid):
    current_user_uuid = g.user

    # Find file by UUID and verify ownership using user UUID
    file_to_delete = File.query.filter_by(uuid=file_uuid, owner=current_user_uuid).first()
    
    if not file_to_delete:
        return jsonify({'error': 'File not found or you do not own this file'}), 404
    
    try:
        # Delete all PACs associated with this file
        PAC.query.filter_by(file_id=file_to_delete.id).delete()
        db.session.commit()

        # Delete the file record from database
        db.session.delete(file_to_delete)
        db.session.commit()

        # Delete the encrypted file from filesystem
        encrypted_files_dir = os.path.join(current_app.config['UPLOAD_FOLDER'], ENCRYPTED_FILES_DIR)
        file_path = os.path.join(encrypted_files_dir, file_uuid)
        
        if os.path.exists(file_path):
            try:
                os.remove(file_path)
            except OSError as e:
                current_app.logger.error(f"Error deleting file from filesystem {file_path}: {e}")
                return jsonify({'error': 'File deletion failed'}), 500
        else:
            current_app.logger.warning(f"Encrypted file not found in filesystem: {file_path}")
    
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error during file deletion: {e}")
        return jsonify({'error': 'File deletion failed'}), 500
    
    return jsonify({'message': 'File and associated PACs deleted successfully'}), 200

def get_user_pacs(user_id: int, is_recipient: bool) -> list:
    """Get PACs for a user, either sent or received.
    
    Args:
        user_id: The ID of the user
        is_recipient: True to get received PACs, False to get sent PACs
        
    Returns:
        list: List of PAC objects with their details
    """
    # Query based on whether we want sent or received PACs
    if is_recipient:
        pacs = PAC.query.filter_by(recipient_id=user_id).all()
    else:
        pacs = PAC.query.filter_by(issuer_id=user_id).all()
    
    pacs_list = []
    for pac in pacs:
        # Get the associated file
        file = File.query.get(pac.file_id)
        if not file:
            continue  # Skip if file not found
            
        pac_data = {
            'pac_id': pac.id,
            'file_uuid': file.uuid,
            'file_name': file.filename,
            'mime_type': file.mime_type,
            'encrypted_file_key': base64.b64encode(pac.encrypted_file_key).decode('utf-8'),
            'k_file_nonce': base64.b64encode(pac.k_file_nonce).decode('utf-8'),
            'sender_ephemeral_public_key': base64.b64encode(pac.sender_ephemeral_public_key).decode('utf-8'),
            'valid_until': pac.valid_until.isoformat() if pac.valid_until else None,
            'revoked': pac.revoked,
            'signature': base64.b64encode(pac.signature).decode('utf-8')
        }
        
        # Add user info based on whether this is a sent or received PAC
        if is_recipient:
            pac_data.update({
                'issuer_uuid': pac.issuer.uuid,
                'issuer_username': pac.issuer.username
            })
        else:
            pac_data.update({
                'recipient_uuid': pac.recipient.uuid,
                'recipient_username': pac.recipient.username
            })
            
        pacs_list.append(pac_data)
    
    return pacs_list

@files_bp.route('/pacs', methods=['GET'])
@login_required
def get_pacs():
    """Get all PACs (sent and received) for the authenticated user.
    
    Returns:
        JSON response with two arrays:
        - sent_pacs: PACs issued by the user
        - received_pacs: PACs received by the user
    """
    current_user = g.user
    
    # Get both sent and received PACs using the helper function
    sent_pacs = get_user_pacs(current_user.id, is_recipient=False)
    received_pacs = get_user_pacs(current_user.id, is_recipient=True)
    
    return jsonify({
        'sent_pacs': sent_pacs,
        'received_pacs': received_pacs
    }), 200

@files_bp.route('/owned', methods=['GET'])
@login_required
def get_owned_files():
    """Get all files owned by the authenticated user.
    
    Returns:
        JSON response with list of files:
        {
            "files": [
                {
                    "uuid": str,
                    "filename": str,
                    "mime_type": str
                }
            ]
        }
    """
    current_user = g.user
    
    # Get all files owned by the user
    owned_files = File.query.filter_by(owner_id=current_user.id).all()
    
    files_list = []
    for file in owned_files:
        files_list.append({
            'uuid': file.uuid,
            'filename': file.filename,
            'mime_type': file.mime_type
        })
    
    return jsonify({
        'files': files_list
    }), 200 