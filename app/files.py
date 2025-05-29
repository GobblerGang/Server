from flask import Blueprint, request, jsonify, send_file, current_app, session, g
import os
from werkzeug.utils import secure_filename
from .auth import login_required
from .models import db, User, File, PAC
from datetime import datetime
import base64

files_bp = Blueprint('files', __name__)

@files_bp.route('/', methods=['GET'])
@login_required
def get_files():
    current_user = g.user

    owned_files_list = File.query.filter_by(owner=current_user).all()
    owned_filenames = [f.filename for f in owned_files_list]

    shared_pacs = PAC.query.filter_by(recipient=current_user, revoked=False).all()
    shared_filenames = [pac.file.filename for pac in shared_pacs if pac.file]
    
    return jsonify({
        'owned_files': owned_filenames,
        'shared_files': shared_filenames
    }), 200

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
    encrypted_files_dir = os.path.join(current_app.config['UPLOAD_FOLDER'], 'encrypted_file_blobs')
    os.makedirs(encrypted_files_dir, exist_ok=True)

    # Save the encrypted file to disk using the UUID as filename
    file_path = os.path.join(encrypted_files_dir, file_uuid)
    with open(file_path, 'wb') as f:
        f.write(encrypted_blob)
    
    return True

@files_bp.route('/upload', methods=['POST'])
@login_required
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

@files_bp.route('/download/<filename>', methods=['GET'])
@login_required
def download_file(filename):
    current_user = g.user #getting user form our auth header

    file_to_download = File.query.filter_by(filename=filename).first()
    
    if not file_to_download:
        return jsonify({'error': 'File not found'}), 404
        
    is_owner = (file_to_download.owner == current_user)
    has_valid_pac = PAC.query.filter_by(
        file=file_to_download,
        recipient=current_user,
        revoked=False
    ).first() is not None

    if not is_owner and not has_valid_pac:
        return jsonify({'error': 'Access denied'}), 403
    
    file_content_bytes = file_to_download.encrypted_blob

    return send_file(file_content_bytes, as_attachment=True, download_name=filename, mimetype=file_to_download.mime_type or 'application/octet-stream')

@files_bp.route('/share', methods=['POST'])
@login_required
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

@files_bp.route('/revoke', methods=['POST'])
@login_required
def revoke_access():
    issuer_user = g.user
    data = request.get_json()

    filename = data.get('filename')
    recipient_username = data.get('username')

    if not filename or not recipient_username:
        return jsonify({'error': 'Missing filename or recipient username'}), 400

    file_to_revoke = File.query.filter_by(filename=filename).first()
    if not file_to_revoke:
        return jsonify({'error': 'File not found'}), 404

    if file_to_revoke.owner != issuer_user:
        return jsonify({'error': 'You can only revoke access to files you own'}), 403

    recipient_user = User.query.filter_by(username=recipient_username).first()
    if not recipient_user:
        return jsonify({'error': 'Recipient user not found'}), 404

    pac_to_revoke = PAC.query.filter_by(
        file=file_to_revoke,
        recipient=recipient_user,
        issuer=issuer_user,
        revoked=False
    ).first()

    if not pac_to_revoke:
        return jsonify({'message': 'No active share found for this user'}), 404

    pac_to_revoke.revoked = True
    db.session.commit()
    
    return jsonify({'message': 'Access revoked successfully'}), 200

@files_bp.route('/delete/<filename>', methods=['DELETE'])
@login_required
def delete_file(filename):
    current_user = g.user

    file_to_delete = File.query.filter_by(filename=filename, owner=current_user).first()
    
    if not file_to_delete:
        return jsonify({'error': 'File not found or you do not own this file'}), 404
        
    PAC.query.filter_by(file=file_to_delete).delete()
    db.session.commit()

    db.session.delete(file_to_delete)
    db.session.commit()
    
    file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)
    if os.path.exists(file_path):
        try:
            os.remove(file_path)
        except OSError as e:
            current_app.logger.error(f"Error deleting file from filesystem {file_path}: {e}")
            return jsonify({'error': 'File deletion failed'}), 500
    
    return jsonify({'message': 'File deleted successfully'}), 200

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