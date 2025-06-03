from flask import Blueprint, request, jsonify, current_app, g
import os
from .auth import login_required
from .models import db, User, File, PAC
from datetime import datetime
import base64

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
def upload_file():
    """Upload an encrypted file to the server.
    
    Expected JSON payload:
    {
        "file_name": str,
        "enc_file_ciphertext": str (base64 encoded),
        "mime_type": str,
        "file_nonce": str (base64 encoded),
        "enc_file_k": str (base64 encoded),
        "k_file_nonce": str (base64 encoded)
    }
    
    Returns:
        JSON response with file information:
        {
            "message": str,
            "file_uuid": str
        }
        
    Error Responses:
        400: Missing required fields or invalid base64 encoding
        400: File with same name already exists for user
        500: Failed to save encrypted file
    """
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

    # # Check if user already has a file with this name
    # existing_filename = File.query.filter_by(owner=current_user, filename=filename).first()
    # if existing_filename:
    #     return jsonify({'error': f'File with name \'{filename}\' already exists for this user'}), 400

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
        'success': True,
        'file_uuid': new_file.uuid
    }), 201

@files_bp.route('/download/<file_uuid>', methods=['GET'])
@login_required
def download_file(file_uuid):
    """Download an encrypted file from the server.
    
    URL Parameters:
        file_uuid: str - The UUID of the file to download
        
    Returns:
        JSON response with encrypted file data:
        {
            "encrypted_blob": str (base64 encoded),
            "file_nonce": str (base64 encoded),
            "filename": str,
            "mime_type": str
        }
        
    Error Responses:
        404: File not found
        403: Access denied (user is not owner and has no valid PAC)
        500: Failed to read encrypted file
        
    Note:
        User must either:
        - Be the owner of the file, or
        - Have a valid Pre-Authorized Access Certificate (PAC)
    """
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
            'encrypted_blob': base64.b64encode(encrypted_blob).decode('utf-8'),
            'file_nonce': base64.b64encode(file_to_download.file_nonce).decode('utf-8'),
            'filename': file_to_download.filename,
            'mime_type': file_to_download.mime_type
        }), 200
    except Exception as e:
        current_app.logger.error(f"Error reading encrypted file: {e}")
        return jsonify({'error': 'Failed to read encrypted file'}), 500

@files_bp.route('/share', methods=['POST'])
@login_required
def share_file():
    """Share a file with another user by creating a Pre-Authorized Access Certificate (PAC).
    
    Expected JSON payload:
    {
        "recipient_uuid": str,
        "file_uuid": str,
        "valid_until": str (ISO format timestamp, optional),
        "encrypted_file_key": str (base64 encoded),
        "signature": str (base64 encoded),
        "sender_ephemeral_public": str (base64 encoded),
        "k_file_nonce": str (base64 encoded),
    }
    
    Returns:
        JSON response with success message:
        {
            "success": bool,
            "error": str (if any)
        }
        
    Error Responses:
        400: Missing required fields
        400: Invalid base64 encoding for keys/signature/nonce
        400: Invalid date format for valid_until
        404: File not found
        404: Recipient user not found
        403: User is not the owner of the file
        
    Note:
        - All cryptographic values (encrypted_file_key, signature, sender_ephemeral_public, k_file_nonce) 
          must be base64 encoded
        - valid_until is optional, if not provided the PAC will not expire
        - User must be the owner of the file to share it
    """
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
        'k_file_nonce': k_file_nonce,
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
        # Convert base64 strings to bytes
        encrypted_file_key_bytes = base64.b64decode(encrypted_file_key)
        sender_ephemeral_public_bytes = base64.b64decode(sender_ephemeral_public)
        signature_bytes = base64.b64decode(signature)
        k_file_nonce_bytes = base64.b64decode(k_file_nonce)
    except ValueError:
        return jsonify({'error': 'Invalid base64 encoding for key, signature, or nonce'}), 400

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
        'success': True,
    }), 201

@files_bp.route('/revoke/<pac_id>', methods=['POST'])
@login_required
def revoke_access(pac_id):
    """Revoke a Pre-Authorized Access Certificate (PAC) for a shared file.
    
    URL Parameters:
        pac_id: int - The ID of the PAC to revoke
        
    Returns:
        JSON response with success message:
        {
            "message": str
        }
        
    Error Responses:
        404: PAC not found or user is not the issuer
        400: PAC is already revoked
        500: Failed to revoke access
        
    Note:
        - Only the original issuer of the PAC can revoke it
        - Revocation is permanent and cannot be undone
        - The file itself is not deleted, only the access is revoked
    """
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
    """Delete a file and all its associated PACs.
    
    URL Parameters:
        file_uuid: str - The UUID of the file to delete
        
    Returns:
        JSON response with success message:
        {
            "message": str
        }
        
    Error Responses:
        404: File not found or user is not the owner
        500: Failed to delete file or associated PACs
        
    Note:
        - Only the owner of the file can delete it
        - This operation is permanent and cannot be undone
        - All PACs associated with the file will be deleted
        - Both the database record and the encrypted file blob will be removed
        - If the file blob is not found in the filesystem, the operation will still succeed
          but a warning will be logged
    """
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
        
        pac_data.update({
                'issuer_uuid': pac.issuer.uuid,
                'issuer_username': pac.issuer.username
            })
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
        - issued_pacs: PACs issued by the user
        - received_pacs: PACs received by the user
    """
    current_user = g.user
    
    # Get both sent and received PACs using the helper function
    issued_pacs = get_user_pacs(current_user.id, is_recipient=False)
    received_pacs = get_user_pacs(current_user.id, is_recipient=True)
    
    return jsonify({
        'issued': issued_pacs,
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
                    "file_uuid": str,
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
            'file_uuid': file.uuid,
            'filename': file.filename,
            'mime_type': file.mime_type
        })
    
    return jsonify({
        'files': files_list
    }), 200

@files_bp.route('/info/<file_uuid>', methods=['GET'])
@login_required
def get_file_info(file_uuid):
    """Get detailed information about a file by UUID.
    
    Returns:
        JSON response with file information:
        {
            "file_uuid": str,
            "filename": str,
            "mime_type": str,
            "file_nonce": str (base64 encoded),
            "k_file_encrypted": str (base64 encoded),
            "k_file_nonce": str (base64 encoded),
            "owner_uuid": str,
        }
    """
    current_user = g.user

    # Find the file and verify ownership
    file = File.query.filter_by(uuid=file_uuid).first()
    
    if not file:
        return jsonify({'error': 'File not found'}), 404
        
    if file.owner != current_user:
        return jsonify({'error': 'Access denied - you do not own this file'}), 403
    
    try:
        response = {
            'uuid': file.uuid,
            'filename': file.filename,
            'mime_type': file.mime_type,
            'file_nonce': base64.b64encode(file.file_nonce).decode('utf-8'),
            'k_file_encrypted': base64.b64encode(file.k_file_encrypted).decode('utf-8'),
            'k_file_nonce': base64.b64encode(file.k_file_nonce).decode('utf-8'),
            'owner_uuid': file.owner.uuid,
        }
        return jsonify(response), 200
    except Exception as e:
        current_app.logger.error(f"Error encoding file info: {e}")
        return jsonify({'error': 'Error encoding file information'}), 500