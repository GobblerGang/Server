from flask import Blueprint, request, jsonify, send_file, current_app, session, g
import os
from werkzeug.utils import secure_filename
from .auth import login_required
from .models import db, User, File, PAC

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

@files_bp.route('/upload', methods=['POST'])
@login_required
def upload_file():
    current_user = g.user
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400

    filename = secure_filename(file.filename)
    
    existing_file = File.query.filter_by(owner=current_user, filename=filename).first()
    if existing_file:
        return jsonify({'error': f'File with name \'{filename}\' already exists for this user'}), 400

    file_content = file.read()
    mime_type = file.content_type
    
    new_file = File(
        filename=filename,
        encrypted_blob=file_content,
        owner=current_user,
        mime_type=mime_type
    )
    
    db.session.add(new_file)
    db.session.commit()
    
    return jsonify({'message': 'File uploaded successfully', 'file_id': new_file.id}), 201

@files_bp.route('/download/<filename>', methods=['GET'])
@login_required
def download_file(filename):
    current_user = g.user

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

    filename = data.get('filename')
    recipient_username = data.get('recipient_username')
    encrypted_file_key_hex = data.get('encrypted_file_key')
    sender_ephemeral_public_key_hex = data.get('sender_ephemeral_public_key')
    valid_until_str = data.get('valid_until')
    signature_hex = data.get('signature')

    if not filename or not recipient_username or not encrypted_file_key_hex or not sender_ephemeral_public_key_hex or not signature_hex:
        return jsonify({'error': 'Missing required fields for sharing'}), 400

    file_to_share = File.query.filter_by(filename=filename).first()
    if not file_to_share:
        return jsonify({'error': 'File not found'}), 404

    if file_to_share.owner != issuer_user:
        return jsonify({'error': 'You can only share files you own'}), 403

    recipient_user = User.query.filter_by(username=recipient_username).first()
    if not recipient_user:
        return jsonify({'error': 'Recipient user not found'}), 404

    try:
        encrypted_file_key_bytes = bytes.fromhex(encrypted_file_key_hex)
        sender_ephemeral_public_key_bytes = bytes.fromhex(sender_ephemeral_public_key_hex)
        signature_bytes = bytes.fromhex(signature_hex)
    except ValueError:
        return jsonify({'error': 'Invalid hex format for key or signature'}), 400

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
        sender_ephemeral_public_key=sender_ephemeral_public_key_bytes,
        valid_until=valid_until_dt,
        revoked=False,
        signature=signature_bytes
    )

    db.session.add(new_pac)
    db.session.commit()
    
    return jsonify({'message': 'File shared successfully', 'pac_id': new_pac.id}), 201

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