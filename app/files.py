from flask import Blueprint, request, jsonify, send_file, current_app, session
import os
from werkzeug.utils import secure_filename
from .data import users, files, save_users
from .auth import login_required

files_bp = Blueprint('files', __name__)

@files_bp.route('/', methods=['GET'])
@login_required
def get_files():
    username = session['username']
    owned_files = [f for f, data in files.items() if data['owner'] == username]
    shared_files = [f for f, data in files.items() if username in data.get('shared_with', [])]
    
    return jsonify({
        'owned_files': owned_files,
        'shared_files': shared_files
    }), 200

@files_bp.route('/upload', methods=['POST'])
@login_required
def upload_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400

    username = session['username']
    filename = secure_filename(file.filename)
    
    # Save file
    file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)
    file.save(file_path)
    
    # Update file metadata
    files[filename] = {
        'owner': username,
        'shared_with': []
    }
    
    return jsonify({'message': 'File uploaded successfully'}), 201

@files_bp.route('/download/<filename>', methods=['GET'])
@login_required
def download_file(filename):
    username = session['username']
    file_data = files.get(filename)
    
    if not file_data:
        return jsonify({'error': 'File not found'}), 404
        
    if file_data['owner'] != username and username not in file_data.get('shared_with', []):
        return jsonify({'error': 'Access denied'}), 403
    
    file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)
    return send_file(file_path, as_attachment=True)

@files_bp.route('/share', methods=['POST'])
@login_required
def share_file():
    data = request.get_json()
    filename = data.get('filename')
    target_user = data.get('username')
    username = session['username']
    
    if not filename or not target_user:
        return jsonify({'error': 'Missing filename or target username'}), 400
        
    if filename not in files:
        return jsonify({'error': 'File not found'}), 404
        
    if files[filename]['owner'] != username:
        return jsonify({'error': 'You can only share files you own'}), 403
        
    if target_user not in users:
        return jsonify({'error': 'Target user does not exist'}), 404
        
    if target_user not in files[filename]['shared_with']:
        files[filename]['shared_with'].append(target_user) # type: ignore
        
    return jsonify({'message': 'File shared successfully'}), 200

@files_bp.route('/revoke', methods=['POST'])
@login_required
def revoke_access():
    data = request.get_json()
    filename = data.get('filename')
    target_user = data.get('username')
    username = session['username']
    
    if not filename or not target_user:
        return jsonify({'error': 'Missing filename or target username'}), 400
        
    if filename not in files:
        return jsonify({'error': 'File not found'}), 404
        
    if files[filename]['owner'] != username:
        return jsonify({'error': 'You can only revoke access to files you own'}), 403
        
    if target_user in files[filename]['shared_with']:
        files[filename]['shared_with'].remove(target_user) # type: ignore
        
    return jsonify({'message': 'Access revoked successfully'}), 200

@files_bp.route('/delete/<filename>', methods=['DELETE'])
@login_required
def delete_file(filename):
    username = session['username']
    
    if filename not in files:
        return jsonify({'error': 'File not found'}), 404
        
    if files[filename]['owner'] != username:
        return jsonify({'error': 'You can only delete files you own'}), 403
    
    # Delete file from filesystem
    file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)
    if os.path.exists(file_path):
        os.remove(file_path)
    
    # Remove from files dictionary
    del files[filename] # type: ignore
    
    return jsonify({'message': 'File deleted successfully'}), 200 