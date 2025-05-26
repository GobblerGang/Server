import socket
import ssl
from flask import Flask, request, jsonify, send_file, session
from flask_cors import CORS
import os
import bcrypt
import json
from werkzeug.utils import secure_filename

app = Flask(__name__)
CORS(app)

# Configuration
app.secret_key = 'your-secret-key'  # Change this in production!
app.config['UPLOAD_FOLDER'] = 'uploads'
jwt = JWTManager(app)

# SSL Configuration
ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ssl_context.load_cert_chain(certfile="server.crt", keyfile="server.key")

# Ensure upload directory exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# In-memory storage (replace with database in production)
users = {}
files = {}  # {filename: {'owner': username, 'shared_with': [usernames]}}

# Helper functions
def save_users():
    with open('users.json', 'w') as f:
        json.dump(users, f)

def load_users():
    global users
    try:
        with open('users.json', 'r') as f:
            users = json.load(f)
    except FileNotFoundError:
        users = {}

# Load existing users
load_users()

@app.before_request
def log_request_info():
    client_ip = request.remote_addr
    print(f"Request from IP: {client_ip} - {request.method} {request.path}")

@app.route('/')
def home():
    return jsonify({
        'status': 'running',
        'message': 'File Sharing Server is running',
        'endpoints': {
            'register': '/api/register',
            'login': '/api/login',
            'logout': '/api/logout',
            'files': '/api/files',
            'upload': '/api/files/upload',
            'download': '/api/files/download/<filename>',
            'share': '/api/files/share',
            'revoke': '/api/files/revoke',
            'delete': '/api/files/delete/<filename>'
        }
    })

@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'error': 'Missing username or password'}), 400

    if username in users:
        return jsonify({'error': 'Username already exists'}), 400

    # Hash password
    hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    users[username] = {
        'password': hashed.decode('utf-8'),
        'files': []
    }
    save_users()

    return jsonify({'message': 'User registered successfully'}), 201

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'error': 'Missing username or password'}), 400

    user = users.get(username)
    if not user or not bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
        return jsonify({'error': 'Invalid username or password'}), 401

    session['username'] = username
    return jsonify({'message': 'Logged in successfully'}), 200

@app.route('/api/logout', methods=['POST'])
def logout():
    session.pop('username', None)
    return jsonify({'message': 'Logged out successfully'}), 200

def login_required(f):
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return jsonify({'error': 'Authentication required'}), 401
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function

@app.route('/api/files', methods=['GET'])
@login_required
def get_files():
    username = session['username']
    owned_files = [f for f, data in files.items() if data['owner'] == username]
    shared_files = [f for f, data in files.items() if username in data.get('shared_with', [])]
    
    return jsonify({
        'owned_files': owned_files,
        'shared_files': shared_files
    }), 200

@app.route('/api/files/upload', methods=['POST'])
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
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(file_path)
    
    # Update file metadata
    files[filename] = {
        'owner': username,
        'shared_with': []
    }
    
    return jsonify({'message': 'File uploaded successfully'}), 201

@app.route('/api/files/download/<filename>', methods=['GET'])
@login_required
def download_file(filename):
    username = session['username']
    file_data = files.get(filename)
    
    if not file_data:
        return jsonify({'error': 'File not found'}), 404
        
    if file_data['owner'] != username and username not in file_data.get('shared_with', []):
        return jsonify({'error': 'Access denied'}), 403
    
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    return send_file(file_path, as_attachment=True)

@app.route('/api/files/share', methods=['POST'])
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
        files[filename]['shared_with'].append(target_user)
        
    return jsonify({'message': 'File shared successfully'}), 200

@app.route('/api/files/revoke', methods=['POST'])
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
        files[filename]['shared_with'].remove(target_user)
        
    return jsonify({'message': 'Access revoked successfully'}), 200

@app.route('/api/files/delete/<filename>', methods=['DELETE'])
@login_required
def delete_file(filename):
    username = session['username']
    
    if filename not in files:
        return jsonify({'error': 'File not found'}), 404
        
    if files[filename]['owner'] != username:
        return jsonify({'error': 'You can only delete files you own'}), 403
    
    # Delete file from filesystem
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    if os.path.exists(file_path):
        os.remove(file_path)
    
    # Remove from files dictionary
    del files[filename]
    
    return jsonify({'message': 'File deleted successfully'}), 200

if __name__ == '__main__':
    print("\n=== Secure File Sharing Server ===")
    print("Server is running with TLS and listening on all interfaces")
    print("You can access it using:")
    print("  - https://localhost:4433")
    print("  - https://127.0.0.1:4433")
    print("  - https://<your-ip-address>:4433")
    print("\nAvailable endpoints:")
    print("  - GET  /")
    print("  - POST /api/register")
    print("  - POST /api/login")
    print("  - GET  /api/files")
    print("  - POST /api/files/upload")
    print("  - GET  /api/files/download/<filename>")
    print("  - POST /api/files/share")
    print("  - POST /api/files/revoke")
    print("  - DELETE /api/files/delete/<filename>")
    print("\nPress Ctrl+C to stop the server")
    print("===========================\n")
    app.run(host='0.0.0.0', port=4433, ssl_context=ssl_context, debug=True)
