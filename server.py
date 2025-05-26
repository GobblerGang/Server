from flask import Flask, request, jsonify, send_file, session
from flask_cors import CORS
import os
import bcrypt
import json
from werkzeug.utils import secure_filename
import socket
import ssl
from contextlib import contextmanager
import logging

# Initialize Flask app
app = Flask(__name__)
CORS(app)

# Configuration
app.secret_key = 'your-secret-key'  # Change this in production!
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['REMOTE_SERVER'] = 'gobblergang.gobbler.info'
app.config['REMOTE_PORT'] = 443

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

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

# SSL Connection Utilities
@contextmanager
def secure_connection(hostname=None, port=None):
    """Context manager for secure SSL connections using low-level sockets"""
    if hostname is None:
        hostname = app.config['REMOTE_SERVER']
    if port is None:
        port = app.config['REMOTE_PORT']
    
    # Hostname resolution
    try:
        addr_info = socket.getaddrinfo(
            hostname, port, 
            socket.AF_INET, 
            socket.SOCK_STREAM
        )
        family, socktype, proto, canonname, sockaddr = addr_info[0]
    except socket.gaierror as e:
        raise Exception(f"Hostname resolution failed: {str(e)}")
    
    # Create raw socket
    raw_sock = socket.socket(family, socktype, proto)
    
    try:
        # Set timeout to prevent hanging
        raw_sock.settimeout(10.0)
        
        # Connect at socket level
        raw_sock.connect(sockaddr)
        
        # Create SSL context with specific options
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.verify_mode = ssl.CERT_REQUIRED
        context.check_hostname = True
        
        # Load system trusted CA certificates
        context.load_default_certs()
        
        # Wrap socket with SSL
        secure_sock = context.wrap_socket(raw_sock, server_hostname=hostname)
        
        # Verify certificate
        cert = secure_sock.getpeercert()
        if not cert:
            raise Exception("No certificate received from server")
        
        yield secure_sock
        
    except ssl.SSLError as e:
        raise Exception(f"SSL error: {str(e)}")
    except socket.error as e:
        raise Exception(f"Socket error: {str(e)}")
    except Exception as e:
        raise Exception(f"Connection error: {str(e)}")
    finally:
        secure_sock.close()

def verify_remote_server():
    """Verify we can establish a secure connection to the remote server"""
    try:
        with secure_connection() as sock:
            # Perform a simple GET request to verify the connection
            request = (
                f"GET / HTTP/1.1\r\n"
                f"Host: {app.config['REMOTE_SERVER']}\r\n"
                f"Connection: close\r\n\r\n"
            )
            sock.sendall(request.encode())
            
            # Read response (just first part for verification)
            response = sock.recv(1024)
            if b"200 OK" not in response:
                raise Exception("Server did not return successful response")
            
        return True
    except Exception as e:
        logger.error(f"Remote server verification failed: {str(e)}")
        return False

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
            'delete': '/api/files/delete/<filename>',
            'health': '/api/health'
        }
    })

@app.route('/api/health')
def health_check():
    """Endpoint to verify secure connection to remote server"""
    if verify_remote_server():
        return jsonify({
            'status': 'healthy',
            'message': f"Secure connection to {app.config['REMOTE_SERVER']} verified",
            'server': app.config['REMOTE_SERVER'],
            'port': app.config['REMOTE_PORT']
        }), 200
    else:
        return jsonify({
            'status': 'unhealthy',
            'message': f"Failed to establish secure connection to {app.config['REMOTE_SERVER']}",
            'server': app.config['REMOTE_SERVER'],
            'port': app.config['REMOTE_PORT']
        }), 503

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
    # Verify remote server on startup
    logger.info(f"Attempting to verify connection to {app.config['REMOTE_SERVER']}")
    if verify_remote_server():
        logger.info(f"Successfully verified secure connection to {app.config['REMOTE_SERVER']}")
    else:
        logger.warning(f"Failed to verify connection to {app.config['REMOTE_SERVER']}")
    
    # Run the Flask app
    app.run(
        host='0.0.0.0',
        port=5000,
        debug=True,
        ssl_context='adhoc'  # For development only - use proper certs in production
    )