from flask import Flask, jsonify, request
from flask_cors import CORS
import os
import ssl
from flask_sqlalchemy import SQLAlchemy
from dotenv import load_dotenv
import logging
import uuid
import time # Import time for nonce timestamping
from urllib.parse import quote_plus # Import quote_plus for URL encoding

load_dotenv()

db = SQLAlchemy()

# In-memory storage for used nonces (for development only)
# In production, use a database or distributed cache
used_nonces = {}

def create_app(config_name='default'):
    app = Flask(__name__)
    CORS(app)

    # Configuration from environment variables
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or 'a-very-hard-to-guess-string'
    
    # Set debug mode based on config
    app.config['DEBUG'] = config_name == 'development'
    
    # Database configuration using individual environment variables
    db_user = os.getenv("DB_USER")
    db_pass = os.getenv("DB_PASSWORD")
    db_host = os.getenv("DB_HOST")
    db_port = os.getenv("DB_PORT", "3306") # Default to 3306 if not set
    db_name = os.getenv("DB_NAME")

    if not all([db_user, db_pass, db_host, db_name]):
        # Raise a descriptive error if database environment variables are not set
        raise ValueError("Database environment variables (DB_USER, DB_PASSWORD, DB_HOST, DB_NAME) must be set.")

    # URL-encode the password before including it in the URI
    encoded_db_pass = quote_plus(db_pass)
    app.config['SQLALCHEMY_DATABASE_URI'] = f'mysql+mysqlconnector://{db_user}:{encoded_db_pass}@{db_host}:{db_port}/{db_name}'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['UPLOAD_FOLDER'] = os.environ.get('UPLOAD_FOLDER') or 'uploads'

    db.init_app(app)

    # Configure logging
    logging.basicConfig(level=logging.INFO) # Set desired logging level
    app.logger.setLevel(logging.INFO)
    # Optionally add a handler if default isn't sufficient (e.g., for specific formatting)
    # handler = logging.StreamHandler()
    # app.logger.addHandler(handler)

    # Ensure upload directory exists
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    
    # SSL Configuration - Keep for development testing with self-signed certs
    # In production, a reverse proxy handles SSL
    try:
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_context.load_cert_chain(certfile=os.environ.get('SSL_CERT_PATH') or "server.crt", keyfile=os.environ.get('SSL_KEY_PATH') or "server.key")
        app.config['SSL_CONTEXT'] = ssl_context
    except FileNotFoundError:
        app.logger.warning("SSL certificate files not found. Running without SSL context.")
        app.config['SSL_CONTEXT'] = None

    # Import models so that they are known to SQLAlchemy and Alembic
    from . import models

    # Import and register blueprints
    from .auth import auth_bp, verify_signature_authorization # Import verify_signature_authorization
    from .files import files_bp
    app.register_blueprint(auth_bp, url_prefix='/api')
    app.register_blueprint(files_bp, url_prefix='/api/files')

    # Add a simple root route
    @app.route('/')
    def home():
        app.logger.info("Root endpoint accessed") # Example log message
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
                'nonce': '/api/nonce' # Add nonce endpoint
            }
        })

    @app.route('/api/nonce', methods=['POST'])
    def get_nonce():
        data = request.get_json()
        username = data.get('username')
        if not username:
            return jsonify({'error': 'Username required'}), 400

        user = models.User.query.filter_by(username=username).first()
        if not user:
            return jsonify({'error': 'User not found'}), 404

        nonce = str(uuid.uuid4())
        timestamp = int(time.time())

        if username not in used_nonces:
            used_nonces[username] = {}
        used_nonces[username][nonce] = timestamp

        app.logger.info(f"Issued nonce {nonce} for user {username}")

        return jsonify({'nonce': nonce}), 200

    @app.before_request
    def log_request_info():
        client_ip = request.remote_addr
        app.logger.info(f"Request from IP: {client_ip} - {request.method} {request.path}")

    return app 