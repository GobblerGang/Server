from flask import Flask, jsonify
from flask_cors import CORS
import os
import ssl

def create_app():
    app = Flask(__name__)
    CORS(app)
    app.secret_key = 'your-secret-key' # Change this in production!
    app.config['UPLOAD_FOLDER'] = 'uploads'

    # Ensure upload directory exists
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    
    # SSL Configuration - Keep for development testing with self-signed certs
    # In production, a reverse proxy handles SSL
    try:
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_context.load_cert_chain(certfile="server.crt", keyfile="server.key")
        app.config['SSL_CONTEXT'] = ssl_context
    except FileNotFoundError:
        print("Warning: SSL certificate files not found. Running without SSL context.")
        app.config['SSL_CONTEXT'] = None

    # Import and register blueprints
    from .auth import auth_bp
    from .files import files_bp
    app.register_blueprint(auth_bp, url_prefix='/api')
    app.register_blueprint(files_bp, url_prefix='/api/files')

    # Add a simple root route
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

    return app 