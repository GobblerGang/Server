from flask import Flask, jsonify
from flask_cors import CORS
from app.config.config import Config
from app.routes.auth import auth_bp
from app.routes.files import files_bp

def create_app():
    app = Flask(__name__)
    CORS(app)
    
    # Load configuration
    app.config.from_object(Config)
    
    # Register blueprints
    app.register_blueprint(auth_bp, url_prefix='/api')
    app.register_blueprint(files_bp, url_prefix='/api/files')
    
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