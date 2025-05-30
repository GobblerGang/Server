import os
from app import create_app
import logging

config_name = os.environ.get('FLASK_CONFIG') or 'default'
app = create_app(config_name)

def print_endpoints():
    """Print all available endpoints when server starts."""
    print("\n=== Available Endpoints ===")
    
    # Auth endpoints
    print("\nAuthentication Endpoints (/api):")
    print("  POST /register     - Register new user")
    print("  GET  /nonce        - Get authentication nonce")
    print("  GET  /generate-uuid - Generate unique UUID for registration")
    print("  PUT  /change-password - Update KEK after password change")
    print("  GET  /kek          - Get user's Key Encryption Key")
    
    # File endpoints
    print("\nFile Endpoints (/api/files):")
    print("  POST   /upload              - Upload new file")
    print("  GET    /download/<uuid>     - Download file by UUID")
    print("  POST   /share               - Share file with user")
    print("  POST   /revoke/<pac_id>     - Revoke file access")
    print("  DELETE /delete/<uuid>       - Delete file")
    print("  GET    /owned               - List owned files")
    print("  GET    /pacs                - List PACs (sent and received)")
    print("  GET    /info/<uuid>         - Get detailed file information")
    
    # User endpoints
    print("\nUser Endpoints (/api/users):")
    print("  GET /<username>             - Get user info by username")
    print("  GET /keys/<uuid>            - Get user keys by UUID")
    
    print("\n==========================\n")

if __name__ == '__main__':
    # Configure logging
    logging.basicConfig(level=logging.INFO)
    
    # Print available endpoints
    print_endpoints()
    
    # Use the SSL context from app config if available
    ssl_context = app.config.get('SSL_CONTEXT')
    
    # For development testing with SSL
    if ssl_context and config_name == 'development':
         print("\n=== Secure File Sharing Server (Development with SSL) ===")
         app.run(host='0.0.0.0', port=4433, ssl_context=ssl_context, debug=True)
    else:
        # For development testing without SSL or production
        print(f"\n=== File Sharing Server ({config_name.capitalize()}) ===")
        app.run(host='0.0.0.0', port=6969, debug=app.config['DEBUG']) 


