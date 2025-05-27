import os
from app import create_app

config_name = os.environ.get('FLASK_CONFIG') or 'default'
app = create_app(config_name)

if __name__ == '__main__':
    # Use the SSL context from app config if available
    ssl_context = app.config.get('SSL_CONTEXT')
    
    # For development testing with SSL
    if ssl_context and config_name == 'development':
         print("\n=== Secure File Sharing Server (Development with SSL) ===")
         print("Server is running with TLS and listening on all interfaces")
         print("You can access it using:")
         print("  - https://localhost:4433")
         print("  - https://127.0.0.0.1:4433")
         print("  - https://<your-ip-address>:4433") # Replace with your server's actual IP
         print("\nAvailable endpoints:")
         print("  - POST /api/nonce") # Add nonce endpoint here
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
    else:
        # For development testing without SSL or production
        print(f"\n=== File Sharing Server ({config_name.capitalize()}) ===")
        print("Server is running and listening on all interfaces")
        print("You can access it using:")
        print("  - http://localhost:6969")
        print("  - http://127.0.0.0.1:6969")
        print("  - http://<your-ip-address>:6969") # Replace with your server's actual IP
        print("\nAvailable endpoints:")
        print("  - POST /api/nonce") # Add nonce endpoint here as well
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
        app.run(host='0.0.0.0', port=6969, debug=app.config['DEBUG']) 