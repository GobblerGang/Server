import os
from app import create_app

config_name = os.environ.get('FLASK_CONFIG') or 'default'
app = create_app(config_name)

def print_endpoints():
    print("\nAvailable endpoints:")
    print("  - GET  /")
    print("  - POST /api/nonce") 
    print("  - POST /api/register")
    print("  - POST /api/login")
    print("  - GET  /api/files")
    print("  - POST /api/files/upload")
    print("  - GET  /api/files/download/<filename>")
    print("  - POST /api/files/share")
    print("  - POST /api/files/revoke")
    print("  - DELETE /api/files/delete/<filename>\n")

if __name__ == '__main__':
    # Use the SSL context from app config if available
    ssl_context = app.config.get('SSL_CONTEXT')
    
    # For development testing with SSL
    if ssl_context and config_name == 'development':
         print("\n=== Secure File Sharing Server (Development with SSL) ===")
         print_endpoints()
         app.run(host='0.0.0.0', port=4433, ssl_context=ssl_context, debug=True)
    else:
        # For development testing without SSL or production
        print(f"\n=== File Sharing Server ({config_name.capitalize()}) ===")
        print_endpoints()
        app.run(host='0.0.0.0', port=6969, debug=app.config['DEBUG']) 


