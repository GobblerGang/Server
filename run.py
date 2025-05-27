from app import create_app

app = create_app()

if __name__ == '__main__':
    # Use the SSL context from app config if available
    ssl_context = app.config.get('SSL_CONTEXT')
    
    # For development testing with SSL
    if ssl_context:
         print("\n=== Secure File Sharing Server ===")
         print("Server is running with TLS and listening on all interfaces")
         print("You can access it using:")
         print("  - https://localhost:4433")
         print("  - https://127.0.0.0.1:4433")
         print("  - https://<your-ip-address>:4433") # Replace with your server's actual IP
         print("\nPress Ctrl+C to stop the server")
         print("===========================\n")
         app.run(host='0.0.0.0', port=4433, ssl_context=ssl_context, debug=True)
    else:
        # For development testing without SSL
        print("\n=== File Sharing Server (No SSL) ===")
        print("Server is running and listening on all interfaces")
        print("You can access it using:")
        print("  - http://localhost:6969")
        print("  - http://127.0.0.0.1:6969")
        print("  - http://<your-ip-address>:6969") # Replace with your server's actual IP
        print("\nPress Ctrl+C to stop the server")
        print("===========================\n")
        app.run(host='0.0.0.0', port=6969, debug=True) 