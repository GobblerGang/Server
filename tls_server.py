import socket
import ssl

# Create TCP socket
bindsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
bindsocket.bind(('0.0.0.0', 4433))  # Listen on all interfaces
bindsocket.listen(5)
print("TLS server listening on port 4433...")

# Create SSL context with server's cert and key
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(certfile="server.crt", keyfile="server.key")

# Accept and handle secure connections
while True:
    client_sock, addr = bindsocket.accept()
    print(f"Connection from {addr}")

    with context.wrap_socket(client_sock, server_side=True) as ssock:
        data = ssock.recv(1024)
        print(f"Received: {data.decode()}")
        ssock.sendall(b"Secure reply: Hello from server")
