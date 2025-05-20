import pycurl
from io import BytesIO
import certifi

def make_secure_request(url):
    # Create a buffer to store the response
    buffer = BytesIO()
    
    # Initialize curl
    c = pycurl.Curl()
    
    # Set up the request
    c.setopt(c.URL, url)
    c.setopt(c.WRITEDATA, buffer)
    
    # SSL/TLS configuration
    c.setopt(c.SSL_VERIFYPEER, 1)  # Verify the peer's certificate
    c.setopt(c.SSL_VERIFYHOST, 2)  # Verify the certificate's name against host
    c.setopt(c.CAINFO, certifi.where())  # Use certifi's certificate bundle
    
    try:
        # Perform the request
        c.perform()
        
        # Get the response
        response = buffer.getvalue().decode('utf-8')
        print(f"Response: {response}")
        
    except pycurl.error as e:
        print(f"Error: {e}")
    
    finally:
        # Clean up
        c.close()
        buffer.close()

if __name__ == "__main__":
    # Replace with your server's hostname or IP
    server_url = "https://localhost:5000/api/secure"
    make_secure_request(server_url) 