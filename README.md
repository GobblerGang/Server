# Secure File Sharing Application

A secure file sharing system with end-to-end encryption, user authentication, and access control features.

## Features

- User authentication and registration
- Secure file upload and storage
- End-to-end encryption for files
- Access control management
- Pre-authorized access certificates (PAC) system

## Prerequisites

- MySQL/MariaDB database server
- Python 3.8 or higher
- pip (Python package manager)

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd <repository-directory>
```

2. Create and activate a virtual environment:
```bash
python -m venv .venv
# On Windows
.venv\Scripts\activate
# On Unix/MacOS
source .venv/bin/activate
```

3. Install the required dependencies:
```bash
pip install -r requirements.txt
```

## Database Setup

1. Run the SQL generation script:
```bash
python generate_sql.py
```

2. Create a new MySQL database:
```sql
CREATE DATABASE your_db_name;
```

3. Import the generated database schema:
```bash
mysql -u your_username -p your_db_name < server_db_schema.sql
```

## Configuration

1. Create a `.env` file in the root directory with the following variables:
```env
# Database Configuration
DB_HOST=localhost
DB_USER=your_username
DB_PASSWORD=your_password
DB_NAME=your_db_name
DB_PORT=3306

# Application Security
SECRET_KEY=your_secret_key
NONCE_LIFESPAN=300
TIMESTAMP_TOLERANCE=10

# SSL Configuration (for development)
SSL_CERT_PATH=server.crt
SSL_KEY_PATH=server.key

# File Upload Configuration
UPLOAD_FOLDER=uploads
```

## Running the Application

1. Start the server:
```bash
python app.py
```

The server will start running on `https://localhost:4433` in development mode (with SSL).

## API Endpoints

### Authentication
- POST `/api/register` - Register a new user
- POST `/api/login` - User login
- POST `/api/logout` - User logout
- GET `/api/nonce` - Get a nonce for authentication

### Files
- GET `/api/files` - List user's files (both owned and shared)
- POST `/api/files/upload` - Upload a new file
- GET `/api/files/download/<filename>` - Download a file
- POST `/api/files/share` - Share a file with another user
- POST `/api/files/revoke` - Revoke access to a shared file
- DELETE `/api/files/delete/<filename>` - Delete a file

## Security Features

- All files are encrypted before storage
- End-to-end encryption using public key cryptography
- Secure user authentication with nonce-based challenge-response
- Pre-authorised access certificates for controlled file sharing
- Identity verification through digital signatures
- SSL/TLS encryption in development mode
- Automatic nonce cleanup every hour
- Security headers for HTTP responses

## Development vs Production

### Development
- Uses self-signed certificates for SSL
- Runs on port 4433
- Debug mode enabled
- Direct SSL handling

### Production
- SSL handled by reverse proxy (e.g., Nginx)
- Runs on port 6969
- Debug mode disabled
- Enhanced security headers
- Rate limiting recommended


