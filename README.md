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

## Database Setup

1. Create a new MySQL database:
```sql
CREATE DATABASE secure_file_sharing;
```

2. Import the database schema:
```bash
mysql -u your_username -p secure_file_sharing < server_db_schema.sql
```

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd <repository-directory>
```

2. Create and activate a virtual environment (recommended):
```bash
python -m venv venv
# On Windows
venv\Scripts\activate
# On Unix/MacOS
source venv/bin/activate
```

3. Install the required dependencies:
```bash
pip install -r requirements.txt
```

## Configuration

1. Create a `.env` file in the root directory with the following variables:
```env
DB_HOST=localhost
DB_USER=your_username
DB_PASSWORD=your_password
DB_NAME=secure_file_sharing
SECRET_KEY=your_secret_key
```

## Running the Application

1. Start the server:
```bash
python app.py
```

The server will start running on `http://localhost:5000` by default.

## API Endpoints

### Authentication
- POST `/api/auth/register` - Register a new user
- POST `/api/auth/login` - User login
- POST `/api/auth/logout` - User logout

### Files
- POST `/api/files/upload` - Upload a new file
- GET `/api/files/list` - List user's files
- GET `/api/files/<file_id>` - Download a file
- DELETE `/api/files/<file_id>` - Delete a file

### Access Control
- POST `/api/pac/create` - Create a pre-authorized access certificate
- GET `/api/pac/list` - List PACs for a file
- POST `/api/pac/revoke` - Revoke a PAC

## Security Features

- All files are encrypted before storage
- End-to-end encryption using public key cryptography
- Secure user authentication with nonce-based challenge-response
- Pre-authorised access certificates for controlled file sharing
- Identity verification through digital signatures


