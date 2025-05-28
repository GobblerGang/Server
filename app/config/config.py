import os

class Config:
    SECRET_KEY = 'your-secret-key'  # Change this in production!
    UPLOAD_FOLDER = 'uploads'
    
    # Ensure upload directory exists
    os.makedirs(UPLOAD_FOLDER, exist_ok=True) 