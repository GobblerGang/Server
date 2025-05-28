from functools import wraps
from flask import session, jsonify
import bcrypt
import json

# In-memory storage (replace with database in production)
users = {}

def save_users():
    with open('users.json', 'w') as f:
        json.dump(users, f)

def load_users():
    global users
    try:
        with open('users.json', 'r') as f:
            users = json.load(f)
    except FileNotFoundError:
        users = {}

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return jsonify({'error': 'Authentication required'}), 401
        return f(*args, **kwargs)
    return decorated_function

# Load existing users
load_users() 