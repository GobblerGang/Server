from flask import Blueprint, request, jsonify
from werkzeug.security import generate_password_hash
from .models import db, User
import uuid

api = Blueprint('api', __name__)

@api.route('/api/users', methods=['POST'])
def add_user():
    data = request.get_json()

    if not data or not all(key in data for key in ('email', 'name', 'password')):
        return jsonify({'error': 'Missing required fields: email, name, password'}), 400

    email = data['email']
    name = data['name']
    password = data['password']

    existing_user = User.query.filter_by(email=email).first()
    if existing_user:
        return jsonify({'error': 'User with this email already exists'}), 409

    hashed_password = generate_password_hash(password)

    new_user = User(
        id=str(uuid.uuid4()),  
        email=email,
        name=name,
        password=hashed_password
    )

    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'User created successfully', 'user': {'id': new_user.id, 'email': new_user.email, 'name': new_user.name}}), 201