import pytest
from Server import app, db
from models import User

@pytest.fixture
def client():
    # Set up the Flask test client
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'  # Use an in-memory SQLite database for testing
    with app.test_client() as client:
        with app.app_context():
            db.create_all()  # Create tables
        yield client
        with app.app_context():
            db.drop_all()  # Clean up tables after tests

def test_add_user_success(client):
    # Test adding a new user successfully
    response = client.post('/api/users', json={
        'email': 'test@example.com',
        'name': 'Test User',
        'password': 'securepassword'
    })
    assert response.status_code == 201
    data = response.get_json()
    assert data['message'] == 'User created successfully'
    assert data['user']['email'] == 'test@example.com'

def test_add_user_missing_fields(client):
    # Test adding a user with missing fields
    response = client.post('/api/users', json={
        'email': 'test@example.com'
    })
    assert response.status_code == 400
    data = response.get_json()
    assert data['error'] == 'Missing required fields: email, name, password'

def test_add_user_duplicate_email(client):
    # Test adding a user with a duplicate email
    client.post('/api/users', json={
        'email': 'test@example.com',
        'name': 'Test User',
        'password': 'securepassword'
    })
    response = client.post('/api/users', json={
        'email': 'test@example.com',
        'name': 'Another User',
        'password': 'anotherpassword'
    })
    assert response.status_code == 409
    data = response.get_json()
    assert data['error'] == 'User with this email already exists'