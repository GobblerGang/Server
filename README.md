# Flask Application

This is a Flask-based web application with CORS support and file upload capabilities.

## Prerequisites

- Python 3.8 or higher
- pip (Python package installer)

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd <repository-name>
```

2. Create and activate a virtual environment:
```bash
# On Windows
python -m venv venv
.\venv\Scripts\activate

# On macOS/Linux
python3 -m venv venv
source venv/bin/activate
```

3. Install the required dependencies:
```bash
pip install -r requirements.txt
```

## Running the Application

1. Make sure your virtual environment is activated

2. Start the application:
```bash
python run.py
```

The application will start in debug mode and be available at `http://localhost:5000`

## Project Structure

- `app/` - Main application package
- `uploads/` - Directory for uploaded files
- `requirements.txt` - Python dependencies
- `run.py` - Application entry point

## Dependencies

- Flask 3.0.2
- Flask-CORS 4.0.0
- Werkzeug 3.0.1
- python-dotenv 1.0.1
- bcrypt 4.1.2 