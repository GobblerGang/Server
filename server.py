from app import app
import os

@app.route('/')
def home():
    return "Gobbler Team"

if __name__ == '__main__':
    host = os.getenv('FLASK_RUN_HOST')
    port = int(os.getenv('FLASK_RUN_PORT'))
    app.run(host=host, port=port, debug=True) 
