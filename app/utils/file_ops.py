# In-memory storage for file metadata
files = {}  # {filename: {'owner': username, 'shared_with': [usernames]}}

def get_user_files(username):
    owned_files = [f for f, data in files.items() if data['owner'] == username]
    shared_files = [f for f, data in files.items() if username in data.get('shared_with', [])]
    return owned_files, shared_files

def can_access_file(username, filename):
    file_data = files.get(filename)
    if not file_data:
        return False
    return file_data['owner'] == username or username in file_data.get('shared_with', []) 