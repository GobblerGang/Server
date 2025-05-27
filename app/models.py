from . import db
from datetime import datetime

# Association table for many-to-many relationship between files and users (shared files)
shared_files = db.Table('bridge_shared_files',
    db.Column('file_id', db.Integer, db.ForeignKey('files.id'), primary_key=True),
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True)
)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    files_owned = db.relationship('File', backref='owner', lazy=True)
    files_shared_with = db.relationship('File', secondary=shared_files, backref=db.backref('shared_with_users', lazy='dynamic'), lazy='dynamic')

    def __repr__(self):
        return f'<User {self.username}>'

class File(db.Model):
    __tablename__ = 'files'
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    upload_date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    def __repr__(self):
        return f'<File {self.filename}>' 