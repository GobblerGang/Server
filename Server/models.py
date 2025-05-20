from Server import db
import uuid
from sqlalchemy import LargeBinary

class User(db.Model):
    __tablename__ = 'user'
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    email = db.Column(db.String(255), nullable=False, unique=True)
    name = db.Column(db.String(255), nullable=False)
    password = db.Column(db.String(255), nullable=False)
    
    files = db.relationship('File', backref='owner', lazy=True)
    
    def __repr__(self):
        return f'<User {self.email}>'

class File(db.Model):
    __tablename__ = 'files'
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    ownerId = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=False)
    name = db.Column(db.String(255), nullable=False)
    type = db.Column(db.String(50), nullable=False)
    enc_key = db.Column(LargeBinary, nullable=False) 
    
    shared_with = db.relationship('SharedFile', backref='file', lazy=True)
    
    def __repr__(self):
        return f'<File {self.name}>'

class SharedFile(db.Model):
    __tablename__ = 'bridge_shared_files'
    
    id = db.Column(db.BigInteger, primary_key=True, autoincrement=True)
    userId = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=False)
    fileId = db.Column(db.String(36), db.ForeignKey('files.id'), nullable=False)
    
    
    def __repr__(self):
        return f'<SharedFile user:{self.userId} file:{self.fileId}>'