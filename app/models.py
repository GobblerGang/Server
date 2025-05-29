# from . import db
# from datetime import datetime
# import uuid

# # Association table for many-to-many relationship between files and users (shared files)
# # Removed based on whiteboard schema, PAC table handles sharing
# # shared_files = db.Table('bridge_shared_files',
# #     db.Column('file_id', db.Integer, db.ForeignKey('files.id'), primary_key=True),
# #     db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True)
# # )

# class User(db.Model):
#     id = db.Column(db.Integer, primary_key=True)
#     uuid = db.Column(db.String(36), unique=True, nullable=False, default=lambda: str(uuid.uuid4())) # Using String for UUID as MySQL UUID type can be complex
#     username = db.Column(db.String(80), unique=True, nullable=False)
#     email = db.Column(db.String(120), unique=True, nullable=False) 
#     keys = db.relationship('UserKeys', backref='user', uselist=False) 
#     files_owned = db.relationship('File', backref='owner', lazy=True)
#     pac_issued = db.relationship('PAC', backref='issuer', foreign_keys='PAC.issuer_id', lazy='dynamic')
#     pac_received = db.relationship('PAC', backref='recipient', foreign_keys='PAC.recipient_id', lazy='dynamic')



#     def __repr__(self):
#         return f'<User {self.username}>'

# class UserKeys(db.Model):
#     __tablename__ = 'user_keys'
#     user_id = db.Column(db.Integer, db.ForeignKey('user.id'), primary_key=True)
#     identity_key = db.Column(db.LargeBinary, nullable=False)
#     signed_prekey = db.Column(db.LargeBinary, nullable=False) 
#     opks = db.Column(db.JSON, nullable=True)

#     def __repr__(self):
#         return f'<UserKeys for user_id {self.user_id}>'

# class File(db.Model):
#     __tablename__ = 'files'
#     id = db.Column(db.Integer, primary_key=True)
#     encrypted_blob = db.Column(db.LargeBinary, nullable=False) # Storing encrypted file content as binary
#     filename = db.Column(db.String(255), nullable=False)
#     upload_date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
#     owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
#     mime_type = db.Column(db.String(100), nullable=True) # Assuming mime type can be nullable

#     # Relationship to PACs associated with this file
#     pacs = db.relationship('PAC', backref='file', lazy='dynamic')

#     def __repr__(self):
#         return f'<File {self.filename}>'

# class PAC(db.Model):
#     __tablename__ = 'pac'
#     id = db.Column(db.Integer, primary_key=True)
#     file_id = db.Column(db.Integer, db.ForeignKey('files.id'), nullable=False)
#     recipient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
#     issuer_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
#     encrypted_file_key = db.Column(db.LargeBinary, nullable=False) # Assuming binary key data
#     sender_ephemeral_public_key = db.Column(db.LargeBinary, nullable=False) # Assuming binary key data
#     valid_until = db.Column(db.DateTime, nullable=True) # Assuming it can be null if perpetually valid
#     revoked = db.Column(db.Boolean, default=False, nullable=False)
#     signature = db.Column(db.LargeBinary, nullable=False) # Assuming binary signature data

#     def __repr__(self):
#         return f'<PAC {self.id} for File {self.file_id} to User {self.recipient_id}>' 

# class Nonce(db.Model):
#     __tablename__ = 'nonces'
    
#     id = db.Column(db.Integer, primary_key=True)
#     # this should be a foreign key to the User table User id
#     username = db.Column(db.String(80), db.ForeignKey('user.username'), nullable=False)
#     nonce = db.Column(db.String(64), nullable=False)
#     timestamp = db.Column(db.DateTime, nullable=False)
#     used = db.Column(db.Boolean, default=False)
    
#     # Add index for faster lookups
#     __table_args__ = (
#         db.Index('idx_nonce_lookup', 'username', 'nonce'),
#     )
    
#     def __repr__(self):
#         return f'<Nonce {self.nonce} for {self.username}>' 
    
from . import db
from datetime import datetime
import uuid

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    uuid = db.Column(db.String(36), unique=True, nullable=False, default=lambda: str(uuid.uuid4()))
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    keys = db.relationship('UserKeys', backref='user', uselist=False)
    files_owned = db.relationship('File', backref='owner', lazy=True)
    pac_issued = db.relationship('PAC', backref='issuer', foreign_keys='PAC.issuer_id', lazy='dynamic')
    pac_received = db.relationship('PAC', backref='recipient', foreign_keys='PAC.recipient_id', lazy='dynamic')

    def __repr__(self):
        return f'<User {self.username}>'

class UserKeys(db.Model):
    __tablename__ = 'user_keys'
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), primary_key=True)
    identity_key_public = db.Column(db.LargeBinary, nullable=False)         # Ed25519 public key
    signed_prekey_public = db.Column(db.LargeBinary, nullable=False)        # X25519 public key
    signed_prekey_signature = db.Column(db.LargeBinary, nullable=False)     # Signature by identity key
    opks = db.Column(db.JSON, nullable=True)                                # Array of one-time prekeys (public)

    def __repr__(self):
        return f'<UserKeys for user_id {self.user_id}>'

class File(db.Model):
    __tablename__ = 'files'
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    encrypted_blob = db.Column(db.LargeBinary, nullable=False)              
    file_nonce = db.Column(db.LargeBinary, nullable=False)                  
    k_file_encrypted = db.Column(db.LargeBinary, nullable=False)            
    k_file_nonce = db.Column(db.LargeBinary, nullable=False)                
    upload_date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    mime_type = db.Column(db.String(100), nullable=True)
    pacs = db.relationship('PAC', backref='file', lazy='dynamic')

    def __repr__(self):
        return f'<File {self.filename}>'

class PAC(db.Model):
    __tablename__ = 'pac'
    id = db.Column(db.Integer, primary_key=True)
    file_id = db.Column(db.Integer, db.ForeignKey('files.id'), nullable=False)
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    issuer_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    encrypted_file_key = db.Column(db.LargeBinary, nullable=False)          # k_file encrypted for recipient
    k_file_nonce = db.Column(db.LargeBinary, nullable=False)                # Nonce used for above
    sender_ephemeral_public_key = db.Column(db.LargeBinary, nullable=False) # X25519 public key
    valid_until = db.Column(db.DateTime, nullable=True)
    revoked = db.Column(db.Boolean, default=False, nullable=False)
    signature = db.Column(db.LargeBinary, nullable=False)                   # Ed25519 signature

    def __repr__(self):
        return f'<PAC {self.id} for File {self.file_id} to User {self.recipient_id}>'

class Nonce(db.Model):
    __tablename__ = 'nonces'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    nonce = db.Column(db.String(64), nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False)
    used = db.Column(db.Boolean, default=False)

    __table_args__ = (
        db.Index('idx_nonce_lookup', 'user_id', 'nonce'),
    )

    def __repr__(self):
        return f'<Nonce {self.nonce} for user_id {self.user_id}>'