from . import db
from datetime import datetime
import uuid
import base64

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    uuid = db.Column(db.String(36), unique=True, nullable=False)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    salt = db.Column(db.String(24), nullable=False)
    
    keys = db.relationship('UserKeys', backref='user', uselist=False, cascade='all, delete-orphan')
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
    uuid = db.Column(db.String(36), unique=True, nullable=False, default=lambda: str(uuid.uuid4()))
    filename = db.Column(db.String(255), nullable=False)
    file_nonce = db.Column(db.LargeBinary, nullable=False)                  
    k_file_encrypted = db.Column(db.LargeBinary, nullable=False)            
    k_file_nonce = db.Column(db.LargeBinary, nullable=False)                
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
    user_uuid = db.Column(db.String(36), db.ForeignKey('user.uuid'), nullable=False)
    nonce = db.Column(db.LargeBinary, nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    used = db.Column(db.Boolean, default=False)

    __table_args__ = (
        db.Index('idx_nonce_lookup', 'user_uuid', 'nonce'),
    )

    def __repr__(self):
        return f'<Nonce {self.nonce} for user {self.user_uuid}>'

class KeyEncryptionKey(db.Model):
    __tablename__ = 'key_encryption_keys'
    id = db.Column(db.Integer, primary_key=True)
    uuid = db.Column(db.String(36), unique=True, nullable=False, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    enc_kek_cyphertext = db.Column(db.LargeBinary, nullable=False)  # The KEK encrypted with master password derived key
    nonce = db.Column(db.LargeBinary, nullable=False)         # Nonce used for encryption
    updated_at = db.Column(db.String(255), nullable=False) # Needs to be a string to ensure no truncation issues
    
    # Relationship with User
    user = db.relationship('User', backref=db.backref('keks', lazy='dynamic'))
    
    def __repr__(self):
        return f'<KeyEncryptionKey {self.uuid}>'
        
    def to_dict(self):
        """Convert the KEK to a dictionary representation."""
        return {
            'uuid': self.uuid,
            'user_uuid': self.user.uuid,
            'enc_kek_cyphertext': base64.b64encode(self.enc_kek_cyphertext).decode('utf-8'),
            'nonce': base64.b64encode(self.nonce).decode('utf-8'),
            'associated_data': self.associated_data,
            'created_at': self.created_at.isoformat()
        }