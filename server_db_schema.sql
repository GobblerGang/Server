CREATE TABLE user (
	id INTEGER NOT NULL AUTO_INCREMENT, 
	uuid VARCHAR(36) NOT NULL, 
	username VARCHAR(80) NOT NULL, 
	email VARCHAR(120) NOT NULL, 
	PRIMARY KEY (id), 
	UNIQUE (uuid), 
	UNIQUE (username), 
	UNIQUE (email)
);

CREATE TABLE files (
	id INTEGER NOT NULL AUTO_INCREMENT, 
	uuid VARCHAR(36) NOT NULL, 
	filename VARCHAR(255) NOT NULL, 
	file_nonce BLOB NOT NULL, 
	k_file_encrypted BLOB NOT NULL, 
	k_file_nonce BLOB NOT NULL, 
	upload_date DATETIME NOT NULL, 
	owner_id INTEGER NOT NULL, 
	mime_type VARCHAR(100), 
	PRIMARY KEY (id), 
	UNIQUE (uuid), 
	FOREIGN KEY(owner_id) REFERENCES user (id)
);

CREATE TABLE nonces (
	id INTEGER NOT NULL AUTO_INCREMENT, 
	user_uuid VARCHAR(36) NOT NULL, 
	nonce VARCHAR(64) NOT NULL, 
	timestamp DATETIME NOT NULL, 
	used BOOL, 
	PRIMARY KEY (id), 
	FOREIGN KEY(user_uuid) REFERENCES user (uuid)
);

CREATE TABLE user_keys (
	user_id INTEGER NOT NULL, 
	identity_key_public BLOB NOT NULL, 
	signed_prekey_public BLOB NOT NULL, 
	signed_prekey_signature BLOB NOT NULL, 
	opks JSON, 
	PRIMARY KEY (user_id), 
	FOREIGN KEY(user_id) REFERENCES user (id)
);

CREATE TABLE pac (
	id INTEGER NOT NULL AUTO_INCREMENT, 
	file_id INTEGER NOT NULL, 
	recipient_id INTEGER NOT NULL, 
	issuer_id INTEGER NOT NULL, 
	encrypted_file_key BLOB NOT NULL, 
	k_file_nonce BLOB NOT NULL, 
	sender_ephemeral_public_key BLOB NOT NULL, 
	valid_until DATETIME, 
	revoked BOOL NOT NULL, 
	signature BLOB NOT NULL, 
	PRIMARY KEY (id), 
	FOREIGN KEY(file_id) REFERENCES files (id), 
	FOREIGN KEY(recipient_id) REFERENCES user (id), 
	FOREIGN KEY(issuer_id) REFERENCES user (id)
);

