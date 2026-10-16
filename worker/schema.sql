CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, login TEXT NOT NULL UNIQUE, salt TEXT NOT NULL, password_hash TEXT NOT NULL, created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS sessions (token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL, expires_at INTEGER NOT NULL, FOREIGN KEY(user_id) REFERENCES users(id));
CREATE TABLE IF NOT EXISTS addresses (id TEXT PRIMARY KEY, user_id TEXT NOT NULL, address TEXT NOT NULL UNIQUE, created_at INTEGER NOT NULL, FOREIGN KEY(user_id) REFERENCES users(id));
CREATE INDEX IF NOT EXISTS idx_addresses_user ON addresses(user_id);
CREATE TABLE IF NOT EXISTS mail_items (id TEXT PRIMARY KEY, address_id TEXT NOT NULL, sender TEXT, recipient TEXT, subject TEXT, text_body TEXT, html_body TEXT, received_at INTEGER NOT NULL, FOREIGN KEY(address_id) REFERENCES addresses(id));
CREATE INDEX IF NOT EXISTS idx_mail_items_address ON mail_items(address_id, received_at DESC);
CREATE TABLE IF NOT EXISTS signup_attempts (ip_hash TEXT NOT NULL, at INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS idx_signup_attempts ON signup_attempts(ip_hash,at);
