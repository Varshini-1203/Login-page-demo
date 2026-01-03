import sqlite3
import hashlib
import os
from datetime import datetime

class AuthDatabase:
    """Database handler for user authentication"""
    
    def __init__(self, db_path="users.db"):
        """Initialize database connection and create tables if needed"""
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        """Create users table if it doesn't exist"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def hash_password(self, password, salt=None):
        """Hash password with salt using SHA-256"""
        if salt is None:
            salt = os.urandom(32)
        
        # Combine password and salt, then hash
        pwd_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
        
        # Return salt + hash as hex string
        return salt.hex() + pwd_hash.hex()
    
    def verify_password(self, stored_password, provided_password):
        """Verify a password against the stored hash"""
        # Extract salt (first 64 characters = 32 bytes in hex)
        salt = bytes.fromhex(stored_password[:64])
        stored_hash = stored_password[64:]
        
        # Hash the provided password with the same salt
        pwd_hash = hashlib.pbkdf2_hmac('sha256', provided_password.encode('utf-8'), salt, 100000)
        
        return pwd_hash.hex() == stored_hash
    
    def create_user(self, username, email, password):
        """Create a new user account"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Hash the password
            password_hash = self.hash_password(password)
            
            # Insert user
            cursor.execute('''
                INSERT INTO users (username, email, password_hash)
                VALUES (?, ?, ?)
            ''', (username, email, password_hash))
            
            conn.commit()
            conn.close()
            return True, "Account created successfully!"
        
        except sqlite3.IntegrityError as e:
            if "username" in str(e):
                return False, "Username already exists!"
            elif "email" in str(e):
                return False, "Email already registered!"
            else:
                return False, "Error creating account!"
        except Exception as e:
            return False, f"Error: {str(e)}"
    
    def verify_user(self, username_or_email, password):
        """Verify user credentials for login"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Check if input is email or username
            cursor.execute('''
                SELECT username, email, password_hash FROM users
                WHERE username = ? OR email = ?
            ''', (username_or_email, username_or_email))
            
            result = cursor.fetchone()
            conn.close()
            
            if result is None:
                return False, None, "User not found!"
            
            username, email, stored_password = result
            
            # Verify password
            if self.verify_password(stored_password, password):
                return True, {"username": username, "email": email}, "Login successful!"
            else:
                return False, None, "Incorrect password!"
        
        except Exception as e:
            return False, None, f"Error: {str(e)}"
    
    def get_user_info(self, username):
        """Get user information by username"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT username, email, created_at FROM users
                WHERE username = ?
            ''', (username,))
            
            result = cursor.fetchone()
            conn.close()
            
            if result:
                return {
                    "username": result[0],
                    "email": result[1],
                    "created_at": result[2]
                }
            return None
        
        except Exception as e:
            return None
