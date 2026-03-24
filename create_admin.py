import sys
import getpass
import sqlite3
from database import get_db_connection
import bcrypt

def create_admin(username, password):
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')
    
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute("INSERT INTO users (username, password_hash, role) VALUES (?, ?, 'admin')", (username, hashed))
        conn.commit()
        print(f"Successfully created admin user: {username}")
    except sqlite3.IntegrityError:
        print(f"Error: User '{username}' already exists.")
    finally:
        conn.close()

if __name__ == '__main__':
    if len(sys.argv) > 1:
        username = sys.argv[1]
    else:
        username = input("Enter admin username: ")
        
    password = getpass.getpass("Enter admin password: ")
    confirm_password = getpass.getpass("Confirm admin password: ")
    
    if password != confirm_password:
        print("Passwords do not match. Aborting.")
        sys.exit(1)
        
    if not username or not password:
        print("Username and password cannot be empty.")
        sys.exit(1)
        
    create_admin(username, password)
