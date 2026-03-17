import sqlite3
import bcrypt

DATABASE = 'app.db'

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    with open('schema.sql', 'r') as f:
        conn.executescript(f.read())
    conn.commit()
    conn.close()

def create_user(username, password):
    # Hash password with bcrypt
    salt = bcrypt.gensalt()
    # It must be string to store in DB
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')
    
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        # Parameterized query to prevent SQL Injection
        cur.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, hashed))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()

def verify_user(username, password):
    conn = get_db_connection()
    cur = conn.cursor()
    # Parameterized query to prevent SQL Injection
    user = cur.execute("SELECT id, password_hash, role FROM users WHERE username = ?", (username,)).fetchone()
    conn.close()
    
    if user:
        if bcrypt.checkpw(password.encode('utf-8'), user['password_hash'].encode('utf-8')):
            return user['id'], user['role']
    return None, None

def insert_feedback(user_id, message):
    conn = get_db_connection()
    cur = conn.cursor()
    # Parameterized query to prevent SQL Injection
    cur.execute("INSERT INTO feedback (user_id, message) VALUES (?, ?)", (user_id, message))
    conn.commit()
    conn.close()

def get_all_feedback():
    conn = get_db_connection()
    # Join queries to fetch feedback and the username who posted it
    feedback = conn.execute(
        "SELECT f.id, f.message, f.timestamp, u.username "
        "FROM feedback f JOIN users u ON f.user_id = u.id "
        "ORDER BY f.timestamp DESC"
    ).fetchall()
    conn.close()
    return feedback

def get_all_users():
    conn = get_db_connection()
    users = conn.execute("SELECT id, username, role FROM users ORDER BY id").fetchall()
    conn.close()
    return users

def delete_user(user_id):
    conn = get_db_connection()
    cur = conn.cursor()
    # Delete their feedback first due to foreign keys. Better to manually delete here.
    cur.execute("DELETE FROM feedback WHERE user_id = ?", (user_id,))
    cur.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()

def delete_feedback(feedback_id):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("DELETE FROM feedback WHERE id = ?", (feedback_id,))
    conn.commit()
    conn.close()

def change_password(user_id, new_password):
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(new_password.encode('utf-8'), salt).decode('utf-8')
    
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("UPDATE users SET password_hash = ? WHERE id = ?", (hashed, user_id))
    conn.commit()
    conn.close()

def promote_user(user_id):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("UPDATE users SET role = 'admin' WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()
