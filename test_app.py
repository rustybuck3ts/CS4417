import pytest
import os
import sqlite3
from app import app, limiter
import database

@pytest.fixture
def client():
    # Configure app for testing
    app.config['TESTING'] = True
    app.config['WTF_CSRF_ENABLED'] = False # Disable CSRF for easier testing of inputs
    limiter.enabled = False # Explicitly disable limiter object
    
    # Overwrite the database to be a test DB temporarily
    database.DATABASE = 'test_app.db'
    
    with app.test_client() as client:
        with app.app_context():
            database.init_db()
        yield client

    # Cleanup after test
    if os.path.exists('test_app.db'):
        os.remove('test_app.db')

def test_register_and_login(client):
    """Test user registration and subsequent login."""
    # Register
    rv = client.post('/register', data=dict(
        username='testuser',
        password='testpassword'
    ), follow_redirects=True)
    assert b'Registration successful' in rv.data

    # Login
    rv = client.post('/login', data=dict(
        username='testuser',
        password='testpassword'
    ), follow_redirects=True)
    assert b'Welcome, testuser' in rv.data

def test_sql_injection_login(client):
    """Test that SQL injection in login fails (tests parameterized queries)."""
    # Create valid user first
    database.create_user('admin', 'adminpass')
    
    # Attempt SQL injection to bypass login
    rv = client.post('/login', data=dict(
        username="admin' OR '1'='1",
        password="any"
    ), follow_redirects=True)
    
    # Should not log in as admin
    assert b'Invalid credentials' in rv.data
    assert b'Welcome, admin' not in rv.data

def test_xss_protection_feedback(client):
    """Test that XSS payloads are filtered in feedback (tests Jinja/MarkupSafe escaping)."""
    # Create and login user
    database.create_user('testuser', 'testpassword')
    client.post('/login', data=dict(username='testuser', password='testpassword'), follow_redirects=True)

    # Submit malicious feedback
    xss_payload = "<script>alert('xss')</script>"
    rv = client.post('/feedback', data=dict(
        message=xss_payload
    ), follow_redirects=True)
    
    # Check that feedback is submitted successfully
    assert b'Feedback submitted successfully' in rv.data
    
    # Check that the script tags are escaped in the output
    rv = client.get('/')
    assert b'&lt;script&gt;alert(' in rv.data
    assert b'<script>alert(\'xss\')</script>' not in rv.data

def test_change_password(client):
    """Test user changing their own password."""
    database.create_user('testuser', 'oldpass')
    # Login
    client.post('/login', data=dict(username='testuser', password='oldpass'))
    
    with app.app_context():
        conn = database.get_db_connection()
        user_id = conn.execute("SELECT id FROM users WHERE username='testuser'").fetchone()['id']
        conn.close()

    rv = client.post(f'/change_password/{user_id}', data=dict(new_password='newpass'), follow_redirects=True)
    assert b'Password changed successfully' in rv.data
    
    # Logout and login with new password
    client.get('/logout')
    rv = client.post('/login', data=dict(username='testuser', password='newpass'), follow_redirects=True)
    assert b'Welcome, testuser' in rv.data

def test_admin_promote_and_change_user_password(client):
    """Test admin changing another user's password and promoting them."""
    database.create_user('admin', 'adminpass')
    
    with app.app_context():
        conn = database.get_db_connection()
        admin_id = conn.execute("SELECT id FROM users WHERE username='admin'").fetchone()['id']
        conn.close()
    
    database.promote_user(admin_id) # Promote admin
    database.create_user('normaluser', 'userpass')

    with app.app_context():
        conn = database.get_db_connection()
        user_id = conn.execute("SELECT id FROM users WHERE username='normaluser'").fetchone()['id']
        conn.close()

    # Login as admin
    client.post('/login', data=dict(username='admin', password='adminpass'))

    # Change user's password
    rv = client.post(f'/change_password/{user_id}', data=dict(new_password='adminsetpass'), follow_redirects=True)
    assert b'Password changed successfully' in rv.data

    # Promote user
    rv = client.post(f'/admin/promote_user/{user_id}', data=dict(), follow_redirects=True)
    assert b'promoted to admin successfully' in rv.data

    # Check if user can login with new password and access admin page
    client.get('/logout')
    rv = client.post('/login', data=dict(username='normaluser', password='adminsetpass'), follow_redirects=True)
    assert b'Welcome, normaluser' in rv.data
    
    rv = client.get('/admin')
    assert b'Admin Dashboard' in rv.data

def test_index_redirect_not_logged_in(client):
    rv = client.get('/', follow_redirects=False)
    assert rv.status_code == 302
    assert '/login' in rv.location

def test_registration_validation(client):
    # Empty username
    rv = client.post('/register', data=dict(username='', password='pass'), follow_redirects=True)
    assert b'Username and password required' in rv.data
    # Empty password
    rv = client.post('/register', data=dict(username='user', password=''), follow_redirects=True)
    assert b'Username and password required' in rv.data
    # Duplicate username
    database.create_user('existing', 'pass')
    rv = client.post('/register', data=dict(username='existing', password='newpass'), follow_redirects=True)
    assert b'Username already exists' in rv.data

def test_login_validation(client):
    rv = client.post('/login', data=dict(username='', password='p'), follow_redirects=True)
    assert b'Invalid credentials' in rv.data

def test_logout(client):
    database.create_user('logmeout', 'pass')
    client.post('/login', data=dict(username='logmeout', password='pass'))
    rv = client.get('/logout', follow_redirects=True)
    assert b'You have been logged out' in rv.data
    # Should redirect to login on index
    rv = client.get('/', follow_redirects=False)
    assert rv.status_code == 302

def test_feedback_validation(client):
    database.create_user('fuser', 'pass')
    client.post('/login', data=dict(username='fuser', password='pass'))
    rv = client.post('/feedback', data=dict(message='   '), follow_redirects=True)
    assert b'Feedback cannot be empty' in rv.data

def test_unauthorized_admin_access(client):
    database.create_user('normal', 'pass')
    client.post('/login', data=dict(username='normal', password='pass'))
    rv = client.get('/admin', follow_redirects=True)
    assert b'Unauthorized access' in rv.data

def test_unauthorized_user_deletion(client):
    database.create_user('normal', 'pass')
    database.create_user('other', 'pass')
    
    with app.app_context():
        conn = database.get_db_connection()
        other_id = conn.execute("SELECT id FROM users WHERE username='other'").fetchone()['id']
        conn.close()

    client.post('/login', data=dict(username='normal', password='pass'))
    rv = client.post(f'/admin/delete_user/{other_id}', follow_redirects=True)
    assert b'Unauthorized access' in rv.data

    with app.app_context():
        conn = database.get_db_connection()
        exists = conn.execute("SELECT id FROM users WHERE id=?", (other_id,)).fetchone()
        conn.close()
    assert exists is not None

def test_unauthorized_feedback_deletion(client):
    database.create_user('admin2', 'pass')
    with app.app_context():
        conn = database.get_db_connection()
        admin_id = conn.execute("SELECT id FROM users WHERE username='admin2'").fetchone()['id']
        conn.close()
    database.promote_user(admin_id)
    database.insert_feedback(admin_id, 'test feedback')
    
    with app.app_context():
        conn = database.get_db_connection()
        f_id = conn.execute("SELECT id FROM feedback LIMIT 1").fetchone()['id']
        conn.close()

    database.create_user('normal', 'pass')
    client.post('/login', data=dict(username='normal', password='pass'))
    rv = client.post(f'/admin/delete_feedback/{f_id}', follow_redirects=True)
    assert b'Unauthorized access' in rv.data

def test_unauthorized_promotion(client):
    database.create_user('normal', 'pass')
    database.create_user('other', 'pass')
    with app.app_context():
        conn = database.get_db_connection()
        other_id = conn.execute("SELECT id FROM users WHERE username='other'").fetchone()['id']
        conn.close()

    client.post('/login', data=dict(username='normal', password='pass'))
    rv = client.post(f'/admin/promote_user/{other_id}', follow_redirects=True)
    assert b'Unauthorized access' in rv.data
    
    with app.app_context():
        conn = database.get_db_connection()
        role = conn.execute("SELECT role FROM users WHERE id=?", (other_id,)).fetchone()['role']
        conn.close()
    assert role == 'user'

def test_admin_delete_self(client):
    database.create_user('admin3', 'pass')
    with app.app_context():
        conn = database.get_db_connection()
        admin_id = conn.execute("SELECT id FROM users WHERE username='admin3'").fetchone()['id']
        conn.close()
    database.promote_user(admin_id)
    
    client.post('/login', data=dict(username='admin3', password='pass'))
    rv = client.post(f'/admin/delete_user/{admin_id}', follow_redirects=True)
    assert b'Cannot delete yourself' in rv.data

def test_admin_delete_feedback(client):
    database.create_user('admin4', 'pass')
    with app.app_context():
        conn = database.get_db_connection()
        admin_id = conn.execute("SELECT id FROM users WHERE username='admin4'").fetchone()['id']
        conn.close()
    database.promote_user(admin_id)
    database.insert_feedback(admin_id, 'to be deleted')
    
    with app.app_context():
        conn = database.get_db_connection()
        f_id = conn.execute("SELECT id FROM feedback ORDER BY id DESC LIMIT 1").fetchone()['id']
        conn.close()

    client.post('/login', data=dict(username='admin4', password='pass'))
    rv = client.post(f'/admin/delete_feedback/{f_id}', follow_redirects=True)
    assert b'deleted successfully' in rv.data
    
    with app.app_context():
        conn = database.get_db_connection()
        deleted_f = conn.execute("SELECT id FROM feedback WHERE id=?", (f_id,)).fetchone()
        conn.close()
    assert deleted_f is None

def test_unauthorized_password_change(client):
    database.create_user('vic', 'pass')
    database.create_user('att', 'pass')
    with app.app_context():
        conn = database.get_db_connection()
        vic_id = conn.execute("SELECT id FROM users WHERE username='vic'").fetchone()['id']
        conn.close()

    client.post('/login', data=dict(username='att', password='pass'))
    rv = client.post(f'/change_password/{vic_id}', data=dict(new_password='hacked'), follow_redirects=True)
    assert b'Unauthorized access' in rv.data

