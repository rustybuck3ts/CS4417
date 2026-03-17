import pytest
import os
import sqlite3
from app import app
import database

@pytest.fixture
def client():
    # Configure app for testing
    app.config['TESTING'] = True
    app.config['WTF_CSRF_ENABLED'] = False # Disable CSRF for easier testing of inputs
    
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
