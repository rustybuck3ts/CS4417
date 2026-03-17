from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_wtf.csrf import CSRFProtect
from markupsafe import escape
import database
import os

app = Flask(__name__)
# Secure secret key for sessions and CSRF
app.secret_key = os.urandom(32)
# Enable CSRF Protection globally
csrf = CSRFProtect(app)

@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    feedback_entries = database.get_all_feedback()
    return render_template('index.html', feedback_entries=feedback_entries)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        
        if not username or not password:
            flash("Username and password required.", "error")
            return render_template('register.html')
            
        if database.create_user(username, password):
            flash("Registration successful. Please log in.", "success")
            return redirect(url_for('login'))
        else:
            flash("Username already exists.", "error")
            
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        
        user_id, role = database.verify_user(username, password)
        if user_id:
            # Regenerate session ID and store user_id (Least privilege context)
            session.clear()
            session['user_id'] = user_id
            session['username'] = username
            session['role'] = role
            return redirect(url_for('index'))
        else:
            flash("Invalid credentials.", "error")
            
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for('login'))

@app.route('/feedback', methods=['GET', 'POST'])
def feedback():
    if 'user_id' not in session:
        flash("You need to log in to submit feedback.", "error")
        return redirect(url_for('login'))
        
    if request.method == 'POST':
        # Sanitize / escape input against XSS
        message = escape(request.form['message'].strip())
        
        if not message:
            flash("Feedback cannot be empty.", "error")
        else:
            database.insert_feedback(session['user_id'], message)
            flash("Feedback submitted successfully.", "success")
            return redirect(url_for('index'))
            
    return render_template('feedback.html')

@app.route('/admin')
def admin():
    if session.get('role') != 'admin':
        flash("Unauthorized access.", "error")
        return redirect(url_for('index'))
    
    users = database.get_all_users()
    feedback_entries = database.get_all_feedback()
    return render_template('admin.html', users=users, feedback_entries=feedback_entries)

@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
def delete_user(user_id):
    if session.get('role') != 'admin':
        flash("Unauthorized access.", "error")
        return redirect(url_for('index'))
        
    if user_id == session.get('user_id'):
        flash("Cannot delete yourself.", "error")
        return redirect(url_for('admin'))
        
    database.delete_user(user_id)
    flash(f"User {user_id} deleted successfully.", "success")
    return redirect(url_for('admin'))

@app.route('/admin/delete_feedback/<int:feedback_id>', methods=['POST'])
def delete_feedback(feedback_id):
    if session.get('role') != 'admin':
        flash("Unauthorized access.", "error")
        return redirect(url_for('index'))
        
    database.delete_feedback(feedback_id)
    flash(f"Feedback {feedback_id} deleted successfully.", "success")
    return redirect(url_for('admin'))

@app.route('/change_password/<int:user_id>', methods=['POST'])
def change_password(user_id):
    if 'user_id' not in session:
        flash("You need to log in.", "error")
        return redirect(url_for('login'))
        
    if user_id != session['user_id'] and session.get('role') != 'admin':
        flash("Unauthorized access.", "error")
        return redirect(url_for('index'))
        
    new_password = request.form.get('new_password', '')
    if not new_password:
        flash("Password cannot be empty.", "error")
    else:
        database.change_password(user_id, new_password)
        flash("Password changed successfully.", "success")
        
    if session.get('role') == 'admin' and user_id != session['user_id']:
        return redirect(url_for('admin'))
    return redirect(url_for('index'))

@app.route('/admin/promote_user/<int:user_id>', methods=['POST'])
def promote_user(user_id):
    if session.get('role') != 'admin':
        flash("Unauthorized access.", "error")
        return redirect(url_for('index'))
        
    database.promote_user(user_id)
    flash(f"User {user_id} promoted to admin successfully.", "success")
    return redirect(url_for('admin'))


if __name__ == '__main__':
    # Initialize DB before running
    if not os.path.exists('app.db'):
        database.init_db()
    
    # Use standard Flask dev server
    app.run(debug=True)
