from flask import Flask, request, render_template, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_session import Session
import time
import json
import os
import re

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# Flask-Limiter for rate limiting
limiter = Limiter(get_remote_address, app=app)

# Flask-Session for session management
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_PERMANENT'] = False
app.config['PERMANENT_SESSION_LIFETIME'] = 900  # 15 minutes
Session(app)

# Load users from JSON file
USERS_FILE = 'users.json'
if not os.path.exists(USERS_FILE):
    with open(USERS_FILE, 'w') as f:
        json.dump({}, f)

def load_users():
    with open(USERS_FILE, 'r') as f:
        return json.load(f)

def save_users(users):
    with open(USERS_FILE, 'w') as f:
        json.dump(users, f)

users = load_users()

# Track failed login attempts
failed_attempts = {}

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form.get('role', 'user')

        # Check if the username already exists
        if username in users:
            flash(f'The username "{username}" is already registered. Please choose a different username or log in.', 'error')
            return redirect(url_for('register'))

        # Validate password constraints
        password_constraints = r'^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[!@#$%^&*(),.?":{}|<>]).{8,}$'
        if not re.match(password_constraints, password):
            flash('Password must be at least 8 characters long, contain 1 uppercase letter, 1 lowercase letter, 1 digit, and 1 special character.', 'error')
            return redirect(url_for('register'))

        # Hash the password before saving
        hashed_password = generate_password_hash(password)
        users[username] = {'password': hashed_password, 'role': role}
        save_users(users)
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per 3 minutes", key_func=get_remote_address)
def login():
    global failed_attempts

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        recaptcha_response = request.form.get('g-recaptcha-response')

        # Initialize failed attempts for the user
        if username not in failed_attempts:
            failed_attempts[username] = {'count': 0, 'blocked_until': None}

        # Check if the user is blocked
        if failed_attempts[username]['blocked_until']:
            if time.time() < failed_attempts[username]['blocked_until']:
                remaining_time = int(failed_attempts[username]['blocked_until'] - time.time())
                flash(f'You are blocked from logging in. Try again in {remaining_time} seconds.', 'error')
                return render_template('login.html', show_captcha=True, attempts=failed_attempts[username]['count'])

        # Check if the user has failed login 3 times
        if failed_attempts[username]['count'] >= 3:
            if not recaptcha_response:
                flash('Please complete the CAPTCHA to continue.', 'error')
                return render_template('login.html', show_captcha=True, attempts=failed_attempts[username]['count'])

        user = users.get(username)
        if not user or not check_password_hash(user['password'], password):
            failed_attempts[username]['count'] += 1

            # Block the user after 5 failed attempts
            if failed_attempts[username]['count'] >= 3:
                failed_attempts[username]['blocked_until'] = time.time() + 180  # Block for 3 minutes
                flash('Too many failed attempts. You are blocked for 3 minutes.', 'error')
                return render_template('login.html', show_captcha=True, attempts=failed_attempts[username]['count'])

            flash(f'Invalid username or password. Attempt {failed_attempts[username]["count"]}/5.', 'error')
            return render_template('login.html', show_captcha=failed_attempts[username]['count'] >= 3, attempts=failed_attempts[username]['count'])

        # Reset failed attempts on successful login
        failed_attempts[username] = {'count': 0, 'blocked_until': None}

        # Store user information in the session
        session['username'] = username
        session['role'] = user['role']
        session['last_activity'] = time.time()
        flash('Login successful!', 'success')
        return redirect(url_for('dashboard'))

    return render_template('login.html', show_captcha=False, attempts=0)

@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        flash('Unauthorized access. Please log in.', 'error')
        return redirect(url_for('login'))

    # Check for session timeout
    if time.time() - session.get('last_activity', 0) > 900:  # 15 minutes
        session.clear()
        flash('Session timed out. Please log in again.', 'error')
        return redirect(url_for('login'))

    session['last_activity'] = time.time()  # Update last activity time
    username = session['username']
    user_files = users.get(username, {}).get('files', [])
    return render_template('dashboard.html', username=username, files=user_files)

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully.', 'success')
    return redirect(url_for('home'))

@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    if 'username' not in session:
        flash('Unauthorized access. Please log in.', 'error')
        return redirect(url_for('login'))

    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file provided.', 'error')
            return redirect(url_for('upload_file'))

        file = request.files['file']
        if file.filename == '':
            flash('No selected file.', 'error')
            return redirect(url_for('upload_file'))

        if file and file.filename.endswith('.pdf'):
            username = session['username']
            user_files = users.get(username, {}).get('files', [])

            # Check if the file already exists for the user
            if file.filename in user_files:
                flash(f'The file "{file.filename}" already exists in your uploads.', 'error')
                return redirect(url_for('dashboard'))

            # Save the file to the uploads folder
            filepath = os.path.join('uploads', file.filename)
            file.save(filepath)

            # Add the file to the user's file list
            users[username].setdefault('files', []).append(file.filename)
            save_users(users)
            flash('File uploaded successfully!', 'success')
            return redirect(url_for('dashboard'))

        flash('Invalid file type. Only PDF files are allowed.', 'error')
        return redirect(url_for('upload_file'))

    return render_template('upload.html')

@app.route('/delete', methods=['POST'])
def delete_file():
    if 'username' not in session:
        flash('Unauthorized access. Please log in.', 'error')
        return redirect(url_for('login'))

    username = session['username']
    filename = request.form.get('filename')

    # Check if the file exists in the user's file list
    if filename in users.get(username, {}).get('files', []):
        # Remove the file from the user's file list
        users[username]['files'].remove(filename)
        save_users(users)

        # Delete the file from the uploads folder
        filepath = os.path.join('uploads', filename)
        if os.path.exists(filepath):
            os.remove(filepath)

        flash(f'The file "{filename}" has been deleted successfully.', 'success')
    else:
        flash('File not found or unauthorized action.', 'error')

    return redirect(url_for('dashboard'))

if __name__ == '__main__':
    app.run(debug=True)