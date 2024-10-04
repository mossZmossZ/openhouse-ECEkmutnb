from flask import Flask, render_template, request, redirect, url_for, session
import sqlite3
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'supersecretkey'

# Admin credentials for CTF
ADMIN_USERNAME = 'Admin'
ADMIN_PASSWORD = 'P@ssw0rd'

# Dashboard login credentials
DASHBOARD_USERNAME = 'root'
DASHBOARD_PASSWORD = 'password'

# SQLite database setup
DATABASE = 'logs.db'

# Function to connect to SQLite database
def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

# Function to log IP and timestamp into the database for the /admin route
def log_ip(ip, route):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    conn = get_db_connection()
    conn.execute('INSERT INTO logs (ip, timestamp, route) VALUES (?, ?, ?)', (ip, timestamp, route))
    conn.commit()
    conn.close()

# Home route (CTF login page)
@app.route('/')
def home():
    return render_template('index.html')

# CTF Login route
@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']

    # Check if username and password are correct for CTF admin
    if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
        session['admin_logged_in'] = True  # Set session to indicate admin is logged in
        return redirect(url_for('admin_page'))  # Redirect to the admin page

    # If username is correct but password is wrong
    elif username == ADMIN_USERNAME and password != ADMIN_PASSWORD:
        return render_template('index.html', wrong_password=True, wrong_username=False)

    # If both username and password are wrong
    else:
        return render_template('index.html', wrong_password=True, wrong_username=True)

# CTF Admin page with flag (log access only for /admin)
@app.route('/admin')
def admin_page():
    if not session.get('admin_logged_in'):
        return redirect(url_for('home'))

    ip = request.remote_addr  # Log IP when /admin page is accessed
    log_ip(ip, '/admin')

    return render_template('admin_flag.html', flag='flag{admin_ctf_challenge}')

# Separate login for dashboard
@app.route('/dashboard_login', methods=['GET', 'POST'])
def dashboard_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Check if the username and password are correct for the dashboard
        if username == DASHBOARD_USERNAME and password == DASHBOARD_PASSWORD:
            session['dashboard_logged_in'] = True
            return redirect(url_for('dashboard'))

        return render_template('dashboard_login.html', error=True)

    return render_template('dashboard_login.html')

# Dashboard route (requires login) - Ensure this is defined only once
@app.route('/dashboard')
def dashboard():
    if not session.get('dashboard_logged_in'):
        return redirect(url_for('dashboard_login'))

    # Fetch IP logs from SQLite database
    conn = get_db_connection()
    logs = conn.execute('SELECT ip, timestamp, route FROM logs WHERE route = "/admin"').fetchall()
    
    # Get the count of logs
    log_count = conn.execute('SELECT COUNT(*) FROM logs WHERE route = "/admin"').fetchone()[0]
    
    conn.close()

    return render_template('dashboard.html', logs=logs, log_count=log_count)

# Route to clear all log data
@app.route('/clear_logs', methods=['POST'])
def clear_logs():
    if not session.get('dashboard_logged_in'):
        return redirect(url_for('dashboard_login'))

    # Connect to the database and clear logs
    conn = get_db_connection()
    conn.execute('DELETE FROM logs')
    conn.commit()
    conn.close()

    return redirect(url_for('dashboard'))

# Logout route for both CTF and Dashboard
@app.route('/logout')
def logout():
    session.pop('dashboard_logged_in', None)
    session.pop('admin_logged_in', None)
    return redirect(url_for('home'))

if __name__ == '__main__':
    # Ensure the database and table exist for logging
    conn = get_db_connection()
    conn.execute('''CREATE TABLE IF NOT EXISTS logs (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        ip TEXT NOT NULL,
                        timestamp TEXT NOT NULL,
                        route TEXT NOT NULL
                    )''')
    conn.commit()
    conn.close()

    app.run(debug=True)
