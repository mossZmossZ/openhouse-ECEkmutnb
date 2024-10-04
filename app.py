from flask import Flask, render_template, request, redirect, url_for

app = Flask(__name__)
app.secret_key = 'supersecretkey'

# Admin's MD5 hashed password (hash of 'admin')
ADMIN_HASH = '21232f297a57a5a743894a0e4a801fc3'

@app.route('/')
def home():
    return render_template('index.html')

# Login route
@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']

    # Check if username and password are both 'admin'
    if username == 'admin' and password == 'admin':
        # Redirect to the 'Is Admin?' page
        return render_template('admin_check.html', is_admin=True)

    # Check if the password is the MD5 hash of 'admin' (for admin flag page)
    elif username == 'admin' and password == ADMIN_HASH:
        # Redirect to the flag page
        return redirect(url_for('admin_page'))

    # If credentials don't match, redirect back to the home page
    return redirect(url_for('home'))

# Admin page with flag (only accessible with MD5 password)
@app.route('/admin')
def admin_page():
    return render_template('admin_flag.html', flag='flag{admin_ctf_challenge}')

# Logout route (just redirects to home without sessions)
@app.route('/logout')
def logout():
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)
