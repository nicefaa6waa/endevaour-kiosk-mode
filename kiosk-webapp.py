#!/usr/bin/env python3

import os
import subprocess
from flask import Flask, request, session, redirect, url_for, render_template_string, flash

app = Flask(__name__)
app.secret_key = os.environ.get('KIOSK_SECRET_KEY', 'default_secret_key_change_me')  # Set via env or replace

# These will be set dynamically by the installer via sed or env
KIOSK_USER = os.environ.get('KIOSK_USER', 'kiosk')  # Fallback
KIOSK_PASS = os.environ.get('KIOSK_PASS', '')  # Fallback - set securely

def logged_in():
    return session.get('logged_in', False)

@app.before_request
def require_login():
    if request.endpoint and request.endpoint != 'login' and request.endpoint != 'static' and not logged_in():
        return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        if request.form['username'] == KIOSK_USER and request.form['password'] == KIOSK_PASS:
            session['logged_in'] = True
            flash('Logged in successfully')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid credentials')
    return render_template_string('''
<!DOCTYPE html>
<html><head><title>Kiosk Login</title></head><body>
<h1>Kiosk Control Login</h1>
<form method="post">
    Username: <input type="text" name="username"><br><br>
    Password: <input type="password" name="password"><br><br>
    <input type="submit" value="Login">
</form>
{% with messages = get_flashed_messages() %}
  {% if messages %}
    <ul>
    {% for message in messages %}
      <li>{{ message }}</li>
    {% endfor %}
    </ul>
  {% endif %}
{% endwith %}
</body></html>
    ''')

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    flash('Logged out successfully')
    return redirect(url_for('login'))

@app.route('/')
def dashboard():
    try:
        status_output = subprocess.check_output(['/usr/local/bin/kiosk-status']).decode('utf-8')
    except:
        status_output = "Error getting status"
    try:
        with open('/etc/kiosk/config', 'r') as f:
            lines = f.readlines()
            url_line = [line for line in lines if 'KIOSK_URL' in line][0]
            current_url = url_line.split('=')[1].strip().strip('"')
    except:
        current_url = "Unknown"
    return render_template_string('''
<!DOCTYPE html>
<html><head><title>Kiosk Dashboard</title></head><body>
<h1>Kiosk Dashboard</h1>
<p><a href="/logout">Logout</a></p>
<h2>Current URL: {{ current_url }}</h2>
<h2>Status</h2>
<pre>{{ status_output }}</pre>
<h2>Update URL</h2>
<form method="post" action="/update_url">
    New URL: <input type="text" name="new_url" value="{{ current_url }}"><br><br>
    <input type="submit" value="Update URL">
</form>
<h2>Controls</h2>
<p><a href="/restart_browser">Restart Browser</a></p>
<p><a href="/reboot" onclick="return confirm('Reboot the system?')">Reboot System</a></p>
{% with messages = get_flashed_messages() %}
  {% if messages %}
    <ul>
    {% for message in messages %}
      <li>{{ message }}</li>
    {% endfor %}
    </ul>
  {% endif %}
{% endwith %}
</body></html>
    ''', status_output=status_output, current_url=current_url)

@app.route('/update_url', methods=['POST'])
def update_url():
    new_url = request.form['new_url']
    try:
        subprocess.run(['sed', '-i', f's|KIOSK_URL=.*|KIOSK_URL=\\"{new_url}\\"|g', '/etc/kiosk/config'], check=True)
        flash('URL updated successfully. Restart browser or reboot to apply.')
    except Exception as e:
        flash(f'Error updating URL: {str(e)}')
    return redirect(url_for('dashboard'))

@app.route('/restart_browser')
def restart_browser():
    try:
        subprocess.run(['pkill', '-f', 'firefox'], check=True)
        flash('Browser restarted successfully.')
    except Exception as e:
        flash(f'Error restarting browser: {str(e)}')
    return redirect(url_for('dashboard'))

@app.route('/reboot')
def reboot():
    os.system('reboot')
    return 'Rebooting...'

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=False)
