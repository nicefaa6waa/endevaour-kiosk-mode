#!/usr/bin/env python3

import os
import subprocess
from flask import Flask, request, session, redirect, url_for, render_template_string, flash

app = Flask(__name__)
app.secret_key = os.environ.get('KIOSK_SECRET_KEY', 'default_secret_key_change_me')  # Set via env or replace

# These will be set dynamically by the installer via env
KIOSK_USER = os.environ.get('KIOSK_USER', 'kiosk')  # Fallback
KIOSK_PASS = os.environ.get('KIOSK_PASS', '')  # Fallback - set securely

toggle_flags = {
    "infobars": ("--disable-infobars", "Disable Info Bars"),
    "hang_monitor": ("--disable-hang-monitor", "Disable Hang Monitor"),
    "translate_ui": ("--disable-features=TranslateUI", "Disable Translate UI"),
    "overscroll_history": ("--overscroll-history-navigation=0", "Disable Overscroll History Navigation"),
    "pinch": ("--disable-pinch", "Disable Pinch"),
    "notifications": ("--disable-notifications", "Disable Notifications"),
    "popup_blocking": ("--disable-popup-blocking", "Disable Popup Blocking"),
    "dev_shm_usage": ("--disable-dev-shm-usage", "Disable Dev SHM Usage"),
    "extensions": ("--disable-extensions", "Disable Extensions"),
    "speech_api": ("--disable-speech-api", "Disable Speech API"),
    "background_timer_throttling": ("--disable-background-timer-throttling", "Disable Background Timer Throttling"),
    "renderer_backgrounding": ("--disable-renderer-backgrounding", "Disable Renderer Backgrounding"),
    "backgrounding_occluded_windows": ("--disable-backgrounding-occluded-windows", "Disable Backgrounding Occluded Windows"),
    "component_update": ("--disable-component-update", "Disable Component Update"),
    "sync": ("--disable-sync", "Disable Sync"),
    "default_apps": ("--disable-default-apps", "Disable Default Apps"),
}

all_prefs = list(toggle_flags.keys())
pref_names = {k: d for k, (_, d) in toggle_flags.items()}

fixed_flags = [
    '--user-data-dir=/home/$KIOSK_USER/.chrome-kiosk',
    '--kiosk "$KIOSK_URL"',
    '--no-first-run',
]

def load_prefs_states():
    states = {p: False for p in all_prefs}
    autostart_path = f"/home/{KIOSK_USER}/.config/openbox/autostart"
    if os.path.exists(autostart_path):
        with open(autostart_path, 'r') as f:
            content = f.read()
            for pref in all_prefs:
                flag, _ = toggle_flags[pref]
                if flag in content:
                    states[pref] = True
    return states

def save_prefs(form_states):
    selected = []
    for pref in all_prefs:
        if f"disable_{pref}" in form_states:
            flag, _ = toggle_flags[pref]
            selected.append(flag)

    all_flags_list = fixed_flags + selected
    chrome_cmd = "google-chrome-stable \\\\\n        " + " \\\\\n        ".join(all_flags_list) + " &"

    start_browser_func = f'''start_browser() {{
    # Load configuration each time to pick up changes
    if [ -f /etc/kiosk/config ]; then
        source /etc/kiosk/config
    else
        echo "Kiosk config not found. Exiting." >&2
        exit 1
    fi

    {chrome_cmd}
}}'''

    monitor_part = '''# Monitor browser process and restart if closed (use pgrep for robustness, check all chrome)
while true; do
    if ! pgrep google-chrome > /dev/null 2>&1; then
        echo "Browser crashed or closed. Restarting..." >&2
        # Clean up any stragglers
        pkill -f google-chrome 2>/dev/null || true
        sleep 5
        start_browser
    fi
    sleep 1
done'''

    beginning = '''#!/bin/bash

# Function to start browser in kiosk mode (using chrome)
'''

    full_autostart = beginning + start_browser_func + '\n\n# Ensure clean start: kill any lingering Chrome processes\npkill -f google-chrome 2>/dev/null || true\nsleep 3\n\n# Start the browser\nstart_browser\n\n' + monitor_part

    autostart_path = f"/home/{KIOSK_USER}/.config/openbox/autostart"
    with open(autostart_path, 'w') as f:
        f.write(full_autostart)
    os.chmod(autostart_path, 0o755)
    subprocess.run(["chown", f"{KIOSK_USER}:{KIOSK_USER}", autostart_path], check=False)

def get_usb_status():
    try:
        output = subprocess.check_output(["systemctl", "is-active", "usbguard"]).decode().strip()
        return output == "active"
    except:
        return False

def toggle_usb(enable):
    path = "/etc/usbguard/usbguard-daemon.conf"
    policy_target = "block" if enable else "allow"
    common_conf = f"""RuleFile=/etc/usbguard/rules.conf
ImplicitPolicyTarget={policy_target}
PresentDevicePolicy=apply-policy
PresentControllerPolicy=allow
InsertedDevicePolicy=block
AuthorizedDefault=none
RestoreControllerDeviceState=false
DeviceManagerBackend=uevent
"""
    with open(path, "w") as f:
        f.write(common_conf)

    action = "enable" if enable else "disable"
    subprocess.run(["systemctl", action, "--now", "usbguard"], check=True)

    if enable and not os.path.exists("/etc/usbguard/rules.conf"):
        subprocess.run(["usbguard", "generate-policy"], stdout=open("/etc/usbguard/rules.conf", "w"), check=True)

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
<html><head><title>Kiosk Login</title>
<style>
body { font-family: Arial, sans-serif; max-width: 400px; margin: auto; padding: 20px; }
input { width: 100%; padding: 8px; margin: 5px 0; box-sizing: border-box; }
input[type="submit"] { background: #007bff; color: white; border: none; cursor: pointer; }
ul { color: red; list-style: none; padding: 0; }
</style>
</head><body>
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

@app.route('/', methods=['GET'])
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
    states = load_prefs_states()
    usb_enabled = get_usb_status()
    return render_template_string('''
<!DOCTYPE html>
<html><head><title>Kiosk Dashboard</title>
<style>
body { font-family: Arial, sans-serif; max-width: 800px; margin: auto; padding: 20px; line-height: 1.6; }
h1, h2 { color: #333; border-bottom: 2px solid #007bff; padding-bottom: 5px; }
section { border: 1px solid #ddd; padding: 15px; margin: 15px 0; border-radius: 5px; background: #f9f9f9; }
pre { background: #f4f4f4; padding: 10px; border-radius: 5px; overflow: auto; white-space: pre-wrap; }
input[type="text"], input[type="url"] { width: 70%; padding: 8px; margin: 5px 0; }
input[type="submit"], button { background: #007bff; color: white; padding: 8px 16px; border: none; border-radius: 4px; cursor: pointer; margin: 5px; }
input[type="submit"]:hover, button:hover { background: #0056b3; }
label { display: block; margin: 5px 0; }
ul { color: #dc3545; list-style: none; padding: 0; }
a { color: #007bff; text-decoration: none; }
a:hover { text-decoration: underline; }
hr { border: none; border-top: 1px solid #ddd; margin: 20px 0; }
</style>
</head><body>
<h1>Kiosk Dashboard</h1>
<p><a href="/logout">Logout</a></p>
<hr>

<section>
<h2>Current URL</h2>
<form method="post" action="/update_url">
    New URL: <input type="url" name="new_url" value="{{ current_url }}"><br><br>
    <input type="submit" value="Update URL">
</form>
</section>
<hr>

<section>
<h2>System Status</h2>
<pre>{{ status_output }}</pre>
</section>
<hr>

<section>
<h2>USB Security</h2>
<p>Current Status: <strong>{{ "ON" if usb_enabled else "OFF" }}</strong></p>
<form method="post" action="/toggle_usb">
    <input type="hidden" name="enable" value="{{ 0 if usb_enabled else 1 }}">
    <input type="submit" value="Turn {{ 'OFF' if usb_enabled else 'ON' }} USB Security" onclick="return confirm('Toggle USB Security?');">
</form>
<p><small>Note: Toggling may require replugging USB devices to take effect.</small></p>
</section>
<hr>

<section>
<h2>Chrome Flags</h2>
<form method="post" action="/save_prefs">
    {% for pref in all_prefs %}
        {% set disabled = states[pref] %}
        <label>
            <input type="checkbox" name="disable_{{ pref }}" {{ 'checked' if disabled else '' }}>
            {{ pref_names[pref] }} {% if disabled %}(Disabled){% else %}(Enabled){% endif %}
        </label>
    {% endfor %}
    <br><br>
    <input type="submit" value="Save Flags" onclick="return confirm('Save changes? Restart browser to apply.');">
</form>
<p><small>Checked means the feature is disabled (flag included).</small></p>
</section>
<hr>

<section>
<h2>Controls</h2>
<p><a href="/restart_browser" onclick="return confirm('Restart browser?');">Restart Browser</a></p>
<p><a href="/reboot" onclick="return confirm('Reboot the system?');">Reboot System</a></p>
</section>

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
    ''', status_output=status_output, current_url=current_url, states=states, usb_enabled=usb_enabled, all_prefs=all_prefs, pref_names=pref_names)

@app.route('/update_url', methods=['POST'])
def update_url():
    new_url = request.form['new_url']
    try:
        subprocess.run(['sed', '-i', f's|KIOSK_URL=.*|KIOSK_URL=\\"{new_url}\\"|g', '/etc/kiosk/config'], check=True)
        flash('URL updated successfully. Restart browser to apply.')
    except Exception as e:
        flash(f'Error updating URL: {str(e)}')
    return redirect(url_for('dashboard'))

@app.route('/save_prefs', methods=['POST'])
def save_prefs_route():
    try:
        save_prefs(request.form)
        flash('Chrome flags saved. Restart browser to apply.')
    except Exception as e:
        flash(f'Error saving flags: {str(e)}')
    return redirect(url_for('dashboard'))

@app.route('/toggle_usb', methods=['POST'])
def toggle_usb_route():
    enable = request.form.get('enable') == '1'
    try:
        toggle_usb(enable)
        flash(f'USB Security turned {"ON" if enable else "OFF"}.')
    except Exception as e:
        flash(f'Error toggling USB: {str(e)}')
    return redirect(url_for('dashboard'))

@app.route('/restart_browser')
def restart_browser():
    try:
        subprocess.run(['pkill', '-f', 'google-chrome'], check=True)
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
