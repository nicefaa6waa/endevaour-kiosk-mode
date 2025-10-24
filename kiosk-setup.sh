#!/bin/bash

# EndeavourOS Kiosk Setup Script
# Usage: curl -sSL https://raw.githubusercontent.com/yourusername/yourrepo/main/kiosk-setup.sh | sudo bash

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_status() {
    echo -e "${GREEN}[✓]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

print_error() {
    echo -e "${RED}[✗]${NC} $1"
}

print_info() {
    echo -e "${BLUE}[i]${NC} $1"
}

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    print_error "Please run with sudo"
    exit 1
fi

echo ""
echo "========================================"
echo "  EndeavourOS Kiosk Setup Installer"
echo "========================================"
echo ""

# Interactive prompts
read -p "Enter kiosk username: " KIOSK_USER

# Password input with confirmation
KIOSK_PASS=""
KIOSK_PASS_CONFIRM=""
while [ "$KIOSK_PASS" != "$KIOSK_PASS_CONFIRM" ] || [ -z "$KIOSK_PASS" ]; do
    read -s -p "Enter password for $KIOSK_USER: " KIOSK_PASS
    echo
    read -s -p "Confirm password: " KIOSK_PASS_CONFIRM
    echo
    if [ "$KIOSK_PASS" != "$KIOSK_PASS_CONFIRM" ]; then
        print_error "Passwords do not match. Try again."
    elif [ -z "$KIOSK_PASS" ]; then
        print_error "Password cannot be empty. Try again."
    fi
done

read -p "Enter kiosk URL (e.g., https://example.com): " KIOSK_URL

echo ""
print_info "SSH Key Setup"
echo "Paste your SSH public key (or press Enter to skip):"
read -p "> " SSH_PUBLIC_KEY

# Confirmation
echo ""
echo "========================================"
echo "Configuration Summary:"
echo "========================================"
echo "Username: $KIOSK_USER"
echo "Kiosk URL: $KIOSK_URL"
if [ -n "$SSH_PUBLIC_KEY" ]; then
    echo "SSH Key: Provided"
else
    echo "SSH Key: Not provided (password auth will be used)"
fi
echo ""
read -p "Continue with installation? (y/N): " CONFIRM

if [[ ! "$CONFIRM" =~ ^[Yy]$ ]]; then
    print_error "Installation cancelled"
    exit 1
fi

echo ""
print_status "Starting installation..."

# Update system
print_status "Updating system..."
pacman -Sy --noconfirm

# Install required packages (switched to firefox)
print_status "Installing required packages..."
pacman -S --needed --noconfirm \
    xorg-server \
    xorg-xinit \
    openbox \
    firefox \
    unclutter \
    xdotool \
    openssh \
    usbguard \
    xorg-xset \
    sudo \
    python-flask

# Create kiosk user
print_status "Creating kiosk user..."
if id "$KIOSK_USER" &>/dev/null; then
    print_warning "User $KIOSK_USER already exists, updating configuration..."
else
    useradd -m -s /bin/bash "$KIOSK_USER"
fi

echo "$KIOSK_USER:$KIOSK_PASS" | chpasswd
usermod -aG wheel "$KIOSK_USER" 2>/dev/null || true

# Setup SSH
print_status "Configuring SSH..."
mkdir -p /home/$KIOSK_USER/.ssh
chmod 700 /home/$KIOSK_USER/.ssh

if [ -n "$SSH_PUBLIC_KEY" ]; then
    echo "$SSH_PUBLIC_KEY" > /home/$KIOSK_USER/.ssh/authorized_keys
    chmod 600 /home/$KIOSK_USER/.ssh/authorized_keys
    chown -R $KIOSK_USER:$KIOSK_USER /home/$KIOSK_USER/.ssh
    print_status "SSH key configured"
fi

# Configure SSH daemon
cat > /etc/ssh/sshd_config.d/kiosk.conf <<EOF
# Kiosk SSH Configuration
PermitRootLogin no
PubkeyAuthentication yes
PasswordAuthentication $([ -n "$SSH_PUBLIC_KEY" ] && echo "no" || echo "yes")
AuthorizedKeysFile .ssh/authorized_keys
EOF

systemctl enable sshd.service
systemctl restart sshd.service

# Create config directory
print_status "Creating configuration files..."
mkdir -p /etc/kiosk
cat > /etc/kiosk/config <<EOF
KIOSK_URL="$KIOSK_URL"
KIOSK_USER="$KIOSK_USER"
EOF

chmod 644 /etc/kiosk/config

# Disable display manager and boot to console (FIXED: disable first to avoid symlink conflict)
print_status "Disabling display manager and enabling console boot..."
systemctl disable display-manager.service 2>/dev/null || true
systemctl mask display-manager.service
systemctl set-default multi-user.target
systemctl daemon-reload

# Configure autologin on console tty1
print_status "Configuring autologin for $KIOSK_USER..."
mkdir -p /etc/systemd/system/getty@tty1.service.d/

# Remove any existing autologin configuration
rm -f /etc/systemd/system/getty@tty1.service.d/autologin.conf
rm -f /etc/systemd/system/getty@tty1.service.d/override.conf

# Create new autologin configuration
cat > /etc/systemd/system/getty@tty1.service.d/autologin.conf <<EOF
[Service]
ExecStart=
ExecStart=-/sbin/agetty -o '-p -f -- \\u' --noclear --autologin $KIOSK_USER %I \$TERM
EOF

systemctl daemon-reload
systemctl enable getty@tty1.service

# Create Firefox kiosk profile with custom prefs
print_status "Creating Firefox kiosk profile with custom preferences..."
mkdir -p /home/$KIOSK_USER/.mozilla/firefox/kiosk
cat > /home/$KIOSK_USER/.mozilla/firefox/kiosk/user.js <<EOF
user_pref("media.webspeech.synth.enabled", false);
user_pref("browser.newtabpage.activity-stream.asrouter.enabled", false);
user_pref("browser.newtabpage.activity-stream.asrouter.userprefs.cfr.addons", false);
user_pref("browser.newtabpage.activity-stream.asrouter.userprefs.cfr.features", false);
user_pref("browser.newtabpage.activity-stream.feeds.asrouterfeed", false);
user_pref("browser.messaging-system.whatsNewPanel.enabled", false);
user_pref("browser.vpn_promo.enabled", false);
user_pref("browser.newtabpage.activity-stream.systemtickers", false);
user_pref("app.normandy.enabled", false);
user_pref("browser.gesture.swipe.left", "");
user_pref("browser.gesture.swipe.right", "");
EOF

# Create .xinitrc
print_status "Creating .xinitrc..."
cat > /home/$KIOSK_USER/.xinitrc <<EOF
#!/bin/bash

# Disable screen blanking and power management
xset s off
xset -dpms
xset s noblank

# Hide cursor after inactivity
unclutter -idle 0.1 &

# Start Openbox window manager
exec openbox-session
EOF

chmod +x /home/$KIOSK_USER/.xinitrc

# Create Openbox configuration (improved monitoring)
print_status "Creating Openbox configuration..."
mkdir -p /home/$KIOSK_USER/.config/openbox
cat > /home/$KIOSK_USER/.config/openbox/autostart <<'AUTOSTART_SCRIPT'
#!/bin/bash

# Load configuration if exists
if [ -f /etc/kiosk/config ]; then
    source /etc/kiosk/config
else
    echo "Kiosk config not found. Exiting." >&2
    exit 1
fi

# Function to start browser in kiosk mode (using firefox)
start_browser() {
    firefox \
        --kiosk "$KIOSK_URL" \
        --no-remote \
        --new-instance \
        --disable-infobars \
        --no-first-run \
        --disable-session-crashed-bubble \
        --disable-features=TranslateUI \
        --check-for-update-interval=31536000 \
        --disable-component-update \
        --overscroll-history-navigation=0 \
        --disable-pinch \
        --disable-notifications \
        --disable-popup-blocking \
        --disable-dev-shm-usage \
        --disable-extensions \
        --profile ~/.mozilla/firefox/kiosk &
}

# Ensure clean start: kill any lingering Firefox processes
pkill -f firefox 2>/dev/null || true
sleep 3

# Start the browser
start_browser

# Monitor browser process and restart if closed (use pgrep for robustness, check all firefox)
while true; do
    if ! pgrep firefox > /dev/null 2>&1; then
        echo "Browser crashed or closed. Restarting..." >&2
        # Clean up any stragglers
        pkill -f firefox 2>/dev/null || true
        sleep 5
        start_browser
    fi
    sleep 1
done
AUTOSTART_SCRIPT

chmod +x /home/$KIOSK_USER/.config/openbox/autostart

# Create .bash_profile for auto-start X on console
print_status "Creating .bash_profile..."
cat > /home/$KIOSK_USER/.bash_profile <<EOF
if [[ -z \$DISPLAY ]] && [[ \$(tty) = /dev/tty1 ]]; then
    exec startx
fi
EOF

# Configure USB blocking with USBGuard
print_status "Configuring USBGuard..."
if [ ! -f /etc/usbguard/rules.conf ]; then
    mkdir -p /etc/usbguard
    usbguard generate-policy > /etc/usbguard/rules.conf 2>/dev/null || echo "allow" > /etc/usbguard/rules.conf
fi

cat > /etc/usbguard/usbguard-daemon.conf <<EOF
RuleFile=/etc/usbguard/rules.conf
ImplicitPolicyTarget=block
PresentDevicePolicy=apply-policy
PresentControllerPolicy=allow
InsertedDevicePolicy=block
AuthorizedDefault=none
RestoreControllerDeviceState=false
DeviceManagerBackend=uevent
EOF

systemctl enable usbguard.service

# Disable GRUB timeout for instant boot
print_status "Disabling GRUB timeout for instant boot..."
if grep -q '^GRUB_TIMEOUT=' /etc/default/grub; then
    sed -i 's/^GRUB_TIMEOUT=.*/GRUB_TIMEOUT=0/' /etc/default/grub
else
    echo 'GRUB_TIMEOUT=0' >> /etc/default/grub
fi
grub-mkconfig -o /boot/grub/grub.cfg

# Set proper ownership
chown -R $KIOSK_USER:$KIOSK_USER /home/$KIOSK_USER

# Create management script for updating URL
print_status "Creating management scripts..."
cat > /usr/local/bin/kiosk-update-url <<'UPDATE_SCRIPT'
#!/bin/bash

if [ "$EUID" -ne 0 ]; then 
    echo "Please run with sudo"
    exit 1
fi

if [ -z "$1" ]; then
    echo "Usage: sudo kiosk-update-url <new-url>"
    if [ -f /etc/kiosk/config ]; then
        echo "Current URL: $(grep KIOSK_URL /etc/kiosk/config | cut -d'"' -f2)"
    fi
    exit 1
fi

NEW_URL="$1"
if [ -f /etc/kiosk/config ]; then
    sed -i "s|KIOSK_URL=.*|KIOSK_URL=\"$NEW_URL\"|g" /etc/kiosk/config
    echo "Kiosk URL updated to: $NEW_URL"
else
    echo "Config not found. Run the main installer first."
    exit 1
fi
echo "Restart the system or kill firefox process for changes to take effect."
echo "To restart immediately: sudo systemctl restart getty@tty1"
UPDATE_SCRIPT

chmod +x /usr/local/bin/kiosk-update-url

# Create script to show current config
cat > /usr/local/bin/kiosk-status <<'STATUS_SCRIPT'
#!/bin/bash

echo "========================================"
echo "  Kiosk Status"
echo "========================================"
echo ""

if [ -f /etc/kiosk/config ]; then
    source /etc/kiosk/config
    echo "Username: $KIOSK_USER"
    echo "Current URL: $KIOSK_URL"
else
    echo "Kiosk not configured"
    exit 1
fi

echo ""
echo "Boot Target: $(systemctl get-default)"
echo "DM Status: $(systemctl is-enabled display-manager.service 2>/dev/null || echo 'masked/disabled')"
echo "SSH Status: $(systemctl is-active sshd)"
echo "USBGuard Status: $(systemctl is-active usbguard)"

if pgrep -f "firefox --kiosk" > /dev/null; then
    echo "Browser Status: Running"
else
    echo "Browser Status: Not running"
fi

echo ""
echo "Available commands:"
echo "  sudo kiosk-update-url <url>  - Update kiosk URL"
echo "  kiosk-status                  - Show this status"
echo "  sudo reboot                   - Restart to apply changes"
STATUS_SCRIPT

chmod +x /usr/local/bin/kiosk-status

# Create web control app
print_status "Creating web control app..."
SECRET_KEY=$(openssl rand -hex 32 2>/dev/null || echo "default_secret_key_change_me")
cat > /usr/local/bin/kiosk-webapp.py <<PYEOF
#!/usr/bin/env python3

import os
import subprocess
from flask import Flask, request, session, redirect, url_for, render_template_string, flash

app = Flask(__name__)
app.secret_key = '$SECRET_KEY'

KIOSK_USER = '$KIOSK_USER'
KIOSK_PASS = '$KIOSK_PASS'

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
PYEOF

chmod 600 /usr/local/bin/kiosk-webapp.py

# Create systemd service for web app
print_status "Creating web app systemd service..."
cat > /etc/systemd/system/kiosk-web.service <<EOF
[Unit]
Description=Kiosk Web Control App
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/bin/python /usr/local/bin/kiosk-webapp.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable kiosk-web.service

# Final summary
echo ""
echo "========================================"
print_status "Installation Complete!"
echo "========================================"
echo ""
print_info "Configuration:"
echo "  • Username: $KIOSK_USER"
echo "  • Kiosk URL: $KIOSK_URL"
echo "  • Boot Mode: Console (DM disabled/masked)"
echo "  • GRUB: Instant boot (timeout disabled)"
echo "  • SSH: Enabled on port 22"
if [ -n "$SSH_PUBLIC_KEY" ]; then
    echo "  • SSH Auth: Key-based only"
else
    echo "  • SSH Auth: Password (consider adding SSH key later)"
fi
echo "  • USB Protection: Enabled"
echo "  • Firefox: Custom preferences applied (Web Speech disabled, notifications/promos disabled, swipe gestures disabled)"
echo "  • Web Control: http://[IP]:8080 (login with kiosk credentials)"
echo ""
print_info "Management Commands:"
echo "  • Update URL: sudo kiosk-update-url <new-url>"
echo "  • Check status: kiosk-status"
echo "  • Web Dashboard: http://IP:8080"
echo ""
print_info "SSH Connection:"
IP=$(ip route get 1 2>/dev/null | awk '{print $7; exit}')
if [ -n "$IP" ]; then
    echo "  ssh $KIOSK_USER@$IP"
    echo "  Web: http://$IP:8080"
else
    HOSTNAME=$(hostname)
    echo "  ssh $KIOSK_USER@$HOSTNAME (or use IP address)"
    echo "  Web: http://$HOSTNAME:8080 (or use IP address)"
fi
echo ""
print_warning "REBOOT REQUIRED FOR KIOSK MODE (DM changes take effect)"
echo "  sudo reboot"
echo ""
print_info "To revert to graphical boot later:"
echo "  sudo systemctl unmask display-manager.service"
echo "  sudo systemctl set-default graphical.target"
echo "  sudo reboot"
echo ""
print_warning "Note: Web app password is stored in plain text in /usr/local/bin/kiosk-webapp.py (root-only access)"
