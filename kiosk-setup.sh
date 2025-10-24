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

# Install required packages (added xbindkeys for key disabling)
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
    xbindkeys

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

# Create Firefox kiosk profile and security prefs
print_status "Setting up Firefox kiosk profile..."
su - $KIOSK_USER -c "firefox -CreateProfile kiosk /home/$KIOSK_USER/.mozilla/firefox/kiosk" >/dev/null 2>&1
cat > /home/$KIOSK_USER/.mozilla/firefox/kiosk/user.js <<EOF
// Kiosk Security Prefs
user_pref("browser.startup.homepage", "$KIOSK_URL");
user_pref("browser.tabs.warnOnClose", false);
user_pref("browser.tabs.warnOnCloseOtherTabs", false);
user_pref("browser.tabs.warnOnOpen", false);
user_pref("dom.disable_window_flip", true);
user_pref("dom.disable_window_move_resize", true);
user_pref("privacy.trackingprotection.enabled", true);
user_pref("network.protocol-handler.warn-external.http", true);
user_pref("network.protocol-handler.warn-external.https", true);
user_pref("browser.safebrowsing.enabled", true);
EOF
chown -R $KIOSK_USER:$KIOSK_USER /home/$KIOSK_USER/.mozilla

# Create local kiosk HTML wrapper for URL enforcement (iframe sandbox)
print_status "Creating kiosk HTML wrapper..."
cat > /home/$KIOSK_USER/kiosk.html <<EOF
<!DOCTYPE html>
<html>
<head>
    <title>Kiosk</title>
    <style>body, html { margin: 0; padding: 0; overflow: hidden; }</style>
</head>
<body>
    <iframe src="$KIOSK_URL" sandbox="allow-scripts allow-same-origin allow-forms allow-popups-to-escape-sandbox" style="border: none; width: 100%; height: 100vh;"></iframe>
    <script>
        // Prevent context menu and unload
        document.addEventListener('contextmenu', e => e.preventDefault());
        window.addEventListener('beforeunload', () => { window.location.href = '$KIOSK_URL'; });
        // Refocus iframe periodically
        setInterval(() => { document.querySelector('iframe').focus(); }, 5000);
    </script>
</body>
</html>
EOF
chown $KIOSK_USER:$KIOSK_USER /home/$KIOSK_USER/kiosk.html

# Create .xinitrc (added xbindkeys)
print_status "Creating .xinitrc..."
cat > /home/$KIOSK_USER/.xinitrc <<EOF
#!/bin/bash

# Disable screen blanking and power management
xset s off
xset -dpms
xset s noblank

# Hide cursor after inactivity
unclutter -idle 0.1 &

# Start keybinding daemon to disable shortcuts
xbindkeys &

# Start Openbox window manager
exec openbox-session
EOF

chmod +x /home/$KIOSK_USER/.xinitrc

# Create Openbox configuration (updated for profile, private, HTML wrapper)
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

# Function to start browser in kiosk mode (enhanced: profile, private, iframe wrapper)
start_browser() {
    firefox \
        -P kiosk \
        --kiosk "file:///home/$KIOSK_USER/kiosk.html" \
        --private-window \
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
        --disable-extensions &
}

# Start the browser
start_browser

# Monitor browser process and restart if closed (use pgrep for robustness)
while true; do
    if ! pgrep -f "firefox -P kiosk --kiosk" > /dev/null 2>&1; then
        echo "Browser crashed or closed. Restarting..." >&2
        sleep 2
        start_browser
    fi
    sleep 5
done
AUTOSTART_SCRIPT

chmod +x /home/$KIOSK_USER/.config/openbox/autostart

# Create xbindkeys config to disable Ctrl+W and Alt+F4
print_status "Configuring key disabling..."
cat > /home/$KIOSK_USER/.xbindkeysrc <<EOF
# Disable Ctrl+W (close tab)
""
    Control + w

# Disable Alt+F4 (close window)
""
    Alt + F4
EOF
chown $KIOSK_USER:$KIOSK_USER /home/$KIOSK_USER/.xbindkeysrc

# Create .bash_profile for auto-start X on console
print_status "Creating .bash_profile..."
cat > /home/$KIOSK_USER/.bash_profile <<EOF
if [[ -z \$DISPLAY ]] && [[ \$(tty) = /dev/tty1 ]]; then
    exec startx
fi
EOF

# Configure USB blocking with USBGuard (enhanced: strict block fallback)
print_status "Configuring USBGuard..."
mkdir -p /etc/usbguard
if ! usbguard generate-policy > /etc/usbguard/rules.conf 2>/dev/null; then
    # Strict block all if generation fails
    cat > /etc/usbguard/rules.conf <<EOF
# Block all USB devices by default
block
EOF
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

systemctl enable --now usbguard.service

# Set proper ownership
chown -R $KIOSK_USER:$KIOSK_USER /home/$KIOSK_USER

# Create management script for updating URL (reloads HTML too)
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
    # Update user.js homepage
    if [ -f /etc/kiosk/config ]; then source /etc/kiosk/config; fi
    sed -i "s|user_pref(\"browser.startup.homepage\", \".*\"|user_pref(\"browser.startup.homepage\", \"$KIOSK_URL\"|g" /home/$KIOSK_USER/.mozilla/firefox/kiosk/user.js 2>/dev/null || true
    # Update HTML iframe
    sed -i "s|src=.*|src=\"$KIOSK_URL\"|g" /home/$KIOSK_USER/kiosk.html
    chown $KIOSK_USER:$KIOSK_USER /home/$KIOSK_USER/kiosk.html
    echo "Kiosk URL updated to: $NEW_URL"
else
    echo "Config not found. Run the main installer first."
    exit 1
fi
echo "Restart the session for changes: sudo systemctl restart getty@tty1"
UPDATE_SCRIPT

chmod +x /usr/local/bin/kiosk-update-url

# Create script to show current config (added USB rules count)
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
echo "USB Rules Count: $(wc -l < /etc/usbguard/rules.conf 2>/dev/null || echo 'N/A') (low = strict blocking)"

if pgrep -f "firefox -P kiosk --kiosk" > /dev/null; then
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

# Final summary (fixed IP display)
echo ""
echo "========================================"
print_status "Installation Complete!"
echo "========================================"
echo ""
print_info "Configuration:"
echo "  • Username: $KIOSK_USER"
echo "  • Kiosk URL: $KIOSK_URL"
echo "  • Boot Mode: Console (DM disabled/masked)"
echo "  • SSH: Enabled on port 22"
if [ -n "$SSH_PUBLIC_KEY" ]; then
    echo "  • SSH Auth: Key-based only"
else
    echo "  • SSH Auth: Password (consider adding SSH key later)"
fi
echo "  • USB Protection: New devices blocked"
echo "  • Browser Security: Keys disabled, URL enforced via iframe"
echo ""
print_info "Management Commands:"
echo "  • Update URL: sudo kiosk-update-url <new-url>"
echo "  • Check status: kiosk-status"
echo ""
IP=$(hostname -I | awk '{print $1}')
print_info "SSH Connection:"
echo "  ssh $KIOSK_USER@$IP"
echo ""
print_warning "REBOOT REQUIRED FOR KIOSK MODE"
echo "  sudo reboot"
echo ""
print_info "To revert to graphical boot later:"
echo "  sudo systemctl unmask display-manager.service"
echo "  sudo systemctl set-default graphical.target"
echo "  sudo reboot"
