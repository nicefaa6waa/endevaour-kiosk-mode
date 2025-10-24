#!/bin/bash

# EndeavourOS Kiosk Setup Script (Idempotent Version)
# Safe for re-runs: Cleans conflicts, prompts for reset.

set -e

# Colors for output (unchanged)
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_status() { echo -e "${GREEN}[✓]${NC} $1"; }
print_warning() { echo -e "${YELLOW}[!]${NC} $1"; }
print_error() { echo -e "${RED}[✗]${NC} $1"; }
print_info() { echo -e "${BLUE}[i]${NC} $1"; }

# Check root
if [ "$EUID" -ne 0 ]; then 
    print_error "Please run with sudo"
    exit 1
fi

echo ""
echo "========================================"
echo "  EndeavourOS Kiosk Setup (Idempotent)"
echo "========================================"
echo ""

# Interactive prompts (unchanged, but add reset check)
read -p "Enter kiosk username: " KIOSK_USER

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

# Reset prompt for re-runs
echo ""
if id "$KIOSK_USER" &>/dev/null; then
    read -p "User $KIOSK_USER exists. Full reset (delete profile/configs)? (y/N): " RESET_CONFIRM
    if [[ "$RESET_CONFIRM" =~ ^[Yy]$ ]]; then
        print_status "Full reset initiated..."
        rm -rf /home/$KIOSK_USER/.mozilla /home/$KIOSK_USER/.config/openbox /home/$KIOSK_USER/.xinitrc /home/$KIOSK_USER/.bash_profile /home/$KIOSK_USER/kiosk.html /home/$KIOSK_USER/.xbindkeysrc
        print_info "Reset complete."
    fi
fi

# Confirmation (unchanged)
echo ""
echo "========================================"
echo "Configuration Summary:"
echo "========================================"
echo "Username: $KIOSK_USER"
echo "Kiosk URL: $KIOSK_URL"
if [ -n "$SSH_PUBLIC_KEY" ]; then
    echo "SSH Key: Provided"
else
    echo "SSH Key: Not provided"
fi
echo ""
read -p "Continue? (y/N): " CONFIRM

if [[ ! "$CONFIRM" =~ ^[Yy]$ ]]; then
    print_error "Cancelled"
    exit 1
fi

print_status "Starting..."

# Update/Install (idempotent: --needed skips)
print_status "Updating/Installing packages..."
pacman -Sy --noconfirm
pacman -S --needed --noconfirm xorg-server xorg-xinit openbox firefox unclutter xdotool openssh usbguard xorg-xset sudo xbindkeys
sleep 1

# User (always re-set password/ownership)
print_status "Handling user $KIOSK_USER..."
if ! id "$KIOSK_USER" &>/dev/null; then
    useradd -m -s /bin/bash "$KIOSK_USER"
fi
echo "$KIOSK_USER:$KIOSK_PASS" | chpasswd
usermod -aG wheel "$KIOSK_USER" 2>/dev/null || true
chown -R "$KIOSK_USER:$KIOSK_USER" "/home/$KIOSK_USER"
print_info "User ready."

# SSH (unchanged, but log)
print_status "Configuring SSH..."
mkdir -p "/home/$KIOSK_USER/.ssh"
chmod 700 "/home/$KIOSK_USER/.ssh"
if [ -n "$SSH_PUBLIC_KEY" ]; then
    echo "$SSH_PUBLIC_KEY" > "/home/$KIOSK_USER/.ssh/authorized_keys"
    chmod 600 "/home/$KIOSK_USER/.ssh/authorized_keys"
fi
chown -R "$KIOSK_USER:$KIOSK_USER" "/home/$KIOSK_USER/.ssh"

cat > /etc/ssh/sshd_config.d/kiosk.conf <<EOF
PermitRootLogin no
PubkeyAuthentication yes
PasswordAuthentication $([ -n "$SSH_PUBLIC_KEY" ] && echo "no" || echo "yes")
AuthorizedKeysFile .ssh/authorized_keys
EOF

systemctl enable sshd --now
print_info "SSH: journalctl -u sshd -n 10"

# Config file
print_status "Creating /etc/kiosk/config..."
mkdir -p /etc/kiosk
cat > /etc/kiosk/config <<EOF
KIOSK_URL="$KIOSK_URL"
KIOSK_USER="$KIOSK_USER"
EOF
chmod 644 /etc/kiosk/config

# DM/Autologin (idempotent: mask/disable safe to re-run)
print_status "Configuring console boot/autologin..."
systemctl disable display-manager.service 2>/dev/null || true
systemctl mask display-manager.service
systemctl set-default multi-user.target
systemctl daemon-reload

mkdir -p /etc/systemd/system/getty@tty1.service.d/
cat > /etc/systemd/system/getty@tty1.service.d/autologin.conf <<EOF
[Service]
ExecStart=
ExecStart=-/sbin/agetty -o '-p -f -- \\u' --noclear --autologin $KIOSK_USER %I \$TERM
EOF
systemctl daemon-reload
systemctl enable getty@tty1
print_info "Autologin: journalctl -u getty@tty1 -n 10"

# Firefox profile (CLEAN BEFORE CREATE)
print_status "Setting up Firefox profile (cleaning existing)..."
rm -rf "/home/$KIOSK_USER/.mozilla/firefox/kiosk"  # Nuke for re-run
su - "$KIOSK_USER" -c "firefox -CreateProfile 'kiosk /home/$KIOSK_USER/.mozilla/firefox/kiosk'"
cat > "/home/$KIOSK_USER/.mozilla/firefox/kiosk/user.js" <<EOF
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
chown -R "$KIOSK_USER:$KIOSK_USER" "/home/$KIOSK_USER/.mozilla"
print_status "Profile ready."

# HTML wrapper
print_status "Creating kiosk.html..."
cat > "/home/$KIOSK_USER/kiosk.html" <<EOF
<!DOCTYPE html>
<html><head><title>Kiosk</title><style>body, html { margin: 0; padding: 0; overflow: hidden; }</style></head>
<body><iframe src="$KIOSK_URL" sandbox="allow-scripts allow-same-origin allow-forms allow-popups-to-escape-sandbox" style="border: none; width: 100%; height: 100vh;"></iframe>
<script>document.addEventListener('contextmenu', e => e.preventDefault()); window.addEventListener('beforeunload', () => { window.location.href = '$KIOSK_URL'; }); setInterval(() => { document.querySelector('iframe').focus(); }, 5000);</script></body></html>
EOF
chown "$KIOSK_USER:$KIOSK_USER" "/home/$KIOSK_USER/kiosk.html"

# .xinitrc
print_status "Creating .xinitrc..."
cat > "/home/$KIOSK_USER/.xinitrc" <<'EOF'
#!/bin/bash
xset s off && xset -dpms && xset s noblank
unclutter -idle 0.1 &
xbindkeys &
exec openbox-session
EOF
chmod +x "/home/$KIOSK_USER/.xinitrc"

# Openbox autostart
print_status "Creating Openbox autostart..."
mkdir -p "/home/$KIOSK_USER/.config/openbox"
cat > "/home/$KIOSK_USER/.config/openbox/autostart" <<'EOF'
#!/bin/bash
source /etc/kiosk/config
start_browser() {
    firefox -P kiosk --kiosk "file:///home/$KIOSK_USER/kiosk.html" --private-window --no-remote --new-instance --disable-infobars --no-first-run --disable-session-crashed-bubble --disable-features=TranslateUI --check-for-update-interval=31536000 --disable-component-update --overscroll-history-navigation=0 --disable-pinch --disable-notifications --disable-popup-blocking --disable-dev-shm-usage --disable-extensions &
}
start_browser
while true; do
    if ! pgrep -f "firefox -P kiosk --kiosk" >/dev/null 2>&1; then
        echo "Restarting browser..." >&2
        sleep 2
        start_browser
    fi
    sleep 5
done
EOF
chmod +x "/home/$KIOSK_USER/.config/openbox/autostart"

# xbindkeys
print_status "Configuring keys..."
cat > "/home/$KIOSK_USER/.xbindkeysrc" <<EOF
"" Control + w
"" Alt + F4
EOF
chown "$KIOSK_USER:$KIOSK_USER" "/home/$KIOSK_USER/.xbindkeysrc"

# .bash_profile (force startx on tty1)
print_status "Creating .bash_profile..."
cat > "/home/$KIOSK_USER/.bash_profile" <<EOF
if [[ -z \$DISPLAY && \$(tty) = /dev/tty1 ]]; then
    print_info "Starting X on tty1..."
    exec startx
fi
EOF

# USBGuard (unchanged)
print_status "Configuring USBGuard..."
mkdir -p /etc/usbguard
usbguard generate-policy > /etc/usbguard/rules.conf 2>/dev/null || cat > /etc/usbguard/rules.conf <<EOF
block
EOF
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
systemctl enable --now usbguard
print_info "USB: journalctl -u usbguard -n 10"

# Final chown
chown -R "$KIOSK_USER:$KIOSK_USER" "/home/$KIOSK_USER"

# Management scripts (unchanged from debug version, with logs)
print_status "Creating management scripts..."

# kiosk-update-url
cat > /usr/local/bin/kiosk-update-url <<'EOF'
#!/bin/bash
source /etc/kiosk/config
read -p "New URL: " NEW_URL
sed -i "s|^KIOSK_URL=.*|KIOSK_URL=\"$NEW_URL\"|" /etc/kiosk/config
pkill -f "firefox -P kiosk" || true
sleep 2
su - $KIOSK_USER -c "DISPLAY=:0 firefox -P kiosk --kiosk \"file:///home/$KIOSK_USER/kiosk.html\" --private-window --no-remote --new-instance &"
echo "Updated to $NEW_URL"
EOF
chmod +x /usr/local/bin/kiosk-update-url

# kiosk-status
cat > /usr/local/bin/kiosk-status <<'EOF'
#!/bin/bash
source /etc/kiosk/config
echo "Kiosk Status for $KIOSK_USER:"
echo "URL: $KIOSK_URL"
if pgrep -f "firefox -P kiosk --kiosk" >/dev/null; then
    echo "Browser: Running"
else
    echo "Browser: Not running"
fi
echo "X Session: $(ps aux | grep "[s]tartx" | wc -l) instances"
echo "To update URL: kiosk-update-url"
EOF
chmod +x /usr/local/bin/kiosk-status

echo ""
print_status "Complete! REBOOT to test."
IP=$(hostname -I | awk '{print $1}')
echo "SSH: ssh $KIOSK_USER@$IP"
echo "Post-reboot check: kiosk-status"
