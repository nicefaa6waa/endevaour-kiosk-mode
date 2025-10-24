#!/bin/bash

# EndeavourOS Kiosk Setup Script (Improved)
# Usage: curl -sSL https://raw.githubusercontent.com/yourusername/yourrepo/main/kiosk-setup.sh   | sudo bash

set -e # Exit on any error

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
echo "  EndeavourOS Kiosk Setup Installer (Improved)"
echo "========================================"
echo ""

# Interactive prompts
read -p "Enter kiosk username: " KIOSK_USER

# Ask if user should have no password
read -p "Set user with no password? (y/N): " NO_PASS_RESPONSE
NO_PASS=false
if [[ "$NO_PASS_RESPONSE" =~ ^[Yy]$ ]]; then
    NO_PASS=true
fi

KIOSK_PASS=""
KIOSK_PASS_CONFIRM=""

if [ "$NO_PASS" = false ]; then
    # Password input with confirmation (only if not setting no password)
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
fi

read -p "Enter kiosk URL (e.g., https://example.com): " KIOSK_URL

echo ""
print_info "SSH Key Setup (Optional)"
echo "Paste your SSH public key (or press Enter to skip):"
read -p "> " SSH_PUBLIC_KEY

# Confirmation
echo ""
echo "========================================"
echo "Configuration Summary:"
echo "========================================"
echo "Username: $KIOSK_USER"
if [ "$NO_PASS" = true ]; then
    echo "Password: No password set"
else
    echo "Password: Set"
fi
echo "Kiosk URL: $KIOSK_URL"
if [ -n "$SSH_PUBLIC_KEY" ]; then
    echo "SSH Key: Provided"
else
    echo "SSH Key: Not provided"
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

# Install required packages (including firefox, openbox, xorg, etc.)
print_status "Installing required packages..."
REQUIRED_PACKAGES=(
    xorg-server
    xorg-xinit
    openbox
    firefox # Changed from chromium to firefox
    xorg-xset
    xdotool
    unclutter
    openssh
    usbguard
    sudo
    # Add other needed packages here if any
)
# Install packages, handling potential conflicts or missing dependencies gracefully
if ! pacman -S --needed --noconfirm "${REQUIRED_PACKAGES[@]}"; then
    print_error "Failed to install some required packages. Check pacman logs."
    exit 1
fi
print_status "Required packages installed successfully."

# Create kiosk user
print_status "Creating kiosk user: $KIOSK_USER..."
if id "$KIOSK_USER" &>/dev/null; then
    print_warning "User $KIOSK_USER already exists, updating configuration..."
else
    # Create user with home directory
    useradd -m -s /bin/bash "$KIOSK_USER"
    print_status "User $KIOSK_USER created."
fi

# Set password or lock it
if [ "$NO_PASS" = true ]; then
    # Lock the password (effectively no password login allowed via console, but autologin bypasses this)
    # For autologin purposes, locking might be safer if no password is desired.
    # However, for getty autologin, we often just don't set one. 
    # Let's explicitly lock it here.
    passwd -l "$KIOSK_USER" 2>/dev/null || true
    print_status "Password locked for user $KIOSK_USER (autologin will still work)."
else
    echo "$KIOSK_USER:$KIOSK_PASS" | chpasswd
    print_status "Password set for user $KIOSK_USER."
fi

# Add user to necessary groups (wheel for sudo, video for Xorg if needed)
usermod -aG wheel,video "$KIOSK_USER" 2>/dev/null || true

# Setup SSH (if key provided)
if [ -n "$SSH_PUBLIC_KEY" ]; then
    print_status "Configuring SSH for user $KIOSK_USER..."
    mkdir -p /home/$KIOSK_USER/.ssh
    chmod 700 /home/$KIOSK_USER/.ssh
    echo "$SSH_PUBLIC_KEY" > /home/$KIOSK_USER/.ssh/authorized_keys
    chmod 600 /home/$KIOSK_USER/.ssh/authorized_keys
    chown -R $KIOSK_USER:$KIOSK_USER /home/$KIOSK_USER/.ssh
    print_status "SSH key configured for $KIOSK_USER."

    # Configure SSH daemon for key-only auth if key was provided
    cat > /etc/ssh/sshd_config.d/kiosk.conf <<EOF
# Kiosk SSH Configuration
PermitRootLogin no
PubkeyAuthentication yes
PasswordAuthentication no
AuthorizedKeysFile .ssh/authorized_keys
EOF
else
    # If no key, allow password auth (less secure)
    cat > /etc/ssh/sshd_config.d/kiosk.conf <<EOF
# Kiosk SSH Configuration
PermitRootLogin no
PubkeyAuthentication yes
PasswordAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
EOF
fi

# Enable and restart SSH service
systemctl enable sshd.service
systemctl restart sshd.service
print_status "SSH service configured and restarted."

# Create config directory and file
print_status "Creating kiosk configuration..."
mkdir -p /etc/kiosk
cat > /etc/kiosk/config <<EOF
KIOSK_URL="$KIOSK_URL"
KIOSK_USER="$KIOSK_USER"
NO_PASS="$NO_PASS" # Pass the flag to the kiosk script
EOF
chmod 644 /etc/kiosk/config

# Configure autologin for getty on tty1
print_status "Configuring autologin for getty on tty1..."
GETTY_SERVICE_DIR="/etc/systemd/system/getty@tty1.service.d"
mkdir -p "$GETTY_SERVICE_DIR"

# Create override file for autologin
cat > "$GETTY_SERVICE_DIR/override.conf" <<EOF
[Service]
ExecStart=
ExecStart=-/sbin/agetty -o '-p -f -- \\\u' --noclear --autologin $KIOSK_USER %I \$TERM
EOF

# Reload systemd to apply changes
systemctl daemon-reload
print_status "Autologin configured for user $KIOSK_USER on tty1."

# Create .xinitrc (this script is called by startx)
print_status "Creating .xinitrc for user $KIOSK_USER..."
XINITRC_PATH="/home/$KIOSK_USER/.xinitrc"
cat > "$XINITRC_PATH" <<'EOF'
#!/bin/bash

# Disable screen blanking and power management
xset s off
xset -dpms
xset s noblank

# Hide cursor after inactivity (adjust idle time if needed)
unclutter -idle 0.1 -root &

# Start the window manager (Openbox)
exec openbox-session
EOF
chmod +x "$XINITRC_PATH"
chown $KIOSK_USER:$KIOSK_USER "$XINITRC_PATH"

# Create Openbox autostart file (runs after the window manager starts)
print_status "Creating Openbox autostart configuration..."
OPENBOX_AUTOSTART_DIR="/home/$KIOSK_USER/.config/openbox"
mkdir -p "$OPENBOX_AUTOSTART_DIR"
OPENBOX_AUTOSTART_PATH="$OPENBOX_AUTOSTART_DIR/autostart"
cat > "$OPENBOX_AUTOSTART_PATH" <<'AUTOSTART_EOF'
#!/bin/bash

# Load kiosk configuration
if [ -f /etc/kiosk/config ]; then
    source /etc/kiosk/config
else
    echo "ERROR: /etc/kiosk/config not found!" >&2
    exit 1
fi

echo "Starting Kiosk for URL: $KIOSK_URL"

# Function to start Firefox in kiosk mode
start_firefox() {
    # Use firefox with specific kiosk flags
    # --kiosk: Fullscreen mode
    # --new-instance: Ensure a new instance is started
    # Additional flags for security/UX
    firefox \
        --kiosk \
        --new-instance \
        --disable-infobars \
        --disable-notifications \
        --disable-web-security \
        --disable-features=TranslateUI \
        --no-first-run \
        --safe-mode \
        "$KIOSK_URL" &
    
    # Capture the PID of the firefox process
    FIREFOX_PID=$!
    echo "Firefox started with PID: $FIREFOX_PID"
}

# Start the browser initially
start_firefox

# Monitor the browser process
while true; do
    # Check if the firefox process is still running using its PID
    if ! kill -0 "$FIREFOX_PID" 2>/dev/null; then
        echo "Firefox process (PID $FIREFOX_PID) seems to have died. Restarting..."
        # Wait a short time before restarting
        sleep 2
        start_firefox
    fi
    # Sleep before checking again to avoid excessive CPU usage
    sleep 5
done
AUTOSTART_EOF
chmod +x "$OPENBOX_AUTOSTART_PATH"
chown $KIOSK_USER:$KIOSK_USER "$OPENBOX_AUTOSTART_PATH"

# Create .bash_profile to automatically start X session on login to tty1
print_status "Creating .bash_profile for auto-start X session..."
BASH_PROFILE_PATH="/home/$KIOSK_USER/.bash_profile"
cat > "$BASH_PROFILE_PATH" <<'EOF'
# Check if DISPLAY is not set (meaning X isn't running)
# AND if the current terminal is tty1 (where autologin happens)
if [ -z "$DISPLAY" ] && [ "$(tty)" = "/dev/tty1" ]; then
    # Start the X session using startx, which reads .xinitrc
    exec startx
fi
EOF
chown $KIOSK_USER:$KIOSK_USER "$BASH_PROFILE_PATH"

# Configure USBGuard (basic setup)
print_status "Configuring USBGuard..."
if [ ! -f /etc/usbguard/rules.conf ]; then
    # Generate initial policy allowing currently connected devices
    usbguard generate-policy > /etc/usbguard/rules.conf 2>/dev/null || echo "allow" > /etc/usbguard/rules.conf
    print_status "Initial USBGuard rules generated."
else
    print_info "Existing USBGuard rules preserved."
fi

# Configure daemon settings
cat > /etc/usbguard/usbguard-daemon.conf <<EOF
RuleFile=/etc/usbguard/rules.conf
ImplicitPolicyTarget=block
PresentDevicePolicy=apply-policy
PresentControllerPolicy=allow
InsertedDevicePolicy=block # Default policy for new devices
AuthorizedDefault=none
RestoreControllerDeviceState=false
DeviceManagerBackend=uevent
EOF

# Enable USBGuard service
systemctl enable usbguard.service
print_status "USBGuard service enabled."

# Ensure correct ownership of user's home directory
chown -R $KIOSK_USER:$KIOSK_USER /home/$KIOSK_USER

# Create management script for updating URL
print_status "Creating management script: kiosk-update-url..."
cat > /usr/local/bin/kiosk-update-url <<'UPDATE_SCRIPT_EOF'
#!/bin/bash

if [ "$EUID" -ne 0 ]; then 
    echo "Error: Please run with sudo." >&2
    exit 1
fi

if [ -z "$1" ]; then
    echo "Usage: sudo kiosk-update-url <new-url>"
    if [ -f /etc/kiosk/config ]; then
        source /etc/kiosk/config
        echo "Current URL: $KIOSK_URL"
    fi
    exit 1
fi

NEW_URL="$1"

# Update the configuration file
if sed -i "s|^KIOSK_URL=.*|KIOSK_URL=\"$NEW_URL\"|" /etc/kiosk/config; then
    echo "Kiosk URL updated to: $NEW_URL"
    echo "Changes will take effect after restarting the kiosk session."
    echo "To restart the X session for the kiosk user, you can usually:"
    echo " 1. Kill the user's processes (e.g., sudo pkill -u $KIOSK_USER)"
    echo " 2. Or reboot the system: sudo reboot"
    # Optionally, kill firefox and let the script in autostart restart it
    # sudo -u $KIOSK_USER pkill firefox
    # This is trickier as it requires identifying the correct user session.
    # A full reboot is often the simplest way to ensure the new URL is loaded.
else
    echo "Error updating configuration file." >&2
    exit 1
fi
UPDATE_SCRIPT_EOF
chmod +x /usr/local/bin/kiosk-update-url

# Create script to show current config
print_status "Creating management script: kiosk-status..."
cat > /usr/local/bin/kiosk-status <<'STATUS_SCRIPT_EOF'
#!/bin/bash

echo "========================================"
echo "  Kiosk Status Report"
echo "========================================"
echo ""

if [ -f /etc/kiosk/config ]; then
    source /etc/kiosk/config
    echo "Username: $KIOSK_USER"
    echo "Current URL: $KIOSK_URL"
    echo "No Password Mode: $NO_PASS"
else
    echo "ERROR: Kiosk configuration file (/etc/kiosk/config) not found!"
    exit 1
fi

echo ""
echo "System Services:"
echo "  SSH Status: $(systemctl is-active sshd 2>/dev/null || echo 'unknown')"
echo "  USBGuard Status: $(systemctl is-active usbguard 2>/dev/null || echo 'unknown')"
echo ""
echo "Kiosk Process Status:"
# Find processes owned by the kiosk user that look like firefox
FIREFOX_PID=$(pgrep -u "$KIOSK_USER" firefox | head -n 1)
if [ -n "$FIREFOX_PID" ]; then
    echo "  Firefox (PID $FIREFOX_PID): Running"
    # Optional: Check if the URL in the process matches the config
    # This is complex and might require parsing /proc/<pid>/cmdline
else
    echo "  Firefox: Not running (or not found under user $KIOSK_USER)"
fi

OPENBOX_PID=$(pgrep -u "$KIOSK_USER" openbox-session | head -n 1)
if [ -n "$OPENBOX_PID" ]; then
    echo "  Openbox (PID $OPENBOX_PID): Running"
else
    echo "  Openbox: Not running (or not found under user $KIOSK_USER)"
fi

echo ""
echo "Management Commands:"
echo "  sudo kiosk-update-url <new-url>  # Update the displayed URL"
echo "  sudo kiosk-status                 # Show this status report"
echo "  sudo reboot                       # Restart the system"
STATUS_SCRIPT_EOF
chmod +x /usr/local/bin/kiosk-status

# Final summary
echo ""
echo "========================================"
print_status "Installation Complete!"
echo "========================================"
echo ""
print_info "Configuration Summary:"
echo "  Username: $KIOSK_USER"
echo "  Kiosk URL: $KIOSK_URL"
echo "  No Password Mode: $NO_PASS"
echo "  SSH: Enabled on port 22"
if [ -n "$SSH_PUBLIC_KEY" ]; then
    echo "    Authentication: Key-based only"
else
    echo "    Authentication: Password-based (or none if --no-password was used)"
fi
echo "  USB Protection: Enabled (via USBGuard)"
echo ""
print_info "Management Commands:"
echo "  sudo kiosk-update-url <new-url>  # Update the kiosk URL"
echo "  sudo kiosk-status                # View current status"
echo ""
print_info "SSH Access (if configured):"
echo "  ssh $KIOSK_USER@<YOUR_MACHINE_IP>"
echo ""
print_warning "IMPORTANT: Reboot the system to start the kiosk mode automatically."
echo "  sudo reboot"
echo ""
print_info "After reboot, the system should boot directly into the Firefox kiosk displaying $KIOSK_URL."
echo ""
