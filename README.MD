# EndeavourOS Kiosk Setup Guide

## Overview

Welcome to the **EndeavourOS Kiosk Setup**—a streamlined tool designed exclusively for our startup's internal deployment. This setup turns any compatible EndeavourOS machine into a secure, always-on digital kiosk for displaying web-based content (e.g., dashboards, signage, or apps). It's built for reliability in our production environments, like office displays or client demos, with remote management to minimize on-site visits.

**Key Goals**:
- Quick deployment: One script handles installation and config.
- Security-first: Locks down USBs, enables SSH/firewall, and restricts browser features.
- Remote ops: Web dashboard for URL swaps, pref tweaks, and reboots.
- Minimal maintenance: Auto-restarts browser; console boot for fast recovery.

This guide walks you through setup, daily use, and troubleshooting—tailored for our IT team or on-site admins. No deep Linux knowledge required!

## System Requirements

- **OS**: EndeavourOS (latest stable; tested on Plasma edition).
- **Hardware**: x86_64 PC (e.g., mini-PC, repurposed laptop; 4GB+ RAM recommended for smooth Firefox).
- **Network**: Ethernet/Wi-Fi for initial setup; static IP preferred for remote access.
- **Access**: Root privileges (`sudo`); internet for package downloads.
- **Files**: Download `kiosk-setup.sh` and `kiosk-webapp.py` from our internal repo (place in same folder).

**Pro Tip**: Test on a VM first (e.g., VirtualBox with EndeavourOS ISO) to avoid disrupting live hardware.

## Step-by-Step Installation

### 1. Prepare the Machine
- Boot into EndeavourOS and update: `sudo pacman -Syu`.
- Log in as root or use `sudo` for the next steps.
- Copy the two files to a working directory: `/tmp/kiosk/` (or similar).

### 2. Run the Setup Script
```bash
cd /tmp/kiosk/  # Or your dir
chmod +x kiosk-setup.sh  # Optional, but good practice
sudo ./kiosk-setup.sh
```

**What Happens During Install**:
- **Prompts**:
  - **Username**: e.g., `kiosk` (creates a dedicated user).
  - **Password**: Set a strong one (used for SSH/web login; confirm twice).
  - **Kiosk URL**: Your starting webpage, e.g., `https://our-startup-dashboard.com`.
  - **SSH Key**: Paste your public key (from `~/.ssh/id_rsa.pub`) for key-based auth; skip for password-only.
- **Actions**:
  - Installs essentials: Firefox, Openbox (light WM), USBGuard, Firewalld, etc.
  - Creates user, sets autologin on TTY1.
  - Configures Firefox profile with kiosk tweaks (disables promos, gestures, etc.).
  - Enables SSH (port 22), web app (port 8080), and USB blocking.
  - Disables display manager for console boot (faster, no GUI login).
  - Copies web app and starts its service.

**Time**: ~5-10 mins (depending on packages).

### 3. Reboot and Verify
```bash
sudo reboot
```
- **Expected Boot**: GRUB (instant) → Console login (auto) → X starts → Full-screen Firefox at your URL.
- **Find IP**: On another machine, scan network (e.g., `nmap -sn 192.168.1.0/24`) or check router.
- **Test Web Access**: `http://<IP>:8080` → Login with username/password.

If issues arise, see [Troubleshooting](#troubleshooting) below.

## Daily Operations

### Accessing the Kiosk
- **Local**: Boots directly to browser—no keyboard needed (cursor hidden after 0.1s).
- **Remote**:
  - **SSH**: `ssh kiosk@<IP>` (use key or password).
  - **Web Dashboard**: `http://<IP>:8080` (modern UI; mobile-friendly).

### Managing via Web Dashboard
Log in → Clean, sectioned interface:

1. **Current URL**:
   - Edit the field (e.g., switch to a new dashboard).
   - Submit → Changes save to config; restart browser to apply.

2. **System Status**:
   - Real-time snapshot: Boot mode, services (SSH, USBGuard), browser running?
   - Raw output for quick checks.

3. **USB Security**:
   - Toggle ON (blocks unknown devices) / OFF (allows all).
   - Status shows current state; replug devices after toggle.

4. **Firefox Preferences**:
   - 11 checkboxes for common tweaks (e.g., disable Web Speech, VPN promos, swipe gestures).
   - Check to disable (kiosk-default: all off); save → Restart browser.
   - Why? Reduces distractions/telemetry for our locked-down use.

5. **Controls**:
   - **Restart Browser**: Kills/relaunches Firefox (applies URL/pref changes; ~5s downtime).
   - **Reboot System**: Full restart (use for boot-level changes; confirm prompt).

**Logout** anytime for security.

### CLI Quick Commands
From SSH or local console (as `kiosk` user; `sudo` for admin tasks):

| Command | What It Does | When to Use |
|---------|--------------|-------------|
| `kiosk-status` | Prints config, services, browser status. | Daily health check. |
| `sudo kiosk-update-url <URL>` | Updates URL in config. | If web UI is down. |
| `pkill firefox` | Restarts browser (manual). | Quick URL/pref apply. |
| `sudo reboot` | Full reboot. | After major changes. |
| `journalctl -u kiosk-web -f` | Tail web app logs. | Debug dashboard issues. |

**Batch Updates**: For multiple kiosks, script SSH: e.g., `for ip in 192.168.1.{10..20}; do ssh kiosk@$ip "sudo kiosk-update-url https://new-url.com"; done`.

## How It All Works (Under the Hood)

For curious admins: High-level flow without code dives.

### Boot Sequence
1. **GRUB** (0s timeout) → Systemd multi-user target (no desktop login).
2. **Autologin** (TTY1): Systemd `getty` logs in `kiosk` user automatically.
3. **Start X**: `~/.bash_profile` runs `startx`.
4. **X Session**: `~/.xinitrc` tweaks display (no blanking, hide cursor) → Launches Openbox.
5. **Openbox**: `autostart` script:
   - Sources `/etc/kiosk/config` (URL/user).
   - Kills old Firefox.
   - Starts new: `firefox --kiosk <URL> --profile kiosk` (with flags for lockdown).
   - Loops: Checks every 1s; restarts if crashed (3-5s delay).

### Security & Services
- **USBGuard**: Blocks devices by default; web toggle edits daemon conf → Restarts service.
- **Firewalld**: Only 22 (SSH) + 8080 (web) open; auto-starts.
- **SSH**: No root login; key optional. Restarted post-config.
- **Web App**: Flask service (root-owned); sessions for login. Edits files like `user.js` (Firefox prefs) and removes cache (`prefs.js`) for instant reloads.
- **Firefox Profile**: Custom `~/.mozilla/firefox/kiosk/` with `user.js` overrides (e.g., `false` disables features). `profiles.ini` locks to this profile.

**Changes Apply**:
- URL/Prefs: Browser restart (web button or `pkill`).
- USB: Immediate (replug devices).
- Boot tweaks: Full reboot.

### Customization Tips
- **Add Prefs**: Edit `kiosk-webapp.py` (add to `bool_prefs` list) → Reinstall script.
- **Different Browser**: Swap `firefox` in `autostart` (e.g., Chromium; update packages).
- **Logs**: Firefox console: `~/.mozilla/firefox/kiosk/console.log`.

## Troubleshooting

Common hiccups and fixes:

| Problem | Likely Cause | Steps to Fix |
|---------|--------------|--------------|
| **Old URL persists after update** | Config not reloaded. | Update via web/CLI → Restart browser (not full reboot). |
| **Prefs don't stick** | Firefox cache. | Save in web → Restart; check `user.js` ownership (`chown kiosk:kiosk`). |
| **No web access** | Firewall/IP wrong. | `sudo firewall-cmd --list-ports` (confirm 8080); `ip addr show`. Restart service: `sudo systemctl restart kiosk-web`. |
| **Browser crashes on boot** | Profile issue. | SSH in → `rm -rf ~/.mozilla/firefox/kiosk` → Reboot (regens profile). |
| **USB toggle no effect** | Devices already authorized. | Turn OFF → Unplug all → Turn ON → Replug. |
| **Slow boot/no X** | Graphics driver. | Install `mesa` or NVIDIA drivers pre-setup; check `journalctl -b -p err`. |
| **SSH denied** | Key mismatch/password. | Verify key in `~/.ssh/authorized_keys`; reset password: `sudo chpasswd kiosk:<newpass>`. |

**Full Reset**:
- Revert boot: `sudo systemctl unmask display-manager && sudo systemctl set-default graphical.target && sudo reboot`.
- Nuke kiosk: `sudo userdel -r kiosk && sudo rm -rf /etc/kiosk /usr/local/bin/kiosk-* && sudo systemctl disable --now sshd firewalld usbguard kiosk-web`.

**Support**: Ping IT Slack (#kiosk-ops) with logs (`journalctl -u getty@tty1` or screenshots).

## Best Practices for Our Team

- **Deployment**: Image golden setup to USB for new machines.
- **Monitoring**: Cron job on central server: SSH ping kiosks daily; alert on downtime.
- **Updates**: Pacman system updates monthly; re-run script for kiosk tweaks.
- **Backup**: Configs in `/etc/kiosk/`; profile in `/home/kiosk/.mozilla/` (rsync to NAS).
- **Security Audit**: Rotate passwords quarterly; monitor SSH logs (`journalctl -u sshd`).

This guide keeps things simple—deploy, manage, forget. Questions? Reply to the repo issue or ask in Slack.

*Internal Doc v1.0 | Last Updated: October 24, 2025*
