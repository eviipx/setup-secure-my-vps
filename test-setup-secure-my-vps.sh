#!/usr/bin/env bash

# VPS Quick Setup Script
# Author: [Your Name]
# License: MIT
# Description: This script automates the setup and configuration of a new VPS.

# Define colors and symbols for output
RD="\033[01;31m"
YW="\033[33m"
GN="\033[1;92m"
CL="\033[m"
CM="${GN}✓${CL}"
CROSS="${RD}✗${CL}"

# Function to display success, info, and error messages
msg_ok() { echo -e "${CM} $1"; }
msg_info() { echo -e "${YW}ℹ️  $1${CL}"; }
msg_error() { echo -e "${CROSS} $1"; }

# Exit script on error
set -euo pipefail
shopt -s inherit_errexit nullglob

# Function to display header
header_info() {
  clear
  cat <<"EOF"
   ____    __              ____      ____                                    _   _____  ______
  / __/__ / /___ _____    / __/___  / __/__ ______ _________   __ _  __ __  | | / / _ \/ __/ /
 _\ \/ -_) __/ // / _ \   > _/_ _/ _\ \/ -_) __/ // / __/ -_) /  ' \/ // /  | |/ / ___/\ \/_/
/___/\__/\__/\_,_/ .__/  |_____/  /___/\__/\__/\_,_/_/  \__/ /_/_/_/\_, /   |___/_/  /___(_)
                /_/                                                /___/
EOF
}

# Ensure root privileges
check_root() {
  if [[ "$EUID" -ne 0 ]]; then
    msg_error "This script must be run as root"
    exit 1
  fi
}

# Prompt for continued setup
continue_prompt() {
  if whiptail --title "Proceed with Setup?" --yesno "Do you want to proceed with the setup?" 10 60; then
    echo "Starting the setup process..."
  else
    echo "Exiting the setup. No changes have been made."
    exit 0
  fi
}

# Step 1: Set Hostname (Optional)
set_hostname() {
  if whiptail --title "Set Hostname" --yesno "Do you want to set the hostname?" 10 60 ; then
    hostname=$(whiptail --inputbox "Enter hostname (e.g. VPS-CTX42-HZR-FI)" 12 70 3>&1 1>&2 2>&3)
    hostnamectl set-hostname "$hostname"
    msg_ok "Hostname set to $hostname"
  else
    msg_info "Skipped setting hostname"
  fi
}

# Step 2: Set Time Zone (Optional)
set_timezone() {
  if whiptail --title "Set Time Zone" --yesno "Do you want to set the time zone?" 10 60 ; then
    dpkg-reconfigure tzdata
    timezone=$(timedatectl | grep "Time zone" | awk '{print $3}')
    msg_ok "Time zone set to $timezone"
  else
    msg_info "Skipped setting time zone"
  fi
}

# Step 3: Root Password Update (Optional)
set_root_password() {
  if whiptail --title "Root Password" --yesno "Do you want to create or change the root password?" 10 60 ; then
    passwd root
    msg_ok "Root password changed"
  else
    msg_info "Skipped root password change"
  fi
}

# Step 4: OS and Apps Update (Optional)
update_system() {
  if whiptail --title "Update System" --yesno "Do you want to update the system and apps to the latest version?" 10 60 --yes-button "Start" --no-button "Skip"; then
    msg_info "Updating system and apps"
    apt update && apt upgrade -y
    msg_ok "System and apps updated"
  else
    msg_info "Skipped system and apps update"
  fi
}

# Step 5: Netbird VPN Installation (Optional)
install_netbird() {
  if whiptail --title "Netbird VPN" --yesno "Do you want to install and configure Netbird VPN?" 10 60 ; then
    msg_info "Installing Netbird VPN"
    curl -fsSL https://pkgs.netbird.io/install.sh | sh
    setup_key=$(whiptail --inputbox "Enter your Netbird setup key:" 10 60 3>&1 1>&2 2>&3)
    netbird up --setup-key "$setup_key"
    netbird_ip_range=$(whiptail --inputbox "Enter your Netbird IP range (e.g., 100.92.0.0/16):" 10 60 "100.92.0.0/16" 3>&1 1>&2 2>&3)
    msg_ok "Netbird VPN installed and configured with IP range $netbird_ip_range"
  else
    msg_info "Skipped Netbird VPN installation"
  fi
}

# Step 6: Create Non-Root User (Optional)
create_user() {
  if whiptail --title "Create Non-Root User" --yesno "Do you want to create a non-root user with sudo access?" 10 60 ; then
    username=$(whiptail --inputbox "Enter username for new user:" 10 60 3>&1 1>&2 2>&3)
    adduser "$username"
    usermod -aG sudo "$username"
    msg_ok "User $username created with sudo access"
  else
    msg_info "Skipped creating non-root user"
  fi
}

# Step 7: SSH Key Setup (Optional)
setup_ssh_key() {
  if whiptail --title "SSH Key Login" --yesno "Enable SSH key-based authentication?" 20 70 ; then
    ssh_key=$(whiptail --inputbox "Enter public SSH key:" 25 70 3>&1 1>&2 2>&3)
    ssh_user=$(whiptail --inputbox "Username to add SSH key to:" 10 60 3>&1 1>&2 2>&3)

    sudo -u "$ssh_user" mkdir -p /home/"$ssh_user"/.ssh
    echo "$ssh_key" | sudo -u "$ssh_user" tee /home/"$ssh_user"/.ssh/authorized_keys >/dev/null
    chmod 600 /home/"$ssh_user"/.ssh/authorized_keys
    chown "$ssh_user":"$ssh_user" /home/"$ssh_user"/.ssh/authorized_keys

    msg_ok "SSH key added for $ssh_user. Disabling root login."
    sed -i 's/^#\?\s*PermitRootLogin\s.*/PermitRootLogin no/' /etc/ssh/sshd_config
    sed -i 's/^#\?\s*PasswordAuthentication\s.*/PasswordAuthentication no/' /etc/ssh/sshd_config
    systemctl restart sshd
  else
    msg_info "Skipped SSH key setup"
  fi
}

# Step 8: Fail2Ban Installation (Optional)
install_fail2ban() {
  if whiptail --title "Fail2Ban Installation" --yesno "Do you want to install and configure Fail2Ban?" 10 60; then
    msg_info "Installing Fail2Ban"
    apt install fail2ban -y
    systemctl enable fail2ban
    systemctl start fail2ban
    msg_ok "Fail2Ban installed and running"

    [[ -f /etc/fail2ban/jail.local ]] || cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local

    # Remove existing settings first to avoid duplicates
    sed -i '/^bantime/d' /etc/fail2ban/jail.local
    sed -i '/^findtime/d' /etc/fail2ban/jail.local
    sed -i '/^maxretry/d' /etc/fail2ban/jail.local
    sed -i '/^ignoreip/d' /etc/fail2ban/jail.local

    # Add default settings
    cat <<EOF >> /etc/fail2ban/jail.local
bantime = 600
findtime = 600
maxretry = 5
EOF

    # Only add the Netbird IP range if it's available (i.e., if Netbird was installed)
    if [[ -n "${netbird_ip_range:-}" ]]; then
      echo "ignoreip = 127.0.0.1/8 $netbird_ip_range" >> /etc/fail2ban/jail.local
      msg_ok "Netbird IP range $netbird_ip_range whitelisted in Fail2Ban"
    else
      echo "ignoreip = 127.0.0.1/8" >> /etc/fail2ban/jail.local  # Default without Netbird
      msg_info "No Netbird IP range found, only localhost whitelisted in Fail2Ban"
    fi

    systemctl restart fail2ban
    msg_ok "Fail2Ban configuration updated and service restarted"
  else
    msg_info "Skipped Fail2Ban installation"
  fi
}

# Step 9: UFW Firewall Installation (Optional)
install_ufw() {
  if whiptail --title "Uncomplicated Firewall (UFW)" --yesno "Do you want to install and configure UFW?" 10 60 ; then
    msg_info "Installing UFW"
    apt install ufw -y
    ufw allow OpenSSH
    ufw allow 80/tcp
    ufw allow 443/tcp
    [[ -n $netbird_ip_range ]] && ufw allow from "$netbird_ip_range"
    ufw enable
    msg_ok "UFW enabled with default rules"
  else
    msg_info "Skipped UFW installation"
  fi
}

# Step 10: Webmin Installation (Optional)
install_webmin() {
  if whiptail --title "Webmin" --yesno "Do you want to install Webmin for web-based server management?" 10 60 ; then
    msg_info "Installing Webmin"
    curl -o setup-repos.sh https://raw.githubusercontent.com/webmin/webmin/master/setup-repos.sh
    sh setup-repos.sh
    apt-get install --install-recommends webmin -y
    msg_ok "Webmin installed. Access at https://<server-ip>:10000"
  else
    msg_info "Skipped Webmin installation"
  fi
}

# Step 11: Install Optional Tools (Optional)
install_optional_tools() {
  if whiptail --title "Optional Tools" --yesno "Install btop, speedtest-cli, and fastfetch?" 15 75 ; then
    msg_info "Installing btop, speedtest-cli, and fastfetch"
    apt install btop speedtest-cli -y
    add-apt-repository ppa:zhangsongcui3371/fastfetch -y
    apt update
    apt install fastfetch -y
    msg_ok "Optional tools installed"
  else
    msg_info "Skipped optional tools installation"
  fi
}

# Step 12: Unattended Upgrades Setup (Optional)
setup_automatic_updates() {
  if whiptail --title "Unattended-Upgrades" --yesno "Enable automatic security updates?" 10 60 ; then
    msg_info "Installing unattended-upgrades"
    apt install unattended-upgrades -y
    printf "APT::Periodic::Update-Package-Lists \"1\";\nAPT::Periodic::Unattended-Upgrade \"1\";\n" > /etc/apt/apt.conf.d/20auto-upgrades
    sed -i 's|^//Unattended-Upgrade::Automatic-Reboot "false";|Unattended-Upgrade::Automatic-Reboot "true";|' /etc/apt/apt.conf.d/50unattended-upgrades
    systemctl start unattended-upgrades
    msg_ok "Automatic updates configured"
  else
    msg_info "Skipped automatic updates configuration"
  fi
}

# Final Summary
display_summary() {
  echo -e "\n=======================\nVPS Setup Summary\n======================="
}

# Main script execution
check_root
header_info
continue_prompt
set_hostname
set_timezone
set_root_password
update_system
install_netbird
create_user
setup_ssh_key
install_fail2ban
install_ufw
install_webmin
install_optional_tools
setup_automatic_updates
msg_ok "VPS Setup Complete!"
display_summary
