#!/usr/bin/env bash

# VPS Quick Setup Script
# Author: [Your Name]
# License: MIT
# Description: This script automates the setup and configuration of a new VPS.

# Define colors and symbols for output
RD=$(echo "\\033[01;31m")
YW=$(echo "\\033[33m")
GN=$(echo "\\033[1;92m")
CL=$(echo "\\033[m")
BFR="\\\\r\\\\033[K"
HOLD="-"
CM="${GN}✓${CL}"
CROSS="${RD}✗${CL}"

# Ensure script exits on error
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

# Welcome Screen
welcome_screen() {
  whiptail --title "Welcome to VPS Quick Setup Script" --msgbox "This script will help you quickly set up your VPS with the following steps:\n\n
1. Set Hostname (Optional)\n
2. Set Time Zone\n
3. Update and Upgrade OS and Applications\n
4. Install and Configure Netbird VPN (Optional)\n
5. Create Non-Root User with Sudo Access (Optional)\n
6. Configure SSH for Key-based Login (Optional)\n
7. Install and Configure Fail2Ban (Optional)\n
8. Setup and Configure UFW (Optional)\n
9. Install Webmin (Optional)\n
10. Install Optional Tools (Optional)\n
11. Enable Automatic Security Updates (Optional)\n\n
Do you want to continue?" 20 78

  if (whiptail --title "Continue?" --yesno "Do you want to continue with the script?" 10 60); then
    echo "Starting the setup process..."
  else
    echo "Exiting the setup. No changes have been made."
    exit 0
  fi
}

check_root() {
  if [[ "$EUID" -ne 0 ]]; then
    echo -e "${RD}This script must be run as root${CL}"
    exit 1
  fi
}

check_root
header_info
welcome_screen

# Step 1: Set Hostname (Optional)
set_hostname() {
  if (whiptail --title "Set Hostname" --yesno "Do you want to set the hostname?" 10 60); then
    hostname=$(whiptail --inputbox "Enter hostname [service].[host/type].[site/location]:" 10 60 3>&1 1>&2 2>&3)
    sudo hostnamectl set-hostname "$hostname"
    msg_ok "Hostname set to $hostname"
  else
    msg_error "Skipped setting hostname"
  fi
}

set_hostname

# Step 2: Set Time Zone (Always)
set_timezone() {
  msg_info "Setting time zone"
  sudo dpkg-reconfigure tzdata
  msg_ok "Time zone set"
}

set_timezone

# Step 3: Create or Change Password for Root (Optional)
set_root_password() {
  if (whiptail --title "Root Password" --yesno "Do you want to create or change the root password?" 10 60); then
    msg_info "Changing root password"
    sudo passwd root
    msg_ok "Root password changed"
  else
    msg_error "Skipped root password change"
  fi
}

set_root_password

# Step 4: Update OS and Apps (Always with confirmation)
update_system() {
  whiptail --title "Update OS and Apps" --msgbox "Click 'Continue' to update and upgrade the system." 8 58
  msg_info "Updating system"
  sudo apt update && sudo apt upgrade -y
  msg_ok "System updated"
}

update_system

# Step 5: Install and Configure Netbird VPN (Optional)
install_netbird() {
  if (whiptail --title "Netbird VPN" --yesno "Do you want to install and configure Netbird VPN?" 10 60); then
    msg_info "Installing Netbird VPN"
    curl -fsSL https://pkgs.netbird.io/install.sh | sh
    setup_key=$(whiptail --inputbox "Enter your Netbird setup key:" 10 60 3>&1 1>&2 2>&3)
    sudo netbird up --setup-key "$setup_key"
    msg_ok "Netbird VPN installed and configured"
  else
    msg_error "Skipped Netbird VPN installation"
  fi
}

install_netbird

# Step 6: Setup Non-Root User with Sudo Access (Optional)
create_user() {
  if (whiptail --title "Non-Root User" --yesno "Do you want to create a non-root user with sudo access? (Recommended for disabling SSH root login)" 10 60); then
    username=$(whiptail --inputbox "Enter username for the new user:" 10 60 3>&1 1>&2 2>&3)
    msg_info "Creating user $username"
    sudo adduser "$username"
    sudo usermod -aG sudo "$username"
    msg_ok "User $username created and added to sudo group"
  else
    msg_error "Skipped creating non-root user"
  fi
}

create_user

# Step 7: Enable SSH Key for Passwordless Login and Enforce Key-Based Authentication (Optional)
setup_ssh_key() {
  if (whiptail --title "SSH Key Login" --yesno "Do you want to enable SSH key for passwordless login and enforce key-based authentication?" 10 60); then
    echo "Please provide your public SSH key for passwordless login."
    echo "Tip: On your local machine (Mac/Linux/WSL), you can retrieve your public key using:"
    echo "  cat ~/.ssh/id_rsa.pub  # For RSA key"
    echo "  cat ~/.ssh/id_ed25519.pub  # For Ed25519 key"
    echo "Example output:"
    echo "  ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQE... user@hostname"
    ssh_key=$(whiptail --inputbox "Paste your public SSH key here:" 10 60 3>&1 1>&2 2>&3)
    mkdir -p ~/.ssh
    echo "$ssh_key" >> ~/.ssh/authorized_keys
    chmod 600 ~/.ssh/authorized_keys
    msg_info "Configuring SSH"
    sudo sed -i 's/PermitRootLogin .*/PermitRootLogin no/' /etc/ssh/sshd_config
    sudo sed -i 's/PasswordAuthentication .*/PasswordAuthentication no/' /etc/ssh/sshd_config
    sudo sed -i 's/PubkeyAuthentication .*/PubkeyAuthentication yes/' /etc/ssh/sshd_config
    sudo systemctl restart sshd
    msg_ok "SSH key added and root login disabled"
  else
    msg_info "Disabling root login but keeping password authentication for SSH"
    sudo sed -i 's/PermitRootLogin .*/PermitRootLogin no/' /etc/ssh/sshd_config
    sudo sed -i 's/PubkeyAuthentication .*/PubkeyAuthentication yes/' /etc/ssh/sshd_config
    sudo systemctl restart sshd
    msg_ok "Root login disabled, but password login enabled"
  fi
}

setup_ssh_key

# Step 8: Install and Configure Fail2Ban (Optional)
install_fail2ban() {
  if (whiptail --title "Fail2Ban" --yesno "Do you want to install and configure Fail2Ban?" 10 60); then
    msg_info "
