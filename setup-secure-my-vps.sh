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
  whiptail --title "🚀 VPS Quick Setup Script 🚀" --msgbox "Welcome to the VPS Quick Setup Script!\n\n
🔧 This script will guide you through the essential setup of your VPS.\n\n
✨ Key Highlights ✨\n
- System Update & Optimization
- Security Configuration
- User & SSH Setup
- Optional Tools & Services\n\n
Ready to start the configuration?" 15 60
}

continue_prompt() {
  if (whiptail --title "Proceed with Setup?" --yesno "Do you want to proceed with the setup?" 10 60); then
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
continue_prompt

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
    msg_info "Installing Fail2Ban"
    sudo apt install fail2ban -y
    sudo systemctl enable fail2ban
    sudo systemctl start fail2ban
    msg_ok "Fail2Ban installed with default settings"
    echo "Default Fail2Ban settings:"
    echo "  bantime = 10m"
    echo "  findtime = 10m"
    echo "  maxretry = 5"
    echo "  ignoreip = 127.0.0.1/8 ::1"
  else
    msg_error "Skipped Fail2Ban installation"
  fi
}

install_fail2ban

# Step 9: Setup and Configure UFW (Optional)
install_ufw() {
  if (whiptail --title "Uncomplicated Firewall (UFW)" --yesno "Do you want to install and configure UFW?" 10 60); then
    msg_info "Installing UFW"
    sudo apt install ufw -y
    sudo ufw allow OpenSSH
    sudo ufw allow 80/tcp
    sudo ufw allow 443/tcp

    # Ask for custom firewall rules
    while (whiptail --title "Custom UFW Rule" --yesno "Do you want to add a custom UFW rule?" 10 60); do
      port=$(whiptail --inputbox "Enter the port number:" 10 60 3>&1 1>&2 2>&3)
      protocol=$(whiptail --menu "Select protocol:" 10 60 2 "TCP" "" "UDP" "" 3>&1 1>&2 2>&3)
      ip_range=$(whiptail --inputbox "Allow traffic from (e.g., 0.0.0.0/0 for anywhere, or specific IP range):" 10 60 3>&1 1>&2 2>&3)

      sudo ufw allow from "$ip_range" to any port "$port" proto "$protocol"
      msg_ok "Custom UFW rule added for port $port ($protocol) from $ip_range"
    done

    sudo ufw enable
    msg_ok "UFW installed and configured"
  else
    msg_error "Skipped UFW installation"
  fi
}

install_ufw

# Step 10: Install Webmin (Optional)
install_webmin() {
  if (whiptail --title "Webmin" --yesno "Do you want to install Webmin for web-based server management?" 10 60); then
    msg_info "Installing Webmin"
    curl -o setup-repos.sh https://raw.githubusercontent.com/webmin/webmin/master/setup-repos.sh
    sh setup-repos.sh
    sudo apt-get install --install-recommends webmin -y

    msg_ok "Webmin installed"
    echo "You can access Webmin via your browser at https://<server-ip>:10000"
  else
    msg_error "Skipped Webmin installation"
  fi
}

install_webmin

# Step 11: Install Optional Tools (Optional)
install_optional_tools() {
  if (whiptail --title "Optional Tools" --yesno "Do you want to install optional tools (btop, speedtest-cli, fastfetch)?" 10 60); then
    msg_info "Installing optional tools"
    sudo apt install btop speedtest-cli -y
    sudo add-apt-repository ppa:zhangyunchen3371/fastfetch -y
    sudo apt update
    sudo apt install fastfetch -y
    msg_ok "Optional tools installed"
  else
    msg_error "Skipped optional tools installation"
  fi
}

install_optional_tools

# Step 12: Automatic Security Updates (Optional)
setup_automatic_updates() {
  if (whiptail --title "Automatic Security Updates" --yesno "Do you want to enable automatic security updates?" 10 60); then
    msg_info "Installing unattended-upgrades for automatic security updates"
    sudo apt install unattended-upgrades -y
    sudo dpkg-reconfigure --priority=low unattended-upgrades

    msg_ok "Automatic security updates configured"
    echo "Security updates will be checked daily, but no automatic reboot."
  else
    msg_error "Skipped automatic security updates"
  fi
}

setup_automatic_updates

msg_ok "VPS Quick Setup is complete!"
