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

# Functions for displaying messages
msg_info() {
  local msg="$1"
  echo -ne " ${HOLD} ${YW}${msg}..."
}

msg_ok() {
  local msg="$1"
  echo -e "${BFR} ${CM} ${GN}${msg}${CL}"
}

msg_error() {
  local msg="$1"
  echo -e "${BFR} ${CROSS} ${RD}${msg}${CL}"
}

# Check if running as root
check_root() {
  if [[ "$EUID" -ne 0 ]]; then
    echo -e "${RD}This script must be run as root${CL}"
    exit 1
  fi
}

check_root
header_info

# Step 1: Set Hostname (Optional)
set_hostname() {
  CHOICE=$(whiptail --title "Set Hostname" --menu "Do you want to set the hostname?" 14 58 2 \
    "yes" " " \
    "no" " " 3>&2 2>&1 1>&3)
  case $CHOICE in
    yes)
      read -p "Enter hostname [service].[host/type].[site/location]: " hostname
      sudo hostnamectl set-hostname "$hostname"
      msg_ok "Hostname set to $hostname"
      ;;
    no)
      msg_error "Skipped setting hostname"
      ;;
  esac
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
  CHOICE=$(whiptail --title "Root Password" --menu "Do you want to create or change the root password?" 14 58 2 \
    "yes" " " \
    "no" " " 3>&2 2>&1 1>&3)
  case $CHOICE in
    yes)
      msg_info "Changing root password"
      sudo passwd root
      msg_ok "Root password changed"
      ;;
    no)
      msg_error "Skipped root password change"
      ;;
  esac
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
  CHOICE=$(whiptail --title "Netbird VPN" --menu "Do you want to install and configure Netbird VPN?" 14 58 2 \
    "yes" " " \
    "no" " " 3>&2 2>&1 1>&3)
  case $CHOICE in
    yes)
      msg_info "Installing Netbird VPN"
      curl -fsSL https://pkgs.netbird.io/install.sh | sh
      read -p "Enter your Netbird setup key: " setup_key
      sudo netbird up --setup-key "$setup_key"
      msg_ok "Netbird VPN installed and configured"
      ;;
    no)
      msg_error "Skipped Netbird VPN installation"
      ;;
  esac
}

install_netbird

# Step 6: Setup Non-Root User with Sudo Access (Optional)
create_user() {
  CHOICE=$(whiptail --title "Non-Root User" --menu "Do you want to create a non-root user with sudo access? (Recommended for disabling SSH root login)" 14 58 2 \
    "yes" " " \
    "no" " " 3>&2 2>&1 1>&3)
  case $CHOICE in
    yes)
      read -p "Enter username for the new user: " username
      msg_info "Creating user $username"
      sudo adduser "$username"
      sudo usermod -aG sudo "$username"
      msg_ok "User $username created and added to sudo group"
      ;;
    no)
      msg_error "Skipped creating non-root user"
      ;;
  esac
}

create_user

# Step 7: Enable SSH Key for Passwordless Login and Enforce Key-Based Authentication (Optional)
setup_ssh_key() {
  CHOICE=$(whiptail --title "SSH Key Login" --menu "Do you want to enable SSH key for passwordless login and enforce key-based authentication?" 14 58 2 \
    "yes" " " \
    "no" " " 3>&2 2>&1 1>&3)
  case $CHOICE in
    yes)
      echo "Please provide your public SSH key for passwordless login."
      echo "Tip: On your local machine (Mac/Linux/WSL), you can retrieve your public key using:"
      echo "  cat ~/.ssh/id_rsa.pub  # For RSA key"
      echo "  cat ~/.ssh/id_ed25519.pub  # For Ed25519 key"
      echo "Example output:"
      echo "  ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQE... user@hostname"
      read -p "Paste your public SSH key here: " ssh_key
      mkdir -p ~/.ssh
      echo "$ssh_key" >> ~/.ssh/authorized_keys
      chmod 600 ~/.ssh/authorized_keys
      msg_info "Configuring SSH"
      sudo sed -i 's/PermitRootLogin .*/PermitRootLogin no/' /etc/ssh/sshd_config
      sudo sed -i 's/PasswordAuthentication .*/PasswordAuthentication no/' /etc/ssh/sshd_config
      sudo sed -i 's/PubkeyAuthentication .*/PubkeyAuthentication yes/' /etc/ssh/sshd_config
      sudo systemctl restart sshd
      msg_ok "SSH key added and root login disabled"
      ;;
    no)
      msg_info "Disabling root login but keeping password authentication for SSH"
      sudo sed -i 's/PermitRootLogin .*/PermitRootLogin no/' /etc/ssh/sshd_config
      sudo sed -i 's/PubkeyAuthentication .*/PubkeyAuthentication yes/' /etc/ssh/sshd_config
      sudo systemctl restart sshd
      msg_ok "Root login disabled, but password login enabled"
      ;;
  esac
}

setup_ssh_key

# Step 8: Install and Configure Fail2Ban (Optional)
install_fail2ban() {
  CHOICE=$(whiptail --title "Fail2Ban" --menu "Do you want to install and configure Fail2Ban?" 14 58 2 \
    "yes" " " \
    "no" " " 3>&2 2>&1 1>&3)
  case $CHOICE in
    yes)
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
      ;;
    no)
      msg_error "Skipped Fail2Ban installation"
      ;;
  esac
}

install_fail2ban

# Step 9: Setup and Configure UFW (Optional)
install_ufw() {
  CHOICE=$(whiptail --title "Uncomplicated Firewall (UFW)" --menu "