#!/usr/bin/env bash

# Ubuntu VPS Setup Script
# Author: SkillGap.io
# License: MIT
# Description: Script to configure a new Ubuntu VPS

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

# Function to display header info
header_info() {
  clear
  cat <<"EOF"
    ____  _    ____  ____  _____   ____             __     ____           __       
   / __ \| |  / /  |/  / |/ /   | / __ \____  _____/ /_   /  _/___  _____/ /______
  / /_/ / | / / /|_/ / /|_/ / /| |/ / / / __ \/ ___/ __/   / // __ \/ ___/ //_/ ___/
 / ____/| |/ / /  / / /  / / ___ / /_/ / /_/ (__  ) /_   _/ // / / (__  ) ,< (__  ) 
/_/     |___/_/  /_/_/  /_/_/  |_\____/\____/____/\__/  /___/_/ /_/____/_/|_/____/ 

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

# Function to check if running as root
check_root() {
  if [[ "$EUID" -ne 0 ]]; then
    echo -e "${RD}This script must be run as root${CL}"
    exit 1
  fi
}

check_root

# 1. Configure Timezone
configure_timezone() {
  CHOICE=$(whiptail --title "Timezone Configuration" --menu "Change the timezone?" 14 58 2 \
    "yes" " " \
    "no" " " 3>&2 2>&1 1>&3)
  case $CHOICE in
  yes)
    msg_info "Changing timezone"
    sudo dpkg-reconfigure tzdata
    msg_ok "Timezone updated"
    ;;
  no)
    msg_error "Timezone configuration skipped"
    ;;
  esac
}

# 2. Set Root Password
set_root_password() {
  CHOICE=$(whiptail --title "Root Password" --menu "Change or set root password?" 14 58 2 \
    "yes" " " \
    "no" " " 3>&2 2>&1 1>&3)
  case $CHOICE in
  yes)
    msg_info "Changing root password"
    sudo passwd root
    msg_ok "Root password changed"
    ;;
  no)
    msg_error "Root password change skipped"
    ;;
  esac
}

# 3. Update System
update_system() {
  CHOICE=$(whiptail --title "System Update" --menu "Update and upgrade the system?" 14 58 2 \
    "yes" " " \
    "no" " " 3>&2 2>&1 1>&3)
  case $CHOICE in
  yes)
    msg_info "Updating system"
    sudo apt update && sudo apt upgrade -y
    msg_ok "System updated"
    ;;
  no)
    msg_error "System update skipped"
    ;;
  esac
}

# 4. Install Netbird VPN Client
install_netbird() {
  CHOICE=$(whiptail --title "Netbird VPN" --menu "Install Netbird VPN client?" 14 58 2 \
    "yes" " " \
    "no" " " 3>&2 2>&1 1>&3)
  case $CHOICE in
  yes)
    msg_info "Installing Netbird VPN client"
    curl -fsSL https://pkgs.netbird.io/install.sh | sh
    msg_ok "Netbird VPN client installed"
    ;;
  no)
    msg_error "Netbird VPN client installation skipped"
    ;;
  esac
}

# 5. Configure Netbird VPN
configure_netbird() {
  CHOICE=$(whiptail --title "Netbird VPN Configuration" --menu "Configure Netbird VPN?" 14 58 2 \
    "yes" " " \
    "no" " " 3>&2 2>&1 1>&3)
  case $CHOICE in
  yes)
    read -p "Enter your Netbird setup key: " setup_key
    msg_info "Configuring Netbird VPN"
    sudo netbird up --setup-key "$setup_key"
    msg_ok "Netbird VPN configured"
    ;;
  no)
    msg_error "Netbird VPN configuration skipped"
    ;;
  esac
}

# 6. Create Non-Root User
create_user() {
  CHOICE=$(whiptail --title "Create Non-Root User" --menu "Create a non-root user and add to sudo?" 14 58 2 \
    "yes" " " \
    "no" " " 3>&2 2>&1 1>&3)
  case $CHOICE in
  yes)
    read -p "Enter the username for the new user: " username
    msg_info "Creating user $username"
    sudo adduser $username
    sudo usermod -aG sudo $username
    msg_ok "User $username created and added to sudo"
    ;;
  no)
    msg_error "User creation skipped"
    ;;
  esac
}

# 7. Install Fail2Ban
install_fail2ban() {
  CHOICE=$(whiptail --title "Install Fail2Ban" --menu "Install Fail2Ban for brute-force protection?" 14 58 2 \
    "yes" " " \
    "no" " " 3>&2 2>&1 1>&3)
  case $CHOICE in
  yes)
    msg_info "Installing Fail2Ban"
    sudo apt install -y fail2ban
    msg_ok "Fail2Ban installed"
    ;;
  no)
    msg_error "Fail2Ban installation skipped"
    ;;
  esac
}

# 8. Install and Configure UFW
install_ufw() {
  CHOICE=$(whiptail --title "Install and Configure UFW" --menu "Install and configure UFW (Uncomplicated Firewall)?" 14 58 2 \
    "yes" " " \
    "no" " " 3>&2 2>&1 1>&3)
  case $CHOICE in
  yes)
    msg_info "Installing UFW"
    sudo apt install -y ufw
    sudo ufw allow OpenSSH
    sudo ufw enable
    msg_ok "UFW installed and configured"
    ;;
  no)
    msg_error "UFW installation and configuration skipped"
    ;;
  esac
}

# 9. Install Additional Packages
install_additional_packages() {
  CHOICE=$(whiptail --title "Install Additional Packages" --menu "Install additional utilities (btop, speedtest-cli, neofetch, unattended-upgrades)?" 14 58 2 \
    "yes" " " \
    "no" " " 3>&2 2>&1 1>&3)
  case $CHOICE in
  yes)
    msg_info "Installing additional packages"
    sudo apt install -y btop speedtest-cli neofetch unattended-upgrades
    msg_ok "Additional packages installed"
    ;;
  no)
    msg_error "Installation of additional packages skipped"
    ;;
  esac
}

start_routines() {
  header_info
  
  configure_timezone
  set_root_password
  update_system
  install_netbird
  configure_netbird
  create_user
  install_fail2ban
  install_ufw
  install_additional_packages
}

# Start the configuration routines
start_routines
