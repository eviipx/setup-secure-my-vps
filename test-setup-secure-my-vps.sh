#!/bin/bash

# Colors for output
COLOR_GREEN="\e[32m"
COLOR_YELLOW="\e[33m"
COLOR_RED="\e[31m"
COLOR_RESET="\e[0m"

check_root() {
  if [ "$EUID" -ne 0 ]; then
    echo -e "${COLOR_RED}✗ This script must be run as root${COLOR_RESET}"
    exit 1
  fi
}

success() {
  echo -e "${COLOR_GREEN}✔ $1${COLOR_RESET}"
}

info() {
  echo -e "${COLOR_YELLOW}ℹ $1${COLOR_RESET}"
}

error() {
  echo -e "${COLOR_RED}✗ $1${COLOR_RESET}"
}

# Install required dependencies: whiptail
apt install -y whiptail

ask_hostname() {
  if whiptail --yesno "Would you like to set a hostname?" 8 40; then
    HOSTNAME=$(whiptail --inputbox "Enter your desired hostname" 8 40 3>&1 1>&2 2>&3)
    hostnamectl set-hostname $HOSTNAME && success "Hostname set to $HOSTNAME"
  else
    info "Skipping hostname configuration"
  fi
}

ask_timezone() {
  if whiptail --yesno "Would you like to configure the time zone?" 8 40; then
    dpkg-reconfigure tzdata && success "Time zone updated"
  else
    info "Skipping time zone configuration"
  fi
}

ask_root_password() {
  if whiptail --yesno "Do you want to change the root password?" 8 40; then
    passwd && success "Root password updated"
  else
    info "Skipping root password change"
  fi
}

update_system() {
  if whiptail --yesno "Do you want to update system packages?" 8 40; then
    apt update && apt upgrade -y && success "System updated"
  else
    info "Skipping system update"
  fi
}

install_netbird() {
  if whiptail --yesno "Would you like to install Netbird VPN?" 8 40; then
    NETBIRD_KEY=$(whiptail --inputbox "Enter your Netbird setup key" 8 40 3>&1 1>&2 2>&3)
    NETBIRD_IP_RANGE=$(whiptail --inputbox "Enter desired IP range for Netbird" 8 40 3>&1 1>&2 2>&3)
    # Example installation command, to be replaced with actual Netbird install process
    curl -fsSL https://packages.netbird.io/install.sh | sh && netbird up --setup-key=$NETBIRD_KEY --vpn-range=$NETBIRD_IP_RANGE
    success "Netbird VPN installed and configured"
  else
    info "Skipping Netbird VPN installation"
  fi
}

create_user() {
  if whiptail --yesno "Would you like to create a new non-root user?" 8 40; then
    USERNAME=$(whiptail --inputbox "Enter the new username" 8 40 3>&1 1>&2 2>&3)
    adduser $USERNAME && usermod -aG sudo $USERNAME && success "User $USERNAME created and added to sudo group"
  else
    info "Skipping user creation"
  fi
}

configure_ssh() {
  if whiptail --yesno "Would you like to configure SSH?" 8 40; then
    if whiptail --yesno "Disable root login and password authentication?" 8 40; then
      sed -i '/PermitRootLogin/s/yes/no/' /etc/ssh/sshd_config
      sed -i '/PasswordAuthentication/s/yes/no/' /etc/ssh/sshd_config
      success "SSH root login and password authentication disabled"
    fi
    if whiptail --yesno "Set up passwordless SSH login (enter SSH public key)?" 8 40; then
      PUBKEY=$(whiptail --inputbox "Enter your SSH public key" 8 40 3>&1 1>&2 2>&3)
      mkdir -p /home/$USERNAME/.ssh && echo $PUBKEY > /home/$USERNAME/.ssh/authorized_keys && chown -R $USERNAME:$USERNAME /home/$USERNAME/.ssh
      chmod 600 /home/$USERNAME/.ssh/authorized_keys
      success "SSH key added for $USERNAME"
    fi
    systemctl restart sshd && success "SSH configuration finished"
  else
    info "Skipping SSH configuration"
  fi
}

install_fail2ban() {
  if whiptail --yesno "Would you like to install Fail2Ban?" 8 40; then
    apt install -y fail2ban && systemctl enable fail2ban --now
    success "Fail2Ban installed and running"
  else
    info "Skipping Fail2Ban installation"
  fi
}

configure_ufw() {
  if whiptail --yesno "Would you like to configure UFW (firewall)?" 8 40; then
    apt install -y ufw
    ufw allow OpenSSH
    if whiptail --yesno "Allow HTTP and HTTPS?" 8 40; then
      ufw allow http && ufw allow https && success "Allowed HTTP and HTTPS through firewall"
    fi
    ufw enable && success "UFW firewall configured and enabled"
  else
    info "Skipping UFW configuration"
  fi
}

install_webmin() {
  if whiptail --yesno "Do you want to install Webmin?" 8 40; then
    wget -q -O - http://www.webmin.com/jcameron-key.asc | apt-key add -
    echo "deb http://download.webmin.com/download/repository sarge contrib" > /etc/apt/sources.list.d/webmin.list
    apt update && apt install webmin -y && success "Webmin installed"
  else
    info "Skipping Webmin installation"
  fi
}

install_optional_tools() {
  if whiptail --yesno "Do you want to install optional tools (btop, speedtest-cli, fastfetch)?" 8 40; then
    apt install -y btop speedtest-cli fastfetch && success "Optional tools installed"
  else
    info "Skipping optional tools installation"
  fi
}

enable_auto_updates() {
  if whiptail --yesno "Do you want to enable automatic security updates?" 8 40; then
    apt install -y unattended-upgrades
    dpkg-reconfigure --priority=low unattended-upgrades && success "Automatic security updates enabled"
  else
    info "Skipping automatic updates"
  fi
}

summary() {
  whiptail --msgbox "Setup complete! Review the installation steps in the log above." 8 40
  echo -e "${COLOR_GREEN}Setup Complete!${COLOR_RESET}"
}

# Run all the functions in sequence
main() {
  check_root
  ask_hostname
  ask_timezone
  ask_root_password
  update_system
  install_netbird
  create_user
  configure_ssh
  install_fail2ban
  configure_ufw
  install_webmin
  install_optional_tools
  enable_auto_updates
  summary
}

main
