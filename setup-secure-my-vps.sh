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
CM="${GN}✓${CL}"
CROSS="${RD}✗${CL}"

# Function to display success messages
msg_ok() {
  echo -e "${CM} $1"
}

# Function to display info messages
msg_info() {
  echo -e "${YW}ℹ️  $1${CL}"
}

# Function to display error messages
msg_error() {
  echo -e "${CROSS} $1"
}

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
  whiptail --title "🚀 Setup & Secure My VPS 🚀" --msgbox "Welcome! This script will guide you through the essential setup and security configuration of your VPS.\n\n
✨ Key Highlights ✨\n
- System Update & Optimization\n
- Security Configuration\n
- User & SSH Setup\n
- Optional Tools & Services\n" 20 75
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
    msg_error "This script must be run as root"
    exit 1
  fi
}

# Initialize tracking variables
hostname_set="No"
timezone_set="No"
root_password_set="No"
system_updated="No"
netbird_installed="No"
netbird_ip_range=""
non_root_user_created="No"
ssh_key_configured="No"
ssh_details="No SSH configuration made"
fail2ban_installed="No"
fail2ban_details="No Fail2Ban configuration"
ufw_installed="No"
ufw_rules="No UFW rules applied"
webmin_installed="No"
webmin_url="Not installed"
optional_tools_installed="No"
automatic_updates_enabled="No"
auto_updates_details="No automatic updates configured"

# Step 1: Set Hostname (Optional)
set_hostname() {
  if (whiptail --title "Set Hostname" --yesno "Do you want to set the hostname?" 10 60); then
    hostname=$(whiptail --inputbox "Enter hostname in the format:\n\n[service]-[type]-[vendor]-[location]\n\nExample: VPS-CTX42-HZR-FI or WEB-CX22-HZR-US" 12 70 3>&1 1>&2 2>&3)
    sudo hostnamectl set-hostname "$hostname"
    hostname_set="Yes (Hostname: $hostname)"
    msg_ok "Hostname set to $hostname"
  else
    msg_error "Skipped setting hostname"
  fi
}

# Step 2: Set Time Zone (Optional)
set_timezone() {
  if (whiptail --title "Set Time Zone" --yesno "Do you want to set the time zone?" 10 60); then
    sudo dpkg-reconfigure tzdata
    timezone=$(timedatectl | grep "Time zone" | awk '{print $3}')
    timezone_set="Yes (Time zone: $timezone)"
    msg_ok "Time zone set"
  else
    msg_error "Skipped setting time zone"
  fi
}

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

# Step 4: Update OS and Apps (Optional)
update_system() {
  if (whiptail --title "Update OS and Apps" --yesno "Do you want to update the system and apps to the latest version?" 10 60 --yes-button "Start" --no-button "Skip"); then
    msg_info "Updating system and apps"
    sudo apt update && sudo apt upgrade -y
    msg_ok "System and apps updated"
  else
    msg_error "Skipped system and apps update"
  fi
}

# Step 5: Setup Overlay Network/VPN (Netbird) (Optional)
install_netbird() {
  if (whiptail --title "Netbird VPN" --yesno "Do you want to install and configure Netbird VPN?" 10 60); then
    msg_info "Installing Netbird VPN"
    curl -fsSL https://pkgs.netbird.io/install.sh | sh
    setup_key=$(whiptail --inputbox "Enter your Netbird setup key (Example: XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX)" 10 60 3>&1 1>&2 2>&3)
    sudo netbird up --setup-key "$setup_key"

    # Prompt for Netbird IP range
    netbird_ip_range=$(whiptail --inputbox "Enter your Netbird IP range (e.g., 100.92.0.0/16):" 10 60 "100.92.0.0/16" 3>&1 1>&2 2>&3)
    msg_ok "Netbird VPN installed and configured with IP range $netbird_ip_range"
  else
    msg_error "Skipped Netbird VPN installation"
  fi
}

# Step 6: Setup Non-Root User with Sudo Access (Optional)
create_user() {
  if (whiptail --title "Non-Root User" --yesno "Do you want to create a non-root user with sudo access? (Recommended to be able to disable root login for SSH)" 10 60); then
    username=$(whiptail --inputbox "Enter username for the new user:" 10 60 3>&1 1>&2 2>&3)
    msg_info "Creating user $username"
    sudo adduser "$username"
    sudo usermod -aG sudo "$username"
    msg_ok "User $username created and added to sudo group"
  else
    msg_error "Skipped creating non-root user"
  fi
}

# Step 7: SSH Key for Passwordless Login and Enforce Key-Based Authentication (Optional)
setup_ssh_key() {
  if (whiptail --title "SSH Key Login" --yesno "Do you want to enable SSH key for passwordless login and enforce key-based authentication?" 20 70); then
    # SSH key prompt with enhanced instructions
    ssh_key=$(whiptail --inputbox "Please provide your public SSH key for passwordless login.\n\nTip: If you're on a Mac or Linux machine, you can view your public key using:\n\n  cat ~/.ssh/id_rsa.pub  # For RSA key\n  cat ~/.ssh/id_ed25519.pub  # For Ed25519 key\n\nExample output (RSA key):\n  ssh-rsa AAAAB3Nza...rest_of_key... user@hostname\n\nCopy the entire output and paste it here:" 25 70 3>&1 1>&2 2>&3)

    # Prompt for the username to add the SSH key to
    ssh_user=$(whiptail --inputbox "Enter the username for SSH key setup (e.g., the non-root user you created):" 10 60 3>&1 1>&2 2>&3)

    # Add SSH key to the specified user's authorized_keys
    sudo -u "$ssh_user" mkdir -p /home/"$ssh_user"/.ssh
    echo "$ssh_key" | sudo -u "$ssh_user" tee /home/"$ssh_user"/.ssh/authorized_keys >/dev/null
    sudo chmod 600 /home/"$ssh_user"/.ssh/authorized_keys
    sudo chown "$ssh_user":"$ssh_user" /home/"$ssh_user"/.ssh/authorized_keys

    msg_info "Configuring SSH"
    # Backup sshd_config
    sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak

    # Modify SSH configuration to disable root login and password authentication
    sudo sed -i 's/^#\?\s*PermitRootLogin\s.*/PermitRootLogin no/' /etc/ssh/sshd_config
    sudo sed -i 's/^#\?\s*PasswordAuthentication\s.*/PasswordAuthentication no/' /etc/ssh/sshd_config
    sudo sed -i 's/^#\?\s*PubkeyAuthentication\s.*/PubkeyAuthentication yes/' /etc/ssh/sshd_config

    # Restart SSH service
    sudo systemctl restart sshd

    ssh_details=$(sudo sshd -T | grep -E 'permitrootlogin|pubkeyauthentication|passwordauthentication')
    ssh_key_configured="Yes (SSH settings: $ssh_details)"
    msg_ok "SSH key added for user $ssh_user and root login disabled"
  else
    ssh_details=$(sudo sshd -T | grep -E 'permitrootlogin|pubkeyauthentication|passwordauthentication')
    ssh_key_configured="No"
    msg_info "Disabling root login but keeping password authentication for SSH"
    sudo sed -i 's/^#\?\s*PermitRootLogin\s.*/PermitRootLogin no/' /etc/ssh/sshd_config
    sudo sed -i 's/^#\?\s*PubkeyAuthentication\s.*/PubkeyAuthentication yes/' /etc/ssh/sshd_config
    sudo systemctl restart sshd
    msg_ok "Root login disabled, but password login enabled"
  fi
}

# Step 8: Install and Configure Fail2Ban (Optional)
install_fail2ban() {
  if (whiptail --title "Fail2Ban" --yesno "Do you want to install and configure Fail2Ban?" 10 60); then
    # Install Fail2Ban if not already installed
    msg_info "Installing Fail2Ban"
    sudo apt install fail2ban -y

    # Enable Fail2Ban service
    msg_info "Enabling and starting Fail2Ban service"
    sudo systemctl enable fail2ban

    # Check if Fail2Ban service is already running
    if sudo systemctl is-active --quiet fail2ban; then
      msg_info "Fail2Ban is already running. Reloading the service to apply changes."
      sudo systemctl reload fail2ban
    else
      sudo systemctl start fail2ban
    fi

    # Create a local jail configuration if it doesn't exist
    if [ ! -f /etc/fail2ban/jail.local ]; then
      msg_info "Creating /etc/fail2ban/jail.local from the default configuration"
      sudo cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
    fi

    # Ensure default settings are present in jail.local
    msg_info "Ensuring default Fail2Ban settings are in place"
    sudo sed -i '/^bantime/d' /etc/fail2ban/jail.local
    sudo sed -i '/^findtime/d' /etc/fail2ban/jail.local
    sudo sed -i '/^maxretry/d' /etc/fail2ban/jail.local
    sudo sed -i '/^ignoreip/d' /etc/fail2ban/jail.local

    # Add default values for Fail2Ban if they are missing
    sudo bash -c 'echo "bantime = 600" >> /etc/fail2ban/jail.local'
    sudo bash -c 'echo "findtime = 600" >> /etc/fail2ban/jail.local'
    sudo bash -c 'echo "maxretry = 5" >> /etc/fail2ban/jail.local'
    sudo bash -c 'echo "ignoreip = 127.0.0.1/8 $netbird_ip_range" >> /etc/fail2ban/jail.local'

    msg_ok "Default Fail2Ban settings ensured"

    # Restart Fail2Ban to apply changes
    msg_info "Restarting Fail2Ban service to apply configuration changes"
    sudo systemctl restart fail2ban

    # Verify if Fail2Ban restarted successfully
    if sudo systemctl is-active --quiet fail2ban; then
      msg_ok "Fail2Ban restarted successfully"
    else
      msg_error "Fail2Ban failed to restart. Please check logs."
      return 1 # Exit the function if Fail2Ban fails to restart
    fi

    # Extract relevant Fail2Ban settings for summary
    msg_info "Extracting Fail2Ban settings for summary"
    bantime=$(grep -E '^bantime' /etc/fail2ban/jail.local | head -n 1 | tr -d "'")
    findtime=$(grep -E '^findtime' /etc/fail2ban/jail.local | head -n 1 | tr -d "'")
    maxretry=$(grep -E '^maxretry' /etc/fail2ban/jail.local | head -n 1 | tr -d "'")
    ignoreip=$(grep -E '^ignoreip' /etc/fail2ban/jail.local | head -n 1 | tr -d "'")

    echo "DEBUG: bantime=$bantime, findtime=$findtime, maxretry=$maxretry, ignoreip=$ignoreip"

    if [ -z "$bantime" ] || [ -z "$findtime" ] || [ -z "$maxretry" ] || [ -z "$ignoreip" ]; then
      msg_error "Failed to extract Fail2Ban settings. Please check /etc/fail2ban/jail.local."
      return 1
    else
      fail2ban_details="bantime = $bantime, findtime = $findtime, maxretry = $maxretry, ignoreip = $ignoreip"
      fail2ban_installed="Yes (Settings: $fail2ban_details)"
      msg_ok "Fail2Ban installed and configured"
    fi

  else
    msg_error "Skipped Fail2Ban installation"
  fi
}

# Main script execution starts here
check_root
header_info
welcome_screen
continue_prompt
set_hostname
set_timezone
set_root_password
update_system
install_netbird
create_user
setup_ssh_key
install_fail2ban

# Step 9: Install and Configure UFW (Optional)
install_ufw() {
  if (whiptail --title "Uncomplicated Firewall (UFW)" --yesno "Do you want to install and configure Uncomplicated Firewall (UFW)?" 10 60); then
    msg_info "Installing UFW"
    sudo apt install ufw -y

    # Enable UFW with default settings
    if (whiptail --title "Enable UFW" --yesno "Do you want to enable UFW and apply default settings?\n(Default: Allow OpenSSH, HTTP, and HTTPS)" 10 60); then
      sudo ufw allow OpenSSH
      sudo ufw allow 80/tcp
      sudo ufw allow 443/tcp

      # Allow traffic from Netbird IP range if set
      if [ -n "$netbird_ip_range" ]; then
        sudo ufw allow from "$netbird_ip_range"
        msg_ok "Allowed traffic from Netbird IP range: $netbird_ip_range"
      fi

      sudo ufw enable
      ufw_rules=$(sudo ufw status)
      msg_ok "UFW enabled with default settings (OpenSSH, HTTP, HTTPS)"
    else
      msg_error "UFW was installed but not enabled"
    fi

    # Existing code for adding custom UFW rules
    while (whiptail --title "Custom Firewall Rule" --yesno "Do you want to add a custom firewall rule?" 10 60); do
      # Custom rule prompts...
    done

  else
    msg_error "Skipped UFW installation"
  fi
}

    # Step 9.3: Ask for custom firewall rules
    while (whiptail --title "Custom Firewall Rule" --yesno "Do you want to add a custom firewall rules?" 10 60); do
      port=$(whiptail --inputbox "Enter the port number:" 10 60 3>&1 1>&2 2>&3)
      protocol=$(whiptail --menu "Select protocol:" 10 60 2 "TCP" "" "UDP" "" 3>&1 1>&2 2>&3)
      ip_range=$(whiptail --inputbox "Allow traffic from (e.g., 0.0.0.0/0 for anywhere, or specific IP range):" 10 60 3>&1 1>&2 2>&3)

      sudo ufw allow from "$ip_range" to any port "$port" proto "$protocol"
      msg_ok "Custom UFW rule added for port $port ($protocol) from $ip_range"
    done

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
  if (whiptail --title "Optional Tools" --yesno "Do you want to install the following optional tools?\n\n\
1. 📊 **btop**: A system resource monitor.\n\
2. ⚡ **speedtest-cli**: A tool to check network speed.\n\
3. 🔍 **fastfetch**: A system information tool." 15 75); then
    msg_info "Installing optional tools"

    # Install btop and speedtest-cli
    sudo apt install btop speedtest-cli -y

    # Add the repository and install fastfetch
    sudo add-apt-repository ppa:zhangsongcui3371/fastfetch -y
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
  if (whiptail --title "Configuring Unattended-Upgrades" --yesno "Enable automatic download and installation of stable security updates?" 10 60); then
    sudo apt install unattended-upgrades -y

    msg_info "Configuring unattended-upgrades"

    # Enable automatic updates by creating or modifying /etc/apt/apt.conf.d/20auto-upgrades
    sudo bash -c 'cat > /etc/apt/apt.conf.d/20auto-upgrades <<EOF
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF'

    # Optionally, configure automatic reboot if required
    sudo sed -i 's|^//Unattended-Upgrade::Automatic-Reboot "false";|Unattended-Upgrade::Automatic-Reboot "true";|' /etc/apt/apt.conf.d/50unattended-upgrades

    # Extract relevant Unattended-Upgrade settings for summary
    auto_reboot=$(grep -E '^Unattended-Upgrade::Automatic-Reboot' /etc/apt/apt.conf.d/50unattended-upgrades | head -n 1 | tr -d '";')
    update_frequency=$(grep -E 'APT::Periodic::Update-Package-Lists' /etc/apt/apt.conf.d/20auto-upgrades | cut -d '"' -f2)
    upgrade_frequency=$(grep -E 'APT::Periodic::Unattended-Upgrade' /etc/apt/apt.conf.d/20auto-upgrades | cut -d '"' -f2)

    # Extract allowed origins (types of updates)
    allowed_origins=$(grep -E 'Unattended-Upgrade::Allowed-Origins' /etc/apt/apt.conf.d/50unattended-upgrades | grep -oE '".*";' | tr -d '";')

    auto_updates_details="Automatic-Reboot = $auto_reboot, Update frequency: $update_frequency days, Upgrade frequency: $upgrade_frequency days, Allowed updates: $allowed_origins"
    automatic_updates_enabled="Yes (Settings: $auto_updates_details)"
    msg_ok "Automatic security updates configured"
  else
    msg_error "Skipped automatic security updates"
  fi
}

setup_automatic_updates

# Final Summary
display_summary() {
  GREEN='\033[1;32m'
  RED='\033[1;31m'
  BOLD='\033[1m'
  NC='\033[0m' # No Color

  echo ""
  echo "======================="
  echo "VPS Setup Summary"
  echo "======================="

  # Function to format YES/NO with colors and symbols
  format_status() {
    if [[ $1 == "Yes"* ]]; then
      echo -e "✅ ${BOLD}${GREEN}YES${NC} $2"
    else
      echo -e "❌ ${BOLD}${RED}NO${NC} $2"
    fi
  }

  echo -e "Hostname set:          $(format_status \"$hostname_set\")"
  echo -e "Time zone set:         $(format_status \"$timezone_set\")"
  echo -e "Root password set:     $(format_status \"$root_password_set\")"
  echo -e "System updated to latest version: $(format_status \"$system_updated\")"
  echo -e "Netbird VPN installed: $(format_status \"$netbird_installed\")"
  echo -e "Non-root user created: $(format_status \"$non_root_user_created\")"
  echo -e "SSH key configured:    $(format_status \"$ssh_key_configured\")"
  echo -e "Fail2Ban installed:    $(format_status \"$fail2ban_installed\")"
  echo -e "UFW installed:         $(format_status \"$ufw_installed\")"
  echo -e "Webmin installed:      $(format_status \"$webmin_installed\")"
  echo -e "Optional tools installed: $(format_status \"$optional_tools_installed\")"
  echo -e "Automatic security updates enabled: $(format_status \"$automatic_updates_enabled\")"
  echo ""
}

# Call the summary function at the end of the script
msg_ok "VPS Quick Setup is complete!"
display_summary
