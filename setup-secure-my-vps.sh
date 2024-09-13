# Step 12: Automatic Security Updates (Optional)
setup_automatic_updates() {
  if (whiptail --title "Configuring Unattended-Upgrades" --yesno "Enable automatic download and installation of stable security updates?" 10 60); then
    msg_info "Installing unattended-upgrades"
    sudo apt install unattended-upgrades -y

    # Check if unattended-upgrades is already installed
    if dpkg-query -W -f='${Status}' unattended-upgrades 2>/dev/null | grep -q "ok installed"; then
      msg_ok "unattended-upgrades is already installed"
    else
      msg_info "Installing unattended-upgrades"
      sudo apt install unattended-upgrades -y
    fi

    msg_info "Configuring unattended-upgrades"

    # Check if the configuration files exist and make necessary changes
    if [ -f /etc/apt/apt.conf.d/20auto-upgrades ]; then
      msg_info "Modifying /etc/apt/apt.conf.d/20auto-upgrades"
      sudo bash -c 'cat > /etc/apt/apt.conf.d/20auto-upgrades <<EOF
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF'
    else
      msg_error "/etc/apt/apt.conf.d/20auto-upgrades not found, skipping configuration"
      return 1
    fi

    if [ -f /etc/apt/apt.conf.d/50unattended-upgrades ]; then
      msg_info "Configuring auto-reboot in /etc/apt/apt.conf.d/50unattended-upgrades"
      sudo sed -i 's|^//Unattended-Upgrade::Automatic-Reboot "false";|Unattended-Upgrade::Automatic-Reboot "true";|' /etc/apt/apt.conf.d/50unattended-upgrades
    else
      msg_error "/etc/apt/apt.conf.d/50unattended-upgrades not found, skipping reboot configuration"
    fi

    # Verify that the unattended-upgrades service is running
    msg_info "Checking unattended-upgrades service status"
    if sudo systemctl is-active --quiet unattended-upgrades; then
      msg_ok "unattended-upgrades service is active"
    else
      msg_info "Starting unattended-upgrades service"
      sudo systemctl start unattended-upgrades
    fi

    # Extract relevant Unattended-Upgrade settings for summary
    auto_reboot=$(grep -E '^Unattended-Upgrade::Automatic-Reboot' /etc/apt/apt.conf.d/50unattended-upgrades | head -n 1 | tr -d '";')
    update_frequency=$(grep -E 'APT::Periodic::Update-Package-Lists' /etc/apt/apt.conf.d/20auto-upgrades | cut -d '"' -f2)
    upgrade_frequency=$(grep -E 'APT::Periodic::Unattended-Upgrade' /etc/apt/apt.conf.d/20auto-upgrades | cut -d '"' -f2)

    # Extract allowed origins (types of updates)
    allowed_origins=$(grep -E 'Unattended-Upgrade::Allowed-Origins' /etc/apt/apt.conf.d/50unattended-upgrades | grep -oE '".*";' | tr -d '";')

    auto_updates_details="Automatic-Reboot = $auto_reboot, Update frequency: $update_frequency days, Upgrade frequency: $upgrade_frequency days, Allowed updates: $allowed_origins"
    automatic_updates_enabled="Yes (Settings: $auto_updates_details)"
    msg_ok "Automatic security updates configured"

    # Debugging step to see if the script reaches here
    echo "DEBUG: Exiting setup_automatic_updates"

    return 0  # Ensures the function exits cleanly

  else
    msg_error "Skipped automatic security updates"
  fi
}

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
install_ufw
install_webmin
install_optional_tools
setup_automatic_updates

# Ensure the summary is called at the end of the script
msg_ok "VPS Quick Setup is complete!"
display_summary

# Debugging to see if the script reaches the end
echo "DEBUG: Script execution completed"
