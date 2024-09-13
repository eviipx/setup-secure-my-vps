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

    # Step 9.3: Ask for custom firewall rules
    while (whiptail --title "Custom Firewall Rule" --yesno "Do you want to add a custom firewall rule?" 10 60); do
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
