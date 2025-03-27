#!/bin/bash

# Check if the script is running as root
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root"
    exit
fi

check_requirements() {
    local tools_missing=false

    # Loop through each tool and check if it is installed
    for tool in wgctl wgstat; do
        if ! command -v "$tool" &> /dev/null; then
            echo "$tool is not installed."
            echo "You can install it with the following command:"
            echo "sudo bash -c \"\$(wget -qO- https://raw.githubusercontent.com/snaeim/$tool/refs/heads/main/installer.sh)\""
            tools_missing=true
        fi
    done

    # If any tool is missing, exit with status 1
    $tools_missing && exit 1
}


setup_peervision() {
    local HTML_URL="https://raw.githubusercontent.com/snaeim/peervision/refs/heads/main/peervision.html"
    local HTML_PATH="/var/www/html"
    local HTML_FILENAME="peervision.html"
    if [ -d "$HTML_PATH" ]; then
        echo "Directory $HTML_PATH already exists."
    else
        mkdir -p "$HTML_PATH"
        chmod 755 "$HTML_PATH"
    fi
    if sudo curl -sL "$HTML_URL" -o "$HTML_PATH/$HTML_FILENAME"; then
        echo "Downloaded $HTML_FILENAME successfully."
    else
        echo "Failed to download $HTML_FILENAME."
        exit 1
    fi
    return 0
}

# Function to install peervision
setup_peervision_server() {
    local SERVER_URL="https://raw.githubusercontent.com/snaeim/peervision/refs/heads/main/peervision.py"
    local SERVER_PATH="/srv/peervision.py"
    local SERVICE_PATH="/etc/systemd/system/peervision.service"
    local SERVER_PORT="10088"
   
    # Check if service already exists
    if systemctl list-unit-files | grep -q "peervision.service"; then
        echo "peervision service already exists."
        echo "Stopping and removing existing service..."
        systemctl stop peervision.service || true
        systemctl disable peervision.service || true
        rm -f "$SERVICE_PATH"
        echo "Existing service removed."
    fi
   
    # Download the server script
    if curl -sL "$SERVER_URL" -o "$SERVER_PATH"; then
        echo "Downloaded peervision.py successfully."
    else
        echo "Failed to download peervision.py."
        return 1
    fi
      
    # Create systemd service file with journal logging
    cat > "$SERVICE_PATH" << EOF
[Unit]
Description=PeerVision Server
After=network.target

[Service]
ExecStart=/usr/bin/python3 /srv/peervision.py --host 0.0.0.0 --port ${SERVER_PORT}
Restart=on-failure
User=root
Group=root
StandardOutput=journal
StandardError=journal
ProtectHome=true
PrivateTmp=true
NoNewPrivileges=false

[Install]
WantedBy=multi-user.target
EOF
   
    echo "Created systemd service file."
   
    # Open firewall port if UFW is installed and active only if rule doesn't exist
    if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "active"; then
        # Check if the rule already exists
        if ! ufw status | grep -q "${SERVER_PORT}/tcp"; then
            echo "Opening UFW port ${SERVER_PORT}..."
            ufw allow ${SERVER_PORT}/tcp
            echo "UFW port ${SERVER_PORT} opened."
        else
            echo "UFW port ${SERVER_PORT} is already open."
        fi
    fi
   
    # Reload systemd, enable and start the service
    systemctl daemon-reload
    systemctl enable peervision.service
    systemctl start peervision.service
   
    # Verify service status
    if systemctl is-active --quiet peervision.service; then
        echo "peervision service is now running."
    else
        echo "WARNING: peervision service failed to start. Check logs with 'journalctl -u peervision.service'."
        return 1
    fi
    
    return 0
}


check_requirements
setup_peervision
setup_peervision_server
exit 0
