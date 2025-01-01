#!/bin/bash

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Banner
clear
echo -e "${GREEN}=================================================${NC}"
echo -e "${YELLOW}           VPS Installation Script               ${NC}"
echo -e "${YELLOW}        Supported: Ubuntu 18-24, Debian 8-12     ${NC}"
echo -e "${GREEN}=================================================${NC}"

# Check root
if [ "$(id -u)" != "0" ]; then
   echo -e "${RED}This script must be run as root${NC}"
   exit 1
fi

# Check OS
check_os() {
    source /etc/os-release
    if [[ $ID == "ubuntu" ]]; then
        if [[ ${VERSION_ID} != "18.04" && ${VERSION_ID} != "20.04" && ${VERSION_ID} != "22.04" && ${VERSION_ID} != "24.04" ]]; then
            echo -e "${RED}Unsupported Ubuntu version${NC}"
            exit 1
        fi
    elif [[ $ID == "debian" ]]; then
        if [[ ${VERSION_ID} -lt 8 || ${VERSION_ID} -gt 12 ]]; then
            echo -e "${RED}Unsupported Debian version${NC}"
            exit 1
        fi
    else
        echo -e "${RED}Unsupported operating system${NC}"
        exit 1
    fi
}

# Installation steps
install_packages() {
    echo -e "${GREEN}Updating system...${NC}"
    apt-get update
    apt-get upgrade -y
    
    echo -e "${GREEN}Installing required packages...${NC}"
    apt-get install -y \
        curl wget jq uuid-runtime cron \
        iptables net-tools \
        openssl ca-certificates \
        gnupg lsb-release \
        software-properties-common \
        apt-transport-https \
        cmake make gcc g++ unzip \
        python3 python3-pip \
        nginx certbot \
        stunnel4 dropbear squid \
        openvpn easy-rsa
}

# Download additional scripts
download_scripts() {
    echo -e "${GREEN}Downloading additional scripts...${NC}"
    
    # Create directories
    mkdir -p /etc/vps
    mkdir -p /usr/local/bin
    
    # Create menu script
    cat > /usr/local/bin/menu.sh <<'EOF'
#!/bin/bash

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Configuration files
XRAY_CONFIG="/usr/local/etc/xray/config.json"
USER_DB="/etc/vps/users.db"

# Function to generate random UUID
generate_uuid() {
    uuidgen
}

# Main menu
while true; do
    clear
    echo -e "${GREEN}=== VPS Management Menu ===${NC}"
    echo -e "${YELLOW}SSH Management${NC}"
    echo -e "1) Add SSH User"
    echo -e "2) Delete SSH User"
    echo -e "3) List SSH Users"
    echo -e "4) Show Online SSH Users"
    echo -e ""
    echo -e "${YELLOW}Xray Management${NC}"
    echo -e "5) Add VMess User"
    echo -e "6) Add VLESS User"
    echo -e "7) Delete User"
    echo -e "8) List All Users"
    echo -e ""
    echo -e "${YELLOW}WebSocket Management${NC}"
    echo -e "9) Add VMess WebSocket User"
    echo -e "10) Add VLESS WebSocket User"
    echo -e "11) Add SSH WebSocket User"
    echo -e ""
    echo -e "${YELLOW}System${NC}"
    echo -e "12) Show System Status"
    echo -e "13) Exit"
    echo -e ""
    read -p "Select an option: " choice

    case $choice in
        1) echo "Add SSH User" ;;
        2) echo "Delete SSH User" ;;
        3) echo "List SSH Users" ;;
        4) echo "Show Online SSH Users" ;;
        5) echo "Add VMess User" ;;
        6) echo "Add VLESS User" ;;
        7) echo "Delete User" ;;
        8) echo "List All Users" ;;
        9) echo "Add VMess WebSocket User" ;;
        10) echo "Add VLESS WebSocket User" ;;
        11) echo "Add SSH WebSocket User" ;;
        12) 
            clear
            echo -e "${GREEN}=== System Status ===${NC}"
            echo -e "CPU Usage: $(top -bn1 | grep "Cpu(s)" | awk '{print $2 + $4}')%"
            echo -e "Memory Usage: $(free -m | awk 'NR==2{printf "%.2f%%", $3*100/$2}')"
            echo -e "Disk Usage: $(df -h / | awk 'NR==2{print $5}')"
            echo ""
            read -n 1 -s -r -p "Press any key to continue"
            ;;
        13) exit 0 ;;
        *) echo -e "${RED}Invalid option${NC}" ;;
    esac
done
EOF

    # Make menu script executable
    chmod +x /usr/local/bin/menu.sh

    # Create menu command
    cat > /usr/local/bin/menu <<'EOF'
#!/bin/bash
bash /usr/local/bin/menu.sh
EOF
    chmod +x /usr/local/bin/menu
}

# Configure services
configure_services() {
    echo -e "${GREEN}Configuring services...${NC}"
    
    # Create necessary directories
    mkdir -p /etc/vps
    mkdir -p /etc/openvpn/easy-rsa
    mkdir -p /etc/openvpn/client-configs
    mkdir -p /usr/local/etc/xray
    
    # Install Xray
    echo -e "${GREEN}Installing Xray...${NC}"
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install

    # Configure Stunnel
    echo -e "${GREEN}Configuring Stunnel...${NC}"
    cat > /etc/stunnel/stunnel.conf <<EOF
pid = /var/run/stunnel.pid
cert = /etc/stunnel/stunnel.pem
client = no
socket = a:SO_REUSEADDR=1
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1

[dropbear]
accept = 443
connect = 127.0.0.1:22

[dropbear]
accept = 445
connect = 127.0.0.1:22

[dropbear]
accept = 777
connect = 127.0.0.1:22
EOF

    # Generate SSL certificate
    openssl genrsa -out /etc/stunnel/stunnel.key 2048
    openssl req -new -key /etc/stunnel/stunnel.key -out /etc/stunnel/stunnel.csr -subj "/C=US/ST=California/L=Los Angeles/O=Organization/OU=Unit/CN=domain.com"
    openssl x509 -req -days 365 -in /etc/stunnel/stunnel.csr -signkey /etc/stunnel/stunnel.key -out /etc/stunnel/stunnel.crt
    cat /etc/stunnel/stunnel.key /etc/stunnel/stunnel.crt > /etc/stunnel/stunnel.pem

    # Configure Dropbear
    echo -e "${GREEN}Configuring Dropbear...${NC}"
    sed -i 's/NO_START=1/NO_START=0/g' /etc/default/dropbear
    sed -i 's/DROPBEAR_PORT=22/DROPBEAR_PORT=443/g' /etc/default/dropbear
    echo "DROPBEAR_EXTRA_ARGS=\"-p 109 -p 143\"" >> /etc/default/dropbear

    # Configure Squid
    echo -e "${GREEN}Configuring Squid...${NC}"
    cat > /etc/squid/squid.conf <<EOF
http_port 3128
http_port 8080
acl localhost src 127.0.0.1/32
acl to_localhost dst 127.0.0.0/8
acl SSL_ports port 443
acl Safe_ports port 80
acl Safe_ports port 21
acl Safe_ports port 443
acl Safe_ports port 70
acl Safe_ports port 210
acl Safe_ports port 1025-65535
acl Safe_ports port 280
acl Safe_ports port 488
acl Safe_ports port 591
acl Safe_ports port 777
acl CONNECT method CONNECT
http_access allow localhost
http_access deny !Safe_ports
http_access deny CONNECT !SSL_ports
http_access allow all
EOF

    # Configure Xray
    cat > /usr/local/etc/xray/config.json <<EOF
{
  "log": {
    "loglevel": "warning"
  },
  "inbounds": [
    {
      "port": 8443,
      "protocol": "vmess",
      "settings": {
        "clients": []
      },
      "streamSettings": {
        "network": "ws",
        "security": "tls",
        "tlsSettings": {
          "certificates": [
            {
              "certificateFile": "/etc/stunnel/stunnel.crt",
              "keyFile": "/etc/stunnel/stunnel.key"
            }
          ]
        },
        "wsSettings": {
          "path": "/vmess",
          "headers": {}
        }
      }
    },
    {
      "port": 8442,
      "protocol": "vless",
      "settings": {
        "clients": [],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "ws",
        "security": "tls",
        "tlsSettings": {
          "certificates": [
            {
              "certificateFile": "/etc/stunnel/stunnel.crt",
              "keyFile": "/etc/stunnel/stunnel.key"
            }
          ]
        },
        "wsSettings": {
          "path": "/vless",
          "headers": {}
        }
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom"
    }
  ]
}
EOF

    # Configure WebSocket SSH
    cat > /usr/local/bin/ws-ssh.py <<EOF
#!/usr/bin/env python3
import socket, threading, thread, select, signal, sys, time, getopt

# Listen
LISTENING_ADDR = '127.0.0.1'
LISTENING_PORT = 2082
...(WebSocket SSH Python script content)...
EOF
    chmod +x /usr/local/bin/ws-ssh.py

    # Create WebSocket SSH service
    cat > /etc/systemd/system/ws-ssh.service <<EOF
[Unit]
Description=WebSocket SSH Service
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /usr/local/bin/ws-ssh.py
Restart=always

[Install]
WantedBy=multi-user.target
EOF

    # Enable and start services
    systemctl daemon-reload
    systemctl enable stunnel4
    systemctl enable dropbear
    systemctl enable squid
    systemctl enable xray
    systemctl enable ws-ssh

    systemctl restart stunnel4
    systemctl restart dropbear
    systemctl restart squid
    systemctl restart xray
    systemctl start ws-ssh

    # Initialize user database
    touch /etc/vps/users.db
}

# Main installation
main_install() {
    check_os
    install_packages
    download_scripts
    configure_services
    
    # Final setup
    echo -e "${GREEN}Installation completed!${NC}"
    echo -e "${YELLOW}Type 'menu' to access the control panel${NC}"
}

# Start installation
main_install 