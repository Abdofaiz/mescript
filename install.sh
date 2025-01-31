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

# Detect OS
OS=$(lsb_release -si)
VERSION=$(lsb_release -sr)
echo -e "Detected OS: ${YELLOW}$OS $VERSION${NC}"

# Main installation function
main_install() {
    # Update system
    apt update
    
    # Install required packages first
    echo -e "${YELLOW}Installing required packages...${NC}"
    apt install -y software-properties-common curl wget jq uuid-runtime
    
    # Add required PPAs
    add-apt-repository -y ppa:ondrej/nginx
    add-apt-repository -y ppa:ondrej/php
    
    # Update again after adding PPAs
    apt update
    
    # Install base packages
    echo -e "${YELLOW}Installing base packages...${NC}"
    DEBIAN_FRONTEND=noninteractive apt install -y \
        cron \
        iptables \
        iptables-persistent \
        netfilter-persistent \
        ca-certificates \
        lsb-release \
        openssl \
        stunnel4 \
        dropbear \
        squid \
        ufw

    # Temporarily disable UFW
    ufw disable
    
    # Install Xray
    echo -e "${YELLOW}Installing Xray...${NC}"
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)"
    
    # Create required directories
    mkdir -p /etc/stunnel
    mkdir -p /etc/squid
    mkdir -p /etc/xray
    
    # Generate Stunnel certificate
    echo -e "${YELLOW}Generating Stunnel certificate...${NC}"
    openssl req -new -newkey rsa:2048 -days 3650 -nodes -x509 \
        -keyout /etc/stunnel/stunnel.key \
        -out /etc/stunnel/stunnel.pem \
        -subj "/C=US/ST=California/L=Los Angeles/O=FAIZ-VPN/OU=FAIZ-VPN/CN=FAIZ-VPN"
    cat /etc/stunnel/stunnel.key /etc/stunnel/stunnel.pem > /etc/stunnel/stunnel.pem
    
    # Configure Stunnel
    cat > /etc/stunnel/stunnel.conf << EOF
pid = /var/run/stunnel.pid
cert = /etc/stunnel/stunnel.pem
client = no
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1

[dropbear]
accept = 443
connect = 127.0.0.1:80
EOF

    # Configure Squid
    cat > /etc/squid/squid.conf << EOF
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
http_access allow all
http_port 8080
coredump_dir /var/spool/squid
refresh_pattern ^ftp: 1440 20% 10080
refresh_pattern ^gopher: 1440 0% 1440
refresh_pattern -i (/cgi-bin/|\?) 0 0% 0
refresh_pattern . 0 20% 4320
visible_hostname FAIZ-VPN
EOF

    # Configure firewall
    echo -e "${YELLOW}Configuring firewall...${NC}"
    ufw default deny incoming
    ufw default allow outgoing
    ufw allow 22/tcp
    ufw allow 80/tcp
    ufw allow 443/tcp
    ufw allow 8080/tcp
    ufw allow 8442/tcp
    ufw allow 8443/tcp
    echo "y" | ufw enable
    
    # Install menu script
    echo -e "${YELLOW}Installing menu script...${NC}"
    wget -O /usr/local/bin/menu.sh https://raw.githubusercontent.com/Abdofaiz/mescript/main/menu.sh
    chmod +x /usr/local/bin/menu.sh
    ln -sf /usr/local/bin/menu.sh /usr/bin/menu
    
    # Enable and restart services
    systemctl daemon-reload
    systemctl enable stunnel4 dropbear squid xray
    systemctl restart stunnel4 dropbear squid xray
    
    # Create VPS info directory if it doesn't exist
    mkdir -p /etc/vps
    
    # Save installation date
    echo "Installation Date: $(date '+%Y-%m-%d')" > /etc/vps/install-date
    
    # Final setup
    echo -e "${GREEN}Installation completed!${NC}"
    echo -e "${YELLOW}Type 'menu' to access the control panel${NC}"
}

# Start installation
main_install 