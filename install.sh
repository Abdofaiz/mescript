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

# Function to detect OS
detect_os() {
    source /etc/os-release
    OS=$ID
    VERSION_ID=$VERSION_ID
    echo -e "${GREEN}Detected OS: $OS $VERSION_ID${NC}"
}

# Function to update repositories based on OS version
update_repositories() {
    if [[ $OS == "ubuntu" ]]; then
        # Add required repositories for Ubuntu
        apt-get install -y software-properties-common
        add-apt-repository -y ppa:ondrej/nginx
        add-apt-repository -y ppa:ondrej/php
        
        # Update package list
        apt-get update
    elif [[ $OS == "debian" ]]; then
        # Add required repositories for Debian
        apt-get install -y curl gnupg2 ca-certificates lsb-release debian-archive-keyring
        curl https://nginx.org/keys/nginx_signing.key | gpg --dearmor > /usr/share/keyrings/nginx-archive-keyring.gpg
        echo "deb [signed-by=/usr/share/keyrings/nginx-archive-keyring.gpg] http://nginx.org/packages/debian $(lsb_release -cs) nginx" > /etc/apt/sources.list.d/nginx.list
        
        # Update package list
        apt-get update
    fi
}

# Function to install required packages
install_packages() {
    echo -e "${GREEN}Installing required packages...${NC}"
    apt-get install -y \
        curl \
        wget \
        jq \
        uuid-runtime \
        cron \
        iptables \
        iptables-persistent \
        net-tools \
        ca-certificates \
        gnupg \
        lsb-release \
        openssl \
        nginx \
        python3 \
        python3-pip \
        python3-certbot-nginx \
        stunnel4 \
        dropbear \
        squid \
        openvpn \
        easy-rsa \
        fail2ban \
        vnstat \
        ufw \
        build-essential \
        make \
        cmake \
        gcc \
        g++ \
        unzip
}

# Function to install Xray
install_xray() {
    echo -e "${GREEN}Installing Xray...${NC}"
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install
}

# Function to configure services
configure_services() {
    echo -e "${GREEN}Configuring services...${NC}"
    
    # Create necessary directories
    mkdir -p /etc/vps
    mkdir -p /etc/openvpn/easy-rsa
    mkdir -p /etc/openvpn/client-configs
    mkdir -p /usr/local/etc/xray
    
    # Configure Stunnel
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
    sed -i 's/NO_START=1/NO_START=0/g' /etc/default/dropbear
    sed -i 's/DROPBEAR_PORT=22/DROPBEAR_PORT=443/g' /etc/default/dropbear
    echo "DROPBEAR_EXTRA_ARGS=\"-p 109 -p 143\"" >> /etc/default/dropbear

    # Configure Squid
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

    # Configure UFW
    ufw default deny incoming
    ufw default allow outgoing
    ufw allow 22/tcp
    ufw allow 80/tcp
    ufw allow 443/tcp
    ufw allow 3128/tcp
    ufw allow 8080/tcp
    ufw allow 1194/tcp
    ufw allow 1194/udp
    echo "y" | ufw enable
}

# Function to install menu script
install_menu() {
    echo -e "${GREEN}Installing menu script...${NC}"
    wget -O /usr/local/bin/menu.sh "https://raw.githubusercontent.com/Abdofaiz/mescript/main/menu.sh"
    chmod +x /usr/local/bin/menu.sh
    
    # Create menu command
    echo '#!/bin/bash' > /usr/bin/menu
    echo 'bash /usr/local/bin/menu.sh' >> /usr/bin/menu
    chmod +x /usr/bin/menu
}

# Main installation
main_install() {
    detect_os
    update_repositories
    install_packages
    install_xray
    configure_services
    install_menu
    
    # Start and enable services
    systemctl daemon-reload
    systemctl enable stunnel4
    systemctl enable dropbear
    systemctl enable squid
    systemctl enable xray
    
    systemctl restart stunnel4
    systemctl restart dropbear
    systemctl restart squid
    systemctl restart xray
    
    # Final setup
    echo -e "${GREEN}Installation completed!${NC}"
    echo -e "${YELLOW}Type 'menu' to access the control panel${NC}"
}

# Start installation
main_install 