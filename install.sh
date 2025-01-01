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
    
    # Download menu script
    wget -O /usr/local/bin/menu "https://raw.githubusercontent.com/yourusername/yourrepo/main/menu.sh"
    chmod +x /usr/local/bin/menu
    
    # Download other required files
    # Add your repository URLs here
}

# Configure services
configure_services() {
    echo -e "${GREEN}Configuring services...${NC}"
    
    # Run the configuration commands from install_vps.sh
    # Add your configuration commands here
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