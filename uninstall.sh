#!/bin/bash

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Banner
clear
echo -e "${GREEN}=================================================${NC}"
echo -e "${YELLOW}           VPS Uninstallation Script             ${NC}"
echo -e "${GREEN}=================================================${NC}"

# Check root
if [ "$(id -u)" != "0" ]; then
   echo -e "${RED}This script must be run as root${NC}"
   exit 1
fi

# Stop services
echo -e "${YELLOW}Stopping services...${NC}"
systemctl stop stunnel4
systemctl stop dropbear
systemctl stop squid
systemctl stop xray
systemctl stop ws-ssh
systemctl stop fail2ban
systemctl stop vnstat

# Disable services
echo -e "${YELLOW}Disabling services...${NC}"
systemctl disable stunnel4
systemctl disable dropbear
systemctl disable squid
systemctl disable xray
systemctl disable ws-ssh
systemctl disable fail2ban
systemctl disable vnstat

# Remove service files
echo -e "${YELLOW}Removing service files...${NC}"
rm -f /etc/systemd/system/ws-ssh.service
systemctl daemon-reload

# Remove installed packages
echo -e "${YELLOW}Removing installed packages...${NC}"
apt-get remove -y stunnel4 dropbear squid openvpn easy-rsa fail2ban vnstat ufw python3-pip nginx
apt-get autoremove -y

# Remove Xray
echo -e "${YELLOW}Removing Xray...${NC}"
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ remove

# Remove UDP Custom
echo -e "${YELLOW}Removing UDP Custom...${NC}"
rm -rf /usr/local/udpgw
rm -rf /root/udp

# Remove configuration directories
echo -e "${YELLOW}Removing configuration directories...${NC}"
rm -rf /etc/vps
rm -rf /etc/openvpn
rm -rf /usr/local/etc/xray
rm -rf /etc/stunnel
rm -f /usr/local/bin/menu.sh
rm -f /usr/bin/menu

# Reset UFW rules
echo -e "${YELLOW}Resetting UFW rules...${NC}"
ufw reset
ufw disable

echo -e "${GREEN}Uninstallation completed!${NC}"
echo -e "${YELLOW}Your system has been restored to its previous state.${NC}"
echo -e "${YELLOW}Please reboot your system to complete the cleanup.${NC}"