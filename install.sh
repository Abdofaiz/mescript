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

# Remove conflicting packages first
apt remove -y ufw iptables-persistent netfilter-persistent

# Install base packages without conflicts
echo -e "${YELLOW}Installing base packages...${NC}"
DEBIAN_FRONTEND=noninteractive apt install -y \
    cron \
    iptables \
    ca-certificates \
    lsb-release \
    openssl \
    stunnel4 \
    dropbear \
    squid

# Create service files for Ubuntu 24.04
cat > /etc/systemd/system/stunnel4.service << 'EOF'
[Unit]
Description=SSL tunnel for network daemons
After=network.target
After=syslog.target

[Service]
ExecStart=/usr/bin/stunnel4 /etc/stunnel/stunnel.conf
Type=forking

[Install]
WantedBy=multi-user.target
EOF

cat > /etc/systemd/system/dropbear.service << 'EOF'
[Unit]
Description=Dropbear SSH Server
After=network.target

[Service]
Type=simple
ExecStart=/usr/sbin/dropbear -F -p 22
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

# Add this before enabling services:
systemctl daemon-reload

# Modify the service enabling section:
echo -e "${YELLOW}Enabling and starting services...${NC}"
for service in stunnel4 dropbear squid xray; do
    if [ -f "/etc/systemd/system/$service.service" ] || [ -f "/lib/systemd/system/$service.service" ]; then
        systemctl enable $service
        systemctl restart $service
    else
        echo -e "${RED}Warning: $service.service not found${NC}"
    fi
done

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
pid = /var/run/stunnel4.pid
cert = /etc/stunnel/stunnel.pem
client = no
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1

[dropbear]
accept = 447
connect = 127.0.0.1:143

[openvpn]
accept = 587
connect = 127.0.0.1:1194
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

# Clear existing rules
iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X
iptables -t mangle -F
iptables -t mangle -X

# Default policy
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# Allow loopback
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# Allow established connections
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow SSH (port 22)
iptables -A INPUT -p tcp --dport 22 -j ACCEPT

# Allow HTTP (port 80)
iptables -A INPUT -p tcp --dport 80 -j ACCEPT

# Allow HTTPS (port 443)
iptables -A INPUT -p tcp --dport 443 -j ACCEPT

# Allow Squid (port 8080)
iptables -A INPUT -p tcp --dport 8080 -j ACCEPT

# Allow Xray (ports 8442, 8443)
iptables -A INPUT -p tcp --dport 8442 -j ACCEPT
iptables -A INPUT -p tcp --dport 8443 -j ACCEPT

# Save iptables rules
mkdir -p /etc/iptables
iptables-save > /etc/iptables/rules.v4

# Create service to load iptables rules on boot
cat > /etc/systemd/system/iptables-restore.service << 'EOF'
[Unit]
Description=Restore iptables rules
Before=network-pre.target

[Service]
Type=oneshot
ExecStart=/sbin/iptables-restore /etc/iptables/rules.v4
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

# Enable iptables-restore service
systemctl daemon-reload
systemctl enable iptables-restore

# Install menu script properly
echo -e "${YELLOW}Installing menu script...${NC}"

# Create menu directory
mkdir -p /usr/local/bin/menu

# Download menu components
wget -O /usr/local/bin/menu/menu.sh "https://raw.githubusercontent.com/Abdofaiz/mescript/main/menu.sh"
wget -O /usr/local/bin/menu/ssh.sh "https://raw.githubusercontent.com/Abdofaiz/mescript/main/ssh.sh"
wget -O /usr/local/bin/menu/system.sh "https://raw.githubusercontent.com/Abdofaiz/mescript/main/system.sh"
wget -O /usr/local/bin/menu/vless.sh "https://raw.githubusercontent.com/Abdofaiz/mescript/main/vless.sh"
wget -O /usr/local/bin/menu/vmess.sh "https://raw.githubusercontent.com/Abdofaiz/mescript/main/vmess.sh"

# Make scripts executable
chmod +x /usr/local/bin/menu/*.sh

# Create main menu command
cat > /usr/bin/menu << 'EOF'
#!/bin/bash
/usr/local/bin/menu/menu.sh
EOF

# Make menu command executable
chmod +x /usr/bin/menu

# Create aliases for quick access
cat > /root/.bash_aliases << 'EOF'
alias m="menu"
alias menu="menu"
EOF

# Load new aliases
source /root/.bash_aliases

echo -e "${GREEN}Menu installation completed!${NC}"

# Create VPS info directory if it doesn't exist
mkdir -p /etc/vps

# Save installation date
echo "Installation Date: $(date '+%Y-%m-%d')" > /etc/vps/install-date

# Final setup
echo -e "${GREEN}Installation completed!${NC}"
echo -e "${YELLOW}Type 'menu' to access the control panel${NC}"

# Add these service installations and configurations after the initial package installation:

# Install Nginx
apt install -y nginx
systemctl enable nginx
systemctl start nginx

# Configure Dropbear
cat > /etc/default/dropbear << 'EOF'
NO_START=0
DROPBEAR_PORT=143
DROPBEAR_EXTRA_ARGS="-p 50000"
DROPBEAR_BANNER="/etc/issue.net"
DROPBEAR_RECEIVE_WINDOW=65536
EOF

# Install BadVPN
wget -O /usr/bin/badvpn-udpgw "https://raw.githubusercontent.com/Abdofaiz/mescript/main/badvpn-udpgw64"
chmod +x /usr/bin/badvpn-udpgw

# Create BadVPN service
cat > /etc/systemd/system/badvpn.service << 'EOF'
[Unit]
Description=BadVPN UDP Gateway
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/badvpn-udpgw --listen-addr 127.0.0.1:7300
Restart=always

[Install]
WantedBy=multi-user.target
EOF

# Configure WebSocket
cat > /etc/nginx/conf.d/ws.conf << 'EOF'
server {
    listen 80;
    server_name 127.0.0.1;
    
    location / {
        proxy_pass http://127.0.0.1:700;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
    }
}
EOF

# Create WebSocket service
cat > /etc/systemd/system/ws-ssh.service << 'EOF'
[Unit]
Description=WebSocket SSH Service
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 -m websockify --web=/usr/share/websockify 700 127.0.0.1:143
Restart=always

[Install]
WantedBy=multi-user.target
EOF

# Install WebSocket dependencies
apt install -y python3-websockify

# Enable and start all services
systemctl daemon-reload

services=(
    "nginx"
    "dropbear"
    "stunnel4"
    "badvpn"
    "ws-ssh"
    "xray"
    "squid"
)

for service in "${services[@]}"; do
    echo "Starting $service..."
    systemctl enable $service
    systemctl restart $service
    sleep 1
done

# Verify services are running
echo "Checking service status..."
for service in "${services[@]}"; do
    if systemctl is-active --quiet $service; then
        echo "$service is running"
    else
        echo "$service failed to start"
        systemctl status $service
    fi
done 