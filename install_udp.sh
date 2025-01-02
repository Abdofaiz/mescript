#!/bin/bash

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

echo -e "${GREEN}Installing UDP Custom...${NC}"

# Install dependencies
apt-get update
apt-get install -y wget curl screen

# Create directories
mkdir -p /usr/local/udpgw
mkdir -p /root/udp

# Download UDP Custom binary
wget -O /usr/local/udpgw/udp-custom "https://raw.githubusercontent.com/ChumoGH/ScriptCGH/main/Utils/udp-custom"
chmod +x /usr/local/udpgw/udp-custom

# Create symlink
ln -sf /usr/local/udpgw/udp-custom /usr/bin/udp-custom

# Create config file
cat > /root/udp/config.json <<EOF
{
    "listen": ":36712",
    "stream_buffer": 16777216,
    "receive_buffer": 33554432,
    "auth": {
        "mode": "passwords",
        "passwords": []
    }
}
EOF

# Create service file
cat > /etc/systemd/system/udp-custom.service <<EOF
[Unit]
Description=UDP Custom by ChumoGH
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/root/udp
ExecStart=/usr/local/udpgw/udp-custom server
Restart=always
RestartSec=3s

[Install]
WantedBy=multi-user.target
EOF

# Set permissions
chmod +x /usr/local/udpgw/udp-custom
chmod 644 /etc/systemd/system/udp-custom.service
chmod 644 /root/udp/config.json

# Enable and start service
systemctl daemon-reload
systemctl enable udp-custom
systemctl start udp-custom

# Allow UDP ports
ufw allow 36712/udp
ufw allow 1-65535/udp

echo -e "${GREEN}UDP Custom installed successfully${NC}" 