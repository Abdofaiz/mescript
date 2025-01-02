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

# Allow UDP ports
ufw allow 36712/udp
ufw allow 1-65535/udp

echo -e "${GREEN}UDP Custom installed successfully${NC}" 