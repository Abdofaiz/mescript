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
mkdir -p /etc/ADMRufu/install
mkdir -p /root/udp

# Download UDP Custom binary
wget -O /etc/ADMRufu/install/udp-custom "https://github.com/rudi9999/ADMRufu/raw/main/Utils/udp-custom/udp-custom"
chmod +x /etc/ADMRufu/install/udp-custom

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

# Allow UDP ports - fixed port range syntax
ufw allow 36712/udp
for port in {1..65535}; do
    ufw allow $port/udp >/dev/null 2>&1
done

echo -e "${GREEN}UDP Custom installed successfully${NC}" 