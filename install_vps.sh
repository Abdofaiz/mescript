#!/bin/bash

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

# Function to check OS compatibility
check_os() {
    source /etc/os-release
    if [[ $ID == "ubuntu" ]]; then
        if [[ ${VERSION_ID} != "18.04" && ${VERSION_ID} != "20.04" && ${VERSION_ID} != "22.04" && ${VERSION_ID} != "24.04" ]]; then
            echo -e "${RED}This script only supports Ubuntu 18.04, 20.04, 22.04, and 24.04${NC}"
            exit 1
        fi
    elif [[ $ID == "debian" ]]; then
        if [[ ${VERSION_ID} -lt 8 || ${VERSION_ID} -gt 12 ]]; then
            echo -e "${RED}This script only supports Debian 8-12${NC}"
            exit 1
        fi
    else
        echo -e "${RED}This script only supports Ubuntu and Debian${NC}"
        exit 1
    fi
}

# Function to install dependencies based on OS
install_dependencies() {
    source /etc/os-release
    
    # Common packages
    local packages=(
        curl wget jq uuid-runtime cron
        iptables net-tools
        openssl ca-certificates
        gnupg lsb-release
    )
    
    # Add OS-specific packages
    if [[ $ID == "ubuntu" ]]; then
        packages+=(software-properties-common)
    elif [[ $ID == "debian" ]]; then
        packages+=(apt-transport-https)
        if [[ ${VERSION_ID} -le 9 ]]; then
            # For Debian 8-9
            echo "deb http://deb.debian.org/debian $(lsb_release -sc)-backports main" > /etc/apt/sources.list.d/backports.list
            apt-get update
        fi
    fi
    
    # Install packages
    apt-get install -y "${packages[@]}"
}

# Add after color definitions and before main script
check_os
install_dependencies

# Modify the OpenVPN installation for older systems
install_openvpn() {
    source /etc/os-release
    
    if [[ $ID == "debian" && ${VERSION_ID} -le 9 ]]; then
        # For Debian 8-9
        wget -O /etc/apt/trusted.gpg.d/openvpn-as-repo.gpg https://as-repository.openvpn.net/as-repo-public.gpg
        echo "deb http://as-repository.openvpn.net/as/debian $(lsb_release -sc) main" > /etc/apt/sources.list.d/openvpn-as-repo.list
        apt-get update
    fi
    
    apt-get install -y openvpn easy-rsa
    
    # Use appropriate Easy-RSA version
    if [[ -d /usr/share/easy-rsa ]]; then
        cp -r /usr/share/easy-rsa/* /etc/openvpn/easy-rsa/
    else
        # Fallback for older systems
        wget -O /tmp/EasyRSA-3.0.8.tgz https://github.com/OpenVPN/easy-rsa/releases/download/v3.0.8/EasyRSA-3.0.8.tgz
        tar xzf /tmp/EasyRSA-3.0.8.tgz -C /etc/openvpn/
        mv /etc/openvpn/EasyRSA-3.0.8/* /etc/openvpn/easy-rsa/
        rm -rf /tmp/EasyRSA-3.0.8.tgz /etc/openvpn/EasyRSA-3.0.8
    fi
}

# Modify the stunnel installation for older systems
install_stunnel() {
    source /etc/os-release
    
    if [[ $ID == "debian" && ${VERSION_ID} -le 9 ]]; then
        # For Debian 8-9
        apt-get install -y stunnel4
        sed -i 's/ENABLED=0/ENABLED=1/g' /etc/default/stunnel4
    else
        apt-get install -y stunnel4
    fi
}

# Modify the BadVPN installation
install_badvpn() {
    cd /usr/local/src
    wget https://github.com/ambrop72/badvpn/archive/refs/tags/1.999.130.tar.gz
    tar xf 1.999.130.tar.gz
    cd badvpn-1.999.130
    cmake -DBUILD_NOTHING_BY_DEFAULT=1 -DBUILD_UDPGW=1
    make install
    
    # Create BadVPN services for different ports
    for port in 7100 7200 7300; do
        cat > /etc/systemd/system/badvpn-udpgw-$port.service <<EOF
[Unit]
Description=BadVPN UDP Gateway on port $port
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/badvpn-udpgw --listen-addr 127.0.0.1:$port --max-clients 500
Restart=always

[Install]
WantedBy=multi-user.target
EOF
        systemctl enable badvpn-udpgw-$port
        systemctl start badvpn-udpgw-$port
    done
}

# Replace the original package installation with these functions
echo -e "${GREEN}Installing required packages...${NC}"
install_stunnel
install_badvpn
install_openvpn

# Add network interface detection
get_network_interface() {
    # Try to get the main interface
    local interface=$(ip route get 8.8.8.8 | awk '{print $5; exit}')
    if [[ -z "$interface" ]]; then
        # Fallback to the first non-loopback interface
        interface=$(ip link show | awk -F: '$2 !~ /lo/ {print $2;exit}' | tr -d ' ')
    fi
    echo "$interface"
}

# Update the iptables rules to use the detected interface
INTERFACE=$(get_network_interface)
iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o $INTERFACE -j MASQUERADE

# Add system optimization
optimize_system() {
    # TCP optimization
    cat >> /etc/sysctl.conf <<EOF
# TCP optimization
net.ipv4.tcp_window_scaling = 1
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 16384 16777216
net.ipv4.tcp_congestion_control = bbr
net.core.default_qdisc = fq
EOF
    
    # Apply settings
    sysctl -p
    
    # Increase open files limit
    cat >> /etc/security/limits.conf <<EOF
* soft nofile 51200
* hard nofile 51200
EOF
}

# Function to optimize RAM usage
optimize_ram() {
    echo -e "${GREEN}Optimizing RAM usage...${NC}"
    
    # Configure SYSCTL for better RAM management
    cat >> /etc/sysctl.conf <<EOF
# RAM Optimization
vm.swappiness = 10
vm.dirty_ratio = 60
vm.dirty_background_ratio = 2
vm.vfs_cache_pressure = 50
vm.overcommit_memory = 1
vm.min_free_kbytes = 65536
EOF

    # Create and configure SWAP if not exists
    if [ ! -f /swapfile ]; then
        # Calculate swap size (2x RAM for servers with <= 2GB, RAM size for servers with > 2GB)
        total_ram=$(free -m | grep Mem: | awk '{print $2}')
        if [ $total_ram -le 2048 ]; then
            swap_size=$((total_ram * 2))
        else
            swap_size=$total_ram
        fi
        
        # Create swap file
        dd if=/dev/zero of=/swapfile bs=1M count=$swap_size
        chmod 600 /swapfile
        mkswap /swapfile
        swapon /swapfile
        echo '/swapfile none swap sw 0 0' >> /etc/fstab
        
        # Configure swap settings
        echo 'vm.swappiness=10' >> /etc/sysctl.conf
        echo 'vm.vfs_cache_pressure=50' >> /etc/sysctl.conf
    fi
    
    # Configure system limits
    cat >> /etc/security/limits.conf <<EOF
* soft memlock unlimited
* hard memlock unlimited
* soft nofile 65535
* hard nofile 65535
EOF
    
    # Enable automatic memory cleaning
    cat > /etc/cron.daily/clean-memory <<EOF
#!/bin/bash
sync; echo 3 > /proc/sys/vm/drop_caches
swapoff -a && swapon -a
EOF
    chmod +x /etc/cron.daily/clean-memory
}

# Function to optimize CPU performance
optimize_cpu() {
    echo -e "${GREEN}Optimizing CPU performance...${NC}"
    
    # Install CPU frequency scaling tools
    apt-get install -y cpufrequtils
    
    # Set CPU governor to performance
    for cpu in /sys/devices/system/cpu/cpu[0-9]*; do
        echo "performance" > $cpu/cpufreq/scaling_governor
    done
    
    # Configure CPU frequency scaling
    cat > /etc/default/cpufrequtils <<EOF
GOVERNOR="performance"
MIN_SPEED="0"
MAX_SPEED="0"
EOF
    
    # Configure process scheduling
    cat >> /etc/sysctl.conf <<EOF
# CPU Optimization
kernel.sched_migration_cost_ns = 5000000
kernel.sched_autogroup_enabled = 0
kernel.sched_wakeup_granularity_ns = 15000000
kernel.sched_min_granularity_ns = 10000000
kernel.sched_latency_ns = 80000000
EOF
    
    # Configure IRQ balance for better CPU utilization
    apt-get install -y irqbalance
    systemctl enable irqbalance
    systemctl start irqbalance
    
    # Create CPU optimization service
    cat > /etc/systemd/system/cpu-optimization.service <<EOF
[Unit]
Description=CPU Optimization Service
After=network.target

[Service]
Type=oneshot
ExecStart=/bin/bash -c 'for cpu in /sys/devices/system/cpu/cpu[0-9]*; do echo performance > \$cpu/cpufreq/scaling_governor; done'
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

    systemctl enable cpu-optimization
    systemctl start cpu-optimization
}

# Function to optimize network performance
optimize_network() {
    echo -e "${GREEN}Optimizing network performance...${NC}"
    
    cat >> /etc/sysctl.conf <<EOF
# Network Optimization
net.core.netdev_max_backlog = 16384
net.core.somaxconn = 32768
net.core.rmem_default = 262144
net.core.wmem_default = 262144
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216
net.ipv4.tcp_max_syn_backlog = 8192
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_tw_reuse = 1
net.ipv4.ip_local_port_range = 1024 65535
net.ipv4.tcp_max_tw_buckets = 1440000
EOF
}

# Function to create monitoring script
create_monitoring_script() {
    cat > /usr/local/bin/system-monitor <<EOF
#!/bin/bash
echo "System Monitor"
echo "-------------"
echo "CPU Usage:"
top -bn1 | grep "Cpu(s)" | awk '{print \$2 + \$4}' | awk '{print \$0"%"}'
echo
echo "Memory Usage:"
free -m | awk 'NR==2{printf "%.2f%%\n", \$3*100/\$2}'
echo
echo "Swap Usage:"
free -m | awk 'NR==3{printf "%.2f%%\n", \$3*100/\$2}'
echo
echo "Disk Usage:"
df -h / | awk 'NR==2{print \$5}'
EOF
    chmod +x /usr/local/bin/system-monitor
}

# Add these lines after the optimize_system call
optimize_ram
optimize_cpu
optimize_network
create_monitoring_script

# Add monitoring cron job
(crontab -l 2>/dev/null; echo "*/5 * * * * /usr/local/bin/system-monitor > /var/log/system-stats.log") | crontab -

# Add to the version information
echo "Optimizations: RAM, CPU, Network" >> /etc/vps/version.txt

# Add version information
echo "# Installation Details" > /etc/vps/version.txt
echo "Date: $(date)" >> /etc/vps/version.txt
echo "OS: $ID $VERSION_ID" >> /etc/vps/version.txt
echo "Kernel: $(uname -r)" >> /etc/vps/version.txt

# Check if script is run as root
if [ "$(id -u)" != "0" ]; then
   echo -e "${RED}This script must be run as root${NC}"
   exit 1
fi

# Update system
echo -e "${GREEN}Updating system...${NC}"
apt-get update
apt-get upgrade -y

# Configure Stunnel
echo -e "${GREEN}Configuring Stunnel...${NC}"

# Create required directories
mkdir -p /var/run/stunnel4
mkdir -p /etc/stunnel
chmod 755 /var/run/stunnel4

# Create Stunnel configuration
cat > /etc/stunnel/stunnel.conf <<EOF
# Stunnel configuration file

# Basic settings
pid = /var/run/stunnel4/stunnel.pid
output = /var/log/stunnel4/stunnel.log
debug = 7
syslog = no

# SSL settings
cert = /etc/stunnel/stunnel.pem
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1
client = no
[dropbear-1]
accept = 443
connect = 127.0.0.1:22

[dropbear-2]
accept = 445
connect = 127.0.0.1:22

[dropbear-3]
accept = 777
connect = 127.0.0.1:22
EOF

# Create log directory
mkdir -p /var/log/stunnel4
chmod 755 /var/log/stunnel4

# Generate SSL certificate
openssl genrsa -out /etc/stunnel/stunnel.key 2048
openssl req -new -key /etc/stunnel/stunnel.key -out /etc/stunnel/stunnel.csr -subj "/C=US/ST=California/L=Los Angeles/O=Organization/OU=Unit/CN=domain.com"
openssl x509 -req -days 365 -in /etc/stunnel/stunnel.csr -signkey /etc/stunnel/stunnel.key -out /etc/stunnel/stunnel.crt
cat /etc/stunnel/stunnel.key /etc/stunnel/stunnel.crt > /etc/stunnel/stunnel.pem
chmod 600 /etc/stunnel/stunnel.pem

# Update Stunnel default configuration
sed -i 's/ENABLED=0/ENABLED=1/g' /etc/default/stunnel4

# Create Stunnel service override
mkdir -p /etc/systemd/system/stunnel4.service.d/
cat > /etc/systemd/system/stunnel4.service.d/override.conf <<EOF
[Service]
ExecStart=
ExecStart=/usr/bin/stunnel4 /etc/stunnel/stunnel.conf
Type=forking
EOF

# Reload systemd and restart Stunnel
systemctl daemon-reload
systemctl restart stunnel4

# Configure Dropbear
echo -e "${GREEN}Configuring Dropbear...${NC}"
sed -i 's/NO_START=1/NO_START=0/g' /etc/default/dropbear
sed -i 's/DROPBEAR_PORT=22/DROPBEAR_PORT=443/g' /etc/default/dropbear
echo "DROPBEAR_EXTRA_ARGS=\"-p 109 -p 143\"" >> /etc/default/dropbear

# Configure Squid Proxy
echo -e "${GREEN}Configuring Squid Proxy...${NC}"
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

# Create BadVPN services
cat > /etc/systemd/system/badvpn1.service <<EOF
[Unit]
Description=BadVPN UDP Gateway 7100
After=network.target

[Service]
ExecStart=/usr/bin/badvpn-udpgw --listen-addr 127.0.0.1:7100 --max-clients 500
Restart=always

[Install]
WantedBy=multi-user.target
EOF

cat > /etc/systemd/system/badvpn2.service <<EOF
[Unit]
Description=BadVPN UDP Gateway 7200
After=network.target

[Service]
ExecStart=/usr/bin/badvpn-udpgw --listen-addr 127.0.0.1:7200 --max-clients 500
Restart=always

[Install]
WantedBy=multi-user.target
EOF

cat > /etc/systemd/system/badvpn3.service <<EOF
[Unit]
Description=BadVPN UDP Gateway 7300
After=network.target

[Service]
ExecStart=/usr/bin/badvpn-udpgw --listen-addr 127.0.0.1:7300 --max-clients 500
Restart=always

[Install]
WantedBy=multi-user.target
EOF

# Start and enable services
echo -e "${GREEN}Starting services...${NC}"
systemctl daemon-reload
systemctl enable stunnel4
systemctl enable dropbear
systemctl enable squid
systemctl enable badvpn1
systemctl enable badvpn2
systemctl enable badvpn3

systemctl restart stunnel4
systemctl restart dropbear
systemctl restart squid
systemctl start badvpn1
systemctl start badvpn2
systemctl start badvpn3

# Add after the existing package installation
echo -e "${GREEN}Installing Xray...${NC}"
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install

# Create Xray config directory if it doesn't exist
mkdir -p /usr/local/etc/xray

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
        "network": "tcp",
        "security": "tls",
        "tlsSettings": {
          "certificates": [
            {
              "certificateFile": "/etc/stunnel/stunnel.crt",
              "keyFile": "/etc/stunnel/stunnel.key"
            }
          ]
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
        "network": "tcp",
        "security": "tls",
        "tlsSettings": {
          "certificates": [
            {
              "certificateFile": "/etc/stunnel/stunnel.crt",
              "keyFile": "/etc/stunnel/stunnel.key"
            }
          ]
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

# Start Xray service
systemctl enable xray
systemctl restart xray

# Create VPS config directory
mkdir -p /etc/vps

# Add after the existing package installation
echo -e "${GREEN}Installing OpenVPN...${NC}"
apt-get install -y openvpn easy-rsa

# Setup OpenVPN and Easy-RSA
mkdir -p /etc/openvpn/easy-rsa
cp -r /usr/share/easy-rsa/* /etc/openvpn/easy-rsa/
cd /etc/openvpn/easy-rsa

# Initialize PKI
./easyrsa init-pki
echo "yes" | ./easyrsa build-ca nopass
echo "yes" | ./easyrsa gen-dh
echo "yes" | ./easyrsa build-server-full server nopass

# Generate ta key
openvpn --genkey --secret ta.key

# Copy necessary files
cp pki/ca.crt pki/dh.pem pki/issued/server.crt pki/private/server.key ta.key /etc/openvpn/

# Configure OpenVPN Server
cat > /etc/openvpn/server.conf <<EOF
port 1194
proto udp
dev tun
ca ca.crt
cert server.crt
key server.key
dh dh.pem
tls-auth ta.key 0
server 10.8.0.0 255.255.255.0
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 8.8.8.8"
push "dhcp-option DNS 8.8.4.4"
duplicate-cn
cipher AES-256-CBC
auth SHA256
comp-lzo
user nobody
group nogroup
persist-key
persist-tun
status openvpn-status.log
verb 3
client-to-client
script-security 3
auth-user-pass-verify /etc/openvpn/auth.sh via-env
username-as-common-name
verify-client-cert none
EOF

# Create authentication script
cat > /etc/openvpn/auth.sh <<EOF
#!/bin/bash
USERDB="/etc/vps/users.db"
USERNAME=\${username}
PASSWORD=\${password}

if grep -q "^ovpn:\${USERNAME}:\${PASSWORD}:" "\$USERDB"; then
    exit 0
else
    exit 1
fi
EOF

chmod +x /etc/openvpn/auth.sh

# Enable IP forwarding
echo "net.ipv4.ip_forward = 1" >> /etc/sysctl.conf
sysctl -p

# Configure NAT
iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE
iptables-save > /etc/iptables.rules

# Create script to restore iptables rules on boot
cat > /etc/network/if-pre-up.d/iptables <<EOF
#!/bin/bash
iptables-restore < /etc/iptables.rules
EOF

chmod +x /etc/network/if-pre-up.d/iptables

# Enable and start OpenVPN
systemctl enable openvpn@server
systemctl start openvpn@server

# Add to final echo messages
echo -e "${GREEN}OpenVPN UDP port: 1194${NC}"

echo -e "${GREEN}Installation completed!${NC}"
echo -e "${GREEN}Stunnel ports: 443, 445, 777${NC}"
echo -e "${GREEN}Dropbear ports: 443, 109, 143${NC}"
echo -e "${GREEN}Squid Proxy ports: 3128, 8080${NC}"
echo -e "${GREEN}BadVPN ports: 7100, 7200, 7300${NC}"
echo -e "${GREEN}Xray VMess port: 8443${NC}"
echo -e "${GREEN}Xray VLESS port: 8442${NC}"

# Add after the Xray configuration section
echo -e "${GREEN}Configuring WebSocket...${NC}"

# Install Nginx for WebSocket
apt-get install -y nginx

# Configure Nginx for WebSocket
cat > /etc/nginx/conf.d/websocket.conf <<EOF
server {
    listen 80;
    listen [::]:80;
    server_name "";
    
    location / {
        proxy_pass http://127.0.0.1:8880;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$http_host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }
}
EOF

# Update Xray config to support WebSocket
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
      },
      "sniffing": {
        "enabled": true,
        "destOverride": ["http", "tls"]
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
      },
      "sniffing": {
        "enabled": true,
        "destOverride": ["http", "tls"]
      }
    },
    {
      "port": 8880,
      "protocol": "vmess",
      "settings": {
        "clients": []
      },
      "streamSettings": {
        "network": "ws",
        "wsSettings": {
          "path": "/vmess",
          "headers": {}
        }
      }
    },
    {
      "port": 8881,
      "protocol": "vless",
      "settings": {
        "clients": [],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "ws",
        "wsSettings": {
          "path": "/vless",
          "headers": {}
        }
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "settings": {}
    },
    {
      "protocol": "blackhole",
      "settings": {},
      "tag": "blocked"
    }
  ],
  "routing": {
    "rules": [
      {
        "type": "field",
        "ip": ["geoip:private"],
        "outboundTag": "blocked"
      }
    ]
  }
}
EOF

# Configure WebSocket for SSH
cat > /etc/nginx/conf.d/ws-ssh.conf <<EOF
server {
    listen 80;
    listen [::]:80;
    server_name "";
    
    location /ssh-ws {
        proxy_pass http://127.0.0.1:2082;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$http_host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }
}
EOF

# Install Websocket-SSH Python script
cat > /usr/local/bin/ws-ssh.py <<EOF
#!/usr/bin/env python3
import socket, threading, thread, select, signal, sys, time, getopt

# Listen
LISTENING_ADDR = '127.0.0.1'
LISTENING_PORT = 2082

# Pass
PASS = ''

# CONST
BUFLEN = 4096 * 4
TIMEOUT = 60
DEFAULT_HOST = '127.0.0.1:22'
RESPONSE = 'HTTP/1.1 101 WebSocket Protocol Handshake\r\n\r\n'

class Server(threading.Thread):
    def __init__(self, host, port):
        threading.Thread.__init__(self)
        self.running = False
        self.host = host
        self.port = port
        self.threads = []
        self.threadsLock = threading.Lock()
        self.logLock = threading.Lock()

    def run(self):
        self.soc = socket.socket(socket.AF_INET)
        self.soc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.soc.settimeout(2)
        intport = int(self.port)
        self.soc.bind((self.host, intport))
        self.soc.listen(0)
        self.running = True

        try:
            while self.running:
                try:
                    c, addr = self.soc.accept()
                    c.setblocking(1)
                except socket.timeout:
                    continue

                conn = ConnectionHandler(c, self, addr)
                conn.start()
                self.addConn(conn)
        finally:
            self.running = False
            self.soc.close()

    def printLog(self, log):
        self.logLock.acquire()
        print log
        self.logLock.release()

    def addConn(self, conn):
        try:
            self.threadsLock.acquire()
            if self.running:
                self.threads.append(conn)
        finally:
            self.threadsLock.release()

    def removeConn(self, conn):
        try:
            self.threadsLock.acquire()
            self.threads.remove(conn)
        finally:
            self.threadsLock.release()

    def close(self):
        try:
            self.running = False
            self.threadsLock.acquire()

            threads = list(self.threads)
            for c in threads:
                c.close()
        finally:
            self.threadsLock.release()


class ConnectionHandler(threading.Thread):
    def __init__(self, socClient, server, addr):
        threading.Thread.__init__(self)
        self.clientClosed = False
        self.targetClosed = True
        self.client = socClient
        self.client_buffer = ''
        self.server = server
        self.log = 'Connection: ' + str(addr)

    def close(self):
        try:
            if not self.clientClosed:
                self.client.shutdown(socket.SHUT_RDWR)
                self.client.close()
        except:
            pass
        finally:
            self.clientClosed = True

        try:
            if not self.targetClosed:
                self.target.shutdown(socket.SHUT_RDWR)
                self.target.close()
        except:
            pass
        finally:
            self.targetClosed = True

    def run(self):
        try:
            self.client_buffer = self.client.recv(BUFLEN)

            hostPort = self.findHeader(self.client_buffer, 'X-Real-Host')

            if hostPort == '':
                hostPort = DEFAULT_HOST

            split = self.findHeader(self.client_buffer, 'X-Split')

            if split != '':
                self.client.recv(BUFLEN)

            if hostPort != '':
                passwd = self.findHeader(self.client_buffer, 'X-Pass')
				
                if len(PASS) != 0 and passwd == PASS:
                    self.method_CONNECT(hostPort)
                elif len(PASS) != 0 and passwd != PASS:
                    self.client.send('HTTP/1.1 400 WrongPass!\r\n\r\n')
                elif hostPort.startswith('127.0.0.1') or hostPort.startswith('localhost'):
                    self.method_CONNECT(hostPort)
                else:
                    self.client.send('HTTP/1.1 403 Forbidden!\r\n\r\n')
            else:
                print '- No X-Real-Host!'
                self.client.send('HTTP/1.1 400 NoXRealHost!\r\n\r\n')

        except Exception as e:
            self.log += ' - error: ' + e.strerror
            self.server.printLog(self.log)
	    pass
        finally:
            self.close()
            self.server.removeConn(self)

    def findHeader(self, head, header):
        aux = head.find(header + ': ')

        if aux == -1:
            return ''

        aux = head.find(':', aux)
        head = head[aux+2:]
        aux = head.find('\r\n')

        if aux == -1:
            return ''

        return head[:aux];

    def connect_target(self, host):
        i = host.find(':')
        if i != -1:
            port = int(host[i+1:])
            host = host[:i]
        else:
            if self.method=='CONNECT':
                port = 443
            else:
                port = sys.argv[1]

        (soc_family, soc_type, proto, _, address) = socket.getaddrinfo(host, port)[0]

        self.target = socket.socket(soc_family, soc_type, proto)
        self.targetClosed = False
        self.target.connect(address)

    def method_CONNECT(self, path):
        self.log += ' - CONNECT ' + path

        self.connect_target(path)
        self.client.sendall(RESPONSE)
        self.client_buffer = ''

        self.server.printLog(self.log)
        self.doCONNECT()

    def doCONNECT(self):
        socs = [self.client, self.target]
        count = 0
        error = False
        while True:
            count += 1
            (recv, _, err) = select.select(socs, [], socs, 3)
            if err:
                error = True
            if recv:
                for in_ in recv:
		    try:
                        data = in_.recv(BUFLEN)
                        if data:
			    if in_ is self.target:
				self.client.send(data)
                            else:
                                while data:
                                    byte = self.target.send(data)
                                    data = data[byte:]

                            count = 0
			else:
			    break
		    except:
                        error = True
                        break
            if count == TIMEOUT:
                error = True
            if error:
                break


def print_usage():
    print 'Usage: proxy.py -p <port>'
    print '       proxy.py -b <bindAddr> -p <port>'
    print '       proxy.py -b 0.0.0.0 -p 80'

def parse_args(argv):
    global LISTENING_ADDR
    global LISTENING_PORT
    
    try:
        opts, args = getopt.getopt(argv,"hb:p:",["bind=","port="])
    except getopt.GetoptError:
        print_usage()
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print_usage()
            sys.exit()
        elif opt in ("-b", "--bind"):
            LISTENING_ADDR = arg
        elif opt in ("-p", "--port"):
            LISTENING_PORT = int(arg)


def main(host=LISTENING_ADDR, port=LISTENING_PORT):
    print "\n:-------PythonProxy-------:\n"
    print "Listening addr: " + LISTENING_ADDR
    print "Listening port: " + str(LISTENING_PORT) + "\n"
    print ":-------------------------:\n"
    server = Server(LISTENING_ADDR, LISTENING_PORT)
    server.start()
    while True:
        try:
            time.sleep(2)
        except KeyboardInterrupt:
            print 'Stopping...'
            server.close()
            break

if __name__ == '__main__':
    parse_args(sys.argv[1:])
    main()
EOF

chmod +x /usr/local/bin/ws-ssh.py

# Create systemd service for WebSocket SSH
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

# Enable and start WebSocket SSH service
systemctl enable ws-ssh
systemctl start ws-ssh

# Update Xray WebSocket configuration
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
      },
      "sniffing": {
        "enabled": true,
        "destOverride": ["http", "tls"]
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
      },
      "sniffing": {
        "enabled": true,
        "destOverride": ["http", "tls"]
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "settings": {}
    },
    {
      "protocol": "blackhole",
      "settings": {},
      "tag": "blocked"
    }
  ],
  "routing": {
    "rules": [
      {
        "type": "field",
        "ip": ["geoip:private"],
        "outboundTag": "blocked"
      }
    ]
  }
}
EOF

# Configure UDP ports for SSH
iptables -t nat -A PREROUTING -p udp --dport 1:65535 -j REDIRECT --to-port 22
iptables-save > /etc/iptables.rules

# Create startup script for UDP ports
cat > /etc/network/if-pre-up.d/iptables <<EOF
#!/bin/sh
iptables-restore < /etc/iptables.rules
EOF
chmod +x /etc/network/if-pre-up.d/iptables

# Configure OpenVPN UDP
if [[ -f /etc/openvpn/server.conf ]]; then
    cp /etc/openvpn/server.conf /etc/openvpn/server-tcp.conf
    cp /etc/openvpn/server.conf /etc/openvpn/server-udp.conf
    
    # Configure TCP
    sed -i 's/proto udp/proto tcp/g' /etc/openvpn/server-tcp.conf
    
    # Configure UDP
    sed -i 's/port 1194/port 2200/g' /etc/openvpn/server-udp.conf
    
    # Enable both services
    systemctl enable openvpn@server-tcp
    systemctl enable openvpn@server-udp
    systemctl start openvpn@server-tcp
    systemctl start openvpn@server-udp
fi 

# Configure UFW
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp
ufw allow 1:65535/udp  # Allow all UDP ports
ufw allow 80/tcp
ufw allow 443/tcp
ufw allow 3128/tcp
ufw allow 8080/tcp
ufw allow 1194/tcp
ufw allow 1194/udp
ufw allow 2200/udp     # OpenVPN UDP port
ufw allow 80/udp
ufw allow 7100:7300/udp  # BadVPN ports
echo "y" | ufw enable 

# Configure HTTP Custom Support
cat > /etc/systemd/system/http-custom.service <<EOF
[Unit]
Description=HTTP Custom Service
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/bin/python3 -m http.server 80
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

# Start HTTP Custom service
systemctl daemon-reload
systemctl enable http-custom
systemctl start http-custom

# Configure Nginx for HTTP Custom
cat > /etc/nginx/conf.d/http-custom.conf <<EOF
server {
    listen 80;
    server_name _;
    
    location / {
        proxy_pass http://127.0.0.1:80;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$http_host;
    }
}
EOF

# Restart Nginx
systemctl restart nginx 

# Install HTTP Custom Proxy
cat > /usr/local/bin/http-custom.py <<'EOF'
#!/usr/bin/env python3
import socket
import select
import threading
import sys

LISTENING_PORT = 80
BUFFER_SIZE = 8192

def handle_client(client_socket, remote_socket):
    while True:
        r, w, e = select.select([client_socket, remote_socket], [], [], 3)
        if not r:
            break
            
        for sock in r:
            try:
                data = sock.recv(BUFFER_SIZE)
                if not data:
                    break
                    
                if sock is client_socket:
                    remote_socket.send(data)
                else:
                    client_socket.send(data)
            except:
                break
                
    client_socket.close()
    remote_socket.close()

def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('0.0.0.0', LISTENING_PORT))
    server.listen(0)
    
    print(f"[*] HTTP Custom Proxy listening on 0.0.0.0:{LISTENING_PORT}")
    
    while True:
        try:
            client_socket, addr = server.accept()
            print(f"[*] Accepted connection from {addr[0]}:{addr[1]}")
            
            remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            remote_socket.connect(('127.0.0.1', 22))
            
            thread = threading.Thread(target=handle_client, args=(client_socket, remote_socket))
            thread.daemon = True
            thread.start()
        except Exception as e:
            print(f"[!] Error: {e}")
            break
            
    server.close()

if __name__ == '__main__':
    start_server()
EOF

chmod +x /usr/local/bin/http-custom.py

# Create service for HTTP Custom
cat > /etc/systemd/system/http-custom.service <<EOF
[Unit]
Description=HTTP Custom Proxy Service
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/bin/python3 /usr/local/bin/http-custom.py
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable http-custom
systemctl start http-custom 

# Configure Stunnel5 (based on cfsshws repository)
echo -e "${GREEN}Configuring Stunnel5...${NC}"

# Install Stunnel5
apt-get install -y stunnel5

# Create required directories
mkdir -p /etc/stunnel5
mkdir -p /var/log/stunnel5

# Create Stunnel configuration
cat > /etc/stunnel5/stunnel5.conf <<EOF
cert = /etc/stunnel5/stunnel5.pem
client = no
socket = a:SO_REUSEADDR=1
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1

[dropbear]
accept = 445
connect = 127.0.0.1:109

[openssh]
accept = 777
connect = 127.0.0.1:22

[openvpn]
accept = 990
connect = 127.0.0.1:1194

[stunnel]
accept = 443
connect = 127.0.0.1:222
EOF

# Generate SSL certificate
openssl genrsa -out /etc/stunnel5/stunnel5.key 2048
openssl req -new -key /etc/stunnel5/stunnel5.key -out /etc/stunnel5/stunnel5.csr -subj "/C=ID/ST=Jakarta/L=Jakarta/O=Stunnel/OU=Stunnel/CN=Stunnel"
openssl x509 -req -days 365 -in /etc/stunnel5/stunnel5.csr -signkey /etc/stunnel5/stunnel5.key -out /etc/stunnel5/stunnel5.crt
cat /etc/stunnel5/stunnel5.key /etc/stunnel5/stunnel5.crt > /etc/stunnel5/stunnel5.pem

# Create systemd service
cat > /etc/systemd/system/stunnel5.service <<EOF
[Unit]
Description=Stunnel5 Service
Documentation=https://stunnel.org
After=syslog.target network-online.target

[Service]
ExecStart=/usr/bin/stunnel5 /etc/stunnel5/stunnel5.conf
Type=forking

[Install]
WantedBy=multi-user.target
EOF

# Set permissions
chmod 600 /etc/stunnel5/stunnel5.pem
chown -R nobody:nogroup /var/log/stunnel5

# Enable and start service
systemctl enable stunnel5
systemctl start stunnel5 

# Update port configurations based on cfsshws
# SSH: 443, 22
# OpenVPN: TCP 1194, UDP 2200, SSL 990
# Stunnel5: 443, 445, 777
# Dropbear: 443, 109, 143
# Squid Proxy: 3128, 8080
# Badvpn: 7100, 7200, 7300
# Nginx: 89
# XRAYS Vmess TLS: 8443
# XRAYS Vmess None TLS: 80
# XRAYS Vless TLS: 8443
# XRAYS Vless None TLS: 80
# XRAYS Trojan: 2083
# Websocket TLS: 443
# Websocket None TLS: 80
# Websocket Ovpn: 2086
# OHP SSH: 8181
# OHP Dropbear: 8282
# OHP OpenVPN: 8383
# Trojan Go: 2087

# Configure UFW with these ports
ufw allow 22/tcp        # SSH
ufw allow 443/tcp       # SSL/TLS
ufw allow 80/tcp        # HTTP
ufw allow 1194/tcp      # OpenVPN TCP
ufw allow 2200/udp      # OpenVPN UDP
ufw allow 990/tcp       # OpenVPN SSL
ufw allow 109/tcp       # Dropbear
ufw allow 143/tcp       # Dropbear
ufw allow 3128/tcp      # Squid
ufw allow 8080/tcp      # Squid
ufw allow 7100:7300/udp # BadVPN
ufw allow 89/tcp        # Nginx
ufw allow 8443/tcp      # XRAYS
ufw allow 2083/tcp      # XRAYS Trojan
ufw allow 2086/tcp      # WS OpenVPN
ufw allow 8181/tcp      # OHP SSH
ufw allow 8282/tcp      # OHP Dropbear
ufw allow 8383/tcp      # OHP OpenVPN
ufw allow 2087/tcp      # Trojan Go 

# Install UDP Custom
install_udp_custom() {
    echo -e "${GREEN}Installing UDP Custom...${NC}"
    
    # Clone UDP Custom repository
    cd /root
    git clone https://github.com/http-custom/udp-custom
    cd udp-custom
    chmod +x install.sh
    ./install.sh
}

# Add this line after other installations
install_udp_custom 