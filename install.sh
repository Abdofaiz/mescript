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
    wget -O /usr/local/bin/menu "https://raw.githubusercontent.com/Abdofaiz/mescript/main/menu.sh"
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
    cat > /usr/local/bin/ws-ssh.py <<'EOF'
#!/usr/bin/env python3
import socket
import threading
import select
import signal
import sys
import time
import getopt

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
        self.soc.bind((self.host, self.port))
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
        print(log)
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
        self.running = False

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
            self.client_buffer = self.client.recv(BUFLEN).decode()
            hostPort = DEFAULT_HOST

            self.target = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.target.connect(('127.0.0.1', 22))
            self.targetClosed = False
            self.client.send(RESPONSE.encode())
            
            self.client_buffer = ''
            self.doCONNECT()
        except Exception as e:
            self.log += ' - error: ' + str(e)
            self.server.printLog(self.log)
        finally:
            self.close()
            self.server.removeConn(self)

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

def main():
    print("\n:-------PythonProxy-------:\n")
    print("Listening addr: " + LISTENING_ADDR)
    print("Listening port: " + str(LISTENING_PORT) + "\n")
    print(":-------------------------:\n")
    
    server = Server(LISTENING_ADDR, LISTENING_PORT)
    server.start()
    
    while True:
        try:
            time.sleep(2)
        except KeyboardInterrupt:
            print('Stopping...')
            server.close()
            break

if __name__ == '__main__':
    main()
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