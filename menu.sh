#!/bin/bash

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

# Configuration files
XRAY_CONFIG="/usr/local/etc/xray/config.json"
USER_DB="/etc/vps/users.db"

# Add after color definitions
ADMRufu="/etc/ADMRufu"

# Create user database if it doesn't exist
[ ! -f "$USER_DB" ] && touch "$USER_DB"

# Function to generate random UUID
generate_uuid() {
    uuidgen
}

# Function to wait for user input
press_enter() {
    echo ""
    echo -e "${YELLOW}Press enter to return to the main menu...${NC}"
    read
}

# Function to create SSH & OpenVPN account
create_ssh_ovpn() {
    clear
    echo -e "${GREEN}=== Create SSH & OpenVPN Account ===${NC}"
    read -p "Username: " username
    read -p "Password: " password
    read -p "Duration (days): " duration

    # Check if user exists
    if id "$username" &>/dev/null; then
        echo -e "${RED}Error: User already exists${NC}"
        return 1
    fi

    # Calculate expiry date
    exp_date=$(date -d "+${duration} days" +"%Y-%m-%d")
    
    # Create user
    useradd -e $(date -d "$exp_date" +"%Y-%m-%d") -s /bin/false -M "$username"
    echo "$username:$password" | chpasswd

    # Add to database
    echo "ssh:${username}:${password}:${exp_date}" >> $USER_DB

    # Get server IP
    server_ip=$(curl -s ipv4.icanhazip.com)

    clear
    echo -e "${GREEN}Account Created Successfully${NC}"
    echo -e "Username: $username"
    echo -e "Password: $password"
    echo -e "Expired Date: $exp_date"
    echo -e "\nConnection Details:"
    echo -e "SSH Port: 22, 109, 143"
    echo -e "SSL/TLS Port: 443, 445, 777"
    echo -e "Squid Proxy: 3128, 8080"
    echo -e "OpenVPN TCP: 1194"
    echo -e "Server IP: $server_ip"
    echo -e "\nDownload OpenVPN Config: http://$server_ip:81/client-tcp.ovpn"
}

# Function to delete SSH & OpenVPN account
delete_ssh_ovpn() {
    clear
    echo -e "${GREEN}=== Delete SSH & OpenVPN Account ===${NC}"
    echo -e "Current users:"
    echo -e "${YELLOW}"
    grep "^ssh:" $USER_DB | cut -d: -f2
    echo -e "${NC}"
    read -p "Username to delete: " username

    # Check if user exists
    if ! grep -q "^ssh:$username:" $USER_DB; then
        echo -e "${RED}Error: User not found${NC}"
        read -n 1 -s -r -p "Press any key to continue"
        return 1
    fi

    # Delete user
    userdel -f "$username"
    sed -i "/^ssh:$username:/d" $USER_DB

    echo -e "${GREEN}User deleted successfully${NC}"
    read -n 1 -s -r -p "Press any key to continue"
}

# Function to extend SSH & OpenVPN account
extend_ssh_ovpn() {
    clear
    echo -e "${GREEN}=== Extend SSH & OpenVPN Account ===${NC}"
    echo -e "Current users:"
    echo -e "${YELLOW}"
    grep "^ssh:" $USER_DB | cut -d: -f2
    echo -e "${NC}"
    read -p "Username to extend: " username
    read -p "Additional days: " days

    # Check if user exists
    if ! grep -q "^ssh:$username:" $USER_DB; then
        echo -e "${RED}Error: User not found${NC}"
        read -n 1 -s -r -p "Press any key to continue"
        return 1
    fi

    # Calculate new expiry date
    current_exp=$(grep "^ssh:$username:" $USER_DB | cut -d: -f4)
    new_exp=$(date -d "$current_exp + $days days" +"%Y-%m-%d")
    
    # Update system
    chage -E $(date -d "$new_exp" +"%Y-%m-%d") "$username"
    
    # Update database
    sed -i "s|^ssh:$username:.*|ssh:$username:$(grep "^ssh:$username:" $USER_DB | cut -d: -f3):$new_exp|" $USER_DB

    echo -e "${GREEN}Account extended successfully${NC}"
    echo -e "New expiry date: $new_exp"
    read -n 1 -s -r -p "Press any key to continue"
}

# Function to check SSH & OpenVPN users
check_ssh_ovpn() {
    clear
    echo -e "${GREEN}=== SSH & OpenVPN User Status ===${NC}"
    echo -e "\nOnline Users:"
    echo -e "${YELLOW}"
    who | grep -v "root"
    echo -e "${NC}"
    echo -e "\nUser List:"
    echo -e "Username | Expiry Date | Status"
    echo -e "--------------------------------"
    while IFS=: read -r type username _ expiry; do
        if [[ "$type" == "ssh" ]]; then
            if [[ $(date -d "$expiry" +%s) -gt $(date +%s) ]]; then
                status="${GREEN}Active${NC}"
            else
                status="${RED}Expired${NC}"
            fi
            echo -e "$username | $expiry | $status"
        fi
    done < $USER_DB
    
    read -n 1 -s -r -p "Press any key to continue"
}

# Function to create VMess account
create_vmess() {
    clear
    echo -e "${GREEN}=== Create VMess Account ===${NC}"
    read -p "Username: " username
    read -p "Duration (days): " duration

    # Check if user exists
    if grep -q "^vmess:$username:" $USER_DB; then
        echo -e "${RED}Error: User already exists${NC}"
        return 1
    fi

    # Generate UUID
    uuid=$(generate_uuid)
    
    # Calculate expiry date
    exp_date=$(date -d "+${duration} days" +"%Y-%m-%d")
    
    # Add to Xray config
    jq --arg uuid "$uuid" '.inbounds[0].settings.clients += [{"id": $uuid, "alterId": 0}]' $XRAY_CONFIG > tmp.json
    mv tmp.json $XRAY_CONFIG
    
    # Add to database
    echo "vmess:${username}:${uuid}:${exp_date}" >> $USER_DB
    
    # Get server IP
    server_ip=$(curl -s ipv4.icanhazip.com)
    
    # Restart Xray service
    systemctl restart xray
    
    # Create VMess URL
    vmess_json="{
      \"v\": \"2\",
      \"ps\": \"${username}\",
      \"add\": \"${server_ip}\",
      \"port\": \"8443\",
      \"id\": \"${uuid}\",
      \"aid\": \"0\",
      \"net\": \"ws\",
      \"path\": \"/vmess\",
      \"type\": \"none\",
      \"host\": \"\",
      \"tls\": \"tls\"
    }"
    vmess_url="vmess://$(echo $vmess_json | base64 -w 0)"
    
    clear
    echo -e "${GREEN}VMess Account Created Successfully${NC}"
    echo -e "Username: $username"
    echo -e "UUID: $uuid"
    echo -e "Expired Date: $exp_date"
    echo -e "\nConnection Details:"
    echo -e "Address: $server_ip"
    echo -e "Port: 8443"
    echo -e "Protocol: VMess"
    echo -e "Path: /vmess"
    echo -e "TLS: Yes"
    echo -e "\nVMess URL:"
    echo -e "$vmess_url"
}

# Function to delete VMess account
delete_vmess() {
    clear
    echo -e "${GREEN}=== Delete VMess Account ===${NC}"
    echo -e "Current users:"
    echo -e "${YELLOW}"
    grep "^vmess:" $USER_DB | cut -d: -f2
    echo -e "${NC}"
    read -p "Username to delete: " username

    # Check if user exists
    if ! grep -q "^vmess:$username:" $USER_DB; then
        echo -e "${RED}Error: User not found${NC}"
        return 1
    fi

    # Get UUID
    uuid=$(grep "^vmess:$username:" $USER_DB | cut -d: -f3)
    
    # Remove from Xray config
    jq --arg uuid "$uuid" '.inbounds[0].settings.clients = [.inbounds[0].settings.clients[] | select(.id != $uuid)]' $XRAY_CONFIG > tmp.json
    mv tmp.json $XRAY_CONFIG
    
    # Remove from database
    sed -i "/^vmess:$username:/d" $USER_DB
    
    # Restart Xray service
    systemctl restart xray
    
    echo -e "${GREEN}VMess account deleted successfully${NC}"
}

# Function to extend VMess account
extend_vmess() {
    clear
    echo -e "${GREEN}=== Extend VMess Account ===${NC}"
    echo -e "Current users:"
    echo -e "${YELLOW}"
    grep "^vmess:" $USER_DB | cut -d: -f2
    echo -e "${NC}"
    read -p "Username to extend: " username
    read -p "Additional days: " days

    # Check if user exists
    if ! grep -q "^vmess:$username:" $USER_DB; then
        echo -e "${RED}Error: User not found${NC}"
        return 1
    fi

    # Calculate new expiry date
    current_exp=$(grep "^vmess:$username:" $USER_DB | cut -d: -f4)
    new_exp=$(date -d "$current_exp + $days days" +"%Y-%m-%d")
    
    # Update database
    uuid=$(grep "^vmess:$username:" $USER_DB | cut -d: -f3)
    sed -i "s|^vmess:$username:.*|vmess:$username:$uuid:$new_exp|" $USER_DB
    
    echo -e "${GREEN}Account extended successfully${NC}"
    echo -e "New expiry date: $new_exp"
}

# Function to check VMess users
check_vmess() {
    clear
    echo -e "${GREEN}=== VMess User Status ===${NC}"
    echo -e "\nUser List:"
    echo -e "Username | UUID | Expiry Date | Status"
    echo -e "----------------------------------------"
    while IFS=: read -r type username uuid expiry; do
        if [[ "$type" == "vmess" ]]; then
            if [[ $(date -d "$expiry" +%s) -gt $(date +%s) ]]; then
                status="${GREEN}Active${NC}"
            else
                status="${RED}Expired${NC}"
            fi
            echo -e "$username | $uuid | $expiry | $status"
        fi
    done < $USER_DB
}

# Function to create VLESS account
create_vless() {
    clear
    echo -e "${GREEN}=== Create VLESS Account ===${NC}"
    read -p "Username: " username
    read -p "Duration (days): " duration

    # Check if user exists
    if grep -q "^vless:$username:" $USER_DB; then
        echo -e "${RED}Error: User already exists${NC}"
        return 1
    fi

    # Generate UUID
    uuid=$(generate_uuid)
    
    # Calculate expiry date
    exp_date=$(date -d "+${duration} days" +"%Y-%m-%d")
    
    # Add to Xray config
    jq --arg uuid "$uuid" '.inbounds[1].settings.clients += [{"id": $uuid, "flow": "xtls-rprx-direct"}]' $XRAY_CONFIG > tmp.json
    mv tmp.json $XRAY_CONFIG
    
    # Add to database
    echo "vless:${username}:${uuid}:${exp_date}" >> $USER_DB
    
    # Get server IP
    server_ip=$(curl -s ipv4.icanhazip.com)
    
    # Restart Xray service
    systemctl restart xray
    
    clear
    echo -e "${GREEN}VLESS Account Created Successfully${NC}"
    echo -e "Username: $username"
    echo -e "UUID: $uuid"
    echo -e "Expired Date: $exp_date"
    echo -e "\nConnection Details:"
    echo -e "Address: $server_ip"
    echo -e "Port: 8442"
    echo -e "Protocol: VLESS"
    echo -e "Path: /vless"
    echo -e "TLS: Yes"
    echo -e "\nVLESS URL:"
    echo -e "vless://${uuid}@${server_ip}:8442?security=tls&encryption=none&headerType=none&type=tcp&flow=xtls-rprx-direct#${username}"
}

# Function to delete VLESS account
delete_vless() {
    clear
    echo -e "${GREEN}=== Delete VLESS Account ===${NC}"
    echo -e "Current users:"
    echo -e "${YELLOW}"
    grep "^vless:" $USER_DB | cut -d: -f2
    echo -e "${NC}"
    read -p "Username to delete: " username

    # Check if user exists
    if ! grep -q "^vless:$username:" $USER_DB; then
        echo -e "${RED}Error: User not found${NC}"
        return 1
    fi

    # Get UUID
    uuid=$(grep "^vless:$username:" $USER_DB | cut -d: -f3)
    
    # Remove from Xray config
    jq --arg uuid "$uuid" '.inbounds[1].settings.clients = [.inbounds[1].settings.clients[] | select(.id != $uuid)]' $XRAY_CONFIG > tmp.json
    mv tmp.json $XRAY_CONFIG
    
    # Remove from database
    sed -i "/^vless:$username:/d" $USER_DB
    
    # Restart Xray service
    systemctl restart xray
    
    echo -e "${GREEN}VLESS account deleted successfully${NC}"
}

# Function to extend VLESS account
extend_vless() {
    clear
    echo -e "${GREEN}=== Extend VLESS Account ===${NC}"
    echo -e "Current users:"
    echo -e "${YELLOW}"
    grep "^vless:" $USER_DB | cut -d: -f2
    echo -e "${NC}"
    read -p "Username to extend: " username
    read -p "Additional days: " days

    # Check if user exists
    if ! grep -q "^vless:$username:" $USER_DB; then
        echo -e "${RED}Error: User not found${NC}"
        return 1
    fi

    # Calculate new expiry date
    current_exp=$(grep "^vless:$username:" $USER_DB | cut -d: -f4)
    new_exp=$(date -d "$current_exp + $days days" +"%Y-%m-%d")
    
    # Update database
    uuid=$(grep "^vless:$username:" $USER_DB | cut -d: -f3)
    sed -i "s|^vless:$username:.*|vless:$username:$uuid:$new_exp|" $USER_DB
    
    echo -e "${GREEN}Account extended successfully${NC}"
    echo -e "New expiry date: $new_exp"
}

# Function to check VLESS users
check_vless() {
    clear
    echo -e "${GREEN}=== VLESS User Status ===${NC}"
    echo -e "\nUser List:"
    echo -e "Username | UUID | Expiry Date | Status"
    echo -e "----------------------------------------"
    while IFS=: read -r type username uuid expiry; do
        if [[ "$type" == "vless" ]]; then
            if [[ $(date -d "$expiry" +%s) -gt $(date +%s) ]]; then
                status="${GREEN}Active${NC}"
            else
                status="${RED}Expired${NC}"
            fi
            echo -e "$username | $uuid | $expiry | $status"
        fi
    done < $USER_DB
}

# Function to create WebSocket account
create_ws() {
    clear
    echo -e "${GREEN}=== Create WebSocket Account ===${NC}"
    read -p "Username: " username
    read -p "Password: " password
    read -p "Duration (days): " duration

    # Check if user exists
    if grep -q "^ws:$username:" $USER_DB; then
        echo -e "${RED}Error: User already exists${NC}"
        return 1
    fi

    # Calculate expiry date
    exp_date=$(date -d "+${duration} days" +"%Y-%m-%d")
    
    # Create system user
    useradd -e $(date -d "$exp_date" +"%Y-%m-%d") -s /bin/false -M "$username"
    echo "$username:$password" | chpasswd

    # Add to database
    echo "ws:${username}:${password}:${exp_date}" >> $USER_DB
    
    # Get server IP
    server_ip=$(curl -s ipv4.icanhazip.com)
    
    clear
    echo -e "${GREEN}WebSocket Account Created Successfully${NC}"
    echo -e "Username: $username"
    echo -e "Password: $password"
    echo -e "Expired Date: $exp_date"
    echo -e "\nConnection Details:"
    echo -e "Address: $server_ip"
    echo -e "Port: 80"
    echo -e "Path: /ws"
    echo -e "\nWebSocket Config:"
    echo -e "URL: ws://$server_ip:80/ws"
    echo -e "Header:"
    echo -e "Host: $server_ip"
    echo -e "Upgrade: websocket"
    echo -e "Connection: Upgrade"
    echo -e "User-Agent: [ua]"
}

# Function to delete WebSocket account
delete_ws() {
    clear
    echo -e "${GREEN}=== Delete WebSocket Account ===${NC}"
    echo -e "Current users:"
    echo -e "${YELLOW}"
    grep "^ws:" $USER_DB | cut -d: -f2
    echo -e "${NC}"
    read -p "Username to delete: " username

    # Check if user exists
    if ! grep -q "^ws:$username:" $USER_DB; then
        echo -e "${RED}Error: User not found${NC}"
        return 1
    fi

    # Delete system user
    userdel -f "$username"
    
    # Remove from database
    sed -i "/^ws:$username:/d" $USER_DB
    
    echo -e "${GREEN}WebSocket account deleted successfully${NC}"
}

# Function to extend WebSocket account
extend_ws() {
    clear
    echo -e "${GREEN}=== Extend WebSocket Account ===${NC}"
    echo -e "Current users:"
    echo -e "${YELLOW}"
    grep "^ws:" $USER_DB | cut -d: -f2
    echo -e "${NC}"
    read -p "Username to extend: " username
    read -p "Additional days: " days

    # Check if user exists
    if ! grep -q "^ws:$username:" $USER_DB; then
        echo -e "${RED}Error: User not found${NC}"
        return 1
    fi

    # Calculate new expiry date
    current_exp=$(grep "^ws:$username:" $USER_DB | cut -d: -f4)
    new_exp=$(date -d "$current_exp + $days days" +"%Y-%m-%d")
    
    # Update system
    chage -E $(date -d "$new_exp" +"%Y-%m-%d") "$username"
    
    # Update database
    password=$(grep "^ws:$username:" $USER_DB | cut -d: -f3)
    sed -i "s|^ws:$username:.*|ws:$username:$password:$new_exp|" $USER_DB
    
    echo -e "${GREEN}Account extended successfully${NC}"
    echo -e "New expiry date: $new_exp"
}

# Function to check WebSocket users
check_ws() {
    clear
    echo -e "${GREEN}=== WebSocket User Status ===${NC}"
    echo -e "\nUser List:"
    echo -e "Username | Expiry Date | Status"
    echo -e "--------------------------------"
    while IFS=: read -r type username _ expiry; do
        if [[ "$type" == "ws" ]]; then
            if [[ $(date -d "$expiry" +%s) -gt $(date +%s) ]]; then
                status="${GREEN}Active${NC}"
            else
                status="${RED}Expired${NC}"
            fi
            echo -e "$username | $expiry | $status"
        fi
    done < $USER_DB
    
    echo -e "\nOnline Users:"
    echo -e "${YELLOW}"
    netstat -anp | grep ESTABLISHED | grep python3 | awk '{print $5}' | cut -d: -f1 | sort | uniq
    echo -e "${NC}"
}

# Function to change domain
change_domain() {
    clear
    echo -e "${GREEN}=== Add/Change Domain ===${NC}"
    echo -e "Current domain settings:"
    if [ -f "/etc/vps/domain.conf" ]; then
        current_domain=$(cat /etc/vps/domain.conf)
        echo -e "Current domain: ${YELLOW}$current_domain${NC}"
    else
        echo -e "${RED}No domain configured${NC}"
    fi
    
    echo -e "\n${YELLOW}Options:${NC}"
    echo -e "1) Add/Change domain"
    echo -e "2) Use IP address"
    echo -e "3) Back to menu"
    
    read -p "Select option: " domain_option
    
    case $domain_option in
        1)
            read -p "Enter your domain: " new_domain
            
            # Save domain
            echo "$new_domain" > /etc/vps/domain.conf
            
            # Update Nginx config
            cat > /etc/nginx/conf.d/xray.conf <<EOF
server {
    listen 80;
    listen [::]:80;
    server_name $new_domain;
    
    location / {
        return 301 https://\$host\$request_uri;
    }
}

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name $new_domain;
    
    ssl_certificate /etc/letsencrypt/live/$new_domain/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$new_domain/privkey.pem;
    ssl_ciphers EECDH+CHACHA20:EECDH+CHACHA20-draft:EECDH+ECDSA+AES128:EECDH+aRSA+AES128:RSA+AES128:EECDH+ECDSA+AES256:EECDH+aRSA+AES256:RSA+AES256:EECDH+ECDSA+3DES:EECDH+aRSA+3DES:RSA+3DES:!MD5;
    ssl_protocols TLSv1.2 TLSv1.3;
    
    location / {
        proxy_pass http://127.0.0.1:80;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$http_host;
    }
    
    location /vmess {
        proxy_pass http://127.0.0.1:8443;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$http_host;
    }
    
    location /vless {
        proxy_pass http://127.0.0.1:8442;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$http_host;
    }
}
EOF
            
            # Get SSL certificate
            systemctl stop nginx
            certbot certonly --standalone --preferred-challenges http --agree-tos --email admin@$new_domain -d $new_domain
            systemctl start nginx
            
            # Update Xray config
            jq --arg domain "$new_domain" '.inbounds[0].streamSettings.tlsSettings.serverName = $domain | .inbounds[1].streamSettings.tlsSettings.serverName = $domain' $XRAY_CONFIG > tmp.json
            mv tmp.json $XRAY_CONFIG
            
            # Restart services
            systemctl restart nginx
            systemctl restart xray
            
            echo -e "${GREEN}Domain has been updated to: $new_domain${NC}"
            ;;
        2)
            server_ip=$(curl -s ipv4.icanhazip.com)
            echo "$server_ip" > /etc/vps/domain.conf
            
            # Update configs to use IP
            sed -i "s/server_name .*/server_name $server_ip;/g" /etc/nginx/conf.d/xray.conf
            
            echo -e "${GREEN}System will use IP address: $server_ip${NC}"
            ;;
        3)
            return 0
            ;;
        *)
            echo -e "${RED}Invalid option${NC}"
            ;;
    esac
}

# Function to change ports
change_ports() {
    clear
    echo -e "${GREEN}=== Change Port Services ===${NC}"
    echo -e "\nCurrent ports:"
    echo -e "SSH: 22 (TCP/UDP)"
    echo -e "SSH UDP: 1-65535"
    echo -e "Dropbear: 109, 143"
    echo -e "Stunnel: 443, 445, 777"
    echo -e "Squid: 3128, 8080"
    echo -e "OpenVPN: 1194 (TCP/UDP)"
    echo -e "Xray VMess: 8443"
    echo -e "Xray VLESS: 8442"
    echo -e "WebSocket: 80"
    
    echo -e "\n${YELLOW}Select service to change port:${NC}"
    echo -e "1) SSH TCP"
    echo -e "2) SSH UDP"
    echo -e "3) Dropbear"
    echo -e "4) Stunnel"
    echo -e "5) Squid"
    echo -e "6) OpenVPN TCP"
    echo -e "7) OpenVPN UDP"
    echo -e "8) Xray VMess"
    echo -e "9) Xray VLESS"
    echo -e "10) WebSocket"
    echo -e "11) Back to menu"
    
    read -p "Select option: " port_option
    
    case $port_option in
        1)
            read -p "Enter new SSH TCP port: " new_port
            sed -i "s/Port 22/Port $new_port/g" /etc/ssh/sshd_config
            systemctl restart ssh
            ;;
        2)
            read -p "Enter UDP port range (example: 1-65535): " udp_range
            # Configure UDP ports using iptables
            iptables -t nat -A PREROUTING -p udp --dport $udp_range -j REDIRECT --to-port 22
            # Save iptables rules
            iptables-save > /etc/iptables.rules
            # Create startup script for UDP ports
            cat > /etc/network/if-pre-up.d/iptables <<EOF
#!/bin/sh
iptables-restore < /etc/iptables.rules
EOF
            chmod +x /etc/network/if-pre-up.d/iptables
            ;;
        3)
            read -p "Enter new Dropbear ports (space-separated): " new_ports
            sed -i "s/DROPBEAR_EXTRA_ARGS=.*/DROPBEAR_EXTRA_ARGS=\"-p $new_ports\"/g" /etc/default/dropbear
            systemctl restart dropbear
            ;;
        4)
            read -p "Enter new Stunnel ports (space-separated): " new_ports
            for port in $new_ports; do
                sed -i "s/accept = .*/accept = $port/g" /etc/stunnel/stunnel.conf
            done
            systemctl restart stunnel4
            ;;
        5)
            read -p "Enter new Squid ports (space-separated): " new_ports
            sed -i "s/http_port .*/http_port $new_ports/g" /etc/squid/squid.conf
            systemctl restart squid
            ;;
        6)
            read -p "Enter new OpenVPN port: " new_port
            sed -i "s/port .*/port $new_port/g" /etc/openvpn/server.conf
            systemctl restart openvpn
            ;;
        7)
            read -p "Enter new VMess port: " new_port
            jq --arg port "$new_port" '.inbounds[0].port = ($port|tonumber)' $XRAY_CONFIG > tmp.json
            mv tmp.json $XRAY_CONFIG
            systemctl restart xray
            ;;
        8)
            read -p "Enter new VLESS port: " new_port
            jq --arg port "$new_port" '.inbounds[1].port = ($port|tonumber)' $XRAY_CONFIG > tmp.json
            mv tmp.json $XRAY_CONFIG
            systemctl restart xray
            ;;
        9)
            read -p "Enter new WebSocket port: " new_port
            sed -i "s/LISTENING_PORT = .*/LISTENING_PORT = $new_port/g" /usr/local/bin/ws-ssh.py
            systemctl restart ws-ssh
            ;;
        10)
            return 0
            ;;
        *)
            echo -e "${RED}Invalid option${NC}"
            ;;
    esac
    
    echo -e "${GREEN}Port(s) updated successfully${NC}"
}

# Function to create SSH UDP account
create_ssh_udp() {
    clear
    echo -e "${GREEN}=== Create UDP Custom Account ===${NC}"
    read -p "Username: " username
    read -p "Password: " password
    read -p "Duration (days): " duration

    # Check if user exists
    if id "$username" &>/dev/null; then
        echo -e "${RED}Error: User already exists${NC}"
        return 1
    fi

    # Calculate expiry date
    exp_date=$(date -d "+${duration} days" +"%Y-%m-%d")
    
    # Create user
    useradd -e $(date -d "$exp_date" +"%Y-%m-%d") -s /bin/false -M "$username"
    echo "$username:$password" | chpasswd

    # Get server IP
    server_ip=$(curl -s ipv4.icanhazip.com)

    # Add to UDP Custom config
    cat >> /root/udp/config.json <<EOF
{
    "username": "${username}",
    "password": "${password}",
    "exp": "${exp_date}"
}
EOF

    # Create client config
    cat > /home/$username-udp.txt <<EOF
# UDP Custom Config
Server: ${server_ip}
Port: 1-65535
Username: ${username}
Password: ${password}
Expired: ${exp_date}

# Additional Info
UDP Port: All ports from 1-65535 are available
Default Excluded Ports: 53,5300 (DNS)
EOF

    clear
    echo -e "${GREEN}UDP Custom Account Created Successfully${NC}"
    echo -e "Username: $username"
    echo -e "Password: $password"
    echo -e "Expired Date: $exp_date"
    echo -e "\nConnection Details:"
    echo -e "Server Host: $server_ip"
    echo -e "Available Ports: 1-65535"
    echo -e "Excluded Ports: 53,5300"
    echo -e "\nConfig file saved as: /home/$username-udp.txt"
}

# Function to delete UDP account
delete_ssh_udp() {
    clear
    echo -e "${GREEN}=== Delete UDP Custom Account ===${NC}"
    echo -e "Current UDP users:"
    echo -e "${YELLOW}"
    jq -r '.[] | select(.username != null) | .username' /root/udp/config.json
    echo -e "${NC}"
    read -p "Username to delete: " username

    # Delete from UDP config
    jq --arg user "$username" 'del(.[] | select(.username == $user))' /root/udp/config.json > /root/udp/config.json.tmp
    mv /root/udp/config.json.tmp /root/udp/config.json

    # Delete system user
    userdel -f "$username"
    rm -f /home/$username-udp.txt

    echo -e "${GREEN}UDP Custom account deleted successfully${NC}"
}

# Function to check UDP users
check_ssh_udp() {
    clear
    echo -e "${GREEN}=== UDP Custom User Status ===${NC}"
    echo -e "\nUser List:"
    echo -e "Username | Expiry Date | Status"
    echo -e "----------------------------------------"
    
    while read -r user; do
        exp=$(jq -r --arg user "$user" '.[] | select(.username == $user) | .exp' /root/udp/config.json)
        if [[ $(date -d "$exp" +%s) -gt $(date +%s) ]]; then
            status="${GREEN}Active${NC}"
        else
            status="${RED}Expired${NC}"
        fi
        echo -e "$user | $exp | $status"
    done < <(jq -r '.[].username' /root/udp/config.json)
    
    echo -e "\nActive Connections:"
    netstat -anp | grep ESTABLISHED | grep udp
}

# Update the UDP service management functions
start_udp_custom() {
    if pgrep -x "udp-custom" > /dev/null; then
        echo -e "${YELLOW}UDP Custom is already running${NC}"
    else
        echo -e "${GREEN}Starting UDP Custom...${NC}"
        if [ -f "/etc/ADMRufu/install/udp-custom" ]; then
            systemctl start udp-custom
            sleep 2
            if pgrep -x "udp-custom" > /dev/null; then
                echo -e "${GREEN}UDP Custom started successfully${NC}"
            else
                echo -e "${RED}Failed to start UDP Custom${NC}"
                echo -e "Trying alternative method..."
                cd /root/udp
                /etc/ADMRufu/install/udp-custom server &
                sleep 2
                if pgrep -x "udp-custom" > /dev/null; then
                    echo -e "${GREEN}UDP Custom started successfully (alternative method)${NC}"
                else
                    echo -e "${RED}Failed to start UDP Custom. Please check installation${NC}"
                    echo -e "Run these commands to reinstall:"
                    echo -e "${YELLOW}wget -O install-udp.sh \"https://raw.githubusercontent.com/Abdofaiz/mescript/main/install_udp.sh\" && chmod +x install-udp.sh && ./install-udp.sh${NC}"
                fi
            fi
        else
            echo -e "${RED}UDP Custom binary not found. Please reinstall.${NC}"
            echo -e "Run these commands to install:"
            echo -e "${YELLOW}wget -O install-udp.sh \"https://raw.githubusercontent.com/Abdofaiz/mescript/main/install_udp.sh\" && chmod +x install-udp.sh && ./install-udp.sh${NC}"
        fi
    fi
}

stop_udp_custom() {
    if pgrep -x "udp-custom" > /dev/null; then
        echo -e "${GREEN}Stopping UDP Custom...${NC}"
        pkill -x "udp-custom"
        sleep 2
        if ! pgrep -x "udp-custom" > /dev/null; then
            echo -e "${GREEN}UDP Custom stopped successfully${NC}"
        else
            echo -e "${RED}Failed to stop UDP Custom${NC}"
            echo -e "Trying force kill..."
            killall -9 udp-custom
            echo -e "${GREEN}UDP Custom force stopped${NC}"
        fi
    else
        echo -e "${YELLOW}UDP Custom is not running${NC}"
    fi
}

restart_udp_custom() {
    echo -e "${GREEN}Restarting UDP Custom...${NC}"
    stop_udp_custom
    sleep 2
    start_udp_custom
}

# Main menu loop
while true; do
    clear
    echo -e "${GREEN}╔═══════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║              ${YELLOW}VPS MANAGEMENT MENU${GREEN}              ║${NC}"
    echo -e "${GREEN}╚═══════════════════════════════════════════════╝${NC}"
    echo -e ""
    echo -e "${YELLOW}SSH & OpenVPN Menu${NC}"
    echo -e "${CYAN}[1]${NC} • Create SSH & OpenVPN Account"
    echo -e "${CYAN}[2]${NC} • Delete SSH & OpenVPN Account"
    echo -e "${CYAN}[3]${NC} • Extend SSH & OpenVPN Account"
    echo -e "${CYAN}[4]${NC} • Check User Login SSH & OpenVPN"
    echo -e ""
    echo -e "${YELLOW}Xray/VMess Menu${NC}"
    echo -e "${CYAN}[5]${NC} • Create VMess Account"
    echo -e "${CYAN}[6]${NC} • Delete VMess Account"
    echo -e "${CYAN}[7]${NC} • Extend VMess Account"
    echo -e "${CYAN}[8]${NC} • Check User Login VMess"
    echo -e ""
    echo -e "${YELLOW}Xray/VLess Menu${NC}"
    echo -e "${CYAN}[9]${NC} • Create VLess Account"
    echo -e "${CYAN}[10]${NC} • Delete VLess Account"
    echo -e "${CYAN}[11]${NC} • Extend VLess Account"
    echo -e "${CYAN}[12]${NC} • Check User Login VLess"
    echo -e ""
    echo -e "${YELLOW}WebSocket Menu${NC}"
    echo -e "${CYAN}[13]${NC} • Create WebSocket Account"
    echo -e "${CYAN}[14]${NC} • Delete WebSocket Account"
    echo -e "${CYAN}[15]${NC} • Extend WebSocket Account"
    echo -e "${CYAN}[16]${NC} • Check User Login WebSocket"
    echo -e ""
    echo -e "${YELLOW}System Menu${NC}"
    echo -e "${CYAN}[17]${NC} • Add/Change Domain"
    echo -e "${CYAN}[18]${NC} • Change Port Services"
    echo -e "${CYAN}[19]${NC} • Check System Status"
    echo -e "${CYAN}[20]${NC} • Check Running Services"
    echo -e "${CYAN}[21]${NC} • Check Memory Usage"
    echo -e "${CYAN}[22]${NC} • Reboot VPS"
    echo -e "${CYAN}[23]${NC} • Exit"
    echo -e ""
    echo -e "${YELLOW}SSH UDP Menu${NC}"
    echo -e "${CYAN}[24]${NC} • Create SSH UDP Account"
    echo -e "${CYAN}[25]${NC} • Delete SSH UDP Account"
    echo -e "${CYAN}[26]${NC} • Check SSH UDP Users"
    echo -e ""
    echo -e "${CYAN}[27]${NC} • Start UDP Custom"
    echo -e "${CYAN}[28]${NC} • Stop UDP Custom"
    echo -e "${CYAN}[29]${NC} • Restart UDP Custom"
    echo -e ""
    read -p "Select menu [1-29]: " choice

    case $choice in
        1) 
            create_ssh_ovpn
            press_enter
            ;;
        2) 
            delete_ssh_ovpn
            press_enter
            ;;
        3) 
            extend_ssh_ovpn
            press_enter
            ;;
        4) 
            check_ssh_ovpn
            press_enter
            ;;
        5) 
            create_vmess
            press_enter
            ;;
        6) 
            delete_vmess
            press_enter
            ;;
        7) 
            extend_vmess
            press_enter
            ;;
        8) 
            check_vmess
            press_enter
            ;;
        9) 
            create_vless
            press_enter
            ;;
        10) 
            delete_vless
            press_enter
            ;;
        11) 
            extend_vless
            press_enter
            ;;
        12) 
            check_vless
            press_enter
            ;;
        13) 
            create_ws
            press_enter
            ;;
        14) 
            delete_ws
            press_enter
            ;;
        15) 
            extend_ws
            press_enter
            ;;
        16) 
            check_ws
            press_enter
            ;;
        17) 
            change_domain
            press_enter
            ;;
        18) 
            change_ports
            press_enter
            ;;
        19) 
            clear
            echo -e "${GREEN}=== System Status ===${NC}"
            echo -e "CPU Usage: $(top -bn1 | grep "Cpu(s)" | awk '{print $2 + $4}')%"
            echo -e "Memory Usage: $(free -m | awk 'NR==2{printf "%.2f%%", $3*100/$2}')"
            echo -e "Disk Usage: $(df -h / | awk 'NR==2{print $5}')"
            press_enter
            ;;
        20)
            clear
            echo -e "${GREEN}=== Running Services ===${NC}"
            echo -e "Stunnel: $(systemctl is-active stunnel4)"
            echo -e "Dropbear: $(systemctl is-active dropbear)"
            echo -e "Squid: $(systemctl is-active squid)"
            echo -e "OpenVPN: $(systemctl is-active openvpn)"
            echo -e "Xray: $(systemctl is-active xray)"
            echo -e "WebSocket: $(systemctl is-active ws-ssh)"
            press_enter
            ;;
        21)
            clear
            echo -e "${GREEN}=== Memory Usage ===${NC}"
            free -h
            press_enter
            ;;
        22)
            read -p "Are you sure you want to reboot? [y/n]: " answer
            if [ "$answer" == "y" ]; then
                reboot
            fi
            press_enter
            ;;
        23) 
            clear
            exit 0 
            ;;
        24)
            create_ssh_udp
            press_enter
            ;;
        25)
            delete_ssh_udp
            press_enter
            ;;
        26)
            check_ssh_udp
            press_enter
            ;;
        27)
            start_udp_custom
            press_enter
            ;;
        28)
            stop_udp_custom
            press_enter
            ;;
        29)
            restart_udp_custom
            press_enter
            ;;
        *)
            echo -e "${RED}Please enter a number between 1 and 29${NC}"
            press_enter
            ;;
    esac
done 