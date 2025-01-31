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

# Add at the beginning of the script after color definitions
SCRIPT_URL="https://raw.githubusercontent.com/Abdofaiz/mescript/main"

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
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "                 FAIZ-VPN USER STATUS"
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

    # Filter out common service IPs and duplicates
    EXCLUDE_IPS=(
        "127.0.0.1"
        "157.240."      # Facebook
        "142.250."      # Google
        "172.217."      # Google
        "216.58."       # Google
        "216.239."      # Google
        "173.194."      # Google
        "20.33."        # Microsoft
        "20.47."        # Microsoft
        "149.154."      # Telegram
        "209.85."       # Google
        "144.208."      # Other services
    )

    # Create exclude pattern
    EXCLUDE_PATTERN=$(printf "|%s" "${EXCLUDE_IPS[@]}")
    EXCLUDE_PATTERN=${EXCLUDE_PATTERN:1}

    # First show active connections summary
    echo -e "\n${YELLOW}Active Users Summary:${NC}"
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    printf "%-15s %-15s %-15s %-15s\n" "Username" "SSH/SSL" "Dropbear" "Total"
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

    while IFS=: read -r type username _ expiry; do
        if [[ "$type" == "ssh" ]]; then
            # Get unique real client IPs
            client_ips=($(netstat -natp | grep 'ESTABLISHED.*sshd\|ESTABLISHED.*stunnel' | grep -w "$username" | \
                         grep -vE "$EXCLUDE_PATTERN" | awk '{print $5}' | cut -d: -f1 | sort -u))
            ssh_count=${#client_ips[@]}
            
            db_ips=($(netstat -natp | grep 'ESTABLISHED.*dropbear' | grep -w "$username" | \
                     grep -vE "$EXCLUDE_PATTERN" | awk '{print $5}' | cut -d: -f1 | sort -u))
            db_count=${#db_ips[@]}
            
            total=$((ssh_count + db_count))
            
            if [ $total -gt 0 ]; then
                printf "%-15s %-15s %-15s %-15s\n" "$username" "$ssh_count" "$db_count" "$total"
            fi
        fi
    done < $USER_DB
    
    # Then show detailed connection information
    echo -e "\n${YELLOW}Detailed Connection Info:${NC}"
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

    while IFS=: read -r type username _ expiry; do
        if [[ "$type" == "ssh" ]]; then
            # Get unique client IPs
            client_ips=($(netstat -natp | grep 'ESTABLISHED.*\(sshd\|stunnel\|dropbear\)' | grep -w "$username" | \
                         grep -vE "$EXCLUDE_PATTERN" | awk '{print $5}' | cut -d: -f1 | sort -u))
            total=${#client_ips[@]}
            
            if [ $total -gt 0 ]; then
                echo -e "\n${GREEN}User: $username${NC}"
                echo -e "Expiry: $expiry"
                if [[ $(date -d "$expiry" +%s) -gt $(date +%s) ]]; then
                    echo -e "Status: ${GREEN}Active${NC}"
                else
                    echo -e "Status: ${RED}Expired${NC}"
                fi
                
                echo -e "\n${YELLOW}Active Connections:${NC}"
                for ip in "${client_ips[@]}"; do
                    conn_info=$(netstat -natp | grep 'ESTABLISHED.*\(sshd\|stunnel\|dropbear\)' | grep -w "$username" | grep "$ip" | head -1)
                    port=$(echo "$conn_info" | awk '{print $5}' | cut -d: -f2)
                    pid=$(echo "$conn_info" | awk '{print $7}' | cut -d/ -f1)
                    duration=$(ps -p $pid -o etime= 2>/dev/null || echo "N/A")
                    conn_type=""
                    if echo "$conn_info" | grep -q "sshd\|stunnel"; then
                        conn_type="SSH/SSL"
                    elif echo "$conn_info" | grep -q "dropbear"; then
                        conn_type="Dropbear"
                    fi
                    echo -e "   > IP: $ip"
                    echo -e "      Type: $conn_type"
                    echo -e "      Port: $port"
                    echo -e "      Duration: $duration"
                done
                
                echo -e "\n${YELLOW}Connection Summary:${NC}"
                echo -e "   • Total Unique IPs: $total"
                echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
            fi
        fi
    done < $USER_DB

    echo -e "\n${YELLOW}Support: @faizvpn${NC}"
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
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
        if [ -f "/usr/local/udpgw/udp-custom" ]; then
            cd /root/udp
            screen -dmS udp-custom /usr/local/udpgw/udp-custom server
            sleep 2
            if pgrep -x "udp-custom" > /dev/null; then
                echo -e "${GREEN}UDP Custom started successfully${NC}"
            else
                echo -e "${RED}Failed to start UDP Custom${NC}"
                echo -e "Trying alternative method..."
                cd /root/udp
                /usr/local/udpgw/udp-custom server &
                sleep 2
                if pgrep -x "udp-custom" > /dev/null; then
                    echo -e "${GREEN}UDP Custom started successfully (alternative method)${NC}"
                else
                    echo -e "${RED}Failed to start UDP Custom. Please check installation${NC}"
                    echo -e "Run these commands to reinstall:"
                    echo -e "${YELLOW}wget -O install-udp.sh \"https://raw.githubusercontent.com/ChumoGH/ScriptCGH/main/install-udp.sh\" && chmod +x install-udp.sh && ./install-udp.sh${NC}"
                fi
            fi
        else
            echo -e "${RED}UDP Custom binary not found. Please reinstall.${NC}"
            echo -e "Run these commands to install:"
            echo -e "${YELLOW}wget -O install-udp.sh \"https://raw.githubusercontent.com/ChumoGH/ScriptCGH/main/install-udp.sh\" && chmod +x install-udp.sh && ./install-udp.sh${NC}"
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

# Function to check service status
check_service_status() {
    local service=$1
    if systemctl is-active --quiet $service; then
        echo -e "${GREEN}Running${NC}"
    else
        echo -e "${RED}Not Running${NC}"
    fi
}

# Function to install BadVPN
install_badvpn() {
    if [ ! -f "/usr/bin/badvpn-udpgw" ]; then
        echo -e "${YELLOW}Installing BadVPN...${NC}"
        
        # Install dependencies
        apt-get update
        apt-get install -y cmake make gcc build-essential
        
        # Create directory and download source
        mkdir -p /tmp/badvpn
        cd /tmp/badvpn
        
        # Download and extract BadVPN source
        wget -O badvpn.zip "https://github.com/ambrop72/badvpn/archive/refs/heads/master.zip"
        unzip badvpn.zip
        cd badvpn-master
        
        # Compile and install
        cmake . -DBUILD_NOTHING_BY_DEFAULT=1 -DBUILD_UDPGW=1
        make install
        
        # Create systemd service
        cat > /etc/systemd/system/badvpn.service << EOF
[Unit]
Description=BadVPN UDPGW Service
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/badvpn-udpgw --listen-addr 127.0.0.1:7300 --max-clients 1000 --max-connections-for-client 100
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

        # Reload systemd and enable service
        systemctl daemon-reload
        systemctl enable badvpn
        systemctl start badvpn
        
        # Cleanup
        cd ~
        rm -rf /tmp/badvpn
        
        echo -e "${GREEN}BadVPN installed successfully${NC}"
    else
        echo -e "${YELLOW}BadVPN is already installed${NC}"
    fi
}

# Function to install BadVPN (Alternative Method)
install_badvpn_alt() {
    if [ ! -f "/usr/bin/badvpn-udpgw" ]; then
        echo -e "${YELLOW}Installing BadVPN (Alternative Method)...${NC}"
        
        # Download pre-compiled binary
        wget -O /usr/bin/badvpn-udpgw "https://raw.githubusercontent.com/Abdofaiz/mescript/main/badvpn-udpgw64"
        chmod +x /usr/bin/badvpn-udpgw
        
        # Create systemd service
        cat > /etc/systemd/system/badvpn.service << EOF
[Unit]
Description=BadVPN UDPGW Service
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/bin/badvpn-udpgw --listen-addr 127.0.0.1:7300 --max-clients 1000 --max-connections-for-client 100
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

        # Reload systemd and enable service
        systemctl daemon-reload
        systemctl enable badvpn
        systemctl start badvpn
        
        echo -e "${GREEN}BadVPN installed successfully${NC}"
    else
        echo -e "${YELLOW}BadVPN is already installed${NC}"
    fi
}

# Function to manage BadVPN
manage_badvpn() {
    clear
    echo -e "${GREEN}=================================================${NC}"
    echo -e "${YELLOW}              BadVPN Management                  ${NC}"
    echo -e "${GREEN}=================================================${NC}"
    echo -e "${GREEN}1.${NC} Install BadVPN (Compile from source)"
    echo -e "${GREEN}2.${NC} Install BadVPN (Pre-compiled binary)"
    echo -e "${GREEN}3.${NC} Start BadVPN"
    echo -e "${GREEN}4.${NC} Stop BadVPN"
    echo -e "${GREEN}5.${NC} Restart BadVPN"
    echo -e "${GREEN}6.${NC} Check BadVPN Status"
    echo -e "${GREEN}0.${NC} Back to Main Menu"
    echo -e "${GREEN}=================================================${NC}"
    read -p "Select option: " badvpn_option

    case $badvpn_option in
        1)
            install_badvpn
            ;;
        2)
            install_badvpn_alt
            ;;
        3)
            systemctl start badvpn
            echo -e "${GREEN}BadVPN started${NC}"
            ;;
        4)
            systemctl stop badvpn
            echo -e "${YELLOW}BadVPN stopped${NC}"
            ;;
        5)
            systemctl restart badvpn
            echo -e "${GREEN}BadVPN restarted${NC}"
            ;;
        6)
            if systemctl is-active --quiet badvpn; then
                echo -e "${GREEN}BadVPN is running${NC}"
                echo -e "Port: 7300"
                echo -e "Status: $(systemctl status badvpn | grep Active)"
                echo -e "Memory usage: $(ps aux | grep badvpn | grep -v grep | awk '{print $6/1024 "MB"}')"
            else
                echo -e "${RED}BadVPN is not running${NC}"
            fi
            ;;
        0)
            return
            ;;
        *)
            echo -e "${RED}Invalid option${NC}"
            ;;
    esac
    read -n 1 -s -r -p "Press any key to continue"
    manage_badvpn
}

# Function to display service statuses
show_service_status() {
    clear
    echo -e "${GREEN}=================================================${NC}"
    echo -e "${YELLOW}               Service Status Check              ${NC}"
    echo -e "${GREEN}=================================================${NC}"
    echo -e "${YELLOW}UDP Custom     :${NC} $(check_service_status udp-custom)"
    echo -e "${YELLOW}Stunnel4       :${NC} $(check_service_status stunnel4)"
    echo -e "${YELLOW}Dropbear       :${NC} $(check_service_status dropbear)"
    echo -e "${YELLOW}WebSocket SSH  :${NC} $(check_service_status ws-ssh)"
    echo -e "${YELLOW}Xray          :${NC} $(check_service_status xray)"
    echo -e "${YELLOW}Nginx         :${NC} $(check_service_status nginx)"
    echo -e "${YELLOW}Squid         :${NC} $(check_service_status squid)"
    echo -e "${YELLOW}BadVPN        :${NC} $(check_service_status badvpn)"
    echo -e "${GREEN}=================================================${NC}"
    echo ""
    read -n 1 -s -r -p "Press any key to return to menu"
}

# Function to get system information
get_system_info() {
    # Get IP addresses (with timeout to prevent hanging)
    IPVPS=$(curl -s --max-time 5 ipv4.icanhazip.com || echo "Unable to get IP")
    
    # Get CPU load (simplified for reliability)
    CPU_LOAD=$(cat /proc/loadavg | awk '{print $1}')
    
    # Get RAM usage (simplified calculation)
    TOTAL_RAM=$(free -m | grep Mem | awk '{print $2}')
    USED_RAM=$(free -m | grep Mem | awk '{print $3}')
    RAM_PERCENT=$(( (USED_RAM * 100) / TOTAL_RAM ))
    
    # Get domain if exists
    DOMAIN=$(cat /etc/vps/domain.conf 2>/dev/null || echo "Not Set")
    
    # Get system uptime
    UPTIME=$(uptime -p | cut -d " " -f 2-)

    # Get install date
    if [ -f "/etc/vps/install-date" ]; then
        INSTALL_DATE=$(cat /etc/vps/install-date | cut -d: -f2 | xargs)
    else
        INSTALL_DATE="Not Available"
    fi
}

# Function to configure Telegram bot
configure_telegram_bot() {
    clear
    echo -e "${GREEN}=================================================${NC}"
    echo -e "${YELLOW}         Telegram Bot Configuration              ${NC}"
    echo -e "${GREEN}=================================================${NC}"
    
    # Check if config file exists
    if [ ! -d "/etc/vps" ]; then
        mkdir -p /etc/vps
    fi
    
    if [ -f "/etc/vps/telegram.conf" ]; then
        current_token=$(cat /etc/vps/telegram.conf | grep "BOT_TOKEN=" | cut -d= -f2)
        current_username=$(cat /etc/vps/telegram.conf | grep "BOT_USERNAME=" | cut -d= -f2)
        echo -e "Current Configuration:"
        echo -e "Bot Username: $current_username"
        echo -e "Bot Token: $current_token"
        echo -e ""
    fi
    
    echo -e "1. Set Bot Token"
    echo -e "2. Set Bot Username"
    echo -e "3. Start Bot Service"
    echo -e "4. Stop Bot Service"
    echo -e "5. Restart Bot Service"
    echo -e "0. Back to Main Menu"
    echo -e "${GREEN}=================================================${NC}"
    read -p "Select option: " bot_config_option
    
    case $bot_config_option in
        1)
            read -p "Enter Bot Token: " bot_token
            echo "BOT_TOKEN=$bot_token" > /etc/vps/telegram.conf
            echo -e "${GREEN}Bot token saved successfully${NC}"
            ;;
        2)
            read -p "Enter Bot Username: " bot_username
            echo "BOT_USERNAME=$bot_username" >> /etc/vps/telegram.conf
            echo -e "${GREEN}Bot username saved successfully${NC}"
            ;;
        3)
            if [ -f "/etc/vps/telegram.conf" ]; then
                screen -dmS telegram_bot bash /usr/local/bin/telegram_handler.sh
                echo -e "${GREEN}Telegram bot service started${NC}"
            else
                echo -e "${RED}Please configure bot token and username first${NC}"
            fi
            ;;
        4)
            pkill -f "telegram_handler.sh"
            echo -e "${YELLOW}Telegram bot service stopped${NC}"
            ;;
        5)
            pkill -f "telegram_handler.sh"
            sleep 2
            if [ -f "/etc/vps/telegram.conf" ]; then
                screen -dmS telegram_bot bash /usr/local/bin/telegram_handler.sh
                echo -e "${GREEN}Telegram bot service restarted${NC}"
            else
                echo -e "${RED}Please configure bot token and username first${NC}"
            fi
            ;;
        0)
            return
            ;;
        *)
            echo -e "${RED}Invalid option${NC}"
            ;;
    esac
    read -n 1 -s -r -p "Press any key to continue"
    configure_telegram_bot
}

# Function to install Telegram bot handler
install_telegram_bot() {
    clear
    echo -e "${GREEN}=================================================${NC}"
    echo -e "${YELLOW}         Installing Telegram Bot Handler         ${NC}"
    echo -e "${GREEN}=================================================${NC}"
    
    # Create directories
    mkdir -p /usr/local/bin
    mkdir -p /etc/vps
    
    # Download and install telegram handler
    echo -e "${YELLOW}Installing telegram handler...${NC}"
    wget -O /usr/local/bin/telegram_handler.sh "https://raw.githubusercontent.com/Abdofaiz/mescript/main/bot/telegram_handler.sh"
    chmod +x /usr/local/bin/telegram_handler.sh
    
    # Install dependencies
    echo -e "${YELLOW}Installing required packages...${NC}"
    apt-get update
    apt-get install -y jq curl screen
    
    echo -e "${GREEN}Installation completed!${NC}"
    echo -e "${YELLOW}Please configure your bot settings in the Telegram Bot Manager menu${NC}"
    
    read -n 1 -s -r -p "Press any key to continue"
    manage_telegram_bot
}

# Function to manage Telegram bot
manage_telegram_bot() {
    clear
    echo -e "${GREEN}=================================================${NC}"
    echo -e "${YELLOW}            Telegram Bot Management              ${NC}"
    echo -e "${GREEN}=================================================${NC}"
    
    # Check if telegram handler is installed
    if [ ! -f "/usr/local/bin/telegram_handler.sh" ]; then
        echo -e "${RED}Telegram bot handler is not installed${NC}"
        echo -e "${GREEN}1.${NC} Install Telegram Bot Handler"
        echo -e "${GREEN}0.${NC} Back to Main Menu"
        echo -e "${GREEN}=================================================${NC}"
        read -p "Select option: " bot_option
        
        case $bot_option in
            1)
                install_telegram_bot
                ;;
            0)
                return
                ;;
            *)
                echo -e "${RED}Invalid option${NC}"
                ;;
        esac
        read -n 1 -s -r -p "Press any key to continue"
        manage_telegram_bot
        return
    fi
    
    echo -e "${GREEN}1.${NC} Configure Bot Settings"
    echo -e "${GREEN}2.${NC} Add New User"
    echo -e "${GREEN}3.${NC} Remove User"
    echo -e "${GREEN}4.${NC} Check User Status"
    echo -e "${GREEN}5.${NC} Server Status"
    echo -e "${GREEN}6.${NC} Reinstall Bot Handler"
    echo -e "${GREEN}0.${NC} Back to Main Menu"
    echo -e "${GREEN}=================================================${NC}"
    read -p "Select option: " bot_option

    case $bot_option in
        1)
            configure_telegram_bot
            ;;
        2)
            if [ -f "/etc/vps/telegram.conf" ]; then
                BOT_USERNAME=$(cat /etc/vps/telegram.conf | grep "BOT_USERNAME=" | cut -d= -f2)
                echo -e "${YELLOW}Visit Telegram Bot: @$BOT_USERNAME${NC}"
                echo -e "Use command: /adduser username password duration"
            else
                echo -e "${RED}Please configure bot settings first${NC}"
            fi
            ;;
        3)
            if [ -f "/etc/vps/telegram.conf" ]; then
                BOT_USERNAME=$(cat /etc/vps/telegram.conf | grep "BOT_USERNAME=" | cut -d= -f2)
                echo -e "${YELLOW}Visit Telegram Bot: @$BOT_USERNAME${NC}"
                echo -e "Use command: /removeuser username"
            else
                echo -e "${RED}Please configure bot settings first${NC}"
            fi
            ;;
        4)
            if [ -f "/etc/vps/telegram.conf" ]; then
                BOT_USERNAME=$(cat /etc/vps/telegram.conf | grep "BOT_USERNAME=" | cut -d= -f2)
                echo -e "${YELLOW}Visit Telegram Bot: @$BOT_USERNAME${NC}"
                echo -e "Use command: /status username"
            else
                echo -e "${RED}Please configure bot settings first${NC}"
            fi
            ;;
        5)
            if [ -f "/etc/vps/telegram.conf" ]; then
                BOT_USERNAME=$(cat /etc/vps/telegram.conf | grep "BOT_USERNAME=" | cut -d= -f2)
                echo -e "${YELLOW}Visit Telegram Bot: @$BOT_USERNAME${NC}"
                echo -e "Use command: /server"
            else
                echo -e "${RED}Please configure bot settings first${NC}"
            fi
            ;;
        6)
            install_telegram_bot
            ;;
        0)
            return
            ;;
        *)
            echo -e "${RED}Invalid option${NC}"
            ;;
    esac
    read -n 1 -s -r -p "Press any key to continue"
    manage_telegram_bot
}

# Function to reinstall script
reinstall_script() {
    clear
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "            🚀 𝙁𝘼𝙄𝙕-𝙑𝙋𝙉 𝙍𝙀𝙄𝙉𝙎𝙏𝘼𝙇𝙇"
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e ""
    echo -e "${YELLOW}This will reinstall all script components:${NC}"
    echo -e " • SSH & OpenVPN"
    echo -e " • Stunnel4"
    echo -e " • Dropbear"
    echo -e " • Squid Proxy"
    echo -e " • BadVPN UDP"
    echo -e " • Xray"
    echo -e " • Websocket"
    echo -e ""
    echo -e "${RED}Warning: All current settings will be backed up${NC}"
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    read -p "Do you want to continue? [y/N]: " confirm

    if [[ "$confirm" == "y" || "$confirm" == "Y" ]]; then
        # Backup current configs
        echo -e "\n${YELLOW}Backing up current configurations...${NC}"
        mkdir -p /etc/vps/backup
        cp /etc/vps/*.conf /etc/vps/backup/ 2>/dev/null
        cp /etc/vps/*.db /etc/vps/backup/ 2>/dev/null
        
        # Download and run installer
        echo -e "\n${YELLOW}Downloading latest installer...${NC}"
        wget -O install.sh "${SCRIPT_URL}/install.sh"
        chmod +x install.sh
        
        echo -e "\n${YELLOW}Starting reinstallation...${NC}"
        ./install.sh
        
        # Restore configs
        echo -e "\n${YELLOW}Restoring configurations...${NC}"
        cp /etc/vps/backup/* /etc/vps/ 2>/dev/null
        
        echo -e "\n${GREEN}Reinstallation completed!${NC}"
        echo -e "Your previous settings have been restored."
        echo -e "\n${YELLOW}Please reboot your VPS to apply all changes${NC}"
        read -p "Reboot now? [y/N]: " reboot
        if [[ "$reboot" == "y" || "$reboot" == "Y" ]]; then
            reboot
        fi
    else
        echo -e "\n${YELLOW}Reinstallation cancelled${NC}"
    fi
    
    read -n 1 -s -r -p "Press any key to continue"
}

# Function to fix Stunnel4 configuration
fix_stunnel() {
    clear
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "                Fix Stunnel4 Service"
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

    # Install stunnel if not installed
    apt-get install -y stunnel4

    # Stop the service first
    systemctl stop stunnel4

    # Create proper stunnel config directory if it doesn't exist
    mkdir -p /etc/stunnel

    # Create proper stunnel config
    cat > /etc/stunnel/stunnel.conf <<EOF
pid = /var/run/stunnel4.pid
cert = /etc/stunnel/stunnel.pem
client = no
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1
TIMEOUTclose = 0

[dropbear]
accept = 443
connect = 127.0.0.1:109
TIMEOUTidle = 300

[openssh]
accept = 777
connect = 127.0.0.1:22
TIMEOUTidle = 300

[openvpn]
accept = 442
connect = 127.0.0.1:1194
TIMEOUTidle = 300
EOF

    # Create SSL certificate if it doesn't exist
    if [ ! -f "/etc/stunnel/stunnel.pem" ]; then
        echo -e "\n${YELLOW}Creating new SSL Certificate...${NC}"
        openssl genrsa -out /etc/stunnel/stunnel.key 2048
        openssl req -new -key /etc/stunnel/stunnel.key -out /etc/stunnel/stunnel.csr -subj "/C=US/ST=California/L=Los Angeles/O=FAIZ-VPN/OU=FAIZ-VPN/CN=$(curl -s ipv4.icanhazip.com)"
        openssl x509 -req -days 3650 -in /etc/stunnel/stunnel.csr -signkey /etc/stunnel/stunnel.key -out /etc/stunnel/stunnel.crt
        cat /etc/stunnel/stunnel.key /etc/stunnel/stunnel.crt > /etc/stunnel/stunnel.pem
    fi

    # Fix permissions
    chmod 600 /etc/stunnel/stunnel.pem
    
    # Enable stunnel in default config
    echo "ENABLED=1" > /etc/default/stunnel4

    # Create systemd service file
    cat > /etc/systemd/system/stunnel4.service <<EOF
[Unit]
Description=SSL tunnel for network daemons
After=network.target
After=syslog.target

[Service]
Type=forking
ExecStart=/usr/bin/stunnel4 /etc/stunnel/stunnel.conf
ExecStop=/usr/bin/pkill stunnel4
TimeoutSec=600

[Install]
WantedBy=multi-user.target
EOF

    # Fix common network issues
    sysctl -w net.ipv4.tcp_timestamps=1
    sysctl -w net.ipv4.tcp_window_scaling=1
    sysctl -w net.ipv4.tcp_sack=1
    sysctl -w net.ipv4.tcp_fin_timeout=30
    sysctl -w net.ipv4.tcp_keepalive_time=1200
    sysctl -w net.ipv4.tcp_max_syn_backlog=4096

    # Reload systemd and restart stunnel
    systemctl daemon-reload
    systemctl enable stunnel4
    systemctl restart stunnel4

    # Check if service is running
    if systemctl is-active --quiet stunnel4; then
        echo -e "\n${GREEN}Stunnel4 service has been fixed and is running!${NC}"
        echo -e "\n${YELLOW}Port Information:${NC}"
        echo -e "• SSL/TLS Dropbear : 443"
        echo -e "• SSL/TLS OpenSSH  : 777"
        echo -e "• SSL/TLS OpenVPN  : 442"
        
        # Show connection status
        echo -e "\n${YELLOW}Service Status:${NC}"
        echo -e "• Stunnel4: $(systemctl is-active stunnel4)"
        echo -e "• Dropbear: $(systemctl is-active dropbear)"
        echo -e "• OpenSSH: $(systemctl is-active ssh)"
        
        # Show listening ports
        echo -e "\n${YELLOW}Listening Ports:${NC}"
        netstat -tulpn | grep -E 'stunnel|dropbear|sshd'
    else
        echo -e "\n${RED}Failed to start Stunnel4. Checking logs...${NC}"
        journalctl -u stunnel4 --no-pager | tail -n 10
    fi
}

# Add this function to menu.sh
fix_ssh_config() {
    clear
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "            Fix SSH Connection Issues"
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

    # Backup original config
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak

    # Update SSH configuration
    cat > /etc/ssh/sshd_config <<EOF
Port 22
Protocol 2
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
HostKey /etc/ssh/ssh_host_ed25519_key
UsePAM yes
ClientAliveInterval 120
ClientAliveCountMax 3
MaxAuthTries 6
PubkeyAuthentication yes
PermitRootLogin yes
PasswordAuthentication yes
ChallengeResponseAuthentication no
KerberosAuthentication no
GSSAPIAuthentication no
X11Forwarding yes
PrintMotd no
AcceptEnv LANG LC_*
Subsystem sftp /usr/lib/openssh/sftp-server
EOF

    # Restart SSH service
    systemctl restart ssh

    echo -e "\n${GREEN}SSH configuration has been updated!${NC}"
    echo -e "• ClientAliveInterval: 120 seconds"
    echo -e "• ClientAliveCountMax: 3"
    echo -e "• MaxAuthTries: 6"
}

# Main menu display
show_main_menu() {
    clear
    get_system_info
    
    echo -e "${GREEN}=================================================${NC}"
    echo -e "${GREEN}║                  ${YELLOW}• FAIZ-VPN •                  ${GREEN}║${NC}"
    echo -e "${GREEN}║              ${YELLOW}PREMIUM VPS MANAGER              ${GREEN}║${NC}"
    echo -e "${GREEN}=================================================${NC}"
    echo -e "${YELLOW}VPS Information${NC}"
    echo -e "${GREEN}- IP VPS        :${NC} $IPVPS"
    echo -e "${GREEN}- Domain        :${NC} $DOMAIN"
    echo -e "${GREEN}- CPU Load      :${NC} $CPU_LOAD"
    echo -e "${GREEN}- RAM Usage     :${NC} $USED_RAM MB / $TOTAL_RAM MB ($RAM_PERCENT%)"
    echo -e "${GREEN}- Uptime        :${NC} $UPTIME"
    echo -e "${GREEN}- Install Date  :${NC} $INSTALL_DATE"
    echo -e "${GREEN}=================================================${NC}"
    echo -e "${GREEN}1.${NC} SSH & OpenVPN Menu"
    echo -e "${GREEN}2.${NC} Xray Menu"
    echo -e "${GREEN}3.${NC} UDP Custom Menu"
    echo -e "${GREEN}4.${NC} System Information"
    echo -e "${GREEN}5.${NC} System Settings"
    echo -e "${GREEN}6.${NC} Service Status"
    echo -e "${GREEN}7.${NC} BadVPN Manager"
    echo -e "${GREEN}8.${NC} Telegram Bot Manager"
    echo -e "${GREEN}9.${NC} Reinstall VPS Script"
    echo -e "${RED}10.${NC} Uninstall VPS Script"
    echo -e "${GREEN}0.${NC} Exit"
    echo -e "${GREEN}=================================================${NC}"
    echo -e "${GREEN}║            ${YELLOW}Telegram: @faizvpn               ${GREEN}║${NC}"
    echo -e "${GREEN}=================================================${NC}"
}

# Main script execution
while true; do
    show_main_menu
    read -p "Select menu: " menu_option
    
    case $menu_option in
        1)
            clear
            echo -e "${GREEN}=== SSH & OpenVPN Menu ===${NC}"
            echo -e "${GREEN}1.${NC} Create SSH & OpenVPN Account"
            echo -e "${GREEN}2.${NC} Delete SSH & OpenVPN Account"
            echo -e "${GREEN}3.${NC} Extend SSH & OpenVPN Account"
            echo -e "${GREEN}4.${NC} Check User Login SSH & OpenVPN"
            echo -e "${GREEN}0.${NC} Back to main menu"
            read -p "Select option: " ssh_option

            case $ssh_option in
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
                0)
                    continue
                    ;;
                *)
                    echo -e "${RED}Invalid option${NC}"
                    press_enter
                    ;;
            esac
            ;;
        2)
            clear
            echo -e "${GREEN}=== Xray Menu ===${NC}"
            echo -e "${GREEN}1.${NC} Create VMess Account"
            echo -e "${GREEN}2.${NC} Delete VMess Account"
            echo -e "${GREEN}3.${NC} Extend VMess Account"
            echo -e "${GREEN}4.${NC} Check User Login VMess"
            echo -e "${GREEN}5.${NC} Create VLess Account"
            echo -e "${GREEN}6.${NC} Delete VLess Account"
            echo -e "${GREEN}7.${NC} Extend VLess Account"
            echo -e "${GREEN}8.${NC} Check User Login VLess"
            echo -e "${GREEN}0.${NC} Back to main menu"
            read -p "Select option: " xray_option

            case $xray_option in
                1)
                    create_vmess
                    press_enter
                    ;;
                2)
                    delete_vmess
                    press_enter
                    ;;
                3)
                    extend_vmess
                    press_enter
                    ;;
                4)
                    check_vmess
                    press_enter
                    ;;
                5)
                    create_vless
                    press_enter
                    ;;
                6)
                    delete_vless
                    press_enter
                    ;;
                7)
                    extend_vless
                    press_enter
                    ;;
                8)
                    check_vless
                    press_enter
                    ;;
                0)
                    continue
                    ;;
                *)
                    echo -e "${RED}Invalid option${NC}"
                    press_enter
                    ;;
            esac
            ;;
        3)
            clear
            echo -e "${GREEN}=== UDP Custom Menu ===${NC}"
            echo -e "${GREEN}1.${NC} Create SSH UDP Account"
            echo -e "${GREEN}2.${NC} Delete SSH UDP Account"
            echo -e "${GREEN}3.${NC} Check SSH UDP Users"
            echo -e "${GREEN}4.${NC} Start UDP Custom"
            echo -e "${GREEN}5.${NC} Stop UDP Custom"
            echo -e "${GREEN}6.${NC} Restart UDP Custom"
            echo -e "${GREEN}0.${NC} Back to main menu"
            read -p "Select option: " udp_option

            case $udp_option in
                1)
                    create_ssh_udp
                    press_enter
                    ;;
                2)
                    delete_ssh_udp
                    press_enter
                    ;;
                3)
                    check_ssh_udp
                    press_enter
                    ;;
                4)
                    start_udp_custom
                    press_enter
                    ;;
                5)
                    stop_udp_custom
                    press_enter
                    ;;
                6)
                    restart_udp_custom
                    press_enter
                    ;;
                0)
                    continue
                    ;;
                *)
                    echo -e "${RED}Invalid option${NC}"
                    press_enter
                    ;;
            esac
            ;;
        4)
            clear
            echo -e "${GREEN}=== System Information ===${NC}"
            echo -e "CPU Usage: $(top -bn1 | grep "Cpu(s)" | awk '{print $2 + $4}')%"
            echo -e "Memory Usage: $(free -m | awk 'NR==2{printf "%.2f%%", $3*100/$2}')"
            echo -e "Disk Usage: $(df -h / | awk 'NR==2{print $5}')"
            press_enter
            ;;
        5)
            clear
            echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
            echo -e "              🛠️ 𝙎𝙮𝙨𝙩𝙚𝙢 𝙎𝙚𝙩𝙩𝙞𝙣𝙜𝙨"
            echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
            echo -e "${GREEN}1.${NC} Add/Change Domain"
            echo -e "${GREEN}2.${NC} Change Port Services"
            echo -e "${GREEN}3.${NC} Fix Stunnel4 Service"
            echo -e "${GREEN}4.${NC} Fix SSH Config"
            echo -e "${GREEN}0.${NC} Back to main menu"
            echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
            read -p "Select option: " settings_option

            case $settings_option in
                1)
                    change_domain
                    press_enter
                    ;;
                2)
                    change_ports
                    press_enter
                    ;;
                3)
                    fix_stunnel
                    press_enter
                    ;;
                4)
                    fix_ssh_config
                    press_enter
                    ;;
                0)
                    continue
                    ;;
                *)
                    echo -e "${RED}Invalid option${NC}"
                    press_enter
                    ;;
            esac
            ;;
        6)
            show_service_status
            ;;
        7)
            manage_badvpn
            ;;
        8)
            manage_telegram_bot
            ;;
        9)
            reinstall_script
            ;;
        10)
            echo -e "${RED}Warning: This will uninstall all VPS services${NC}"
            read -p "Are you sure you want to continue? (y/n): " confirm
            if [[ $confirm == "y" || $confirm == "Y" ]]; then
                wget -O uninstall.sh https://raw.githubusercontent.com/Abdofaiz/mescript/main/uninstall.sh
                chmod +x uninstall.sh
                ./uninstall.sh
            fi
            ;;
        0)
            clear
            exit 0
            ;;
        *)
            echo -e "${RED}Invalid option${NC}"
            press_enter
            ;;
    esac
    
    # Add a small delay before showing menu again
    sleep 1
done 