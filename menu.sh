#!/bin/bash

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Configuration files
XRAY_CONFIG="/usr/local/etc/xray/config.json"
USER_DB="/etc/vps/users.db"

# Create directory for user database
mkdir -p /etc/vps

# Function to generate random UUID
generate_uuid() {
    uuidgen
}

# Function to add VMess user
add_vmess_user() {
    clear
    echo -e "${GREEN}=== Add VMess User ===${NC}"
    read -p "Username: " username
    read -p "Expired days: " expired_days
    
    uuid=$(generate_uuid)
    exp_date=$(date -d "+${expired_days} days" +"%Y-%m-%d")
    
    # Add to Xray config
    jq --arg uuid "$uuid" '.inbounds[0].settings.clients += [{"id": $uuid, "alterId": 0}]' $XRAY_CONFIG > tmp.json
    mv tmp.json $XRAY_CONFIG
    
    # Add to user database
    echo "vmess:${username}:${uuid}:${exp_date}" >> $USER_DB
    
    systemctl restart xray
    
    clear
    echo -e "${GREEN}VMess Account Created Successfully${NC}"
    echo -e "Username: ${username}"
    echo -e "Protocol: VMess"
    echo -e "UUID: ${uuid}"
    echo -e "Expired Date: ${exp_date}"
    echo -e "Port: 8443"
    echo ""
    read -n 1 -s -r -p "Press any key to continue"
}

# Function to add VMess WebSocket user
add_vmess_ws_user() {
    clear
    echo -e "${GREEN}=== Add VMess WebSocket User ===${NC}"
    read -p "Username: " username
    read -p "Expired days: " expired_days
    read -p "SNI (hostname): " sni
    
    uuid=$(generate_uuid)
    exp_date=$(date -d "+${expired_days} days" +"%Y-%m-%d")
    
    # Add to Xray config (both TLS and non-TLS)
    jq --arg uuid "$uuid" '.inbounds[0].settings.clients += [{"id": $uuid, "alterId": 0}]' $XRAY_CONFIG > tmp.json
    mv tmp.json $XRAY_CONFIG
    jq --arg uuid "$uuid" '.inbounds[2].settings.clients += [{"id": $uuid, "alterId": 0}]' $XRAY_CONFIG > tmp.json
    mv tmp.json $XRAY_CONFIG
    
    # Add to user database
    echo "vmess-ws:${username}:${uuid}:${exp_date}:${sni}" >> $USER_DB
    
    systemctl restart xray
    
    # Generate v2ray config
    server_ip=$(curl -s ipv4.icanhazip.com)
    
    # TLS config
    tls_config=$(cat <<EOF
{
  "v": "2",
  "ps": "${username}-ws-tls",
  "add": "${server_ip}",
  "port": "443",
  "id": "${uuid}",
  "aid": "0",
  "net": "ws",
  "path": "/vmess",
  "type": "none",
  "host": "${sni}",
  "tls": "tls",
  "sni": "${sni}"
}
EOF
)
    
    # Non-TLS config
    nontls_config=$(cat <<EOF
{
  "v": "2",
  "ps": "${username}-ws",
  "add": "${server_ip}",
  "port": "80",
  "id": "${uuid}",
  "aid": "0",
  "net": "ws",
  "path": "/vmess",
  "type": "none",
  "host": "${sni}",
  "tls": "none"
}
EOF
)
    
    clear
    echo -e "${GREEN}VMess WebSocket Account Created Successfully${NC}"
    echo -e "Username: ${username}"
    echo -e "Protocol: VMess WebSocket"
    echo -e "UUID: ${uuid}"
    echo -e "Expired Date: ${exp_date}"
    echo -e "SNI: ${sni}"
    echo -e "\nTLS Configuration:"
    echo -e "vmess://$(echo $tls_config | base64 -w 0)"
    echo -e "\nNon-TLS Configuration:"
    echo -e "vmess://$(echo $nontls_config | base64 -w 0)"
    echo ""
    read -n 1 -s -r -p "Press any key to continue"
}

# Function to add VLESS user
add_vless_user() {
    clear
    echo -e "${GREEN}=== Add VLESS User ===${NC}"
    read -p "Username: " username
    read -p "Expired days: " expired_days
    
    uuid=$(generate_uuid)
    exp_date=$(date -d "+${expired_days} days" +"%Y-%m-%d")
    
    # Add to Xray config
    jq --arg uuid "$uuid" '.inbounds[1].settings.clients += [{"id": $uuid, "flow": "xtls-rprx-direct"}]' $XRAY_CONFIG > tmp.json
    mv tmp.json $XRAY_CONFIG
    
    # Add to user database
    echo "vless:${username}:${uuid}:${exp_date}" >> $USER_DB
    
    systemctl restart xray
    
    clear
    echo -e "${GREEN}VLESS Account Created Successfully${NC}"
    echo -e "Username: ${username}"
    echo -e "Protocol: VLESS"
    echo -e "UUID: ${uuid}"
    echo -e "Expired Date: ${exp_date}"
    echo -e "Port: 8442"
    echo ""
    read -n 1 -s -r -p "Press any key to continue"
}

# Function to add VLESS WebSocket user
add_vless_ws_user() {
    clear
    echo -e "${GREEN}=== Add VLESS WebSocket User ===${NC}"
    read -p "Username: " username
    read -p "Expired days: " expired_days
    read -p "SNI (hostname): " sni
    
    uuid=$(generate_uuid)
    exp_date=$(date -d "+${expired_days} days" +"%Y-%m-%d")
    
    # Add to Xray config (both TLS and non-TLS)
    jq --arg uuid "$uuid" '.inbounds[1].settings.clients += [{"id": $uuid, "flow": "xtls-rprx-direct"}]' $XRAY_CONFIG > tmp.json
    mv tmp.json $XRAY_CONFIG
    jq --arg uuid "$uuid" '.inbounds[3].settings.clients += [{"id": $uuid}]' $XRAY_CONFIG > tmp.json
    mv tmp.json $XRAY_CONFIG
    
    # Add to user database
    echo "vless-ws:${username}:${uuid}:${exp_date}:${sni}" >> $USER_DB
    
    systemctl restart xray
    
    server_ip=$(curl -s ipv4.icanhazip.com)
    
    clear
    echo -e "${GREEN}VLESS WebSocket Account Created Successfully${NC}"
    echo -e "Username: ${username}"
    echo -e "Protocol: VLESS WebSocket"
    echo -e "UUID: ${uuid}"
    echo -e "Expired Date: ${exp_date}"
    echo -e "SNI: ${sni}"
    echo -e "\nTLS Configuration:"
    echo -e "vless://${uuid}@${server_ip}:443?path=/vless&security=tls&encryption=none&host=${sni}&type=ws&sni=${sni}#${username}-ws-tls"
    echo -e "\nNon-TLS Configuration:"
    echo -e "vless://${uuid}@${server_ip}:80?path=/vless&encryption=none&host=${sni}&type=ws#${username}-ws"
    echo ""
    read -n 1 -s -r -p "Press any key to continue"
}

# Function to delete user
delete_user() {
    clear
    echo -e "${GREEN}=== Delete User ===${NC}"
    echo -e "Current users:"
    echo -e "${YELLOW}"
    cat $USER_DB | awk -F: '{print $2}'
    echo -e "${NC}"
    read -p "Enter username to delete: " username
    
    # Get user info
    user_info=$(grep ":${username}:" $USER_DB)
    if [ -z "$user_info" ]; then
        echo -e "${RED}User not found${NC}"
        return
    fi
    
    protocol=$(echo $user_info | cut -d: -f1)
    uuid=$(echo $user_info | cut -d: -f3)
    
    # Remove from Xray config
    if [ "$protocol" == "vmess" ]; then
        jq --arg uuid "$uuid" '.inbounds[0].settings.clients = [.inbounds[0].settings.clients[] | select(.id != $uuid)]' $XRAY_CONFIG > tmp.json
    else
        jq --arg uuid "$uuid" '.inbounds[1].settings.clients = [.inbounds[1].settings.clients[] | select(.id != $uuid)]' $XRAY_CONFIG > tmp.json
    fi
    mv tmp.json $XRAY_CONFIG
    
    # Remove from user database
    sed -i "/.*:${username}:/d" $USER_DB
    
    systemctl restart xray
    
    echo -e "${GREEN}User deleted successfully${NC}"
    read -n 1 -s -r -p "Press any key to continue"
}

# Function to list users
list_users() {
    clear
    echo -e "${GREEN}=== User List ===${NC}"
    echo -e "Protocol | Username | UUID | Expiry Date"
    echo -e "----------------------------------------"
    while IFS=: read -r protocol username uuid expiry; do
        echo -e "$protocol | $username | $uuid | $expiry"
    done < $USER_DB
    echo ""
    read -n 1 -s -r -p "Press any key to continue"
}

# Function to show online users
show_online_users() {
    clear
    echo -e "${GREEN}=== Online Users ===${NC}"
    netstat -anp | grep ESTABLISHED | grep xray
    echo ""
    read -n 1 -s -r -p "Press any key to continue"
}

# Function to add SSH user
add_ssh_user() {
    clear
    echo -e "${GREEN}=== Add SSH User ===${NC}"
    read -p "Username: " username
    read -p "Password: " password
    read -p "Expired days: " expired_days
    
    # Check if user exists
    if id "$username" &>/dev/null; then
        echo -e "${RED}User already exists${NC}"
        read -n 1 -s -r -p "Press any key to continue"
        return
    }
    
    # Calculate expiry date
    exp_date=$(date -d "+${expired_days} days" +"%Y-%m-%d")
    
    # Create user with password and expiry date
    useradd -e $(date -d "$exp_date" +"%Y-%m-%d") -s /bin/bash -M "$username"
    echo "$username:$password" | chpasswd
    
    # Add to user database
    echo "ssh:${username}:${password}:${exp_date}" >> $USER_DB
    
    clear
    echo -e "${GREEN}SSH Account Created Successfully${NC}"
    echo -e "Username: ${username}"
    echo -e "Password: ${password}"
    echo -e "Expired Date: ${exp_date}"
    echo -e "SSH Ports: 22, 109, 143"
    echo -e "Dropbear Ports: 443, 109, 143"
    echo -e "SSL Ports: 443, 445, 777"
    echo ""
    read -n 1 -s -r -p "Press any key to continue"
}

# Function to delete SSH user
delete_ssh_user() {
    clear
    echo -e "${GREEN}=== Delete SSH User ===${NC}"
    echo -e "Current SSH users:"
    echo -e "${YELLOW}"
    grep "^ssh:" $USER_DB | cut -d: -f2
    echo -e "${NC}"
    read -p "Enter username to delete: " username
    
    # Check if user exists
    if ! id "$username" &>/dev/null; then
        echo -e "${RED}User not found${NC}"
        read -n 1 -s -r -p "Press any key to continue"
        return
    }
    
    # Delete user from system
    userdel -f "$username"
    
    # Remove from user database
    sed -i "/^ssh:${username}:/d" $USER_DB
    
    echo -e "${GREEN}SSH user deleted successfully${NC}"
    read -n 1 -s -r -p "Press any key to continue"
}

# Function to list SSH users
list_ssh_users() {
    clear
    echo -e "${GREEN}=== SSH User List ===${NC}"
    echo -e "Username | Password | Expiry Date"
    echo -e "--------------------------------"
    grep "^ssh:" $USER_DB | while IFS=: read -r type username password expiry; do
        echo -e "$username | $password | $expiry"
    done
    echo ""
    read -n 1 -s -r -p "Press any key to continue"
}

# Function to show online SSH users
show_online_ssh_users() {
    clear
    echo -e "${GREEN}=== Online SSH Users ===${NC}"
    who | grep -v "root"
    echo ""
    read -n 1 -s -r -p "Press any key to continue"
}

# Function to check expired users and remove them
check_expired_users() {
    while IFS=: read -r protocol username _ expiry; do
        if [[ $(date -d "$expiry" +%s) -lt $(date +%s) ]]; then
            case $protocol in
                "ssh")
                    userdel -f "$username" 2>/dev/null
                    sed -i "/^ssh:${username}:/d" $USER_DB
                    ;;
                "vmess"|"vless")
                    uuid=$(grep ":${username}:" $USER_DB | cut -d: -f3)
                    if [ "$protocol" == "vmess" ]; then
                        jq --arg uuid "$uuid" '.inbounds[0].settings.clients = [.inbounds[0].settings.clients[] | select(.id != $uuid)]' $XRAY_CONFIG > tmp.json
                    else
                        jq --arg uuid "$uuid" '.inbounds[1].settings.clients = [.inbounds[1].settings.clients[] | select(.id != $uuid)]' $XRAY_CONFIG > tmp.json
                    fi
                    mv tmp.json $XRAY_CONFIG
                    sed -i "/.*:${username}:/d" $USER_DB
                    systemctl restart xray
                    ;;
            esac
        fi
    done < $USER_DB
}

# Function to install certbot
install_certbot() {
    apt-get update
    apt-get install -y certbot
}

# Function to setup domain and SSL
setup_domain() {
    clear
    echo -e "${GREEN}=== Domain Setup and SSL Configuration ===${NC}"
    read -p "Enter your domain/subdomain: " domain
    
    # Save domain to config
    echo "$domain" > /etc/vps/domain.conf
    
    # Check if domain points to server
    server_ip=$(curl -s ipv4.icanhazip.com)
    domain_ip=$(dig +short "$domain")
    
    if [ "$server_ip" != "$domain_ip" ]; then
        echo -e "${RED}Warning: Domain $domain does not point to this server ($server_ip)${NC}"
        echo -e "${RED}Please make sure your domain points to $server_ip${NC}"
        read -p "Continue anyway? (y/n): " confirm
        if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
            return
        fi
    fi
    
    # Install certbot if not installed
    if ! command -v certbot &> /dev/null; then
        echo -e "${YELLOW}Installing Certbot...${NC}"
        install_certbot
    fi
    
    # Stop services that might use port 80
    systemctl stop nginx 2>/dev/null
    systemctl stop apache2 2>/dev/null
    
    # Get SSL certificate
    echo -e "${GREEN}Obtaining SSL Certificate...${NC}"
    certbot certonly --standalone --preferred-challenges http --agree-tos --email admin@"$domain" -d "$domain"
    
    if [ $? -eq 0 ]; then
        # Update certificates for services
        cp /etc/letsencrypt/live/"$domain"/fullchain.pem /etc/stunnel/stunnel.crt
        cp /etc/letsencrypt/live/"$domain"/privkey.pem /etc/stunnel/stunnel.key
        cat /etc/stunnel/stunnel.key /etc/stunnel/stunnel.crt > /etc/stunnel/stunnel.pem
        
        # Update Xray config with new certificate
        jq --arg cert "/etc/letsencrypt/live/$domain/fullchain.pem" \
           --arg key "/etc/letsencrypt/live/$domain/privkey.pem" \
           '.inbounds[].streamSettings.tlsSettings.certificates[0].certificateFile = $cert | 
            .inbounds[].streamSettings.tlsSettings.certificates[0].keyFile = $key' \
           $XRAY_CONFIG > tmp.json && mv tmp.json $XRAY_CONFIG
        
        # Restart services
        systemctl restart stunnel4
        systemctl restart xray
        
        # Setup auto-renewal
        setup_cert_renewal
        
        echo -e "${GREEN}Domain setup and SSL configuration completed successfully!${NC}"
        echo -e "Domain: $domain"
        echo -e "Certificate will auto-renew before expiry"
    else
        echo -e "${RED}Failed to obtain SSL certificate${NC}"
    fi
    
    read -n 1 -s -r -p "Press any key to continue"
}

# Function to setup certificate auto-renewal
setup_cert_renewal() {
    local domain=$(cat /etc/vps/domain.conf)
    
    # Create renewal script
    cat > /usr/local/bin/renew-cert.sh <<EOF
#!/bin/bash
certbot renew --quiet
cp /etc/letsencrypt/live/$domain/fullchain.pem /etc/stunnel/stunnel.crt
cp /etc/letsencrypt/live/$domain/privkey.pem /etc/stunnel/stunnel.key
cat /etc/stunnel/stunnel.key /etc/stunnel/stunnel.crt > /etc/stunnel/stunnel.pem
systemctl restart stunnel4
systemctl restart xray
EOF

    chmod +x /usr/local/bin/renew-cert.sh
    
    # Add to crontab (run twice daily)
    (crontab -l 2>/dev/null; echo "0 0,12 * * * /usr/local/bin/renew-cert.sh") | crontab -
}

# Function to show domain info
show_domain_info() {
    clear
    echo -e "${GREEN}=== Domain Information ===${NC}"
    
    if [ -f /etc/vps/domain.conf ]; then
        domain=$(cat /etc/vps/domain.conf)
        echo -e "Current domain: $domain"
        
        # Check SSL certificate
        if [ -d "/etc/letsencrypt/live/$domain" ]; then
            echo -e "\nSSL Certificate Information:"
            certbot certificates | grep -A 2 "$domain"
        else
            echo -e "\n${RED}No SSL certificate found${NC}"
        fi
    else
        echo -e "${RED}No domain configured${NC}"
    fi
    
    read -n 1 -s -r -p "Press any key to continue"
}

# Function to add OpenVPN user
add_ovpn_user() {
    clear
    echo -e "${GREEN}=== Add OpenVPN User ===${NC}"
    read -p "Username: " username
    read -p "Password: " password
    read -p "Expired days: " expired_days
    
    # Calculate expiry date
    exp_date=$(date -d "+${expired_days} days" +"%Y-%m-%d")
    
    # Add to user database
    echo "ovpn:${username}:${password}:${exp_date}" >> $USER_DB
    
    # Generate client config
    cat > "/etc/openvpn/client-configs/${username}.ovpn" <<EOF
client
dev tun
proto udp
remote $(curl -s ipv4.icanhazip.com) 1194
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
cipher AES-256-CBC
auth SHA256
comp-lzo
verb 3
auth-user-pass
EOF

    # Add the CA certificate to the client config
    echo "<ca>" >> "/etc/openvpn/client-configs/${username}.ovpn"
    cat "/etc/openvpn/ca.crt" >> "/etc/openvpn/client-configs/${username}.ovpn"
    echo "</ca>" >> "/etc/openvpn/client-configs/${username}.ovpn"
    
    # Add the TLS key to the client config
    echo "<tls-auth>" >> "/etc/openvpn/client-configs/${username}.ovpn"
    cat "/etc/openvpn/ta.key" >> "/etc/openvpn/client-configs/${username}.ovpn"
    echo "</tls-auth>" >> "/etc/openvpn/client-configs/${username}.ovpn"
    echo "key-direction 1" >> "/etc/openvpn/client-configs/${username}.ovpn"
    
    clear
    echo -e "${GREEN}OpenVPN Account Created Successfully${NC}"
    echo -e "Username: ${username}"
    echo -e "Password: ${password}"
    echo -e "Expired Date: ${exp_date}"
    echo -e "Config File: /etc/openvpn/client-configs/${username}.ovpn"
    echo -e "Port: 1194 (UDP)"
    echo ""
    read -n 1 -s -r -p "Press any key to continue"
}

# Function to delete OpenVPN user
delete_ovpn_user() {
    clear
    echo -e "${GREEN}=== Delete OpenVPN User ===${NC}"
    echo -e "Current OpenVPN users:"
    echo -e "${YELLOW}"
    grep "^ovpn:" $USER_DB | cut -d: -f2
    echo -e "${NC}"
    read -p "Enter username to delete: " username
    
    # Remove from user database
    sed -i "/^ovpn:${username}:/d" $USER_DB
    
    # Remove client config
    rm -f "/etc/openvpn/client-configs/${username}.ovpn"
    
    echo -e "${GREEN}OpenVPN user deleted successfully${NC}"
    read -n 1 -s -r -p "Press any key to continue"
}

# Function to add WebSocket SSH user
add_ws_ssh_user() {
    clear
    echo -e "${GREEN}=== Add WebSocket SSH User ===${NC}"
    read -p "Username: " username
    read -p "Password: " password
    read -p "Expired days: " expired_days
    read -p "SNI (hostname): " sni
    
    # Calculate expiry date
    exp_date=$(date -d "+${expired_days} days" +"%Y-%m-%d")
    
    # Create user with password and expiry date
    useradd -e $(date -d "$exp_date" +"%Y-%m-%d") -s /bin/bash -M "$username"
    echo "$username:$password" | chpasswd
    
    # Add to user database
    echo "ws-ssh:${username}:${password}:${exp_date}:${sni}" >> $USER_DB
    
    # Get server IP
    server_ip=$(curl -s ipv4.icanhazip.com)
    
    clear
    echo -e "${GREEN}WebSocket SSH Account Created Successfully${NC}"
    echo -e "Username: ${username}"
    echo -e "Password: ${password}"
    echo -e "Expired Date: ${exp_date}"
    echo -e "SNI: ${sni}"
    echo -e "\nWebSocket Configuration:"
    echo -e "Host: ${server_ip}"
    echo -e "Port: 80"
    echo -e "Path: /ssh-ws"
    echo -e "TLS: No"
    echo ""
    read -n 1 -s -r -p "Press any key to continue"
}

# Check expired users every time menu is opened
check_expired_users

# Main menu
while true; do
    clear
    echo -e "${GREEN}=== VPS Management Menu ===${NC}"
    echo -e "${YELLOW}Domain Management${NC}"
    echo -e "1) Setup Domain & SSL"
    echo -e "2) Show Domain Info"
    echo -e ""
    echo -e "${YELLOW}SSH Management${NC}"
    echo -e "3) Add SSH User"
    echo -e "4) Delete SSH User"
    echo -e "5) List SSH Users"
    echo -e "6) Show Online SSH Users"
    echo -e ""
    echo -e "${YELLOW}OpenVPN Management${NC}"
    echo -e "7) Add OpenVPN User"
    echo -e "8) Delete OpenVPN User"
    echo -e ""
    echo -e "${YELLOW}Xray Management${NC}"
    echo -e "9) Add VMess User"
    echo -e "10) Add VLESS User"
    echo -e "11) Delete User"
    echo -e "12) List All Users"
    echo -e "13) Show Online Users"
    echo -e "${YELLOW}WebSocket Management${NC}"
    echo -e "14) Add VMess WebSocket User"
    echo -e "15) Add VLESS WebSocket User"
    echo -e "16) Add SSH WebSocket User"
    echo -e "17) Exit"
    read -p "Select an option: " choice
    
    case $choice in
        1) setup_domain ;;
        2) show_domain_info ;;
        3) add_ssh_user ;;
        4) delete_ssh_user ;;
        5) list_ssh_users ;;
        6) show_online_ssh_users ;;
        7) add_ovpn_user ;;
        8) delete_ovpn_user ;;
        9) add_vmess_user ;;
        10) add_vless_user ;;
        11) delete_user ;;
        12) list_users ;;
        13) show_online_users ;;
        14) add_vmess_ws_user ;;
        15) add_vless_ws_user ;;
        16) add_ws_ssh_user ;;
        17) break ;;
        *) echo -e "${RED}Invalid option${NC}" ;;
    esac
done 