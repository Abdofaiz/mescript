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
    read -p "Select menu [1-23]: " choice

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
        *)
            echo -e "${RED}Please enter a number between 1 and 23${NC}"
            press_enter
            ;;
    esac
done 