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

# Function to generate random UUID
generate_uuid() {
    uuidgen
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
        read -n 1 -s -r -p "Press any key to continue"
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
    
    read -n 1 -s -r -p "Press any key to continue"
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

# Main menu
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
    read -p "Select menu: " choice

    case $choice in
        1) create_ssh_ovpn ;;
        2) delete_ssh_ovpn ;;
        3) extend_ssh_ovpn ;;
        4) check_ssh_ovpn ;;
        5) echo "Creating VMess Account..." ;;
        6) echo "Deleting VMess Account..." ;;
        7) echo "Extending VMess Account..." ;;
        8) echo "Checking VMess Users..." ;;
        9) echo "Creating VLess Account..." ;;
        10) echo "Deleting VLess Account..." ;;
        11) echo "Extending VLess Account..." ;;
        12) echo "Checking VLess Users..." ;;
        13) echo "Creating WebSocket Account..." ;;
        14) echo "Deleting WebSocket Account..." ;;
        15) echo "Extending WebSocket Account..." ;;
        16) echo "Checking WebSocket Users..." ;;
        17) echo "Adding/Changing Domain..." ;;
        18) echo "Changing Port Services..." ;;
        19) 
            clear
            echo -e "${GREEN}=== System Status ===${NC}"
            echo -e "CPU Usage: $(top -bn1 | grep "Cpu(s)" | awk '{print $2 + $4}')%"
            echo -e "Memory Usage: $(free -m | awk 'NR==2{printf "%.2f%%", $3*100/$2}')"
            echo -e "Disk Usage: $(df -h / | awk 'NR==2{print $5}')"
            echo ""
            read -n 1 -s -r -p "Press any key to continue"
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
            echo ""
            read -n 1 -s -r -p "Press any key to continue"
            ;;
        21)
            clear
            echo -e "${GREEN}=== Memory Usage ===${NC}"
            free -h
            echo ""
            read -n 1 -s -r -p "Press any key to continue"
            ;;
        22)
            read -p "Are you sure you want to reboot? [y/n]: " answer
            if [ "$answer" == "y" ]; then
                reboot
            fi
            ;;
        23) exit 0 ;;
        *) echo -e "${RED}Invalid option${NC}" ;;
    esac
done 