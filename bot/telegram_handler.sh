#!/bin/bash

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Configuration files
USER_DB="/etc/vps/users.db"
BOT_CONFIG="/etc/vps/telegram.conf"

# Load bot configuration
source $BOT_CONFIG

# Add these variables for conversation state
declare -A USER_STATES
declare -A TEMP_DATA

# Add these at the start of the file
LOG_FILE="/var/log/telegram-bot.log"

log_debug() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE"
}

# Function to create SSH account
create_account() {
    local chat_id=$1
    local username=$2
    local password=$3
    local duration=$4

    # Check if user exists
    if id "$username" &>/dev/null; then
        send_message "$chat_id" "❌ Error: User already exists"
        return 1
    fi

    # Calculate expiry date
    exp_date=$(date -d "+${duration} days" +"%Y-%m-%d")
    
    # Create user
    useradd -e $(date -d "$exp_date" +"%Y-%m-%d") -s /bin/false -M "$username"
    echo "$username:$password" | chpasswd

    # Add to database
    echo "ssh:${username}:${password}:${exp_date}" >> $USER_DB

    # Get server IP and domain
    server_ip=$(curl -s ipv4.icanhazip.com)
    domain=$(cat /etc/vps/domain.conf 2>/dev/null || echo "Not Set")

    # Format the success message
    message="━━━━━━━━━━━━━━━━━━━━━\n"
    message+="       🚀 𝙁𝘼𝙄𝙕-𝙑𝙋𝙉 𝙈𝘼𝙉𝘼𝙂𝙀𝙍\n"
    message+="     ━━━━━━━━━━━━━━━━━━━━━\n\n"
    message+="✅ 𝘼𝙘𝙘𝙤𝙪𝙣𝙩 𝘾𝙧𝙚𝙖𝙩𝙚𝙙 𝙎𝙪𝙘𝙘𝙚𝙨𝙨𝙛𝙪𝙡𝙡𝙮!\n\n"
    message+="👤 𝙐𝙨𝙚𝙧𝙣𝙖𝙢𝙚: $username\n"
    message+="🔑 𝙋𝙖𝙨𝙨𝙬𝙤𝙧𝙙: $password\n"
    message+="⏱ 𝘿𝙪𝙧𝙖𝙩𝙞𝙤𝙣: $duration days\n"
    message+="📅 𝙀𝙭𝙥𝙞𝙧𝙮: $exp_date\n\n"
    message+="🌐 𝙎𝙚𝙧𝙫𝙚𝙧 𝘿𝙚𝙩𝙖𝙞𝙡𝙨:\n"
    message+="📍 𝙄𝙋: $server_ip\n"
    message+="🔗 𝘿𝙤𝙢𝙖𝙞𝙣: $domain\n\n"
    message+="🔰 𝙐𝘿𝙋 𝘾𝙪𝙨𝙩𝙤𝙢: $server_ip:1-65535@$username:$password\n\n"
    message+="💎 𝙎𝙚𝙧𝙫𝙞𝙘𝙚𝙨:\n"
    message+="• SSL/TLS : 443\n"
    message+="• Websocket SSL : 443\n"
    message+="• Websocket HTTP : 80\n"
    message+="• UDP Custom : 1-65535\n\n"
    message+=" 💡 𝙎𝙪𝙥𝙥𝙤𝙧𝙩: @faizvpn\n"
    message+="━━━━━━━━━━━━━━━━━━━━━"
    
    send_message "$chat_id" "$message"
}

# Function to create VLESS account
create_vless() {
    local chat_id=$1
    local username=$2
    local duration=$3

    # Generate UUID
    uuid=$(uuidgen)
    
    # Calculate expiry date
    exp_date=$(date -d "+${duration} days" +"%Y-%m-%d")
    
    # Add to Xray config
    # ... (add your VLESS configuration logic here)
    
    # Get server IP/domain
    domain=$(cat /etc/vps/domain.conf 2>/dev/null || curl -s ipv4.icanhazip.com)
    
    message="✅ VLESS Account Created\n\n"
    message+="Username: $username\n"
    message+="UUID: $uuid\n"
    message+="Expired Date: $exp_date\n"
    message+="Domain: $domain\n"
    message+="Port: 8443\n"
    message+="Security: TLS\n"
    
    send_message "$chat_id" "$message"
}

# Function to create VMess account
create_vmess() {
    local chat_id=$1
    local username=$2
    local duration=$3

    # Generate UUID
    uuid=$(uuidgen)
    
    # Calculate expiry date
    exp_date=$(date -d "+${duration} days" +"%Y-%m-%d")
    
    # Add to Xray config
    # ... (add your VMess configuration logic here)
    
    # Get server IP/domain
    domain=$(cat /etc/vps/domain.conf 2>/dev/null || curl -s ipv4.icanhazip.com)
    
    message="✅ VMess Account Created\n\n"
    message+="Username: $username\n"
    message+="UUID: $uuid\n"
    message+="Expired Date: $exp_date\n"
    message+="Domain: $domain\n"
    message+="Port: 8443\n"
    message+="Security: TLS\n"
    
    send_message "$chat_id" "$message"
}

# Function to delete user
delete_user() {
    local chat_id=$1
    local username=$2

    if ! grep -q "^ssh:$username:" $USER_DB; then
        send_message "$chat_id" "❌ Error: User not found"
        return 1
    fi

    userdel -f "$username"
    sed -i "/^ssh:$username:/d" $USER_DB
    
    send_message "$chat_id" "✅ User $username has been deleted"
}

# Function to check server status
check_status() {
    local chat_id=$1
    
    # Get system information
    cpu_load=$(top -bn1 | grep "Cpu(s)" | awk '{print $2 + $4}')
    memory_usage=$(free -m | awk 'NR==2{printf "%.2f%%", $3*100/$2}')
    disk_usage=$(df -h / | awk 'NR==2{print $5}')
    uptime=$(uptime -p)
    
    message="📊 Server Status\n\n"
    message+="CPU Usage: $cpu_load%\n"
    message+="Memory Usage: $memory_usage\n"
    message+="Disk Usage: $disk_usage\n"
    message+="Uptime: $uptime\n\n"
    message+="🔰 Service Status:\n"
    message+="SSH: $(systemctl is-active ssh)\n"
    message+="Dropbear: $(systemctl is-active dropbear)\n"
    message+="Stunnel4: $(systemctl is-active stunnel4)\n"
    message+="Xray: $(systemctl is-active xray)\n"
    
    send_message "$chat_id" "$message"
}

# Function to send message
send_message() {
    local chat_id=$1
    local message=$2
    curl -s -X POST "https://api.telegram.org/bot$BOT_TOKEN/sendMessage" \
        -d chat_id="$chat_id" \
        -d text="$message" \
        -d parse_mode="HTML"
}

# Function to handle conversation flow
handle_conversation() {
    local chat_id=$1
    local message=$2
    local state=${USER_STATES[$chat_id]}

    # Ignore commands during conversation
    if [[ "$message" == /* ]]; then
        send_message "$chat_id" "❌ Please complete the current process first or type 'cancel' to abort"
        return
    fi

    # Allow canceling the process
    if [[ "${message,,}" == "cancel" ]]; then
        unset USER_STATES[$chat_id]
        unset TEMP_DATA["${chat_id}_username"]
        unset TEMP_DATA["${chat_id}_password"]
        send_message "$chat_id" "✅ Process cancelled"
        return
    }

    case $state in
        "WAITING_USERNAME")
            # Validate username
            if [[ ! $message =~ ^[a-zA-Z0-9_]+$ ]]; then
                send_message "$chat_id" "❌ Invalid username. Use only letters, numbers and underscore"
                return
            fi
            TEMP_DATA["${chat_id}_username"]=$message
            USER_STATES[$chat_id]="WAITING_PASSWORD"
            send_message "$chat_id" "𝙎𝙚𝙣𝙙 𝙋𝙖𝙨𝙨 :"
            ;;
        "WAITING_PASSWORD")
            # Validate password
            if [[ ${#message} -lt 6 ]]; then
                send_message "$chat_id" "❌ Password must be at least 6 characters"
                return
            fi
            TEMP_DATA["${chat_id}_password"]=$message
            USER_STATES[$chat_id]="WAITING_DURATION"
            send_message "$chat_id" "𝙎𝙚𝙣𝙙 𝘿𝙪𝙧𝙖𝙩𝙞𝙤𝙣 (𝘿𝙖𝙮𝙨) :"
            ;;
        "WAITING_DURATION")
            # Validate duration
            if ! [[ "$message" =~ ^[0-9]+$ ]] || [ "$message" -lt 1 ] || [ "$message" -gt 30 ]; then
                send_message "$chat_id" "❌ Invalid duration. Please enter a number between 1-30"
                return
            fi
            
            # Create account with collected data
            create_account "$chat_id" "${TEMP_DATA["${chat_id}_username"]}" "${TEMP_DATA["${chat_id}_password"]}" "$message"
            
            # Clear conversation state
            unset USER_STATES[$chat_id]
            unset TEMP_DATA["${chat_id}_username"]
            unset TEMP_DATA["${chat_id}_password"]
            ;;
    esac
}

# Update the handle_command function
handle_command() {
    local chat_id=$1
    local command=$2
    local message=$3
    
    # Check if user is in conversation
    if [ -n "${USER_STATES[$chat_id]}" ]; then
        handle_conversation "$chat_id" "$message"
        return
    }
    
    case $command in
        "/start" | "/help")
            message="⚡ 𝙁𝘼𝙄𝙕-𝙑𝙋𝙉 ⚡\n"
            message+="      𝙎𝙀𝙍𝙑𝙀𝙍 𝙋𝙍𝙀𝙈𝙄𝙐𝙈\n\n"
            message+="    👋 𝙒𝙀𝙇𝘾𝙊𝙈𝙀 𝙏𝙊 𝙁𝘼𝙄𝙕-𝙑𝙋𝙉\n\n"
            message+="      📝 𝘾𝙊𝙈𝙈𝘼𝙉𝘿 𝙇𝙄𝙎𝙏 :\n\n"
            message+="          ⚡ /create\n"
            message+="     𝘾𝙧𝙚𝙖𝙩𝙚 𝙉𝙚𝙬 𝘼𝙘𝙘𝙤𝙪𝙣𝙩\n\n"
            message+="          🌐 /vless\n"
            message+="       𝘾𝙧𝙚𝙖𝙩𝙚 𝙑𝙇𝙀𝙎𝙎 𝘼𝙘𝙘𝙤𝙪𝙣𝙩\n\n"
            message+="          🌐 /vmess\n"
            message+="       𝘾𝙧𝙚𝙖𝙩𝙚 𝙑𝙈𝙚𝙨𝙨 𝘼𝙘𝙘𝙤𝙪𝙣𝙩\n\n"
            message+="          🗑️ /delete\n"
            message+="       𝙍𝙚𝙢𝙤𝙫𝙚 𝙐𝙨𝙚𝙧\n\n"
            message+="          📊 /status\n"
            message+="       𝙎𝙚𝙧𝙫𝙚𝙧 𝙎𝙩𝙖𝙩𝙪𝙨\n\n"
            message+="          🔄 /restart\n"
            message+="      𝙍𝙚𝙨𝙩𝙖𝙧𝙩 𝘼𝙡𝙡 𝙎𝙚𝙧𝙫𝙞𝙘𝙚𝙨\n\n"
            message+="          🔌 /reboot\n"
            message+="        𝙍𝙚𝙗𝙤𝙤𝙩 𝙎𝙚𝙧𝙫𝙚𝙧\n\n"
            message+="      💫 𝙎𝙪𝙥𝙥𝙤𝙧𝙩: @faizvpn"
            send_message "$chat_id" "$message"
            ;;
        "/create")
            USER_STATES[$chat_id]="WAITING_USERNAME"
            send_message "$chat_id" "𝙎𝙚𝙣𝙙 𝙐𝙨𝙚𝙧 :"
            ;;
        "/vless")
            if [ ${#args[@]} -eq 0 ]; then
                message="🌐 Create VLESS Account\n\n"
                message+="Usage: /vless username days\n\n"
                message+="Example:\n"
                message+="/vless test123 30"
                send_message "$chat_id" "$message"
                return
            elif [ ${#args[@]} -ne 2 ]; then
                send_message "$chat_id" "❌ Error: Wrong format\n\nUsage: /vless username days\nExample: /vless test123 30"
                return 1
            fi
            create_vless "$chat_id" "${args[0]}" "${args[1]}"
            ;;
        "/vmess")
            if [ ${#args[@]} -eq 0 ]; then
                message="🌐 Create VMess Account\n\n"
                message+="Usage: /vmess username days\n\n"
                message+="Example:\n"
                message+="/vmess test123 30"
                send_message "$chat_id" "$message"
                return
            elif [ ${#args[@]} -ne 2 ]; then
                send_message "$chat_id" "❌ Error: Wrong format\n\nUsage: /vmess username days\nExample: /vmess test123 30"
                return 1
            fi
            create_vmess "$chat_id" "${args[0]}" "${args[1]}"
            ;;
        "/delete")
            if [ ${#args[@]} -eq 0 ]; then
                message="🗑️ Delete User Account\n\n"
                message+="Usage: /delete username\n\n"
                message+="Example:\n"
                message+="/delete test123"
                send_message "$chat_id" "$message"
                return
            elif [ ${#args[@]} -ne 1 ]; then
                send_message "$chat_id" "❌ Error: Wrong format\n\nUsage: /delete username\nExample: /delete test123"
                return 1
            fi
            delete_user "$chat_id" "${args[0]}"
            ;;
        "/status")
            check_status "$chat_id"
            ;;
        "/restart")
            systemctl restart ssh dropbear stunnel4 xray
            send_message "$chat_id" "✅ All services have been restarted"
            ;;
        "/reboot")
            send_message "$chat_id" "🔄 Server is rebooting..."
            reboot
            ;;
        *)
            send_message "$chat_id" "❌ Unknown command. Use /help to see available commands."
            ;;
    esac
}

# Update the main loop with logging
while true; do
    log_debug "Getting updates with offset $offset"
    updates=$(curl -s "$API_URL/getUpdates?offset=$offset&timeout=60")
    
    if ! echo "$updates" | jq -e '.result' >/dev/null 2>&1; then
        log_debug "Error: Invalid updates response"
        log_debug "Response: $updates"
        sleep 5
        continue
    fi
    
    # Process updates with logging
    while read -r update; do
        if [ -n "$update" ]; then
            log_debug "Processing update: $update"
            chat_id=$(echo "$update" | jq -r '.message.chat.id')
            message=$(echo "$update" | jq -r '.message.text')
            update_id=$(echo "$update" | jq -r '.update_id')
            
            log_debug "Chat ID: $chat_id, Message: $message"
            
            if [ -n "$message" ] && [ "$message" != "null" ]; then
                process_message "$chat_id" "$message"
            fi
            
            offset=$((update_id + 1))
            log_debug "New offset: $offset"
        fi
    done < <(echo "$updates" | jq -c '.result[]')
    
    sleep 1
done