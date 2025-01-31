#!/bin/bash

# Load configuration
if [ -f "/etc/vps/telegram.conf" ]; then
    source /etc/vps/telegram.conf
else
    echo "Error: Telegram configuration not found"
    exit 1
fi

API_URL="https://api.telegram.org/bot$BOT_TOKEN"

# Function to send message
send_message() {
    local chat_id=$1
    local text=$2
    curl -s -X POST "$API_URL/sendMessage" -d "chat_id=$chat_id" -d "text=$text" -d "parse_mode=HTML"
}

# Function to add new user
add_user() {
    local chat_id=$1
    local username=$2
    local password=$3
    local duration=$4
    
    if [ -z "$username" ] || [ -z "$password" ] || [ -z "$duration" ]; then
        send_message "$chat_id" "❌ Usage: /adduser <username> <password> <duration>\n\nExample: /adduser john pass123 30"
        return 1
    fi
    
    # Add user using your existing script
    useradd -e $(date -d "+$duration days" +"%Y-%m-%d") -s /bin/false -M $username
    echo "$username:$password" | chpasswd
    
    send_message "$chat_id" "✅ Account Created Successfully\n\n👤 Username: $username\n🔑 Password: $password\n⏱ Duration: $duration days\n\n🌐 Server Details:\nIP: $(curl -s ipv4.icanhazip.com)\nDomain: $(cat /etc/vps/domain.conf 2>/dev/null || echo 'Not Set')"
}

# Function to remove user
remove_user() {
    local chat_id=$1
    local username=$2
    
    if [ -z "$username" ]; then
        send_message "$chat_id" "❌ Usage: /removeuser <username>\n\nExample: /removeuser john"
        return 1
    fi
    
    if id "$username" &>/dev/null; then
        userdel -r $username 2>/dev/null
        send_message "$chat_id" "✅ User $username has been removed successfully"
    else
        send_message "$chat_id" "❌ User $username does not exist"
    fi
}

# Function to check user status
check_user_status() {
    local chat_id=$1
    local username=$2
    
    if [ -z "$username" ]; then
        send_message "$chat_id" "❌ Usage: /status <username>\n\nExample: /status john"
        return 1
    fi
    
    if id "$username" &>/dev/null; then
        local expiry=$(chage -l $username | grep "Account expires" | cut -d: -f2)
        local status="🟢 Active"
        
        if [ $(date -d "$expiry" +%s) -lt $(date +%s) ]; then
            status="🔴 Expired"
        fi
        
        send_message "$chat_id" "📊 Account Status\n\n👤 Username: $username\n📅 Expiry: $expiry\n📊 Status: $status"
    else
        send_message "$chat_id" "❌ User $username does not exist"
    fi
}

# Function to get server status
server_status() {
    local chat_id=$1
    
    local cpu_load=$(cat /proc/loadavg | awk '{print $1}')
    local memory=$(free -m | grep Mem | awk '{printf("%.2f%%", $3/$2*100)}')
    local disk=$(df -h / | awk 'NR==2 {print $5}')
    local uptime=$(uptime -p)
    
    send_message "$chat_id" "🖥 Server Status\n\n📊 CPU Load: $cpu_load\n💾 Memory Usage: $memory\n💿 Disk Usage: $disk\n⏰ Uptime: $uptime\n\n🌐 Server Info:\nIP: $(curl -s ipv4.icanhazip.com)\nDomain: $(cat /etc/vps/domain.conf 2>/dev/null || echo 'Not Set')"
}

# Function to show help message
show_help() {
    local chat_id=$1
    send_message "$chat_id" "👋 Welcome to VPS Management Bot!\n\n📝 Available Commands:\n\n/adduser - Create new account\nFormat: /adduser username password days\n\n/removeuser - Delete account\nFormat: /removeuser username\n\n/status - Check account status\nFormat: /status username\n\n/server - View server status\n\n💡 Need help? Contact @faizvpn"
}

# Main bot loop
process_message() {
    local chat_id=$1
    local message=$2
    
    case $message in
        "/start"|"/help")
            show_help "$chat_id"
            ;;
        "/adduser "*)
            local params=(${message#"/adduser "})
            if [ ${#params[@]} -eq 3 ]; then
                add_user "$chat_id" "${params[0]}" "${params[1]}" "${params[2]}"
            else
                send_message "$chat_id" "❌ Usage: /adduser <username> <password> <duration>\n\nExample: /adduser john pass123 30"
            fi
            ;;
        "/removeuser "*)
            local username=${message#"/removeuser "}
            remove_user "$chat_id" "$username"
            ;;
        "/status "*)
            local username=${message#"/status "}
            check_user_status "$chat_id" "$username"
            ;;
        "/server")
            server_status "$chat_id"
            ;;
        *)
            send_message "$chat_id" "❌ Unknown command\n\n📝 Available Commands:\n/start - Show menu\n/adduser - Create account\n/removeuser - Delete account\n/status - Check account\n/server - Server status\n\n💡 Need help? Contact @faizvpn"
            ;;
    esac
}

# Start webhook or polling
if [ "$1" = "webhook" ]; then
    curl -F "url=https://your-domain.com/webhook" "$API_URL/setWebhook"
else
    offset=0
    while true; do
        updates=$(curl -s "$API_URL/getUpdates?offset=$offset&timeout=60")
        
        for update in $(echo "$updates" | jq -r '.result[] | @base64'); do
            update_data=$(echo $update | base64 -d)
            chat_id=$(echo $update_data | jq -r '.message.chat.id')
            message=$(echo $update_data | jq -r '.message.text')
            update_id=$(echo $update_data | jq -r '.update_id')
            
            process_message "$chat_id" "$message"
            offset=$((update_id + 1))
        done
        
        sleep 1
    done
fi