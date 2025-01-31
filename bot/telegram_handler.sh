#!/bin/bash

BOT_TOKEN="7536534477:AAEVbj_rJwGjYhpGUCHCDZjUnZXfbn2fL9o"
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
    
    send_message "$chat_id" "✅ User created successfully!\n\nUsername: $username\nPassword: $password\nDuration: $duration days"
}

# Function to remove user
remove_user() {
    local chat_id=$1
    local username=$2
    
    userdel -r $username 2>/dev/null
    send_message "$chat_id" "✅ User $username has been removed"
}

# Function to check user status
check_user_status() {
    local chat_id=$1
    local username=$2
    
    local expiry=$(chage -l $username | grep "Account expires" | cut -d: -f2)
    local status="Active"
    
    if [ $(date -d "$expiry" +%s) -lt $(date +%s) ]; then
        status="Expired"
    fi
    
    send_message "$chat_id" "👤 User: $username\n📅 Expiry: $expiry\n📊 Status: $status"
}

# Function to get server status
server_status() {
    local chat_id=$1
    
    local cpu_load=$(cat /proc/loadavg | awk '{print $1}')
    local memory=$(free -m | grep Mem | awk '{printf("%.2f%%", $3/$2*100)}')
    local disk=$(df -h / | awk 'NR==2 {print $5}')
    
    send_message "$chat_id" "🖥 Server Status\n\n📊 CPU Load: $cpu_load\n💾 Memory Usage: $memory\n💿 Disk Usage: $disk"
}

# Main bot loop
process_message() {
    local chat_id=$1
    local message=$2
    
    case $message in
        "/start")
            send_message "$chat_id" "Welcome to FAIZ-VPN Management Bot!\n\nAvailable Commands:\n\n/adduser <username> <password> <duration> - Add new user\n/removeuser <username> - Remove user\n/status <username> - Check user status\n/server - Check server status"
            ;;
        "/adduser")
            send_message "$chat_id" "❌ Usage: /adduser <username> <password> <duration>\n\nExample: /adduser john pass123 30"
            ;;
        "/adduser "*)
            local params=(${message#"/adduser "})
            if [ ${#params[@]} -eq 3 ]; then
                add_user "$chat_id" "${params[0]}" "${params[1]}" "${params[2]}"
            else
                send_message "$chat_id" "❌ Usage: /adduser <username> <password> <duration>\n\nExample: /adduser john pass123 30"
            fi
            ;;
        "/removeuser")
            send_message "$chat_id" "❌ Usage: /removeuser <username>\n\nExample: /removeuser john"
            ;;
        "/removeuser "*)
            local username=${message#"/removeuser "}
            remove_user "$chat_id" "$username"
            ;;
        "/status")
            send_message "$chat_id" "❌ Usage: /status <username>\n\nExample: /status john"
            ;;
        "/status "*)
            local username=${message#"/status "}
            check_user_status "$chat_id" "$username"
            ;;
        "/server")
            server_status "$chat_id"
            ;;
        *)
            send_message "$chat_id" "❌ Unknown command.\n\nAvailable Commands:\n/start - Show all commands\n/adduser - Add new user\n/removeuser - Remove user\n/status - Check user status\n/server - Check server status"
            ;;
    esac
}

# Start webhook or polling
if [ "$1" = "webhook" ]; then
    # Setup webhook (if you want to use webhook instead of polling)
    curl -F "url=https://your-domain.com/webhook" "$API_URL/setWebhook"
else
    # Use polling
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