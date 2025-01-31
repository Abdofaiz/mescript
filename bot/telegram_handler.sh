#!/bin/bash

# Load configuration
if [ -f "/etc/vps/telegram.conf" ]; then
    source /etc/vps/telegram.conf
else
    echo "Error: Telegram configuration not found"
    exit 1
fi

API_URL="https://api.telegram.org/bot$BOT_TOKEN"

# Store user creation state
declare -A user_states
declare -A user_data

# Function to send message
send_message() {
    local chat_id=$1
    local text=$2
    curl -s -X POST "$API_URL/sendMessage" -d "chat_id=$chat_id" -d "text=$text" -d "parse_mode=HTML"
}

# Function to create user
create_user() {
    local chat_id=$1
    local username=$2
    local password=$3
    
    # Add user
    useradd -e $(date -d "+30 days" +"%Y-%m-%d") -s /bin/false -M $username
    echo "$username:$password" | chpasswd
    
    send_message "$chat_id" "\
━━━━━━━━━━━━━━━━━━━━━
       🚀 𝙁𝘼𝙄𝙕-𝙑𝙋𝙉 𝙈𝘼𝙉𝘼𝙂𝙀𝙍
━━━━━━━━━━━━━━━━━━━━━

✅ 𝘼𝙘𝙘𝙤𝙪𝙣𝙩 𝘾𝙧𝙚𝙖𝙩𝙚𝙙 𝙎𝙪𝙘𝙘𝙚𝙨𝙨𝙛𝙪𝙡𝙡𝙮!

👤 𝙐𝙨𝙚𝙧𝙣𝙖𝙢𝙚: $username
🔑 𝙋𝙖𝙨𝙨𝙬𝙤𝙧𝙙: $password
⏱ 𝘿𝙪𝙧𝙖𝙩𝙞𝙤𝙣: 30 days

🌐 𝙎𝙚𝙧𝙫𝙚𝙧 𝘿𝙚𝙩𝙖𝙞𝙡𝙨:
📍 𝙄𝙋: $(curl -s ipv4.icanhazip.com)
🔗 𝘿𝙤𝙢𝙖𝙞𝙣: $(cat /etc/vps/domain.conf 2>/dev/null || echo 'Not Set')
📅 𝙀𝙭𝙥𝙞𝙧𝙮: $(date -d "+30 days" +"%Y-%m-%d")

💡 𝙎𝙪𝙥𝙥𝙤𝙧𝙩: @faizvpn
━━━━━━━━━━━━━━━━━━━━━"
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
    send_message "$chat_id" "\
━━━━━━━━━━━━━━━━━━━━━
       🚀 𝙁𝘼𝙄𝙕-𝙑𝙋𝙉 𝙈𝘼𝙉𝘼𝙂𝙀𝙍
━━━━━━━━━━━━━━━━━━━━━

👋 𝙒𝙚𝙡𝙘𝙤𝙢𝙚!

📝 𝘾𝙤𝙢𝙢𝙖𝙣𝙙𝙨:
/create - 𝘾𝙧𝙚𝙖𝙩𝙚 𝙣𝙚𝙬 𝙪𝙨𝙚𝙧
/status - 𝘾𝙝𝙚𝙘𝙠 𝙨𝙩𝙖𝙩𝙪𝙨
/server - 𝙎𝙚𝙧𝙫𝙚𝙧 𝙞𝙣𝙛𝙤

💡 𝙎𝙪𝙥𝙥𝙤𝙧𝙩: @faizvpn
━━━━━━━━━━━━━━━━━━━━━"
}

# Process messages
process_message() {
    local chat_id=$1
    local message=$2
    
    # Get current state
    local state=${user_states[$chat_id]:-"none"}
    
    case $state in
        "none")
            case $message in
                "/create")
                    user_states[$chat_id]="waiting_username"
                    send_message "$chat_id" "𝙎𝙚𝙣𝙙 𝙐𝙨𝙚𝙧 :"
                    ;;
                "/start")
                    send_message "$chat_id" "\
━━━━━━━━━━━━━━━━━━━━━
       🚀 𝙁𝘼𝙄𝙕-𝙑𝙋𝙉 𝙈𝘼𝙉𝘼𝙂𝙀𝙍
━━━━━━━━━━━━━━━━━━━━━

👋 𝙒𝙚𝙡𝙘𝙤𝙢𝙚!

📝 𝘾𝙤𝙢𝙢𝙖𝙣𝙙𝙨:
/create - 𝘾𝙧𝙚𝙖𝙩𝙚 𝙣𝙚𝙬 𝙪𝙨𝙚𝙧
/status - 𝘾𝙝𝙚𝙘𝙠 𝙨𝙩𝙖𝙩𝙪𝙨
/server - 𝙎𝙚𝙧𝙫𝙚𝙧 𝙞𝙣𝙛𝙤

💡 𝙎𝙪𝙥𝙥𝙤𝙧𝙩: @faizvpn
━━━━━━━━━━━━━━━━━━━━━"
                    ;;
                *)
                    send_message "$chat_id" "𝙐𝙨𝙚 /create 𝙩𝙤 𝙘𝙧𝙚𝙖𝙩𝙚 𝙣𝙚𝙬 𝙪𝙨𝙚𝙧"
                    ;;
            esac
            ;;
        "waiting_username")
            user_data[$chat_id,username]=$message
            user_states[$chat_id]="waiting_password"
            send_message "$chat_id" "𝙎𝙚𝙣𝙙 𝙋𝙖𝙨𝙨 :"
            ;;
        "waiting_password")
            local username=${user_data[$chat_id,username]}
            create_user "$chat_id" "$username" "$message"
            user_states[$chat_id]="none"
            unset user_data[$chat_id,username]
            ;;
    esac
}

# Start bot loop
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