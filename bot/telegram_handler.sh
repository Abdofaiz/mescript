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

# Function to get server details
get_server_details() {
    local ip=$(curl -s ipv4.icanhazip.com)
    local domain=$(cat /etc/vps/domain.conf 2>/dev/null || echo 'Not Set')
    local username=$1
    local password=$2
    
    echo "\
🌐 𝙎𝙚𝙧𝙫𝙚𝙧 𝘿𝙚𝙩𝙖𝙞𝙡𝙨:
📍 𝙄𝙋: $ip
🔗 𝘿𝙤𝙢𝙖𝙞𝙣: $domain

🔰 𝙐𝘿𝙋 𝘾𝙪𝙨𝙤𝙢𝙤𝙣: $ip:1-65535@$username:$password

💎 𝙎𝙚𝙧𝙫𝙞𝙘𝙚𝙨:
• SSL/TLS : 443
• Websocket SSL : 443
• Websocket HTTP : 80
• UDP Custom : 1-65535"
}

# Function to generate fancy text and icons
get_fancy_text() {
    local text=$1
    echo "𝙁𝘼𝙄𝙕-𝙑𝙋𝙉"
}

get_fancy_icon() {
    local type=$1
    case $type in
        "welcome") echo "👋" ;;
        "create") echo "⚡" ;;
        "status") echo "🔍" ;;
        "server") echo "📊" ;;
        "support") echo "💡" ;;
        "success") echo "✅" ;;
        "user") echo "👤" ;;
        "pass") echo "🔑" ;;
        "duration") echo "⏱" ;;
        "expiry") echo "📅" ;;
        "ip") echo "📍" ;;
        "domain") echo "🔗" ;;
        "port") echo "📡" ;;
        "ssl") echo "🔒" ;;
        "websocket") echo "🌐" ;;
        "udp") echo "🔰" ;;
        "services") echo "💎" ;;
        *) echo "•" ;;
    esac
}

get_border() {
    echo "━━━━━━━━━━━━━━━━━━━━━"
}

# Function to center text
center_text() {
    local text=$1
    local width=35
    local padding=$(( (width - ${#text}) / 2 ))
    printf "%${padding}s%s%${padding}s" "" "$text" ""
}

# Function to create user
create_user() {
    local chat_id=$1
    local username=$2
    local password=$3
    local duration=$4
    
    # Add user
    useradd -e $(date -d "+$duration days" +"%Y-%m-%d") -s /bin/false -M $username
    echo "$username:$password" | chpasswd
    
    # Get server details with username and password
    local server_details=$(get_server_details "$username" "$password")
    
    send_message "$chat_id" "\
     ━━━━━━━━━━━━━━━━━━━━━
       🚀 𝙁𝘼𝙄𝙕-𝙑𝙋𝙉 𝙈𝘼𝙉𝘼𝙂𝙀𝙍
     ━━━━━━━━━━━━━━━━━━━━━

✅ 𝘼𝙘𝙘𝙤𝙪𝙣𝙩 𝘾𝙧𝙚𝙖𝙩𝙚𝙙 𝙎𝙪𝙘𝙘𝙚𝙨𝙨𝙛𝙪𝙡𝙡𝙮!

👤 𝙐𝙨𝙚𝙧𝙣𝙖𝙢𝙚: $username
🔑 𝙋𝙖𝙨𝙨𝙬𝙤𝙧𝙙: $password
⏱ 𝘿𝙪𝙧𝙖𝙩𝙞𝙤𝙣: $duration days
📅 𝙀𝙭𝙥𝙞𝙧𝙮: $(date -d "+$duration days" +"%Y-%m-%d")

$server_details

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

# Function to show server status
server_status() {
    local chat_id=$1
    
    local cpu_load=$(cat /proc/loadavg | awk '{print $1}')
    local memory=$(free -m | grep Mem | awk '{printf("%.2f%%", $3/$2*100)}')
    local disk=$(df -h / | awk 'NR==2 {print $5}')
    local uptime=$(uptime -p)
    local server_details=$(get_server_details)
    
    send_message "$chat_id" "\
      ━━━━━━━━━━━━━━━━━━━━━
       🚀 𝙁𝘼𝙄𝙕-𝙑𝙋𝙉 𝙈𝘼𝙉𝘼𝙂𝙀𝙍
     ━━━━━━━━━━━━━━━━━━━━━

📊 𝙎𝙚𝙧𝙫𝙚𝙧 𝙎𝙩𝙖𝙩𝙪𝙨:
📱 𝘾𝙋𝙐 𝙇𝙤𝙖𝙙: $cpu_load
💾 𝙈𝙚𝙢𝙤𝙧𝙮: $memory
💿 𝘿𝙞𝙨𝙠: $disk
⏰ 𝙐𝙥𝙩𝙞𝙢𝙚: $uptime

$server_details

💡 𝙎𝙪𝙥𝙥𝙤𝙧𝙩: @faizvpn
━━━━━━━━━━━━━━━━━━━━━"
}

# Function to show welcome message
show_welcome() {
    local chat_id=$1
    send_message "$chat_id" "$(cat << 'EOF'
⚡ 𝙁𝘼𝙄𝙕-𝙑𝙋𝙉 ⚡
      𝙎𝙀𝙍𝙑𝙀𝙍 𝙋𝙍𝙀𝙈𝙄𝙐𝙈

    👋 𝙒𝙀𝙇𝘾𝙊𝙈𝙀 𝙏𝙊 𝙁𝘼𝙄𝙕-𝙑𝙋𝙉

      📝 𝘾𝙊𝙈𝙈𝘼𝙉𝘿 𝙇𝙄𝙎𝙏 :

          ⚡ /create
     𝘾𝙧𝙚𝙖𝙩𝙚 𝙉𝙚𝙬 𝘼𝙘𝙘𝙤𝙪𝙣𝙩

          🌐 /vless
       𝘾𝙧𝙚𝙖𝙩𝙚 𝙑𝙇𝙀𝙎𝙎 𝘼𝙘𝙘𝙤𝙪𝙣𝙩

          🌐 /vmess
       𝘾𝙧𝙚𝙖𝙩𝙚 𝙑𝙈𝙚𝙨𝙨 𝘼𝙘𝙘𝙤𝙪𝙣𝙩

          🗑️ /delete
       𝙍𝙚𝙢𝙤𝙫𝙚 𝙐𝙨𝙚𝙧

          📊 /status
       𝙎𝙚𝙧𝙫𝙚𝙧 𝙎𝙩𝙖𝙩𝙪𝙨

          🔄 /restart
      𝙍𝙚𝙨𝙩𝙖𝙧𝙩 𝘼𝙡𝙡 𝙎𝙚𝙧𝙫𝙞𝙘𝙚𝙨

          🔌 /reboot
        𝙍𝙚𝙗𝙤𝙤𝙩 𝙎𝙚𝙧𝙫𝙚𝙧

      💫 𝙎𝙪𝙥𝙥𝙤𝙧𝙩: @faizvpn
EOF
)"
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

# Function to create user response
create_user_response() {
    local username=$1
    local password=$2
    local duration=$3
    local ip=$4
    local domain=$5
    local expiry=$6
    
    send_message "$chat_id" "$(cat << EOF
        ━━━━━━━━━━━━━━━━━━━━━

       ⚡ 𝙁𝘼𝙄𝙕-𝙑𝙋𝙉 ⚡

 ━━━━━━━━━━━━━━━━━━━━━

    ✅ 𝘼𝙘𝙘𝙤𝙪𝙣𝙩 𝘾𝙧𝙚𝙖𝙩𝙚𝙙!

    👤 𝙐𝙨𝙚𝙧𝙣𝙖𝙢𝙚 : $username
    🔑 𝙋𝙖𝙨𝙨𝙬𝙤𝙧𝙙 : $password
    ⏱ 𝘿𝙪𝙧𝙖𝙩𝙞𝙤𝙣 : $duration Days

      🌐 𝙎𝙚𝙧𝙫𝙚𝙧 𝘿𝙚𝙩𝙖𝙞𝙡𝙨:
      📍 𝙄𝙋: $ip
      🔗 𝘿𝙤𝙢𝙖𝙞𝙣: $domain
      📅 𝙀𝙭𝙥𝙞𝙧𝙮: $expiry

    ━━━━━━━━━━━━━━━━━━━━━
      💫 𝙎𝙪𝙥𝙥𝙤𝙧𝙩: @faizvpn
     ━━━━━━━━━━━━━━━━━━━━━
EOF
)"
}

# Function to restart services
restart_services() {
    local chat_id=$1
    
    send_message "$chat_id" "🔄 𝙍𝙚𝙨𝙩𝙖𝙧𝙩𝙞𝙣𝙜 𝙎𝙚𝙧𝙫𝙞𝙘𝙚𝙨..."
    
    # Restart services
    systemctl restart ssh
    systemctl restart dropbear
    systemctl restart stunnel4
    systemctl restart openvpn
    systemctl restart trojan
    systemctl restart shadowsocks-libev
    
    send_message "$chat_id" "$(cat << 'EOF'

       ⚡ 𝙁𝘼𝙄𝙕-𝙑𝙋𝙉 ⚡

    ✅ 𝙎𝙧𝙫𝙞𝙘𝙚𝙨 𝙖𝙧𝙩𝙖𝙧𝙩𝙚𝙙!

      📋 𝙎𝙧𝙫𝙞𝙘𝙚𝙨 𝙇𝙞𝙨𝙩 𝙇𝙞𝙨𝙩 𝙗𝙖𝙘𝙠 𝙨𝙤𝙤𝙣
         • SSH
         • Dropbear
         • Stunnel4
         • OpenVPN
         • Trojan
         • Shadowsocks

      💫 𝙎𝙪𝙥𝙥𝙤𝙧𝙩: @faizvpn

EOF
)"
}

# Function to reboot server
reboot_server() {
    local chat_id=$1
    
    send_message "$chat_id" "$(cat << 'EOF'

       ⚡ 𝙁��𝙄𝙕-��𝙋𝙉 ⚡

    🔌 𝙍𝙚��𝙤𝙤𝙩 𝙎𝙚𝙧𝙫𝙚𝙧...
    
    ⏳ 𝙡𝙚𝙖𝙨𝙚 𝙬𝙖𝙞 1-2 𝙢𝙞𝙣𝙪𝙩𝙚𝙨
    
    🔄 𝙎𝙮𝙨𝙩𝙚𝙢 𝙬𝙞𝙡𝙡 𝙗𝙚 𝙗𝙖𝙘𝙠 𝙨𝙤𝙤𝙣

      💫 𝙎𝙪𝙥𝙥𝙤𝙧𝙩: @faizvpn

EOF
)"
    
    # Schedule reboot after message is sent
    (sleep 2 && reboot) &
}

# Function to delete user
delete_user() {
    local chat_id=$1
    local username=$2
    
    if [ -z "$username" ]; then
        send_message "$chat_id" "𝙎𝙚𝙣𝙙 𝙐𝙨𝙚𝙧𝙣𝙖𝙢𝙚 𝙩𝙤 𝙍𝙚𝙢𝙤𝙫𝙚:"
        return
    fi

    if id "$username" &>/dev/null; then
        userdel -f "$username"
        rm -rf /home/$username
        send_message "$chat_id" "$(cat << EOF
     ━━━━━━━━━━━━━━━━━━━━━
       🚀 𝙁𝘼𝙄𝙕-𝙑𝙋𝙉 𝙈𝘼𝙉𝘼𝙂𝙀𝙍
     ━━━━━━━━━━━━━━━━━━━━━

✅ 𝙐𝙨𝙚𝙧 𝙍𝙚𝙢𝙤𝙫𝙚𝙙 𝙎𝙪𝙘𝙘𝙚𝙨𝙨𝙛𝙪𝙡𝙡𝙮!

👤 Username: $username

💫 𝙎𝙪𝙥𝙥𝙤𝙧𝙩: @faizvpn
━━━━━━━━━━━━━━━━━━━━━
EOF
)"
    else
        send_message "$chat_id" "❌ 𝙐𝙨𝙚𝙧 $username 𝙙𝙤𝙚𝙨 𝙣𝙤𝙩 𝙚𝙩"
    fi
}

# Function to check server status
check_server_status() {
    local chat_id=$1
    
    # Get system info
    local cpu_usage=$(top -bn1 | grep "Cpu(s)" | awk '{print $2}')
    local memory_info=$(free -m | grep Mem)
    local memory_total=$(echo $memory_info | awk '{print $2}')
    local memory_used=$(echo $memory_info | awk '{print $3}')
    local memory_usage=$((memory_used * 100 / memory_total))
    local disk_usage=$(df -h / | awk 'NR==2 {print $5}' | cut -d'%' -f1)
    local uptime=$(uptime -p)
    
    # Get domain/host info
    local domain=$(cat /etc/vps/domain.conf 2>/dev/null || curl -s ipv4.icanhazip.com)
    
    # Check service status
    local ssh_status=$(systemctl is-active ssh)
    local dropbear_status=$(systemctl is-active dropbear)
    local stunnel_status=$(systemctl is-active stunnel4)
    local xray_status=$(systemctl is-active xray)
    
    send_message "$chat_id" "$(cat << EOF
     ━━━━━━━━━━━━━━━━━━━━━
       🚀 𝙁𝘼𝙄𝙕-𝙑𝙋𝙉 𝙎𝙏𝘼𝙏𝙐𝙎
     ━━━━━━━━━━━━━━━━━━━━━

💻 𝙎𝙮𝙨𝙩𝙚𝙢 𝙄𝙣𝙛𝙤:
 • CPU: $cpu_usage%
 • RAM: $memory_usage%
 • Disk: $disk_usage%
 • Uptime: $uptime

📊 𝙎𝙚𝙧𝙫𝙞𝙘𝙚 𝙎𝙩𝙖𝙩𝙪𝙨:
 • SSH: ${ssh_status^^}
 • Dropbear: ${dropbear_status^^}
 • Stunnel: ${stunnel_status^^}
 • Xray: ${xray_status^^}

🌐 𝙑𝙇𝙀𝙎𝙎 𝘾𝙤𝙣𝙛𝙞𝙜:
 • Host: $domain
 • SNI: $domain
 • Port: 8442
 • Path: /vless
 • Network: ws
 • TLS: tls

🌐 𝙑𝙈𝙚𝙨𝙨 𝘾𝙤𝙣𝙛𝙞𝙜:
 • Host: $domain
 • SNI: $domain
 • Port: 8443
 • Path: /vmess
 • Network: ws
 • TLS: tls

      💫 𝙎𝙪𝙥𝙥𝙤𝙧𝙩: @faizvpn
━━━━━━━━━━━━━━━━━━━━━
EOF
)"
}

# Function to create Xray user
create_xray_user() {
    local chat_id=$1
    local protocol=$2
    local username=$3
    
    # Generate UUID
    local uuid=$(uuidgen)
    local domain=$(cat /etc/vps/domain.conf 2>/dev/null || curl -s ipv4.icanhazip.com)
    local exp_date=$(date -d "+30 days" +"%Y-%m-%d")
    
    if [[ "$protocol" == "vless" ]]; then
        local port="8442"
        local path="/vless"
        local config="vless://${uuid}@${domain}:${port}?path=${path}&security=tls&encryption=none&type=ws#FAIZ-${username}"
        
        # Add user to Xray config
        local xray_config="/usr/local/etc/xray/config.json"
        if [ -f "$xray_config" ]; then
            # Create backup of current config
            cp "$xray_config" "${xray_config}.bak"
            
            # Add VLESS user to config
            jq --arg uuid "$uuid" --arg username "$username" '.inbounds[] | select(.protocol == "vless") | .settings.clients += [{"id": $uuid, "email": $username}]' "$xray_config" > "${xray_config}.tmp"
            mv "${xray_config}.tmp" "$xray_config"
            
            # Restart Xray service
            systemctl restart xray
            
            # Save user info to database
            echo "vless:${username}:${uuid}:${exp_date}" >> /etc/vps/users.db
            
            send_message "$chat_id" "$(cat << EOF
     ━━━━━━━━━━━━━━━━━━━━━
       🚀 𝙁𝘼𝙄𝙕-𝙑𝙋𝙉 𝙈𝘼𝙉𝘼𝙂𝙀𝙍
     ━━━━━━━━━━━━━━━━━━━━━

✅ VLESS Account Created!

👤 Username: $username
🔑 UUID: $uuid
📅 Expired: $exp_date

🌐 Configuration:
• Host: $domain
• SNI: $domain
• Port: $port
• Path: $path
• Network: ws
• TLS: tls

📝 VLESS Config:
<code>$config</code>

      💫 𝙎𝙪𝙥𝙥𝙤𝙧𝙩: @faizvpn
━━━━━━━━━━━━━━━━━━━━━
EOF
)"
        else
            send_message "$chat_id" "❌ Error: Xray configuration file not found"
        fi
    fi
}

# Process messages
process_message() {
    local chat_id=$1
    local message=$2
    
    case $message in
        "/vless")
            send_message "$chat_id" "𝙎𝙚𝙣𝙙 𝙐𝙨𝙚𝙧𝙣𝙖𝙢𝙚:"
            user_states[$chat_id]="waiting_vless_username"
            ;;
        "/vmess")
            create_xray_user "$chat_id" "vmess" "$message"
            user_states[$chat_id]="none"
            ;;
        "/status")
            check_server_status "$chat_id"
            ;;
        "/server")
            server_status "$chat_id"
            ;;
        "/restart")
            restart_services "$chat_id"
            ;;
        "/reboot")
            reboot_server "$chat_id"
            ;;
        "/help")
            show_help "$chat_id"
            ;;
        "/delete")
            user_states[$chat_id]="waiting_delete_username"
            send_message "$chat_id" "𝙎𝙚��𝙙 𝙐𝙨𝙚𝙧𝙣𝙖𝙢𝙚 𝙩𝙤 𝙍𝙚𝙢𝙤𝙫𝙚:"
            ;;
        *)
            send_message "$chat_id" "𝙐𝙨𝙚 /start 𝙩𝙤 𝙨𝙚𝙚 𝙖𝙫𝙖𝙞𝙡𝙖𝙗𝙡�� 𝙘𝙤𝙢𝙢𝙖𝙣𝙙𝙨"
            ;;
    esac
    
    # Get current state
    local state=${user_states[$chat_id]:-"none"}
    
    case $state in
        "waiting_vless_username")
            if [[ -n "$message" ]]; then
                create_xray_user "$chat_id" "vless" "$message"
                user_states[$chat_id]="none"
            else
                send_message "$chat_id" "❌ Invalid username. Please try again."
            fi
            ;;
        "waiting_delete_username")
            delete_user "$chat_id" "$message"
            user_states[$chat_id]="none"
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