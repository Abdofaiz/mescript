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

          🔍 /status
      𝘾𝙝𝙚𝙘𝙠 𝙐𝙨𝙚𝙧 𝙎𝙩𝙖𝙩𝙪𝙨

          📊 /server
     𝙎𝙚𝙧𝙫𝙚𝙧 𝙄𝙣𝙛𝙤𝙧𝙢𝙖𝙩𝙞𝙤𝙣

          👥 /list
       𝙇𝙞𝙨𝙩 𝘼𝙡𝙡 𝙐𝙨𝙚𝙧𝙨

          ℹ️ /info
      𝙐𝙨𝙚𝙧 𝙄𝙣𝙛𝙤𝙧𝙢𝙖𝙩𝙞𝙤𝙣

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

    ✅ 𝙎𝙚𝙧𝙫𝙞𝙘��𝙨 𝙍𝙚𝙨𝙩𝙖𝙧𝙩𝙚𝙙!

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

          🔍 /status
      𝘾𝙝𝙚𝙘𝙠 𝙐𝙨𝙚𝙧 𝙎𝙩𝙖𝙩𝙪𝙨

          📊 /server
     𝙎𝙚𝙧𝙫𝙚𝙧 𝙄𝙣𝙛𝙤𝙧𝙢𝙖𝙩𝙞𝙤𝙣

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

    ✅ 𝙎𝙚𝙧𝙫𝙞𝙘𝙚𝙨 𝙍𝙚𝙨𝙩𝙖𝙧𝙩𝙚𝙙!

      📋 𝙎��𝙧𝙫𝙞𝙘𝙚𝙨 𝙇𝙞𝙨𝙩:
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

       ⚡ 𝙁𝘼𝙄𝙕-𝙑𝙋𝙉 ⚡

    🔌 𝙍𝙚𝙗𝙤𝙤𝙩𝙞𝙣𝙜 𝙎𝙚𝙧𝙫𝙚𝙧...
    
    ⏳ ��𝙡𝙚𝙖𝙨𝙚 𝙬𝙖𝙞 1-2 𝙢𝙞𝙣𝙪𝙩𝙚𝙨
    
    🔄 𝙎𝙮𝙨𝙩𝙚𝙢 𝙬𝙞𝙡𝙡 𝙗𝙚 𝙗𝙖𝙘𝙠 𝙨𝙤𝙤𝙣

      💫 𝙎𝙪𝙥𝙥𝙤𝙧𝙩: @faizvpn

EOF
)"
    
    # Schedule reboot after message is sent
    (sleep 2 && reboot) &
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
                "/start")
                    show_welcome "$chat_id"
                    ;;
                "/create")
                    user_states[$chat_id]="waiting_username"
                    send_message "$chat_id" "𝙎𝙚𝙣𝙙 𝙐𝙨𝙚𝙧 :"
                    ;;
                "/status")
                    send_message "$chat_id" "𝙎𝙚𝙣𝙙 𝙐𝙨𝙚𝙧𝙣𝙖𝙢𝙚 𝙩𝙤 𝘾𝙝𝙚𝙘𝙠:"
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
                *)
                    send_message "$chat_id" "𝙐𝙨𝙚 /start 𝙩𝙤 𝙨𝙚𝙚 𝙖𝙫𝙖𝙞𝙡𝙖𝙗𝙡𝙚 𝙘𝙤𝙢𝙢𝙖𝙣𝙙𝙨"
                    ;;
            esac
            ;;
        "waiting_username")
            user_data[$chat_id,username]=$message
            user_states[$chat_id]="waiting_password"
            send_message "$chat_id" "𝙎𝙚𝙣𝙙 𝙋𝙖𝙨𝙨 :"
            ;;
        "waiting_password")
            user_data[$chat_id,password]=$message
            user_states[$chat_id]="waiting_duration"
            send_message "$chat_id" "𝙎𝙚𝙣𝙙 𝘿𝙪𝙧𝙖𝙩𝙞𝙤𝙣 (𝘿𝙖𝙮𝙨) :"
            ;;
        "waiting_duration")
            local username=${user_data[$chat_id,username]}
            local password=${user_data[$chat_id,password]}
            create_user "$chat_id" "$username" "$password" "$message"
            user_states[$chat_id]="none"
            unset user_data[$chat_id,username]
            unset user_data[$chat_id,password]
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