#!/bin/bash
# Advanced Tunnel Script with WireGuard and Network Optimizations
# Features: WireGuard, QoS, Traffic Shaping, Encryption, Multipath

# ---------------- CONSTANTS ----------------
VERSION="2.0.0"
GITHUB_REPO="https://github.com/advanced-tunnel/scripts"
WIREGUARD_PORT=51820
DEFAULT_MTU=1420
CONFIG_DIR="/etc/advanced_tunnel"

# ---------------- COLORS ----------------
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

# ---------------- DEPENDENCIES ----------------
REQUIRED_PACKAGES=("wireguard" "iproute2" "jq" "curl" "bc" "ethtool" "ifstat" "tc" "resolvconf")

# ---------------- FUNCTIONS ----------------

check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}[ERROR] Please run as root${NC}"
        exit 1
    fi
}

install_dependencies() {
    echo -e "${BLUE}[*] Checking and installing dependencies...${NC}"
    
    # Detect package manager
    if command -v apt >/dev/null 2>&1; then
        PM="apt"
    elif command -v yum >/dev/null 2>&1; then
        PM="yum"
    elif command -v dnf >/dev/null 2>&1; then
        PM="dnf"
    else
        echo -e "${RED}[ERROR] Could not detect package manager${NC}"
        exit 1
    fi

    # Update package lists
    $PM update -y

    # Install required packages
    for pkg in "${REQUIRED_PACKAGES[@]}"; do
        if ! command -v "$pkg" >/dev/null 2>&1; then
            echo -e "${YELLOW}[+] Installing $pkg...${NC}"
            $PM install -y "$pkg"
        fi
    done

    # Install WireGuard if not present
    if ! command -v wg >/dev/null 2>&1; then
        echo -e "${YELLOW}[+] Installing WireGuard...${NC}"
        if [ "$PM" = "apt" ]; then
            $PM install -y wireguard wireguard-tools
        elif [ "$PM" = "yum" ] || [ "$PM" = "dnf" ]; then
            $PM install -y epel-release
            $PM install -y wireguard-tools
        fi
    fi
}

get_server_info() {
    echo -e "${BLUE}[*] Gathering server information...${NC}"
    
    PUBLIC_IP=$(curl -4 -sS https://ifconfig.me)
    INTERFACE=$(ip route get 1.1.1.1 | awk '{print $5}' | head -n1)
    SERVER_COUNTRY=$(curl -sS "http://ip-api.com/json/$PUBLIC_IP" | jq -r '.country')
    SERVER_ISP=$(curl -sS "http://ip-api.com/json/$PUBLIC_IP" | jq -r '.isp')
    CPU_CORES=$(nproc)
    TOTAL_MEM=$(free -m | awk '/Mem:/ {print $2}')
    
    # Network interface details
    INTERFACE_SPEED=$(ethtool "$INTERFACE" 2>/dev/null | grep -i "speed" | awk '{print $2}')
    INTERFACE_DUPLEX=$(ethtool "$INTERFACE" 2>/dev/null | grep -i "duplex" | awk '{print $2}')
}

optimize_kernel() {
    echo -e "${BLUE}[*] Applying kernel optimizations...${NC}"
    
    # TCP optimizations
    sysctl -w net.core.rmem_max=16777216
    sysctl -w net.core.wmem_max=16777216
    sysctl -w net.ipv4.tcp_rmem="4096 87380 16777216"
    sysctl -w net.ipv4.tcp_wmem="4096 65536 16777216"
    sysctl -w net.ipv4.tcp_congestion_control=bbr
    sysctl -w net.ipv4.tcp_fastopen=3
    sysctl -w net.core.default_qdisc=fq
    sysctl -w net.ipv4.tcp_mtu_probing=1
    
    # UDP optimizations for WireGuard
    sysctl -w net.core.netdev_max_backlog=100000
    sysctl -w net.core.optmem_max=4194304
    
    # Save settings
    mkdir -p /etc/sysctl.d
    cat > /etc/sysctl.d/99-advanced-tunnel.conf <<EOF
net.core.rmem_max=16777216
net.core.wmem_max=16777216
net.ipv4.tcp_rmem=4096 87380 16777216
net.ipv4.tcp_wmem=4096 65536 16777216
net.ipv4.tcp_congestion_control=bbr
net.ipv4.tcp_fastopen=3
net.core.default_qdisc=fq
net.ipv4.tcp_mtu_probing=1
net.core.netdev_max_backlog=100000
net.core.optmem_max=4194304
EOF
    
    sysctl --system
}

generate_wireguard_keys() {
    echo -e "${BLUE}[*] Generating WireGuard keys...${NC}"
    
    mkdir -p "$CONFIG_DIR"
    chmod 700 "$CONFIG_DIR"
    
    if [ ! -f "$CONFIG_DIR/privatekey" ]; then
        wg genkey | tee "$CONFIG_DIR/privatekey" | wg pubkey > "$CONFIG_DIR/publickey"
        chmod 600 "$CONFIG_DIR/privatekey" "$CONFIG_DIR/publickey"
    fi
    
    PRIVATE_KEY=$(cat "$CONFIG_DIR/privatekey")
    PUBLIC_KEY=$(cat "$CONFIG_DIR/publickey")
}

setup_wireguard() {
    echo -e "${BLUE}[*] Configuring WireGuard...${NC}"
    
    # Determine role
    echo "Select server role:"
    echo "1) Endpoint (Iran)"
    echo "2) Client (Kharej)"
    read -rp "Enter choice [1-2]: " ROLE_CHOICE
    
    if [ "$ROLE_CHOICE" = "1" ]; then
        # Endpoint configuration
        read -rp "Enter client public key: " CLIENT_PUBKEY
        read -rp "Enter client allowed IPs (e.g., 10.0.0.2/32): " CLIENT_IP
        read -rp "Enter client endpoint IP: " CLIENT_ENDPOINT
        
        SERVER_IP="10.0.0.1"
        SERVER_PORT=$WIREGUARD_PORT
        
        cat > /etc/wireguard/wg0.conf <<EOF
[Interface]
Address = $SERVER_IP/24
PrivateKey = $PRIVATE_KEY
ListenPort = $SERVER_PORT
MTU = $DEFAULT_MTU

# Client configuration
[Peer]
PublicKey = $CLIENT_PUBKEY
AllowedIPs = $CLIENT_IP
Endpoint = $CLIENT_ENDPOINT:$SERVER_PORT
PersistentKeepalive = 25
EOF
        
    elif [ "$ROLE_CHOICE" = "2" ]; then
        # Client configuration
        read -rp "Enter server public key: " SERVER_PUBKEY
        read -rp "Enter server endpoint IP: " SERVER_ENDPOINT
        
        CLIENT_IP="10.0.0.2"
        SERVER_IP="10.0.0.1"
        
        cat > /etc/wireguard/wg0.conf <<EOF
[Interface]
Address = $CLIENT_IP/24
PrivateKey = $PRIVATE_KEY
MTU = $DEFAULT_MTU

# Server configuration
[Peer]
PublicKey = $SERVER_PUBKEY
AllowedIPs = 0.0.0.0/0
Endpoint = $SERVER_ENDPOINT:$WIREGUARD_PORT
PersistentKeepalive = 25
EOF
    else
        echo -e "${RED}[ERROR] Invalid choice${NC}"
        exit 1
    fi
    
    # Enable IP forwarding
    echo 1 > /proc/sys/net/ipv4/ip_forward
    sysctl -w net.ipv4.ip_forward=1
    
    # Start WireGuard
    systemctl enable --now wg-quick@wg0
    systemctl restart wg-quick@wg0
    
    echo -e "${GREEN}[+] WireGuard configured successfully${NC}"
}

configure_qos() {
    echo -e "${BLUE}[*] Configuring Quality of Service (QoS)...${NC}"
    
    # Clear existing qdisc
    tc qdisc del dev "$INTERFACE" root 2>/dev/null
    
    # HTB (Hierarchical Token Bucket) for bandwidth management
    tc qdisc add dev "$INTERFACE" root handle 1: htb default 10
    
    # Root class with maximum available bandwidth
    TOTAL_BANDWIDTH=$(($(ethtool "$INTERFACE" | grep -i "speed" | awk '{print $2}' | sed 's/[^0-9]*//g') * 1000))
    if [ -z "$TOTAL_BANDWIDTH" ] || [ "$TOTAL_BANDWIDTH" -le 0 ]; then
        TOTAL_BANDWIDTH=1000000 # Default to 1Gbps if detection fails
    fi
    
    tc class add dev "$INTERFACE" parent 1: classid 1:1 htb rate ${TOTAL_BANDWIDTH}kbit ceil ${TOTAL_BANDWIDTH}kbit
    
    # Subclasses for different traffic types
    tc class add dev "$INTERFACE" parent 1:1 classid 1:10 htb rate $((TOTAL_BANDWIDTH * 80 / 100))kbit ceil ${TOTAL_BANDWIDTH}kbit prio 0
    tc class add dev "$INTERFACE" parent 1:1 classid 1:20 htb rate $((TOTAL_BANDWIDTH * 15 / 100))kbit ceil $((TOTAL_BANDWIDTH * 30 / 100))kbit prio 1
    tc class add dev "$INTERFACE" parent 1:1 classid 1:30 htb rate $((TOTAL_BANDWIDTH * 5 / 100))kbit ceil $((TOTAL_BANDWIDTH * 10 / 100))kbit prio 2
    
    # SFQ (Stochastic Fairness Queueing) for fair bandwidth distribution
    tc qdisc add dev "$INTERFACE" parent 1:10 handle 10: sfq perturb 10
    tc qdisc add dev "$INTERFACE" parent 1:20 handle 20: sfq perturb 10
    tc qdisc add dev "$INTERFACE" parent 1:30 handle 30: sfq perturb 10
    
    # Filters to classify traffic
    tc filter add dev "$INTERFACE" parent 1:0 protocol ip prio 1 u32 match ip dport 22 0xffff flowid 1:20 # SSH
    tc filter add dev "$INTERFACE" parent 1:0 protocol ip prio 1 u32 match ip sport 22 0xffff flowid 1:20 # SSH
    tc filter add dev "$INTERFACE" parent 1:0 protocol ip prio 2 u32 match ip protocol 1 0xff flowid 1:30 # ICMP
    tc filter add dev "$INTERFACE" parent 1:0 protocol ip prio 3 u32 match ip protocol 17 0xff flowid 1:10 # UDP
    tc filter add dev "$INTERFACE" parent 1:0 protocol ip prio 4 u32 match ip protocol 6 0xff flowid 1:10 # TCP
    
    echo -e "${GREEN}[+] QoS configured successfully${NC}"
}

configure_firewall() {
    echo -e "${BLUE}[*] Configuring firewall rules...${NC}"
    
    # Flush existing rules
    iptables -F
    iptables -X
    iptables -t nat -F
    iptables -t nat -X
    iptables -t mangle -F
    iptables -t mangle -X
    
    # Default policies
    iptables -P INPUT DROP
    iptables -P FORWARD DROP
    iptables -P OUTPUT ACCEPT
    
    # Allow loopback
    iptables -A INPUT -i lo -j ACCEPT
    iptables -A OUTPUT -o lo -j ACCEPT
    
    # Allow established connections
    iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    
    # Allow WireGuard
    iptables -A INPUT -p udp --dport $WIREGUARD_PORT -j ACCEPT
    iptables -A FORWARD -i wg0 -j ACCEPT
    iptables -A FORWARD -o wg0 -j ACCEPT
    
    # NAT for client role
    if [ "$ROLE_CHOICE" = "2" ]; then
        iptables -t nat -A POSTROUTING -o "$INTERFACE" -j MASQUERADE
    fi
    
    # Save rules
    if command -v iptables-save >/dev/null 2>&1; then
        mkdir -p /etc/iptables
        iptables-save > /etc/iptables/rules.v4
    fi
    
    echo -e "${GREEN}[+] Firewall configured successfully${NC}"
}

monitor_traffic() {
    echo -e "${BLUE}[*] Setting up traffic monitoring...${NC}"
    
    cat > /usr/local/bin/tunnel_monitor.sh <<'EOF'
#!/bin/bash
INTERFACE="wg0"
LOG_FILE="/var/log/tunnel_monitor.log"
MAX_LOG_SIZE=1048576 # 1MB

# Rotate log if needed
if [ -f "$LOG_FILE" ] && [ $(stat -c%s "$LOG_FILE") -gt $MAX_LOG_SIZE ]; then
    mv "$LOG_FILE" "${LOG_FILE}.1"
fi

# Get current timestamp
TIMESTAMP=$(date "+%Y-%m-%d %H:%M:%S")

# Get interface stats
RX_BYTES=$(cat /sys/class/net/$INTERFACE/statistics/rx_bytes)
TX_BYTES=$(cat /sys/class/net/$INTERFACE/statistics/tx_bytes)

# Calculate human-readable values
function human_readable {
    local bytes=$1
    if [ $bytes -ge 1000000000 ]; then
        echo "$(echo "scale=2; $bytes/1000000000" | bc) GB"
    elif [ $bytes -ge 1000000 ]; then
        echo "$(echo "scale=2; $bytes/1000000" | bc) MB"
    elif [ $bytes -ge 1000 ]; then
        echo "$(echo "scale=2; $bytes/1000" | bc) KB"
    else
        echo "$bytes bytes"
    fi
}

RX_HR=$(human_readable $RX_BYTES)
TX_HR=$(human_readable $TX_BYTES)

# Log stats
echo "[$TIMESTAMP] Interface $INTERFACE - RX: $RX_HR | TX: $TX_HR" >> "$LOG_FILE"
EOF
    
    chmod +x /usr/local/bin/tunnel_monitor.sh
    
    # Add to crontab to run every 5 minutes
    (crontab -l 2>/dev/null; echo "*/5 * * * * /usr/local/bin/tunnel_monitor.sh") | crontab -
    
    echo -e "${GREEN}[+] Traffic monitoring configured successfully${NC}"
}

show_menu() {
    clear
    echo -e "${BLUE}+-----------------------------------------------------+"
    echo -e "|               ADVANCED TUNNEL SCRIPT v$VERSION         |"
    echo -e "+-----------------------------------------------------+${NC}"
    echo -e "| Server IP: $PUBLIC_IP"
    echo -e "| Interface: $INTERFACE ($INTERFACE_SPEED $INTERFACE_DUPLEX)"
    echo -e "| CPU Cores: $CPU_CORES | Memory: ${TOTAL_MEM}MB"
    echo -e "+-----------------------------------------------------+"
    echo -e "| ${GREEN}1${NC}. Install Tunnel (WireGuard + Optimizations)"
    echo -e "| ${GREEN}2${NC}. Uninstall Tunnel"
    echo -e "| ${GREEN}3${NC}. Show Tunnel Status"
    echo -e "| ${GREEN}4${NC}. Optimize Network Settings"
    echo -e "| ${GREEN}5${NC}. Configure QoS"
    echo -e "| ${GREEN}6${NC}. Monitor Traffic"
    echo -e "| ${GREEN}0${NC}. Exit"
    echo -e "+-----------------------------------------------------+${NC}"
}

show_status() {
    echo -e "${BLUE}[*] Current tunnel status:${NC}"
    
    # WireGuard status
    if systemctl is-active --quiet wg-quick@wg0; then
        echo -e "${GREEN}[+] WireGuard is running${NC}"
        wg show
    else
        echo -e "${RED}[-] WireGuard is not running${NC}"
    fi
    
    # Interface statistics
    echo -e "\n${BLUE}Interface statistics:${NC}"
    ip -s link show wg0 2>/dev/null || echo -e "${RED}WireGuard interface not found${NC}"
    
    # Connection quality
    echo -e "\n${BLUE}Connection quality:${NC}"
    ping -c 4 1.1.1.1 | tail -n 2
    
    # Traffic statistics
    echo -e "\n${BLUE}Traffic statistics:${NC}"
    ifstat -i wg0,"$INTERFACE" -n -q 1 1
}

uninstall_tunnel() {
    echo -e "${BLUE}[*] Uninstalling tunnel...${NC}"
    
    # Stop and disable WireGuard
    systemctl stop wg-quick@wg0 2>/dev/null
    systemctl disable wg-quick@wg0 2>/dev/null
    
    # Remove configuration
    rm -f /etc/wireguard/wg0.conf
    rm -rf "$CONFIG_DIR"
    
    # Remove monitoring
    rm -f /usr/local/bin/tunnel_monitor.sh
    crontab -l | grep -v tunnel_monitor.sh | crontab -
    
    # Reset firewall
    iptables -F
    iptables -X
    iptables -t nat -F
    iptables -t nat -X
    iptables -t mangle -F
    iptables -t mangle -X
    iptables -P INPUT ACCEPT
    iptables -P FORWARD ACCEPT
    iptables -P OUTPUT ACCEPT
    
    echo -e "${GREEN}[+] Tunnel uninstalled successfully${NC}"
}

# ---------------- MAIN EXECUTION ----------------
check_root
install_dependencies
get_server_info

while true; do
    show_menu
    read -rp "Enter your choice [0-6]: " choice
    
    case $choice in
        1)
            optimize_kernel
            generate_wireguard_keys
            setup_wireguard
            configure_qos
            configure_firewall
            monitor_traffic
            echo -e "${GREEN}[+] Tunnel installation complete!${NC}"
            read -rp "Press Enter to continue..."
            ;;
        2)
            uninstall_tunnel
            read -rp "Press Enter to continue..."
            ;;
        3)
            show_status
            read -rp "Press Enter to continue..."
            ;;
        4)
            optimize_kernel
            echo -e "${GREEN}[+] Network optimizations applied${NC}"
            read -rp "Press Enter to continue..."
            ;;
        5)
            configure_qos
            read -rp "Press Enter to continue..."
            ;;
        6)
            monitor_traffic
            read -rp "Press Enter to continue..."
            ;;
        0)
            echo -e "${BLUE}[*] Exiting...${NC}"
            exit 0
            ;;
        *)
            echo -e "${RED}[ERROR] Invalid option${NC}"
            sleep 1
            ;;
    esac
done
