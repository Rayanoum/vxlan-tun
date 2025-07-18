#!/bin/bash

# ------------------ CONFIGURATION ------------------
TUNNEL_TYPE="mpls-udp"  # Using MPLS over UDP for high performance
TUNNEL_MTU=9000         # Jumbo frames for better performance
LABEL_STACK_DEPTH=3      # Depth of MPLS label stack
CRYPTO_MODE="none"       # Options: none, aes128, chacha20
COMPRESSION="lz4"        # Options: none, lz4, zstd

# ------------------ DEPENDENCIES ------------------
install_dependencies() {
    echo "[*] Installing required dependencies..."
    apt update -y
    apt install -y build-essential cmake libpcap-dev libssl-dev \
                   zlib1g-dev liblz4-dev libzstd-dev python3-pip \
                   linux-headers-$(uname -r) git
    
    # Install MPLS kernel module if not present
    if ! lsmod | grep -q mpls; then
        echo "[*] Enabling MPLS in kernel..."
        modprobe mpls-router
        modprobe mpls-iptunnel
        echo "mpls-router" >> /etc/modules
        echo "mpls-iptunnel" >> /etc/modules
    fi
    
    # Enable IP forwarding
    sysctl -w net.ipv4.ip_forward=1
    sysctl -w net.mpls.platform_labels=1048575
    sysctl -w net.mpls.conf.default.input=1
    sysctl -w net.mpls.ip_ttl_propagate=1
}

# ------------------ TUNNEL SETUP ------------------
setup_mpls_udp_tunnel() {
    local role=$1
    local local_ip=$2
    local remote_ip=$3
    local udp_port=$4
    
    echo "[*] Setting up MPLS-over-UDP tunnel..."
    
    # Create virtual interface
    ip link add name mpls-udp0 type udp local $local_ip remote $remote_ip dstport $udp_port
    
    # Set MTU
    ip link set mpls-udp0 mtu $TUNNEL_MTU up
    
    # Configure MPLS
    ip -f mpls route add 100 as via inet $local_ip
    ip -f mpls route add 200 as via inet $remote_ip
    
    # Enable MPLS on interface
    sysctl -w net.mpls.conf.mpls-udp0.input=1
    
    # Configure label switching
    if [ "$role" == "ingress" ]; then
        echo "[*] Configuring as ingress LER (Label Edge Router)"
        mpls labelspace set dev mpls-udp0 labelspace 0
        mpls ilm add label gen $((RANDOM%1000+100)) labelspace 0 \
            proto ipv4 \
            nhlfe encap mpls \
            action out $remote_ip \
            labels $((RANDOM%1000+100)),$((RANDOM%1000+100)),$((RANDOM%1000+100))
    else
        echo "[*] Configuring as egress LER (Label Edge Router)"
        mpls labelspace set dev mpls-udp0 labelspace 0
        mpls ilm add label gen $((RANDOM%1000+100)) labelspace 0 \
            proto ipv4 \
            nhlfe decap \
            action pop
    fi
    
    # Enable ECMP for load balancing
    sysctl -w net.mpls.platform_labels=1048575
    sysctl -w net.mpls.multipath=1
}

# ------------------ TRAFFIC OPTIMIZATION ------------------
optimize_traffic() {
    echo "[*] Optimizing network stack..."
    
    # TCP optimizations
    sysctl -w net.core.rmem_max=16777216
    sysctl -w net.core.wmem_max=16777216
    sysctl -w net.ipv4.tcp_rmem="4096 87380 16777216"
    sysctl -w net.ipv4.tcp_wmem="4096 65536 16777216"
    sysctl -w net.ipv4.tcp_congestion_control=bbr
    sysctl -w net.ipv4.tcp_mtu_probing=1
    sysctl -w net.ipv4.tcp_fastopen=3
    
    # UDP optimizations
    sysctl -w net.core.netdev_max_backlog=100000
    sysctl -w net.core.somaxconn=65535
    
    # MPLS optimizations
    sysctl -w net.mpls.platform_labels=1048575
    sysctl -w net.mpls.ip_ttl_propagate=1
}

# ------------------ SECURITY ------------------
setup_security() {
    local udp_port=$1
    
    echo "[*] Configuring firewall rules..."
    
    # Basic firewall
    iptables -N MPLS-UDP-PROTECT
    iptables -A INPUT -p udp --dport $udp_port -j MPLS-UDP-PROTECT
    iptables -A MPLS-UDP-PROTECT -m conntrack --ctstate INVALID -j DROP
    iptables -A MPLS-UDP-PROTECT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    iptables -A MPLS-UDP-PROTECT -p udp --dport $udp_port -m recent --name MPLS --set
    iptables -A MPLS-UDP-PROTECT -p udp --dport $udp_port -m recent --name MPLS --update --seconds 60 --hitcount 100 -j DROP
    iptables -A MPLS-UDP-PROTECT -p udp --dport $udp_port -j ACCEPT
    
    # Rate limiting
    iptables -A INPUT -p udp --dport $udp_port -m limit --limit 1000/sec -j ACCEPT
    iptables -A INPUT -p udp --dport $udp_port -j DROP
    
    echo "[+] Firewall rules configured"
}

# ------------------ MONITORING ------------------
setup_monitoring() {
    echo "[*] Setting up monitoring..."
    
    # Install telegraf for metrics
    if ! command -v telegraf &> /dev/null; then
        curl -sL https://repos.influxdata.com/influxdb.key | apt-key add -
        echo "deb https://repos.influxdata.com/debian $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/influxdb.list
        apt update -y
        apt install -y telegraf
    fi
    
    # Configure telegraf
    cat <<EOF > /etc/telegraf/telegraf.conf
[agent]
  interval = "10s"
  round_interval = true
  metric_batch_size = 1000
  metric_buffer_limit = 10000
  collection_jitter = "0s"
  flush_interval = "10s"
  flush_jitter = "0s"
  precision = ""
  hostname = "$(hostname)"
  omit_hostname = false

[[inputs.net]]
  interfaces = ["mpls-udp0"]

[[inputs.netstat]]

[[inputs.system]]

[[outputs.influxdb]]
  urls = ["http://localhost:8086"]
  database = "mpls_metrics"
  skip_database_creation = false
EOF
    
    systemctl restart telegraf
    echo "[+] Monitoring setup complete"
}

# ------------------ MAIN SCRIPT ------------------
main() {
    # Check root
    if [ "$(id -u)" -ne 0 ]; then
        echo "This script must be run as root" >&2
        exit 1
    fi
    
    # Install dependencies
    install_dependencies
    
    # Get configuration
    clear
    echo "╔════════════════════════════════════════════╗"
    echo "║    Advanced MPLS-over-UDP Tunnel Setup     ║"
    echo "╚════════════════════════════════════════════╝"
    echo ""
    echo "Choose role:"
    echo "1) Ingress (Client/Edge)"
    echo "2) Egress (Server/Core)"
    read -p "Select role [1/2]: " role_choice
    
    read -p "Local IP address: " local_ip
    read -p "Remote IP address: " remote_ip
    read -p "UDP port for tunnel (default: 6635): " udp_port
    udp_port=${udp_port:-6635}
    
    # Validate port
    if ! [[ "$udp_port" =~ ^[0-9]+$ ]] || [ "$udp_port" -lt 1 ] || [ "$udp_port" -gt 65535 ]; then
        echo "Invalid port number" >&2
        exit 1
    fi
    
    # Setup based on role
    if [ "$role_choice" == "1" ]; then
        setup_mpls_udp_tunnel "ingress" "$local_ip" "$remote_ip" "$udp_port"
    elif [ "$role_choice" == "2" ]; then
        setup_mpls_udp_tunnel "egress" "$local_ip" "$remote_ip" "$udp_port"
    else
        echo "Invalid role selection" >&2
        exit 1
    fi
    
    # Additional optimizations
    optimize_traffic
    setup_security "$udp_port"
    setup_monitoring
    
    echo ""
    echo "╔════════════════════════════════════════════╗"
    echo "║          Tunnel Setup Complete            ║"
    echo "╠════════════════════════════════════════════╣"
    echo "║ Role: $(if [ "$role_choice" == "1" ]; then echo "Ingress (Client)"; else echo "Egress (Server)"; fi)"
    echo "║ Local IP: $local_ip"
    echo "║ Remote IP: $remote_ip"
    echo "║ UDP Port: $udp_port"
    echo "║ MTU: $TUNNEL_MTU"
    echo "║ MPLS Labels: $LABEL_STACK_DEPTH"
    echo "╚════════════════════════════════════════════╝"
    echo ""
    echo "To make the tunnel persistent across reboots, add the following to /etc/rc.local:"
    echo "ip link set mpls-udp0 up"
    echo "sysctl -w net.mpls.conf.mpls-udp0.input=1"
}

# Run main function
main
