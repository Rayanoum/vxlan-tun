#!/bin/bash
# Advanced Tunnel Script using Geneve and QUIC
# Features: High Performance, Low Resource Usage, Secure

# ---------------- INSTALL DEPENDENCIES ----------------
echo "[*] Updating and installing dependencies..."
sudo apt update -y
sudo apt install -y git build-essential cmake libssl-dev zlib1g-dev \
    libuv1-dev libprotobuf-dev protobuf-compiler libsodium-dev \
    libpcre3-dev libcap-dev libtool automake pkg-config curl jq

# ---------------- COLORS ----------------
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m'

# ---------------- FUNCTIONS ----------------

check_status() {
    ip link show | grep -q 'geneve' && echo -e "${GREEN}Active${NC}" || echo -e "${RED}Inactive${NC}"
}

show_menu() {
    clear
    SERVER_IP=$(hostname -I | awk '{print $1}')
    SERVER_COUNTRY=$(curl -sS "http://ip-api.com/json/$SERVER_IP" | jq -r '.country')
    SERVER_ISP=$(curl -sS "http://ip-api.com/json/$SERVER_IP" | jq -r '.isp')

    echo -e "${BLUE}+-------------------------------------------------------------------------+"
    echo "|   _____ ______ _   _ _______ ______  _____  _    _ _______  |"
    echo "|  / ____|  ____| \ | |__   __|  ____|/ ____|| |  | |__   __| |"
    echo "| | |  __| |__  |  \| |  | |  | |__  | (___  | |  | |  | |    |"
    echo "| | | |_ |  __| | . \ |  | |  |  __|  \___ \ | |  | |  | |    |"
    echo "| | |__| | |____| |\  |  | |  | |____ ____) || |__| |  | |    |"
    echo "|  \_____|______|_| \_|  |_|  |______|_____/  \____/   |_|    |"
    echo -e "+-------------------------------------------------------------------------+${NC}"    
    echo -e "| ${YELLOW}Server Country${NC} | $SERVER_COUNTRY"
    echo -e "| ${YELLOW}Server IP${NC}      | $SERVER_IP"
    echo -e "| ${YELLOW}Server ISP${NC}     | $SERVER_ISP"
    echo -e "| ${YELLOW}Tunnel Status${NC}  | $(check_status)"
    echo -e "${BLUE}+-------------------------------------------------------------------------+${NC}"
    echo -e "| ${GREEN}1${NC}- Install Advanced Tunnel (Geneve+QUIC)"
    echo -e "| ${GREEN}2${NC}- Uninstall Tunnel"
    echo -e "| ${GREEN}3${NC}- Install Performance Optimizations"
    echo -e "| ${GREEN}4${NC}- Show Tunnel Status"
    echo -e "| ${GREEN}5${NC}- Exit"
    echo -e "${BLUE}+-------------------------------------------------------------------------+${NC}"
}

install_quic_tunnel() {
    # Install QUIC implementation (lsquic)
    echo "[*] Installing LSQUIC..."
    git clone https://github.com/litespeedtech/lsquic.git
    cd lsquic
    git submodule init
    git submodule update
    cmake -DBORINGSSL_DIR=/usr/local/boringssl .
    make
    sudo make install
    cd ..
    
    # Install Geneve support
    echo "[*] Configuring Geneve tunnel..."
    sudo modprobe geneve
    
    # Get tunnel parameters
    read -p "Enter remote server IP: " REMOTE_IP
    read -p "Enter tunnel port (default 6081): " TUNNEL_PORT
    TUNNEL_PORT=${TUNNEL_PORT:-6081}
    read -p "Enter VNI (Virtual Network Identifier): " VNI
    
    # Create Geneve interface
    sudo ip link add gen-tun type geneve id $VNI remote $REMOTE_IP dstport $TUNNEL_PORT
    sudo ip addr add 10.200.0.1/24 dev gen-tun
    sudo ip link set gen-tun up
    
    # Configure QUIC transport
    echo "[*] Setting up QUIC transport..."
    cat <<EOF | sudo tee /etc/systemd/system/quic-tunnel.service
[Unit]
Description=QUIC Tunnel Service
After=network.target

[Service]
ExecStart=/usr/local/bin/lsquic_http_server -i gen-tun -p $TUNNEL_PORT -k /etc/ssl/private/ssl-cert-snakeoil.key -c /etc/ssl/certs/ssl-cert-snakeoil.pem
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF

    # Enable and start service
    sudo systemctl daemon-reload
    sudo systemctl enable quic-tunnel
    sudo systemctl start quic-tunnel
    
    echo -e "${GREEN}[+] Advanced Geneve+QUIC tunnel installed successfully!${NC}"
}

uninstall_tunnel() {
    echo "[*] Removing tunnel..."
    sudo ip link del gen-tun 2>/dev/null
    sudo systemctl stop quic-tunnel
    sudo systemctl disable quic-tunnel
    sudo rm /etc/systemd/system/quic-tunnel.service
    sudo systemctl daemon-reload
    echo -e "${GREEN}[+] Tunnel removed successfully!${NC}"
}

install_optimizations() {
    echo "[*] Installing performance optimizations..."
    
    # Install BBR2
    sudo apt install -y --install-recommends linux-generic-hwe-20.04
    echo "net.core.default_qdisc=fq" | sudo tee -a /etc/sysctl.conf
    echo "net.ipv4.tcp_congestion_control=bbr2" | sudo tee -a /etc/sysctl.conf
    sudo sysctl -p
    
    # Kernel optimizations
    echo "[*] Applying kernel optimizations..."
    cat <<EOF | sudo tee -a /etc/sysctl.conf
# Network performance
net.core.rmem_max=16777216
net.core.wmem_max=16777216
net.ipv4.tcp_rmem=4096 87380 16777216
net.ipv4.tcp_wmem=4096 65536 16777216
net.ipv4.tcp_fastopen=3
net.ipv4.tcp_mtu_probing=1
net.ipv4.tcp_tw_reuse=1
EOF
    
    sudo sysctl -p
    echo -e "${GREEN}[+] Performance optimizations installed!${NC}"
}

# ---------------- MAIN PROGRAM ----------------
while true; do
    show_menu
    read -p "Enter your choice [1-5]: " choice
    
    case $choice in
        1)
            install_quic_tunnel
            ;;
        2)
            uninstall_tunnel
            ;;
        3)
            install_optimizations
            ;;
        4)
            echo -e "Tunnel Status: $(check_status)"
            ;;
        5)
            echo "Exiting..."
            exit 0
            ;;
        *)
            echo -e "${RED}[!] Invalid option!${NC}"
            ;;
    esac
    
    read -p "Press Enter to continue..."
done
