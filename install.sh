#!/bin/bash

# ---------------- CONSTANTS ----------------
VERSION="2.0.0"
AUTHOR="@AminiDev"
GITHUB_REPO="https://github.com/MrAminiDev/NetOptix"

# ---------------- COLORS ----------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# ---------------- DEPENDENCIES ----------------
REQUIRED_PACKAGES=(
    "iproute2" 
    "net-tools"
    "grep"
    "awk"
    "sudo"
    "iputils-ping"
    "jq"
    "curl"
    "haproxy"
    "iptables"
    "resolvconf"
    "dnsutils"
)

# ---------------- FUNCTIONS ----------------

# Function to display error messages
error_msg() {
    echo -e "${RED}[ERROR] $1${NC}" >&2
}

# Function to display success messages
success_msg() {
    echo -e "${GREEN}[SUCCESS] $1${NC}"
}

# Function to display info messages
info_msg() {
    echo -e "${BLUE}[INFO] $1${NC}"
}

# Function to display warning messages
warning_msg() {
    echo -e "${YELLOW}[WARNING] $1${NC}"
}

# Function to check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        error_msg "This script must be run as root"
        exit 1
    fi
}

# Function to install dependencies
install_dependencies() {
    info_msg "Updating package list..."
    apt update -y || {
        error_msg "Failed to update package list"
        return 1
    }

    info_msg "Installing required packages..."
    for pkg in "${REQUIRED_PACKAGES[@]}"; do
        if ! dpkg -l | grep -q "^ii  $pkg "; then
            info_msg "Installing $pkg..."
            apt install -y "$pkg" || {
                error_msg "Failed to install $pkg"
                return 1
            }
        else
            info_msg "$pkg is already installed"
        fi
    done
    
    success_msg "All dependencies installed successfully"
    return 0
}

# Function to get server info
get_server_info() {
    local ip=$(hostname -I | awk '{print $1}')
    local info=$(curl -sS "http://ip-api.com/json/$ip")
    local country=$(echo "$info" | jq -r '.country // "Unknown"')
    local isp=$(echo "$info" | jq -r '.isp // "Unknown"')
    local asn=$(echo "$info" | jq -r '.as // "Unknown"')
    
    echo "$ip,$country,$isp,$asn"
}

# Function to check VXLAN status
check_vxlan_status() {
    local vxlan_count=$(ip -d link show | grep -c 'vxlan[0-9]\+')
    if [[ $vxlan_count -gt 0 ]]; then
        echo "Active ($vxlan_count tunnels)"
    else
        echo "Inactive"
    fi
}

# Function to display menu
show_menu() {
    clear
    IFS=',' read -r ip country isp asn <<< "$(get_server_info)"
    
    echo -e "${CYAN}+-------------------------------------------------------------------------+"
    echo "|   __  __       _        _____           _        _   _             |"
    echo "|  |  \/  |     | |      |_   _|         | |      | | (_)            |"
    echo "|  | \  / | __ _| |_ ___   | |  _ __  ___| |_ __ _| |_ _  ___  ___   |"
    echo "|  | |\/| |/ _  | __/ _ \  | | | '_ \/ __| __/ _  | __| |/ _ \/ __|  |"
    echo "|  | |  | | (_| | || (_) |_| |_| | | \__ \ || (_| | |_| |  __/\__ \  |"
    echo "|  |_|  |_|\__,_|\__\___/_____|_| |_|___/\__\__,_|\__|_|\___||___/  |"
    echo -e "+-------------------------------------------------------------------------+${NC}"    
    echo -e "| ${YELLOW}Telegram Channel: ${MAGENTA}$AUTHOR${NC}  |  ${YELLOW}Version: ${GREEN}$VERSION${NC}  |"
    echo -e "${CYAN}+-------------------------------------------------------------------------+${NC}"      
    echo -e "| ${GREEN}Server IP${NC}         |  $ip"
    echo -e "| ${GREEN}Server Country${NC}    |  $country"
    echo -e "| ${GREEN}Server ISP${NC}        |  $isp"
    echo -e "| ${GREEN}Server ASN${NC}        |  $asn"
    echo -e "| ${GREEN}Tunnel Status${NC}     |  $(check_vxlan_status)"
    echo -e "${CYAN}+-------------------------------------------------------------------------+${NC}"
    echo -e "| ${YELLOW}Please choose an option:${NC}"
    echo -e "${CYAN}+-------------------------------------------------------------------------+${NC}"
    echo -e "1. Install new tunnel"
    echo -e "2. Uninstall tunnel(s)"
    echo -e "3. Install BBR"
    echo -e "4. Check tunnel status"
    echo -e "5. Update script"
    echo -e "0. Exit"
    echo -e "${CYAN}+-------------------------------------------------------------------------+${NC}"
    echo -e "${NC}"
}

# Function to validate IP address
validate_ip() {
    local ip=$1
    local stat=1
    
    if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        IFS='.' read -r -a octets <<< "$ip"
        [[ ${octets[0]} -le 255 && ${octets[1]} -le 255 && \
           ${octets[2]} -le 255 && ${octets[3]} -le 255 ]]
        stat=$?
    fi
    
    return $stat
}

# Function to validate port
validate_port() {
    local port=$1
    [[ $port =~ ^[0-9]+$ ]] && (( port >= 1 && port <= 65535 ))
}

# Function to uninstall all VXLAN tunnels
uninstall_vxlan() {
    info_msg "Removing all VXLAN tunnels..."
    
    # Remove VXLAN interfaces
    for iface in $(ip -d link show | grep -o 'vxlan[0-9]\+'); do
        info_msg "Removing interface $iface..."
        ip link del $iface 2>/dev/null || \
            error_msg "Failed to remove interface $iface"
    done
    
    # Remove scripts and services
    rm -f /usr/local/bin/vxlan_bridge.sh /etc/ping_vxlan.sh
    
    # Disable and remove service
    if systemctl is-active --quiet vxlan-tunnel.service; then
        info_msg "Stopping vxlan-tunnel service..."
        systemctl stop vxlan-tunnel.service || \
            error_msg "Failed to stop vxlan-tunnel service"
    fi
    
    if systemctl is-enabled --quiet vxlan-tunnel.service; then
        info_msg "Disabling vxlan-tunnel service..."
        systemctl disable vxlan-tunnel.service || \
            error_msg "Failed to disable vxlan-tunnel service"
    fi
    
    rm -f /etc/systemd/system/vxlan-tunnel.service
    systemctl daemon-reload
    
    # Clean up HAProxy
    if systemctl is-active --quiet haproxy; then
        info_msg "Stopping HAProxy service..."
        systemctl stop haproxy || \
            error_msg "Failed to stop HAProxy service"
    fi
    
    if systemctl is-enabled --quiet haproxy; then
        info_msg "Disabling HAProxy service..."
        systemctl disable haproxy || \
            error_msg "Failed to disable HAProxy service"
    fi
    
    # Remove HAProxy config
    rm -f /etc/haproxy/haproxy.cfg
    
    success_msg "VXLAN tunnels and related services have been removed"
}

# Function to install BBR
install_bbr() {
    info_msg "Installing BBR..."
    
    if ! curl -fsSL "${GITHUB_REPO}/raw/main/scripts/bbr.sh" -o /tmp/bbr.sh; then
        error_msg "Failed to download BBR script"
        return 1
    fi
    
    if ! bash /tmp/bbr.sh; then
        error_msg "BBR installation failed"
        return 1
    fi
    
    rm -f /tmp/bbr.sh
    success_msg "BBR installed successfully"
    return 0
}

# Function to configure HAProxy
configure_haproxy() {
    local config_file="/etc/haproxy/haproxy.cfg"
    local backup_file="/etc/haproxy/haproxy.cfg.bak"
    
    info_msg "Configuring HAProxy..."
    
    # Backup existing config
    if [[ -f $config_file ]]; then
        info_msg "Backing up existing HAProxy config..."
        cp "$config_file" "$backup_file" || {
            error_msg "Failed to backup HAProxy config"
            return 1
        }
    fi
    
    # Get ports from user
    while true; do
        read -p "Enter ports to forward (comma-separated, e.g., 80,443): " ports_input
        if [[ -z $ports_input ]]; then
            error_msg "Ports cannot be empty"
            continue
        fi
        
        # Validate ports
        local valid=true
        IFS=',' read -ra ports <<< "$ports_input"
        for port in "${ports[@]}"; do
            if ! validate_port "$port"; then
                error_msg "Invalid port: $port"
                valid=false
                break
            fi
        done
        
        $valid && break
    done
    
    local local_ip=$(hostname -I | awk '{print $1}')
    
    # Generate new config
    cat <<EOF > "$config_file"
global
    log /dev/log local0
    log /dev/log local1 notice
    chroot /var/lib/haproxy
    stats socket /run/haproxy/admin.sock mode 660 level admin
    stats timeout 30s
    user haproxy
    group haproxy
    daemon
    maxconn 20000
    tune.ssl.default-dh-param 2048

defaults
    log global
    mode tcp
    option dontlognull
    option redispatch
    retries 3
    timeout connect 5000
    timeout client 50000
    timeout server 50000
    maxconn 10000
EOF

    # Add frontend and backend for each port
    for port in "${ports[@]}"; do
        cat <<EOF >> "$config_file"

frontend fr_$port
    bind *:$port
    default_backend bk_$port

backend bk_$port
    server server1 $local_ip:$port check
EOF
    done
    
    # Add stats endpoint
    cat <<EOF >> "$config_file"

listen stats
    bind *:1936
    stats enable
    stats uri /
    stats hide-version
    stats auth admin:${RANDOM_PASSWORD:-$(openssl rand -hex 8)}
EOF
    
    # Validate config
    if ! haproxy -c -f "$config_file"; then
        error_msg "HAProxy configuration is invalid"
        if [[ -f $backup_file ]]; then
            warning_msg "Restoring previous HAProxy config..."
            mv "$backup_file" "$config_file"
        fi
        return 1
    fi
    
    # Restart HAProxy
    info_msg "Restarting HAProxy..."
    systemctl restart haproxy || {
        error_msg "Failed to restart HAProxy"
        return 1
    }
    
    success_msg "HAProxy configured successfully"
    info_msg "Stats page available at: http://${local_ip}:1936/"
    return 0
}

# Function to setup VXLAN tunnel
setup_vxlan() {
    local role=$1
    local iran_ip=$2
    local kharej_ip=$3
    local port=$4
    
    local vni=88
    local vxlan_if="vxlan${vni}"
    local local_ip=$(hostname -I | awk '{print $1}')
    
    # Determine VXLAN parameters based on role
    if [[ $role == "iran" ]]; then
        local vxlan_ip="30.0.0.1/24"
        local remote_ip=$kharej_ip
    else
        local vxlan_ip="30.0.0.2/24"
        local remote_ip=$iran_ip
    fi
    
    # Detect main interface
    local interface=$(ip route get 1.1.1.1 | awk '{print $5}' | head -n1)
    if [[ -z $interface ]]; then
        error_msg "Could not detect main network interface"
        return 1
    fi
    
    info_msg "Setting up VXLAN tunnel..."
    info_msg "Role: $role"
    info_msg "Local IP: $local_ip"
    info_msg "Remote IP: $remote_ip"
    info_msg "VXLAN Interface: $vxlan_if"
    info_msg "VXLAN IP: $vxlan_ip"
    info_msg "Port: $port"
    info_msg "Network Interface: $interface"
    
    # Create VXLAN interface
    if ! ip link add $vxlan_if type vxlan id $vni local $local_ip remote $remote_ip dev $interface dstport $port nolearning; then
        error_msg "Failed to create VXLAN interface"
        return 1
    fi
    
    # Assign IP address
    if ! ip addr add $vxlan_ip dev $vxlan_if; then
        error_msg "Failed to assign IP to VXLAN interface"
        ip link del $vxlan_if 2>/dev/null
        return 1
    fi
    
    # Bring interface up
    if ! ip link set $vxlan_if up; then
        error_msg "Failed to bring up VXLAN interface"
        ip link del $vxlan_if 2>/dev/null
        return 1
    fi
    
    # Add iptables rules
    info_msg "Configuring iptables rules..."
    iptables -I INPUT -p udp --dport $port -j ACCEPT || \
        warning_msg "Failed to add UDP port rule to iptables"
    iptables -I INPUT -s $remote_ip -j ACCEPT || \
        warning_msg "Failed to add remote IP rule to iptables"
    iptables -I INPUT -s ${vxlan_ip%/*} -j ACCEPT || \
        warning_msg "Failed to add VXLAN IP rule to iptables"
    
    # Create persistent service
    create_vxlan_service $vxlan_if $vni $local_ip $remote_ip $interface $port $vxlan_ip
    
    success_msg "VXLAN tunnel setup completed successfully"
    
    if [[ $role == "iran" ]]; then
        echo -e "${CYAN}+-----------------------------------------------+"
        echo -e "| ${YELLOW}Iran Server Configuration${NC}              |"
        echo -e "${CYAN}+-----------------------------------------------+"
        echo -e "| ${GREEN}VXLAN IP${NC}         | 30.0.0.1             |"
        echo -e "| ${GREEN}Tunnel Port${NC}      | $port                |"
        echo -e "${CYAN}+-----------------------------------------------+${NC}"
    else
        echo -e "${CYAN}+-----------------------------------------------+"
        echo -e "| ${YELLOW}Kharej Server Configuration${NC}            |"
        echo -e "${CYAN}+-----------------------------------------------+"
        echo -e "| ${GREEN}VXLAN IP${NC}         | 30.0.0.2             |"
        echo -e "| ${GREEN}Tunnel Port${NC}      | $port                |"
        echo -e "${CYAN}+-----------------------------------------------+${NC}"
    fi
    
    return 0
}

# Function to create systemd service for VXLAN
create_vxlan_service() {
    local vxlan_if=$1
    local vni=$2
    local local_ip=$3
    local remote_ip=$4
    local interface=$5
    local port=$6
    local vxlan_ip=$7
    
    info_msg "Creating persistent VXLAN service..."
    
    # Create bridge script
    cat <<EOF > /usr/local/bin/vxlan_bridge.sh
#!/bin/bash

# Wait for network to be ready
while ! ping -c 1 -W 1 $remote_ip &> /dev/null; do
    sleep 1
done

# Create VXLAN interface
ip link add $vxlan_if type vxlan id $vni local $local_ip remote $remote_ip dev $interface dstport $port nolearning
ip addr add $vxlan_ip dev $vxlan_if
ip link set $vxlan_if up

# Add iptables rules
iptables -I INPUT -p udp --dport $port -j ACCEPT
iptables -I INPUT -s $remote_ip -j ACCEPT
iptables -I INPUT -s ${vxlan_ip%/*} -j ACCEPT
EOF
    
    chmod +x /usr/local/bin/vxlan_bridge.sh
    
    # Create systemd service
    cat <<EOF > /etc/systemd/system/vxlan-tunnel.service
[Unit]
Description=VXLAN Tunnel Interface
After=network.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/bin/vxlan_bridge.sh
TimeoutStartSec=300

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    systemctl enable vxlan-tunnel.service
    systemctl start vxlan-tunnel.service
    
    # Verify service is running
    if ! systemctl is-active --quiet vxlan-tunnel.service; then
        error_msg "Failed to start vxlan-tunnel service"
        return 1
    fi
    
    success_msg "VXLAN service created and started successfully"
    return 0
}

# Function to check tunnel status
check_tunnel_status() {
    local vxlan_count=$(ip -d link show | grep -c 'vxlan[0-9]\+')
    
    if [[ $vxlan_count -eq 0 ]]; then
        info_msg "No active VXLAN tunnels found"
        return 0
    fi
    
    echo -e "${CYAN}+-----------------------------------------------+"
    echo -e "| ${YELLOW}Active VXLAN Tunnels ($vxlan_count)${NC}               |"
    echo -e "${CYAN}+-----------------------------------------------+"
    
    ip -d link show | grep 'vxlan[0-9]\+' | while read -r line; do
        local iface=$(echo "$line" | awk -F: '{print $2}' | xargs)
        local vni=$(echo "$line" | grep -o 'vni [0-9]\+' | awk '{print $2}')
        local local_ip=$(ip -d link show "$iface" | grep -o 'local [0-9.]\+' | awk '{print $2}')
        local remote_ip=$(ip -d link show "$iface" | grep -o 'remote [0-9.]\+' | awk '{print $2}')
        local port=$(ip -d link show "$iface" | grep -o 'dstport [0-9]\+' | awk '{print $2}')
        
        echo -e "| ${GREEN}Interface${NC}  | $iface"
        echo -e "| ${GREEN}VNI${NC}        | $vni"
        echo -e "| ${GREEN}Local IP${NC}   | $local_ip"
        echo -e "| ${GREEN}Remote IP${NC}  | $remote_ip"
        echo -e "| ${GREEN}Port${NC}       | $port"
        echo -e "${CYAN}+-----------------------------------------------+${NC}"
    done
    
    return 0
}

# Function to update script
update_script() {
    info_msg "Checking for updates..."
    
    local temp_file="/tmp/vxlan_tunnel_updater.sh"
    
    if ! curl -fsSL "${GITHUB_REPO}/raw/main/scripts/vxlan_tunnel.sh" -o "$temp_file"; then
        error_msg "Failed to download updated script"
        return 1
    fi
    
    # Verify the downloaded script
    if ! grep -q "VXLAN Tunnel Script" "$temp_file"; then
        error_msg "Downloaded file doesn't appear to be a valid script"
        rm -f "$temp_file"
        return 1
    fi
    
    # Compare versions
    local current_version=$VERSION
    local new_version=$(grep -m1 "VERSION=" "$temp_file" | cut -d'"' -f2)
    
    if [[ "$current_version" == "$new_version" ]]; then
        info_msg "You already have the latest version ($VERSION)"
        rm -f "$temp_file"
        return 0
    fi
    
    info_msg "Updating from version $current_version to $new_version"
    
    # Backup current script
    local backup_file="${0}.bak"
    cp "$0" "$backup_file" || {
        error_msg "Failed to backup current script"
        rm -f "$temp_file"
        return 1
    }
    
    # Replace script
    if ! mv "$temp_file" "$0"; then
        error_msg "Failed to replace script"
        rm -f "$temp_file"
        return 1
    fi
    
    chmod +x "$0"
    
    success_msg "Script updated successfully to version $new_version"
    info_msg "Please run the script again to use the new version"
    
    exit 0
}

# ---------------- MAIN PROGRAM ----------------
check_root
install_dependencies || {
    error_msg "Failed to install required dependencies"
    exit 1
}

while true; do
    show_menu
    read -p "Enter your choice [0-5]: " choice
    
    case $choice in
        1)
            # Install new tunnel
            echo "Choose server role:"
            echo "1. Iran"
            echo "2. Kharej"
            read -p "Enter choice (1/2): " role_choice
            
            if [[ "$role_choice" != "1" && "$role_choice" != "2" ]]; then
                error_msg "Invalid choice"
                sleep 2
                continue
            fi
            
            # Get IP addresses
            while true; do
                read -p "Enter IRAN IP: " iran_ip
                if validate_ip "$iran_ip"; then
                    break
                else
                    error_msg "Invalid IP address"
                fi
            done
            
            while true; do
                read -p "Enter Kharej IP: " kharej_ip
                if validate_ip "$kharej_ip"; then
                    break
                else
                    error_msg "Invalid IP address"
                fi
            done
            
            # Get port
            while true; do
                read -p "Enter tunnel port (1-65535): " port
                if validate_port "$port"; then
                    break
                else
                    error_msg "Invalid port number"
                fi
            done
            
            # Configure HAProxy for Iran server
            if [[ "$role_choice" == "1" ]]; then
                read -p "Configure HAProxy for port forwarding? [y/N]: " haproxy_choice
                if [[ "$haproxy_choice" =~ ^[Yy]$ ]]; then
                    configure_haproxy || {
                        error_msg "HAProxy configuration failed"
                        sleep 3
                        continue
                    }
                fi
            fi
            
            # Setup VXLAN
            if [[ "$role_choice" == "1" ]]; then
                role="iran"
            else
                role="kharej"
            fi
            
            setup_vxlan "$role" "$iran_ip" "$kharej_ip" "$port" || {
                error_msg "VXLAN setup failed"
            }
            
            read -p "Press Enter to continue..."
            ;;
        2)
            # Uninstall tunnel(s)
            read -p "Are you sure you want to uninstall all tunnels? [y/N]: " confirm
            if [[ "$confirm" =~ ^[Yy]$ ]]; then
                uninstall_vxlan
            fi
            read -p "Press Enter to continue..."
            ;;
        3)
            # Install BBR
            install_bbr
            read -p "Press Enter to continue..."
            ;;
        4)
            # Check tunnel status
            check_tunnel_status
            read -p "Press Enter to continue..."
            ;;
        5)
            # Update script
            update_script
            read -p "Press Enter to continue..."
            ;;
        0)
            # Exit
            info_msg "Goodbye!"
            exit 0
            ;;
        *)
            error_msg "Invalid option"
            sleep 1
            ;;
    esac
done
