#!/bin/bash
# Malang Panel Agent Installation Script
# Usage: curl -sSL https://budhilaw.com/install.sh | bash -s -- --token TOKEN --id ID --server SERVER

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default values
AGENT_TOKEN=""
AGENT_ID=""
SERVER_ADDRESS=""
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/malangpanel"
SERVICE_NAME="malangpanel-agent"
BINARY_URL="https://github.com/budhilaw/malangpanel/releases/latest/download/malangpanel-agent-linux-amd64"

# Print banner
print_banner() {
    echo -e "${BLUE}"
    echo "  __  __       _                   ____                  _ "
    echo " |  \/  | __ _| | __ _ _ __   __ _|  _ \ __ _ _ __   ___| |"
    echo " | |\/| |/ _\` | |/ _\` | '_ \ / _\` | |_) / _\` | '_ \ / _ \ |"
    echo " | |  | | (_| | | (_| | | | | (_| |  __/ (_| | | | |  __/ |"
    echo " |_|  |_|\__,_|_|\__,_|_| |_|\__, |_|   \__,_|_| |_|\___|_|"
    echo "                            |___/                          "
    echo -e "${NC}"
    echo -e "${GREEN}Agent Installation Script${NC}"
    echo ""
}

# Print step
print_step() {
    echo -e "${BLUE}[*]${NC} $1"
}

# Print success
print_success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

# Print error
print_error() {
    echo -e "${RED}[✗]${NC} $1"
}

# Print warning
print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

# Parse arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --token)
                AGENT_TOKEN="$2"
                shift 2
                ;;
            --id)
                AGENT_ID="$2"
                shift 2
                ;;
            --server)
                SERVER_ADDRESS="$2"
                shift 2
                ;;
            --help)
                echo "Usage: $0 --token TOKEN --id ID --server SERVER"
                echo ""
                echo "Options:"
                echo "  --token   Authentication token (required)"
                echo "  --id      Agent ID (required)"
                echo "  --server  Control plane server address (required)"
                echo "            Format: hostname:port (e.g., panel.example.com:9443)"
                exit 0
                ;;
            *)
                print_error "Unknown option: $1"
                exit 1
                ;;
        esac
    done
}

# Validate required arguments
validate_args() {
    if [ -z "$AGENT_TOKEN" ]; then
        print_error "Missing required argument: --token"
        exit 1
    fi
    if [ -z "$AGENT_ID" ]; then
        print_error "Missing required argument: --id"
        exit 1
    fi
    if [ -z "$SERVER_ADDRESS" ]; then
        print_error "Missing required argument: --server"
        exit 1
    fi
}

# Check if running as root
check_root() {
    if [ "$EUID" -ne 0 ]; then
        print_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

# Detect architecture
detect_arch() {
    ARCH=$(uname -m)
    case $ARCH in
        x86_64)
            BINARY_URL="https://github.com/budhilaw/malangpanel/releases/latest/download/malangpanel-agent-linux-amd64"
            ;;
        aarch64|arm64)
            BINARY_URL="https://github.com/budhilaw/malangpanel/releases/latest/download/malangpanel-agent-linux-arm64"
            ;;
        *)
            print_error "Unsupported architecture: $ARCH"
            exit 1
            ;;
    esac
    print_step "Detected architecture: $ARCH"
}

# Download agent binary
download_agent() {
    print_step "Downloading agent binary..."
    
    # Create install directory
    mkdir -p "$INSTALL_DIR"
    
    # Download binary
    if command -v curl &> /dev/null; then
        curl -sSL "$BINARY_URL" -o "$INSTALL_DIR/$SERVICE_NAME"
    elif command -v wget &> /dev/null; then
        wget -q "$BINARY_URL" -O "$INSTALL_DIR/$SERVICE_NAME"
    else
        print_error "Neither curl nor wget found. Please install one of them."
        exit 1
    fi
    
    # Make executable
    chmod +x "$INSTALL_DIR/$SERVICE_NAME"
    
    print_success "Agent downloaded to $INSTALL_DIR/$SERVICE_NAME"
}

# Create config directory
create_config_dir() {
    print_step "Creating configuration directory..."
    mkdir -p "$CONFIG_DIR"
    print_success "Configuration directory created: $CONFIG_DIR"
}

# Create systemd service
create_systemd_service() {
    print_step "Creating systemd service..."
    
    cat > "/etc/systemd/system/${SERVICE_NAME}.service" << EOF
[Unit]
Description=Malang Panel Agent
After=network.target

[Service]
Type=simple
User=root
ExecStart=${INSTALL_DIR}/${SERVICE_NAME} -token "${AGENT_TOKEN}" -id "${AGENT_ID}" -server "${SERVER_ADDRESS}"
Restart=always
RestartSec=5
StandardOutput=append:/var/log/${SERVICE_NAME}.log
StandardError=append:/var/log/${SERVICE_NAME}.log
Environment=PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

[Install]
WantedBy=multi-user.target
EOF
    
    # Reload systemd
    systemctl daemon-reload
    
    print_success "Systemd service created"
}

# Enable and start service
start_service() {
    print_step "Starting agent service..."
    
    systemctl enable "$SERVICE_NAME" --quiet
    systemctl start "$SERVICE_NAME"
    
    # Wait a moment and check status
    sleep 2
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        print_success "Agent service started successfully"
    else
        print_warning "Service may not have started correctly. Check logs with: journalctl -u $SERVICE_NAME"
    fi
}

# Print completion message
print_completion() {
    echo ""
    echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}  Installation Complete!${NC}"
    echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
    echo ""
    echo "Agent ID:     $AGENT_ID"
    echo "Server:       $SERVER_ADDRESS"
    echo ""
    echo "Useful commands:"
    echo "  View logs:     journalctl -u $SERVICE_NAME -f"
    echo "  Check status:  systemctl status $SERVICE_NAME"
    echo "  Restart:       systemctl restart $SERVICE_NAME"
    echo "  Stop:          systemctl stop $SERVICE_NAME"
    echo ""
    echo "Config file:   $CONFIG_DIR/agent.yaml"
    echo "Binary:        $INSTALL_DIR/$SERVICE_NAME"
    echo ""
}

# Main installation flow
main() {
    print_banner
    parse_args "$@"
    validate_args
    check_root
    detect_arch
    download_agent
    create_config_dir
    create_systemd_service
    start_service
    print_completion
}

# Run main
main "$@"
