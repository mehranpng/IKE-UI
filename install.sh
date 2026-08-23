#!/usr/bin/env bash
set -e

REPO_URL="https://github.com/mehranpng/IKE-UI.git"
APP_VERSION="1.7.1"
INSTALL_DIR="/opt/ike-ui"
PANEL_DIR="${INSTALL_DIR}/panel"
DB_DIR="/etc/strongswan-panel"
DB_PATH="${DB_DIR}/panel.db"
SECRETS_PATH="/etc/ipsec.secrets"
SECRET_KEY_PATH="${DB_DIR}/secret.key"
BIN_PATH="/usr/local/bin/ike-ui"
ALT_BIN_PATH="/usr/bin/ike-ui"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

is_reserved_path() {
    local p
    p=$(echo "$1" | sed -e 's|^/*||' -e 's|/*$||' | tr '[:upper:]' '[:lower:]')
    case "$p" in
        login|logout|settings|user|admin|api|backup|restore|static|sub|subscription)
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

generate_rand_user() {
    tr -dc 'a-z' < /dev/urandom 2>/dev/null | head -c 8 || python3 -c "import secrets, string; print(''.join(secrets.choice(string.ascii_lowercase) for _ in range(8)))"
}

generate_rand_pass() {
    tr -dc 'a-zA-Z0-9' < /dev/urandom 2>/dev/null | head -c 12 || python3 -c "import secrets, string; print(''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(12)))"
}

generate_rand_path() {
    tr -dc 'a-zA-Z0-9' < /dev/urandom 2>/dev/null | head -c 16 || python3 -c "import secrets, string; print(''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(16)))"
}

is_port_in_use() {
    local p="$1"
    if [ -z "$p" ]; then
        return 1
    fi
    local proc=""
    if command -v ss >/dev/null 2>&1; then
        proc=$(ss -tulpn 2>/dev/null | grep -E "[: ]${p}\b" || true)
    elif command -v netstat >/dev/null 2>&1; then
        proc=$(netstat -tulpn 2>/dev/null | grep -E "[: ]${p}\b" || true)
    elif command -v lsof >/dev/null 2>&1; then
        proc=$(lsof -iTCP:"${p}" -sTCP:LISTEN 2>/dev/null || true)
    fi

    if [ -n "$proc" ]; then
        if echo "$proc" | grep -qv "nginx"; then
            return 0
        fi
        return 1
    fi

    python3 -c "
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('0.0.0.0', int('$p')))
    s.close()
    sys.exit(1)
except Exception:
    sys.exit(0)
" 2>/dev/null && return 0

    return 1
}

get_current_domain() {
    local d=""
    if [ -f /etc/nginx/sites-available/ike-ui ]; then
        d=$(grep -oP 'server_name\s+\K[^;]+' /etc/nginx/sites-available/ike-ui 2>/dev/null | head -n1 | tr -d ' ' || true)
    fi
    if [ -z "$d" ] && [ -f "${DB_PATH}" ]; then
        d=$(sqlite3 "${DB_PATH}" "SELECT value FROM system_config WHERE key='server_domain';" 2>/dev/null || true)
    fi
    if [ -z "$d" ] && [ -f /etc/systemd/system/ike-ui.service ]; then
        d=$(grep -oP 'Environment="SERVER_DOMAIN=\K[^"]+' /etc/systemd/system/ike-ui.service 2>/dev/null || true)
    fi
    echo "$d"
}

get_current_port() {
    local p=""
    if [ -f /etc/nginx/sites-available/ike-ui ]; then
        p=$(grep -oP 'listen\s+\K[0-9]+(?=\s+ssl)' /etc/nginx/sites-available/ike-ui 2>/dev/null | head -n1 || true)
    fi
    if [ -z "$p" ] && [ -f "${DB_PATH}" ]; then
        p=$(sqlite3 "${DB_PATH}" "SELECT value FROM system_config WHERE key='panel_port';" 2>/dev/null || true)
    fi
    echo "${p:-443}"
}

get_current_path() {
    local path=""
    if [ -f /etc/nginx/sites-available/ike-ui ]; then
        path=$(grep -oP 'location\s+/\K[^/{\s]+(?=/\s*\{)' /etc/nginx/sites-available/ike-ui 2>/dev/null | head -n1 || true)
    fi
    if [ -z "$path" ] && [ -f "${DB_PATH}" ]; then
        path=$(sqlite3 "${DB_PATH}" "SELECT value FROM system_config WHERE key='panel_path';" 2>/dev/null || true)
    fi
    echo "$path"
}

generate_nginx_config() {
    local domain="$1"
    local port="${2:-443}"
    local path="$3"

    path=$(echo "$path" | sed -e 's|^/*||' -e 's|/*$||')

    local redirect_port=""
    if [ "$port" != "443" ]; then
        redirect_port=":${port}"
    fi

    cat > /etc/nginx/sites-available/ike-ui << NGINX_EOF
server {
    listen 80;
    server_name ${domain};
    return 301 https://\$host${redirect_port}\$request_uri;
}

server {
    listen ${port} ssl http2;
    server_name ${domain};

    ssl_certificate /etc/letsencrypt/live/${domain}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/${domain}/privkey.pem;

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
NGINX_EOF

    if [ -n "$path" ]; then
        cat >> /etc/nginx/sites-available/ike-ui << NGINX_EOF

    location = /${path} {
        return 301 /${path}/;
    }

    location /${path}/ {
        proxy_pass http://127.0.0.1:8000/;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header X-Forwarded-Port \$server_port;
        proxy_set_header X-Forwarded-Prefix /${path};

        proxy_buffering off;
        proxy_cache off;
        proxy_read_timeout 86400s;
        proxy_set_header Connection '';
        proxy_http_version 1.1;
        chunked_transfer_encoding off;
    }

    location /sub {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header X-Forwarded-Port \$server_port;
        proxy_set_header X-Forwarded-Prefix "";

        proxy_buffering off;
        proxy_cache off;
        proxy_read_timeout 86400s;
        proxy_set_header Connection '';
        proxy_http_version 1.1;
        chunked_transfer_encoding off;
    }

    location /static {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header X-Forwarded-Port \$server_port;
        proxy_set_header X-Forwarded-Prefix "";
    }

    location / {
        return 404;
    }
}
NGINX_EOF
    else
        cat >> /etc/nginx/sites-available/ike-ui << NGINX_EOF

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header X-Forwarded-Port \$server_port;
        proxy_set_header X-Forwarded-Prefix "";

        proxy_buffering off;
        proxy_cache off;
        proxy_read_timeout 86400s;
        proxy_set_header Connection '';
        proxy_http_version 1.1;
        chunked_transfer_encoding off;
    }
}
NGINX_EOF
    fi

    rm -f /etc/nginx/sites-enabled/default
    ln -sf /etc/nginx/sites-available/ike-ui /etc/nginx/sites-enabled/ike-ui
}

show_banner() {
    clear 2>/dev/null || true
    local cur_ver="$APP_VERSION"
    if [ -f "${INSTALL_DIR}/install.sh" ]; then
        local disk_ver
        disk_ver=$(grep -oP '^APP_VERSION=["\x27]?\K[^"\x27\s]+' "${INSTALL_DIR}/install.sh" 2>/dev/null || true)
        if [ -n "$disk_ver" ]; then
            cur_ver="$disk_ver"
            APP_VERSION="$disk_ver"
        fi
    fi
    echo -e "${PURPLE}${BOLD}"
    cat << BANNER
  ██╗██╗  ██╗███████╗      ██╗   ██╗██╗
  ██║██║ ██╔╝██╔════╝      ██║   ██║██║
  ██║█████╔╝ █████╗  █████╗██║   ██║██║
  ██║██╔═██╗ ██╔══╝  ╚════╝██║   ██║██║
  ██║██║  ██╗███████╗      ╚██████╔╝██║
  ╚═╝╚═╝  ╚═╝╚══════╝       ╚═════╝ ╚═╝
         IKE-UI Manager v${cur_ver}
BANNER
    echo -e "${CYAN}====================================================${NC}"

    local panel_domain
    panel_domain=$(get_current_domain)
    local panel_port
    panel_port=$(get_current_port)
    local panel_path
    panel_path=$(get_current_path)

    if [ -n "$panel_domain" ]; then
        local status_badge="${GREEN}● Online${NC}"
        if ! systemctl is-active --quiet ike-ui 2>/dev/null && ! systemctl is-active --quiet ikev2-panel 2>/dev/null; then
            status_badge="${RED}○ Stopped${NC}"
        fi
        local port_display=""
        if [ "$panel_port" != "443" ] && [ -n "$panel_port" ]; then
            port_display=":${panel_port}"
        fi
        local path_display=""
        if [ -n "$panel_path" ] && [ "$panel_path" != "/" ]; then
            path_display="/${panel_path#/}"
        fi
        echo -e " ${BOLD}Panel URL:${NC} ${CYAN}https://${panel_domain}${port_display}${path_display}${NC} [${status_badge}]"
        echo -e "${CYAN}====================================================${NC}"
    fi
    echo -e "${NC}"
}

check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        echo -e "${RED}[X] Error: This script must be run as root (or with sudo).${NC}" >&2
        exit 1
    fi
}

check_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$ID
    else
        echo -e "${RED}[X] Unsupported Linux distribution. Debian/Ubuntu is required.${NC}" >&2
        exit 1
    fi

    if [[ "$OS" != "ubuntu" && "$OS" != "debian" && "$OS" != "raspbian" && "$OS" != "kali" && "$OS" != "pop" && "$OS" != "linuxmint" ]]; then
        echo -e "${YELLOW}[!] Warning: Your OS ($OS) is not Debian/Ubuntu based.${NC}"
        echo -e "${YELLOW}    IKE-UI relies on apt-get for strongSwan and system services.${NC}"
        read -rp "Do you want to continue anyway? [y/N]: " confirm
        if [[ ! "$confirm" =~ ^[yY]([eE][sS])?$ ]]; then
            echo -e "${RED}Installation cancelled.${NC}"
            exit 1
        fi
    fi
}

detect_network() {
    NET_IFACE=$(ip route get 1.1.1.1 2>/dev/null | awk '{print $5; exit}')
    if [ -z "$NET_IFACE" ]; then
        NET_IFACE=$(ip route show default 2>/dev/null | awk '{print $5; exit}')
    fi
    if [ -z "$NET_IFACE" ]; then
        NET_IFACE="eth0"
    fi

    SERVER_IP=$(curl -s4 --max-time 5 https://api.ipify.org || curl -s4 --max-time 5 https://ifconfig.me || echo "Unknown")
}

setup_cli_shortcut() {
    mkdir -p "$(dirname "$BIN_PATH")"
    cat > "$BIN_PATH" << 'CLI_EOF'
#!/usr/bin/env bash
exec /opt/ike-ui/install.sh "$@"
CLI_EOF
    chmod +x "$BIN_PATH"
    ln -sf "$BIN_PATH" "$ALT_BIN_PATH" 2>/dev/null || true
}

is_installed() {
    if [ -f /etc/systemd/system/ike-ui.service ] || [ -f "${DB_PATH}" ] || [ -f "${PANEL_DIR}/app.py" ]; then
        return 0
    fi
    return 1
}

bootstrap_environment() {
    SCRIPT_SOURCE="${BASH_SOURCE[0]}"
    if [ -f "$SCRIPT_SOURCE" ]; then
        CURRENT_DIR="$(cd "$(dirname "$SCRIPT_SOURCE")" && pwd)"
    else
        CURRENT_DIR=""
    fi

    if [ "$CURRENT_DIR" != "$INSTALL_DIR" ]; then
        check_root
        check_os

        local is_first_install=0
        if ! is_installed; then
            is_first_install=1
            read -rp "Do you want to install IKE-UI panel? [y/n]: " confirm_install
            if [[ ! "$confirm_install" =~ ^[yY]([eE][sS])?$ ]]; then
                echo -e "${YELLOW}[*] Installation cancelled.${NC}"
                exit 0
            fi
        else
            show_banner
        fi

        echo -e "${CYAN}[*] Installing base dependencies (git, curl, ca-certificates)...${NC}"
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -y
        apt-get install -y curl git ca-certificates tar iptables sudo

        echo -e "${CYAN}[*] Setting up IKE-UI in ${INSTALL_DIR}...${NC}"
        mkdir -p "$(dirname "$INSTALL_DIR")"

        if [ -d "$INSTALL_DIR/.git" ]; then
            cd "$INSTALL_DIR"
            git remote set-url origin "$REPO_URL" 2>/dev/null || true
            git fetch --all --tags --prune
            git reset --hard origin/main
        else
            if [ -d "$INSTALL_DIR" ]; then
                rm -rf "${INSTALL_DIR:?}"/*
            fi
            git clone -b main "$REPO_URL" "$INSTALL_DIR"
        fi

        chmod +x "${INSTALL_DIR}/install.sh"
        setup_cli_shortcut

        echo -e "${GREEN}[+] Initialization complete.${NC}"
        echo ""

        if [ "$is_first_install" -eq 1 ] && [ -z "$1" ]; then
            exec "${INSTALL_DIR}/install.sh" --first-install
        else
            exec "${INSTALL_DIR}/install.sh" "$@"
        fi
    fi
}

apply_firewall() {
    detect_network
    iptables -t nat -C POSTROUTING -s 10.10.10.0/24 -o "$NET_IFACE" -j MASQUERADE 2>/dev/null || \
        iptables -t nat -A POSTROUTING -s 10.10.10.0/24 -o "$NET_IFACE" -j MASQUERADE

    iptables -C FORWARD -s 10.10.10.0/24 -j ACCEPT 2>/dev/null || \
        iptables -A FORWARD -s 10.10.10.0/24 -j ACCEPT

    iptables -C FORWARD -d 10.10.10.0/24 -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || \
        iptables -A FORWARD -d 10.10.10.0/24 -m state --state RELATED,ESTABLISHED -j ACCEPT

    iptables -t mangle -C FORWARD -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1360 2>/dev/null || \
        iptables -t mangle -A FORWARD -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1360

    local current_port
    current_port=$(get_current_port)

    if command -v ufw >/dev/null 2>&1; then
        ufw allow 500/udp >/dev/null 2>&1 || true
        ufw allow 4500/udp >/dev/null 2>&1 || true
        ufw allow 80/tcp >/dev/null 2>&1 || true
        ufw allow 443/tcp >/dev/null 2>&1 || true
        if [ -n "$current_port" ] && [ "$current_port" != "443" ] && [ "$current_port" != "80" ]; then
            ufw allow "${current_port}/tcp" >/dev/null 2>&1 || true
        fi
    fi

    if [ -n "$current_port" ] && [ "$current_port" != "443" ] && [ "$current_port" != "80" ]; then
        iptables -C INPUT -p tcp --dport "${current_port}" -j ACCEPT 2>/dev/null || \
            iptables -A INPUT -p tcp --dport "${current_port}" -j ACCEPT 2>/dev/null || true
    fi
}

install_all() {
    show_banner
    detect_network

    if [ -f /etc/systemd/system/ike-ui.service ] || [ -f "${DB_PATH}" ] || [ -d "${PANEL_DIR}" ]; then
        echo -e "${YELLOW}[!] Warning: IKE-UI is already installed on this server.${NC}"
        read -rp "Are you sure you want to reinstall / re-deploy? [y/N]: " confirm_reinstall
        if [[ ! "$confirm_reinstall" =~ ^[yY]([eE][sS])?$ ]]; then
            echo -e "${YELLOW}[*] Reinstallation cancelled.${NC}"
            return 0 2>/dev/null || exit 0
        fi
        echo ""
    fi

    echo -e "${YELLOW}[*] Primary Network Interface:${NC} ${BOLD}${NET_IFACE}${NC}"
    echo -e "${YELLOW}[*] Public IP Address:${NC} ${BOLD}${SERVER_IP}${NC}"
    echo ""

    if [ -n "$1" ]; then
        DOMAIN="$1"
    else
        read -rp "Enter Domain Name (e.g. vpn.example.com): " DOMAIN
    fi

    if [ -z "$DOMAIN" ]; then
        echo -e "${RED}[X] Error: Domain name cannot be empty.${NC}"
        exit 1
    fi

    echo ""
    while true; do
        read -rp "Enter Panel Web Port [default: 443]: " PANEL_PORT
        PANEL_PORT=${PANEL_PORT:-443}
        if [[ ! "$PANEL_PORT" =~ ^[0-9]+$ ]] || [ "$PANEL_PORT" -lt 1 ] || [ "$PANEL_PORT" -gt 65535 ]; then
            echo -e "${RED}[X] Invalid port number. Must be between 1 and 65535.${NC}"
            continue
        fi
        if [ "$PANEL_PORT" -eq 500 ] || [ "$PANEL_PORT" -eq 4500 ]; then
            echo -e "${RED}[X] Port ${PANEL_PORT} is reserved for StrongSwan IKEv2 VPN.${NC}"
            continue
        fi
        if [ "$PANEL_PORT" -eq 80 ]; then
            echo -e "${RED}[X] Port 80 is reserved for Let's Encrypt / HTTP validation.${NC}"
            continue
        fi
        if [ "$PANEL_PORT" -ne 443 ] && is_port_in_use "$PANEL_PORT"; then
            echo -e "${RED}[X] Port ${PANEL_PORT} is currently in use by another service! Please choose a different port.${NC}"
            continue
        fi
        break
    done

    echo ""
    while true; do
        local rand_path
        rand_path=$(generate_rand_path)
        read -rp "Enter Panel Secret Path [default: random 16-chars (${rand_path})]: " PANEL_PATH
        PANEL_PATH=${PANEL_PATH:-$rand_path}
        PANEL_PATH=$(echo "$PANEL_PATH" | sed -e 's|^/*||' -e 's|/*$||' | tr -cd 'a-zA-Z0-9_-')
        if [ -z "$PANEL_PATH" ]; then
            PANEL_PATH="$rand_path"
        fi
        if is_reserved_path "$PANEL_PATH"; then
            echo -e "${RED}[X] Error: '/${PANEL_PATH}' is a reserved system path and cannot be used as secret path.${NC}"
            echo -e "${YELLOW}[!] Reserved paths: login, logout, settings, user, admin, api, backup, restore, static, sub, subscription.${NC}"
        else
            break
        fi
    done

    echo ""
    local rand_user
    rand_user=$(generate_rand_user)
    read -rp "Enter Admin Username [default: random 8-letters (${rand_user})]: " ADMIN_USER
    ADMIN_USER=${ADMIN_USER:-$rand_user}
    ADMIN_USER=$(echo "$ADMIN_USER" | tr -cd 'a-zA-Z0-9_@.-')
    if [ -z "$ADMIN_USER" ]; then
        ADMIN_USER="$rand_user"
    fi

    local rand_pass
    rand_pass=$(generate_rand_pass)
    read -rp "Enter Admin Password [default: random 12-chars (${rand_pass})]: " ADMIN_PASS
    ADMIN_PASS=${ADMIN_PASS:-$rand_pass}
    if [ -z "$ADMIN_PASS" ]; then
        ADMIN_PASS="$rand_pass"
    fi

    local port_str=""
    if [ "$PANEL_PORT" != "443" ]; then
        port_str=":${PANEL_PORT}"
    fi
    local path_str=""
    if [ -n "$PANEL_PATH" ] && [ "$PANEL_PATH" != "/" ]; then
        path_str="/${PANEL_PATH}"
    fi
    local full_panel_url="https://${DOMAIN}${port_str}${path_str}"

    echo ""
    echo -e "${YELLOW}[*] Installation Summary:${NC}"
    echo -e "  • Domain:      ${CYAN}${DOMAIN}${NC}"
    echo -e "  • Web Port:    ${CYAN}${PANEL_PORT}${NC}"
    echo -e "  • Secret Path: ${CYAN}/${PANEL_PATH}${NC}"
    echo -e "  • Panel URL:   ${CYAN}${full_panel_url}${NC}"
    echo -e "  • Admin User:  ${CYAN}${ADMIN_USER}${NC}"
    echo -e "  • Admin Pass:  ${CYAN}${ADMIN_PASS}${NC}"
    echo -e "  • IP/Iface:    ${CYAN}${SERVER_IP} (${NET_IFACE})${NC}"
    echo ""
    read -rp "Ready to proceed with installation? [y/N]: " confirm_install
    if [[ ! "$confirm_install" =~ ^[yY]([eE][sS])?$ ]]; then
        echo -e "${YELLOW}[*] Installation cancelled.${NC}"
        return 0 2>/dev/null || exit 0
    fi

    echo ""
    echo -e "${CYAN}[1/7] Installing dependencies...${NC}"
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y
    apt-get install -y \
        strongswan \
        strongswan-pki \
        libcharon-extra-plugins \
        libcharon-extauth-plugins \
        libstrongswan-extra-plugins \
        libstrongswan-standard-plugins \
        certbot \
        nginx \
        python3 \
        python3-pip \
        python3-venv \
        sqlite3 \
        curl \
        git \
        iptables

    setup_cli_shortcut

    echo -e "${CYAN}[2/7] Checking Let's Encrypt SSL for ${DOMAIN}...${NC}"
    systemctl stop nginx 2>/dev/null || true

    if [ -d "/etc/letsencrypt/live/${DOMAIN}" ] && [ -f "/etc/letsencrypt/live/${DOMAIN}/fullchain.pem" ]; then
        echo -e "${GREEN}[+] Existing certificate found for ${DOMAIN}.${NC}"
    else
        certbot certonly --standalone \
            --agree-tos \
            --no-eff-email \
            -m "admin@${DOMAIN}" \
            -d "${DOMAIN}" \
            --key-type rsa \
            --rsa-key-size 2048 \
            --non-interactive
    fi

    echo -e "${CYAN}[3/7] Setting up certificates and auto-renewal hook...${NC}"
    mkdir -p /etc/ipsec.d/certs /etc/ipsec.d/cacerts /etc/ipsec.d/private
    if [ -f "/etc/letsencrypt/live/${DOMAIN}/fullchain.pem" ]; then
        cp "/etc/letsencrypt/live/${DOMAIN}/fullchain.pem" /etc/ipsec.d/certs/cert.pem
    else
        cp "/etc/letsencrypt/live/${DOMAIN}/cert.pem" /etc/ipsec.d/certs/cert.pem
    fi
    cp "/etc/letsencrypt/live/${DOMAIN}/privkey.pem" /etc/ipsec.d/private/privkey.pem
    rm -f /etc/ipsec.d/cacerts/*
    if [ -f "/etc/letsencrypt/live/${DOMAIN}/chain.pem" ]; then
        python3 -c "
import re
with open('/etc/letsencrypt/live/${DOMAIN}/chain.pem', 'r') as f:
    text = f.read()
certs = re.findall(r'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----', text, re.DOTALL)
if certs:
    for i, c in enumerate(certs):
        with open(f'/etc/ipsec.d/cacerts/chain_{i}.pem', 'w') as out:
            out.write(c.strip() + '\n')
else:
    with open('/etc/ipsec.d/cacerts/chain.pem', 'w') as out:
        out.write(text)
" 2>/dev/null || cp "/etc/letsencrypt/live/${DOMAIN}/chain.pem" /etc/ipsec.d/cacerts/chain.pem
    fi

    chmod 600 /etc/ipsec.d/private/privkey.pem
    chmod 644 /etc/ipsec.d/certs/cert.pem /etc/ipsec.d/cacerts/* 2>/dev/null || true

    mkdir -p /etc/letsencrypt/renewal-hooks/deploy
    cat > /etc/letsencrypt/renewal-hooks/deploy/strongswan.sh << 'RENEW_EOF'
#!/usr/bin/env bash
for domain_dir in /etc/letsencrypt/live/*; do
    if [ -d "$domain_dir" ] && { [ -f "$domain_dir/fullchain.pem" ] || [ -f "$domain_dir/cert.pem" ]; }; then
        if [ -f "$domain_dir/fullchain.pem" ]; then
            cp "$domain_dir/fullchain.pem" /etc/ipsec.d/certs/cert.pem
        else
            cp "$domain_dir/cert.pem" /etc/ipsec.d/certs/cert.pem
        fi
        cp "$domain_dir/privkey.pem" /etc/ipsec.d/private/privkey.pem
        rm -f /etc/ipsec.d/cacerts/*
        if [ -f "$domain_dir/chain.pem" ]; then
            python3 -c "
import re
with open('$domain_dir/chain.pem', 'r') as f:
    text = f.read()
certs = re.findall(r'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----', text, re.DOTALL)
if certs:
    for i, c in enumerate(certs):
        with open(f'/etc/ipsec.d/cacerts/chain_{i}.pem', 'w') as out:
            out.write(c.strip() + '\n')
else:
    with open('/etc/ipsec.d/cacerts/chain.pem', 'w') as out:
        out.write(text)
" 2>/dev/null || cp "$domain_dir/chain.pem" /etc/ipsec.d/cacerts/chain.pem
        fi
        chmod 600 /etc/ipsec.d/private/privkey.pem
        chmod 644 /etc/ipsec.d/certs/cert.pem /etc/ipsec.d/cacerts/* 2>/dev/null || true
        ipsec rereadall 2>/dev/null || true
        ipsec restart 2>/dev/null || systemctl restart strongswan-starter.service 2>/dev/null || systemctl restart strongswan.service 2>/dev/null || true
        systemctl reload nginx 2>/dev/null || true
        break
    fi
done
RENEW_EOF
    chmod +x /etc/letsencrypt/renewal-hooks/deploy/strongswan.sh

    echo -e "${CYAN}[4/7] Generating StrongSwan configs...${NC}"
    cat > /etc/ipsec.conf << CONF_EOF
config setup
    charondebug="ike 1, knl 1, cfg 0"
    uniqueids=never

conn %default
    keyexchange=ikev2
    ike=aes256gcm16-prfsha384-ecp384,aes256gcm16-prfsha256-ecp256,aes256-sha256-modp2048,aes256-sha1-modp2048,aes256-sha1-modp1024,aes128-sha1-modp1024,3des-sha1-modp1024!
    esp=aes256gcm16-ecp384,aes256gcm16,aes256-sha256,aes256-sha1,aes128-sha256,aes128-sha1,3des-sha1!
    dpdaction=clear
    dpddelay=30s
    dpdtimeout=120s

conn ikev2-vpn
    auto=add
    left=%any
    leftid=@${DOMAIN}
    leftcert=cert.pem
    leftsendcert=always
    leftsubnet=0.0.0.0/0
    right=%any
    rightid=%any
    rightauth=eap-mschapv2
    rightsourceip=10.10.10.0/24
    rightdns=1.1.1.1,8.8.8.8
    rightsendcert=never
    eap_identity=%identity
CONF_EOF

    mkdir -p "${DB_DIR}"
    if [ ! -f "${SECRETS_PATH}" ]; then
        cat > "${SECRETS_PATH}" << 'SEC_EOF'
: RSA privkey.pem
SEC_EOF
        chmod 600 "${SECRETS_PATH}"
    fi

    echo -e "${CYAN}[5/7] Configuring network, forwarding and firewall rules...${NC}"
    cat > /etc/sysctl.d/99-ikev2-vpn.conf << 'SYSCTL_EOF'
net.ipv4.ip_forward = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
SYSCTL_EOF
    sysctl -p /etc/sysctl.d/99-ikev2-vpn.conf >/dev/null 2>&1 || true

    apply_firewall

    cat > /etc/systemd/system/ike-rules.service << 'RULES_EOF'
[Unit]
Description=IKE-UI Firewall & NAT Rules
After=network.target

[Service]
Type=oneshot
ExecStart=/opt/ike-ui/install.sh --apply-firewall
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
RULES_EOF

    systemctl daemon-reload
    systemctl enable ike-rules.service

    echo -e "${CYAN}[6/7] Setting up Python virtual environment & dependencies...${NC}"
    python3 -m venv "${INSTALL_DIR}/venv"
    "${INSTALL_DIR}/venv/bin/pip" install --upgrade pip >/dev/null
    "${INSTALL_DIR}/venv/bin/pip" install -r "${INSTALL_DIR}/panel/requirements.txt" >/dev/null

    SERVER_DOMAIN="${DOMAIN}" DB_PATH="${DB_PATH}" SECRETS_PATH="${SECRETS_PATH}" SECRET_KEY_PATH="${SECRET_KEY_PATH}" \
    VPN_USER_INFO=$("${INSTALL_DIR}/venv/bin/python" -c "
import sys
sys.path.insert(0, '${INSTALL_DIR}/panel')
import app
from werkzeug.security import generate_password_hash
app.init_db()
conn = app.get_db()
cursor = conn.cursor()
cursor.execute('SELECT id FROM admin LIMIT 1')
row = cursor.fetchone()
if row:
    cursor.execute('UPDATE admin SET username = ?, password_hash = ? WHERE id = ?', ('${ADMIN_USER}', generate_password_hash('${ADMIN_PASS}'), row['id']))
else:
    cursor.execute('INSERT INTO admin (username, password_hash) VALUES (?, ?)', ('${ADMIN_USER}', generate_password_hash('${ADMIN_PASS}')))

cursor.execute('''
    INSERT INTO system_config (key, value) VALUES ('server_domain', ?)
    ON CONFLICT(key) DO UPDATE SET value = excluded.value
''', ('${DOMAIN}',))
cursor.execute('''
    INSERT INTO system_config (key, value) VALUES ('panel_port', ?)
    ON CONFLICT(key) DO UPDATE SET value = excluded.value
''', ('${PANEL_PORT}',))
cursor.execute('''
    INSERT INTO system_config (key, value) VALUES ('panel_path', ?)
    ON CONFLICT(key) DO UPDATE SET value = excluded.value
''', ('${PANEL_PATH}',))

conn.commit()

cursor.execute('SELECT username, password FROM users ORDER BY id ASC LIMIT 1')
u = cursor.fetchone()
conn.close()
app.sync_ipsec_secrets()
if u:
    print(f'{u[\"username\"]}:{u[\"password\"]}')
else:
    print('user1:Generated')
" 2>/dev/null || echo "user1:Generated")

    DEFAULT_VPN_USER=$(echo "$VPN_USER_INFO" | cut -d: -f1)
    DEFAULT_VPN_PASS=$(echo "$VPN_USER_INFO" | cut -d: -f2)

    cat > /etc/systemd/system/ike-ui.service << SERVICE_EOF
[Unit]
Description=IKE-UI Management Panel
After=network.target strongswan-starter.service strongswan.service

[Service]
Type=simple
User=root
WorkingDirectory=${INSTALL_DIR}/panel
Environment="SERVER_DOMAIN=${DOMAIN}"
Environment="DB_PATH=${DB_PATH}"
Environment="SECRETS_PATH=${SECRETS_PATH}"
Environment="SECRET_KEY_PATH=${SECRET_KEY_PATH}"
ExecStart=${INSTALL_DIR}/venv/bin/gunicorn --workers 2 --threads 8 --worker-class gthread --worker-connections 1000 --timeout 30 --graceful-timeout 2 -b 127.0.0.1:8000 app:app
Restart=always
RestartSec=3
TimeoutStopSec=5s

[Install]
WantedBy=multi-user.target
SERVICE_EOF

    ln -sf /etc/systemd/system/ike-ui.service /etc/systemd/system/ikev2-panel.service 2>/dev/null || true

    echo -e "${CYAN}[7/7] Configuring Nginx reverse proxy...${NC}"
    generate_nginx_config "$DOMAIN" "$PANEL_PORT" "$PANEL_PATH"

    systemctl daemon-reload
    systemctl enable strongswan-starter.service 2>/dev/null || systemctl enable strongswan.service 2>/dev/null || true
    systemctl enable ike-ui.service
    systemctl enable nginx.service

    systemctl restart strongswan-starter.service 2>/dev/null || systemctl restart strongswan.service 2>/dev/null || ipsec restart 2>/dev/null || true
    systemctl restart ike-ui.service
    systemctl restart nginx.service

    show_banner
    echo -e "${GREEN}${BOLD}====================================================================${NC}"
    echo -e "${GREEN}${BOLD}       IKE-UI Server & Panel Successfully Deployed!        ${NC}"
    echo -e "${GREEN}${BOLD}====================================================================${NC}"
    echo ""
    echo -e "  ${BOLD}Server Domain:${NC}    ${CYAN}https://${DOMAIN}${NC}"
    echo -e "  ${BOLD}Server IP:${NC}        ${YELLOW}${SERVER_IP}${NC}"
    echo -e "  ${BOLD}VPN Protocol:${NC}     ${GREEN}IKEv2 / IPsec (UDP 500 / 4500)${NC}"
    echo ""
    echo -e "  ${BOLD}Panel Access Details:${NC}"
    echo -e "     • Full URL:  ${CYAN}${full_panel_url}${NC}"
    echo -e "     • Web Port:  ${BOLD}${PANEL_PORT}${NC}"
    echo -e "     • Path:      ${BOLD}/${PANEL_PATH}${NC}"
    echo -e "     • Username:  ${BOLD}${ADMIN_USER}${NC}"
    echo -e "     • Password:  ${BOLD}${ADMIN_PASS}${NC}"
    echo ""
    echo -e "  ${BOLD}Default VPN User:${NC}"
    echo -e "     • Username:  ${BOLD}${DEFAULT_VPN_USER}${NC}"
    echo -e "     • Password:  ${BOLD}${DEFAULT_VPN_PASS}${NC}"
    echo ""
    echo -e "${CYAN}====================================================================${NC}"
    echo -e "${YELLOW}Zero-Cert Setup: No certificates or profiles needed on clients.${NC}"
    echo -e "Enter Server: ${BOLD}${DOMAIN}${NC}, Username, and Password on iOS, Windows, Android, macOS."
    echo -e "${CYAN}====================================================================${NC}"
    echo ""
}

update_ike_ui() {
    local target_channel="$1"

    show_banner
    echo -e "${CYAN}${BOLD}[*] IKE-UI Update Manager${NC}"
    echo ""

    if [ -z "$target_channel" ]; then
        echo -e "${BOLD}Select Update Channel:${NC}"
        echo -e "  ${CYAN}1)${NC}  Latest Tagged Release (Stable) [Recommended]"
        echo -e "  ${CYAN}2)${NC}  Latest Commit (Dev / main branch)"
        echo -e "  ${CYAN}0)${NC}  Cancel"
        echo ""
        read -rp "Enter choice [1-2, default=1]: " update_choice
        case "$update_choice" in
            1|"") target_channel="release" ;;
            2)    target_channel="dev" ;;
            0)    echo -e "${YELLOW}[*] Update cancelled.${NC}"; return 0 ;;
            *)    echo -e "${RED}[X] Invalid option.${NC}"; return 1 ;;
        esac
    fi

    echo ""
    local channel_name="Latest Tagged Release (Stable)"
    if [[ "$target_channel" == "dev" || "$target_channel" == "main" || "$target_channel" == "commit" || "$target_channel" == "2" ]]; then
        channel_name="Latest Commit (Dev / main branch)"
    fi
    echo -e "${YELLOW}[*] Target Update Channel:${NC} ${CYAN}${channel_name}${NC}"
    read -rp "Are you sure you want to proceed with update? [y/N]: " confirm_update
    if [[ ! "$confirm_update" =~ ^[yY]([eE][sS])?$ ]]; then
        echo -e "${YELLOW}[*] Update cancelled.${NC}"
        return 0 2>/dev/null || exit 0
    fi

    echo ""
    if ! command -v git >/dev/null 2>&1; then
        echo -e "${YELLOW}[*] Installing git...${NC}"
        apt-get update -y && apt-get install -y git
    fi

    mkdir -p "$INSTALL_DIR"
    cd "$INSTALL_DIR"

    if [ -d "$INSTALL_DIR/.git" ]; then
        git remote set-url origin "$REPO_URL" 2>/dev/null || true
        echo -e "${CYAN}[1/4] Fetching latest tags and commits from GitHub...${NC}"
        git fetch --all --tags --prune
    else
        echo -e "${YELLOW}[1/4] Initializing Git repository in ${INSTALL_DIR}...${NC}"
        TEMP_CLONE="/tmp/ike-ui-update-temp"
        rm -rf "$TEMP_CLONE"
        git clone "$REPO_URL" "$TEMP_CLONE"
        cp -r "$TEMP_CLONE/.git" "$INSTALL_DIR/"
        rm -rf "$TEMP_CLONE"
        git fetch --all --tags --prune
        echo -e "${GREEN}[+] Converted to tracked Git repository.${NC}"
    fi

    case "$target_channel" in
        release|stable|tag|1)
            local latest_tag
            latest_tag=$(git tag -l --sort=-v:refname | grep -E '^v?[0-9]+\.[0-9]+' | head -n 1)
            if [ -n "$latest_tag" ]; then
                echo -e "${CYAN}[*] Updating to latest release tag: ${GREEN}${BOLD}${latest_tag}${NC}..."
                git checkout -B main origin/main 2>/dev/null || true
                git reset --hard "$latest_tag"
                echo -e "${GREEN}[+] Reset repository to release tag ${latest_tag}.${NC}"
            else
                echo -e "${YELLOW}[!] No release tags found. Falling back to latest commit on main...${NC}"
                git checkout -B main origin/main 2>/dev/null || true
                git reset --hard origin/main
                echo -e "${GREEN}[+] Git repository updated to latest commit.${NC}"
            fi
            ;;
        dev|main|commit|2)
            echo -e "${CYAN}[*] Pulling latest development commits from main branch...${NC}"
            git checkout -B main origin/main 2>/dev/null || true
            git reset --hard origin/main
            echo -e "${GREEN}[+] Git repository updated to latest development commit.${NC}"
            ;;
        *)
            echo -e "${RED}[X] Unknown update target: $target_channel${NC}"
            return 1
            ;;
    esac

    chmod +x "${INSTALL_DIR}/install.sh" 2>/dev/null || true
    setup_cli_shortcut

    echo -e "${CYAN}[2/4] Updating Python dependencies...${NC}"
    if [ ! -d "${INSTALL_DIR}/venv" ]; then
        python3 -m venv "${INSTALL_DIR}/venv"
    fi
    "${INSTALL_DIR}/venv/bin/pip" install --disable-pip-version-check --no-cache-dir -r "${INSTALL_DIR}/panel/requirements.txt" >/dev/null
    echo -e "${GREEN}[+] Python dependencies updated.${NC}"

    echo -e "${CYAN}[3/4] Running database migrations...${NC}"
    "${INSTALL_DIR}/venv/bin/python" -c "
import sys
sys.path.insert(0, '${INSTALL_DIR}/panel')
import app
app.init_db()
"
    echo -e "${GREEN}[+] Database schema verified and updated.${NC}"

    local cur_dom
    cur_dom=$(get_current_domain)
    if [ -n "$cur_dom" ] && [ -d "/etc/letsencrypt/live/${cur_dom}" ]; then
        mkdir -p /etc/ipsec.d/certs /etc/ipsec.d/cacerts /etc/ipsec.d/private
        if [ -f "/etc/letsencrypt/live/${cur_dom}/fullchain.pem" ]; then
            cp "/etc/letsencrypt/live/${cur_dom}/fullchain.pem" /etc/ipsec.d/certs/cert.pem
        fi
        rm -f /etc/ipsec.d/cacerts/*
        if [ -f "/etc/letsencrypt/live/${cur_dom}/chain.pem" ]; then
            python3 -c "
import re
with open('/etc/letsencrypt/live/${cur_dom}/chain.pem', 'r') as f:
    text = f.read()
certs = re.findall(r'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----', text, re.DOTALL)
if certs:
    for i, c in enumerate(certs):
        with open(f'/etc/ipsec.d/cacerts/chain_{i}.pem', 'w') as out:
            out.write(c.strip() + '\n')
else:
    with open('/etc/ipsec.d/cacerts/chain.pem', 'w') as out:
        out.write(text)
" 2>/dev/null || cp "/etc/letsencrypt/live/${cur_dom}/chain.pem" /etc/ipsec.d/cacerts/chain.pem
        fi
        chmod 600 /etc/ipsec.d/private/privkey.pem 2>/dev/null || true
        chmod 644 /etc/ipsec.d/certs/cert.pem /etc/ipsec.d/cacerts/* 2>/dev/null || true
        ipsec rereadall 2>/dev/null || true
        ipsec restart 2>/dev/null || systemctl restart strongswan-starter.service 2>/dev/null || systemctl restart strongswan.service 2>/dev/null || true

        mkdir -p /etc/letsencrypt/renewal-hooks/deploy
        cat > /etc/letsencrypt/renewal-hooks/deploy/strongswan.sh << 'RENEW_EOF'
#!/usr/bin/env bash
for domain_dir in /etc/letsencrypt/live/*; do
    if [ -d "$domain_dir" ] && { [ -f "$domain_dir/fullchain.pem" ] || [ -f "$domain_dir/cert.pem" ]; }; then
        if [ -f "$domain_dir/fullchain.pem" ]; then
            cp "$domain_dir/fullchain.pem" /etc/ipsec.d/certs/cert.pem
        else
            cp "$domain_dir/cert.pem" /etc/ipsec.d/certs/cert.pem
        fi
        cp "$domain_dir/privkey.pem" /etc/ipsec.d/private/privkey.pem
        rm -f /etc/ipsec.d/cacerts/*
        if [ -f "$domain_dir/chain.pem" ]; then
            python3 -c "
import re
with open('$domain_dir/chain.pem', 'r') as f:
    text = f.read()
certs = re.findall(r'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----', text, re.DOTALL)
if certs:
    for i, c in enumerate(certs):
        with open(f'/etc/ipsec.d/cacerts/chain_{i}.pem', 'w') as out:
            out.write(c.strip() + '\n')
else:
    with open('/etc/ipsec.d/cacerts/chain.pem', 'w') as out:
        out.write(text)
" 2>/dev/null || cp "$domain_dir/chain.pem" /etc/ipsec.d/cacerts/chain.pem
        fi
        chmod 600 /etc/ipsec.d/private/privkey.pem
        chmod 644 /etc/ipsec.d/certs/cert.pem /etc/ipsec.d/cacerts/* 2>/dev/null || true
        ipsec rereadall 2>/dev/null || true
        ipsec restart 2>/dev/null || systemctl restart strongswan-starter.service 2>/dev/null || systemctl restart strongswan.service 2>/dev/null || true
        systemctl reload nginx 2>/dev/null || true
        break
    fi
done
RENEW_EOF
        chmod +x /etc/letsencrypt/renewal-hooks/deploy/strongswan.sh
    fi

    echo -e "${CYAN}[4/4] Updating Nginx configuration and restarting services...${NC}"
    local cur_dom cur_port cur_path
    cur_dom=$(get_current_domain)
    cur_port=$(get_current_port)
    cur_path=$(get_current_path)
    if [ -n "$cur_dom" ]; then
        generate_nginx_config "$cur_dom" "$cur_port" "$cur_path"
        if nginx -t >/dev/null 2>&1; then
            systemctl reload nginx 2>/dev/null || systemctl restart nginx 2>/dev/null || true
            echo -e "${GREEN}[+] Nginx configuration updated and reloaded.${NC}"
        fi
    fi

    if [ -f /etc/systemd/system/ike-ui.service ]; then
        sed -i 's|gunicorn .* app:app|gunicorn --workers 2 --threads 8 --worker-class gthread --worker-connections 1000 --timeout 30 --graceful-timeout 2 -b 127.0.0.1:8000 app:app|g' /etc/systemd/system/ike-ui.service
        if ! grep -q "TimeoutStopSec=" /etc/systemd/system/ike-ui.service; then
            sed -i '/RestartSec=/a TimeoutStopSec=5s' /etc/systemd/system/ike-ui.service
        fi
    fi
    systemctl daemon-reload
    systemctl restart ike-ui.service

    sleep 1

    local new_ver=""
    if [ -f "${INSTALL_DIR}/install.sh" ]; then
        new_ver=$(grep -oP '^APP_VERSION=["\x27]?\K[^"\x27\s]+' "${INSTALL_DIR}/install.sh" 2>/dev/null || true)
    fi
    if [ -z "$new_ver" ] && [ -f "${INSTALL_DIR}/panel/app.py" ]; then
        new_ver=$(grep -oP '^APP_VERSION\s*=\s*["\x27]?\K[^"\x27\s]+' "${INSTALL_DIR}/panel/app.py" 2>/dev/null || true)
    fi
    if [ -n "$new_ver" ]; then
        APP_VERSION="$new_ver"
    fi

    if systemctl is-active --quiet ike-ui.service; then
        echo ""
        echo -e "${GREEN}${BOLD}====================================================================${NC}"
        echo -e "${GREEN}${BOLD}       IKE-UI Successfully Updated to Version v${APP_VERSION}!      ${NC}"
        echo -e "${GREEN}${BOLD}====================================================================${NC}"
        local commit_info
        commit_info=$(cd "$INSTALL_DIR" && git log -1 --pretty=format:"%h - %s (%cr)" 2>/dev/null || echo "Latest")
        echo -e "  ${BOLD}Version:${NC}  ${GREEN}${BOLD}v${APP_VERSION}${NC} (${CYAN}${commit_info}${NC})"
        echo -e "  ${BOLD}Status:${NC}   ${GREEN}Active & Running${NC}"
        echo -e "${GREEN}${BOLD}====================================================================${NC}"
        echo ""
    else
        echo -e "${RED}[X] Error: Service failed to start after update. Check logs with 'ike-ui logs'.${NC}"
    fi
}

start_services() {
    echo -e "${YELLOW}[*] Starting all services...${NC}"
    systemctl start strongswan-starter 2>/dev/null || systemctl start strongswan 2>/dev/null || ipsec start 2>/dev/null || true
    systemctl start ike-ui 2>/dev/null || systemctl start ikev2-panel 2>/dev/null || true
    systemctl start nginx
    echo -e "${GREEN}[+] All services started.${NC}"
}

stop_services() {
    echo -e "${YELLOW}[*] Stopping all services...${NC}"
    systemctl stop ike-ui 2>/dev/null || systemctl stop ikev2-panel 2>/dev/null || true
    systemctl stop nginx
    systemctl stop strongswan-starter 2>/dev/null || systemctl stop strongswan 2>/dev/null || ipsec stop 2>/dev/null || true
    echo -e "${GREEN}[+] All services stopped.${NC}"
}

restart_services() {
    echo -e "${YELLOW}[*] Restarting all services...${NC}"
    systemctl restart strongswan-starter 2>/dev/null || systemctl restart strongswan 2>/dev/null || ipsec restart 2>/dev/null || true
    systemctl restart ike-ui 2>/dev/null || systemctl restart ikev2-panel 2>/dev/null || true
    systemctl restart nginx
    echo -e "${GREEN}[+] All services restarted successfully.${NC}"
}

check_status() {
    show_banner
    echo -e "${CYAN}=== StrongSwan IPsec VPN Status ===${NC}"
    ipsec statusall 2>/dev/null || true
    echo ""
    echo -e "${CYAN}=== IKE-UI Panel Status ===${NC}"
    systemctl status ike-ui --no-pager -l 2>/dev/null || systemctl status ikev2-panel --no-pager -l 2>/dev/null || true
    echo ""
    echo -e "${CYAN}=== Nginx Web Server Status ===${NC}"
    systemctl status nginx --no-pager -l || true
}

view_logs() {
    show_banner
    echo -e "${BOLD}Select log stream to view:${NC}"
    echo -e "  ${CYAN}1)${NC} IKE-UI Panel Logs (Live journalctl)"
    echo -e "  ${CYAN}2)${NC} StrongSwan VPN Logs"
    echo -e "  ${CYAN}3)${NC} Nginx Access & Error Logs"
    echo -e "  ${CYAN}4)${NC} Back to Main Menu"
    echo ""
    read -rp "Enter choice [1-4]: " log_choice
    case $log_choice in
        1) journalctl -u ike-ui -n 50 -f ;;
        2) journalctl -u strongswan-starter -u strongswan -n 50 -f ;;
        3) tail -n 50 -f /var/log/nginx/access.log /var/log/nginx/error.log ;;
        *) return ;;
    esac
}

reset_admin_credentials() {
    show_banner
    echo -e "${BOLD}Administrator Credentials Manager${NC}"
    echo ""
    echo -e "${CYAN}[*] Existing Administrators:${NC}"
    "${INSTALL_DIR}/venv/bin/python" -c "
import sys
sys.path.insert(0, '${INSTALL_DIR}/panel')
import app
conn = app.get_db()
cursor = conn.cursor()
cursor.execute('SELECT id, username FROM admin ORDER BY id ASC')
rows = cursor.fetchall()
conn.close()
for r in rows:
    print(f'   • {r[\"username\"]} (ID: {r[\"id\"]})')
" 2>/dev/null || true
    echo ""
    read -rp "Enter Admin Username to add/reset [default: admin]: " NEW_USER
    NEW_USER=${NEW_USER:-admin}

    read -rp "Enter new Admin Password: " NEW_PASS
    if [ -z "$NEW_PASS" ]; then
        echo -e "${RED}[X] Password cannot be empty.${NC}"
        return
    fi
    "${INSTALL_DIR}/venv/bin/python" -c "
import sys
sys.path.insert(0, '${INSTALL_DIR}/panel')
import app
import datetime
from werkzeug.security import generate_password_hash
conn = app.get_db()
cursor = conn.cursor()
cursor.execute('SELECT id FROM admin WHERE username = ?', ('${NEW_USER}',))
row = cursor.fetchone()
if row:
    cursor.execute('UPDATE admin SET password_hash = ? WHERE id = ?', (generate_password_hash('${NEW_PASS}'), row['id']))
else:
    now = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    cursor.execute('INSERT INTO admin (username, password_hash, created_at) VALUES (?, ?, ?)', ('${NEW_USER}', generate_password_hash('${NEW_PASS}'), now))
conn.commit()
conn.close()
print('[+] Administrator credentials for \'${NEW_USER}\' updated successfully.')
"
}

change_panel_path() {
    show_banner
    echo -e "${BOLD}Change Panel Secret Path${NC}"
    echo ""
    local cur_domain cur_port cur_path
    cur_domain=$(get_current_domain)
    cur_port=$(get_current_port)
    cur_path=$(get_current_path)

    if [ -z "$cur_domain" ]; then
        echo -e "${RED}[X] Error: IKE-UI is not fully installed or domain not found.${NC}"
        return 1
    fi

    local port_str=""
    if [ "$cur_port" != "443" ] && [ -n "$cur_port" ]; then
        port_str=":${cur_port}"
    fi
    local path_str=""
    if [ -n "$cur_path" ] && [ "$cur_path" != "/" ]; then
        path_str="/${cur_path#/}"
    fi

    echo -e "  ${BOLD}Current Path:${NC}      ${CYAN}${path_str:-/(root)}${NC}"
    echo -e "  ${BOLD}Current Panel URL:${NC} ${CYAN}https://${cur_domain}${port_str}${path_str}${NC}"
    echo ""

    while true; do
        local rand_path
        rand_path=$(generate_rand_path)
        read -rp "Enter new Secret Path [default: random 16-chars (${rand_path}), or '/' for root]: " NEW_PATH
        NEW_PATH=${NEW_PATH:-$rand_path}
        if [[ "$NEW_PATH" == "/" || "$NEW_PATH" == "root" ]]; then
            NEW_PATH=""
            break
        else
            NEW_PATH=$(echo "$NEW_PATH" | sed -e 's|^/*||' -e 's|/*$||' | tr -cd 'a-zA-Z0-9_-')
            if [ -z "$NEW_PATH" ]; then
                NEW_PATH="$rand_path"
            fi
            if is_reserved_path "$NEW_PATH"; then
                echo -e "${RED}[X] Error: '/${NEW_PATH}' is a reserved system path and cannot be used.${NC}"
                echo -e "${YELLOW}[!] Reserved paths: login, logout, settings, user, admin, api, backup, restore, static, sub, subscription.${NC}"
            else
                break
            fi
        fi
    done

    echo ""
    echo -e "${CYAN}[*] Updating Nginx configuration...${NC}"
    generate_nginx_config "$cur_domain" "$cur_port" "$NEW_PATH"

    if ! nginx -t >/dev/null 2>&1; then
        echo -e "${RED}[X] Error: Nginx configuration test failed. Reverting to previous path...${NC}"
        generate_nginx_config "$cur_domain" "$cur_port" "$cur_path"
        systemctl reload nginx 2>/dev/null || true
        return 1
    fi

    systemctl reload nginx

    if [ -f "${DB_PATH}" ]; then
        sqlite3 "${DB_PATH}" "INSERT INTO system_config (key, value) VALUES ('panel_path', '${NEW_PATH}') ON CONFLICT(key) DO UPDATE SET value = excluded.value;" 2>/dev/null || \
        python3 -c "import sqlite3; conn=sqlite3.connect('${DB_PATH}'); cursor=conn.cursor(); cursor.execute(\"INSERT INTO system_config (key, value) VALUES ('panel_path', '${NEW_PATH}') ON CONFLICT(key) DO UPDATE SET value = excluded.value\"); conn.commit(); conn.close()" 2>/dev/null || true
    fi

    local new_path_str=""
    if [ -n "$NEW_PATH" ]; then
        new_path_str="/${NEW_PATH}"
    fi
    local new_full_url="https://${cur_domain}${port_str}${new_path_str}"

    echo ""
    echo -e "${GREEN}[+] Panel secret path updated successfully!${NC}"
    echo -e "  ${BOLD}New Panel URL:${NC} ${CYAN}${new_full_url}${NC}"
}

change_panel_port() {
    show_banner
    echo -e "${BOLD}Change Panel Web Port${NC}"
    echo ""
    local cur_domain cur_port cur_path
    cur_domain=$(get_current_domain)
    cur_port=$(get_current_port)
    cur_path=$(get_current_path)

    if [ -z "$cur_domain" ]; then
        echo -e "${RED}[X] Error: IKE-UI is not fully installed or domain not found.${NC}"
        return 1
    fi

    local port_str=""
    if [ "$cur_port" != "443" ] && [ -n "$cur_port" ]; then
        port_str=":${cur_port}"
    fi
    local path_str=""
    if [ -n "$cur_path" ] && [ "$cur_path" != "/" ]; then
        path_str="/${cur_path#/}"
    fi

    echo -e "  ${BOLD}Current Port:${NC}      ${CYAN}${cur_port}${NC}"
    echo -e "  ${BOLD}Current Panel URL:${NC} ${CYAN}https://${cur_domain}${port_str}${path_str}${NC}"
    echo ""

    local NEW_PORT
    while true; do
        read -rp "Enter new Panel Web Port [1-65535, default: 443]: " NEW_PORT
        NEW_PORT=${NEW_PORT:-443}
        if [[ ! "$NEW_PORT" =~ ^[0-9]+$ ]] || [ "$NEW_PORT" -lt 1 ] || [ "$NEW_PORT" -gt 65535 ]; then
            echo -e "${RED}[X] Invalid port number. Must be between 1 and 65535.${NC}"
            continue
        fi
        if [ "$NEW_PORT" -eq 500 ] || [ "$NEW_PORT" -eq 4500 ]; then
            echo -e "${RED}[X] Port ${NEW_PORT} is reserved for StrongSwan IKEv2 VPN.${NC}"
            continue
        fi
        if [ "$NEW_PORT" -eq 80 ]; then
            echo -e "${RED}[X] Port 80 is reserved for Let's Encrypt / HTTP validation.${NC}"
            continue
        fi
        if [ "$NEW_PORT" != "$cur_port" ] && is_port_in_use "$NEW_PORT"; then
            echo -e "${RED}[X] Port ${NEW_PORT} is currently in use by another service! Please choose a different port.${NC}"
            continue
        fi
        break
    done

    echo ""
    echo -e "${CYAN}[*] Updating Nginx configuration & firewall rules...${NC}"
    generate_nginx_config "$cur_domain" "$NEW_PORT" "$cur_path"

    if ! nginx -t >/dev/null 2>&1; then
        echo -e "${RED}[X] Error: Nginx configuration test failed. Reverting to previous port...${NC}"
        generate_nginx_config "$cur_domain" "$cur_port" "$cur_path"
        systemctl reload nginx 2>/dev/null || true
        return 1
    fi

    if [ "$NEW_PORT" != "443" ] && [ "$NEW_PORT" != "80" ]; then
        if command -v ufw >/dev/null 2>&1; then
            ufw allow "${NEW_PORT}/tcp" >/dev/null 2>&1 || true
        fi
        iptables -C INPUT -p tcp --dport "${NEW_PORT}" -j ACCEPT 2>/dev/null || \
            iptables -A INPUT -p tcp --dport "${NEW_PORT}" -j ACCEPT 2>/dev/null || true
    fi

    systemctl reload nginx

    if [ -f "${DB_PATH}" ]; then
        sqlite3 "${DB_PATH}" "INSERT INTO system_config (key, value) VALUES ('panel_port', '${NEW_PORT}') ON CONFLICT(key) DO UPDATE SET value = excluded.value;" 2>/dev/null || \
        python3 -c "import sqlite3; conn=sqlite3.connect('${DB_PATH}'); cursor=conn.cursor(); cursor.execute(\"INSERT INTO system_config (key, value) VALUES ('panel_port', '${NEW_PORT}') ON CONFLICT(key) DO UPDATE SET value = excluded.value\"); conn.commit(); conn.close()" 2>/dev/null || true
    fi

    local new_port_str=""
    if [ "$NEW_PORT" != "443" ]; then
        new_port_str=":${NEW_PORT}"
    fi
    local new_full_url="https://${cur_domain}${new_port_str}${path_str}"

    echo ""
    echo -e "${GREEN}[+] Panel web port updated successfully!${NC}"
    echo -e "  ${BOLD}New Panel URL:${NC} ${CYAN}${new_full_url}${NC}"
}

manage_panel_access() {
    while true; do
        show_banner
        echo -e "${BOLD}Panel Access & Administrator Settings${NC}"
        echo ""
        echo -e "  ${CYAN}1)${NC}  Change Admin Username & Password"
        echo -e "  ${CYAN}2)${NC}  Change Panel Secret Path"
        echo -e "  ${CYAN}3)${NC}  Change Panel Web Port"
        echo -e "  ${CYAN}0)${NC}  Back to Main Menu"
        echo ""
        read -rp "Enter choice [0-3]: " access_choice
        case "$access_choice" in
            1)
                reset_admin_credentials
                echo ""
                read -rp "Press Enter to continue..."
                ;;
            2)
                change_panel_path
                echo ""
                read -rp "Press Enter to continue..."
                ;;
            3)
                change_panel_port
                echo ""
                read -rp "Press Enter to continue..."
                ;;
            0)
                return 0
                ;;
            *)
                echo -e "${RED}Invalid option.${NC}"
                sleep 1
                ;;
        esac
    done
}

renew_ssl() {
    echo -e "${YELLOW}[*] Testing and renewing Let's Encrypt certificates...${NC}"
    certbot renew --deploy-hook "/etc/letsencrypt/renewal-hooks/deploy/strongswan.sh"
    echo -e "${GREEN}[+] SSL renewal completed.${NC}"
}

change_server_domain() {
    show_banner
    echo -e "${BOLD}Change Server Domain / Subdomain${NC}"
    echo ""
    local cur_domain cur_port cur_path
    cur_domain=$(get_current_domain)
    cur_port=$(get_current_port)
    cur_path=$(get_current_path)

    if [ -z "$cur_domain" ]; then
        echo -e "${RED}[X] Error: IKE-UI is not fully installed or current domain is missing.${NC}"
        return 1
    fi

    echo -e "  ${BOLD}Current Domain:${NC} ${CYAN}https://${cur_domain}${NC}"
    echo ""
    echo -e "${RED}${BOLD}[!] WARNING: Changing the domain will issue a new SSL certificate and update StrongSwan IPsec.${NC}"
    echo -e "${YELLOW}[!] All active VPN client connections will be disconnected, and users must update the server domain in their client settings.${NC}"
    echo ""
    read -rp "Do you want to proceed with domain migration? [y/N]: " confirm_1
    if [[ ! "$confirm_1" =~ ^[yY]([eE][sS])?$ ]]; then
        echo -e "${YELLOW}[*] Domain change cancelled.${NC}"
        return 0
    fi

    echo ""
    read -rp "Enter New Domain Name (e.g. vpn2.example.com): " NEW_DOMAIN
    NEW_DOMAIN=$(echo "$NEW_DOMAIN" | tr -d '[:space:]' | tr '[:upper:]' '[:lower:]')
    if [ -z "$NEW_DOMAIN" ]; then
        echo -e "${RED}[X] Error: New domain cannot be empty.${NC}"
        return 1
    fi
    if [ "$NEW_DOMAIN" == "$cur_domain" ]; then
        echo -e "${YELLOW}[*] The entered domain is the same as current domain.${NC}"
        return 0
    fi

    echo ""
    echo -e "${RED}${BOLD}[!] Step 2: Final Confirmation${NC}"
    echo -e "  • Old Domain: ${YELLOW}${cur_domain}${NC}"
    echo -e "  • New Domain: ${GREEN}${NEW_DOMAIN}${NC}"
    read -rp "Are you sure you want to apply domain migration now? [y/N]: " confirm_2
    if [[ ! "$confirm_2" =~ ^[yY]([eE][sS])?$ ]]; then
        echo -e "${YELLOW}[*] Domain change cancelled.${NC}"
        return 0
    fi

    echo ""
    echo -e "${CYAN}[1/5] Stopping Nginx for SSL certificate provisioning...${NC}"
    systemctl stop nginx 2>/dev/null || true

    echo -e "${CYAN}[2/5] Obtaining SSL certificate for ${NEW_DOMAIN}...${NC}"
    if [ -d "/etc/letsencrypt/live/${NEW_DOMAIN}" ] && [ -f "/etc/letsencrypt/live/${NEW_DOMAIN}/fullchain.pem" ]; then
        echo -e "${GREEN}[+] Existing certificate found for ${NEW_DOMAIN}.${NC}"
    else
        if ! certbot certonly --standalone \
            --agree-tos \
            --no-eff-email \
            -m "admin@${NEW_DOMAIN}" \
            -d "${NEW_DOMAIN}" \
            --key-type rsa \
            --rsa-key-size 2048 \
            --non-interactive; then
            echo -e "${RED}[X] Failed to obtain SSL certificate for ${NEW_DOMAIN}.${NC}"
            echo -e "${YELLOW}[*] Restoring Nginx with existing configuration...${NC}"
            systemctl start nginx 2>/dev/null || true
            return 1
        fi
    fi

    echo -e "${CYAN}[3/5] Updating certificate files for StrongSwan...${NC}"
    mkdir -p /etc/ipsec.d/certs /etc/ipsec.d/cacerts /etc/ipsec.d/private
    if [ -f "/etc/letsencrypt/live/${NEW_DOMAIN}/fullchain.pem" ]; then
        cp "/etc/letsencrypt/live/${NEW_DOMAIN}/fullchain.pem" /etc/ipsec.d/certs/cert.pem
    else
        cp "/etc/letsencrypt/live/${NEW_DOMAIN}/cert.pem" /etc/ipsec.d/certs/cert.pem
    fi
    cp "/etc/letsencrypt/live/${NEW_DOMAIN}/privkey.pem" /etc/ipsec.d/private/privkey.pem
    rm -f /etc/ipsec.d/cacerts/*
    if [ -f "/etc/letsencrypt/live/${NEW_DOMAIN}/chain.pem" ]; then
        python3 -c "
import re
with open('/etc/letsencrypt/live/${NEW_DOMAIN}/chain.pem', 'r') as f:
    text = f.read()
certs = re.findall(r'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----', text, re.DOTALL)
if certs:
    for i, c in enumerate(certs):
        with open(f'/etc/ipsec.d/cacerts/chain_{i}.pem', 'w') as out:
            out.write(c.strip() + '\n')
else:
    with open('/etc/ipsec.d/cacerts/chain.pem', 'w') as out:
        out.write(text)
" 2>/dev/null || cp "/etc/letsencrypt/live/${NEW_DOMAIN}/chain.pem" /etc/ipsec.d/cacerts/chain.pem
    fi
    chmod 600 /etc/ipsec.d/private/privkey.pem
    chmod 644 /etc/ipsec.d/certs/cert.pem /etc/ipsec.d/cacerts/* 2>/dev/null || true

    echo -e "${CYAN}[4/5] Updating StrongSwan, Systemd, and Nginx configurations...${NC}"
    if [ -f /etc/ipsec.conf ]; then
        sed -i "s|leftid=@.*|leftid=@${NEW_DOMAIN}|g" /etc/ipsec.conf
    fi
    if [ -f /etc/systemd/system/ike-ui.service ]; then
        sed -i "s|Environment=\"SERVER_DOMAIN=.*\"|Environment=\"SERVER_DOMAIN=${NEW_DOMAIN}\"|g" /etc/systemd/system/ike-ui.service
    fi
    if [ -f "${DB_PATH}" ]; then
        sqlite3 "${DB_PATH}" "INSERT INTO system_config (key, value) VALUES ('server_domain', '${NEW_DOMAIN}') ON CONFLICT(key) DO UPDATE SET value = excluded.value;" 2>/dev/null || \
        python3 -c "import sqlite3; conn=sqlite3.connect('${DB_PATH}'); cursor=conn.cursor(); cursor.execute(\"INSERT INTO system_config (key, value) VALUES ('server_domain', '${NEW_DOMAIN}') ON CONFLICT(key) DO UPDATE SET value = excluded.value\"); conn.commit(); conn.close()" 2>/dev/null || true
    fi

    generate_nginx_config "$NEW_DOMAIN" "$cur_port" "$cur_path"

    echo -e "${CYAN}[5/5] Restarting services...${NC}"
    systemctl daemon-reload
    systemctl restart strongswan-starter.service 2>/dev/null || systemctl restart strongswan.service 2>/dev/null || ipsec restart 2>/dev/null || true
    systemctl restart ike-ui.service
    systemctl restart nginx.service

    local port_str=""
    if [ "$cur_port" != "443" ] && [ -n "$cur_port" ]; then
        port_str=":${cur_port}"
    fi
    local path_str=""
    if [ -n "$cur_path" ] && [ "$cur_path" != "/" ]; then
        path_str="/${cur_path#/}"
    fi
    local new_panel_url="https://${NEW_DOMAIN}${port_str}${path_str}"

    echo ""
    echo -e "${GREEN}${BOLD}====================================================================${NC}"
    echo -e "${GREEN}${BOLD}       Server Domain Successfully Migrated to: ${NEW_DOMAIN}       ${NC}"
    echo -e "${GREEN}${BOLD}====================================================================${NC}"
    echo ""
    echo -e "  ${BOLD}New Domain:${NC}    ${CYAN}https://${NEW_DOMAIN}${NC}"
    echo -e "  ${BOLD}New Panel URL:${NC} ${CYAN}${new_panel_url}${NC}"
    echo ""
    echo -e "${YELLOW}Please inform clients to update their VPN server address to: ${BOLD}${NEW_DOMAIN}${NC}"
    echo -e "${GREEN}${BOLD}====================================================================${NC}"
}

manage_domain_ssl() {
    while true; do
        show_banner
        echo -e "${BOLD}Domain & SSL Certificate Management${NC}"
        echo ""
        echo -e "  ${CYAN}1)${NC}  Renew Let's Encrypt SSL Certificate"
        echo -e "  ${CYAN}2)${NC}  Change Server Domain / Subdomain (Full Migration)"
        echo -e "  ${CYAN}0)${NC}  Back to Main Menu"
        echo ""
        read -rp "Enter choice [0-2]: " domain_choice
        case "$domain_choice" in
            1)
                renew_ssl
                echo ""
                read -rp "Press Enter to continue..."
                ;;
            2)
                change_server_domain
                echo ""
                read -rp "Press Enter to continue..."
                ;;
            0)
                return 0
                ;;
            *)
                echo -e "${RED}Invalid option.${NC}"
                sleep 1
                ;;
        esac
    done
}

uninstall_all() {
    show_banner
    echo -e "${RED}${BOLD}[!] WARNING: You are about to uninstall IKE-UI!${NC}"
    echo ""
    read -rp "Are you sure you want to proceed with uninstallation? [y/N]: " confirm
    if [[ ! "$confirm" =~ ^[yY]([eE][sS])?$ ]]; then
        echo -e "${YELLOW}Uninstallation cancelled.${NC}"
        return
    fi

    echo ""
    read -rp "Do you want to delete user database & credentials (/etc/strongswan-panel)? [y/N]: " del_db

    echo ""
    echo -e "${RED}${BOLD}[!] Final Confirmation:${NC}"
    if [[ "$del_db" =~ ^[yY]([eE][sS])?$ ]]; then
        echo -e "    ${RED}WARNING: All IKE-UI files, services, and user database will be permanently deleted.${NC}"
    else
        echo -e "    ${YELLOW}All IKE-UI services and files will be removed. Database will be preserved at ${DB_DIR}.${NC}"
    fi
    read -rp "Are you completely sure you want to execute uninstallation now? [y/N]: " confirm_final_uninstall
    if [[ ! "$confirm_final_uninstall" =~ ^[yY]([eE][sS])?$ ]]; then
        echo -e "${YELLOW}[*] Uninstallation cancelled.${NC}"
        return 0 2>/dev/null || exit 0
    fi

    echo ""
    echo -e "${CYAN}[*] Stopping and disabling services...${NC}"
    systemctl stop ike-ui 2>/dev/null || true
    systemctl disable ike-ui 2>/dev/null || true
    rm -f /etc/systemd/system/ike-ui.service /etc/systemd/system/ikev2-panel.service

    systemctl stop ike-rules 2>/dev/null || true
    systemctl disable ike-rules 2>/dev/null || true
    rm -f /etc/systemd/system/ike-rules.service

    systemctl daemon-reload

    rm -f /etc/nginx/sites-enabled/ike-ui /etc/nginx/sites-available/ike-ui
    systemctl reload nginx 2>/dev/null || true

    rm -rf "$INSTALL_DIR"
    rm -f "$BIN_PATH" "$ALT_BIN_PATH"

    if [[ "$del_db" =~ ^[yY]([eE][sS])?$ ]]; then
        rm -rf "$DB_DIR"
        echo -e "${YELLOW}[*] Database and credentials removed.${NC}"
    else
        echo -e "${GREEN}[*] Database preserved at ${DB_DIR}.${NC}"
    fi

    echo -e "${GREEN}${BOLD}[+] IKE-UI has been completely uninstalled.${NC}"
    exit 0
}

show_version() {
    local cur_ver="$APP_VERSION"
    if [ -f "${INSTALL_DIR}/install.sh" ]; then
        local disk_ver
        disk_ver=$(grep -oP '^APP_VERSION=["\x27]?\K[^"\x27\s]+' "${INSTALL_DIR}/install.sh" 2>/dev/null || true)
        if [ -n "$disk_ver" ]; then
            cur_ver="$disk_ver"
        fi
    fi
    if [ -d "$INSTALL_DIR/.git" ]; then
        COMMIT=$(cd "$INSTALL_DIR" && git log -1 --pretty=format:"%h (%ci)" 2>/dev/null || echo "git")
        echo -e "${CYAN}IKE-UI Version:${NC} ${BOLD}v${cur_ver}${NC} (${COMMIT})"
    else
        echo -e "${CYAN}IKE-UI Version:${NC} ${BOLD}v${cur_ver}${NC}"
    fi
}

show_help() {
    echo -e "${BOLD}IKE-UI Management CLI${NC}"
    echo ""
    echo -e "Usage: ${CYAN}ike-ui${NC} [command]"
    echo ""
    echo -e "Commands:"
    echo -e "  ${CYAN}(no arg)${NC}            Open interactive management menu"
    echo -e "  ${CYAN}install, -i${NC}         Install Panel / Reinstall"
    echo -e "  ${CYAN}update, -u${NC} [1|2]    Update IKE-UI"
    echo -e "  ${CYAN}restart, -r${NC}         Restart all services (StrongSwan, Panel, Nginx)"
    echo -e "  ${CYAN}start${NC}               Start all services"
    echo -e "  ${CYAN}stop${NC}                Stop all services"
    echo -e "  ${CYAN}status, -s${NC}          Check service status and active VPN connections"
    echo -e "  ${CYAN}logs, -l${NC}            View live service logs"
    echo -e "  ${CYAN}access, -a, -p${NC}      Panel Access & Admin Settings"
    echo -e "  ${CYAN}domain, -d, ssl${NC}     Domain & SSL Management"
    echo -e "  ${CYAN}uninstall${NC}           Uninstall IKE-UI and clean up"
    echo -e "  ${CYAN}version, -v${NC}         Show current installed version"
    echo -e "  ${CYAN}help, -h${NC}            Show this help message"
    echo ""
}

menu() {
    while true; do
        show_banner
        echo -e "${BOLD}Select an action:${NC}"
        echo -e "  ${CYAN}1)${NC}  Install Panel / Reinstall"
        echo -e "  ${CYAN}2)${NC}  Update IKE-UI"
        echo -e "  ${CYAN}3)${NC}  Restart All Services (StrongSwan, Panel, Nginx)"
        echo -e "  ${CYAN}4)${NC}  Stop All Services"
        echo -e "  ${CYAN}5)${NC}  Start All Services"
        echo -e "  ${CYAN}6)${NC}  Check Status & Active VPN Connections"
        echo -e "  ${CYAN}7)${NC}  View Live Logs"
        echo -e "  ${CYAN}8)${NC}  Panel Access & Admin Settings"
        echo -e "  ${CYAN}9)${NC}  Domain & SSL Management"
        echo -e "  ${CYAN}10)${NC} Uninstall IKE-UI"
        echo -e "  ${CYAN}0)${NC}  Exit"
        echo ""
        read -rp "Enter your choice [0-10]: " choice
        case $choice in
            1)
                install_all
                echo ""
                read -rp "Press Enter to continue..."
                ;;
            2)
                update_ike_ui
                echo ""
                read -rp "Press Enter to return to menu..."
                if [ -x "${INSTALL_DIR}/install.sh" ]; then
                    exec "${INSTALL_DIR}/install.sh"
                elif [ -f "${INSTALL_DIR}/install.sh" ]; then
                    exec bash "${INSTALL_DIR}/install.sh"
                fi
                ;;
            3) restart_services; read -rp "Press Enter to continue..." ;;
            4) stop_services; read -rp "Press Enter to continue..." ;;
            5) start_services; read -rp "Press Enter to continue..." ;;
            6) check_status; read -rp "Press Enter to continue..." ;;
            7) view_logs ;;
            8) manage_panel_access ;;
            9) manage_domain_ssl ;;
            10)
                uninstall_all
                echo ""
                read -rp "Press Enter to continue..."
                ;;
            0) exit 0 ;;
            *) echo -e "${RED}Invalid option.${NC}"; sleep 1 ;;
        esac
    done
}

case "$1" in
    version|-v|--version)
        show_version
        exit 0
        ;;
    help|-h|--help)
        show_help
        exit 0
        ;;
    --apply-firewall)
        apply_firewall
        exit 0
        ;;
esac

bootstrap_environment "$@"

check_root

case "$1" in
    --first-install)
        install_all
        echo ""
        read -rp "Press Enter to continue..."
        menu
        ;;
    install|-i|--install)
        install_all "$2"
        ;;
    update|-u|--update)
        update_ike_ui "$2"
        ;;
    restart|-r|--restart)
        restart_services
        ;;
    start)
        start_services
        ;;
    stop)
        stop_services
        ;;
    status|-s|--status)
        check_status
        ;;
    logs|-l|--logs)
        view_logs
        ;;
    access|-a|--access|password|-p|--password)
        manage_panel_access
        ;;
    domain|-d|--domain|ssl|--ssl)
        manage_domain_ssl
        ;;
    uninstall|--uninstall)
        uninstall_all
        ;;
    "")
        if ! is_installed; then
            read -rp "Do you want to install IKE-UI panel? [y/n]: " confirm_install
            if [[ ! "$confirm_install" =~ ^[yY]([eE][sS])?$ ]]; then
                echo -e "${YELLOW}[*] Installation cancelled.${NC}"
                exit 0
            fi
            install_all
            echo ""
            read -rp "Press Enter to continue..."
            menu
        else
            menu
        fi
        ;;
    *)
        echo -e "${RED}Unknown command: $1${NC}"
        show_help
        exit 1
        ;;
esac
