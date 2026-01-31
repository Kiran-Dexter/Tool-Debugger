#!/bin/bash
set -e

# ------------------ HELPERS ------------------
error() { echo "ERROR: $1"; exit 1; }
info()  { echo "[INFO] $1"; }
ask()   { read -rp "$1: " REPLY; echo "$REPLY"; }

# ------------------ PRE-CHECK ------------------
[ "$EUID" -ne 0 ] && error "Run as root (no sudo inside script)"

for cmd in tar make gcc curl systemctl; do
    command -v "$cmd" >/dev/null || error "$cmd not found"
done

echo
echo "====== HAProxy Tarball Install (RHEL 8 | Custom Mount | HTTPS) ======"
echo

# ------------------ INPUTS ------------------
TARBALL=$(ask "Enter full path to HAProxy tar/tar.gz")
[ -f "$TARBALL" ] || error "Tarball not found"

BASE_MOUNT=$(ask "Enter base mount path (e.g. /apps or /opt)")
[ -d "$BASE_MOUNT" ] || error "Mount path does not exist"

INSTALL_PREFIX="${BASE_MOUNT}/haproxy"

CONF_DIR=$(ask "Config directory [/etc/haproxy]")
CONF_DIR=${CONF_DIR:-/etc/haproxy}

BACKEND=$(ask "Backend server (host:port)")
[ -z "$BACKEND" ] && error "Backend is required"

TEST_PATH=$(ask "URL path to test [/]")
TEST_PATH=${TEST_PATH:-/}

ENABLE_HTTPS=$(ask "Enable HTTPS? (yes/no)")
ENABLE_REDIRECT="no"

if [ "$ENABLE_HTTPS" = "yes" ]; then
    ENABLE_REDIRECT=$(ask "Enable HTTP -> HTTPS redirect? (yes/no)")

    CERT_SRC=$(ask "Full path to SSL cert (PEM or CRT)")
    [ -f "$CERT_SRC" ] || error "Certificate file not found"

    KEY_SRC=$(ask "Full path to SSL key (leave empty if cert is PEM)")
    [ -n "$KEY_SRC" ] && [ ! -f "$KEY_SRC" ] && error "Key file not found"
fi

BACKUP_DIR="/var/backups/haproxy-$(date +%F-%H%M%S)"

echo
info "Install prefix : $INSTALL_PREFIX"
info "Config dir     : $CONF_DIR"
info "Backend        : $BACKEND"
info "HTTPS enabled  : $ENABLE_HTTPS"
info "Backup dir     : $BACKUP_DIR"
echo

read -rp "Proceed with installation? (yes/no): " CONFIRM
[ "$CONFIRM" != "yes" ] && error "Aborted"

# ------------------ BACKUP ------------------
if [ -d "$CONF_DIR" ]; then
    info "Backing up existing config"
    mkdir -p "$BACKUP_DIR"
    cp -r "$CONF_DIR" "$BACKUP_DIR/"
fi

# ------------------ EXTRACT ------------------
WORKDIR=$(mktemp -d)
info "Extracting tarball"
tar -xf "$TARBALL" -C "$WORKDIR"

SRC_DIR=$(find "$WORKDIR" -maxdepth 1 -type d -name "haproxy*" | head -1)
[ -d "$SRC_DIR" ] || error "Source directory not found"
cd "$SRC_DIR"

# ------------------ BUILD & INSTALL ------------------
info "Building HAProxy"
make TARGET=linux-glibc USE_OPENSSL=1 USE_ZLIB=1 USE_PCRE=1

info "Installing to $INSTALL_PREFIX"
make install PREFIX="$INSTALL_PREFIX"

# ------------------ SSL SETUP ------------------
if [ "$ENABLE_HTTPS" = "yes" ]; then
    SSL_DIR="${INSTALL_PREFIX}/ssl"
    mkdir -p "$SSL_DIR"
    chmod 700 "$SSL_DIR"

    CERT_PEM="${SSL_DIR}/haproxy.pem"

    if [ -n "$KEY_SRC" ]; then
        cat "$CERT_SRC" "$KEY_SRC" > "$CERT_PEM"
    else
        cp "$CERT_SRC" "$CERT_PEM"
    fi

    chmod 600 "$CERT_PEM"
fi

# ------------------ CONFIG ------------------
mkdir -p "$CONF_DIR"

cat > "$CONF_DIR/haproxy.cfg" <<EOF
global
    daemon
    maxconn 2048

defaults
    mode http
    timeout connect 5s
    timeout client  30s
    timeout server  30s

backend app_back
    balance roundrobin
    option httpchk
    server app1 ${BACKEND} check
EOF

if [ "$ENABLE_HTTPS" = "yes" ]; then
    if [ "$ENABLE_REDIRECT" = "yes" ]; then
        cat >> "$CONF_DIR/haproxy.cfg" <<EOF

frontend http_front
    bind *:80
    http-request redirect scheme https code 301
EOF
    fi

    cat >> "$CONF_DIR/haproxy.cfg" <<EOF

frontend https_front
    bind *:443 ssl crt ${CERT_PEM}
    default_backend app_back
EOF
else
    cat >> "$CONF_DIR/haproxy.cfg" <<EOF

frontend http_front
    bind *:80
    default_backend app_back
EOF
fi

# ------------------ VALIDATE ------------------
info "Validating config"
"$INSTALL_PREFIX/sbin/haproxy" -c -f "$CONF_DIR/haproxy.cfg"

# ------------------ TEMP START ------------------
info "Starting HAProxy for test"
"$INSTALL_PREFIX/sbin/haproxy" -f "$CONF_DIR/haproxy.cfg" -D
sleep 2

# ------------------ TESTS ------------------
if [ "$ENABLE_HTTPS" = "yes" ]; then
    HTTPS_CODE=$(curl -k -s -o /dev/null -w "%{http_code}" \
        "https://127.0.0.1${TEST_PATH}")
    [[ "$HTTPS_CODE" =~ ^2|3 ]] || error "HTTPS test failed (${HTTPS_CODE})"

    if [ "$ENABLE_REDIRECT" = "yes" ]; then
        REDIR_CODE=$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1${TEST_PATH}")
        [[ "$REDIR_CODE" =~ ^301|302 ]] || error "Redirect test failed (${REDIR_CODE})"
    fi
else
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
        "http://127.0.0.1${TEST_PATH}")
    [[ "$HTTP_CODE" =~ ^2|3 ]] || error "HTTP test failed (${HTTP_CODE})"
fi

pkill haproxy || true

# ------------------ SYSTEMD ------------------
info "Creating systemd service"

cat > /etc/systemd/system/haproxy.service <<EOF
[Unit]
Description=HAProxy Load Balancer
After=network.target

[Service]
ExecStart=${INSTALL_PREFIX}/sbin/haproxy -Ws -f ${CONF_DIR}/haproxy.cfg -p /run/haproxy.pid
ExecReload=/bin/kill -USR2 \$MAINPID
Restart=always
LimitNOFILE=100000

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reexec
systemctl daemon-reload
systemctl enable haproxy
systemctl start haproxy

systemctl is-active --quiet haproxy || error "HAProxy failed to start"

echo
echo "====== INSTALLATION SUCCESSFUL ======"
echo "Install Path : $INSTALL_PREFIX"
echo "Config       : $CONF_DIR/haproxy.cfg"
echo "HTTPS        : $ENABLE_HTTPS"
echo "Service      : systemctl status haproxy"
echo
