#!/bin/bash
set -o pipefail

# ================= CONFIG =================
CPU_THRESHOLD=30
MEM_THRESHOLD=30
DISK_THRESHOLD=70
CURL_TIMEOUT=5

REGISTRIES=(
  "https://registry-1.docker.io"
  "https://registry.example.com"
)
# =========================================

STATUS=0

fail() { echo "ERROR: $1"; exit 2; }
warn() { echo "WARNING: $1"; STATUS=1; }

# ---------- VALIDATION ----------
for cmd in awk df curl dig; do
    command -v "$cmd" >/dev/null 2>&1 || fail "$cmd not found"
done

# ---------- CPU CHECK ----------
read -r _ u n s i rest < /proc/stat || fail "Cannot read /proc/stat"
sleep 1
read -r _ u2 n2 s2 i2 rest < /proc/stat || fail "Cannot read /proc/stat"

CPU_IDLE=$((i2 - i))
CPU_TOTAL=$(((u2 + n2 + s2 + i2) - (u + n + s + i)))
CPU_USAGE=$((100 * (CPU_TOTAL - CPU_IDLE) / CPU_TOTAL))

echo "CPU_USAGE=${CPU_USAGE}%"
[ "$CPU_USAGE" -ge "$CPU_THRESHOLD" ] && warn "CPU usage above ${CPU_THRESHOLD}%"

# ---------- MEMORY CHECK ----------
MEM_TOTAL=$(awk '/MemTotal/ {print $2}' /proc/meminfo)
MEM_AVAIL=$(awk '/MemAvailable/ {print $2}' /proc/meminfo)

[ -z "$MEM_TOTAL" ] || [ -z "$MEM_AVAIL" ] && fail "Cannot read memory stats"

MEM_USED=$((MEM_TOTAL - MEM_AVAIL))
MEM_USAGE=$((MEM_USED * 100 / MEM_TOTAL))

echo "MEMORY_USAGE=${MEM_USAGE}%"
[ "$MEM_USAGE" -ge "$MEM_THRESHOLD" ] && warn "Memory usage above ${MEM_THRESHOLD}%"

# ---------- DISK CHECK ----------
DISK_WARN=0

while read -r fs size avail use mount; do
    DISK_WARN=1
    echo "DISK_USAGE=${use}% | FS=${fs} | MOUNT=${mount}"
done < <(
    df -hP 2>/dev/null | awk -v TH="$DISK_THRESHOLD" '
        NR>1 {
            gsub("%","",$5)
            if ($5 >= TH)
                print $1, $2, $4, $5, $6
        }'
)

[ "$DISK_WARN" -eq 1 ] && warn "Disk usage above ${DISK_THRESHOLD}%"

# ---------- DOCKER CHECK (NON-ROOT) ----------
if command -v docker >/dev/null 2>&1; then
    DOCKER_OUT=$(docker info 2>&1)
    RC=$?

    if [ "$RC" -ne 0 ]; then
        case "$DOCKER_OUT" in
            *"Cannot connect to the Docker daemon"*)
                warn "Docker daemon not running or unreachable"
                ;;
            *"permission denied"*|*"Got permission denied"*)
                warn "Docker running but user lacks permission"
                ;;
            *)
                warn "Docker check failed"
                ;;
        esac
    else
        VERSION=$(echo "$DOCKER_OUT" | awk -F': ' '/Server Version/ {print $2}')
        echo "DOCKER_STATUS=RUNNING | VERSION=${VERSION:-unknown}"
    fi
else
    warn "Docker CLI not installed"
fi

# ---------- DNS CHECK (dig + resolv.conf) ----------
DNS_OK=0

if [ ! -r /etc/resolv.conf ]; then
    warn "DNS_STATUS=FAILED"
else
    NAMESERVERS=$(awk '/^nameserver/ {print $2}' /etc/resolv.conf)

    if [ -z "$NAMESERVERS" ]; then
        warn "DNS_STATUS=FAILED"
    else
        for NS in $NAMESERVERS; do
            # Query root zone (.) — safest universal DNS test
            if dig @"$NS" . NS +time=2 +tries=1 +short >/dev/null 2>&1; then
                DNS_OK=1
                break
            fi
        done

        if [ "$DNS_OK" -eq 1 ]; then
            echo "DNS_STATUS=OK"
        else
            warn "DNS_STATUS=FAILED"
        fi
    fi
fi

# ---------- DOCKER REGISTRY CHECK ----------
for REG in "${REGISTRIES[@]}"; do
    URL="${REG%/}/v2/"

    CODE=$(curl -k -s -o /dev/null \
        --connect-timeout "$CURL_TIMEOUT" \
        --max-time "$CURL_TIMEOUT" \
        -w "%{http_code}" \
        "$URL")

    case "$CODE" in
        200)
            echo "REGISTRY=${REG} STATUS=OK (200)"
            ;;
        401)
            echo "REGISTRY=${REG} STATUS=OK (401 Auth Required)"
            ;;
        403)
            warn "REGISTRY=${REG} STATUS=FORBIDDEN (403)"
            ;;
        000)
            warn "REGISTRY=${REG} STATUS=UNREACHABLE"
            ;;
        *)
            warn "REGISTRY=${REG} STATUS=ERROR (HTTP ${CODE})"
            ;;
    esac
done

# ---------- FINAL STATUS ----------
if [ "$STATUS" -eq 0 ]; then
    echo "OK: System, Docker, DNS, and registries are healthy"
    exit 0
fi

exit 0
