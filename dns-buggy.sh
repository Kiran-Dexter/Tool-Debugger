#!/usr/bin/env bash
# dns_failover_monitor.sh
#
#
# Examples:
#   ./dns_failover_monitor.sh
#   ./dns_failover_monitor.sh -s "10.0.0.2,10.0.0.3,8.8.8.8" -t example.com --csv
#   ./dns_failover_monitor.sh -t corp.internal -w 200 -c 800
#
# Exit codes: 0=OK, 1=WARN, 2=CRIT, 3=UNKNOWN

set -u
IFS=$'\n\t'

SCRIPT_NAME="$(basename "$0")"

ok()   { echo "$*"; exit 0; }
warn() { echo "$*"; exit 1; }
crit() { echo "$*"; exit 2; }
unk()  { echo "$*"; exit 3; }

need_cmd() { command -v "$1" >/dev/null 2>&1 || unk "UNKNOWN|reason=missing_cmd|cmd=$1"; }

# Defaults
SERVERS_CSV=""              # if empty: auto-detect from resolv.conf
TARGET_DOMAIN="example.com"
WARN_MS=250
CRIT_MS=1000
TIMEOUT_SECS=3
RETRIES=1
CSV_MODE=0                  # 0=key/value, 1=csv
CHECK_PORTS=1               # best-effort via nc if present

usage() {
  cat <<EOF
$SCRIPT_NAME - DNS failover monitor (one-line, machine-friendly)

Options:
  -s "<ip1,ip2,ip3>"  DNS servers (comma-separated). Default: read from /etc/resolv.conf
  -t "<domain>"       Domain to resolve (default: $TARGET_DOMAIN)
  -w <ms>             Warn threshold ms (default: $WARN_MS)
  -c <ms>             Crit threshold ms (default: $CRIT_MS)
  -T <secs>           Timeout seconds per try (default: $TIMEOUT_SECS)
  -r <n>              Retries per server (default: $RETRIES)
  --csv               Output CSV (single line)
  --no-ports          Skip TCP/UDP 53 checks (faster, less noise)
  -h                  Help

Output (default):
  STATUS|picked_server=...|domain=...|ip=...|rtt_ms=...|used_fallback=0|attempted=...|port_udp53=...|port_tcp53=...

CSV output:
  status,picked_server,domain,ip,rtt_ms,used_fallback,attempted,port_udp53,port_tcp53
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -s) SERVERS_CSV="${2:-}"; shift 2 ;;
    -t) TARGET_DOMAIN="${2:-}"; shift 2 ;;
    -w) WARN_MS="${2:-}"; shift 2 ;;
    -c) CRIT_MS="${2:-}"; shift 2 ;;
    -T) TIMEOUT_SECS="${2:-}"; shift 2 ;;
    -r) RETRIES="${2:-}"; shift 2 ;;
    --csv) CSV_MODE=1; shift ;;
    --no-ports) CHECK_PORTS=0; shift ;;
    -h|--help) usage; exit 0 ;;
    *) usage; unk "UNKNOWN|reason=bad_arg|arg=$1" ;;
  esac
done

[[ "$WARN_MS" =~ ^[0-9]+$ ]] || unk "UNKNOWN|reason=bad_warn_ms|value=$WARN_MS"
[[ "$CRIT_MS" =~ ^[0-9]+$ ]] || unk "UNKNOWN|reason=bad_crit_ms|value=$CRIT_MS"
[[ "$TIMEOUT_SECS" =~ ^[0-9]+$ ]] || unk "UNKNOWN|reason=bad_timeout|value=$TIMEOUT_SECS"
[[ "$RETRIES" =~ ^[0-9]+$ ]] || unk "UNKNOWN|reason=bad_retries|value=$RETRIES"
(( WARN_MS < CRIT_MS )) || unk "UNKNOWN|reason=warn_ge_crit|warn_ms=$WARN_MS|crit_ms=$CRIT_MS"

need_cmd awk
need_cmd sed
need_cmd grep

HAS_DIG=0
command -v dig >/dev/null 2>&1 && HAS_DIG=1
if [[ "$HAS_DIG" -eq 0 ]]; then
  need_cmd getent
fi

HAS_NC=0
command -v nc >/dev/null 2>&1 && HAS_NC=1

now_ms() {
  if date +%s%3N >/dev/null 2>&1; then
    date +%s%3N
  else
    echo "$(( $(date +%s) * 1000 ))"
  fi
}

detect_servers() {
  # outputs comma-separated servers
  awk '/^nameserver[ \t]+/ {print $2}' /etc/resolv.conf 2>/dev/null | paste -sd, - || true
}

if [[ -z "$SERVERS_CSV" ]]; then
  SERVERS_CSV="$(detect_servers)"
fi
[[ -n "${SERVERS_CSV:-}" ]] || unk "UNKNOWN|reason=no_dns_servers"

# Normalize server list: split by comma, trim spaces, drop empties
mapfile -t SERVERS < <(echo "$SERVERS_CSV" | tr ',' '\n' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | awk 'NF')

[[ "${#SERVERS[@]}" -gt 0 ]] || unk "UNKNOWN|reason=no_valid_servers|raw=$SERVERS_CSV"

port_check() {
  local proto="$1" host="$2" port="$3"
  [[ "$CHECK_PORTS" -eq 1 ]] || { echo "SKIP"; return 0; }
  [[ "$HAS_NC" -eq 1 ]] || { echo "SKIP"; return 0; }

  if [[ "$proto" == "tcp" ]]; then
    nc -z -w "$TIMEOUT_SECS" "$host" "$port" >/dev/null 2>&1 && echo "OK" || echo "FAIL"
  else
    nc -zu -w "$TIMEOUT_SECS" "$host" "$port" >/dev/null 2>&1 && echo "OK" || echo "FAIL"
  fi
}

dns_query() {
  local domain="$1" server="$2"
  if [[ "$HAS_DIG" -eq 1 ]]; then
    dig @"$server" "$domain" A +tries="$RETRIES" +time="$TIMEOUT_SECS" +short 2>/dev/null | head -n 1
  else
    # NOTE: getent uses system resolver; if dig isn't present you lose server-specific failover.
    getent ahostsv4 "$domain" 2>/dev/null | awk '{print $1; exit}'
  fi
}

# Try each server in order until one resolves successfully
attempted=""
picked=""
ip=""
rtt_ms=""
used_fallback=0
fail_count=0

first_server="${SERVERS[0]}"

for s in "${SERVERS[@]}"; do
  attempted+="${s},"

  start="$(now_ms)"
  ip="$(dns_query "$TARGET_DOMAIN" "$s" || true)"
  end="$(now_ms)"
  rtt_ms=$(( end - start ))

  if [[ -n "${ip:-}" ]]; then
    picked="$s"
    [[ "$picked" != "$first_server" ]] && used_fallback=1
    break
  else
    fail_count=$((fail_count + 1))
  fi
done

# Trim trailing comma
attempted="${attempted%,}"

udp53="$(port_check udp "$first_server" 53)"
tcp53="$(port_check tcp "$first_server" 53)"

# If none worked => CRIT
if [[ -z "${picked:-}" || -z "${ip:-}" ]]; then
  # If ports are FAIL on primary, likely network/firewall/DNS down; but keep it one-line.
  out_kv="CRIT|reason=resolution_failed|domain=$TARGET_DOMAIN|picked_server=NONE|ip=NONE|rtt_ms=NONE|used_fallback=0|attempted=$attempted|port_udp53=$udp53|port_tcp53=$tcp53"
  if [[ "$CSV_MODE" -eq 1 ]]; then
    echo "CRIT,NONE,$TARGET_DOMAIN,NONE,NONE,0,\"$attempted\",$udp53,$tcp53"
  else
    echo "$out_kv"
  fi
  exit 2
fi

# Severity based on latency of the picked server
sev="OK"
if (( rtt_ms >= CRIT_MS )); then
  sev="WARN"  # keep CRIT for actual failure; slow DNS is WARN (more sane operationally)
elif (( rtt_ms >= WARN_MS )); then
  sev="WARN"
fi

# Build output
if [[ "$CSV_MODE" -eq 1 ]]; then
  echo "$sev,$picked,$TARGET_DOMAIN,$ip,$rtt_ms,$used_fallback,\"$attempted\",$udp53,$tcp53"
else
  echo "$sev|picked_server=$picked|domain=$TARGET_DOMAIN|ip=$ip|rtt_ms=$rtt_ms|used_fallback=$used_fallback|attempted=$attempted|port_udp53=$udp53|port_tcp53=$tcp53"
fi

# Exit code
case "$sev" in
  OK) exit 0 ;;
  WARN) exit 1 ;;
  *) exit 3 ;;
esac
