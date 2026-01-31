#!/bin/bash
set -euo pipefail

error() { echo "ERROR: $1"; exit 1; }
info()  { echo "[INFO] $1"; }
warn()  { echo "[WARN] $1"; }

need() { command -v "$1" >/dev/null 2>&1 || error "$1 not found"; }

need ps
need awk
need sed
need grep
need kill
need readlink

HAS_SYSTEMCTL=0
command -v systemctl >/dev/null 2>&1 && HAS_SYSTEMCTL=1

# -------- Find running haproxy PIDs --------
get_pids() {
  ps -eo pid=,comm=,args= | awk '$2=="haproxy" {print $1}'
}

# -------- Get full cmdline for a PID --------
pid_cmdline() {
  local pid="$1"
  ps -p "$pid" -o args= 2>/dev/null || true
}

# -------- Extract -f <config> from cmdline --------
extract_cfg() {
  local cmd="$1"
  # Handles: -f /path or -f/path
  echo "$cmd" | sed -nE 's/.*(^|[[:space:]])-f[[:space:]]*([^[:space:]]+).*/\2/p' | head -1
}

# -------- Extract binary path from cmdline --------
extract_bin() {
  local cmd="$1"
  # First token is usually binary
  echo "$cmd" | awk '{print $1}' | head -1
}

# -------- Resolve absolute binary path --------
resolve_bin() {
  local b="$1"
  # If it's absolute, keep; else try PATH
  if [[ "$b" == /* ]]; then
    readlink -f "$b" 2>/dev/null || echo "$b"
  else
    command -v "$b" 2>/dev/null || echo "$b"
  fi
}

# -------- Guess install prefix from /path/sbin/haproxy --------
guess_prefix() {
  local binpath="$1"
  # common tarball: /apps/haproxy/sbin/haproxy -> prefix /apps/haproxy
  if [[ "$binpath" == */sbin/haproxy ]]; then
    echo "${binpath%/sbin/haproxy}"
  elif [[ "$binpath" == */bin/haproxy ]]; then
    echo "${binpath%/bin/haproxy}"
  else
    echo ""
  fi
}

# -------- Stop haproxy cleanly --------
stop_pids_cleanly() {
  local pids=("$@")
  [ "${#pids[@]}" -eq 0 ] && return 0

  info "Stopping HAProxy processes (TERM -> wait -> KILL if needed)"
  for pid in "${pids[@]}"; do
    kill -TERM "$pid" 2>/dev/null || true
  done

  # Wait up to 10 seconds
  for _ in $(seq 1 10); do
    sleep 1
    local still
    still=$(get_pids | tr '\n' ' ')
    [ -z "$still" ] && return 0
  done

  warn "Some HAProxy PIDs still alive, sending KILL"
  for pid in "${pids[@]}"; do
    kill -KILL "$pid" 2>/dev/null || true
  done

  sleep 1
}

# -------- Detect systemd unit details --------
detect_systemd_execstart() {
  [ "$HAS_SYSTEMCTL" -eq 1 ] || return 1
  systemctl cat haproxy >/dev/null 2>&1 || return 1
  systemctl show -p ExecStart haproxy 2>/dev/null | sed 's/^ExecStart=//'
}

# -------- Main detection --------
PIDS=($(get_pids || true))

BIN_PATH=""
CFG_PATH=""
PREFIX=""

if [ "${#PIDS[@]}" -gt 0 ]; then
  info "Found running HAProxy PIDs: ${PIDS[*]}"
  # Use first PID as reference
  CMD=$(pid_cmdline "${PIDS[0]}")
  BIN_PATH=$(resolve_bin "$(extract_bin "$CMD")")
  CFG_PATH=$(extract_cfg "$CMD")
  PREFIX=$(guess_prefix "$BIN_PATH")
fi

# If systemd unit exists, prefer its ExecStart (more authoritative)
SYSTEMD_EXEC=""
if SYSTEMD_EXEC=$(detect_systemd_execstart); then
  info "Detected systemd unit: haproxy"
  # ExecStart format can be complex; extract the binary path + -f config if present
  # Example: /apps/haproxy/sbin/haproxy -Ws -f /etc/haproxy/haproxy.cfg -p /run/haproxy.pid ...
  SYS_BIN=$(echo "$SYSTEMD_EXEC" | sed -nE 's/.*path=([^ ;]+).*/\1/p')
  # Fallback if 'path=' not present:
  if [ -z "$SYS_BIN" ]; then
    SYS_BIN=$(echo "$SYSTEMD_EXEC" | awk '{print $1}' | head -1)
  fi
  SYS_BIN=$(resolve_bin "$SYS_BIN")
  SYS_CFG=$(echo "$SYSTEMD_EXEC" | sed -nE 's/.*-f[[:space:]]*([^[:space:];]+).*/\1/p' | head -1)

  [ -n "$SYS_BIN" ] && BIN_PATH="$SYS_BIN"
  [ -n "$SYS_CFG" ] && CFG_PATH="$SYS_CFG"
  PREFIX=$(guess_prefix "$BIN_PATH")
fi

echo
info "Auto-detected:"
echo "  Binary  : ${BIN_PATH:-unknown}"
echo "  Config  : ${CFG_PATH:-unknown}"
echo "  Prefix  : ${PREFIX:-unknown}"
echo "  PIDs    : ${PIDS[*]:-none}"
echo

# Safety: refuse to remove system RPM haproxy unless user forces it
FORCE_SYSTEM="no"
if [ -n "$BIN_PATH" ] && [[ "$BIN_PATH" == "/usr/sbin/haproxy" || "$BIN_PATH" == "/usr/bin/haproxy" ]]; then
  warn "Binary appears to be system-installed (${BIN_PATH})."
  read -rp "This looks like RPM-managed HAProxy. Force removal of files anyway? (yes/no): " FORCE_SYSTEM
  [ "$FORCE_SYSTEM" != "yes" ] && error "Refusing to remove system HAProxy binaries. (Stopping only is possible.)"
fi

read -rp "Proceed to STOP HAProxy and REMOVE detected installation? Type REMOVE to confirm: " CONFIRM
[ "$CONFIRM" != "REMOVE" ] && error "Aborted"

# -------- Stop service first (if present) --------
if [ "$HAS_SYSTEMCTL" -eq 1 ] && systemctl cat haproxy >/dev/null 2>&1; then
  info "Stopping systemd service: haproxy"
  systemctl stop haproxy || true
  systemctl disable haproxy || true
  rm -f /etc/systemd/system/haproxy.service /usr/lib/systemd/system/haproxy.service || true
  systemctl daemon-reload || true
fi

# -------- Stop any remaining pids --------
PIDS=($(get_pids || true))
stop_pids_cleanly "${PIDS[@]}"

# Verify stopped
PIDS=($(get_pids || true))
if [ "${#PIDS[@]}" -gt 0 ]; then
  error "HAProxy processes still running after stop attempt: ${PIDS[*]}"
fi
info "HAProxy processes stopped"

# -------- Remove files (prefix + config) --------
if [ -n "${PREFIX:-}" ] && [ -d "$PREFIX" ]; then
  info "Removing install prefix: $PREFIX"
  rm -rf "$PREFIX"
else
  warn "Install prefix not found or not a directory; skipping prefix removal"
fi

if [ -n "${CFG_PATH:-}" ] && [ -f "$CFG_PATH" ]; then
  CONF_DIR=$(dirname "$CFG_PATH")
  read -rp "Remove config directory ${CONF_DIR}? (yes/no): " RMCONF
  if [ "$RMCONF" = "yes" ]; then
    info "Removing config directory: $CONF_DIR"
    rm -rf "$CONF_DIR"
  else
    info "Preserving config directory: $CONF_DIR"
  fi
else
  warn "Config file not detected; skipping config removal prompt"
fi

# Cleanup pidfile if left behind
rm -f /run/haproxy.pid 2>/dev/null || true

echo
echo "OK: HAProxy clean removal completed"
