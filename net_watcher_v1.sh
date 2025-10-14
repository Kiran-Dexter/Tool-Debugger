#!/usr/bin/env bash
# nw-watcher-v5.sh — TUI + plain-text NIC/TCP watcher with NEW/Public flags + end-of-run summary.
# Safe for non-root. Low overhead. Linux only.

# --- ensure bash, not sh ---
if [ -z "${BASH_VERSION:-}" ]; then
  exec /usr/bin/env bash "$0" "$@"
fi
set -uE -o pipefail

# ------------------ Tunables (env overrides) ------------------
INTERVAL="${INTERVAL:-1}"          # seconds per tick (>=1 recommended)
FLOWS_MAX="${FLOWS_MAX:-200}"      # max flows parsed per tick
INCLUDE_LO="${INCLUDE_LO:-0}"      # 1 = include loopback
ROUTE_TTL="${ROUTE_TTL:-30}"       # seconds to cache ip->iface lookups
OUT_DIR="${OUT_DIR:-.}"            # where the .txt log goes (default current dir)
# --------------------------------------------------------------

# ------------------ Basic env & deps checks -------------------
if [[ ! -r /proc/net/dev ]]; then
  echo "ERROR: Linux only; /proc/net/dev not found." >&2; exit 2
fi

need() { command -v "$1" >/dev/null 2>&1 || { echo "ERROR: missing '$1'." >&2; exit 2; }; }
need ss
need ip
need awk
need sed
# --------------------------------------------------------------

# ------------------ Log file setup ----------------------------
START_ID="$(date +%d%m%y%H%M%S)"
mkdir -p "$OUT_DIR" 2>/dev/null || { echo "ERROR: cannot create OUT_DIR='$OUT_DIR'." >&2; exit 2; }
LOG_PATH="$OUT_DIR/nw_${START_ID}.txt"
if ! : >>"$LOG_PATH" 2>/dev/null; then
  echo "ERROR: cannot write to '$LOG_PATH'." >&2; exit 2
fi
# --------------------------------------------------------------

# ------------------ Small helpers -----------------------------
now_iso() { date -u +%Y-%m-%dT%H:%M:%SZ; }

term_cols() {
  local c
  c="$(tput cols 2>/dev/null || true)"
  if [[ -z "${c:-}" ]]; then
    c="$(stty size 2>/dev/null | awk '{print $2}' || true)"
  fi
  echo "${c:-120}"
}

ellipsize() {
  # $1=text $2=width
  local s="$1" w="${2:-20}"
  (( w<=0 )) && { printf ""; return; }
  local l=${#s}
  (( l<=w )) && { printf "%s" "$s"; return; }
  (( w<=3 )) && { printf "%.*s" "$w" "$s"; return; }
  # no unicode ellipsis to avoid encoding issues
  printf "%s" "$(printf "%s" "$s" | head -c $((w-1)))"
}
# --------------------------------------------------------------

# ------------------ Public IP checks (light) ------------------
ip_only() {
  # [v6]:port%zone or ip:port -> ip
  local a="$1" ip
  if [[ "$a" == \[*\]*:* ]]; then ip="${a%%]*}"; ip="${ip#\[}"; else ip="${a%:*}"; fi
  ip="${ip%%%*}"
  printf '%s' "$ip"
}
is_public_v4() {
  local ip="$1"
  [[ -z "$ip" || "$ip" == "*" ]] && return 1
  [[ "$ip" =~ ^10\. ]] && return 1
  [[ "$ip" =~ ^192\.168\. ]] && return 1
  if [[ "$ip" =~ ^172\.([0-9]{1,3})\. ]]; then
    local n="${BASH_REMATCH[1]}"; (( n>=16 && n<=31 )) && return 1
  fi
  [[ "$ip" =~ ^127\. ]] && return 1
  [[ "$ip" =~ ^169\.254\. ]] && return 1
  [[ "$ip" =~ ^0\. ]] && return 1
  [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]
}
is_public_v6() {
  local ip="$1"
  [[ -z "$ip" || "$ip" == "*" ]] && return 1
  [[ "$ip" == "::1" ]] && return 1
  [[ "$ip" =~ ^[Ff][CcDdEeFf] ]] && return 1   # fc00::/7
  [[ "$ip" =~ ^[Ff][Ee]80 ]] && return 1       # fe80::/10
  [[ "$ip" == *:* ]]
}
is_public_ip() {
  local ip="$1"
  if [[ "$ip" == *:* ]]; then
    is_public_v6 "$ip"
  else
    is_public_v4 "$ip"
  fi
}
# --------------------------------------------------------------

# ------------------ /proc + iface helpers ---------------------
read_netdev() { # name rb rp re rd tb tp te td
  awk 'NR>2 {gsub(":","",$1); printf "%s %s %s %s %s %s %s %s\n",$1,$2,$3,$4,$5,$10,$11,$12 }' /proc/net/dev 2>/dev/null || true
}
iface_state() {
  local ifn="$1" c
  if [[ -r "/sys/class/net/$ifn/carrier" ]]; then
    read -r c < "/sys/class/net/$ifn/carrier" || c=""
    [[ "$c" == "1" ]] && { echo up; return; }
    [[ "$c" == "0" ]] && { echo down; return; }
  fi
  echo "?"
}
iface_ips_txt() { # space-separated v4/v6 list with ** for public
  local ifn="$1" out=""
  while read -r fam addr _; do
    [[ -z "$addr" ]] && continue
    local ip="${addr%/*}" mark=""
    if is_public_ip "$ip"; then mark=" **"; fi
    out+="${ip}${mark} "
  done < <(ip -o addr show dev "$ifn" 2>/dev/null | awk '{print $2,$4}')
  echo "${out%% }"
}
# --------------------------------------------------------------

# ------------------ Route cache (ip -> iface) -----------------
declare -A IFACE_CACHE IFACE_EXP
route_iface() {
  local ip="$1" now dev
  now="$(date +%s)"
  if [[ -n "${IFACE_CACHE[$ip]:-}" && "${IFACE_EXP[$ip]:-0}" -gt "$now" ]]; then
    printf '%s' "${IFACE_CACHE[$ip]}"; return
  fi
  dev="$(ip route get "$ip" 2>/dev/null | awk '{for(i=1;i<=NF;i++){if($i=="dev"){print $(i+1); exit}}}')"
  IFACE_CACHE[$ip]="$dev"; IFACE_EXP[$ip]=$((now+ROUTE_TTL))
  printf '%s' "$dev"
}
# --------------------------------------------------------------

# ------------------ ss runner + parser ------------------------
parse_users() { # users:(("comm",pid=1234, ...)) -> echo "pid|comm"
  local line="$1" u pid comm
  [[ "$line" != *"users:("* ]] && { echo "|"; return; }
  u="${line#*users:(}"; u="${u%%)*}"
  if [[ "$u" == *\"* ]]; then comm="${u#*\"}"; comm="${comm%%\"*}"; fi
  if [[ "$u" == *"pid="* ]]; then pid="${u#*pid=}"; pid="${pid%%[,)]*}"; fi
  echo "${pid:-}|${comm:-}"
}
run_ss() {
  local out
  if out="$(ss -H -tnp 2>/dev/null)"; then PROC_MODE="limited"; echo "$out"; return 0; fi
  PROC_MODE="off"; ss -H -tn 2>/dev/null
}
# --------------------------------------------------------------

# ------------------ Rate state priming -----------------------
declare -A PR_RB PR_TB PR_RE PR_TE PR_RD PR_TD
last_ms="$(date +%s%3N)"
while read -r i rb rp re rd tb tp te td; do
  PR_RB[$i]=$rb; PR_TB[$i]=$tb; PR_RE[$i]=$re; PR_TE[$i]=$te; PR_RD[$i]=$rd; PR_TD[$i]=$td
done < <(read_netdev)
sleep 0.2
# --------------------------------------------------------------

# ------------------ NEW tracking (per run) -------------------
declare -A SEEN_KEYS          # key=pid|src_ip|dst_ip|proto -> 1
SEEN_NEW_LINES=""             # lines to print in final SUMMARY
# --------------------------------------------------------------

# ------------------ Final SUMMARY at exit --------------------
on_exit_summary() {
  [[ -z "${SEEN_NEW_LINES:-}" ]] && exit 0
  {
    echo "SUMMARY$(printf '%s' "$SEEN_NEW_LINES" | sed 's/^/ ; /')"
  } >>"$LOG_PATH" 2>/dev/null || true
}
trap on_exit_summary EXIT INT
# --------------------------------------------------------------

# ------------------ Table renderer ---------------------------
draw_table() { # args: "Header:Width:align(l|r|c)" ... ; reads rows "col1|col2|..."
  local specs=("$@") cols="$(term_cols)" sep="|"
  local widths=() aligns=() names=() sum=0 i s name w a
  for s in "${specs[@]}"; do
    name="${s%%:*}"; s="${s#*:}"; w="${s%%:*}"; a="${s##*:}"
    names+=("$name"); widths+=("$w"); aligns+=("$a"); sum=$((sum+w+1))
  done
  local over=$(( sum+1 - cols ))
  while (( over > 0 )); do
    local idx=-1 best=0 j
    for j in "${!widths[@]}"; do (( widths[j] > best && widths[j] > 6 )) && { best=${widths[j]}; idx=$j; }; done
    (( idx<0 )) && break
    widths[$idx]=$(( widths[$idx]-1 )); over=$(( over-1 ))
  done
  local top="+"
  for w in "${widths[@]}"; do
    for ((i=0;i<w;i++)); do top="${top}-"; done
    top="${top}+"
  done
  echo "$top"
  local hdr="|"
  for i in "${!names[@]}"; do
    local txt="${names[$i]}" w="${widths[$i]}" a="${aligns[$i]}" cell
    if [[ "$a" == "r" ]]; then cell=$(printf "%*s" "$w" "$txt")
    elif [[ "$a" == "c" ]]; then
      local len=${#txt}
      if (( len>=w )); then cell="$(ellipsize "$txt" "$w")"
      else
        local left=$(( (w-len)/2 )); printf -v cell "%*s%s%*s" "$left" "" "$txt" "$((w-len-left))" ""
      fi
    else cell=$(printf "%-*s" "$w" "$txt"); fi
    hdr+="$cell|"
  done
  echo "$hdr"; echo "$top"
  local row
  while IFS= read -r row; do
    [[ -z "$row" ]] && continue
    IFS="|" read -r -a A <<<"$row"
    local out="|"
    for i in "${!widths[@]}"; do
      local t="${A[$i]:-}" w="${widths[$i]}" a="${aligns[$i]}"
      t="$(ellipsize "$t" "$w")"
      local cell
      if [[ "$a" == "r" ]]; then cell=$(printf "%*s" "$w" "$t")
      elif [[ "$a" == "c" ]]; then
        local len=${#t}
        if (( len>=w )); then cell="$t"
        else
          local left=$(( (w-len)/2 )); printf -v cell "%*s%s%*s" "$left" "" "$t" "$((w-len-left))" ""
        fi
      else cell=$(printf "%-*s" "$w" "$t"); fi
      out+="$cell|"
    done
    echo "$out"
  done
  echo "$top"
}
# --------------------------------------------------------------

# ------------------ Write header to log ----------------------
{
  echo "NIC Watch (plain text) - started $(date -u)   file=$(basename "$LOG_PATH")"
  echo
} >>"$LOG_PATH" 2>/dev/null || true
# --------------------------------------------------------------

# ====================== MAIN LOOP ============================
while :; do
  ts="$(now_iso)"
  now_s="$(date +%s)"
  curr_ms="$(date +%s%3N)"
  dt_ms=$(( curr_ms - last_ms ))
  (( dt_ms <= 0 )) && dt_ms=1
  last_ms="$curr_ms"
  dt="$(awk -v ms="$dt_ms" 'BEGIN{printf "%.3f", (ms/1000.0)}')"

  # -------- Interfaces snapshot --------
  IF_ROWS=()
  while read -r ifn rb rp re rd tb tp te td; do
    [[ -z "$ifn" ]] && continue
    [[ "$INCLUDE_LO" -eq 0 && "$ifn" == "lo" ]] && continue
    # deltas
    drb=$(( rb - ${PR_RB[$ifn]:-rb} )); (( drb<0 )) && drb=0
    dtb=$(( tb - ${PR_TB[$ifn]:-tb} )); (( dtb<0 )) && dtb=0
    dre=$(( re - ${PR_RE[$ifn]:-re} )); (( dre<0 )) && dre=0
    dte=$(( te - ${PR_TE[$ifn]:-te} )); (( dte<0 )) && dte=0
    drd=$(( rd - ${PR_RD[$ifn]:-rd} )); (( drd<0 )) && drd=0
    dtd=$(( td - ${PR_TD[$ifn]:-td} )); (( dtd<0 )) && dtd=0
    PR_RB[$ifn]=$rb; PR_TB[$ifn]=$tb; PR_RE[$ifn]=$re; PR_TE[$ifn]=$te; PR_RD[$ifn]=$rd; PR_TD[$ifn]=$td
    # rates
    rxBps="$(awk -v d="$dt" -v v="$drb" 'BEGIN{printf "%.0f",(d>0? v/d:0)}')"
    txBps="$(awk -v d="$dt" -v v="$dtb" 'BEGIN{printf "%.0f",(d>0? v/d:0)}')"
    errps="$(awk -v d="$dt" -v v="$((dre+dte))" 'BEGIN{printf "%.2f",(d>0? v/d:0)}')"
    dropps="$(awk -v d="$dt" -v v="$((drd+dtd))" 'BEGIN{printf "%.2f",(d>0? v/d:0)}')"
    state="$(iface_state "$ifn")"
    ips_txt="$(iface_ips_txt "$ifn")"
    IF_ROWS+=( "$ifn|$state|$rxBps B/s|$txBps B/s|$errps|$dropps|${ips_txt:--}" )
  done < <(read_netdev)

  # -------- Flows snapshot --------
  FLOWS=()
  flows_raw="$(run_ss || true)"
  saw_pid=0; count=0
  while IFS= read -r ln; do
    [[ -z "$ln" ]] && continue
    proto="$(awk '{print tolower($1)}' <<<"$ln")" || continue
    state="$(awk '{print $2}' <<<"$ln")" || continue
    laddr="$(awk '{print $5}' <<<"$ln")" || continue
    raddr="$(awk '{print $6}' <<<"$ln")" || continue
    pidcomm="$(parse_users "$ln")"; pid="${pidcomm%%|*}"; comm="${pidcomm#*|}"
    [[ -n "$pid" && "$pid" =~ ^[0-9]+$ ]] || pid="null"
    [[ "$pid" != "null" ]] && saw_pid=1
    src_ip="$(ip_only "$laddr")"; dst_ip="$(ip_only "$raddr")"
    is_public_ip "$src_ip"; src_pub=$(( $?==0 ? 1 : 0 ))
    is_public_ip "$dst_ip"; dst_pub=$(( $?==0 ? 1 : 0 ))
    dev=""; [[ -n "$dst_ip" ]] && dev="$(route_iface "$dst_ip")"; [[ -z "$dev" && -n "$src_ip" ]] && dev="$(route_iface "$src_ip")"

    # NEW detection (pid|src_ip|dst_ip|proto)
    key="${pid}|${src_ip}|${dst_ip}|${proto}"
    NEW=""
    if [[ -z "${SEEN_KEYS[$key]:-}" ]]; then
      SEEN_KEYS[$key]=1; NEW="NEW"
      conn="$proto"; [[ $src_pub -eq 1 || $dst_pub -eq 1 ]] && conn="${conn}|PUBLIC" || conn="${conn}|PRIVATE"
      SEEN_NEW_LINES+=$'\n'"PID:${pid} | SRC:${laddr} | DEST:${raddr} | CONNECTION:${conn} | STATE:${state} | IFACE:${dev:-?}"
    fi

    # table row
    ldisp="$laddr"; rdisp="$raddr"; [[ $src_pub -eq 1 ]] && ldisp="${ldisp} **"; [[ $dst_pub -eq 1 ]] && rdisp="${rdisp} **"
    pidcol="$([[ "$pid" == "null" ]] && echo "-" || echo "$pid")"
    commcol="$([[ -n "$comm" ]] && echo "$comm" || echo "-")"
    FLOWS+=( "${dev:--}|$proto|$ldisp|->|$rdisp|$state|$pidcol|$commcol|$NEW" )
    (( ++count >= FLOWS_MAX )) && break
  done <<<"$flows_raw"
  [[ "${PROC_MODE:-off}" != "off" ]] && PROC_MODE=$([[ $saw_pid -eq 1 ]] && echo "full" || echo "limited")

  # -------- Append snapshot to TXT log --------
  {
    echo "=== $ts  interval=${INTERVAL}s  proc=${PROC_MODE:-off} ==="
    echo "[Interfaces]"
    if ((${#IF_ROWS[@]}==0)); then
      echo "  (none)"
    else
      for r in "${IF_ROWS[@]}"; do
        IFS="|" read -r a b c d e f g <<<"$r"
        printf "  %-8s %-5s  RX:%-10s TX:%-10s Err/s:%-6s Drop/s:%-6s  %s\n" "$a" "$b" "$c" "$d" "$e" "$f" "$g"
      done
    fi
    echo "[TCP Flows]"
    if ((${#FLOWS[@]}==0)); then
      echo "  (none)"
    else
      for r in "${FLOWS[@]}"; do
        IFS="|" read -r IF P SRC AR DST ST PID PROC NEW <<<"$r"
        printf "  %-8s %-5s %-38s %s %-38s %-10s pid:%-7s %-18s %s\n" "$IF" "$P" "$SRC" "$AR" "$DST" "$ST" "$PID" "$PROC" "$NEW"
      done
    fi
    echo
  } >>"$LOG_PATH" 2>/dev/null || true

  # -------- TUI render --------
  printf "\033[2J\033[H"
  echo "NIC Watch - $ts   interval=${INTERVAL}s   ${PROC_MODE:-off}   log=$(basename "$LOG_PATH")"

  echo; echo "== Interfaces =="
  printf "%s\n" "$(printf "%s\n" "${IF_ROWS[@]}" | draw_table \
    "IF:8:l" "State:7:l" "RX:12:r" "TX:12:r" "Err/s:8:r" "Drop/s:8:r" "IP(s) (*=PUBLIC):40:l")"

  echo; echo "== TCP Flows =="
  if (( ${#FLOWS[@]} )); then
    printf "%s\n" "$(printf "%s\n" "${FLOWS[@]}" | draw_table \
      "IF:8:l" "Proto:5:l" "Source:30:l" " :2:c" "Destination:30:l" "State:10:l" "PID:7:r" "Proc:18:l" "NEW:4:c")"
  else
    echo "(none)"
  fi

  sleep "$INTERVAL"
done
