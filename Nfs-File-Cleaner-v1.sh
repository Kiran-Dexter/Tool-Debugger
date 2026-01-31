#!/bin/bash
set -o pipefail

# ================= CONFIG =================
MOUNT_POINT="/data"
CLEAN_DIRS=("$MOUNT_POINT/tmp" "$MOUNT_POINT/downloads")   # ONLY clean these
LOG_DIR="/tmp"
DISK_THRESHOLD=90
AGE_MINUTES=30
LOCK_FILE="/var/run/data_cleanup.lock"
LOG_FILE="$LOG_DIR/$(date +'%d%m%Y').log"
MAX_DELETES=10000   # safety cap
# ==========================================

# ---------- PRECHECKS ----------
mkdir -p "$LOG_DIR" || exit 1

exec 200>"$LOCK_FILE"
flock -n 200 || {
    echo "[INFO] Cleanup already running. Exiting."
    exit 0
}

command -v df >/dev/null || exit 1
command -v find >/dev/null || exit 1

HAS_LSOF=1
command -v lsof >/dev/null || HAS_LSOF=0

# ---------- FUNCTIONS ----------
disk_usage() {
    df -P "$MOUNT_POINT" | awk 'NR==2 {gsub("%",""); print $5}'
}

log_line() {
    printf "| %-19s | %-8s | %s\n" "$(date '+%F %T')" "$1" "$2" | tee -a "$LOG_FILE"
}

print_header() {
    {
        echo
        echo "=== CLEANUP REPORT ($(date)) ==="
        printf "| %-19s | %-8s | %s\n" "Timestamp" "Status" "File"
        echo "|---------------------|----------|------------------------------"
    } | tee -a "$LOG_FILE"
}

safe_delete() {
    local file="$1"

    if [ "$HAS_LSOF" -eq 1 ] && lsof "$file" >/dev/null 2>&1; then
        log_line "SKIPPED" "$file"
        return
    fi

    if rm -f -- "$file"; then
        log_line "DELETED" "$file"
        ((DELETED++))
    else
        log_line "FAILED" "$file"
        ((FAILED++))
    fi
}

# ---------- VALIDATION ----------
mountpoint -q "$MOUNT_POINT" || {
    echo "[ERROR] $MOUNT_POINT is not a mount point" | tee -a "$LOG_FILE"
    exit 1
}

USAGE=$(disk_usage)
if [ "$USAGE" -lt "$DISK_THRESHOLD" ]; then
    echo "[INFO] Disk usage ${USAGE}% < ${DISK_THRESHOLD}%. No cleanup needed." | tee -a "$LOG_FILE"
    exit 0
fi

# ---------- CLEANUP ----------
print_header

DELETED=0
SKIPPED=0
FAILED=0

for dir in "${CLEAN_DIRS[@]}"; do
    [ -d "$dir" ] || continue

    find "$dir" -type f -mmin +"$AGE_MINUTES" -print0 |
    while IFS= read -r -d '' file; do
        safe_delete "$file"

        CURRENT=$(disk_usage)
        if [ "$CURRENT" -lt "$DISK_THRESHOLD" ]; then
            echo "[INFO] Disk usage now ${CURRENT}%. Stopping cleanup." | tee -a "$LOG_FILE"
            break 2
        fi

        if [ "$DELETED" -ge "$MAX_DELETES" ]; then
            echo "[WARN] Max delete limit reached ($MAX_DELETES). Stopping." | tee -a "$LOG_FILE"
            break 2
        fi
    done
done

# ---------- SUMMARY ----------
{
    echo
    echo "=== SUMMARY ==="
    echo "Deleted : $DELETED"
    echo "Skipped : $SKIPPED"
    echo "Failed  : $FAILED"
    echo "Final Disk Usage: $(disk_usage)%"
} | tee -a "$LOG_FILE"
