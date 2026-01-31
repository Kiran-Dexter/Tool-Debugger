#!/bin/bash
set -o pipefail

THRESHOLD=70

# ---------- VALIDATION ----------
command -v df >/dev/null 2>&1 || { echo "ERROR: df not found"; exit 2; }
command -v awk >/dev/null 2>&1 || { echo "ERROR: awk not found"; exit 2; }

if ! [[ "$THRESHOLD" =~ ^[0-9]+$ ]] || [ "$THRESHOLD" -lt 1 ] || [ "$THRESHOLD" -gt 100 ]; then
    echo "ERROR: Invalid threshold: $THRESHOLD"
    exit 2
fi

# Jenkins / non-TTY safe width
COLS=$(tput cols 2>/dev/null || echo 120)

FS_COL=25
SIZE_COL=10
AVAIL_COL=10
USE_COL=6
MOUNT_COL=$((COLS - FS_COL - SIZE_COL - AVAIL_COL - USE_COL - 15))
[ "$MOUNT_COL" -lt 20 ] && MOUNT_COL=20

print_line() {
    printf '%*s\n' "$COLS" '' | tr ' ' '-'
}

print_line
printf "| %-*s | %-*s | %-*s | %-*s | %-*s |\n" \
  "$FS_COL" "Filesystem" \
  "$SIZE_COL" "Size" \
  "$AVAIL_COL" "Avail" \
  "$USE_COL" "Use%" \
  "$MOUNT_COL" "Mounted On"
print_line

FOUND=0
MAX_USE=0

# Use process substitution (NO subshell bug)
while read -r fs size avail use mount; do
    FOUND=1
    (( use > MAX_USE )) && MAX_USE=$use

    printf "| %-*s | %-*s | %-*s | %*s%% | %-*s |\n" \
      "$FS_COL" "$fs" \
      "$SIZE_COL" "$size" \
      "$AVAIL_COL" "$avail" \
      "$USE_COL" "$use" \
      "$MOUNT_COL" "$mount"
done < <(
    df -hP 2>/dev/null | awk -v TH="$THRESHOLD" '
        NR>1 {
            gsub("%","",$5)
            if ($5 >= TH)
                print $1, $2, $4, $5, $6
        }'
)

print_line

if [ "$FOUND" -eq 0 ]; then
    printf "| %-*s |\n" "$((COLS-4))" "All filesystems are below ${THRESHOLD}% usage"
    print_line
    exit 0
fi

# Jenkins-friendly failure threshold
if [ "$MAX_USE" -ge 90 ]; then
    echo "CRITICAL: Disk usage >= 90%"
    exit 1
fi

exit 0
