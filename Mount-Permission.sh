#!/bin/bash

set -euo pipefail

WATCH_PATH="/data"

TARGET_USER="root"
TARGET_GROUP="root"

DIR_PERM="775"
FILE_PERM="664"

LOG_FILE="/tmp/mount_watch_$(date +%d%m%Y).log"

log() {
echo "$(date '+%F %T') | $1" >> "$LOG_FILE"
}

[[ -d "$WATCH_PATH" ]] || { log "ERROR: Mount path not found: $WATCH_PATH"; exit 1; }

log "Scanning $WATCH_PATH"

find "$WATCH_PATH" | while read ITEM
do

OWNER=$(stat -c "%U" "$ITEM")
GROUP=$(stat -c "%G" "$ITEM")
PERM=$(stat -c "%a" "$ITEM")

if [[ -f "$ITEM" ]]; then
EXPECTED="$FILE_PERM"
else
EXPECTED="$DIR_PERM"
fi

# Fix ownership
if [[ "$OWNER" != "$TARGET_USER" || "$GROUP" != "$TARGET_GROUP" ]]; then
chown "$TARGET_USER:$TARGET_GROUP" "$ITEM"
log "Ownership fixed: $ITEM"
fi

# Fix permission
if [[ "$PERM" != "$EXPECTED" ]]; then
chmod "$EXPECTED" "$ITEM"
log "Permission fixed: $ITEM"
fi

done

log "Scan completed"
