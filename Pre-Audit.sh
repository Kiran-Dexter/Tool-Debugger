#!/bin/bash
# Script 1: RHEL 8/9 Image Build Pre-Install Snapshot
# Purpose: Capture base image package state before installing custom/image software.
# This snapshot will be used by the post-audit script to find what was added.

set -u
set -o pipefail

AUDIT_DIR="/var/tmp/image_audit"
ERROR_LOG="${AUDIT_DIR}/pre_audit_error.log"
META_FILE="${AUDIT_DIR}/pre_audit_metadata.txt"

RPM_BEFORE_NEVRA="${AUDIT_DIR}/rpm_before_nevra.txt"
RPM_BEFORE_NAMES="${AUDIT_DIR}/rpm_before_names.txt"
RPM_BEFORE_TABLE="${AUDIT_DIR}/rpm_before_table.tsv"

DNF_HISTORY_BEFORE="${AUDIT_DIR}/dnf_history_before.txt"
DNF_HISTORY_LAST_ID="${AUDIT_DIR}/dnf_history_last_id_before.txt"

REPO_BEFORE="${AUDIT_DIR}/dnf_repolist_before.txt"
MODULE_BEFORE="${AUDIT_DIR}/dnf_modules_enabled_before.txt"

mkdir -p "$AUDIT_DIR"

: > "$ERROR_LOG"

log_error() {
    echo "[ERROR] $1" | tee -a "$ERROR_LOG" >&2
}

run_cmd() {
    local title="$1"
    local cmd="$2"

    echo "[INFO] $title"

    bash -c "$cmd" 2>> "$ERROR_LOG"

    if [[ $? -ne 0 ]]; then
        log_error "Failed: $title"
        return 1
    fi

    return 0
}

echo "[INFO] Starting pre-install image audit snapshot..."

###############################################################################
# Metadata
###############################################################################

{
    echo "PRE-INSTALL IMAGE AUDIT SNAPSHOT"
    echo "Snapshot Time: $(date)"
    echo "Hostname: $(hostname -f 2>/dev/null || hostname)"
    echo "Kernel: $(uname -r)"
    echo "User: $(whoami)"
    echo "Audit Directory: $AUDIT_DIR"

    if [[ -f /etc/redhat-release ]]; then
        echo "OS Release: $(cat /etc/redhat-release)"
    fi

    if command -v dnf >/dev/null 2>&1; then
        echo "Package Manager: dnf"
    elif command -v yum >/dev/null 2>&1; then
        echo "Package Manager: yum"
    else
        echo "Package Manager: NOT FOUND"
    fi
} > "$META_FILE" 2>> "$ERROR_LOG"

###############################################################################
# RPM baseline
###############################################################################

run_cmd "Capturing RPM baseline with full package NEVRA" \
"rpm -qa --queryformat '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' | sort -f > '$RPM_BEFORE_NEVRA'"

run_cmd "Capturing RPM baseline package names only" \
"rpm -qa --queryformat '%{NAME}\n' | sort -u -f > '$RPM_BEFORE_NAMES'"

run_cmd "Capturing RPM baseline package table" \
"echo -e 'PACKAGE\tVERSION\tRELEASE\tARCH\tVENDOR\tINSTALL_TIME' > '$RPM_BEFORE_TABLE'
rpm -qa --queryformat '%{NAME}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\t%{VENDOR}\t%{INSTALLTIME:date}\n' | sort -f >> '$RPM_BEFORE_TABLE'"

###############################################################################
# DNF/YUM history baseline
###############################################################################

if command -v dnf >/dev/null 2>&1; then
    PKG_MGR="dnf"
elif command -v yum >/dev/null 2>&1; then
    PKG_MGR="yum"
else
    PKG_MGR=""
fi

if [[ -n "$PKG_MGR" ]]; then
    run_cmd "Capturing ${PKG_MGR} history before install" \
    "$PKG_MGR history list > '$DNF_HISTORY_BEFORE'"

    run_cmd "Capturing latest ${PKG_MGR} transaction ID before install" \
    "$PKG_MGR history list | awk 'NR > 2 && \$1 ~ /^[0-9]+$/ {print \$1; exit}' > '$DNF_HISTORY_LAST_ID'"

    run_cmd "Capturing enabled repositories before install" \
    "$PKG_MGR repolist --enabled > '$REPO_BEFORE'"

    run_cmd "Capturing enabled DNF modules before install" \
    "$PKG_MGR module list --enabled > '$MODULE_BEFORE'"
else
    log_error "dnf/yum not found. RPM snapshot captured, but package manager history was not captured."
fi

###############################################################################
# Validation
###############################################################################

RPM_COUNT="$(wc -l < "$RPM_BEFORE_NEVRA" 2>/dev/null || echo 0)"
NAME_COUNT="$(wc -l < "$RPM_BEFORE_NAMES" 2>/dev/null || echo 0)"
LAST_TXN_ID="$(cat "$DNF_HISTORY_LAST_ID" 2>/dev/null || echo NA)"

{
    echo ""
    echo "Snapshot Summary:"
    echo "RPM NEVRA Count: $RPM_COUNT"
    echo "RPM Name Count: $NAME_COUNT"
    echo "Last DNF/YUM Transaction ID Before Install: $LAST_TXN_ID"
} >> "$META_FILE"

echo ""
echo "Pre-install snapshot completed."
echo "Audit directory:"
echo "$AUDIT_DIR"
echo ""
echo "Important files:"
echo "$RPM_BEFORE_NEVRA"
echo "$RPM_BEFORE_NAMES"
echo "$RPM_BEFORE_TABLE"
echo "$DNF_HISTORY_BEFORE"
echo "$DNF_HISTORY_LAST_ID"
echo "$META_FILE"
echo "$ERROR_LOG"
