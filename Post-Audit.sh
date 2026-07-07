#!/bin/bash
# Script 2: RHEL 8/9 Image Build Post-Install Software Audit
#
# Updated behavior:
#   - If requested package list exists, use it.
#   - If requested package list is missing, auto-detect likely requested/main packages.
#   - Dependencies are still separated.
#   - Detailed config/service/path audit runs only for requested/main packages.

set -u
set -o pipefail

SNAPSHOT_DIR="/var/tmp/image_audit"
REQUESTED_INPUT="${1:-/var/tmp/requested_packages.txt}"

DATE_TIME="$(date '+%Y%m%d_%H%M%S')"
HOSTNAME_SHORT="$(hostname -s 2>/dev/null || hostname)"

OUTDIR="/var/log/image-build-audit"
RUN_DIR="${OUTDIR}/run_${HOSTNAME_SHORT}_${DATE_TIME}"
REPORT="${RUN_DIR}/image_software_audit_report.txt"
ERROR_LOG="${RUN_DIR}/post_audit_error.log"

RPM_BEFORE_NAMES="${SNAPSHOT_DIR}/rpm_before_names.txt"
RPM_BEFORE_NEVRA="${SNAPSHOT_DIR}/rpm_before_nevra.txt"
DNF_HISTORY_LAST_ID_BEFORE="${SNAPSHOT_DIR}/dnf_history_last_id_before.txt"

RPM_AFTER_NAMES="${RUN_DIR}/rpm_after_names.txt"
RPM_AFTER_NEVRA="${RUN_DIR}/rpm_after_nevra.txt"
RPM_ADDED_NAMES="${RUN_DIR}/rpm_added_names.txt"
RPM_ADDED_NEVRA="${RUN_DIR}/rpm_added_nevra.txt"

REQUESTED_NORMALIZED="${RUN_DIR}/requested_packages_normalized.txt"
REQUESTED_STATUS_TSV="${RUN_DIR}/requested_package_input_status.tsv"
AUTO_USERINSTALLED="${RUN_DIR}/dnf_userinstalled_packages.txt"
AUTO_REQUESTED="${RUN_DIR}/requested_packages_auto_detected.txt"
REQUESTED_SOURCE_INFO="${RUN_DIR}/requested_package_source.txt"

REQUESTED_PACKAGES_TSV="${RUN_DIR}/requested_packages.tsv"
DEPENDENCY_PACKAGES_TSV="${RUN_DIR}/dependency_packages_added.tsv"
ADDED_PACKAGES_TSV="${RUN_DIR}/all_added_packages.tsv"

PACKAGE_ROOTS_TSV="${RUN_DIR}/package_install_roots.tsv"
PACKAGE_PATHS_TSV="${RUN_DIR}/package_installed_paths.tsv"
PACKAGE_CONFIG_TSV="${RUN_DIR}/package_config_files.tsv"
PACKAGE_SERVICES_TSV="${RUN_DIR}/package_services.tsv"
PACKAGE_MODIFIED_TSV="${RUN_DIR}/package_modified_files.tsv"
TRANSACTION_TSV="${RUN_DIR}/dnf_yum_transactions_after_baseline.tsv"

VERIFY_DIR="${RUN_DIR}/rpm_verify_raw"
HISTORY_DIR="${RUN_DIR}/dnf_yum_history_info"

mkdir -p "$RUN_DIR" "$VERIFY_DIR" "$HISTORY_DIR"
touch "$REPORT" "$ERROR_LOG"

die() {
    echo "[FATAL] $1" | tee -a "$ERROR_LOG" >&2
    exit 1
}

warn() {
    echo "[WARN] $1" | tee -a "$ERROR_LOG" >&2
}

info() {
    echo "[INFO] $1"
}

print_table() {
    local title="$1"
    local file="$2"

    {
        echo ""
        echo "================================================================================"
        echo "$title"
        echo "================================================================================"
    } >> "$REPORT"

    if [[ ! -s "$file" ]]; then
        echo "No data found." >> "$REPORT"
        return
    fi

    if command -v column >/dev/null 2>&1; then
        column -t -s $'\t' "$file" >> "$REPORT" 2>> "$ERROR_LOG"
    else
        cat "$file" >> "$REPORT"
    fi
}

safe_stat() {
    local file="$1"

    if [[ -e "$file" ]]; then
        stat -c '%A\t%a\t%U\t%G' "$file" 2>> "$ERROR_LOG"
    else
        echo -e "MISSING\tMISSING\tMISSING\tMISSING"
    fi
}

safe_sha256() {
    local file="$1"

    if [[ -f "$file" ]]; then
        sha256sum "$file" 2>> "$ERROR_LOG" | awk '{print $1}'
    else
        echo "NA"
    fi
}

pkg_installed() {
    local pkg="$1"
    rpm -q "$pkg" >/dev/null 2>&1
}

get_pkg_name_from_query() {
    local pkg="$1"
    rpm -q "$pkg" --queryformat '%{NAME}\n' 2>/dev/null | head -1
}

get_pkg_repo() {
    local pkg="$1"

    if command -v dnf >/dev/null 2>&1; then
        dnf repoquery --installed "$pkg" --queryformat '%{repoid}' 2>/dev/null | head -1
    elif command -v yum >/dev/null 2>&1; then
        yum repoquery --installed "$pkg" --queryformat '%{repoid}' 2>/dev/null | head -1
    else
        echo "-"
    fi
}

get_pkg_table_line() {
    local pkg="$1"
    local status="$2"
    local repo

    repo="$(get_pkg_repo "$pkg")"
    [[ -z "$repo" ]] && repo="-"

    rpm -q "$pkg" \
        --queryformat "%{NAME}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\t${status}\t%{VENDOR}\t%{PACKAGER}\t${repo}\t%{INSTALLTIME:date}\n" \
        2>> "$ERROR_LOG"
}

classify_path() {
    local path="$1"

    case "$path" in
        /etc/*)
            echo "CONFIG"
            ;;
        /usr/lib/systemd/system/*.service|/etc/systemd/system/*.service|/lib/systemd/system/*.service)
            echo "SERVICE"
            ;;
        /usr/bin/*|/usr/sbin/*|/bin/*|/sbin/*)
            echo "BINARY"
            ;;
        /opt/*)
            echo "APP_OPT"
            ;;
        /usr/local/*)
            echo "APP_USR_LOCAL"
            ;;
        /var/log/*)
            echo "LOG"
            ;;
        /var/lib/*|/var/opt/*)
            echo "DATA"
            ;;
        /usr/lib/*|/usr/lib64/*|/lib/*|/lib64/*)
            echo "LIBRARY"
            ;;
        /usr/share/doc/*|/usr/share/man/*)
            echo "DOC"
            ;;
        /usr/share/*)
            echo "SHARE"
            ;;
        *)
            echo "OTHER"
            ;;
    esac
}

is_config_like_file() {
    local path="$1"

    echo "$path" | grep -Eiq '(\.conf$|\.cfg$|\.ini$|\.yaml$|\.yml$|\.json$|\.xml$|\.properties$|\.toml$|\.cnf$|\.env$|/conf/|/config/|/etc/|/local/)'
}

sanitize_name() {
    echo "$1" | sed 's#[^A-Za-z0-9_.-]#_#g'
}

###############################################################################
# Validation
###############################################################################

[[ -f "$RPM_BEFORE_NAMES" ]] || die "Missing baseline file: $RPM_BEFORE_NAMES. Run Script 1 first."

if [[ "$(id -u)" -ne 0 ]]; then
    die "Run this script as root/sudo."
fi

if command -v dnf >/dev/null 2>&1; then
    PKG_MGR="dnf"
elif command -v yum >/dev/null 2>&1; then
    PKG_MGR="yum"
else
    PKG_MGR=""
    warn "dnf/yum not found. RPM comparison will work, transaction history will be skipped."
fi

###############################################################################
# Header
###############################################################################

{
    echo "IMAGE BUILD SOFTWARE AUDIT REPORT"
    echo "Hostname: $HOSTNAME_SHORT"
    echo "Audit Time: $(date)"
    echo "Snapshot Directory: $SNAPSHOT_DIR"
    echo "Requested Package Input: $REQUESTED_INPUT"
    echo "Run Directory: $RUN_DIR"
    echo "Error Log: $ERROR_LOG"
    echo ""
    [[ -f /etc/redhat-release ]] && echo "OS Release: $(cat /etc/redhat-release)"
} > "$REPORT"

info "Starting post-install image software audit..."

###############################################################################
# Capture after-state RPM snapshot
###############################################################################

info "Capturing after-install RPM state..."

rpm -qa --queryformat '%{NAME}\n' | sort -u -f > "$RPM_AFTER_NAMES" 2>> "$ERROR_LOG"
rpm -qa --queryformat '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' | sort -f > "$RPM_AFTER_NEVRA" 2>> "$ERROR_LOG"

comm -13 "$RPM_BEFORE_NAMES" "$RPM_AFTER_NAMES" > "$RPM_ADDED_NAMES" 2>> "$ERROR_LOG"

if [[ -f "$RPM_BEFORE_NEVRA" ]]; then
    comm -13 "$RPM_BEFORE_NEVRA" "$RPM_AFTER_NEVRA" > "$RPM_ADDED_NEVRA" 2>> "$ERROR_LOG"
else
    cp "$RPM_ADDED_NAMES" "$RPM_ADDED_NEVRA"
fi

###############################################################################
# Requested package handling
###############################################################################

info "Resolving requested/main packages..."

echo -e "INPUT\tNORMALIZED_PACKAGE\tSTATUS\tSOURCE" > "$REQUESTED_STATUS_TSV"
: > "$REQUESTED_NORMALIZED"
: > "$AUTO_USERINSTALLED"
: > "$AUTO_REQUESTED"

if [[ -f "$REQUESTED_INPUT" ]]; then
    echo "MODE=MANUAL_REQUESTED_FILE" > "$REQUESTED_SOURCE_INFO"
    echo "FILE=$REQUESTED_INPUT" >> "$REQUESTED_SOURCE_INFO"

    while IFS= read -r line || [[ -n "$line" ]]; do
        line="${line%%#*}"
        line="$(echo "$line" | awk '{$1=$1; print}')"
        [[ -z "$line" ]] && continue

        line="$(echo "$line" | tr ',' ' ')"

        for token in $line; do
            [[ -z "$token" ]] && continue

            normalized=""
            status=""

            if [[ "$token" == *.rpm && -f "$token" ]]; then
                normalized="$(rpm -qp "$token" --queryformat '%{NAME}\n' 2>> "$ERROR_LOG" | head -1)"

                if [[ -n "$normalized" ]] && pkg_installed "$normalized"; then
                    status="INSTALLED_FROM_RPM_INPUT"
                    echo "$normalized" >> "$REQUESTED_NORMALIZED"
                else
                    status="RPM_INPUT_NOT_INSTALLED"
                fi
            else
                if pkg_installed "$token"; then
                    normalized="$(get_pkg_name_from_query "$token")"
                    status="INSTALLED"
                    echo "$normalized" >> "$REQUESTED_NORMALIZED"
                else
                    normalized="$token"
                    status="NOT_INSTALLED"
                fi
            fi

            [[ -z "$normalized" ]] && normalized="$token"
            echo -e "${token}\t${normalized}\t${status}\tMANUAL_FILE" >> "$REQUESTED_STATUS_TSV"
        done
    done < "$REQUESTED_INPUT"

else
    warn "Requested package file not found: $REQUESTED_INPUT"
    warn "Auto-detecting likely requested packages from packages added after baseline."

    echo "MODE=AUTO_DETECT" > "$REQUESTED_SOURCE_INFO"
    echo "REASON=Requested package file missing" >> "$REQUESTED_SOURCE_INFO"

    if [[ -n "$PKG_MGR" ]]; then
        if [[ "$PKG_MGR" == "dnf" ]]; then
            dnf repoquery --userinstalled --queryformat '%{name}\n' > "$AUTO_USERINSTALLED" 2>> "$ERROR_LOG" || true
        fi

        if [[ ! -s "$AUTO_USERINSTALLED" ]]; then
            "$PKG_MGR" history userinstalled 2>> "$ERROR_LOG" | \
                awk '
                    /^[[:space:]]*$/ {next}
                    /User-Installed Packages/ {next}
                    /^[[:space:]]*[A-Za-z0-9_.+-]+/ {
                        pkg=$1
                        sub(/\.[a-zA-Z0-9_]+$/, "", pkg)
                        print pkg
                    }
                ' | sort -u -f > "$AUTO_USERINSTALLED"
        fi
    fi

    if [[ -s "$AUTO_USERINSTALLED" ]]; then
        grep -Fxf "$AUTO_USERINSTALLED" "$RPM_ADDED_NAMES" | sort -u -f > "$AUTO_REQUESTED" || true
    fi

    if [[ ! -s "$AUTO_REQUESTED" ]]; then
        warn "Could not detect user-installed packages cleanly. Falling back to all added packages."
        cp "$RPM_ADDED_NAMES" "$AUTO_REQUESTED"
        echo "AUTO_METHOD=FALLBACK_ALL_ADDED_PACKAGES" >> "$REQUESTED_SOURCE_INFO"
    else
        echo "AUTO_METHOD=USERINSTALLED_INTERSECT_RPM_ADDED" >> "$REQUESTED_SOURCE_INFO"
    fi

    while read -r pkg; do
        [[ -z "$pkg" ]] && continue

        if pkg_installed "$pkg"; then
            echo "$pkg" >> "$REQUESTED_NORMALIZED"
            echo -e "${pkg}\t${pkg}\tAUTO_SELECTED\tAUTO_DETECT" >> "$REQUESTED_STATUS_TSV"
        fi
    done < "$AUTO_REQUESTED"

    echo "" >> "$REQUESTED_SOURCE_INFO"
    echo "Auto detected requested package file:" >> "$REQUESTED_SOURCE_INFO"
    echo "$AUTO_REQUESTED" >> "$REQUESTED_SOURCE_INFO"
fi

sort -u -f "$REQUESTED_NORMALIZED" -o "$REQUESTED_NORMALIZED"

if [[ ! -s "$REQUESTED_NORMALIZED" ]]; then
    die "No requested/main packages found. Added packages count: $(wc -l < "$RPM_ADDED_NAMES"). Check $REQUESTED_STATUS_TSV"
fi

###############################################################################
# Package inventory tables
###############################################################################

info "Building package inventory tables..."

echo -e "PACKAGE\tVERSION\tRELEASE\tARCH\tBUILD_STATUS\tVENDOR\tPACKAGER\tREPO\tINSTALL_TIME" > "$REQUESTED_PACKAGES_TSV"
echo -e "PACKAGE\tVERSION\tRELEASE\tARCH\tVENDOR\tPACKAGER\tREPO\tINSTALL_TIME" > "$DEPENDENCY_PACKAGES_TSV"
echo -e "PACKAGE\tVERSION\tRELEASE\tARCH\tVENDOR\tPACKAGER\tREPO\tINSTALL_TIME" > "$ADDED_PACKAGES_TSV"

while read -r pkg; do
    [[ -z "$pkg" ]] && continue

    if grep -Fxq "$pkg" "$RPM_ADDED_NAMES"; then
        status="REQUESTED_ADDED_DURING_BUILD"
    else
        status="REQUESTED_ALREADY_PRESENT_IN_BASE"
    fi

    get_pkg_table_line "$pkg" "$status" >> "$REQUESTED_PACKAGES_TSV"
done < "$REQUESTED_NORMALIZED"

while read -r pkg; do
    [[ -z "$pkg" ]] && continue

    repo="$(get_pkg_repo "$pkg")"
    [[ -z "$repo" ]] && repo="-"

    rpm -q "$pkg" \
        --queryformat "%{NAME}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\t%{VENDOR}\t%{PACKAGER}\t${repo}\t%{INSTALLTIME:date}\n" \
        2>> "$ERROR_LOG" >> "$ADDED_PACKAGES_TSV"
done < "$RPM_ADDED_NAMES"

while read -r pkg; do
    [[ -z "$pkg" ]] && continue

    if ! grep -Fxq "$pkg" "$REQUESTED_NORMALIZED"; then
        repo="$(get_pkg_repo "$pkg")"
        [[ -z "$repo" ]] && repo="-"

        rpm -q "$pkg" \
            --queryformat "%{NAME}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\t%{VENDOR}\t%{PACKAGER}\t${repo}\t%{INSTALLTIME:date}\n" \
            2>> "$ERROR_LOG" >> "$DEPENDENCY_PACKAGES_TSV"
    fi
done < "$RPM_ADDED_NAMES"

###############################################################################
# DNF/YUM transaction history after baseline
###############################################################################

info "Capturing DNF/YUM transactions after baseline..."

echo -e "TRANSACTION_ID\tHISTORY_INFO_FILE" > "$TRANSACTION_TSV"

if [[ -n "$PKG_MGR" && -f "$DNF_HISTORY_LAST_ID_BEFORE" ]]; then
    BASE_LAST_ID="$(cat "$DNF_HISTORY_LAST_ID_BEFORE" 2>/dev/null | head -1)"
    [[ -z "$BASE_LAST_ID" ]] && BASE_LAST_ID="0"

    "$PKG_MGR" history list 2>> "$ERROR_LOG" | \
        awk -v base="$BASE_LAST_ID" 'NR > 2 && $1 ~ /^[0-9]+$/ && $1 > base {print $1}' | \
        sort -n | while read -r txid; do
            [[ -z "$txid" ]] && continue

            info_file="${HISTORY_DIR}/transaction_${txid}.txt"
            "$PKG_MGR" history info "$txid" > "$info_file" 2>> "$ERROR_LOG"

            echo -e "${txid}\t${info_file}" >> "$TRANSACTION_TSV"
        done
fi

###############################################################################
# Package paths, configs, services, modified files
###############################################################################

info "Collecting package paths, roots, configs, services, and modified files..."

echo -e "PACKAGE\tROOT_PATH\tROOT_TYPE" > "$PACKAGE_ROOTS_TSV"
echo -e "PACKAGE\tPATH_CLASS\tPATH\tSTATUS\tPERMISSION\tOCTAL\tOWNER\tGROUP" > "$PACKAGE_PATHS_TSV"
echo -e "PACKAGE\tCONFIG_FILE\tORIGIN\tSTATUS\tPERMISSION\tOCTAL\tOWNER\tGROUP\tOWNER_PACKAGE\tRPM_VERIFY_CHANGED\tSHA256" > "$PACKAGE_CONFIG_TSV"
echo -e "PACKAGE\tSERVICE\tENABLED_STATE\tACTIVE_STATE\tUNIT_FILE\tOWNER_PACKAGE\tMATCH_REASON" > "$PACKAGE_SERVICES_TSV"
echo -e "PACKAGE\tVERIFY_FLAGS\tFILE\tRAW_RPM_VERIFY_LINE" > "$PACKAGE_MODIFIED_TSV"

while read -r pkg; do
    [[ -z "$pkg" ]] && continue

    safe_pkg="$(sanitize_name "$pkg")"
    pkg_files="${RUN_DIR}/${safe_pkg}_rpm_files.txt"
    pkg_roots="${RUN_DIR}/${safe_pkg}_roots.txt"
    pkg_config_candidates="${RUN_DIR}/${safe_pkg}_config_candidates.tsv"
    pkg_config_dedup="${RUN_DIR}/${safe_pkg}_config_candidates_dedup.tsv"
    verify_file="${VERIFY_DIR}/${safe_pkg}_rpm_verify.txt"

    : > "$pkg_files"
    : > "$pkg_roots"
    : > "$pkg_config_candidates"

    rpm -ql "$pkg" > "$pkg_files" 2>> "$ERROR_LOG"

    rpm -V "$pkg" > "$verify_file" 2>> "$ERROR_LOG" || true

    while IFS= read -r vline || [[ -n "$vline" ]]; do
        [[ -z "$vline" ]] && continue

        vfile="$(echo "$vline" | awk '{print $NF}')"
        vflags="$(echo "$vline" | sed "s#[[:space:]]${vfile}\$##")"

        echo -e "${pkg}\t${vflags}\t${vfile}\t${vline}" >> "$PACKAGE_MODIFIED_TSV"
    done < "$verify_file"

    while IFS= read -r path || [[ -n "$path" ]]; do
        [[ -z "$path" ]] && continue

        path_class="$(classify_path "$path")"

        if [[ -e "$path" ]]; then
            status="EXISTS"
        else
            status="MISSING"
        fi

        stat_info="$(safe_stat "$path")"

        echo -e "${pkg}\t${path_class}\t${path}\t${status}\t${stat_info}" >> "$PACKAGE_PATHS_TSV"
    done < "$pkg_files"

    awk '
    /^\/opt\/[^\/]+/ {
        split($0,a,"/")
        print "/opt/" a[3] "\tAPP_OPT"
    }
    /^\/usr\/local\/[^\/]+/ {
        split($0,a,"/")
        print "/usr/local/" a[4] "\tAPP_USR_LOCAL"
    }
    /^\/var\/opt\/[^\/]+/ {
        split($0,a,"/")
        print "/var/opt/" a[4] "\tVAR_OPT"
    }
    /^\/etc\/[^\/]+/ {
        split($0,a,"/")
        print "/etc/" a[3] "\tETC_CONFIG_ROOT"
    }
    ' "$pkg_files" | sort -u > "$pkg_roots"

    while IFS=$'\t' read -r root root_type; do
        [[ -z "${root:-}" ]] && continue
        echo -e "${pkg}\t${root}\t${root_type}" >> "$PACKAGE_ROOTS_TSV"
    done < "$pkg_roots"

    rpm -qc "$pkg" 2>> "$ERROR_LOG" | while read -r cfg; do
        [[ -z "$cfg" ]] && continue
        echo -e "${pkg}\t${cfg}\tRPM_CONFIG" >> "$pkg_config_candidates"
    done

    grep -E '^/etc/' "$pkg_files" 2>/dev/null | while read -r cfg; do
        [[ -z "$cfg" ]] && continue
        [[ -f "$cfg" || ! -e "$cfg" ]] || continue
        echo -e "${pkg}\t${cfg}\tRPM_ETC_PATH" >> "$pkg_config_candidates"
    done

    while IFS= read -r owned_file || [[ -n "$owned_file" ]]; do
        [[ -z "$owned_file" ]] && continue

        if is_config_like_file "$owned_file"; then
            [[ -f "$owned_file" || ! -e "$owned_file" ]] || continue
            echo -e "${pkg}\t${owned_file}\tRPM_CONFIG_LIKE_PATH" >> "$pkg_config_candidates"
        fi
    done < "$pkg_files"

    while IFS=$'\t' read -r root root_type; do
        [[ -z "${root:-}" ]] && continue
        [[ -d "$root" ]] || continue

        find "$root" -xdev -type f \
            \( \
                -iname "*.conf" -o \
                -iname "*.cfg" -o \
                -iname "*.ini" -o \
                -iname "*.yaml" -o \
                -iname "*.yml" -o \
                -iname "*.json" -o \
                -iname "*.xml" -o \
                -iname "*.properties" -o \
                -iname "*.toml" -o \
                -iname "*.cnf" -o \
                -iname "*.env" -o \
                -path "*/conf/*" -o \
                -path "*/config/*" -o \
                -path "*/etc/*" -o \
                -path "*/local/*" \
            \) 2>> "$ERROR_LOG" | while read -r custom_cfg; do
                [[ -z "$custom_cfg" ]] && continue
                echo -e "${pkg}\t${custom_cfg}\tROOT_SCAN_${root_type}" >> "$pkg_config_candidates"
            done
    done < "$pkg_roots"

    awk -F'\t' '
    BEGIN { OFS="\t" }
    {
        key=$1 FS $2
        if (!(key in seen)) {
            seen[key]=1
            print $1,$2,$3
        }
    }
    ' "$pkg_config_candidates" > "$pkg_config_dedup"

    while IFS=$'\t' read -r cpkg cfg origin; do
        [[ -z "${cfg:-}" ]] && continue

        if [[ -e "$cfg" ]]; then
            status="EXISTS"
        else
            status="MISSING"
        fi

        stat_info="$(safe_stat "$cfg")"
        sha256="$(safe_sha256 "$cfg")"

        owner_pkg="$(rpm -qf "$cfg" --queryformat '%{NAME}' 2>/dev/null || true)"
        [[ -z "$owner_pkg" ]] && owner_pkg="UNOWNED"

        if grep -F -- "$cfg" "$verify_file" >/dev/null 2>&1; then
            rpm_changed="YES"
        else
            rpm_changed="NO"
        fi

        echo -e "${pkg}\t${cfg}\t${origin}\t${status}\t${stat_info}\t${owner_pkg}\t${rpm_changed}\t${sha256}" >> "$PACKAGE_CONFIG_TSV"
    done < "$pkg_config_dedup"

    if command -v systemctl >/dev/null 2>&1; then
        systemctl list-unit-files --type=service --no-legend --no-pager 2>> "$ERROR_LOG" | while read -r service enabled_state preset; do
            [[ -z "${service:-}" ]] && continue

            unit_file="$(systemctl show "$service" -p FragmentPath --value 2>> "$ERROR_LOG" || true)"
            [[ -z "$unit_file" ]] && unit_file="-"

            active_state="$(systemctl show "$service" -p ActiveState --value 2>> "$ERROR_LOG" || true)"
            [[ -z "$active_state" ]] && active_state="UNKNOWN"

            owner_pkg="UNOWNED"
            match_reason=""

            if [[ "$unit_file" != "-" && -f "$unit_file" ]]; then
                owner_pkg="$(rpm -qf "$unit_file" --queryformat '%{NAME}' 2>/dev/null || true)"
                [[ -z "$owner_pkg" ]] && owner_pkg="UNOWNED"

                if [[ "$owner_pkg" == "$pkg" ]]; then
                    match_reason="UNIT_FILE_OWNED_BY_PACKAGE"
                fi

                if [[ -z "$match_reason" ]] && grep -Fxq "$unit_file" "$pkg_files"; then
                    match_reason="UNIT_FILE_IN_RPM_FILE_LIST"
                fi

                if [[ -z "$match_reason" ]]; then
                    while IFS=$'\t' read -r root root_type; do
                        [[ -z "${root:-}" ]] && continue

                        if grep -Fq "$root" "$unit_file" 2>/dev/null; then
                            match_reason="UNIT_FILE_REFERENCES_PACKAGE_ROOT"
                            break
                        fi
                    done < "$pkg_roots"
                fi

                if [[ -z "$match_reason" ]] && grep -Fqi "$pkg" "$unit_file" 2>/dev/null; then
                    match_reason="UNIT_FILE_REFERENCES_PACKAGE_NAME"
                fi
            fi

            if [[ -n "$match_reason" ]]; then
                echo -e "${pkg}\t${service}\t${enabled_state}\t${active_state}\t${unit_file}\t${owner_pkg}\t${match_reason}" >> "$PACKAGE_SERVICES_TSV"
            fi
        done
    fi

done < "$REQUESTED_NORMALIZED"

###############################################################################
# Summary
###############################################################################

REQUESTED_COUNT="$(tail -n +2 "$REQUESTED_PACKAGES_TSV" | wc -l)"
ADDED_COUNT="$(tail -n +2 "$ADDED_PACKAGES_TSV" | wc -l)"
DEPENDENCY_COUNT="$(tail -n +2 "$DEPENDENCY_PACKAGES_TSV" | wc -l)"
CONFIG_COUNT="$(tail -n +2 "$PACKAGE_CONFIG_TSV" | wc -l)"
SERVICE_COUNT="$(tail -n +2 "$PACKAGE_SERVICES_TSV" | wc -l)"
MODIFIED_COUNT="$(tail -n +2 "$PACKAGE_MODIFIED_TSV" | wc -l)"
TXN_COUNT="$(tail -n +2 "$TRANSACTION_TSV" | wc -l)"

{
    echo ""
    echo "SUMMARY"
    echo "Requested/Main Packages Audited: $REQUESTED_COUNT"
    echo "All Packages Added Since Baseline: $ADDED_COUNT"
    echo "Dependency Packages Added Since Baseline: $DEPENDENCY_COUNT"
    echo "Config Files Found For Requested Packages: $CONFIG_COUNT"
    echo "Services Found For Requested Packages: $SERVICE_COUNT"
    echo "RPM Verify Changed/Missing Files: $MODIFIED_COUNT"
    echo "DNF/YUM Transactions After Baseline: $TXN_COUNT"
} >> "$REPORT"

###############################################################################
# Clean report tables
###############################################################################

print_table "REQUESTED PACKAGE SOURCE" "$REQUESTED_SOURCE_INFO"
print_table "REQUESTED PACKAGE INPUT STATUS" "$REQUESTED_STATUS_TSV"
print_table "REQUESTED / MAIN PACKAGES" "$REQUESTED_PACKAGES_TSV"
print_table "DEPENDENCY PACKAGES ADDED DURING BUILD" "$DEPENDENCY_PACKAGES_TSV"
print_table "PACKAGE INSTALL ROOTS" "$PACKAGE_ROOTS_TSV"
print_table "PACKAGE CONFIG FILES" "$PACKAGE_CONFIG_TSV"
print_table "PACKAGE SERVICES" "$PACKAGE_SERVICES_TSV"
print_table "PACKAGE MODIFIED / RPM VERIFY CHANGES" "$PACKAGE_MODIFIED_TSV"
print_table "DNF/YUM TRANSACTIONS AFTER BASELINE" "$TRANSACTION_TSV"

{
    echo ""
    echo "================================================================================"
    echo "OUTPUT FILES"
    echo "================================================================================"
    echo "Main Report: $REPORT"
    echo "Requested Package Source: $REQUESTED_SOURCE_INFO"
    echo "Requested Packages Normalized: $REQUESTED_NORMALIZED"
    echo "Auto Detected Requested Packages: $AUTO_REQUESTED"
    echo "Requested Packages: $REQUESTED_PACKAGES_TSV"
    echo "Dependency Packages: $DEPENDENCY_PACKAGES_TSV"
    echo "All Added Packages: $ADDED_PACKAGES_TSV"
    echo "Package Roots: $PACKAGE_ROOTS_TSV"
    echo "Package Installed Paths: $PACKAGE_PATHS_TSV"
    echo "Package Config Files: $PACKAGE_CONFIG_TSV"
    echo "Package Services: $PACKAGE_SERVICES_TSV"
    echo "Package Modified Files: $PACKAGE_MODIFIED_TSV"
    echo "DNF/YUM Transactions: $TRANSACTION_TSV"
    echo "Raw RPM Verify Directory: $VERIFY_DIR"
    echo "DNF/YUM History Info Directory: $HISTORY_DIR"
    echo "Error Log: $ERROR_LOG"
} >> "$REPORT"

tar -czf "${RUN_DIR}.tar.gz" -C "$OUTDIR" "$(basename "$RUN_DIR")" 2>> "$ERROR_LOG"

echo ""
echo "Post-install image software audit completed."
echo ""
echo "Main report:"
echo "$REPORT"
echo ""
echo "Compressed output:"
echo "${RUN_DIR}.tar.gz"
echo ""
echo "Important TSV files:"
echo "$REQUESTED_PACKAGES_TSV"
echo "$DEPENDENCY_PACKAGES_TSV"
echo "$PACKAGE_CONFIG_TSV"
echo "$PACKAGE_SERVICES_TSV"
echo "$PACKAGE_MODIFIED_TSV"
echo "$PACKAGE_PATHS_TSV"
echo ""
echo "Error log:"
echo "$ERROR_LOG"
