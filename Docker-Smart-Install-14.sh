#!/usr/bin/env bash
set -Eeuo pipefail

########################################
# CONFIG
########################################

RPM_BASE="/data/docker-rpms"
BACKUP_BASE="/data/docker_backup"

CUSTOM_DOCKER_ROOT="/dockerfs/docker"
DEFAULT_DOCKER_ROOT="/var/lib/docker"

# Keeping your existing multi-user permission model
DOCKER_ROOT_OWNER="root"
DOCKER_ROOT_GROUP="docker"
DOCKER_ROOT_DIR_MODE="775"
DOCKER_ROOT_FILE_MODE="664"

DNF_INSTALL_OPTS=(--nogpgcheck --nobest --skip-broken)

TEST_IMAGE="docker.io/library/alpine:latest"

LOG_FILE="/tmp/docker_install_$(date +%F_%H%M%S).log"

SYSTEMD_DOCKER_OVERRIDE_DIR="/etc/systemd/system/docker.service.d"
SYSTEMD_DOCKER_OVERRIDE_FILE="/etc/systemd/system/docker.service.d/10-data-root.conf"

########################################
# GLOBALS
########################################

OS_MAJOR=""
RPM_PATH=""
BACKUP_DIR=""

DOCKER_INSTALLED="false"
DOCKER_RUNNING="false"
DOCKER_CLI_PRESENT="false"
DOCKER_DAEMON_REACHABLE="false"
DOCKER_SERVICE_STATE="unknown"

FINAL_DOCKER_ROOT=""
PARENT_DOCKER_ROOT=""

########################################
# LOGGING
########################################

log() {
    echo "$(date '+%F %T') | INFO  | $*" | tee -a "$LOG_FILE"
}

warn() {
    echo "$(date '+%F %T') | WARN  | $*" | tee -a "$LOG_FILE"
}

fail() {
    echo "$(date '+%F %T') | ERROR | $*" | tee -a "$LOG_FILE"
    exit 1
}

step() {
    echo
    echo "============================================================"
    echo "STEP: $1"
    echo "============================================================"
    log "STEP: $1"
}

########################################
# ERROR HANDLING
########################################

on_error() {
    local rc=$?
    local line="${1:-unknown}"

    echo
    echo "[✗] Failed"
    echo "Check log: $LOG_FILE"

    echo "$(date '+%F %T') | ERROR | Script failed at line $line with exit code $rc" | tee -a "$LOG_FILE"
    exit "$rc"
}

trap 'on_error $LINENO' ERR

########################################
# COMMAND WRAPPER
########################################

progress_bar() {
    local pid="$1"
    local spin='-\|/'
    local i=0

    while kill -0 "$pid" 2>/dev/null; do
        i=$(( (i + 1) % 4 ))
        printf "\r[%c] Working..." "${spin:$i:1}"
        sleep 0.2
    done
}

run_cmd() {
    log "Executing: $*"

    (
        "$@"
    ) >>"$LOG_FILE" 2>&1 &

    local pid=$!
    progress_bar "$pid"

    if wait "$pid"; then
        printf "\r[✓] Done\n"
    else
        local rc=$?
        printf "\r[✗] Failed\n"
        fail "Command failed with exit code $rc: $*"
    fi
}

########################################
# REQUIREMENTS
########################################

require_root() {
    [[ "${EUID}" -eq 0 ]] || fail "Run this script as root"
}

require_cmds() {
    local cmds=(
        rpm
        dnf
        systemctl
        grep
        awk
        stat
        cp
        mkdir
        dirname
        find
        getent
        timeout
        sort
        sed
        python3
        groupadd
        chmod
        chown
        rm
        cat
    )

    for c in "${cmds[@]}"; do
        command -v "$c" >/dev/null 2>&1 || fail "Missing required command: $c"
    done
}

########################################
# VALIDATION PHASE
########################################

detect_os() {
    OS_MAJOR="$(rpm -E '%{rhel}' 2>/dev/null || true)"

    [[ -n "$OS_MAJOR" ]] || fail "Unable to detect RHEL major version"

    case "$OS_MAJOR" in
        8|9)
            RPM_PATH="$RPM_BASE/rhel$OS_MAJOR"
            ;;
        *)
            fail "Unsupported OS version: $OS_MAJOR. Supported: RHEL/CentOS 8 or 9"
            ;;
    esac

    [[ -d "$RPM_PATH" ]] || fail "RPM repo path not found: $RPM_PATH"

    log "Detected RHEL/CentOS version: $OS_MAJOR"
    log "Using RPM path: $RPM_PATH"
}

validate_rpms_present() {
    step "Validating RPM files"

    shopt -s nullglob
    local rpms=( "$RPM_PATH"/*.rpm )
    shopt -u nullglob

    [[ "${#rpms[@]}" -gt 0 ]] || fail "No RPM files found in $RPM_PATH"

    log "RPM count found: ${#rpms[@]}"

    for f in "${rpms[@]}"; do
        log "RPM found: $f"
    done
}

validate_required_rpms() {
    step "Validating required Docker RPM names"

    local expected=(
        "containerd.io"
        "docker-ce-cli"
        "docker-ce"
        "docker-buildx-plugin"
        "docker-compose-plugin"
    )

    local missing=()
    local found="false"

    for pkg in "${expected[@]}"; do
        found="false"

        shopt -s nullglob
        for f in "$RPM_PATH"/*.rpm; do
            if rpm -qp --queryformat '%{NAME}\n' "$f" 2>/dev/null | grep -qx "$pkg"; then
                found="true"
                break
            fi
        done
        shopt -u nullglob

        [[ "$found" == "true" ]] || missing+=( "$pkg" )
    done

    if [[ "${#missing[@]}" -gt 0 ]]; then
        warn "Missing expected RPMs: ${missing[*]}"
        warn "Install may continue because --skip-broken is enabled, but Docker install may be incomplete."
    else
        log "All expected core Docker RPMs are present"
    fi
}

detect_existing_docker() {
    step "Detecting existing Docker installation"

    local docker_pkgs=""
    local service_state=""
    local docker_info_rc=1

    docker_pkgs="$(rpm -qa | grep -E '^(docker|containerd)' || true)"

    if [[ -n "$docker_pkgs" ]]; then
        DOCKER_INSTALLED="true"
    fi

    if command -v docker >/dev/null 2>&1; then
        DOCKER_CLI_PRESENT="true"
        DOCKER_INSTALLED="true"
    fi

    service_state="$(systemctl is-active docker 2>/dev/null || true)"

    if [[ -z "$service_state" ]]; then
        DOCKER_SERVICE_STATE="unknown"
    else
        DOCKER_SERVICE_STATE="$service_state"
    fi

    if [[ "$DOCKER_SERVICE_STATE" == "active" ]]; then
        DOCKER_RUNNING="true"
    fi

    if [[ "$DOCKER_CLI_PRESENT" == "true" ]]; then
        if timeout 5 docker info >/dev/null 2>&1; then
            docker_info_rc=0
        else
            docker_info_rc=$?
        fi

        if [[ "$docker_info_rc" -eq 0 ]]; then
            DOCKER_DAEMON_REACHABLE="true"
            DOCKER_RUNNING="true"
        fi
    fi

    log "Docker installed         : $DOCKER_INSTALLED"
    log "Docker CLI present       : $DOCKER_CLI_PRESENT"
    log "Docker service state     : $DOCKER_SERVICE_STATE"
    log "Docker daemon reachable  : $DOCKER_DAEMON_REACHABLE"
    log "Docker running           : $DOCKER_RUNNING"

    if [[ -n "$docker_pkgs" ]]; then
        log "Existing Docker/containerd packages:"
        while IFS= read -r p; do
            [[ -n "$p" ]] && log "  $p"
        done <<< "$docker_pkgs"
    else
        log "No Docker/containerd RPM packages currently installed"
    fi
}

detect_docker_root() {
    step "Detecting Docker root directory"

    local root=""

    local common_paths=(
        "/dockerfs/docker"
        "/data/docker"
        "/apps/docker"
        "/var/lib/docker"
    )

    if [[ "$DOCKER_DAEMON_REACHABLE" == "true" ]]; then
        root="$(timeout 5 docker info --format '{{.DockerRootDir}}' 2>/dev/null || true)"

        if [[ -n "$root" && "$root" != "<no value>" ]]; then
            FINAL_DOCKER_ROOT="$root"
            log "Detected Docker root from live daemon: $FINAL_DOCKER_ROOT"
        fi
    fi

    if [[ -z "$FINAL_DOCKER_ROOT" && -f "$SYSTEMD_DOCKER_OVERRIDE_FILE" ]]; then
        root="$(grep -Po -- '--data-root[= ]\K\S+' "$SYSTEMD_DOCKER_OVERRIDE_FILE" 2>/dev/null || true)"

        if [[ -n "$root" ]]; then
            FINAL_DOCKER_ROOT="$root"
            log "Detected Docker root from systemd override: $FINAL_DOCKER_ROOT"
        fi
    fi

    if [[ -z "$FINAL_DOCKER_ROOT" && -f /etc/docker/daemon.json ]]; then
        root="$(python3 - <<'PY'
import json
from pathlib import Path

p = Path("/etc/docker/daemon.json")

try:
    raw = p.read_text().strip()
    data = json.loads(raw) if raw else {}
except Exception:
    raise SystemExit(0)

if isinstance(data, dict):
    value = data.get("data-root", "")
    if value:
        print(value)
PY
)"

        if [[ -n "$root" ]]; then
            FINAL_DOCKER_ROOT="$root"
            log "Detected Docker root from daemon.json for migration: $FINAL_DOCKER_ROOT"
        fi
    fi

    if [[ -z "$FINAL_DOCKER_ROOT" ]]; then
        for d in "${common_paths[@]}"; do
            if [[ -d "$d" ]]; then
                FINAL_DOCKER_ROOT="$d"
                log "Detected Docker root from existing path: $FINAL_DOCKER_ROOT"
                break
            fi
        done
    fi

    if [[ -z "$FINAL_DOCKER_ROOT" && -n "$CUSTOM_DOCKER_ROOT" ]]; then
        FINAL_DOCKER_ROOT="$CUSTOM_DOCKER_ROOT"
        log "Using configured custom Docker root fallback: $FINAL_DOCKER_ROOT"
    fi

    if [[ -z "$FINAL_DOCKER_ROOT" ]]; then
        FINAL_DOCKER_ROOT="$DEFAULT_DOCKER_ROOT"
        log "Using default Docker root fallback: $FINAL_DOCKER_ROOT"
    fi

    PARENT_DOCKER_ROOT="$(dirname "$FINAL_DOCKER_ROOT")"

    [[ -n "$PARENT_DOCKER_ROOT" ]] || fail "Unable to determine parent path for Docker root"

    if [[ ! -d "$PARENT_DOCKER_ROOT" ]]; then
        run_cmd mkdir -p "$PARENT_DOCKER_ROOT"
    fi

    log "Final Docker root selected: $FINAL_DOCKER_ROOT"
    log "Docker root parent path   : $PARENT_DOCKER_ROOT"
}

########################################
# BACKUP PHASE
########################################

backup_systemd_unit() {
    local unit="$1"
    local fragment=""
    local dropins=""
    local target_dir="$BACKUP_DIR/systemd/$unit"

    run_cmd mkdir -p "$target_dir"

    fragment="$(systemctl show -p FragmentPath --value "$unit" 2>/dev/null || true)"
    dropins="$(systemctl show -p DropInPaths --value "$unit" 2>/dev/null || true)"

    if [[ -n "$fragment" && -e "$fragment" ]]; then
        log "Backing up $unit unit file: $fragment"
        run_cmd cp -a "$fragment" "$target_dir/"
    else
        log "No active FragmentPath found for $unit"
    fi

    if [[ -n "$dropins" ]]; then
        read -r -a arr <<< "$dropins"

        for p in "${arr[@]}"; do
            if [[ -e "$p" ]]; then
                log "Backing up $unit drop-in: $p"
                run_cmd cp -a "$p" "$target_dir/"
            fi
        done
    else
        log "No DropInPaths found for $unit"
    fi
}

backup_configs() {
    step "Backing up Docker configuration only"

    BACKUP_DIR="$BACKUP_BASE/$(date +%F_%H%M%S)"
    run_cmd mkdir -p "$BACKUP_DIR"

    if [[ -d /etc/docker ]]; then
        log "Backing up /etc/docker"
        run_cmd cp -a /etc/docker "$BACKUP_DIR/"
    else
        log "No /etc/docker directory found"
    fi

    backup_systemd_unit docker
    backup_systemd_unit containerd

    if [[ -d "$SYSTEMD_DOCKER_OVERRIDE_DIR" ]]; then
        log "Backing up Docker systemd override directory"
        run_cmd mkdir -p "$BACKUP_DIR/systemd-overrides"
        run_cmd cp -a "$SYSTEMD_DOCKER_OVERRIDE_DIR" "$BACKUP_DIR/systemd-overrides/"
    else
        log "No Docker systemd override directory found"
    fi

    log "Backup directory: $BACKUP_DIR"
}

########################################
# DECISION PHASE
########################################

show_decision_summary() {
    step "Decision Summary"

    log "OS Major Version       : $OS_MAJOR"
    log "RPM Source Path        : $RPM_PATH"
    log "Docker Installed       : $DOCKER_INSTALLED"
    log "Docker CLI Present     : $DOCKER_CLI_PRESENT"
    log "Docker Service State   : $DOCKER_SERVICE_STATE"
    log "Docker Reachable       : $DOCKER_DAEMON_REACHABLE"
    log "Selected Docker Root   : $FINAL_DOCKER_ROOT"
    log "Backup Directory       : ${BACKUP_DIR:-N/A}"
    log "DNF Install Options    : ${DNF_INSTALL_OPTS[*]}"

    if [[ "$DOCKER_INSTALLED" == "true" ]]; then
        log "Scenario               : Reinstall"
        log "Decision               : Existing Docker detected -> cleanup/remove/reinstall"
    else
        log "Scenario               : Fresh install"
        log "Decision               : Install Docker from local RPMs"
    fi

    if [[ "$DOCKER_DAEMON_REACHABLE" == "true" ]]; then
        log "Cleanup Strategy       : Docker CLI cleanup will run"
    else
        log "Cleanup Strategy       : Docker CLI cleanup skipped because daemon is unreachable"
    fi

    log "Docker Root Config     : systemd override only"
    log "Managed Override File  : $SYSTEMD_DOCKER_OVERRIDE_FILE"
    log "daemon.json Handling   : remove data-root if found, preserve other settings"
}

########################################
# EXECUTION PHASE
########################################

docker_cleanup() {
    step "Cleaning Docker containers / images / stale resources"

    if [[ "$DOCKER_CLI_PRESENT" != "true" ]]; then
        log "Docker CLI not present - skipping Docker cleanup"
        return
    fi

    if [[ "$DOCKER_DAEMON_REACHABLE" != "true" ]]; then
        log "Docker daemon not reachable - skipping Docker CLI cleanup"
        return
    fi

    local running=""
    local containers=""
    local images=""
    local volumes=""

    running="$(docker ps -q 2>/dev/null || true)"

    if [[ -n "$running" ]]; then
        log "Stopping running containers"
        # shellcheck disable=SC2086
        run_cmd docker stop $running
    else
        log "No running containers found"
    fi

    containers="$(docker ps -aq 2>/dev/null || true)"

    if [[ -n "$containers" ]]; then
        log "Removing all containers"
        # shellcheck disable=SC2086
        run_cmd docker rm -f $containers
    else
        log "No containers found"
    fi

    images="$(docker images -aq 2>/dev/null || true)"

    if [[ -n "$images" ]]; then
        log "Removing all images"
        # shellcheck disable=SC2086
        run_cmd docker rmi -f $images
    else
        log "No images found"
    fi

    volumes="$(docker volume ls -q 2>/dev/null || true)"

    if [[ -n "$volumes" ]]; then
        log "Removing all Docker volumes"
        # shellcheck disable=SC2086
        run_cmd docker volume rm $volumes
    else
        log "No volumes found"
    fi

    log "Pruning Docker networks/system cache"
    run_cmd docker network prune -f
    run_cmd docker system prune -af --volumes
}

stop_services() {
    step "Stopping Docker services"

    systemctl stop docker 2>/dev/null || true
    systemctl stop docker.socket 2>/dev/null || true
    systemctl stop containerd 2>/dev/null || true

    log "Docker/containerd service stop attempted"
}

remove_old_docker() {
    step "Removing old Docker packages"

    local pkgs=""

    pkgs="$(rpm -qa | grep -E '^(docker|containerd)' | sort -u || true)"

    if [[ -z "$pkgs" ]]; then
        log "No existing Docker/containerd packages found"
        return
    fi

    log "Packages to remove:"

    while IFS= read -r p; do
        [[ -n "$p" ]] && log "  $p"
    done <<< "$pkgs"

    # shellcheck disable=SC2086
    run_cmd dnf remove -y $pkgs
}

prepare_docker_group() {
    step "Preparing docker group"

    if getent group "$DOCKER_ROOT_GROUP" >/dev/null 2>&1; then
        log "Group exists: $DOCKER_ROOT_GROUP"
    else
        run_cmd groupadd "$DOCKER_ROOT_GROUP"
        log "Created group: $DOCKER_ROOT_GROUP"
    fi
}

remove_data_root_from_daemon_json() {
    step "Removing Docker data-root from daemon.json if present"

    if [[ ! -f /etc/docker/daemon.json ]]; then
        log "/etc/docker/daemon.json not found - nothing to clean"
        return
    fi

    log "Found /etc/docker/daemon.json"

    if [[ -n "${BACKUP_DIR:-}" && -d "$BACKUP_DIR" ]]; then
        run_cmd cp -a /etc/docker/daemon.json "$BACKUP_DIR/daemon.json.before_data_root_remove"
    fi

    local cleanup_out="/tmp/docker_daemon_json_cleanup_$$.out"

    python3 - <<'PY' >"$cleanup_out" 2>&1
import json
from pathlib import Path

p = Path("/etc/docker/daemon.json")

try:
    raw = p.read_text().strip()
    data = json.loads(raw) if raw else {}
except Exception as e:
    raise SystemExit(f"Invalid JSON in /etc/docker/daemon.json: {e}")

if not isinstance(data, dict):
    raise SystemExit("/etc/docker/daemon.json must contain a JSON object")

if "data-root" in data:
    del data["data-root"]
    p.write_text(json.dumps(data, indent=2) + "\n")
    print("data-root removed")
else:
    print("data-root not present")
PY

    cat "$cleanup_out" >>"$LOG_FILE" 2>/dev/null || true
    rm -f "$cleanup_out" 2>/dev/null || true

    log "daemon.json cleanup completed"
    log "No Docker root will be stored in /etc/docker/daemon.json"
}

cleanup_docker_systemd_overrides() {
    step "Cleaning Docker systemd override files"

    run_cmd mkdir -p "$SYSTEMD_DOCKER_OVERRIDE_DIR"

    shopt -s nullglob
    local dropins=( "$SYSTEMD_DOCKER_OVERRIDE_DIR"/*.conf )
    shopt -u nullglob

    if [[ "${#dropins[@]}" -eq 0 ]]; then
        log "No existing Docker override files found"
        return
    fi

    run_cmd mkdir -p "$BACKUP_DIR/removed-docker-overrides"

    local f=""
    local base=""

    for f in "${dropins[@]}"; do
        base="$(basename "$f")"

        if [[ "$f" == "$SYSTEMD_DOCKER_OVERRIDE_FILE" ]]; then
            log "Keeping managed override for update: $f"
            run_cmd cp -a "$f" "$BACKUP_DIR/removed-docker-overrides/${base}.before_update"
            continue
        fi

        log "Found extra Docker override file: $f"
        run_cmd cp -a "$f" "$BACKUP_DIR/removed-docker-overrides/$base"
        run_cmd rm -f "$f"
        log "Removed extra Docker override file: $f"
    done

    log "Docker override cleanup completed"
    log "Only managed override will remain: $SYSTEMD_DOCKER_OVERRIDE_FILE"
}

configure_docker_root_systemd() {
    step "Configuring Docker root using systemd override"

    [[ -n "$FINAL_DOCKER_ROOT" ]] || fail "FINAL_DOCKER_ROOT is empty"

    run_cmd mkdir -p "$FINAL_DOCKER_ROOT"
    run_cmd mkdir -p "$SYSTEMD_DOCKER_OVERRIDE_DIR"

    cat >"$SYSTEMD_DOCKER_OVERRIDE_FILE" <<EOF
[Service]
ExecStart=
ExecStart=/usr/bin/dockerd --data-root=${FINAL_DOCKER_ROOT} -H fd:// --containerd=/run/containerd/containerd.sock
EOF

    log "Created/updated systemd override: $SYSTEMD_DOCKER_OVERRIDE_FILE"
    log "Docker data-root configured through systemd: $FINAL_DOCKER_ROOT"

    if grep -q '\$FINAL_DOCKER_ROOT' "$SYSTEMD_DOCKER_OVERRIDE_FILE"; then
        fail "Systemd override contains literal variable name. Expected real path."
    fi

    if ! grep -q -- "--data-root=${FINAL_DOCKER_ROOT}" "$SYSTEMD_DOCKER_OVERRIDE_FILE"; then
        fail "Systemd override does not contain expected Docker root: $FINAL_DOCKER_ROOT"
    fi

    log "Verified systemd override contains real Docker root path"
}

set_docker_root_permissions() {
    step "Setting Docker root permissions"

    run_cmd mkdir -p "$FINAL_DOCKER_ROOT"
    run_cmd chown -R "${DOCKER_ROOT_OWNER}:${DOCKER_ROOT_GROUP}" "$FINAL_DOCKER_ROOT"

    find "$FINAL_DOCKER_ROOT" -type d -exec chmod "$DOCKER_ROOT_DIR_MODE" {} \; >>"$LOG_FILE" 2>&1
    find "$FINAL_DOCKER_ROOT" -type f -exec chmod "$DOCKER_ROOT_FILE_MODE" {} \; >>"$LOG_FILE" 2>&1

    log "Applied ownership ${DOCKER_ROOT_OWNER}:${DOCKER_ROOT_GROUP} recursively"
    log "Applied directory mode $DOCKER_ROOT_DIR_MODE recursively"
    log "Applied file mode $DOCKER_ROOT_FILE_MODE recursively"
}

install_docker() {
    step "Installing Docker packages from local RPMs"

    shopt -s nullglob
    local rpms=( "$RPM_PATH"/*.rpm )
    shopt -u nullglob

    [[ "${#rpms[@]}" -gt 0 ]] || fail "No RPMs found in $RPM_PATH"

    run_cmd dnf install -y "${DNF_INSTALL_OPTS[@]}" "${rpms[@]}"
}

start_docker() {
    step "Starting Docker"

    run_cmd systemctl daemon-reload
    run_cmd systemctl enable docker
    run_cmd systemctl restart docker
}

validate_install() {
    step "Validating Docker installation"

    command -v docker >/dev/null 2>&1 || fail "Docker CLI not found after install"

    local docker_version=""
    docker_version="$(docker --version 2>/dev/null || true)"

    [[ -n "$docker_version" ]] || fail "Unable to read Docker version"

    log "Docker version: $docker_version"

    timeout 10 docker info >/dev/null 2>&1 || fail "Docker daemon is not healthy after install"

    log "Docker daemon is healthy"

    local actual_root=""
    actual_root="$(timeout 5 docker info --format '{{.DockerRootDir}}' 2>/dev/null || true)"

    [[ -n "$actual_root" ]] || fail "Unable to read DockerRootDir after install"

    if [[ "$actual_root" != "$FINAL_DOCKER_ROOT" ]]; then
        fail "Docker root mismatch. Expected: $FINAL_DOCKER_ROOT | Actual: $actual_root"
    fi

    log "Docker root validation passed: $actual_root"

    if [[ -f /etc/docker/daemon.json ]]; then
        if python3 - <<'PY'
import json
from pathlib import Path

p = Path("/etc/docker/daemon.json")
raw = p.read_text().strip()
data = json.loads(raw) if raw else {}

if isinstance(data, dict) and "data-root" in data:
    raise SystemExit(1)
PY
        then
            log "Validated: daemon.json does not contain data-root"
        else
            fail "Validation failed: /etc/docker/daemon.json still contains data-root"
        fi
    else
        log "Validated: /etc/docker/daemon.json does not exist"
    fi

    if [[ ! -f "$SYSTEMD_DOCKER_OVERRIDE_FILE" ]]; then
        fail "Validation failed: managed systemd override file missing"
    fi

    if grep -q '\$FINAL_DOCKER_ROOT' "$SYSTEMD_DOCKER_OVERRIDE_FILE"; then
        fail "Validation failed: systemd override contains literal variable name"
    fi

    if ! grep -q -- "--data-root=${FINAL_DOCKER_ROOT}" "$SYSTEMD_DOCKER_OVERRIDE_FILE"; then
        fail "Validation failed: systemd override does not contain expected Docker root"
    fi

    shopt -s nullglob
    local all_dropins=( "$SYSTEMD_DOCKER_OVERRIDE_DIR"/*.conf )
    shopt -u nullglob

    if [[ "${#all_dropins[@]}" -ne 1 ]]; then
        warn "More than one Docker override file found:"
        for f in "${all_dropins[@]}"; do
            warn "  $f"
        done
        fail "Expected only one Docker override file: $SYSTEMD_DOCKER_OVERRIDE_FILE"
    fi

    log "Validated: only one Docker systemd override file exists"
    log "Validated: systemd override contains real Docker root path"

    log "Testing image pull: $TEST_IMAGE"
    run_cmd docker pull "$TEST_IMAGE"
    log "Validation image pull successful: $TEST_IMAGE"
}

final_summary() {
    step "Docker installation completed successfully"

    local scenario="Fresh install"

    if [[ "$DOCKER_INSTALLED" == "true" ]]; then
        scenario="Reinstall"
    fi

    log "Scenario handled         : $scenario"
    log "Docker root              : $FINAL_DOCKER_ROOT"
    log "Docker root config       : systemd override only"
    log "Systemd override file    : $SYSTEMD_DOCKER_OVERRIDE_FILE"
    log "daemon.json data-root    : removed/not used"
    log "Log file                 : $LOG_FILE"
    log "Backup directory         : ${BACKUP_DIR:-N/A}"

    echo
    echo "Useful validation commands:"
    echo "  systemctl cat docker"
    echo "  docker info --format '{{.DockerRootDir}}'"
    echo "  ls -l /etc/systemd/system/docker.service.d/"
    echo "  grep -n \"data-root\" /etc/docker/daemon.json 2>/dev/null || echo \"No data-root in daemon.json\""
    echo
}

########################################
# MAIN
########################################

main() {
    step "Starting Docker Smart Installer"

    ####################################
    # 1. VALIDATION
    ####################################
    step "Validation Phase"
    require_root
    require_cmds
    detect_os
    validate_rpms_present
    validate_required_rpms
    detect_existing_docker
    detect_docker_root

    ####################################
    # 2. BACKUP
    ####################################
    backup_configs

    ####################################
    # 3. DECISION
    ####################################
    show_decision_summary

    ####################################
    # 4. EXECUTION
    ####################################
    docker_cleanup
    stop_services
    remove_old_docker
    prepare_docker_group

    # Do not create daemon.json.
    # If daemon.json exists, only remove data-root.
    remove_data_root_from_daemon_json

    # Remove duplicate Docker override files.
    # Final state: only 10-data-root.conf remains.
    cleanup_docker_systemd_overrides

    # Configure Docker root only through systemd.
    configure_docker_root_systemd

    set_docker_root_permissions
    install_docker
    start_docker
    validate_install
    final_summary
}

main "$@"
