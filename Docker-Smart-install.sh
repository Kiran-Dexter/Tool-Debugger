#!/usr/bin/env bash
set -Eeuo pipefail

########################################
# CONFIG
########################################

RPM_BASE="/data/docker-rpms"
BACKUP_BASE="/data/docker_backup"
DEFAULT_DOCKER_ROOT="/var/lib/docker"

TEST_IMAGE="docker.io/library/alpine:latest"
TEST_BUILD_DIR="/tmp/docker_test_build"

AUTO_MODE="false"
DRY_RUN="false"
SKIP_TESTS="false"
SKIP_CLEANUP="false"

LOG_FILE="/tmp/docker_install_$(date +%F_%H%M%S).log"

########################################
# GLOBALS
########################################

OS_MAJOR=""
RPM_PATH=""
BACKUP_DIR=""

DOCKER_INSTALLED="false"
DOCKER_RUNNING="false"

FINAL_DOCKER_ROOT=""
MOUNT_BASE=""

PERM_OWNER=""
PERM_GROUP=""
PERM_MODE=""

declare -A RPM_MAP

########################################
# LOGGING
########################################

log(){ echo "$(date '+%F %T') | INFO | $*" | tee -a "$LOG_FILE"; }
fail(){ echo "$(date '+%F %T') | ERROR | $*" | tee -a "$LOG_FILE"; exit 1; }

########################################
# ARGUMENT PARSER
########################################

parse_args(){

while [[ $# -gt 0 ]]
do
case "$1" in
--auto) AUTO_MODE="true"; shift ;;
--dry-run) DRY_RUN="true"; shift ;;
--skip-tests) SKIP_TESTS="true"; shift ;;
--skip-cleanup) SKIP_CLEANUP="true"; shift ;;
*) fail "Unknown argument $1" ;;
esac
done

}

########################################
# UI
########################################

step(){

echo
echo "================================================="
echo "STEP: $1"
echo "================================================="

log "STEP: $1"

}

########################################
# SPINNER
########################################

progress_bar(){

pid=$1
spin='-\|/'
i=0

while kill -0 "$pid" 2>/dev/null
do
i=$(( (i+1) %4 ))
printf "\r[%c] Working..." "${spin:$i:1}"
sleep .2
done

printf "\r[✓] Done\n"

}

########################################
# RUN COMMAND
########################################

run_cmd(){

if [[ "$DRY_RUN" == "true" ]]; then
log "[DRY RUN] $*"
return
fi

log "Executing: $*"

(
"$@"
) >> "$LOG_FILE" 2>&1 &

PID=$!
progress_bar "$PID"
wait "$PID"

}

########################################
# REQUIREMENTS
########################################

require_root(){
[[ "$EUID" -eq 0 ]] || fail "Run as root"
}

require_cmds(){

for c in rpm dnf systemctl grep awk stat
do
command -v "$c" >/dev/null 2>&1 || fail "Missing command: $c"
done

}

########################################
# OS DETECTION
########################################

detect_os(){

OS_MAJOR=$(rpm -E %{rhel})

case "$OS_MAJOR" in
8|9)
RPM_PATH="$RPM_BASE/rhel$OS_MAJOR"
;;
*)
fail "Unsupported OS version"
;;
esac

[[ -d "$RPM_PATH" ]] || fail "RPM directory missing: $RPM_PATH"

log "Detected RHEL/CentOS $OS_MAJOR"
log "Using RPM path: $RPM_PATH"

}

########################################
# DOCKER DETECTION
########################################

detect_existing_docker(){

step "Detecting existing Docker installation"

DOCKER_INSTALLED="false"
DOCKER_RUNNING="false"

if rpm -qa | grep -Eq '^(docker|containerd)'; then
DOCKER_INSTALLED="true"
fi

if command -v docker >/dev/null 2>&1; then
DOCKER_INSTALLED="true"
fi

if systemctl is-active --quiet docker 2>/dev/null; then
DOCKER_RUNNING="true"
DOCKER_INSTALLED="true"
fi

if command -v docker >/dev/null 2>&1; then
if docker info >/dev/null 2>&1; then
DOCKER_RUNNING="true"
DOCKER_INSTALLED="true"
fi
fi

log "Docker installed: $DOCKER_INSTALLED"
log "Docker running : $DOCKER_RUNNING"

}

########################################
# DOCKER ROOT DETECTION
########################################

detect_docker_root(){

step "Detecting Docker root directory"

if command -v docker >/dev/null 2>&1; then
root=$(docker info --format '{{.DockerRootDir}}' 2>/dev/null || true)
[[ -n "$root" ]] && FINAL_DOCKER_ROOT="$root"
fi

if [[ -z "${FINAL_DOCKER_ROOT:-}" ]] && [[ -f /etc/docker/daemon.json ]]; then
root=$(grep -Po '"data-root"\s*:\s*"\K[^"]+' /etc/docker/daemon.json || true)
[[ -n "$root" ]] && FINAL_DOCKER_ROOT="$root"
fi

if [[ -z "${FINAL_DOCKER_ROOT:-}" ]]; then
for d in /data/docker /dockerfs/docker /var/lib/docker
do
[[ -d "$d" ]] && FINAL_DOCKER_ROOT="$d" && break
done
fi

[[ -z "${FINAL_DOCKER_ROOT:-}" ]] && FINAL_DOCKER_ROOT="$DEFAULT_DOCKER_ROOT"

MOUNT_BASE=$(dirname "$FINAL_DOCKER_ROOT")

log "Docker root detected: $FINAL_DOCKER_ROOT"

}

########################################
# MOUNT PERMISSIONS
########################################

detect_mount(){

[[ -d "$MOUNT_BASE" ]] || fail "Mount path not found: $MOUNT_BASE"

PERM_OWNER=$(stat -c '%U' "$MOUNT_BASE")
PERM_GROUP=$(stat -c '%G' "$MOUNT_BASE")
PERM_MODE=$(stat -c '%a' "$MOUNT_BASE")

log "Mount path: $MOUNT_BASE"
log "Permissions: $PERM_OWNER:$PERM_GROUP $PERM_MODE"

}

########################################
# RPM SCAN
########################################

scan_rpms(){

for rpmfile in "$RPM_PATH"/*.rpm
do
pkg=$(rpm -qp --queryformat '%{NAME}' "$rpmfile")
RPM_MAP["$pkg"]="$rpmfile"
log "Detected RPM: $pkg"
done

}

validate_core_rpms(){

for pkg in containerd.io docker-ce docker-ce-cli
do
[[ -n "${RPM_MAP[$pkg]:-}" ]] || fail "Missing required RPM $pkg"
done

}

########################################
# BACKUP CONFIG
########################################

backup_configs(){

if [[ "$DOCKER_INSTALLED" == "false" ]]; then
log "Fresh install detected — skipping config backup"
return
fi

step "Backing up Docker configuration"

BACKUP_DIR="$BACKUP_BASE/$(date +%F_%H%M%S)"

run_cmd mkdir -p "$BACKUP_DIR"

[[ -d /etc/docker ]] && run_cmd cp -a /etc/docker "$BACKUP_DIR/"
[[ -d /etc/systemd/system/docker.service.d ]] && \
run_cmd cp -a /etc/systemd/system/docker.service.d "$BACKUP_DIR/"

}

########################################
# CLEANUP
########################################

docker_cleanup(){

[[ "$SKIP_CLEANUP" == "true" ]] && return

if [[ "$DOCKER_RUNNING" == "false" ]]; then
log "Docker daemon not running — skipping cleanup"
return
fi

step "Docker cleanup"

running=$(docker ps -q || true)
[[ -n "$running" ]] && run_cmd docker stop $running

containers=$(docker ps -aq || true)
[[ -n "$containers" ]] && run_cmd docker rm -f $containers

images=$(docker images -aq || true)
[[ -n "$images" ]] && run_cmd docker rmi -f $images

}

########################################
# REMOVE DOCKER
########################################

remove_docker(){

if [[ "$DOCKER_INSTALLED" == "false" ]]; then
log "Fresh install — skipping removal"
return
fi

step "Removing existing Docker"

systemctl stop docker 2>/dev/null || true
systemctl stop containerd 2>/dev/null || true

pkgs=$(rpm -qa | grep -Ei '^docker|^containerd' || true)

[[ -n "$pkgs" ]] && run_cmd dnf remove -y $pkgs

}

########################################
# INSTALL DOCKER
########################################

install_docker(){

step "Installing Docker packages"

run_cmd dnf install -y --nogpgcheck "$RPM_PATH"/*.rpm

}

########################################
# RESTORE PERMISSIONS
########################################

restore_config(){

step "Restoring mount permissions"

run_cmd mkdir -p "$FINAL_DOCKER_ROOT"
run_cmd chown "$PERM_OWNER:$PERM_GROUP" "$FINAL_DOCKER_ROOT"
run_cmd chmod "$PERM_MODE" "$FINAL_DOCKER_ROOT"

}

########################################
# START DOCKER
########################################

start_docker(){

step "Starting Docker service"

run_cmd systemctl daemon-reload
run_cmd systemctl enable docker
run_cmd systemctl start docker

}

########################################
# VALIDATE
########################################

validate_install(){

[[ "$SKIP_TESTS" == "true" ]] && return

step "Validating Docker installation"

docker info >/dev/null || fail "Docker failed to start"

run_cmd docker pull "$TEST_IMAGE"

mkdir -p "$TEST_BUILD_DIR"

cat > "$TEST_BUILD_DIR/Dockerfile" <<EOF
FROM alpine
RUN echo test
EOF

run_cmd docker build "$TEST_BUILD_DIR"

}

########################################
# MAIN
########################################

main(){

require_root
require_cmds
parse_args "$@"

step "Starting Docker Smart Installer"

detect_os
detect_existing_docker
detect_docker_root
detect_mount

scan_rpms
validate_core_rpms

backup_configs
docker_cleanup
remove_docker

install_docker
restore_config
start_docker
validate_install

step "Docker installation completed successfully"

}

main "$@"
