#!/usr/bin/env bash
#==============================================================================
#  ssh-keyexchange.sh  -  Interactive SSH public-key exchange (Linux side)
#
#  Sets up password-less SSH between this Linux host and Windows (or Linux)
#  machines, in both directions:
#     * Windows -> Linux : authorise a Windows user's public key on this host
#     * Linux -> Windows : push this host's public key to a Windows OpenSSH server
#     * Linux -> Linux   : push this host's public key to another Linux host
#  Plus optional install/configuration of Tectia SSH (client & server).
#
#  Companion script for Windows: ssh-keyexchange.ps1
#
#  Usage:  sudo ./ssh-keyexchange.sh            (interactive menu)
#          sudo ./ssh-keyexchange.sh --wizard   (guided end-to-end setup)
#          sudo ./ssh-keyexchange.sh --check    (prerequisite check only)
#          Options: --no-color  --help
#
#  Tested shells: bash 4.2+  (RHEL/CentOS/Rocky/Alma 7-9, Ubuntu, Debian, SLES)
#==============================================================================

set -o pipefail
set -E
umask 022

readonly SCRIPT_NAME="ssh-keyexchange"
readonly SCRIPT_VERSION="1.0.0"
readonly MARKER_OK="KEYX_OK"
readonly MARKER_TEST="KEYX_TEST_OK"
readonly TECTIA_BIN="/opt/tectia/bin"
readonly TECTIA_SBIN="/opt/tectia/sbin"
readonly TECTIA_CONF="/etc/ssh2/ssh-server-config.xml"
readonly TECTIA_SERVICE="ssh-server-g3"

# ----------------------------------------------------------------- state ----
TARGET_USER=""; TARGET_HOME=""; TARGET_GROUP=""
SELECTED_PUB=""          # public key file chosen for pushing
PUBKEY=""                # public key text read from the user (OpenSSH format)
LAST_HOST=""; LAST_PORT="22"; LAST_RUSER=""; LAST_OS=""
OS_ID=""; OS_NAME=""; PKG=""; SSH_SERVICE=""
TMPDIR_KX=""
LOG_FILE=""

# ---------------------------------------------------------------- colours ---
setup_colors() {
    if [[ -t 1 && -z ${NO_COLOR:-} ]]; then
        R=$'\e[1;31m'; G=$'\e[1;32m'; Y=$'\e[1;33m'; B=$'\e[1;34m'
        M=$'\e[1;35m'; C=$'\e[1;36m'; W=$'\e[1;97m'; D=$'\e[2m'; N=$'\e[0m'
        BG=$'\e[44m'
    else
        R=""; G=""; Y=""; B=""; M=""; C=""; W=""; D=""; N=""; BG=""
    fi
}

# ---------------------------------------------------------------- logging ---
init_log() {
    local dir="/var/log/${SCRIPT_NAME}"
    if ! mkdir -p "$dir" 2>/dev/null || [[ ! -w $dir ]]; then dir="/tmp"; fi
    LOG_FILE="${dir}/${SCRIPT_NAME}-$(date +%Y%m%d-%H%M%S).log"
    : > "$LOG_FILE" 2>/dev/null || LOG_FILE="/dev/null"
    chmod 600 "$LOG_FILE" 2>/dev/null
    log "==== $SCRIPT_NAME $SCRIPT_VERSION started by $(id -un) on $(hostname) ===="
}
log() { printf '%s %s\n' "$(date '+%F %T')" "$*" | sed 's/\x1b\[[0-9;]*m//g' >> "$LOG_FILE" 2>/dev/null; }

info()  { printf '  %s[INFO]%s %s\n' "$B" "$N" "$*"; log "INFO  $*"; }
ok()    { printf '  %s[ OK ]%s %s\n' "$G" "$N" "$*"; log "OK    $*"; }
warn()  { printf '  %s[WARN]%s %s\n' "$Y" "$N" "$*"; log "WARN  $*"; }
err()   { printf '  %s[FAIL]%s %s\n' "$R" "$N" "$*" >&2; log "ERROR $*"; }
step()  { printf '\n%s==>%s %s%s%s\n' "$M" "$N" "$W" "$*" "$N"; log "STEP  $*"; }
hint()  { printf '         %s%s%s\n' "$D" "$*" "$N"; }

banner() {
    clear 2>/dev/null || true
    printf '%s%s' "$BG" "$W"
    printf '  %-74s\n' "SSH KEY EXCHANGE  -  Linux <-> Windows   (v$SCRIPT_VERSION)"
    printf '%s\n' "$N"
    printf '  %sHost:%s %s   %sOS:%s %s\n' "$C" "$N" "$(hostname)" "$C" "$N" "${OS_NAME:-unknown}"
    printf '  %sUser:%s %s   %sLog:%s %s\n' "$C" "$N" "${TARGET_USER:-<not selected>}" "$C" "$N" "$LOG_FILE"
}

# ------------------------------------------------------- traps / cleanup ----
cleanup() { [[ -n $TMPDIR_KX && -d $TMPDIR_KX ]] && rm -rf "$TMPDIR_KX"; }
on_interrupt() { printf '\n'; warn "Interrupted by user - exiting."; exit 130; }
on_error() { log "TRACE rc=$1 line=$2 cmd=$3"; }   # log only; errors are handled inline
trap cleanup EXIT
trap on_interrupt INT TERM
trap 'on_error $? $LINENO "$BASH_COMMAND"' ERR

# -------------------------------------------------------- prompt helpers ----
# ask <var> <prompt> [default] [validator]   (set ALLOW_EMPTY=1 to accept blank)
ask() {
    local __var=$1 __prompt=$2 __def=${3-} __val=${4-} __ans
    while true; do
        if [[ -n $__def ]]; then
            printf '  %s?%s %s %s[%s]%s: ' "$C" "$N" "$__prompt" "$D" "$__def" "$N"
        else
            printf '  %s?%s %s: ' "$C" "$N" "$__prompt"
        fi
        if ! IFS= read -r __ans; then printf '\n'; err "Input closed."; exit 1; fi
        __ans="${__ans%$'\r'}"
        __ans="${__ans#"${__ans%%[![:space:]]*}"}"; __ans="${__ans%"${__ans##*[![:space:]]}"}"
        [[ -z $__ans ]] && __ans=$__def
        if [[ -z $__ans ]]; then
            [[ -n ${ALLOW_EMPTY:-} ]] && { printf -v "$__var" '%s' ""; return 0; }
            warn "A value is required."; continue
        fi
        if [[ -n $__val ]] && ! "$__val" "$__ans"; then continue; fi
        printf -v "$__var" '%s' "$__ans"
        log "INPUT $__prompt = $([[ $__prompt == *assword* || $__prompt == *assphrase* ]] && echo '***' || echo "$__ans")"
        return 0
    done
}

ask_yn() {   # ask_yn "question" [y|n]  -> 0 = yes
    local q=$1 def=${2:-y} a hint
    [[ $def == y ]] && hint="Y/n" || hint="y/N"
    while true; do
        printf '  %s?%s %s %s(%s)%s: ' "$C" "$N" "$q" "$D" "$hint" "$N"
        IFS= read -r a || { printf '\n'; exit 1; }
        a=${a%$'\r'}; a=${a:-$def}
        case ${a,,} in
            y|yes) log "INPUT $q = yes"; return 0 ;;
            n|no)  log "INPUT $q = no";  return 1 ;;
            *) warn "Please answer y or n." ;;
        esac
    done
}

ask_secret() {   # ask_secret <var> <prompt> [min-length] (asks twice)
    local __var=$1 __prompt=$2 __min=${3:-0} __a __b
    while true; do
        printf '  %s?%s %s: ' "$C" "$N" "$__prompt"; IFS= read -rs __a; printf '\n'
        printf '  %s?%s Confirm: ' "$C" "$N";       IFS= read -rs __b; printf '\n'
        if [[ $__a != "$__b" ]]; then warn "Entries do not match - try again."; continue; fi
        if (( ${#__a} < __min )); then warn "Must be at least $__min characters."; continue; fi
        printf -v "$__var" '%s' "$__a"; return 0
    done
}

pause() { printf '\n  %sPress Enter to continue...%s' "$D" "$N"; IFS= read -r _ || true; }

# menu_choice <var> <max>  - reads a number 0..max
menu_choice() {
    local __var=$1 __max=$2 __a
    while true; do
        printf '\n  %sSelect an option%s [0-%s]: ' "$W" "$N" "$__max"
        IFS= read -r __a || { printf '\n'; exit 1; }
        __a=${__a%$'\r'}
        if [[ $__a =~ ^[0-9]+$ ]] && (( __a >= 0 && __a <= __max )); then
            printf -v "$__var" '%s' "$__a"; return 0
        fi
        warn "Invalid choice."
    done
}

# ------------------------------------------------------------ validators ----
v_username() {
    [[ $1 =~ ^[a-z_][a-z0-9_.-]{0,31}$ ]] && return 0
    warn "Invalid username: use lowercase letters, digits, '_', '.', '-' (max 32, must start with a letter or '_')."
    return 1
}
v_port() {
    [[ $1 =~ ^[0-9]{1,5}$ ]] && (( 10#$1 >= 1 && 10#$1 <= 65535 )) && return 0
    warn "Port must be a number between 1 and 65535."; return 1
}
is_ipv4() {
    local IFS=. o; [[ $1 =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || return 1
    for o in $1; do (( 10#$o <= 255 )) || return 1; done; return 0
}
v_host() {
    local h=$1
    if [[ $h =~ ^[0-9.]+$ ]]; then is_ipv4 "$h" && return 0; warn "Invalid IPv4 address."; return 1; fi
    [[ $h =~ ^[0-9A-Fa-f:]+$ && $h == *:* ]] && return 0                                  # IPv6
    [[ $h =~ ^[A-Za-z0-9]([A-Za-z0-9-]{0,62})(\.[A-Za-z0-9]([A-Za-z0-9-]{0,62}))*$ ]] && return 0
    warn "Invalid hostname or IP address."; return 1
}
v_from_list() {   # comma-separated list of IPs / CIDRs / hostname patterns for from="..."
    local item IFS=,
    for item in $1; do
        item=${item#!}
        if [[ $item =~ ^[0-9.]+/[0-9]{1,2}$ ]]; then
            is_ipv4 "${item%/*}" && (( ${item#*/} <= 32 )) && continue
        elif [[ $item =~ ^[0-9.]+$ ]]; then
            is_ipv4 "$item" && continue
        elif [[ $item =~ ^[A-Za-z0-9.:*?_-]+(/[0-9]{1,3})?$ ]]; then
            continue
        fi
        warn "Invalid entry '$item'. Use IPs, CIDR (10.0.0.0/24), hostnames or wildcards (10.0.0.*)."
        return 1
    done
    return 0
}
v_winuser() {
    [[ $1 =~ ^[A-Za-z0-9._\ \$@\\-]{1,104}$ ]] && return 0
    warn "Invalid Windows user name (use user, DOMAIN\\user or user@domain)."; return 1
}

# -------------------------------------------------------- generic helpers ---
have() { command -v "$1" >/dev/null 2>&1; }
init_tmp() { TMPDIR_KX=$(mktemp -d "/tmp/${SCRIPT_NAME}.XXXXXX") || { echo "Cannot create a temporary directory." >&2; exit 1; }; chmod 700 "$TMPDIR_KX"; }
tmpd() { printf '%s' "$TMPDIR_KX"; }   # created once in main (safe inside $(...))

backup_file() {   # backup_file <path>  -> prints backup path
    local f=$1 b
    [[ -e $f ]] || return 0
    b="${f}.bak.$(date +%Y%m%d%H%M%S)"
    cp -p -- "$f" "$b" && log "Backup $f -> $b" && printf '%s' "$b"
}

run_logged() {    # run_logged <description> <cmd...>   - shows a spinner-free status
    local desc=$1; shift
    log "RUN   $*"
    local out rc
    out=$("$@" 2>&1); rc=$?
    printf '%s\n' "$out" >> "$LOG_FILE" 2>/dev/null
    if (( rc == 0 )); then ok "$desc"; else err "$desc (exit code $rc)"; printf '%s\n' "$out" | tail -n 8 | sed 's/^/         /' >&2; fi
    return $rc
}

as_user() {       # run a command as TARGET_USER
    if [[ $TARGET_USER == root || $TARGET_USER == "$(id -un)" ]]; then "$@"
    elif have runuser; then runuser -u "$TARGET_USER" -- "$@"
    elif have sudo;    then sudo -H -u "$TARGET_USER" -- "$@"
    else su -s /bin/bash "$TARGET_USER" -c "$(printf '%q ' "$@")"
    fi
}

svc() {           # svc <action> <service>
    if have systemctl && [[ -d /run/systemd/system ]]; then systemctl "$1" "$2"
    else service "$2" "$1"; fi
}
svc_active() {
    if have systemctl && [[ -d /run/systemd/system ]]; then systemctl is-active --quiet "$1"
    else service "$1" status >/dev/null 2>&1; fi
}

selinux_on() { have getenforce && [[ $(getenforce 2>/dev/null) != Disabled ]]; }

local_ips() { (hostname -I 2>/dev/null || ip -o -4 addr show 2>/dev/null | awk '{print $4}' | cut -d/ -f1) | tr -s ' \n' ' '; }

#==============================================================================
#  SYSTEM DETECTION / PREREQUISITES
#==============================================================================
detect_os() {
    if [[ -r /etc/os-release ]]; then
        # shellcheck disable=SC1091
        . /etc/os-release
        OS_ID=${ID:-linux}; OS_NAME=${PRETTY_NAME:-$OS_ID}
    else
        OS_ID=linux; OS_NAME=$(uname -sr)
    fi
    if   have apt-get; then PKG=apt
    elif have dnf;     then PKG=dnf
    elif have yum;     then PKG=yum
    elif have zypper;  then PKG=zypper
    else PKG=""; fi
    detect_ssh_service
}

detect_ssh_service() {
    SSH_SERVICE=""
    if have systemctl; then
        if   systemctl list-unit-files sshd.service 2>/dev/null | grep -q '^sshd\.service'; then SSH_SERVICE=sshd
        elif systemctl list-unit-files ssh.service  2>/dev/null | grep -q '^ssh\.service';  then SSH_SERVICE=ssh
        fi
    fi
    if [[ -z $SSH_SERVICE ]]; then
        [[ $PKG == apt ]] && SSH_SERVICE=ssh || SSH_SERVICE=sshd
    fi
}

pkg_install() {
    case $PKG in
        apt)    DEBIAN_FRONTEND=noninteractive apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y "$@" ;;
        dnf)    dnf install -y "$@" ;;
        yum)    yum install -y "$@" ;;
        zypper) zypper --non-interactive install "$@" ;;
        *) err "No supported package manager found (apt, dnf, yum, zypper)."; return 1 ;;
    esac
}

privsep_dir() { [[ -d /run/sshd ]] || mkdir -p -m 755 /run/sshd 2>/dev/null; }   # needed by "sshd -t/-T" on Debian/Ubuntu
sshd_bin() { privsep_dir; local p; for p in /usr/sbin/sshd /usr/bin/sshd /sbin/sshd; do [[ -x $p ]] && { echo "$p"; return 0; }; done; have sshd && command -v sshd; }

sshd_effective() {   # sshd_effective <keyword>  -> value from "sshd -T"
    local bin; bin=$(sshd_bin) || return 1
    "$bin" -T 2>/dev/null | awk -v k="${1,,}" 'tolower($1)==k { $1=""; sub(/^ /,""); print; exit }'
}

sshd_ports() { local p; p=$(sshd_effective port 2>/dev/null); [[ -n $p ]] && echo "$p" || echo 22; }

firewall_status() {   # prints: firewalld|ufw|none  and whether port is open
    local port=$1
    if have firewall-cmd && firewall-cmd --state >/dev/null 2>&1; then
        if firewall-cmd --list-services 2>/dev/null | grep -qw ssh && [[ $port == 22 ]]; then echo "firewalld:open"
        elif firewall-cmd --list-ports 2>/dev/null | grep -qw "${port}/tcp"; then echo "firewalld:open"
        else echo "firewalld:closed"; fi
    elif have ufw && ufw status 2>/dev/null | grep -q '^Status: active'; then
        if ufw status 2>/dev/null | grep -qE "^(${port}(/tcp)?|OpenSSH)[[:space:]]+ALLOW"; then echo "ufw:open"; else echo "ufw:closed"; fi
    else
        echo "none:open"
    fi
}

open_firewall() {
    local port=${1:-22} fw
    fw=$(firewall_status "$port")
    case $fw in
        firewalld:closed)
            if [[ $port == 22 ]]; then run_logged "firewalld: allow ssh service" firewall-cmd --permanent --add-service=ssh
            else run_logged "firewalld: allow ${port}/tcp" firewall-cmd --permanent --add-port="${port}/tcp"; fi
            run_logged "firewalld: reload" firewall-cmd --reload ;;
        ufw:closed) run_logged "ufw: allow ${port}/tcp" ufw allow "${port}/tcp" ;;
        *) ok "Firewall already allows TCP ${port} (or no active firewall)." ;;
    esac
}

check_prereqs() {
    step "Checking prerequisites"
    local issues=0 v port fw
    FIX_OPENSSH=0; FIX_SERVICE=0; FIX_PUBKEY=0; FIX_FIREWALL=0

    (( EUID == 0 )) && ok "Running as root" || { err "Not running as root"; ((issues++)); }
    ok "OS: $OS_NAME ($(uname -m))"
    [[ -n $PKG ]] && ok "Package manager: $PKG" || { warn "No supported package manager found"; ((issues++)); }

    if have ssh; then ok "OpenSSH client: $(ssh -V 2>&1 | head -1)"; else err "OpenSSH client (ssh) not installed"; FIX_OPENSSH=1; ((issues++)); fi
    for v in ssh-keygen ssh-keyscan; do
        have "$v" && ok "$v available" || { err "$v not found"; FIX_OPENSSH=1; ((issues++)); }
    done
    have ssh-copy-id && ok "ssh-copy-id available" || warn "ssh-copy-id not found (a built-in fallback will be used)"

    if sshd_bin >/dev/null; then
        ok "OpenSSH server installed ($(sshd_bin))"
        if svc_active "$SSH_SERVICE"; then ok "Service '$SSH_SERVICE' is running"
        else err "Service '$SSH_SERVICE' is NOT running"; FIX_SERVICE=1; ((issues++)); fi
        port=$(sshd_ports | head -1)
        v=$(sshd_effective pubkeyauthentication)
        if [[ $v == yes || -z $v ]]; then ok "PubkeyAuthentication: ${v:-yes (default)}"
        else err "PubkeyAuthentication is '$v'"; FIX_PUBKEY=1; ((issues++)); fi
        v=$(sshd_effective authorizedkeysfile)
        [[ -z $v || $v == *".ssh/authorized_keys"* ]] && ok "AuthorizedKeysFile: ${v:-.ssh/authorized_keys}" \
            || warn "AuthorizedKeysFile is '$v' (this script writes ~/.ssh/authorized_keys)"
        v=$(sshd_effective passwordauthentication)
        info "PasswordAuthentication: ${v:-unknown}  (only needed for the first key push *to* this host)"
        v=$(sshd_effective usepam); [[ -n $v ]] && info "UsePAM: $v"
        if have ss && ss -tlnp 2>/dev/null | grep -q sshd; then
            ok "sshd listening on: $(ss -tlnp 2>/dev/null | awk '/sshd/{print $4}' | sort -u | tr '\n' ' ')"
        fi
    else
        err "OpenSSH server (sshd) not installed"; FIX_OPENSSH=1; ((issues++)); port=22
    fi

    fw=$(firewall_status "${port:-22}")
    case $fw in
        *:open)   ok "Firewall: ${fw%%:*} - TCP ${port:-22} allowed" ;;
        *:closed) err "Firewall: ${fw%%:*} - TCP ${port:-22} is NOT allowed"; FIX_FIREWALL=1; ((issues++)) ;;
    esac

    if have getenforce; then info "SELinux: $(getenforce)"; fi
    have iconv && have base64 && ok "iconv/base64 available (needed to configure Windows targets)" \
        || { err "iconv or base64 missing (needed for Linux -> Windows push)"; ((issues++)); }
    info "This host's IP addresses: $(local_ips)"

    if tectia_installed; then
        ok "Tectia detected: $(tectia_version)"
        if [[ -x $TECTIA_SBIN/ssh-server-g3 ]]; then
            svc_active "$TECTIA_SERVICE" && ok "Tectia server service is running" || warn "Tectia server installed but not running"
        fi
    else
        info "Tectia SSH not installed (optional - see Tectia menu)"
    fi

    printf '\n'
    if (( issues == 0 )); then ok "${G}All prerequisites satisfied.${N}"; return 0; fi
    warn "$issues issue(s) found."
    if (( EUID == 0 )) && (( FIX_OPENSSH + FIX_SERVICE + FIX_PUBKEY + FIX_FIREWALL > 0 )) && ask_yn "Fix these issues automatically now?" y; then
        fix_prereqs
    fi
    return 1
}

fix_prereqs() {
    (( FIX_OPENSSH )) && install_openssh
    (( FIX_SERVICE )) && start_sshd
    (( FIX_PUBKEY ))  && ensure_sshd_pubkey
    (( FIX_FIREWALL )) && open_firewall "$(sshd_ports | head -1)"
    return 0
}

#==============================================================================
#  OPENSSH INSTALL / CONFIG
#==============================================================================
install_openssh() {
    step "Installing / repairing OpenSSH"
    local pkgs
    case $PKG in
        apt)     pkgs=(openssh-client openssh-server) ;;
        dnf|yum) pkgs=(openssh openssh-clients openssh-server) ;;
        zypper)  pkgs=(openssh) ;;
        *) err "Cannot install automatically - install OpenSSH client and server manually."; return 1 ;;
    esac
    run_logged "Install ${pkgs[*]}" pkg_install "${pkgs[@]}" || {
        hint "Check repository access / proxy settings, or install the packages manually."; return 1; }
    have iconv || pkg_install glibc-common >/dev/null 2>&1 || true
    detect_ssh_service
    start_sshd
    ensure_sshd_pubkey
    open_firewall "$(sshd_ports | head -1)"
}

start_sshd() {
    local bin; bin=$(sshd_bin) || { err "sshd binary not found."; return 1; }
    # host keys are created by the package on most distros; make sure they exist
    if ! ls /etc/ssh/ssh_host_*_key >/dev/null 2>&1; then run_logged "Generate SSH host keys" ssh-keygen -A; fi
    if ! "$bin" -t 2>>"$LOG_FILE"; then err "sshd configuration test failed:"; "$bin" -t 2>&1 | sed 's/^/         /'; return 1; fi
    if have systemctl && [[ -d /run/systemd/system ]]; then
        run_logged "Enable service $SSH_SERVICE at boot" systemctl enable "$SSH_SERVICE" || true
    fi
    if svc_active "$SSH_SERVICE"; then run_logged "Reload $SSH_SERVICE" svc reload "$SSH_SERVICE" || svc restart "$SSH_SERVICE"
    else run_logged "Start $SSH_SERVICE" svc start "$SSH_SERVICE"; fi
    svc_active "$SSH_SERVICE" && ok "$SSH_SERVICE is running" || {
        err "$SSH_SERVICE failed to start"; have journalctl && journalctl -u "$SSH_SERVICE" -n 15 --no-pager 2>/dev/null | sed 's/^/         /'; return 1; }
}

ensure_sshd_pubkey() {
    step "Ensuring sshd allows public-key authentication"
    local cfg=/etc/ssh/sshd_config bin bak dropin=/etc/ssh/sshd_config.d/10-ssh-keyexchange.conf v
    bin=$(sshd_bin) || { err "sshd not installed."; return 1; }
    v=$(sshd_effective pubkeyauthentication)
    if [[ $v == yes ]]; then ok "PubkeyAuthentication already enabled."; return 0; fi
    bak=$(backup_file "$cfg")
    if grep -qiE '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d/' "$cfg" && [[ -d /etc/ssh/sshd_config.d ]]; then
        printf '# Added by %s on %s\nPubkeyAuthentication yes\n' "$SCRIPT_NAME" "$(date +%F)" > "$dropin"
        chmod 644 "$dropin"; info "Wrote $dropin"
    else
        sed -i -E 's/^([[:space:]]*PubkeyAuthentication[[:space:]]+no)/# \1   # disabled by ssh-keyexchange/I' "$cfg"
        sed -i "1i # Added by ${SCRIPT_NAME} on $(date +%F)\nPubkeyAuthentication yes" "$cfg"
        info "Updated $cfg"
    fi
    if ! "$bin" -t 2>>"$LOG_FILE"; then
        err "New sshd configuration is invalid - restoring backup."
        [[ -n $bak ]] && cp -p "$bak" "$cfg"; rm -f "$dropin"; return 1
    fi
    svc reload "$SSH_SERVICE" >/dev/null 2>&1 || svc restart "$SSH_SERVICE" >/dev/null 2>&1
    [[ $(sshd_effective pubkeyauthentication) == yes ]] && ok "PubkeyAuthentication enabled." || warn "Could not confirm the setting - check $cfg (a Match block may override it)."
}

#==============================================================================
#  USER MANAGEMENT
#==============================================================================
admin_group() { getent group wheel >/dev/null && echo wheel || echo sudo; }

load_user() {
    TARGET_USER=$1
    TARGET_HOME=$(getent passwd "$1" | cut -d: -f6)
    TARGET_GROUP=$(id -gn "$1" 2>/dev/null)
}

show_user() {
    local u=$1 sh st
    sh=$(getent passwd "$u" | cut -d: -f7)
    st=$(passwd -S "$u" 2>/dev/null | awk '{print $2}')
    printf '         %suid/gid:%s %s\n' "$D" "$N" "$(id "$u")"
    printf '         %shome   :%s %s\n' "$D" "$N" "$(getent passwd "$u" | cut -d: -f6)"
    printf '         %sshell  :%s %s   %spassword status:%s %s\n' "$D" "$N" "$sh" "$D" "$N" "${st:-?}"
}

select_or_create_user() {
    step "Select or create the local Linux user"
    local u def shell
    def=${TARGET_USER:-${SUDO_USER:-}}
    [[ $def == root ]] && def=""
    while true; do
        ask u "Linux username to configure for SSH key login" "$def" v_username
        if id "$u" >/dev/null 2>&1; then
            info "User '$u' already exists:"; show_user "$u"
            if ask_yn "Use the existing user '$u'?" y; then load_user "$u"; break; fi
            def=""; continue
        fi
        warn "User '$u' does not exist."
        ask_yn "Create user '$u' now?" y || { def=""; continue; }
        ask shell "Login shell" "/bin/bash"
        [[ -x $shell ]] || { warn "$shell not found - using /bin/sh"; shell=/bin/sh; }
        local gecos; ALLOW_EMPTY=1 ask gecos "Full name / comment (optional)" ""
        if ! run_logged "Create user $u" useradd -m -s "$shell" ${gecos:+-c "$gecos"} "$u"; then
            hint "Check that the name is free and /home is writable."; continue
        fi
        if ask_yn "Set a password for '$u' now? (needed for console/sudo, not for key logins)" y; then
            local tries=0
            until passwd "$u"; do ((++tries >= 3)) && { warn "Password not set - you can run 'passwd $u' later."; break; }; done
        fi
        if ask_yn "Give '$u' administrator (sudo) rights via group '$(admin_group)'?" n; then
            run_logged "Add $u to $(admin_group)" usermod -aG "$(admin_group)" "$u"
        fi
        load_user "$u"; break
    done
    check_user_login_ready
    ok "Working with user: ${W}$TARGET_USER${N} (home $TARGET_HOME)"
}

check_user_login_ready() {
    local sh st usepam
    sh=$(getent passwd "$TARGET_USER" | cut -d: -f7)
    if [[ $sh == */nologin || $sh == */false ]]; then
        warn "Shell for $TARGET_USER is $sh - interactive SSH logins will be refused."
        ask_yn "Change the shell to /bin/bash?" y && run_logged "Set shell /bin/bash" usermod -s /bin/bash "$TARGET_USER"
    fi
    [[ -d $TARGET_HOME ]] || { warn "Home directory $TARGET_HOME is missing - creating it."; mkdir -p "$TARGET_HOME"; chown "$TARGET_USER:$TARGET_GROUP" "$TARGET_HOME"; chmod 750 "$TARGET_HOME"; }
    st=$(passwd -S "$TARGET_USER" 2>/dev/null | awk '{print $2}')
    usepam=$(sshd_effective usepam)
    if [[ $st == L || $st == LK ]] && [[ $usepam == no ]]; then
        warn "Account password is locked and UsePAM is not 'yes' - sshd will refuse key logins."
        if ask_yn "Mark the account as 'no password' (key-only, not locked)?" y; then
            run_logged "usermod -p '*' $TARGET_USER" usermod -p '*' "$TARGET_USER"
        fi
    fi
}

require_user() { [[ -n $TARGET_USER ]] && id "$TARGET_USER" >/dev/null 2>&1 || select_or_create_user; }

#==============================================================================
#  PERMISSIONS
#==============================================================================
fix_ssh_permissions() {
    local u=$TARGET_USER g=$TARGET_GROUP h=$TARGET_HOME d="$TARGET_HOME/.ssh" f owner
    owner=$(stat -c %U "$h" 2>/dev/null)
    [[ $owner != "$u" && $u != root ]] && warn "Home $h is owned by '$owner', not '$u' - sshd (StrictModes) may reject keys."
    local perms; perms=$(stat -c %A "$h" 2>/dev/null)
    if [[ ${perms:5:1} == w || ${perms:8:1} == w ]]; then
        chmod go-w "$h" && info "Removed group/other write permission from $h (required by sshd StrictModes)"
    fi
    mkdir -p "$d"; chown "$u:$g" "$d"; chmod 700 "$d"
    for f in "$d"/* "$d"/.[!.]*; do
        [[ -f $f ]] || continue
        chown "$u:$g" "$f"
        case $(basename "$f") in
            *.pub|known_hosts*) chmod 644 "$f" ;;
            *) chmod 600 "$f" ;;
        esac
    done
    if [[ -d $h/.ssh2 ]]; then
        chown -R "$u:$g" "$h/.ssh2"; chmod 700 "$h/.ssh2"
        find "$h/.ssh2" -type d -exec chmod 700 {} + 2>/dev/null
        find "$h/.ssh2" -type f ! -name '*.pub' -exec chmod 600 {} + 2>/dev/null
        find "$h/.ssh2" -type f -name '*.pub' -exec chmod 644 {} + 2>/dev/null
    fi
    if selinux_on && have restorecon; then restorecon -R "$d" ${h:+"$h/.ssh2"} >/dev/null 2>&1; fi
    ok "Permissions set: ~/.ssh 700, private keys & authorized_keys 600, *.pub 644 (owner $u)"
}

#==============================================================================
#  KEYS
#==============================================================================
key_fp() { ssh-keygen -lf "$1" 2>/dev/null | awk '{print $2"  "$NF" "$1"-bit"}'; }

generate_keypair() {
    require_user
    step "Generate an SSH key pair for $TARGET_USER"
    have ssh-keygen || { err "ssh-keygen not installed - run the OpenSSH install first."; return 1; }
    printf '    %s1)%s ed25519        %s(recommended - modern, small, fast; Windows 10/2019+ OpenSSH OK)%s\n' "$C" "$N" "$D" "$N"
    printf '    %s2)%s rsa 4096       %s(maximum compatibility - older systems and Tectia)%s\n' "$C" "$N" "$D" "$N"
    printf '    %s3)%s ecdsa 521\n' "$C" "$N"
    local c type bits=() keyfile pass="" comment
    menu_choice c 3
    case $c in
        0) return 0 ;;
        1) type=ed25519 ;;
        2) type=rsa; bits=(-b 4096) ;;
        3) type=ecdsa; bits=(-b 521) ;;
    esac
    keyfile="$TARGET_HOME/.ssh/id_${type}"
    mkdir -p "$TARGET_HOME/.ssh"; fix_ssh_permissions >/dev/null
    if [[ -f $keyfile ]]; then
        warn "A key already exists: $keyfile"
        hint "Fingerprint: $(key_fp "$keyfile.pub")"
        printf '    %s1)%s Keep and use the existing key\n    %s2)%s Back it up and create a new key\n' "$C" "$N" "$C" "$N"
        menu_choice c 2
        case $c in
            0) return 0 ;;
            1) SELECTED_PUB="$keyfile.pub"; ok "Using existing key $keyfile"; show_pubkey "$SELECTED_PUB"; return 0 ;;
            2) local ts; ts=$(date +%Y%m%d%H%M%S)
               mv "$keyfile" "$keyfile.bak.$ts"; [[ -f $keyfile.pub ]] && mv "$keyfile.pub" "$keyfile.pub.bak.$ts"
               info "Old key moved to $keyfile.bak.$ts" ;;
        esac
    fi
    if ask_yn "Protect the private key with a passphrase? (choose 'n' for unattended scripts/automation)" n; then
        ask_secret pass "Passphrase" 5
    fi
    ask comment "Key comment" "${TARGET_USER}@$(hostname -s)"
    comment=$(printf '%s' "$comment" | tr -cd 'A-Za-z0-9@._-')
    if ! as_user ssh-keygen -q -t "$type" "${bits[@]}" -f "$keyfile" -N "$pass" -C "$comment" </dev/null 2>>"$LOG_FILE"; then
        err "ssh-keygen failed - see $LOG_FILE"; return 1
    fi
    fix_ssh_permissions
    SELECTED_PUB="$keyfile.pub"
    ok "Key pair created: $keyfile"
    show_pubkey "$SELECTED_PUB"
}

show_pubkey() {
    printf '\n  %sPublic key%s (%s)\n' "$W" "$N" "$1"
    printf '  %sFingerprint:%s %s\n' "$D" "$N" "$(key_fp "$1")"
    printf '%s%s%s\n\n' "$G" "$(cat "$1")" "$N"
}

pick_user_key() {   # sets SELECTED_PUB
    require_user
    local keys=() f i c
    for f in "$TARGET_HOME"/.ssh/*.pub "$TARGET_HOME"/.ssh2/*.openssh.pub; do
        [[ -f $f ]] && ssh-keygen -lf "$f" >/dev/null 2>&1 && keys+=("$f")
    done
    if (( ${#keys[@]} == 0 )); then
        warn "No public keys found for $TARGET_USER."
        ask_yn "Generate a key pair now?" y && generate_keypair && [[ -n $SELECTED_PUB ]] && return 0
        return 1
    fi
    if (( ${#keys[@]} == 1 )); then SELECTED_PUB=${keys[0]}; info "Using key $SELECTED_PUB ($(key_fp "$SELECTED_PUB"))"; return 0; fi
    printf '\n  %sAvailable public keys for %s:%s\n' "$W" "$TARGET_USER" "$N"
    for i in "${!keys[@]}"; do printf '    %s%d)%s %s  %s%s%s\n' "$C" "$((i+1))" "$N" "${keys[$i]}" "$D" "$(key_fp "${keys[$i]}")" "$N"; done
    menu_choice c "${#keys[@]}"
    (( c == 0 )) && return 1
    SELECTED_PUB=${keys[$((c-1))]}
}

# Reads a public key from the operator (paste or file). Accepts OpenSSH one-line
# format or RFC4716 / SECSH (Tectia, PuTTY) format. Result -> PUBKEY (OpenSSH format)
read_public_key() {
    local c line lines="" t f fp
    t="$(tmpd)/in.pub"
    printf '    %s1)%s Paste the public key\n    %s2)%s Read it from a file\n' "$C" "$N" "$C" "$N"
    menu_choice c 2
    case $c in
        0) return 1 ;;
        1) info "Paste the public key (OpenSSH 'ssh-ed25519 AAAA...' or a '---- BEGIN SSH2 PUBLIC KEY ----' block)."
           info "Finish with an empty line:"
           while IFS= read -r line; do
               line=${line%$'\r'}
               [[ -z $line && -n $lines ]] && break
               [[ -z $line ]] && continue
               lines+="$line"$'\n'
               [[ $line == *"END SSH2 PUBLIC KEY"* ]] && break
               [[ $line =~ ^(ssh-|ecdsa-|sk-) && $lines != *"BEGIN SSH2"* ]] && break
           done
           printf '%s' "$lines" > "$t" ;;
        2) ask f "Path to the public key file"
           [[ -r $f ]] || { err "Cannot read $f"; return 1; }
           tr -d '\r' < "$f" > "$t" ;;
    esac
    if grep -q 'BEGIN SSH2 PUBLIC KEY' "$t"; then
        if ! ssh-keygen -i -m RFC4716 -f "$t" > "$t.conv" 2>>"$LOG_FILE"; then err "Could not convert the SSH2/RFC4716 key."; return 1; fi
        info "Converted SSH2 (Tectia/PuTTY) format key to OpenSSH format."
        # keep the comment if present
        local cm; cm=$(grep -i '^Comment:' "$t" | head -1 | sed -E 's/^Comment:[[:space:]]*"?([^"]*)"?.*/\1/' | tr -cd 'A-Za-z0-9@._-')
        PUBKEY="$(head -1 "$t.conv")${cm:+ $cm}"
    else
        PUBKEY=$(grep -E '^(ssh-(rsa|dss|ed25519)|ecdsa-sha2-|sk-)' "$t" | head -1)
    fi
    [[ -n $PUBKEY ]] || { err "No valid public key found in the input."; return 1; }
    printf '%s\n' "$PUBKEY" > "$t"
    if ! fp=$(ssh-keygen -lf "$t" 2>/dev/null); then err "Input is not a valid SSH public key."; return 1; fi
    ok "Valid key: $(awk '{print $2"  "$NF" "$1"-bit"}' <<<"$fp")"
    return 0
}

sanitize_key() {   # "type blob comment"  with a safe comment (no quotes etc.)
    local t b c
    read -r t b c <<<"$1"
    c=$(printf '%s' "$c" | tr -cd 'A-Za-z0-9@._-')
    printf '%s %s%s' "$t" "$b" "${c:+ $c}"
}

#==============================================================================
#  WINDOWS -> LINUX : authorise a remote public key on this host
#==============================================================================
authorize_remote_key() {
    require_user
    step "Authorise a remote (Windows/Linux) public key to log in here as $TARGET_USER"
    info "On Windows, the public key is usually: C:\\Users\\<you>\\.ssh\\id_ed25519.pub (or id_rsa.pub)"
    hint "PowerShell:  Get-Content \$env:USERPROFILE\\.ssh\\id_ed25519.pub"
    read_public_key || { warn "No key authorised."; return 1; }

    local ip opts="" extra line ak blob existing bak
    printf '\n'
    info "Restrict this key to specific source IP addresses? (recommended)"
    hint "Enter the IP(s) of the remote machine as THIS server will see them (mind NAT/VPN)."
    hint "Examples: 192.168.10.25   or   10.0.0.0/24,192.168.1.5   - leave blank to allow from anywhere."
    [[ -n $LAST_HOST ]] && hint "Last remote host used: $LAST_HOST"
    ALLOW_EMPTY=1 ask ip "Allowed source IP(s)" "" v_from_list
    [[ -n $ip ]] && opts="from=\"${ip}\""
    if ask_yn "Also disable port/agent/X11 forwarding for this key? (hardening)" n; then
        extra="no-port-forwarding,no-agent-forwarding,no-X11-forwarding"
        opts=${opts:+$opts,}$extra
    fi
    line="${opts:+$opts }$(sanitize_key "$PUBKEY")"

    ak="$TARGET_HOME/.ssh/authorized_keys"
    mkdir -p "$TARGET_HOME/.ssh"; touch "$ak"
    bak=$(backup_file "$ak")
    blob=$(awk '{print $2}' <<<"$PUBKEY")
    if existing=$(grep -nF "$blob" "$ak"); then
        warn "This key is already authorised:"; hint "$existing"
        if ask_yn "Replace the existing entry with the new options?" y; then
            grep -vF "$blob" "$ak" > "$(tmpd)/ak.new"; cat "$(tmpd)/ak.new" > "$ak"
        else
            info "Left authorized_keys unchanged."; return 0
        fi
    fi
    # make sure the file ends with a newline before appending
    [[ -s $ak && -n $(tail -c1 "$ak") ]] && printf '\n' >> "$ak"
    printf '%s\n' "$line" >> "$ak"
    fix_ssh_permissions
    ok "Key added to $ak ${bak:+(backup: $bak)}"
    [[ -n $ip ]] && ok "Key restricted to source: $ip"
    [[ $(sshd_effective pubkeyauthentication) == yes ]] || ensure_sshd_pubkey
    LAST_HOST=${ip%%,*}
    printf '\n  %sFrom Windows, connect with:%s\n' "$W" "$N"
    local myip; myip=$(local_ips | awk '{print $1}')
    printf '     %sssh -p %s %s@%s%s\n' "$G" "$(sshd_ports | head -1)" "$TARGET_USER" "${myip:-<this-host>}" "$N"
    hint "First connection will ask to confirm this server's host key fingerprint:"
    local k; for k in /etc/ssh/ssh_host_ed25519_key.pub /etc/ssh/ssh_host_ecdsa_key.pub /etc/ssh/ssh_host_rsa_key.pub; do
        [[ -f $k ]] && hint "  $(ssh-keygen -lf "$k" | awk '{print $2"  "$NF}')"
    done
}

list_authorized_keys() {
    require_user
    local ak="$TARGET_HOME/.ssh/authorized_keys" n=0 line t
    step "Keys authorised for $TARGET_USER ($ak)"
    [[ -s $ak ]] || { info "No authorised keys."; return 0; }
    t="$(tmpd)/one.pub"
    while IFS= read -r line; do
        [[ -z $line || $line == \#* ]] && continue
        ((n++))
        printf '%s\n' "$line" | grep -oE '(ssh-[a-z0-9-]+|ecdsa-sha2-[a-z0-9-]+|sk-[a-z0-9@.-]+) [A-Za-z0-9+/=]+.*' > "$t"
        printf '    %s%2d)%s %s\n' "$C" "$n" "$N" "$(ssh-keygen -lf "$t" 2>/dev/null | awk '{print $2"  "$NF}')"
        [[ $line =~ from=\"([^\"]*)\" ]] && printf '        %sfrom: %s%s\n' "$D" "${BASH_REMATCH[1]}" "$N"
    done < "$ak"
}

#==============================================================================
#  KNOWN HOSTS
#==============================================================================
add_known_host() {   # add_known_host <host> <port>
    require_user
    local host=$1 port=${2:-22} t kh name
    t="$(tmpd)/scan"
    info "Fetching host key(s) from $host:$port ..."
    if ! ssh-keyscan -T 8 -p "$port" "$host" > "$t" 2>>"$LOG_FILE" || [[ ! -s $t ]]; then
        err "Could not retrieve the host key from $host:$port."
        hint "Is the SSH server running there and is TCP $port open in its firewall?"
        return 1
    fi
    printf '  %sHost key fingerprints offered by %s:%s\n' "$W" "$host" "$N"
    ssh-keygen -lf "$t" 2>/dev/null | awk '{print "     "$2"  "$NF}'
    hint "Verify on Windows : Get-ChildItem C:\\ProgramData\\ssh\\ssh_host_*.pub | % { ssh-keygen -lf \$_ }"
    hint "Verify on Linux   : for k in /etc/ssh/ssh_host_*.pub; do ssh-keygen -lf \$k; done"
    ask_yn "Do these fingerprints match the remote host?" y || { warn "Host key NOT trusted."; return 1; }
    kh="$TARGET_HOME/.ssh/known_hosts"
    mkdir -p "$TARGET_HOME/.ssh"; touch "$kh"
    [[ $port == 22 ]] && name=$host || name="[$host]:$port"
    ssh-keygen -R "$name" -f "$kh" >/dev/null 2>&1; rm -f "$kh.old"
    cat "$t" >> "$kh"
    fix_ssh_permissions >/dev/null
    ok "Added $name to $kh"
}

known_host_present() { [[ -f $TARGET_HOME/.ssh/known_hosts ]] && ssh-keygen -F "$([[ $2 == 22 ]] && echo "$1" || echo "[$1]:$2")" -f "$TARGET_HOME/.ssh/known_hosts" >/dev/null 2>&1; }

ask_remote() {   # ask_remote <os-label>  -> LAST_HOST LAST_PORT LAST_RUSER
    ask LAST_HOST "Remote $1 host name or IP address" "$LAST_HOST" v_host
    ask LAST_PORT "Remote SSH port" "${LAST_PORT:-22}" v_port
    if [[ $1 == Windows ]]; then
        ask LAST_RUSER "Remote Windows user (user, DOMAIN\\user or user@domain)" "$LAST_RUSER" v_winuser
    else
        ask LAST_RUSER "Remote Linux user" "${LAST_RUSER:-$TARGET_USER}" v_username
    fi
}

check_tcp() {    # check_tcp host port
    if have timeout; then timeout 5 bash -c "exec 3<>/dev/tcp/$1/$2" 2>/dev/null
    else bash -c "exec 3<>/dev/tcp/$1/$2" 2>/dev/null; fi
}

#==============================================================================
#  LINUX -> WINDOWS : push key to a Windows OpenSSH server
#==============================================================================
ps_encode() { printf '%s' "$1" | iconv -f UTF-8 -t UTF-16LE | base64 | tr -d '\n'; }

build_windows_ps() {   # build_windows_ps "<key line>"  - PowerShell run ON the Windows server
cat <<EOF
\$ErrorActionPreference='Stop'
\$k='$1'
try{
\$id=[Security.Principal.WindowsIdentity]::GetCurrent()
\$adm=\$id.Groups -contains (New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544'))
if(\$adm){\$f=Join-Path \$env:ProgramData 'ssh\administrators_authorized_keys'}else{\$d=Join-Path \$env:USERPROFILE '.ssh';if(!(Test-Path \$d)){New-Item -ItemType Directory -Path \$d|Out-Null};\$f=Join-Path \$d 'authorized_keys'}
\$b=(\$k -split ' ')[1];\$c=@()
if(Test-Path \$f){\$c=@(Get-Content -Path \$f|Where-Object{\$_ -and -not \$_.Contains(\$b)})}
\$c+=\$k
Set-Content -Path \$f -Value \$c -Encoding Ascii
& icacls.exe \$f /reset|Out-Null
if(\$adm){\$g=@('*S-1-5-32-544:F','*S-1-5-18:F')}else{\$g=@((\$id.Name+':F'),'*S-1-5-18:F','*S-1-5-32-544:F')}
\$a=@(\$f,'/inheritance:r');foreach(\$x in \$g){\$a+='/grant';\$a+=\$x}
& icacls.exe \$a|Out-Null
if(\$LASTEXITCODE -ne 0){throw 'icacls failed to set permissions'}
Write-Output ('${MARKER_OK}|'+\$adm+'|'+\$f+'|'+\$id.Name)
}catch{Write-Output ('KEYX_ERR|'+\$_.Exception.Message);exit 1}
EOF
}

push_key_to_windows() {
    require_user
    step "Linux -> Windows: install ${TARGET_USER}'s public key on a Windows OpenSSH server"
    have iconv && have base64 || { err "iconv and base64 are required."; return 1; }
    pick_user_key || return 1
    info "Windows prerequisites: OpenSSH Server installed & running (run ssh-keyexchange.ps1 there, option 2)."
    ask_remote Windows
    LAST_OS=Windows
    check_tcp "$LAST_HOST" "$LAST_PORT" || { err "Cannot reach $LAST_HOST:$LAST_PORT (TCP)."; hint "Check the IP, the Windows firewall rule 'OpenSSH-Server-In-TCP' and that the 'sshd' service is running."; return 1; }
    ok "TCP $LAST_HOST:$LAST_PORT reachable"
    known_host_present "$LAST_HOST" "$LAST_PORT" || add_known_host "$LAST_HOST" "$LAST_PORT" || return 1

    local key ps enc out rc
    key=$(sanitize_key "$(head -1 "$SELECTED_PUB")")
    ps=$(build_windows_ps "$key")
    enc=$(ps_encode "$ps")
    info "Connecting as '$LAST_RUSER' - enter the Windows password when prompted."
    log "RUN   ssh -p $LAST_PORT -l $LAST_RUSER $LAST_HOST powershell -EncodedCommand <...>"
    out=$(as_user ssh -p "$LAST_PORT" -l "$LAST_RUSER" -o ConnectTimeout=15 -o NumberOfPasswordPrompts=3 \
          "$LAST_HOST" "powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand $enc")
    rc=$?
    out=$(printf '%s' "$out" | tr -d '\r')
    log "OUT   $out"
    if [[ $out == *"$MARKER_OK|"* ]]; then
        local res; res=$(grep -m1 "^$MARKER_OK|" <<<"$out")
        local adm file who
        IFS='|' read -r _ adm file who <<<"$res"
        ok "Key installed on $LAST_HOST for $who"
        ok "File: $file"
        [[ $adm == True ]] && info "'$who' is an Administrator -> key stored in administrators_authorized_keys (Windows OpenSSH default)."
        ask_yn "Test the password-less connection now?" y && test_connection "$LAST_HOST" "$LAST_PORT" "$LAST_RUSER"
        return 0
    fi
    err "Key installation on Windows failed (ssh exit code $rc)."
    [[ $out == *KEYX_ERR* ]] && hint "Windows said: $(grep -m1 KEYX_ERR <<<"$out" | cut -d'|' -f2-)"
    case $rc in
        255) hint "SSH connection/authentication failed: wrong password, account not allowed, or sshd not running." ;;
        127|1) hint "PowerShell may be unavailable or the command line was rejected on the Windows side." ;;
    esac
    hint "Manual alternative: copy the key below into the Windows script (option 'Authorise a remote key')"
    show_pubkey "$SELECTED_PUB"
    return 1
}

#==============================================================================
#  LINUX -> LINUX : push key to another Linux server
#==============================================================================
push_key_to_linux() {
    require_user
    step "Linux -> Linux: install ${TARGET_USER}'s public key on another Linux server"
    pick_user_key || return 1
    ask_remote Linux
    LAST_OS=Linux
    check_tcp "$LAST_HOST" "$LAST_PORT" || { err "Cannot reach $LAST_HOST:$LAST_PORT (TCP)."; return 1; }
    known_host_present "$LAST_HOST" "$LAST_PORT" || add_known_host "$LAST_HOST" "$LAST_PORT" || return 1
    local key blob rcmd out
    key=$(sanitize_key "$(head -1 "$SELECTED_PUB")")
    blob=$(awk '{print $2}' <<<"$key")
    rcmd="umask 077; mkdir -p ~/.ssh && touch ~/.ssh/authorized_keys && { grep -qF '$blob' ~/.ssh/authorized_keys || echo '$key' >> ~/.ssh/authorized_keys; } && chmod 700 ~/.ssh && chmod 600 ~/.ssh/authorized_keys && chmod go-w ~ ; command -v restorecon >/dev/null 2>&1 && restorecon -R ~/.ssh; echo $MARKER_OK"
    info "Connecting as '$LAST_RUSER' - enter the remote password when prompted."
    out=$(as_user ssh -p "$LAST_PORT" -o ConnectTimeout=15 "$LAST_RUSER@$LAST_HOST" "$rcmd")
    if [[ $out == *"$MARKER_OK"* ]]; then
        ok "Key installed for $LAST_RUSER@$LAST_HOST"
        ask_yn "Test the password-less connection now?" y && test_connection "$LAST_HOST" "$LAST_PORT" "$LAST_RUSER"
        return 0
    fi
    err "Failed to install the key on $LAST_HOST."; return 1
}

#==============================================================================
#  TEST
#==============================================================================
test_connection() {   # test_connection [host port ruser]
    require_user
    step "Testing password-less SSH login"
    local host=${1:-} port=${2:-} ruser=${3:-} out rc
    if [[ -z $host ]]; then
        ask host  "Remote host or IP" "$LAST_HOST" v_host
        ask port  "Remote SSH port" "${LAST_PORT:-22}" v_port
        ask ruser "Remote user" "${LAST_RUSER:-$TARGET_USER}"
    fi
    if [[ $SELECTED_PUB == *.openssh.pub ]] && tectia_installed; then   # Tectia key -> test with sshg3
        tectia_test "$host" "$port" "$ruser"; return $?
    fi
    local idopt=(); [[ -n $SELECTED_PUB && -f ${SELECTED_PUB%.pub} ]] && idopt=(-i "${SELECTED_PUB%.pub}")
    out=$(as_user ssh -p "$port" -l "$ruser" "${idopt[@]}" -o BatchMode=yes -o ConnectTimeout=10 \
          -o PasswordAuthentication=no -o KbdInteractiveAuthentication=no "$host" "echo $MARKER_TEST" 2>&1)
    rc=$?
    log "TEST  rc=$rc out=$out"
    if [[ $out == *"$MARKER_TEST"* ]]; then
        ok "${G}SUCCESS${N} - $TARGET_USER@$(hostname -s) -> $ruser@$host:$port works without a password."
        return 0
    fi
    err "Key-based login failed (exit $rc)."
    printf '%s\n' "$out" | tail -n 5 | sed 's/^/         /'
    case $out in
        *"Host key verification failed"*) hint "Remote host key not trusted - use 'Add a remote host to known_hosts'." ;;
        *"Permission denied"*) hint "Key not accepted: check the key is in the remote authorized_keys (Windows admins: C:\\ProgramData\\ssh\\administrators_authorized_keys) and its permissions." ;;
        *"Connection refused"*|*"timed out"*) hint "Remote SSH server not reachable on port $port." ;;
    esac
    if ask_yn "Show a verbose diagnostic run?" n; then
        as_user ssh -vvv -p "$port" -l "$ruser" "${idopt[@]}" -o BatchMode=yes -o ConnectTimeout=10 "$host" exit 2>&1 \
            | grep -Ei 'offering|authenticat|denied|identity file|server accepts|error|refused' | tail -n 25 | sed 's/^/     /'
    fi
    return 1
}

#==============================================================================
#  TECTIA SSH
#==============================================================================
tectia_installed() { [[ -x $TECTIA_BIN/ssh-keygen-g3 || -x $TECTIA_BIN/sshg3 ]]; }
tectia_version()   { "$TECTIA_BIN/sshg3" -V 2>/dev/null | head -1 || echo "installed"; }

tectia_menu() {
    local c
    while true; do
        banner
        step "Tectia SSH (SSH Communications Security)"
        if tectia_installed; then ok "Installed: $(tectia_version)"; else warn "Tectia is not installed on this host."; fi
        [[ -x $TECTIA_SBIN/ssh-server-g3 ]] && { svc_active "$TECTIA_SERVICE" && ok "Server service running" || warn "Server service not running"; }
        cat <<EOF

    ${C}1)${N} Install Tectia from package files (.rpm/.deb or a .tar/.zip bundle)
    ${C}2)${N} Configure Tectia Server (port, public-key auth, OpenSSH key file, start service)
    ${C}3)${N} Generate a Tectia user key (ssh-keygen-g3) for ${TARGET_USER:-<user>}
    ${C}4)${N} Authorise a remote public key for Tectia Server (optional source-IP restriction)
    ${C}5)${N} Push the Tectia user key to a Windows OpenSSH server
    ${C}6)${N} Test a connection with the Tectia client (sshg3)
    ${C}7)${N} Tectia server status / restart
    ${C}0)${N} Back
EOF
        menu_choice c 7
        case $c in
            0) return 0 ;;
            1) tectia_install ;;
            2) tectia_configure_server ;;
            3) tectia_generate_key ;;
            4) tectia_authorize_key ;;
            5) tectia_push_windows ;;
            6) tectia_test ;;
            7) tectia_status ;;
        esac
        pause
    done
}

tectia_install() {
    step "Install Tectia SSH"
    (( EUID == 0 )) || { err "Root required."; return 1; }
    info "Tectia is licensed software - provide the packages you downloaded from SSH.com."
    local src dir files=() f i sel arch ext
    ask src "Path to a Tectia package, bundle (.tar/.tar.gz/.zip) or directory"
    [[ -e $src ]] || { err "$src not found."; return 1; }
    dir="$(tmpd)/tectia"; mkdir -p "$dir"
    case $src in
        *.tar|*.tar.gz|*.tgz|*.tar.bz2|*.tar.xz) run_logged "Extract $src" tar -xf "$src" -C "$dir" || return 1 ;;
        *.zip) have unzip || { err "unzip not installed."; return 1; }; run_logged "Extract $src" unzip -q -o "$src" -d "$dir" || return 1 ;;
        *) [[ -d $src ]] && dir=$src || cp -- "$src" "$dir/" ;;
    esac
    if have rpm && [[ $PKG != apt ]]; then ext=rpm; else ext=deb; fi
    arch=$(uname -m)
    while IFS= read -r -d '' f; do files+=("$f"); done < <(find "$dir" -type f -iname "*tectia*.${ext}" -print0 | sort -z)
    (( ${#files[@]} )) || { err "No *tectia*.${ext} packages found in $src."; return 1; }
    printf '\n  %sPackages found:%s\n' "$W" "$N"
    for i in "${!files[@]}"; do
        f=$(basename "${files[$i]}")
        [[ $f == *"$arch"* || $f == *noarch* || $f == *all* ]] && printf '    %s%d)%s %s\n' "$C" "$((i+1))" "$N" "$f" \
            || printf '    %s%d)%s %s %s(architecture may not match %s)%s\n' "$C" "$((i+1))" "$N" "$f" "$Y" "$arch" "$N"
    done
    info "Typically install: ssh-tectia-common + ssh-tectia-client (+ ssh-tectia-server for incoming logins)."
    ALLOW_EMPTY=1 ask sel "Numbers to install (e.g. 1 2 3) or 'all'" "all"
    local pick=()
    if [[ $sel == all ]]; then pick=("${files[@]}")
    else for i in $sel; do [[ $i =~ ^[0-9]+$ ]] && (( i>=1 && i<=${#files[@]} )) && pick+=("${files[$((i-1))]}"); done; fi
    (( ${#pick[@]} )) || { warn "Nothing selected."; return 1; }
    if [[ $ext == rpm ]]; then
        if have dnf; then run_logged "Install Tectia packages (dnf)" dnf install -y "${pick[@]}"
        elif have yum; then run_logged "Install Tectia packages (yum)" yum localinstall -y "${pick[@]}"
        elif have zypper; then run_logged "Install Tectia packages (zypper)" zypper --non-interactive --no-gpg-checks install "${pick[@]}"
        else run_logged "Install Tectia packages (rpm)" rpm -Uvh "${pick[@]}"; fi
    else
        run_logged "Install Tectia packages (dpkg)" dpkg -i "${pick[@]}" || run_logged "Resolve dependencies" apt-get -f install -y
    fi || { err "Installation failed - see $LOG_FILE"; return 1; }
    tectia_installed && ok "Tectia installed: $(tectia_version)" || { err "Tectia binaries not found in $TECTIA_BIN after install."; return 1; }
    if [[ -d /etc/ssh2 ]] && ask_yn "Install a Tectia license file now?" y; then
        local lic; ask lic "Path to license file"
        if [[ -f $lic ]]; then mkdir -p /etc/ssh2/licenses; install -m 644 "$lic" /etc/ssh2/licenses/ && ok "License copied to /etc/ssh2/licenses/"
        else err "License file not found: $lic"; fi
    fi
    grep -q '/opt/tectia/bin' /etc/profile.d/tectia.sh 2>/dev/null || {
        printf 'case ":$PATH:" in *:/opt/tectia/bin:*) ;; *) PATH="$PATH:/opt/tectia/bin" ;; esac\n' > /etc/profile.d/tectia.sh
        info "Added /opt/tectia/bin to PATH for login shells (/etc/profile.d/tectia.sh)"; }
    [[ -x $TECTIA_SBIN/ssh-server-g3 ]] && ask_yn "Configure Tectia Server now?" y && tectia_configure_server
    return 0
}

tectia_configure_server() {
    step "Configure Tectia Server"
    [[ -x $TECTIA_SBIN/ssh-server-g3 ]] || { err "Tectia Server is not installed."; return 1; }
    [[ -f $TECTIA_CONF ]] || { err "$TECTIA_CONF not found."; return 1; }
    local port=22 bak c openssh_port
    openssh_port=""
    if svc_active "$SSH_SERVICE"; then openssh_port=$(sshd_ports | head -1); fi
    if [[ -n $openssh_port ]]; then
        warn "OpenSSH sshd is running on port $openssh_port - two servers cannot share one port."
        printf '    %s1)%s Run Tectia Server on a different port (e.g. 2222) - keeps OpenSSH\n' "$C" "$N"
        printf '    %s2)%s Stop & disable OpenSSH sshd and run Tectia on port 22\n' "$C" "$N"
        printf '    %s3)%s Leave ports unchanged\n' "$C" "$N"
        menu_choice c 3
        case $c in
            0) return 0 ;;
            1) ask port "Tectia Server port" "2222" v_port ;;
            2) if [[ -n ${SSH_CONNECTION:-} ]]; then
                   warn "You are connected over SSH right now (${SSH_CONNECTION%% *})."
                   ask_yn "Stopping OpenSSH may drop your session if Tectia fails to start. Continue?" n || return 1
               fi
               run_logged "Stop OpenSSH ($SSH_SERVICE)" svc stop "$SSH_SERVICE"
               have systemctl && run_logged "Disable OpenSSH at boot" systemctl disable "$SSH_SERVICE"
               port=22 ;;
            3) port="" ;;
        esac
    else
        ask port "Tectia Server port" "22" v_port
    fi
    bak=$(backup_file "$TECTIA_CONF"); info "Backup: $bak"
    if [[ -n $port ]]; then
        if grep -q '<listener' "$TECTIA_CONF"; then
            sed -i -E "s/(<listener[^>]*port=\")[0-9]+(\")/\1${port}\2/" "$TECTIA_CONF"
            grep -q "<listener[^>]*port=\"${port}\"" "$TECTIA_CONF" || sed -i -E "s|<listener([^/>]*)(/?>)|<listener\1 port=\"${port}\"\2|" "$TECTIA_CONF"
        elif grep -q '<params' "$TECTIA_CONF"; then
            sed -i -E "0,/<params[^>]*>/s||&\n    <listener id=\"default\" address=\"0.0.0.0\" port=\"${port}\" />|" "$TECTIA_CONF"
        else
            warn "No <params>/<listener> element found - set the port manually in $TECTIA_CONF:"
            hint "<params> <listener id=\"default\" address=\"0.0.0.0\" port=\"${port}\" /> </params>"
        fi
        ok "Listener port set to $port"
        selinux_on && have semanage && [[ $port != 22 ]] && semanage port -a -t ssh_port_t -p tcp "$port" 2>/dev/null
        open_firewall "$port"
    fi
    if grep -q '<auth-publickey' "$TECTIA_CONF"; then
        if ! grep -q 'openssh-authorized-keys-file' "$TECTIA_CONF" && ask_yn "Also accept keys from OpenSSH ~/.ssh/authorized_keys?" y; then
            sed -i -E 's|<auth-publickey([^/>]*)(/?>)|<auth-publickey\1 openssh-authorized-keys-file="%D/.ssh/authorized_keys"\2|' "$TECTIA_CONF"
            ok "Tectia will also read ~/.ssh/authorized_keys"
        fi
    else
        info "No explicit <auth-publickey> element: Tectia defaults apply (keys in ~/.ssh2/authorized_keys/)."
    fi
    have systemctl && systemctl enable "$TECTIA_SERVICE" >/dev/null 2>&1
    if svc_active "$TECTIA_SERVICE"; then run_logged "Restart Tectia server" svc restart "$TECTIA_SERVICE"
    else run_logged "Start Tectia server" svc start "$TECTIA_SERVICE"; fi
    sleep 2
    if svc_active "$TECTIA_SERVICE"; then ok "Tectia server is running."
    else
        err "Tectia server failed to start - restoring previous configuration."
        have journalctl && journalctl -u "$TECTIA_SERVICE" -n 15 --no-pager 2>/dev/null | sed 's/^/         /'
        [[ -n $bak ]] && cp -p "$bak" "$TECTIA_CONF" && svc start "$TECTIA_SERVICE" >/dev/null 2>&1
        hint "Check the license in /etc/ssh2/licenses and the configuration with the Tectia documentation."
        return 1
    fi
}

tectia_generate_key() {
    require_user
    step "Generate a Tectia user key for $TARGET_USER"
    tectia_installed || { err "Tectia client is not installed."; return 1; }
    local c type=rsa bits=4096 name keyfile pass=() comment idf
    printf '    %s1)%s rsa 4096 (default, works with every Tectia version)\n    %s2)%s ed25519 (Tectia 6.4+)\n' "$C" "$N" "$C" "$N"
    menu_choice c 2
    case $c in 0) return 0 ;; 2) type=ed25519; bits="" ;; esac
    name="id_${type}${bits:+_$bits}_keyx"
    keyfile="$TARGET_HOME/.ssh2/$name"
    as_user mkdir -p "$TARGET_HOME/.ssh2"
    if [[ -f $keyfile ]]; then
        warn "$keyfile already exists."
        ask_yn "Back it up and generate a new one?" n || { info "Keeping existing key."; return 0; }
        mv "$keyfile" "$keyfile.bak.$(date +%s)"; mv "$keyfile.pub" "$keyfile.pub.bak.$(date +%s)" 2>/dev/null
    fi
    if ask_yn "Protect the key with a passphrase? ('n' for automation)" n; then
        local p; ask_secret p "Passphrase" 5; pass=(-p "$p")
    else pass=(-P); fi
    ask comment "Key comment" "${TARGET_USER}@$(hostname -s)-tectia"
    if ! as_user "$TECTIA_BIN/ssh-keygen-g3" -t "$type" ${bits:+-b "$bits"} "${pass[@]}" -c "$comment" "$keyfile" </dev/null >>"$LOG_FILE" 2>&1; then
        err "ssh-keygen-g3 failed - see $LOG_FILE"; return 1
    fi
    idf="$TARGET_HOME/.ssh2/identification"
    grep -qx "IdKey $name" "$idf" 2>/dev/null || printf 'IdKey %s\n' "$name" >> "$idf"
    if have ssh-keygen && ssh-keygen -i -m RFC4716 -f "$keyfile.pub" > "$TARGET_HOME/.ssh2/$name.openssh.pub" 2>>"$LOG_FILE"; then
        sed -i "s|\$| ${comment//[^A-Za-z0-9@._-]/}|" "$TARGET_HOME/.ssh2/$name.openssh.pub"
        info "OpenSSH-format copy: $TARGET_HOME/.ssh2/$name.openssh.pub (for Windows/Linux OpenSSH servers)"
        SELECTED_PUB="$TARGET_HOME/.ssh2/$name.openssh.pub"
    fi
    fix_ssh_permissions >/dev/null
    ok "Tectia key created: $keyfile (registered in $idf)"
    printf '\n%s%s%s\n' "$G" "$(cat "$keyfile.pub")" "$N"
}

tectia_authorize_key() {
    require_user
    step "Authorise a remote public key for Tectia Server (user $TARGET_USER)"
    read_public_key || return 1
    local name ip adir="$TARGET_HOME/.ssh2/authorized_keys" kfile authf
    ALLOW_EMPTY=1 ask ip "Restrict to source IP(s) (blank = anywhere)" "" v_from_list
    ask name "Short name for this key (e.g. winpc01)" "remote$(date +%H%M%S)"
    name=$(printf '%s' "$name" | tr -cd 'A-Za-z0-9_.-')
    as_user mkdir -p "$adir"
    printf '%s\n' "$PUBKEY" > "$(tmpd)/k.pub"
    if [[ -z $ip ]]; then
        kfile="$adir/$name.pub"
        ssh-keygen -e -f "$(tmpd)/k.pub" > "$kfile" 2>>"$LOG_FILE" || cp "$(tmpd)/k.pub" "$kfile"
        fix_ssh_permissions >/dev/null
        ok "Key stored in $kfile (Tectia authorized_keys directory)"
    else
        # IP restriction requires the 'authorization' file (Key + Options allow-from)
        kfile="$TARGET_HOME/.ssh2/$name.pub"
        ssh-keygen -e -f "$(tmpd)/k.pub" > "$kfile" 2>>"$LOG_FILE" || cp "$(tmpd)/k.pub" "$kfile"
        authf="$TARGET_HOME/.ssh2/authorization"
        if [[ ! -f $authf ]]; then
            local existing=("$adir"/*.pub)
            if [[ -f ${existing[0]} ]]; then
                warn "Once an 'authorization' file exists, Tectia only accepts keys listed in it."
                if ask_yn "Copy the ${#existing[@]} key(s) from authorized_keys/ into it so they keep working?" y; then
                    local e; for e in "${existing[@]}"; do cp "$e" "$TARGET_HOME/.ssh2/"; printf 'Key %s\n' "$(basename "$e")" >> "$authf"; done
                fi
            fi
        fi
        backup_file "$authf" >/dev/null
        local re; re=$(printf '%s' "$ip" | sed 's/\./\\./g; s/\*/.*/g; s/,/|/g')
        printf 'Key %s.pub\nOptions allow-from="%s"\n' "$name" "$re" >> "$authf"
        fix_ssh_permissions >/dev/null
        ok "Key $kfile authorised in $authf with allow-from=\"$re\""
    fi
    [[ -x $TECTIA_SBIN/ssh-server-g3 ]] || warn "Tectia Server is not installed on this host - keys take effect once it is."
}

tectia_push_windows() {
    require_user
    local f
    for f in "$TARGET_HOME"/.ssh2/*.openssh.pub; do [[ -f $f ]] && SELECTED_PUB=$f; done
    [[ $SELECTED_PUB == *.openssh.pub ]] || { warn "No Tectia key in OpenSSH format found - generate one first (option 3)."; return 1; }
    info "Using Tectia key (OpenSSH format): $SELECTED_PUB"
    push_key_to_windows
}

tectia_test() {
    require_user
    tectia_installed || { err "Tectia client not installed."; return 1; }
    local host=${1:-} port=${2:-} ruser=${3:-} out
    if [[ -z $host ]]; then
        ask host "Remote host" "$LAST_HOST" v_host
        ask port "Remote port" "${LAST_PORT:-22}" v_port
        ask ruser "Remote user" "${LAST_RUSER:-$TARGET_USER}"
    fi
    out=$(as_user "$TECTIA_BIN/sshg3" -B -p "$port" "$ruser@$host" "echo $MARKER_TEST" 2>&1)
    log "TECTIA TEST $out"
    if [[ $out == *"$MARKER_TEST"* ]]; then ok "${G}SUCCESS${N} - Tectia key login to $ruser@$host works."
    else err "Tectia login failed:"; printf '%s\n' "$out" | tail -n 6 | sed 's/^/         /'
         hint "First connection may need host key acceptance: run '$TECTIA_BIN/sshg3 -p $port $ruser@$host' once interactively as $TARGET_USER."
    fi
}

tectia_status() {
    step "Tectia server status"
    if have systemctl; then systemctl status "$TECTIA_SERVICE" --no-pager 2>&1 | head -15 | sed 's/^/   /'; fi
    have ss && ss -tlnp 2>/dev/null | grep -E 'ssh-server-g3|sshd-g3' | sed 's/^/   /'
    ask_yn "Restart the Tectia server now?" n && run_logged "Restart Tectia" svc restart "$TECTIA_SERVICE"
}

#==============================================================================
#  WIZARD / SUMMARY / MENU
#==============================================================================
show_summary() {
    step "Summary"
    printf '   %-22s %s\n' "Local user:" "${TARGET_USER:-<none>} ${TARGET_HOME:+($TARGET_HOME)}"
    printf '   %-22s %s\n' "Selected key:" "${SELECTED_PUB:-<none>}"
    [[ -n $SELECTED_PUB && -f $SELECTED_PUB ]] && printf '   %-22s %s\n' "Fingerprint:" "$(key_fp "$SELECTED_PUB")"
    if [[ -n $TARGET_HOME && -f $TARGET_HOME/.ssh/authorized_keys ]]; then
        printf '   %-22s %s\n' "Authorised keys:" "$(grep -cE '^[^#]' "$TARGET_HOME/.ssh/authorized_keys") in ~/.ssh/authorized_keys"
    fi
    printf '   %-22s %s\n' "sshd service:" "$SSH_SERVICE ($(svc_active "$SSH_SERVICE" && echo running || echo stopped))"
    printf '   %-22s %s\n' "Last remote:" "${LAST_RUSER:+$LAST_RUSER@}${LAST_HOST:-<none>}:${LAST_PORT} ${LAST_OS}"
    printf '   %-22s %s\n' "This host IPs:" "$(local_ips)"
    printf '   %-22s %s\n' "Log file:" "$LOG_FILE"
}

wizard() {
    banner
    step "Guided end-to-end setup"
    info "Steps: prerequisites -> user -> key pair -> exchange keys -> test"
    check_prereqs || ask_yn "Continue anyway?" y || return 1
    select_or_create_user
    if pick_user_key_quiet; then
        info "Existing key found: $SELECTED_PUB ($(key_fp "$SELECTED_PUB"))"
        ask_yn "Use this key? ('n' generates a new one)" y || generate_keypair
    else
        generate_keypair || return 1
    fi
    step "Which direction(s) do you want to configure?"
    cat <<EOF
    ${C}1)${N} Windows -> this Linux   (authorise the Windows user's key here)
    ${C}2)${N} this Linux -> Windows   (install my key on the Windows server)
    ${C}3)${N} Both directions
    ${C}4)${N} this Linux -> another Linux server
EOF
    local c; menu_choice c 4
    case $c in
        1) authorize_remote_key ;;
        2) push_key_to_windows ;;
        3) authorize_remote_key; push_key_to_windows ;;
        4) push_key_to_linux ;;
    esac
    show_summary
}

pick_user_key_quiet() {
    local f
    for f in "$TARGET_HOME"/.ssh/id_ed25519.pub "$TARGET_HOME"/.ssh/id_rsa.pub "$TARGET_HOME"/.ssh/id_ecdsa.pub; do
        [[ -f $f ]] && { SELECTED_PUB=$f; return 0; }
    done
    return 1
}

main_menu() {
    local c
    while true; do
        banner
        cat <<EOF

  ${W}Setup${N}
    ${C} 1)${N} Check prerequisites (and fix)
    ${C} 2)${N} Install / repair OpenSSH client & server
    ${C} 3)${N} Select or create the local user
    ${C} 4)${N} Generate an SSH key pair (and set permissions)
  ${W}Key exchange${N}
    ${C} 5)${N} Windows -> Linux : authorise a remote public key here (with source IP)
    ${C} 6)${N} Linux -> Windows : install my public key on a Windows server
    ${C} 7)${N} Linux -> Linux   : install my public key on another Linux server
    ${C} 8)${N} Add a remote host to known_hosts (verify fingerprint)
    ${C} 9)${N} Test password-less connection
  ${W}Tools${N}
    ${C}10)${N} ${G}Guided end-to-end setup (wizard)${N}
    ${C}11)${N} Tectia SSH: install / configure / keys
    ${C}12)${N} List authorised keys / fix permissions
    ${C}13)${N} Show summary
    ${C} 0)${N} Exit
EOF
        menu_choice c 13
        case $c in
            0) show_summary; printf '\n  %sBye.%s\n\n' "$G" "$N"; exit 0 ;;
            1) check_prereqs ;;
            2) install_openssh ;;
            3) select_or_create_user ;;
            4) generate_keypair ;;
            5) authorize_remote_key ;;
            6) push_key_to_windows ;;
            7) push_key_to_linux ;;
            8) require_user; ask LAST_HOST "Remote host or IP" "$LAST_HOST" v_host
               ask LAST_PORT "Remote SSH port" "${LAST_PORT:-22}" v_port
               add_known_host "$LAST_HOST" "$LAST_PORT" ;;
            9) test_connection ;;
            10) wizard ;;
            11) tectia_menu; continue ;;
            12) list_authorized_keys; fix_ssh_permissions ;;
            13) show_summary ;;
        esac
        pause
    done
}

usage() {
    cat <<EOF
Usage: sudo $0 [--wizard | --check] [--no-color]

Interactive SSH public-key exchange between this Linux host and Windows/Linux hosts.
  --wizard     guided end-to-end setup
  --check      only run the prerequisite check
  --no-color   disable coloured output
  -h, --help   this help
EOF
}

#==============================================================================
#  ENTRY POINT
#==============================================================================
main() {
    local mode=menu a
    for a in "$@"; do
        case $a in
            --wizard) mode=wizard ;;
            --check) mode=check ;;
            --no-color) NO_COLOR=1 ;;
            -h|--help) setup_colors; usage; exit 0 ;;
            *) printf 'Unknown option: %s\n' "$a" >&2; usage; exit 2 ;;
        esac
    done
    setup_colors
    if (( BASH_VERSINFO[0] < 4 )); then echo "bash 4 or newer is required." >&2; exit 1; fi
    if (( EUID != 0 )); then
        printf '%s[WARN]%s Root privileges are needed (user creation, sshd configuration, packages).\n' "$Y" "$N"
        if have sudo; then exec sudo -E bash "$0" "$@"; fi
        printf '%s[FAIL]%s Run this script as root.\n' "$R" "$N" >&2; exit 1
    fi
    [[ -t 0 ]] || { echo "This script is interactive - run it from a terminal." >&2; exit 1; }
    init_log
    init_tmp
    detect_os
    case $mode in
        check)  banner; check_prereqs; exit $? ;;
        wizard) wizard; pause; main_menu ;;
        *)      main_menu ;;
    esac
}

main "$@"
