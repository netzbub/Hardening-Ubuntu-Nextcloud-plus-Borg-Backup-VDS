#!/usr/bin/env bash
# =============================================================================
# install.sh - Ubuntu 24.04 server: installation + hardening
# Implements the "Ubuntu install and hardening" concept
# Rev. 3 - after 2nd double-agent review (Docker ufw bypass, backup permissions/keys,
#          phase-11 lockdown, auditd, container hardening, etc.)
# Rev. 4 (2026-07-12) - council must-fixes integrated:
#          1 Redis cap_add (start blocker), 2 Runtipi path /opt/runtipi (blocker;
#          settings.json schema verified against runtipi.io docs as of 2026-04) -
#          Runtipi itself was replaced by Portainer CE in Rev. 6, see below,
#          3 fstab nofail + docker RequiresMountsFor, 4 password-offline gate,
#          5 DOCKER-USER also IPv6 (after6.rules) + Docker IPv6 explicitly off,
#          6 NC 2FA enforcement (nc-post-setup.sh), 7 fail2ban /64 ban (ipset),
#          8 DNS gate before Caddy start + mandatory failregex test. verify extended.
#          The Redis cap set is theory-based (no Docker in the test environment) -
#          verification on the test server is MANDATORY.
# Rev. 5 (2026-07-19) - hardening run (batch 1-6) verified on the test server, folded back:
#          - GRUB boot params now behind flag ENABLE_GRUB_HARDENING (default OFF) after
#            the boot incident 2026-07-19 (some providers: no rescue/ISO). apparmor/audit params NEVER.
#          - HOSTNAME_FQDN as an optional config var.
#          - sysctl secure_redirects + ufw-sysctl log_martians fix; modprobe usb-storage+blacklist.
#          - PAM: full pwquality set, pwhistory=24, nullok removed, login.defs (UMASK 027/aging),
#            profile.d TMOUT/umask, su restricted to the sudo group.
#          - fail2ban allowipv6=auto + ignoreip WG net; NC filter on the official 2FA regex.
#          - auditd: mkdir fix BEFORE augenrules (fixes ordering bug), L2 rule set (~47),
#            auditd.conf availability-friendly (ROTATE/EMAIL instead of SUSPEND).
#          - NEW phase12: KVM service cleanup, ubuntu user + cloud-init sudoers removed, AIDE.
#          - Caddy systemd sandbox; Compose pids/mem limits (sized for a 16 GB prod box).
#          - extra SSH directives (Ciphers/Kex/MACs, HostbasedAuth/IgnoreRhosts); S.1.f
#            PermitRootLogin cleanup in the main sshd_config.
#          - Lynis from the CISOfy repo (phase 4) instead of the frozen universe package.
# Rev. 6 (2026-08-01) - panel decision + multi-agent review fixes folded back:
#          - Panel research (four criteria: app store, real Docker deploy, real
#            monitoring, compatible with the hardened setup) concluded Runtipi does
#            not fit; phase 11 now installs Portainer CE instead (own docker run,
#            no bundled proxy, binds directly to the WG address, no port 80/443 clash).
#          - AIDE excludes and the monthly update-reminder text updated accordingly.
#          - Fixed a real phase-3 abort bug: '[[ "$KEEP22" == 1 ]] && ufw limit 22/tcp ...'
#            as a bare statement returned exit 1 under 'set -e' whenever KEEP22=0 (the
#            normal case), killing phase3 right after the SSH rule. Now wrapped in 'if'.
#            KEEP22 is now local to phase3().
#          - Disk-space headroom on $HDD_MOUNT: explicit 'tune2fs -m 5' reserved-blocks
#            plus a twice-daily disk-space-alert timer (85%/95% mail thresholds).
#            Percentage-based - unchanged whether $HDD_MOUNT is the transitional second
#            500 GB NVMe or, from month 5, the 4 TB HDD. Two new verify checks; AIDE
#            excludes extended for the alert script's state directory.
#
# USAGE (as root on a fresh Ubuntu 24.04):
#   ./install.sh preflight        # checks + apt update/upgrade
#   ./install.sh phase1           # ... a single phase
#   ./install.sh all              # all phases (stops after SSH hardening
#                                        #  for the mandatory login test!)
#   ./install.sh bootstrap        # preflight+phase1+phase2, ends at the login-test stop
#   ./install.sh rest             # phase3..phase12 + verify (AFTER a successful login test)
#   ./install.sh verify           # health check
#
# 3-STEP ROUTINE (after the prerequisites are front-loaded: DNS, HDD, WG pubkey,
# NC tag, SMTP, SSH pubkey): 'bootstrap' -> test the login in a 2nd terminal -> 'rest'.
# FIRST RUN on a new server still phase by phase (catch Redis/Portainer live).
#
# RECOMMENDATION: run phases individually; after phase2 (SSH) you MUST test the
# login in a SECOND terminal before closing the old session!
# Rescue anchor on lock-out: the VNC console in the provider backend.
#
# Secrets: generated passwords go into $SECRETS_DIR (chmod 700/600).
# WARNING: this script lives in a synced folder / Git repo -
# NEVER leave real passwords permanently in the configuration below.
# =============================================================================
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive   # applies to ALL phases (Review H4)

# ============================ CONFIGURATION ==================================
# Personal / deployment-specific values are NOT stored in this script (it lives in a
# public Git repo). They live in a separate, GIT-IGNORED file `install.conf` next to
# this script. Set it up once:
#     cp install.conf.example install.conf   &&   edit install.conf
# Or point to another location:  INSTALL_CONF=/path/to/install.conf ./install.sh ...
_SCRIPT_DIR="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
INSTALL_CONF="${INSTALL_CONF:-$_SCRIPT_DIR/install.conf}"
if [[ -f "$INSTALL_CONF" ]]; then
    # shellcheck source=/dev/null
    source "$INSTALL_CONF"
fi

# --- Required (set these in install.conf) ---
ADMIN_USER="${ADMIN_USER:-}"               # sudo admin user (SSH login); no default
SSH_PORT="${SSH_PORT:-22022}"              # non-standard SSH port
SSH_PUBKEY="${SSH_PUBKEY:-}"               # REQUIRED: full ed25519 public key line
ADMIN_MAIL="${ADMIN_MAIL:-}"               # REQUIRED: valid address for system mail
HOSTNAME_FQDN="${HOSTNAME_FQDN:-}"         # optional FQDN (e.g. server.example.com); empty = keep provider hostname

# --- Nextcloud (phase 9) ---
NC_DOMAIN="${NC_DOMAIN:-}"                 # e.g. next.example.com
NC_IMAGE_TAG="${NC_IMAGE_TAG:-}"           # REQUIRED for phase9: current stable tag from hub.docker.com/_/nextcloud/tags
                                           # (take the tag WITHOUT the "-apache" suffix; the base image is already Apache).
                                           # Prefer a digest comparison over trusting the "stable" tag name.

# --- WireGuard (phase 8) ---
WG_PORT="${WG_PORT:-51820}"
WG_NET="${WG_NET:-10.8.0}"                 # /24 appended; server = .1, local machine = .2
WG_CLIENT_PUBKEY="${WG_CLIENT_PUBKEY:-}"   # local machine public key (wg genkey | tee wg.key | wg pubkey)

# --- Mail via msmtp (phase 4) ---
SMTP_HOST="${SMTP_HOST:-}"                 # e.g. mail.provider.tld
SMTP_PORT="${SMTP_PORT:-587}"
SMTP_USER="${SMTP_USER:-}"                 # SMTP login (often the full address)
SMTP_PASS="${SMTP_PASS:-}"                 # only for a ONE-TIME write to /etc/msmtp-pass (600); then clear it again
SMTP_FROM="${SMTP_FROM:-}"                 # sender address

# --- Portainer (phase 11) ---
PORTAINER_PORT="${PORTAINER_PORT:-9443}"

# --- HDD / Borg backup on the server HDD (phase 9+10) ---
HDD_MOUNT="${HDD_MOUNT:-/srv/hdd}"         # 4 TB HDD mount point
NCDATA_DIR="${HDD_MOUNT}/ncdata"           # Nextcloud data dir (blobs, ~1 TB)
BACKUP_DIR="${HDD_MOUNT}/backup"           # Borg repos: repo-server + repo-local

# --- General ---
TIMEZONE="${TIMEZONE:-Europe/Berlin}"
SECRETS_DIR="${SECRETS_DIR:-/root/install-secrets}"
LOGFILE="${LOGFILE:-/var/log/harden-install.log}"
WAN_IF="${WAN_IF:-}"                       # WAN interface (Docker/ufw bypass guard, phase 9); empty = auto-detect
# GRUB boot-parameter hardening (phase5). Default OFF: boot params have the largest blast
# radius and some providers have no rescue/ISO, only the provider backup. Enable ONLY with
# a fresh provider backup: "yes" -> update-grub -> reboot -> check /proc/cmdline.
ENABLE_GRUB_HARDENING="${ENABLE_GRUB_HARDENING:-no}"

# Fail early if the personal config was not loaded (skip when only showing usage):
if [[ -n "${1:-}" && "${1:-}" != "usage" && -z "$ADMIN_USER" ]]; then
    echo "[ERROR] No install.conf found (ADMIN_USER empty). Run: cp install.conf.example install.conf, then edit it." >&2
    exit 1
fi
# =============================================================================

C_GRN='\033[0;32m'; C_RED='\033[0;31m'; C_YEL='\033[0;33m'; C_OFF='\033[0m'
log()  { echo -e "${C_GRN}[+]${C_OFF} $*" | tee -a "$LOGFILE"; }
warn() { echo -e "${C_YEL}[!]${C_OFF} $*" | tee -a "$LOGFILE"; }
die()  { echo -e "${C_RED}[ERROR]${C_OFF} $*" | tee -a "$LOGFILE"; exit 1; }

require_root() { [[ $EUID -eq 0 ]] || die "Run as root."; }

backup_file() {  # backup_file <path>
    local f="$1"
    [[ -f "$f" ]] && cp -a "$f" "${f}.bak.$(date +%Y%m%d-%H%M%S)"
    return 0
}

append_once() {  # append_once <line> <file>  - idempotent append
    grep -qxF "$1" "$2" 2>/dev/null || echo "$1" >> "$2"
}

gen_secret() {  # gen_secret <name>  - create/read a secret, print it to stdout
    local f="$SECRETS_DIR/$1"
    if [[ ! -f "$f" ]]; then
        install -d -m 700 "$SECRETS_DIR"
        openssl rand -hex 24 > "$f"      # 48 chars, deterministic length
        chmod 600 "$f"
    fi
    cat "$f"
}

# ============================ PHASE 0: PREFLIGHT =============================
preflight() {
    require_root
    log "Preflight checks"
    grep -q 'VERSION_ID="24.04"' /etc/os-release || warn "No Ubuntu 24.04 detected - this script is written for 24.04!"
    [[ -n "$SSH_PUBKEY" ]] || die "SSH_PUBKEY is empty - set the public key in install.conf."
    # Key VALIDATION (Review K4): a mangled pasted key = total lock-out after phase2
    ssh-keygen -lf /dev/stdin <<<"$SSH_PUBKEY" >/dev/null 2>&1 \
        || die "SSH_PUBKEY is not a valid public key (line break? truncated?)."
    [[ "$ADMIN_MAIL" == *@* ]] || warn "ADMIN_MAIL '$ADMIN_MAIL' is not an email address - system mail will fail!"
    # Early warning instead of aborting mid-'all' (Review M2 logic):
    [[ -n "$NC_IMAGE_TAG" ]]      || warn "NC_IMAGE_TAG empty - phase9 will abort without a value. Set it before 'all'."
    [[ -n "$WG_CLIENT_PUBKEY" ]]  || warn "WG_CLIENT_PUBKEY empty - the WireGuard peer must be added later."
    [[ -n "$SMTP_HOST" ]]        || warn "SMTP_* empty - system mail (backup errors, updates) will not be sent."
    timedatectl set-timezone "$TIMEZONE"
    timedatectl set-ntp true                     # correct time: prerequisite for TLS, TOTP, logs
    # Pin NTP servers (Rev.5 / Batch B1):
    install -d /etc/systemd/timesyncd.conf.d
    cat > /etc/systemd/timesyncd.conf.d/50-hardening.conf <<'EOF'
[Time]
NTP=0.ubuntu.pool.ntp.org 1.ubuntu.pool.ntp.org 2.ubuntu.pool.ntp.org 3.ubuntu.pool.ntp.org
FallbackNTP=ntp.ubuntu.com
EOF
    systemctl restart systemd-timesyncd 2>/dev/null || true
    # Optionally set the hostname (Rev.5):
    if [[ -n "$HOSTNAME_FQDN" ]]; then
        hostnamectl set-hostname "$HOSTNAME_FQDN"
        local short_h="${HOSTNAME_FQDN%%.*}"
        if grep -qE '^127\.0\.1\.1' /etc/hosts; then
            sed -i -E "s|^127\.0\.1\.1.*|127.0.1.1\t${HOSTNAME_FQDN} ${short_h}|" /etc/hosts
        else
            printf '127.0.1.1\t%s %s\n' "$HOSTNAME_FQDN" "$short_h" >> /etc/hosts
        fi
        log "Hostname set: $HOSTNAME_FQDN"
    fi
    apt-get update -q
    apt-get full-upgrade -y -q
    apt-get install -y -q openssl curl gnupg ca-certificates apt-transport-https
    log "Preflight done. If the kernel was updated: reboot after all phases are complete."
}

# ============================ PHASE 1: ADMIN USER ===========================
phase1() {
    require_root
    log "Phase 1: user $ADMIN_USER + sudo"
    if ! id "$ADMIN_USER" &>/dev/null; then
        adduser --disabled-password --gecos "" "$ADMIN_USER"
        local pw; pw="$(gen_secret admin-user-password)"
        echo "${ADMIN_USER}:${pw}" | chpasswd
        log "Password for $ADMIN_USER (sudo only, no SSH login) is in $SECRETS_DIR/admin-user-password"
        # Council-Fix 4 (lock-out trap): the password exists only on-box, root has none.
        # Without an offline-saved password the provider VNC console is USELESS on an
        # SSH lock-out -> the server is unrecoverable without a reinstall.
        warn "REQUIRED: show the password NOW and save it offline (password manager + paper):"
        warn "    cat $SECRETS_DIR/admin-user-password"
        warn "Only then close the first session - the VNC console needs this password."
    fi
    usermod -aG sudo "$ADMIN_USER"

    install -d -m 700 -o "$ADMIN_USER" -g "$ADMIN_USER" "/home/$ADMIN_USER/.ssh"
    local ak="/home/$ADMIN_USER/.ssh/authorized_keys"
    append_once "$SSH_PUBKEY" "$ak"
    chown "$ADMIN_USER:$ADMIN_USER" "$ak"; chmod 600 "$ak"

    # sudo hardening: short timeout, logging, PTY requirement (hinders sudo hijacking)
    cat > /etc/sudoers.d/hardening <<'EOF'
Defaults timestamp_timeout=5
Defaults use_pty
Defaults logfile="/var/log/sudo.log"
EOF
    chmod 440 /etc/sudoers.d/hardening
    visudo -c >/dev/null || die "sudoers syntax error!"
    log "Phase 1 done. TEST in a 2nd terminal: ssh -i <key> ${ADMIN_USER}@<ip>  &&  sudo -v"
}

# ============================ PHASE 2: SSH HARDENING ========================
phase2() {
    require_root
    log "Phase 2: harden SSH (port $SSH_PORT, key-only, only $ADMIN_USER)"
    [[ -f "/home/$ADMIN_USER/.ssh/authorized_keys" ]] || die "Run phase1 first (authorized_keys missing)."

    # ufw already running (re-run/port change)? Open the new port BEFORE the sshd restart (Review M9):
    if command -v ufw &>/dev/null && ufw status 2>/dev/null | grep -q 'Status: active'; then
        ufw limit "${SSH_PORT}/tcp" comment 'SSH rate-limited' || true
    fi

    backup_file /etc/ssh/sshd_config
    # the cloud-init drop-in can re-enable PasswordAuthentication - remove it:
    rm -f /etc/ssh/sshd_config.d/50-cloud-init.conf

    cat > /etc/ssh/sshd_config.d/10-hardening.conf <<EOF
# Hardening drop-in - first value wins, 10- sorts before all other drop-ins
# (exception: 'Port' is additive - so verify also checks that 22 is not listening)
Port $SSH_PORT
PermitRootLogin no
PasswordAuthentication no
PermitEmptyPasswords no
PubkeyAuthentication yes
KbdInteractiveAuthentication no
UsePAM yes
AllowUsers $ADMIN_USER
LoginGraceTime 20
MaxAuthTries 3
MaxSessions 4
MaxStartups 10:30:60
ClientAliveInterval 300
ClientAliveCountMax 2
X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding yes
LogLevel VERBOSE
# Rev.5 (S.1.e) - extra hardening. The whole file is REWRITTEN via cat,
# so there is no duplicate-directive risk (the first-value-wins trap is avoided):
HostbasedAuthentication no
IgnoreRhosts yes
PermitUserEnvironment no
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
EOF
    chmod 600 /etc/ssh/sshd_config /etc/ssh/sshd_config.d/10-hardening.conf

    # Rev.5 (S.1.f): clean up the contradictory Ubuntu default line in the main file.
    # The drop-in wins by include order, but USG/CIS audits would otherwise report
    # a false positive. sshd -T (below via verify) shows the ACTUALLY effective value.
    sed -i 's/^PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config

    sshd -t || die "sshd config invalid - NOT restarted."

    # Ubuntu 24.04: socket activation off, classic service on (unambiguous port handling)
    systemctl disable --now ssh.socket 2>/dev/null || true
    systemctl daemon-reload
    systemctl enable ssh.service
    systemctl restart ssh.service
    log "Phase 2 done. KEEP THE SESSION OPEN and test in a 2nd terminal: ssh -p $SSH_PORT ${ADMIN_USER}@<ip>"
}

# ============================ PHASE 3: FIREWALL ==============================
phase3() {
    require_root
    log "Phase 3: ufw"
    # Guard against out-of-order runs (Review M8): is sshd listening on $SSH_PORT?
    local KEEP22
    if ! ss -tln 2>/dev/null | grep -q ":${SSH_PORT} "; then
        warn "sshd is NOT listening on $SSH_PORT (phase2 missing?) - port 22 stays open too."
        KEEP22=1
    else
        KEEP22=0
    fi
    apt-get install -y -q ufw
    ufw default deny incoming
    ufw default allow outgoing
    ufw limit "${SSH_PORT}/tcp" comment 'SSH rate-limited'
    if [[ "$KEEP22" == 1 ]]; then
        ufw limit 22/tcp comment 'SSH alt port - remove after phase2!'
    fi
    ufw allow 80/tcp  comment 'HTTP ACME+Redirect'
    ufw allow 443/tcp comment 'HTTPS'
    ufw logging low
    ufw --force enable
    ufw status verbose | tee -a "$LOGFILE"
    log "Phase 3 done. The current session stays up (established)."
}

# ==================== PHASE 4: AUTO-UPDATES + MAIL ===========================
phase4() {
    require_root
    log "Phase 4: unattended-upgrades + msmtp"
    apt-get install -y -q unattended-upgrades apt-listchanges msmtp-mta bsd-mailx

    # Use our own 52* file instead of editing 50* (50 belongs to the package, replaced on updates)
    # The Origins-Pattern adds the Docker and Caddy third-party repos (Review M1): otherwise
    # docker-ce/containerd/caddy would NEVER get automatic security patches.
    cat > /etc/apt/apt.conf.d/52unattended-upgrades-local <<EOF
Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::Mail "$ADMIN_MAIL";
Unattended-Upgrade::MailReport "only-on-error";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Origins-Pattern {
    "origin=Docker";
    "origin=Caddy";
    "origin=CISOfy";  # only effective if the CISOfy repo was set up (Lynis itself is
                      # installed by this script in phase 4; see the CISOfy repo step below)
};
EOF
    warn "Verify the origin strings 'Docker'/'Caddy'/'CISOfy' AFTER phase9, otherwise they are a silent no-op:"
    warn "  grep -h '^Origin' /var/lib/apt/lists/*download.docker.com*_Release /var/lib/apt/lists/*caddy*_Release /var/lib/apt/lists/*packages.cisofy.com*_Release"
    cat > /etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF

    # Rev.5 (U): Lynis from the official CISOfy repo - the universe package is frozen
    # at 3.0.9. The Origins-Pattern above (origin=CISOfy) only works with this repo.
    if [[ ! -f /etc/apt/sources.list.d/cisofy-lynis.list ]]; then
        curl -fsSL https://packages.cisofy.com/keys/cisofy-software-public.key \
            | gpg --dearmor -o /usr/share/keyrings/cisofy-lynis.gpg \
            && echo "deb [signed-by=/usr/share/keyrings/cisofy-lynis.gpg] https://packages.cisofy.com/community/lynis/deb/ stable main" \
                > /etc/apt/sources.list.d/cisofy-lynis.list \
            && apt-get update -q \
            || warn "CISOfy repo not set up - Lynis would come from universe (3.0.9). Check network/key."
    fi
    apt-get install -y -q lynis || warn "Lynis installation failed."

    if [[ -n "$SMTP_HOST" && -n "$SMTP_USER" ]]; then
        # Password NOT in msmtprc but in a separate 600 file via passwordeval (Review M1)
        if [[ -n "$SMTP_PASS" ]]; then
            install -m 600 /dev/null /etc/msmtp-pass
            printf '%s\n' "$SMTP_PASS" > /etc/msmtp-pass
            warn "SMTP_PASS is now in /etc/msmtp-pass - CLEAR the variable in install.conf again!"
        fi
        [[ -f /etc/msmtp-pass ]] || warn "/etc/msmtp-pass missing - create: install -m 600 /dev/null /etc/msmtp-pass && echo 'PASS' > /etc/msmtp-pass"
        cat > /etc/msmtprc <<EOF
defaults
auth on
tls on
tls_trust_file /etc/ssl/certs/ca-certificates.crt
logfile /var/log/msmtp.log
account default
host $SMTP_HOST
port $SMTP_PORT
from $SMTP_FROM
user $SMTP_USER
passwordeval cat /etc/msmtp-pass
aliases /etc/aliases
EOF
        chmod 600 /etc/msmtprc
        append_once "root: $ADMIN_MAIL" /etc/aliases
        append_once "default: $ADMIN_MAIL" /etc/aliases
        echo "Test mail from $(hostname) - msmtp works." | mail -s "Server mail test" "$ADMIN_MAIL" \
            && log "Test mail sent to $ADMIN_MAIL - check the inbox." \
            || warn "Test mail failed - check /etc/msmtprc and /var/log/msmtp.log."
    else
        warn "SMTP_* variables empty - create /etc/msmtprc manually later (chmod 600)."
    fi

    # Drop ballast (attack surface/RAM). Stock images ship snapd+core+lxd (Review M6):
    systemctl disable --now ModemManager 2>/dev/null || true
    if command -v snap &>/dev/null; then
        snap remove --purge lxd 2>/dev/null || true
        for s in $(snap list 2>/dev/null | awk 'NR>1 && $1!="snapd" && $1!="core" {print $1}'); do
            snap remove --purge "$s" 2>/dev/null || warn "Snap '$s' not removed - check manually."
        done
        snap remove --purge core22 2>/dev/null || true
        snap remove --purge core24 2>/dev/null || true
        apt-get purge -y -q snapd 2>/dev/null && log "snapd removed." || warn "snapd not removed - check manually (snap list)."
    fi
    log "Phase 4 done."
}

# ================ PHASE 5: KERNEL, NETWORK, FILESYSTEM HARDENING ============
phase5() {
    require_root
    log "Phase 5: sysctl, modprobe, GRUB, fstab, limits, permissions"

    cat > /etc/sysctl.d/99-hardening.conf <<'EOF'
# === Network: anti-spoofing / anti-MITM ===
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0
# === Network: DoS mitigation ===
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
# === Hide kernel info / make exploitation harder ===
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.yama.ptrace_scope = 1
fs.suid_dumpable = 0
kernel.unprivileged_bpf_disabled = 1
net.core.bpf_jit_harden = 2
kernel.kexec_load_disabled = 1
dev.tty.ldisc_autoload = 0
vm.unprivileged_userfaultfd = 0
kernel.randomize_va_space = 2
kernel.sysrq = 0
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0
# === Filesystem: link/FIFO protection in world-writable dirs ===
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.protected_fifos = 2
fs.protected_regular = 2
EOF
    # Docker (phase 9) sets ip_forward itself; do NOT force it to 0 here
    # while Docker is planned. Without Docker: add net.ipv4.ip_forward = 0.
    # Rev.5 (B1): ufw ships its own /etc/ufw/sysctl.conf which can reset log_martians
    # back to 0 - set it to 1 there too, otherwise it is silently overridden:
    if [[ -f /etc/ufw/sysctl.conf ]]; then
        sed -i 's|^net/ipv4/conf/all/log_martians=0|net/ipv4/conf/all/log_martians=1|' /etc/ufw/sysctl.conf
        sed -i 's|^net/ipv4/conf/default/log_martians=0|net/ipv4/conf/default/log_martians=1|' /etc/ufw/sysctl.conf
    fi
    sysctl --system >/dev/null || true
    log "sysctl applied."

    # Block unneeded kernel modules (attack surface of exotic protocols).
    # Rev.5 (B1): install+blacklist per module, plus usb-storage. NO overlayfs (Docker!).
    : > /etc/modprobe.d/99-hardening-blacklist.conf
    for m in dccp sctp rds tipc cramfs freevxfs jffs2 hfs hfsplus udf usb-storage; do
        printf 'install %s /bin/false\nblacklist %s\n' "$m" "$m" >> /etc/modprobe.d/99-hardening-blacklist.conf
    done

    # Kernel boot parameters (take effect after reboot). Rev.5: DEFAULT OFF via ENABLE_GRUB_HARDENING.
    # Incident 2026-07-19: stacked, UNTESTED boot params (apparmor=1 security=apparmor
    # audit=1 audit_backlog_limit=8192) sent the VM into a boot loop;
    # recovery only via the provider backup (no rescue, no ISO mount). The set below
    # (slab_nomerge/init_on_*/page_alloc.shuffle/randomize_kstack_offset/vsyscall=none/lockdown=integrity)
    # is proven safe on THIS KVM (tested), but enabling it stays a deliberate,
    # backup-protected decision. NEVER add the four apparmor/audit params.
    if [[ "$ENABLE_GRUB_HARDENING" == "yes" ]]; then
        install -d /etc/default/grub.d
        cat > /etc/default/grub.d/99-hardening.cfg <<'EOF'
GRUB_CMDLINE_LINUX_DEFAULT="$GRUB_CMDLINE_LINUX_DEFAULT slab_nomerge init_on_alloc=1 init_on_free=1 page_alloc.shuffle=1 randomize_kstack_offset=on vsyscall=none lockdown=integrity"
EOF
        update-grub 2>/dev/null || warn "update-grub failed - check the boot parameters."
        warn "GRUB hardening ACTIVE. Before reboot REQUIRED: fresh provider backup; after reboot check /proc/cmdline."
    else
        log "GRUB boot-parameter hardening skipped (ENABLE_GRUB_HARDENING=no)."
    fi

    # tmp dirs without exec (malware cannot start from temp):
    append_once "tmpfs /tmp     tmpfs defaults,nosuid,nodev,noexec 0 0" /etc/fstab
    append_once "tmpfs /dev/shm tmpfs defaults,nosuid,nodev,noexec 0 0" /etc/fstab
    systemctl daemon-reload

    # Core dumps off (they can contain passwords/keys):
    cat > /etc/security/limits.d/99-hardening.conf <<'EOF'
*   hard   core   0
*   soft   core   0
EOF
    install -d /etc/systemd/coredump.conf.d
    cat > /etc/systemd/coredump.conf.d/disable.conf <<'EOF'
[Coredump]
Storage=none
ProcessSizeMax=0
EOF

    # Permissions of critical files:
    chmod 700 /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly 2>/dev/null || true
    chmod 600 /etc/crontab
    chmod 700 /root
    # Rev.5 (B1): restrict cron/at to root (CIS):
    for f in /etc/cron.allow /etc/at.allow; do echo root > "$f"; chmod 640 "$f"; done
    rm -f /etc/cron.deny /etc/at.deny 2>/dev/null || true

    # Ensure AppArmor (Ubuntu default, but verify):
    apt-get install -y -q apparmor apparmor-utils
    systemctl enable --now apparmor
    aa-status --enabled && log "AppArmor active (enforcing profiles loaded)." || warn "AppArmor NOT active!"

    # === Rev.5 (B2): PAM / password policy / login.defs / su ===
    # Affects only local logins (root emergency console, sudo), not SSH-key remote access -
    # still CIS-relevant baseline hardening. USG reads /etc/security/pwquality.conf (NOT conf.d).
    apt-get install -y -q libpam-pwquality
    cat > /etc/security/pwquality.conf <<'EOF'
minlen = 14
minclass = 4
dcredit = -1
ucredit = -1
lcredit = -1
ocredit = -1
difok = 2
maxrepeat = 3
maxsequence = 3
dictcheck = 1
enforcing = 1
enforce_for_root
EOF
    # pwhistory: block reuse of the last 24 passwords (idempotent):
    if grep -q 'pam_pwhistory.so' /etc/pam.d/common-password; then
        if grep -q 'pam_pwhistory.so.*remember=' /etc/pam.d/common-password; then
            sed -i -E 's|(pam_pwhistory\.so[^#]*\bremember=)[0-9]+|\124|' /etc/pam.d/common-password
        else
            sed -i -E 's|(pam_pwhistory\.so)|\1 remember=24 use_authtok|' /etc/pam.d/common-password
        fi
    else
        sed -i '/pam_pwquality.so/a password\trequisite\t\t\tpam_pwhistory.so remember=24 use_authtok enforce_for_root' /etc/pam.d/common-password
    fi
    # Remove nullok (which allows empty passwords):
    sed -i -E 's/[[:space:]]+nullok\b//g' /etc/pam.d/common-auth
    # login.defs: UMASK + password aging:
    sed -i -E 's|^UMASK[[:space:]]+.*|UMASK\t\t027|' /etc/login.defs
    sed -i -E 's|^PASS_MAX_DAYS[[:space:]]+.*|PASS_MAX_DAYS\t365|' /etc/login.defs
    sed -i -E 's|^PASS_MIN_DAYS[[:space:]]+.*|PASS_MIN_DAYS\t1|' /etc/login.defs
    sed -i -E 's|^PASS_WARN_AGE[[:space:]]+.*|PASS_WARN_AGE\t14|' /etc/login.defs
    chage -M 365 -m 1 -W 14 "$ADMIN_USER" 2>/dev/null || true
    printf 'TMOUT=900\nreadonly TMOUT\nexport TMOUT\n' > /etc/profile.d/99-tmout.sh; chmod 644 /etc/profile.d/99-tmout.sh
    printf 'umask 027\n' > /etc/profile.d/99-umask.sh; chmod 644 /etc/profile.d/99-umask.sh
    # su only for members of the sudo group - ONLY if the admin is in it (else lock-out risk):
    if id -nG "$ADMIN_USER" | grep -qw sudo; then
        backup_file /etc/pam.d/su
        sed -i -E '0,/^[#[:space:]]*auth[[:space:]]+required[[:space:]]+pam_wheel\.so.*/s//auth       required   pam_wheel.so use_uid group=sudo/' /etc/pam.d/su
    else
        warn "$ADMIN_USER not in the sudo group - su restriction NOT applied (lock-out protection)."
    fi

    log "Phase 5 done. Boot parameters + fstab take effect after reboot (plan it at the end)."
}

# ============================ PHASE 6: FAIL2BAN ==============================
phase6() {
    require_root
    log "Phase 6: fail2ban"
    apt-get install -y -q fail2ban python3-systemd ipset

    # Rev.5 (B1): enable IPv6 bans globally + never ban our own WG net + loopback:
    printf '[Definition]\nallowipv6 = auto\n' > /etc/fail2ban/fail2ban.local
    install -d /etc/fail2ban/jail.d
    printf '[DEFAULT]\nignoreip = 127.0.0.1/8 ::1 %s.0/24\n' "$WG_NET" > /etc/fail2ban/jail.d/00-ignoreip.local

    # Council-Fix 7: fail2ban bans IPv6 only as /128 - but an attacker usually has
    # a whole /64 and simply rotates the address. Extra action:
    # every banned IPv6 goes as a /64 prefix into an ipset (v4 = no-op, still
    # handled by action_mw).
    cat > /usr/local/bin/f2b-ban6.sh <<'EOF'
#!/bin/bash
# fail2ban extra action: ban IPv6 attackers as a /64 prefix. IPv4: no-op.
set -u
ACTION="$1"; IP="${2:-}"
SET="f2b-v6prefix"
case "$ACTION" in
  start)
    ipset -exist create "$SET" hash:net family inet6
    ip6tables -C INPUT -m set --match-set "$SET" src -j DROP 2>/dev/null \
      || ip6tables -I INPUT -m set --match-set "$SET" src -j DROP
    ;;
  stop)
    ip6tables -D INPUT -m set --match-set "$SET" src -j DROP 2>/dev/null || true
    ipset destroy "$SET" 2>/dev/null || true
    ;;
  ban)   if [[ "$IP" == *:* ]]; then ipset -exist add "$SET" "${IP}/64"; fi ;;
  unban) if [[ "$IP" == *:* ]]; then ipset -exist del "$SET" "${IP}/64"; fi ;;
esac
exit 0
EOF
    chmod 700 /usr/local/bin/f2b-ban6.sh
    cat > /etc/fail2ban/action.d/ban6-prefix.conf <<'EOF'
[Definition]
actionstart = /usr/local/bin/f2b-ban6.sh start
actionstop  = /usr/local/bin/f2b-ban6.sh stop
actioncheck =
actionban   = /usr/local/bin/f2b-ban6.sh ban <ip>
actionunban = /usr/local/bin/f2b-ban6.sh unban <ip>
EOF

    cat > /etc/fail2ban/jail.local <<EOF
[DEFAULT]
backend  = systemd
bantime  = 1h
findtime = 10m
maxretry = 3
bantime.increment = true
bantime.factor    = 2
bantime.maxtime   = 1w
destemail = $ADMIN_MAIL
sender    = root@$(hostname -f 2>/dev/null || hostname)
# Ban + mail with whois (Review H1; without 'action_mw' no mail is ever sent).
# Second action (Council-Fix 7): also ban IPv6 as a /64 prefix via ipset:
action    = %(action_mw)s
            ban6-prefix

[sshd]
enabled = true
port    = $SSH_PORT

[recidive]
# reads fail2ban's OWN log file, not the journal (Review H2):
enabled  = true
backend  = auto
logpath  = /var/log/fail2ban.log
bantime  = 2w
findtime = 1d
EOF
    apt-get install -y -q whois   # for action_mw (whois in the ban mail)
    systemctl enable --now fail2ban
    systemctl restart fail2ban
    sleep 2
    fail2ban-client status sshd >/dev/null || die "fail2ban sshd jail is not running."
    log "Phase 6 done."
}

# ======================= PHASE 7: LOGGING + AUDITD ===========================
phase7() {
    require_root
    log "Phase 7: journald persistent, auditd, logwatch, debsums"
    install -d /etc/systemd/journald.conf.d
    cat > /etc/systemd/journald.conf.d/persist.conf <<'EOF'
[Journal]
Storage=persistent
SystemMaxUse=1G
MaxRetentionSec=90day
EOF
    systemctl restart systemd-journald

    apt-get install -y -q auditd audispd-plugins

    # Rev.5 (OPEN FIX #2): watch target paths may only exist in phase 8/9/12 -
    # create them up front, otherwise 'augenrules --load' aborts on non-existent paths:
    install -d -m 700 /etc/wireguard
    install -d -m 755 /etc/docker
    install -d /srv/nextcloud && install -d -m 750 /srv/nextcloud/secrets
    [[ -f /srv/nextcloud/docker-compose.yml ]] || touch /srv/nextcloud/docker-compose.yml
    install -d -m 700 /var/log/faillock
    [[ -f /var/log/sudo.log ]]        || install -m 600 /dev/null /var/log/sudo.log
    [[ -f /etc/security/opasswd ]]    || install -m 600 /dev/null /etc/security/opasswd

    # Rev.5 (B3): auditd availability-friendly - on a full/faulty log, rotate
    # or mail/syslog instead of halting the system (avoid SUSPEND/HALT):
    if [[ -f /etc/audit/auditd.conf ]]; then
        sed -i -E 's/^space_left_action.*/space_left_action = EMAIL/;s/^admin_space_left_action.*/admin_space_left_action = EMAIL/;s/^disk_full_action.*/disk_full_action = SYSLOG/;s/^disk_error_action.*/disk_error_action = SYSLOG/' /etc/audit/auditd.conf
        grep -q '^action_mail_acct' /etc/audit/auditd.conf || echo 'action_mail_acct = root' >> /etc/audit/auditd.conf
    fi

    cat > /etc/audit/rules.d/hardening.rules <<'EOF'
-w /etc/ssh/sshd_config -p wa -k sshd_config
-w /etc/ssh/sshd_config.d/ -p wa -k sshd_config
-w /etc/passwd -p wa -k passwd_changes
-w /etc/shadow -p wa -k shadow_changes
-w /etc/group  -p wa -k group_changes
-w /etc/sudoers -p wa -k sudoers
-w /etc/sudoers.d/ -p wa -k sudoers
-w /etc/ufw/ -p wa -k firewall
-w /etc/fail2ban/ -p wa -k fail2ban
-w /etc/wireguard/ -p wa -k wireguard
-w /etc/crontab -p wa -k cron
-w /etc/cron.d/ -p wa -k cron
# TARGETED /srv watches instead of recursive -w /srv/ (Review H5): otherwise the
# 1TB NC blob write load floods the journal and rotates real security events away.
-w /srv/nextcloud/docker-compose.yml -p wa -k nc_config
-w /srv/nextcloud/secrets/ -p wa -k nc_secrets
-w /usr/local/bin/ -p wa -k localbin
-w /etc/docker/ -p wa -k docker_config
EOF
    # Rev.5 (B3): CIS Level 2 rule set (verified on the test server, ~47 rules total):
    cat > /etc/audit/rules.d/cis-l2.rules <<'EOF'
-a always,exit -F arch=b64 -S adjtimex,settimeofday,clock_settime -k time-change
-w /etc/localtime -p wa -k time-change
-a always,exit -F arch=b64 -S sethostname,setdomainname -k system-locale
-w /etc/hosts -p wa -k system-locale
-w /etc/netplan/ -p wa -k system-locale
-w /etc/apparmor/ -p wa -k MAC-policy
-w /etc/apparmor.d/ -p wa -k MAC-policy
-w /var/log/faillock/ -p wa -k logins
-w /var/log/lastlog -p wa -k logins
-w /var/run/utmp -p wa -k session
-w /var/log/wtmp -p wa -k logins
-w /var/log/btmp -p wa -k logins
-w /etc/gshadow -p wa -k identity
-w /etc/nsswitch.conf -p wa -k identity
-w /etc/security/opasswd -p wa -k identity
-w /etc/pam.conf -p wa -k identity
-w /etc/pam.d/ -p wa -k identity
-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat,chown,fchown,fchownat,lchown,setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=1000 -F auid!=unset -k perm_mod
-a always,exit -F arch=b64 -S creat,open,openat,truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=unset -k access
-a always,exit -F arch=b64 -S creat,open,openat,truncate,ftruncate -F exit=-EPERM  -F auid>=1000 -F auid!=unset -k access
-a always,exit -F arch=b64 -S rename,renameat,unlink,unlinkat -F auid>=1000 -F auid!=unset -k delete
-a always,exit -F arch=b64 -S init_module,finit_module,delete_module,create_module,query_module -k modules
-a always,exit -F path=/usr/bin/kmod -F perm=x -F auid>=1000 -F auid!=unset -k modules
-a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=unset -k priv_cmd
-a always,exit -F path=/usr/sbin/usermod -F perm=x -F auid>=1000 -F auid!=unset -k usermod
-a always,exit -F path=/usr/bin/chacl -F perm=x -F auid>=1000 -F auid!=unset -k perm_chng
-a always,exit -F path=/usr/bin/setfacl -F perm=x -F auid>=1000 -F auid!=unset -k perm_chng
-a always,exit -F path=/usr/bin/chcon -F perm=x -F auid>=1000 -F auid!=unset -k perm_chng
-w /var/log/sudo.log -p wa -k sudo_log_file
-a always,exit -F arch=b64 -C euid!=uid -F auid!=unset -S execve -k user_emulation
-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=unset -k export
EOF
    chmod 600 /etc/audit/rules.d/*.rules
    augenrules --load
    systemctl enable --now auditd

    apt-get install -y -q logwatch debsums
    install -d /etc/logwatch/conf
    cat > /etc/logwatch/conf/logwatch.conf <<EOF
Output = mail
MailTo = $ADMIN_MAIL
Detail = Med
Range = yesterday
EOF
    # Weekly package-integrity check (Review: debsums was installed but never ran):
    cat > /etc/cron.weekly/debsums-check <<'EOF'
#!/bin/sh
debsums -s 2>&1 | mail -E -s "debsums: changed package files on $(hostname)" root
EOF
    chmod 700 /etc/cron.weekly/debsums-check
    log "Phase 7 done. auditd rules active: $(auditctl -l | wc -l)"
}

# ============================ PHASE 8: WIREGUARD =============================
phase8() {
    require_root
    log "Phase 8: WireGuard"
    apt-get install -y -q wireguard
    install -d -m 700 "$SECRETS_DIR"
    # umask only in a subshell - otherwise it leaks into later phases (Review K3):
    # Server key AND preshared key (Review M7: a second symmetric layer, ~free).
    (
        umask 077
        # N5: only regenerate if BOTH key files are missing, else regenerate .pub consistently
        if [[ ! -f /etc/wireguard/server.key ]]; then
            wg genkey | tee /etc/wireguard/server.key | wg pubkey > /etc/wireguard/server.pub
        elif [[ ! -f /etc/wireguard/server.pub ]]; then
            wg pubkey < /etc/wireguard/server.key > /etc/wireguard/server.pub
        fi
        [[ -f /etc/wireguard/wg0.psk ]] || wg genpsk > /etc/wireguard/wg0.psk
    )
    local SRV_KEY SRV_PUB WG_PSK
    SRV_KEY="$(cat /etc/wireguard/server.key)"
    SRV_PUB="$(cat /etc/wireguard/server.pub)"
    WG_PSK="$(cat /etc/wireguard/wg0.psk)"

    if [[ -z "$WG_CLIENT_PUBKEY" ]]; then
        warn "WG_CLIENT_PUBKEY empty - wg0.conf is created without a peer; add the peer later."
    fi
    install -m 600 /dev/null /etc/wireguard/wg0.conf   # N1: 600 BEFORE writing the private key
    cat > /etc/wireguard/wg0.conf <<EOF
[Interface]
Address = ${WG_NET}.1/24
ListenPort = $WG_PORT
PrivateKey = $SRV_KEY
EOF
    if [[ -n "$WG_CLIENT_PUBKEY" ]]; then
        cat >> /etc/wireguard/wg0.conf <<EOF

[Peer]
PublicKey    = $WG_CLIENT_PUBKEY
PresharedKey = $WG_PSK
AllowedIPs   = ${WG_NET}.2/32
EOF
    fi
    chmod 600 /etc/wireguard/wg0.conf /etc/wireguard/server.key /etc/wireguard/wg0.psk

    ufw allow "${WG_PORT}/udp" comment 'WireGuard'
    # Re-run: reload the config if the interface is already up, otherwise a
    # changed peer/PSK only takes effect after a manual restart (Review N4).
    if systemctl is-active --quiet wg-quick@wg0; then
        systemctl restart wg-quick@wg0
    else
        systemctl enable --now wg-quick@wg0
    fi

    cat <<EOF | tee "$SECRETS_DIR/wireguard-client.conf.example"
# --- Client config for the LOCAL machine (~/wg-client.conf) ---
[Interface]
Address = ${WG_NET}.2/24
PrivateKey = <PRIVATE KEY OF THE LOCAL MACHINE>

[Peer]
PublicKey    = $SRV_PUB
PresharedKey = $WG_PSK
Endpoint     = <SERVER-IP>:$WG_PORT
AllowedIPs   = ${WG_NET}.0/24
PersistentKeepalive = 25
EOF
    log "Phase 8 done. Client template: $SECRETS_DIR/wireguard-client.conf.example"
    log "OPTIONAL LATER (after 2-4 weeks of stable operation, manual):"
    log "  ufw delete limit ${SSH_PORT}/tcp && ufw allow in on wg0 to any port ${SSH_PORT} proto tcp"
}

# =================== PHASE 9: DOCKER + CADDY + NEXTCLOUD =====================
phase9() {
    require_root
    log "Phase 9: Docker, Caddy (native), Nextcloud stack"
    [[ -n "$NC_IMAGE_TAG" ]] || die "NC_IMAGE_TAG empty - look up the current version on hub.docker.com/_/nextcloud (e.g. 31)."

    # --- Docker from the official repo ---
    if ! command -v docker &>/dev/null; then
        install -m 0755 -d /etc/apt/keyrings
        curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --yes --dearmor -o /etc/apt/keyrings/docker.gpg
        chmod a+r /etc/apt/keyrings/docker.gpg
        echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" \
            > /etc/apt/sources.list.d/docker.list
        apt-get update -q
        apt-get install -y -q docker-ce docker-ce-cli containerd.io docker-compose-plugin
    fi
    # Log rotation + default hardening: no-new-privileges as the daemon default (Review M2),
    # userland-proxy off (smaller attack surface, fewer open sockets).
    # "ipv6": false = Docker default, pinned EXPLICITLY here (Council-Fix 5):
    # The DOCKER-USER guard below is mirrored for v6 too, but Docker IPv6
    # stays disabled as well - whoever enables it must touch BOTH places.
    cat > /etc/docker/daemon.json <<'EOF'
{
  "log-driver": "json-file",
  "log-opts": { "max-size": "10m", "max-file": "3" },
  "live-restore": true,
  "no-new-privileges": true,
  "userland-proxy": false,
  "ipv6": false
}
EOF
    # Council-Fix 3b: Docker may only start once the HDD is mounted - otherwise
    # NC starts against an EMPTY data dir on the NVMe (nofail in fstab
    # makes the boot robust, this drop-in makes it correct):
    install -d /etc/systemd/system/docker.service.d
    cat > /etc/systemd/system/docker.service.d/wait-hdd.conf <<EOF
[Unit]
RequiresMountsFor=$HDD_MOUNT
EOF
    systemctl daemon-reload
    systemctl restart docker

    # === CRITICAL (Review K1): Docker bypasses ufw entirely ===
    # Docker writes its own iptables rules into the FORWARD/DOCKER chains that run BEFORE
    # all ufw hooks. 'ufw deny incoming' does NOT protect published container ports.
    # Without this block, Portainer 9443 (phase 11) would be open despite ufw.
    # Fix: in the DOCKER-USER chain (which Docker honours) drop all NEW inbound from the
    # WAN interface. Loopback (NC 127.0.0.1), wg0 (tunnel) and container-to-
    # container traffic (Docker bridges) stay untouched.
    local wan_if="${WAN_IF:-$(ip route show default 2>/dev/null | awk '/default/{print $5; exit}')}"
    [[ -n "$wan_if" ]] || die "WAN interface not detected - set WAN_IF in install.conf."
    log "Docker firewall: new inbound on '$wan_if' to containers is dropped."
    if ! grep -q 'DOCKER-USER-HARDENING' /etc/ufw/after.rules; then
        cat >> /etc/ufw/after.rules <<EOF

# BEGIN DOCKER-USER-HARDENING (Review K1) - do NOT remove
*filter
:DOCKER-USER - [0:0]
-A DOCKER-USER -i wg0 -j RETURN
-A DOCKER-USER -i lo -j RETURN
-A DOCKER-USER -i ${wan_if} -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
-A DOCKER-USER -i ${wan_if} -j DROP
-A DOCKER-USER -j RETURN
COMMIT
# END DOCKER-USER-HARDENING
EOF
    fi
    # Council-Fix 5: mirror the same guard into after6.rules. As long as Docker IPv6
    # is off (daemon.json above), the v6 DOCKER-USER chain does not exist in
    # Docker's ruleset - this block creates it and is then the safety net,
    # in case Docker IPv6 is ever (accidentally) enabled. The server has a /64!
    if ! grep -q 'DOCKER-USER-HARDENING' /etc/ufw/after6.rules; then
        cat >> /etc/ufw/after6.rules <<EOF

# BEGIN DOCKER-USER-HARDENING v6 (Council-Fix 5) - do NOT remove
*filter
:DOCKER-USER - [0:0]
-A DOCKER-USER -i wg0 -j RETURN
-A DOCKER-USER -i lo -j RETURN
-A DOCKER-USER -i ${wan_if} -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
-A DOCKER-USER -i ${wan_if} -j DROP
-A DOCKER-USER -j RETURN
COMMIT
# END DOCKER-USER-HARDENING v6
EOF
    fi
    # Do NOT swallow after.rules load errors (final review): broken rules = no
    # firewall ruleset on the next boot.
    ufw reload || die "ufw reload failed - check /etc/ufw/after.rules + after6.rules (DOCKER-USER block syntax)."
    # If Docker already created the chain at runtime: activate immediately.
    if iptables -L DOCKER-USER -n &>/dev/null; then
        iptables -C DOCKER-USER -i "$wan_if" -j DROP 2>/dev/null || {
            iptables -I DOCKER-USER -i "$wan_if" -j DROP
            iptables -I DOCKER-USER -i "$wan_if" -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
            iptables -I DOCKER-USER -i lo -j RETURN
            iptables -I DOCKER-USER -i wg0 -j RETURN
        }
    fi

    # --- Caddy native, official repo instructions WITHOUT sed rewriting (Review K2) ---
    if ! command -v caddy &>/dev/null; then
        curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' \
            | gpg --yes --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
        curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' \
            > /etc/apt/sources.list.d/caddy-stable.list
        apt-get update -q && apt-get install -y -q caddy
    fi
    backup_file /etc/caddy/Caddyfile
    cat > /etc/caddy/Caddyfile <<EOF
$NC_DOMAIN {
    reverse_proxy 127.0.0.1:8080
    header Strict-Transport-Security "max-age=15552000; includeSubDomains"
    redir /.well-known/carddav /remote.php/dav/ 301
    redir /.well-known/caldav  /remote.php/dav/ 301
}
EOF
    chmod 644 /etc/caddy/Caddyfile              # must be readable by user 'caddy' (Review K3)
    caddy validate --config /etc/caddy/Caddyfile || die "Caddyfile invalid."

    # === Council-Fix 8: DNS gate BEFORE Caddy start ===
    # Caddy starts ACME attempts for $NC_DOMAIN IMMEDIATELY. If the A/AAAA record
    # still points elsewhere, every failed attempt burns the Let's Encrypt rate limit
    # (5 failures/account/domain/hour).
    local pub4 dns4 dns6
    pub4="$(ip -4 -o addr show dev "$wan_if" scope global | awk '{print $4}' | cut -d/ -f1 | head -1)"
    dns4="$(getent ahostsv4 "$NC_DOMAIN" 2>/dev/null | awk '{print $1; exit}')"
    [[ -n "$dns4" ]] || die "DNS gate: $NC_DOMAIN does not resolve. Set the A record to $pub4, wait for the TTL, then run phase9 again."
    [[ "$dns4" == "$pub4" ]] || die "DNS gate: $NC_DOMAIN -> $dns4, but the server IP is $pub4. Fix the A record, then run phase9 again."
    # AAAA: only check if a real v6 entry exists (::ffff: = mapped v4, ignore).
    # An AAAA that does NOT point to this server also makes ACME fail:
    dns6="$(getent ahostsv6 "$NC_DOMAIN" 2>/dev/null | awk '$1 !~ /^::ffff:/ {print $1; exit}')"
    if [[ -n "$dns6" ]]; then
        ip -6 -o addr show scope global | grep -qF "$dns6" \
            || die "DNS gate: AAAA($NC_DOMAIN)=$dns6 does not belong to this server. Fix or delete the AAAA, then run phase9 again."
    fi
    log "DNS gate passed: $NC_DOMAIN -> $dns4${dns6:+ / $dns6}"

    # Rev.5 (B6): lock Caddy into a systemd sandbox (markedly lowers the Lynis exposure).
    # CAP_NET_BIND_SERVICE for 80/443; ReadWritePaths only the cert/state directory.
    install -d /etc/systemd/system/caddy.service.d
    cat > /etc/systemd/system/caddy.service.d/hardening.conf <<'EOF'
[Service]
ProtectSystem=strict
ReadWritePaths=/var/lib/caddy
ProtectHome=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
ProtectClock=true
ProtectHostname=true
RestrictNamespaces=true
RestrictRealtime=true
RestrictSUIDSGID=true
LockPersonality=true
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
SystemCallArchitectures=native
SystemCallFilter=@system-service
EOF
    systemctl daemon-reload

    systemctl enable --now caddy
    systemctl reload caddy

    # --- 4TB HDD: NC data dir + backup repos (NEXT TO the NC dir) ---
    # Set up the HDD once beforehand (check the device name with 'lsblk'!). Use UUID
    # instead of /dev/sdb1 - device names are not stable on a VPS (Review N2).
    # Council-Fix 3a: 'nofail,x-systemd.device-timeout=30' is REQUIRED - without it
    # a missing/late HDD drops the server into emergency mode WITHOUT SSH
    # (recoverable only via the VNC console). The docker drop-in (above) prevents
    # NC from starting against an empty directory:
    #   parted /dev/sdb mklabel gpt && parted /dev/sdb mkpart primary ext4 0% 100%
    #   mkfs.ext4 /dev/sdb1
    #   tune2fs -m 5 /dev/sdb1   # explicit 5% root-reserve (re-asserted below too, idempotent)
    #   UUID=$(blkid -s UUID -o value /dev/sdb1)
    #   echo "UUID=$UUID $HDD_MOUNT ext4 defaults,nosuid,nodev,nofail,x-systemd.device-timeout=30 0 2" >> /etc/fstab
    #   systemctl daemon-reload && mount "$HDD_MOUNT"
    install -d "$HDD_MOUNT"
    if ! mountpoint -q "$HDD_MOUNT"; then
        warn "HDD is NOT mounted at $HDD_MOUNT - NC data would land on the NVMe!"
        warn "Set up the HDD first (see the comment in phase 9), then start the stack."
    fi

    # --- Space headroom on $HDD_MOUNT (Handover: NC uploads + Borg repos share this volume) ---
    # Percentage-based, so this is identical whether $HDD_MOUNT is currently the transitional
    # second 500 GB NVMe or, from month 5, the 4 TB HDD - no branch, no size constant.
    # ext4 already reserves blocks for root by default; re-assert 5% explicitly so a normal
    # writer (the NC container's mapped uid, Borg over SSH) hits ENOSPC at 95% instead of
    # silently running the volume bit-for-bit full.
    if mountpoint -q "$HDD_MOUNT"; then
        hdd_dev="$(findmnt -no SOURCE "$HDD_MOUNT" 2>/dev/null || true)"
        hdd_fstype="$(findmnt -no FSTYPE "$HDD_MOUNT" 2>/dev/null || true)"
        if [[ -n "$hdd_dev" && "$hdd_fstype" == "ext4" ]]; then
            tune2fs -m 5 "$hdd_dev" || warn "tune2fs -m 5 on $hdd_dev failed - check manually."
        else
            warn "$HDD_MOUNT is not ext4 (fstype: ${hdd_fstype:-unknown}) - reserved-blocks headroom NOT applied, check manually."
        fi
    else
        warn "$HDD_MOUNT not mounted yet - reserved-blocks headroom skipped, re-run phase9 after mounting the volume."
    fi

    # --- Early-warning disk-space alert (before the 5% reserve hard-stops writes) ---
    # Two thresholds, mailed via the existing msmtp setup; a state file avoids re-mailing
    # on every timer tick once a threshold is already reported. Watches both $HDD_MOUNT
    # (NC data + Borg repos) and / (system, DB, container images) - same script either way.
    cat > /usr/local/bin/disk-space-alert.sh <<'DSEOF'
#!/bin/bash
# Warn at 85%, critical at 95% (matches the ext4 5% root-reserve) - one mail per
# newly-crossed threshold, not one per timer run. Usage: disk-space-alert.sh <mount> [<mount> ...]
set -euo pipefail
WARN=85
CRIT=95
STATE_DIR=/var/lib/disk-space-alert
install -d "$STATE_DIR"

for mnt in "$@"; do
    [[ -d "$mnt" ]] || continue
    state_file="$STATE_DIR/$(systemd-escape -p "$mnt").state"
    use=$(df -P "$mnt" 2>/dev/null | awk 'NR==2{gsub("%","",$5); print $5}')
    [[ -n "$use" ]] || continue
    last=0
    [[ -f "$state_file" ]] && last=$(cat "$state_file")

    level=0
    if   (( use >= CRIT )); then level=2
    elif (( use >= WARN )); then level=1
    fi

    if (( level > 0 && level != last )); then
        label="warning (>= ${WARN}%)"
        (( level == 2 )) && label="CRITICAL (>= ${CRIT}%)"
        { echo "Mountpoint $mnt is at ${use}% - $label."; echo; df -h "$mnt"; } \
            | mail -s "Disk space $label: $mnt at ${use}% on $(hostname)" root 2>/dev/null || true
    fi
    echo "$level" > "$state_file"
done
DSEOF
    chmod 750 /usr/local/bin/disk-space-alert.sh

    cat > /etc/systemd/system/disk-space-alert.service <<EOF
[Unit]
Description=Disk space threshold alert (${HDD_MOUNT} and /)

[Service]
Type=oneshot
ExecStart=/usr/local/bin/disk-space-alert.sh ${HDD_MOUNT} /
EOF
    cat > /etc/systemd/system/disk-space-alert.timer <<'EOF'
[Unit]
Description=Run disk-space-alert twice daily

[Timer]
OnCalendar=*-*-* 06,18:00:00
Persistent=true

[Install]
WantedBy=timers.target
EOF
    systemctl daemon-reload
    systemctl enable --now disk-space-alert.timer
    install -d -m 750 "$NCDATA_DIR"   # 750 instead of default 755 (Review M4): no world-read
    chown 33:33 "$NCDATA_DIR"         # www-data in the NC container

    # --- Nextcloud stack ---
    install -d -m 750 /srv/nextcloud/secrets
    gen_secret nc-db-root >/dev/null; gen_secret nc-db-pass >/dev/null; gen_secret nc-admin-pass >/dev/null
    install -m 600 "$SECRETS_DIR/nc-db-root"    /srv/nextcloud/secrets/db_root.txt
    install -m 600 "$SECRETS_DIR/nc-db-pass"    /srv/nextcloud/secrets/db_pass.txt
    install -m 600 "$SECRETS_DIR/nc-admin-pass" /srv/nextcloud/secrets/nc_admin.txt

    cat > /srv/nextcloud/docker-compose.yml <<EOF
services:
  db:
    image: mariadb:11
    restart: unless-stopped
    mem_limit: 2g                                # Rev.5 (B5): DoS containment, sized for a 16 GB prod box
    pids_limit: 256
    command: --transaction-isolation=READ-COMMITTED
    security_opt: [ "no-new-privileges:true" ]   # Review M2
    volumes:
      - ./db:/var/lib/mysql
    environment:
      MARIADB_ROOT_PASSWORD_FILE: /run/secrets/db_root
      MARIADB_DATABASE: nextcloud
      MARIADB_USER: nextcloud
      MARIADB_PASSWORD_FILE: /run/secrets/db_pass
    secrets: [ db_root, db_pass ]
    healthcheck:                     # the NC installer may only run against a ready DB (Review M4)
      test: ["CMD", "healthcheck.sh", "--connect", "--innodb_initialized"]
      interval: 10s
      timeout: 5s
      retries: 12

  redis:
    image: redis:7-alpine
    restart: unless-stopped
    mem_limit: 256m                              # Rev.5 (B5)
    pids_limit: 64
    security_opt: [ "no-new-privileges:true" ]   # Review M2
    # Council-Fix 1: cap_drop [ALL] alone prevents startup - the official
    # entrypoint runs as root, chowns the datadir and switches via gosu to
    # 'redis'. Minimum needed: CHOWN, SETUID, SETGID (no volume mounted,
    # hence no DAC_OVERRIDE). The set is theory-based -> test-server MANDATORY.
    cap_drop: [ ALL ]
    cap_add: [ CHOWN, SETUID, SETGID ]

  app:
    image: nextcloud:${NC_IMAGE_TAG}
    restart: unless-stopped
    mem_limit: 6g                                # Rev.5 (B5)
    pids_limit: 512
    security_opt: [ "no-new-privileges:true" ]   # Review M2
    ports:
      - "127.0.0.1:8080:80"
    depends_on:
      db: { condition: service_healthy }
      redis: { condition: service_started }
    volumes:
      - ./html:/var/www/html
      - ${NCDATA_DIR}:/var/www/html/data   # data dir = HDD, separate from the NC dir
    environment:
      MYSQL_HOST: db
      MYSQL_DATABASE: nextcloud
      MYSQL_USER: nextcloud
      MYSQL_PASSWORD_FILE: /run/secrets/db_pass
      REDIS_HOST: redis
      # The admin account is created UNATTENDED at first start - prevents
      # a stranger from hijacking the open setup (Review H5, certificate transparency!):
      NEXTCLOUD_ADMIN_USER: $ADMIN_USER
      NEXTCLOUD_ADMIN_PASSWORD_FILE: /run/secrets/nc_admin
      NEXTCLOUD_TRUSTED_DOMAINS: $NC_DOMAIN
      TRUSTED_PROXIES: 172.16.0.0/12
      OVERWRITEPROTOCOL: https
      OVERWRITEHOST: $NC_DOMAIN
      OVERWRITECLIURL: https://$NC_DOMAIN
    secrets: [ db_pass, nc_admin ]

  cron:
    image: nextcloud:${NC_IMAGE_TAG}
    restart: unless-stopped
    mem_limit: 1g                                # Rev.5 (B5)
    pids_limit: 256
    security_opt: [ "no-new-privileges:true" ]   # Review M2
    entrypoint: /cron.sh
    depends_on:
      db: { condition: service_healthy }
      redis: { condition: service_started }
    volumes:
      - ./html:/var/www/html
      - ${NCDATA_DIR}:/var/www/html/data

secrets:
  db_root:  { file: ./secrets/db_root.txt }
  db_pass:  { file: ./secrets/db_pass.txt }
  nc_admin: { file: ./secrets/nc_admin.txt }
EOF

    # --- fail2ban jail for Nextcloud (Review M5 - NC is the only public service) ---
    if command -v fail2ban-client &>/dev/null; then
        # Rev.5 (B5): official NC 2FA regex, verified against real NC 33 log lines
        # (fail2ban-regex: 2 matched, 2026-07-19). _groupsre allows arbitrary JSON fields
        # between remoteAddr and message - more robust than the earlier ".*" approach:
        cat > /etc/fail2ban/filter.d/nextcloud.conf <<'EOF'
[Definition]
_groupsre = (?:(?:,?\s*"\w+":(?:"[^"]+"|\w+))*)
failregex = ^\{%(_groupsre)s,?\s*"remoteAddr":"<HOST>"%(_groupsre)s,?\s*"message":"Login failed:
            ^\{%(_groupsre)s,?\s*"remoteAddr":"<HOST>"%(_groupsre)s,?\s*"message":"Two-factor challenge failed:
            ^\{%(_groupsre)s,?\s*"remoteAddr":"<HOST>"%(_groupsre)s,?\s*"message":"Trusted domain error.
datepattern = ,?\s*"time"\s*:\s*"%%Y-%%m-%%d[T ]%%H:%%M:%%S(%%z)?"
EOF
        cat > /etc/fail2ban/jail.d/nextcloud.local <<EOF
[nextcloud]
enabled  = true
backend  = auto
port     = 80,443
filter   = nextcloud
logpath  = ${NCDATA_DIR}/nextcloud.log
maxretry = 3
EOF
        # Create the log file UP FRONT (Review H2 logic): if missing, fail2ban aborts
        # the whole jail on the next (reboot) start - even the sshd jail would be gone.
        # uid/gid 33 = www-data in the container, which writes there later.
        [[ -f "${NCDATA_DIR}/nextcloud.log" ]] || install -o 33 -g 33 -m 640 /dev/null "${NCDATA_DIR}/nextcloud.log"
        systemctl restart fail2ban
    fi

    # Monthly reminder: image tags are pinned on purpose (no :latest), so
    # a human must trigger NC/container updates (Review M1). Cron mails a reminder.
    cat > /etc/cron.monthly/container-update-reminder <<'EOF'
#!/bin/sh
echo "Check container updates: NC tag on hub.docker.com/_/nextcloud, Portainer image, then per stack 'docker compose pull && up -d'. Then occ upgrade if needed." \
  | mail -s "Reminder: container/app updates on $(hostname)" root 2>/dev/null || true
EOF
    chmod 700 /etc/cron.monthly/container-update-reminder

    # Council-Fix 6: NC 2FA is ENFORCED, not just recommended. Since the stack is
    # deliberately not started here, a helper does it, run ONCE after the first
    # start (installs the TOTP app + turns enforcement on):
    cat > /usr/local/bin/nc-post-setup.sh <<'EOF'
#!/bin/bash
# Nextcloud post-hardening - run ONCE, as soon as the stack is up and
# https://<domain> is reachable:  /usr/local/bin/nc-post-setup.sh
set -euo pipefail
C="docker compose -f /srv/nextcloud/docker-compose.yml"
$C ps -q app | grep -q . || { echo "NC stack not running - first: cd /srv/nextcloud && docker compose up -d"; exit 1; }
OCC="$C exec -T -u www-data app php occ"
$OCC app:install twofactor_totp 2>/dev/null || $OCC app:enable twofactor_totp
$OCC twofactorauth:enforce --on
$OCC twofactorauth:enforce
echo "2FA is now ENFORCED - the next login of every account will require TOTP setup."
EOF
    chmod 700 /usr/local/bin/nc-post-setup.sh

    log "Compose file: /srv/nextcloud/docker-compose.yml"
    log "NC admin: user '$ADMIN_USER', password in $SECRETS_DIR/nc-admin-pass"
    warn "Stack NOT started automatically. Start:  cd /srv/nextcloud && docker compose up -d"
    warn "REQUIRED right after:  /usr/local/bin/nc-post-setup.sh   (enforces TOTP 2FA, Council-Fix 6)."
    warn "REQUIRED after the first failed login (Council-Fix 8): test failregex against REAL log lines:"
    warn "    fail2ban-regex ${NCDATA_DIR}/nextcloud.log /etc/fail2ban/filter.d/nextcloud.conf"
    warn "Then: app passwords for clients, occ fine-tuning (see the install guide, phase 9)."
    warn "NC UPDATES (Rev.5/W): ONLY via image tag - bump NC_IMAGE_TAG, then in /srv/nextcloud:"
    warn "    docker compose pull && docker compose up -d && docker compose exec -u www-data app php occ upgrade"
    warn "NEVER use the update button in the NC admin backend (writes to the container FS, lost on recreate / collides with the image)."
}

# =================== PHASE 10: BORG BACKUP ON THE SERVER HDD =================
phase10() {
    require_root
    log "Phase 10: Borg repos on the server HDD ($BACKUP_DIR)"
    apt-get install -y -q borgbackup
    mountpoint -q "$HDD_MOUNT" || die "HDD not mounted at $HDD_MOUNT (setup: see the comment in phase 9)."

    # CRITICAL fix (Review K1/H3): 710 root:$ADMIN_USER - the admin user may TRAVERSE (x), not list (r).
    # 700 root:root locked the admin user out -> trigger + repo-local were dead.
    install -d -m 710 -o root -g "$ADMIN_USER" "$BACKUP_DIR"
    gen_secret borg-passphrase >/dev/null
    install -m 600 "$SECRETS_DIR/borg-passphrase" /root/.borg-passphrase
    warn "BORG PASSPHRASE ($SECRETS_DIR/borg-passphrase) save it externally NOW (password manager + paper)!"

    # Repo 1: the server backs itself up (config, DB dump, /etc, /home):
    if [[ ! -d "$BACKUP_DIR/repo-server" ]]; then
        BORG_PASSCOMMAND='cat /root/.borg-passphrase' \
            borg init --encryption=repokey-blake2 "$BACKUP_DIR/repo-server"
    fi
    # Repo 2: the LOCAL machine backs up here (init from the local machine, command at the end):
    install -d -m 700 -o "$ADMIN_USER" -g "$ADMIN_USER" "$BACKUP_DIR/repo-local"
    # Trigger dir: after its push the local machine triggers the server backup (event- not time-driven):
    install -d -m 770 -o root -g "$ADMIN_USER" "$BACKUP_DIR/trigger"

    # --- Backup key isolation (Review H4): the local machine does NOT use the admin key for backups ---
    # Two purpose-bound forced-command keys, whose authorized_keys lines are printed below.
    # A stolen backup key can NEITHER open a shell NOR delete/encrypt repo-local
    # (append-only), and the trigger key can ONLY create the trigger file.
    log ""
    log "=== Run ONCE on the local machine and add the 2 public keys here ==="
    log "  ssh-keygen -t ed25519 -a 64 -f ~/.ssh/vps_borg      -C 'mac-borg-append-only'"
    log "  ssh-keygen -t ed25519 -a 64 -f ~/.ssh/vps_trigger   -C 'mac-borg-trigger'"
    log "Then on the SERVER add to /home/${ADMIN_USER}/.ssh/authorized_keys (one line each):"
    log "  command=\"borg serve --append-only --restrict-to-path ${BACKUP_DIR}/repo-local\",restrict,no-pty,no-agent-forwarding,no-port-forwarding,no-X11-forwarding <INHALT vps_borg.pub>"
    log "  command=\"touch ${BACKUP_DIR}/trigger/.run-backup\",restrict,no-pty,no-agent-forwarding,no-port-forwarding,no-X11-forwarding <INHALT vps_trigger.pub>"
    log "The backup chain then uses:  borg ... -e 'ssh -i ~/.ssh/vps_borg'  &&  ssh -i ~/.ssh/vps_trigger vps"
    log "Prune on repo-local runs ONLY manually from the local machine (the append-only key cannot prune) - use the admin key or a third full-access key."
    log "========================================================================="

    cat > /usr/local/bin/backup-server.sh <<EOF
#!/bin/bash
# Server backup -> HDD repo. Event-triggered (path unit) or weekly fallback.
set -euo pipefail
rm -f "$BACKUP_DIR/trigger/.run-backup"
export BORG_PASSCOMMAND='cat /root/.borg-passphrase'
REPO="$BACKUP_DIR/repo-server"
COMPOSE="docker compose -f /srv/nextcloud/docker-compose.yml"

mkdir -p /var/backups/nc
NC_RUNNING=0
if \$COMPOSE ps -q app 2>/dev/null | grep -q .; then
    NC_RUNNING=1
    # Consistency files<->DB: put NC briefly into maintenance (Review M3); the trap ensures it turns off again
    trap '\$COMPOSE exec -T -u www-data app php occ maintenance:mode --off || true' EXIT
    \$COMPOSE exec -T -u www-data app php occ maintenance:mode --on
    # DB dump: password via env, not argv (Review M2)
    \$COMPOSE exec -T db sh -c 'MYSQL_PWD="\$(cat /run/secrets/db_root)" exec mariadb-dump --single-transaction --all-databases -uroot' \\
        > /var/backups/nc/db-dump.sql
else
    # NC stack is down: NO fresh dump possible -> do not silently back up a stale one (Review M1 logic)
    if [[ -f /var/backups/nc/db-dump.sql ]]; then
        logger -t borg-backup "WARN: NC stack down - db-dump.sql is stale (as of \$(date -r /var/backups/nc/db-dump.sql '+%Y-%m-%d %H:%M'))"
        echo "WARN: NC stack was down during backup - the DB dump in the archive is NOT from the same day." >&2
    fi
fi

# ONLY config + DB dump + system. NOT the HDD itself (NC blobs are a copy of the
# local data; the repos do not back up themselves; decision 2026-07-08):
borg create --compression zstd,6 --stats \\
    --exclude '/srv/nextcloud/db' --exclude '$HDD_MOUNT' \\
    "\$REPO::{now:%Y-%m-%d_%H%M}" \\
    /srv /etc /var/backups /home /root/.ssh /var/log/journal

if [[ \$NC_RUNNING -eq 1 ]]; then
    \$COMPOSE exec -T -u www-data app php occ maintenance:mode --off
    trap - EXIT
fi

# Cleanup + integrity check (repo is local - prune may run here):
borg prune --keep-daily 7 --keep-weekly 4 --keep-monthly 6 "\$REPO"
borg check --repository-only "\$REPO"
EOF
    chmod 700 /usr/local/bin/backup-server.sh

    # Failures must NOT stay silent (Review H3) - mail on failure:
    # Failure notice: mail (if msmtp present) AND always to the journal + wall (Review N6),
    # so a silent backup death is noticed even without working SMTP.
    cat > /etc/systemd/system/backup-fail-mail.service <<'EOF'
[Unit]
Description=Alarm on a failed Borg backup
[Service]
Type=oneshot
ExecStart=/bin/sh -c 'MSG="BORG BACKUP FAILED on $(hostname) $(date)"; logger -t borg-backup "$MSG"; echo "$MSG" | wall 2>/dev/null; journalctl -u borg-backup.service -n 50 --no-pager | mail -s "$MSG" root 2>/dev/null || true'
EOF
    # StartLimit against trigger DoS (Review M3): max 2 runs per 30 min, else blocked.
    cat > /etc/systemd/system/borg-backup.service <<'EOF'
[Unit]
Description=Borg backup to the server HDD
OnFailure=backup-fail-mail.service
StartLimitIntervalSec=30min
StartLimitBurst=2
[Service]
Type=oneshot
ExecStart=/usr/local/bin/backup-server.sh
EOF
    # EVENT trigger instead of a clock (operator works at night - fixed times are pointless):
    # The local machine triggers after its push:  ssh vps "touch $BACKUP_DIR/trigger/.run-backup"
    cat > /etc/systemd/system/borg-backup.path <<EOF
[Unit]
Description=Trigger: Borg backup when the trigger file appears
[Path]
PathExists=$BACKUP_DIR/trigger/.run-backup
[Install]
WantedBy=multi-user.target
EOF
    # Fallback net: if no trigger comes for weeks, a backup still runs once a week:
    cat > /etc/systemd/system/borg-backup.timer <<'EOF'
[Unit]
Description=Borg backup fallback (weekly)
[Timer]
OnCalendar=weekly
RandomizedDelaySec=6h
Persistent=true
[Install]
WantedBy=timers.target
EOF
    systemctl daemon-reload
    systemctl enable --now borg-backup.path borg-backup.timer

    log "Initialise the repo for the LOCAL machine once (from the local machine):"
    log "  borg init --encryption=repokey-blake2 ssh://${ADMIN_USER}@<server-ip>:${SSH_PORT}${BACKUP_DIR}/repo-local"
    log "Backup chain afterwards:  borg create ... && ssh vps 'touch ${BACKUP_DIR}/trigger/.run-backup'"
    log "Phase 10 done. Do not forget the restore test (borg mount + spot check)!"
}

# ================== PHASE 11: ADMIN PANELS (WIREGUARD ONLY) ==================
phase11() {
    require_root
    log "Phase 11: Cockpit + Portainer CE (reachable via WireGuard only)"
    wg show wg0 &>/dev/null || die "WireGuard (phase8) must be running - panels are exposed ONLY over the tunnel."

    # Cockpit: socket-activated, uses practically nothing without an open session.
    apt-get install -y -q cockpit
    # M6: bind the socket ONLY to the WireGuard address - not 0.0.0.0. ufw is then
    # only the second line, not the only one. (The drop-in overrides the default listen.)
    install -d /etc/systemd/system/cockpit.socket.d
    cat > /etc/systemd/system/cockpit.socket.d/listen.conf <<EOF
[Socket]
ListenStream=
ListenStream=${WG_NET}.1:9090
FreeBind=true
EOF
    systemctl daemon-reload
    systemctl enable --now cockpit.socket
    systemctl restart cockpit.socket
    ufw allow in on wg0 to any port 9090 proto tcp comment 'Cockpit via WireGuard'

    # Portainer CE: Docker deploy + monitoring, no App Store, no proxy of its own.
    # Needs neither 80 nor 443, binds directly to the WG address. Deploy vorlagen only -
    # updates of deployed apps are run by hand, unlike a maintained app store.
    # Public isolation is primarily done by the DOCKER-USER rule (phase 9),
    # ufw + binding are defense-in-depth. The UI is never public.
    if command -v docker &>/dev/null; then
        if ! docker ps -a --format '{{.Names}}' | grep -qx portainer; then
            docker volume create portainer_data >/dev/null
            docker run -d --name portainer --restart=always \
                -p "${WG_NET}.1:${PORTAINER_PORT}:9443" \
                -v /var/run/docker.sock:/var/run/docker.sock \
                -v portainer_data:/data \
                portainer/portainer-ce:lts \
                || die "Portainer container failed to start - check 'docker logs portainer'."
        fi
        ufw allow in on wg0 to any port "$PORTAINER_PORT" proto tcp comment 'Portainer via WireGuard'
    else
        warn "Docker missing (phase9) - Portainer skipped."
    fi
    log "Phase 11 done. In the tunnel:  Cockpit https://${WG_NET}.1:9090  |  Portainer https://${WG_NET}.1:${PORTAINER_PORT}"
    warn "REQUIRED after 'all': check from OUTSIDE (a foreign network) that ${PORTAINER_PORT}/9090 are closed -"
    warn "    nmap -Pn <server-ipv4> -p ${PORTAINER_PORT},9090   UND   nmap -6 -Pn <server-ipv6> -p ${PORTAINER_PORT},9090"
    warn "(Council-Fix 5: scan v6 separately - a v4 scan does not see an IPv6 hole; ss does not see the iptables exposure.)"
}

# ============= PHASE 12: SERVICE CLEANUP + ubuntu USER + AIDE ================
# Run AFTER all other phases (the AIDE DB should reflect the final state).
phase12() {
    require_root
    log "Phase 12: VM service cleanup, ubuntu user, AIDE (Rev.5 / Batch B3/B4)"

    # Disable VM-specific services only on KVM (S.1.a). udisks2 stays (Cockpit storage!):
    if [[ "$(systemd-detect-virt 2>/dev/null)" == "kvm" ]]; then
        systemctl disable --now NetworkManager 2>/dev/null || true
        systemctl mask NetworkManager 2>/dev/null || true
        systemctl disable --now ModemManager wpa_supplicant multipathd 2>/dev/null || true
        # disable lvm2-monitor only if no LVM:
        lsblk -o FSTYPE 2>/dev/null | grep -qi lvm || systemctl disable --now lvm2-monitor 2>/dev/null || true
        log "KVM detected - unneeded VM services disabled (udisks2 kept)."
    else
        log "No KVM detected - VM service cleanup skipped."
    fi

    # Remove the cloud-init default account 'ubuntu' + its NOPASSWD sudoers (S.1.b):
    if [[ -f /etc/sudoers.d/90-cloud-init-users ]]; then
        cp -a /etc/sudoers.d/90-cloud-init-users "$SECRETS_DIR/90-cloud-init-users.removed" 2>/dev/null || true
        rm -f /etc/sudoers.d/90-cloud-init-users
        visudo -c >/dev/null 2>&1 || warn "sudoers check after cloud-init removal failed!"
    fi
    if id ubuntu &>/dev/null; then
        pkill -u ubuntu 2>/dev/null || true
        userdel -r ubuntu 2>/dev/null && log "ubuntu user removed." || warn "ubuntu user not removed - check manually."
    fi

    # Legacy packages (rsync included on purpose - operator decision 2026-07-19; if needed: apt install rsync):
    apt-get purge -y -q telnet inetutils-telnet ftp tnftp rsync 2>/dev/null || true
    dpkg -l 2>/dev/null | awk '/^rc/{print $2}' | xargs -r dpkg --purge >/dev/null 2>&1 || true
    apt-get autoremove --purge -y -q 2>/dev/null || true

    # === AIDE (file integrity) with container/data excludes (S.1.d) ===
    apt-get install -y -q aide aide-common
    install -d /etc/aide/aide.conf.d
    printf '!/var/lib/docker\n!/var/lib/containerd\n!%s\n!/srv/nextcloud/html\n!/srv/nextcloud/db\n!/var/lib/disk-space-alert\n!/proc\n!/sys\n!/run\n' \
        "$HDD_MOUNT" > /etc/aide/aide.conf.d/99_local_excludes
    cat > /etc/aide/aide.conf.d/99_local_audittools <<'EOF'
/usr/sbin/auditctl   p+i+n+u+g+s+b+acl+xattrs+sha512
/usr/sbin/auditd     p+i+n+u+g+s+b+acl+xattrs+sha512
/usr/sbin/ausearch   p+i+n+u+g+s+b+acl+xattrs+sha512
/usr/sbin/aureport   p+i+n+u+g+s+b+acl+xattrs+sha512
/usr/sbin/autrace    p+i+n+u+g+s+b+acl+xattrs+sha512
/usr/sbin/augenrules p+i+n+u+g+s+b+acl+xattrs+sha512
EOF
    warn "AIDE init is running now (several minutes, 100% CPU + high RAM) - do NOT abort, not a hang."
    aideinit -y -f 2>&1 | tail -3 || warn "aideinit reported an error - check /var/log."
    log "Phase 12 done. AIDE DB at /var/lib/aide/aide.db."
}

# ============================ VERIFY / HEALTH-CHECK ==========================
verify() {
    require_root
    echo "=== HEALTH CHECK $(date) ==="
    local ok=0 fail=0
    # no ((ok++)) - returns exit 1 at 0 and kills the script under set -e (Review K1)
    chk() { if eval "$2" &>/dev/null; then echo "[OK]   $1"; ok=$((ok+1)); else echo "[MISSING] $1"; fail=$((fail+1)); fi; }

    chk "SSH service active"               "systemctl is-active ssh"
    chk "SSH listens on $SSH_PORT"         "ss -tlnp | grep -q \":$SSH_PORT \""
    chk "SSH does NOT listen on 22"        "! ss -tln | grep -q ':22 '"
    chk "SSH: password login off"          "sshd -T | grep -qx 'passwordauthentication no'"
    chk "SSH: root login off"              "sshd -T | grep -qx 'permitrootlogin no'"
    chk "SSH: only $ADMIN_USER"            "sshd -T | grep -qx 'allowusers $ADMIN_USER'"
    chk "ufw active"                       "ufw status | grep -q 'Status: active'"
    chk "ufw: port 22 NOT open"            "! ufw status | grep -qE '(^| )22/tcp'"
    chk "fail2ban sshd jail"               "fail2ban-client status sshd"
    chk "auditd active"                    "systemctl is-active auditd"
    chk "AppArmor enforcing"               "aa-status --enabled"
    chk "journald persistent"              "test -d /var/log/journal"
    chk "sysctl: syncookies"               "sysctl -n net.ipv4.tcp_syncookies | grep -qx 1"
    chk "sysctl: kptr_restrict=2"          "sysctl -n kernel.kptr_restrict | grep -qx 2"
    chk "time synced (NTP)"                "timedatectl show -p NTPSynchronized --value | grep -qx yes"
    chk "auto-update timer active"         "systemctl is-active apt-daily-upgrade.timer"
    chk "WireGuard wg0"                    "wg show wg0"
    chk "Docker running"                   "docker info"
    chk "Docker ufw guard (after.rules)"   "grep -q DOCKER-USER-HARDENING /etc/ufw/after.rules"
    chk "Docker ufw guard v6 (after6)"     "grep -q DOCKER-USER-HARDENING /etc/ufw/after6.rules"
    chk "Docker IPv6 off (daemon.json)"    "grep -q '\"ipv6\": false' /etc/docker/daemon.json"
    chk "Docker waits for HDD (drop-in)"   "test -f /etc/systemd/system/docker.service.d/wait-hdd.conf"
    chk "fail2ban /64 ban action (v6)"     "test -x /usr/local/bin/f2b-ban6.sh && grep -q ban6-prefix /etc/fail2ban/jail.local"
    chk "HDD fstab with nofail"            "grep \"$HDD_MOUNT\" /etc/fstab | grep -q nofail"
    chk "NC 2FA helper present"            "test -x /usr/local/bin/nc-post-setup.sh"
    chk "Caddy running"                    "systemctl is-active caddy"
    chk "Cockpit socket active"            "systemctl is-active cockpit.socket"
    # Portainer needs a moment to bind after start - retry instead of a false MISSING (Review M5).
    # SUBSHELL (...) - otherwise 'exit' via eval would end the whole verify (final review HIGH):
    chk "Portainer listens on ${PORTAINER_PORT}" "( for i in 1 2 3 4 5 6; do ss -tln | grep -q \":${PORTAINER_PORT} \" && exit 0; sleep 5; done; exit 1 )"
    chk "HDD mounted ($HDD_MOUNT)"         "mountpoint -q $HDD_MOUNT"
    chk "HDD ext4 reserved blocks ~5%"     "( d=\$(findmnt -no SOURCE $HDD_MOUNT 2>/dev/null) && [[ -n \"\$d\" ]] && p=\$(tune2fs -l \"\$d\" 2>/dev/null | awk '/Reserved block count/{r=\$4} /Block count:/{b=\$3} END{if(b>0) printf \"%d\", (r*100/b)}') && [[ \"\$p\" -ge 4 && \"\$p\" -le 6 ]] )"
    chk "Disk-space-alert timer active"    "systemctl is-active disk-space-alert.timer"
    chk "Borg path trigger active"         "systemctl is-active borg-backup.path"
    chk "Borg fallback timer active"       "systemctl is-active borg-backup.timer"
    chk "DNS resolution"                   "getent hosts archive.ubuntu.com"
    # --- Rev.5 checks ---
    chk "sysctl: secure_redirects=0"       "sysctl -n net.ipv4.conf.all.secure_redirects | grep -qx 0"
    chk "PAM: pwquality minlen=14"         "grep -qE '^minlen = 14' /etc/security/pwquality.conf"
    chk "PAM: pwhistory remember=24"       "grep -q 'remember=24' /etc/pam.d/common-password"
    chk "login.defs UMASK 027"             "grep -qE '^UMASK[[:space:]]+027' /etc/login.defs"
    chk "fail2ban ignores WG net"          "grep -q '$WG_NET.0/24' /etc/fail2ban/jail.d/00-ignoreip.local"
    chk "NC-2FA-Filter (Two-factor)"       "grep -q 'Two-factor' /etc/fail2ban/filter.d/nextcloud.conf"
    chk "Caddy-Sandbox-Drop-in"            "test -f /etc/systemd/system/caddy.service.d/hardening.conf"
    chk "ubuntu user removed"              "! id ubuntu"
    chk "AIDE DB present"                  "test -s /var/lib/aide/aide.db"
    chk "GRUB without apparmor boot param" "! grep -rq 'apparmor=1' /etc/default/grub.d/ 2>/dev/null"

    echo "=== $ok OK, $fail open ==="
    echo "Final audit:  lynis audit system   (Lynis from the CISOfy repo, phase 4)"
    [[ $fail -eq 0 ]] || return 1
}

# ================================ DISPATCH ===================================
usage() {
    sed -n '48,67p' "$0"
    echo "Phases: preflight phase1 phase2 phase3 phase4 phase5 phase6 phase7 phase8 phase9 phase10 phase11 phase12 verify"
    echo "Meta: bootstrap (0-2, stops at the login test)  rest (3-12 + verify)  all (everything with the stop)"
}

main() {
    touch "$LOGFILE" 2>/dev/null || LOGFILE=/dev/null
    case "${1:-}" in
        preflight) preflight ;;
        phase1) phase1 ;; phase2) phase2 ;; phase3) phase3 ;;
        phase4) phase4 ;; phase5) phase5 ;; phase6) phase6 ;;
        phase7) phase7 ;; phase8) phase8 ;;
        phase9) phase9 ;; phase10) phase10 ;; phase11) phase11 ;; phase12) phase12 ;;
        verify) verify || true ;;
        bootstrap)
            preflight; phase1; phase2
            echo ""
            warn "STOP: now log in from a SECOND terminal:  ssh -p $SSH_PORT ${ADMIN_USER}@<server-ip>  &&  sudo -v"
            warn "Login OK -> save the admin password offline:  cat $SECRETS_DIR/admin-user-password"
            warn "Only THEN continue with:  ./install.sh rest"
            ;;
        rest)
            # Continuation after a passed login test (bootstrap). Assumes the
            # prerequisites (DNS, HDD, WG pubkey, NC tag, SMTP) are set up front.
            ss -tln 2>/dev/null | grep -q ":${SSH_PORT} " || die "sshd not listening on $SSH_PORT - run 'bootstrap' + login test first."
            phase3; phase4; phase5; phase6; phase7; phase8; phase9; phase10; phase11; phase12
            verify || true
            warn "Plan a reboot (boot params/fstab only take effect then): shutdown -r +1"
            ;;
        all)
            preflight; phase1; phase2
            # Mandatory login test - 'all' must not close SSH untested (Review K4):
            echo ""
            warn "STOP: now log in from a SECOND terminal:  ssh -p $SSH_PORT ${ADMIN_USER}@<server-ip>"
            read -r -p "Login in the second terminal successful? Only then type 'yes': " ans \
                || die "No interactive terminal - 'all' needs input. Run the phases individually."
            [[ "$ans" == "yes" ]] || die "Aborted - test the SSH login first, then run './install.sh all' again (phases are idempotent)."
            # Council-Fix 4: second gate - the admin password must be saved offline,
            # otherwise the VNC console is useless on a later lock-out.
            read -r -p "Admin password ($SECRETS_DIR/admin-user-password) saved offline? Only then 'yes': " ans2 \
                || die "No interactive terminal."
            [[ "$ans2" == "yes" ]] || die "Aborted - save the password first (cat $SECRETS_DIR/admin-user-password), then start again."
            phase3; phase4; phase5; phase6; phase7; phase8; phase9; phase10; phase11; phase12
            verify || true   # one open point must not swallow the final notes (Review M7)
            warn "Plan a reboot (boot params, fstab, possibly the kernel): shutdown -r +1"
            ;;
        *) usage; exit 1 ;;
    esac
}
main "$@"
