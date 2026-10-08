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
# Rev. 7 (2026-10-01) - first complete end-to-end run on a real machine; folded back:
#          - FIXED: sysctl file renamed to 99-zz-hardening.conf. The old name sorted BEFORE
#            Ubuntu's /usr/lib/sysctl.d/99-protect-links.conf and was overridden by it -
#            fs.protected_fifos read 2 in the file but ran at 1. Silent failure, unseen by verify.
#          - Panel CA (phase 11): Cockpit's cert named the FQDN, Portainer's had an EMPTY
#            subject, while both panels are reached at https://<WG>.1:PORT - no browser can
#            match that. Own CA, one cert with IP:<WG>.1 in the SAN, 800 days, serverAuth.
#          - SSH_CLIENT_KEY + server_ip()/login_cmd(): login hints now print a ready-to-paste
#            command with key path and real IPv4 instead of <ip> placeholders.
#          - login.defs SHA_CRYPT_MIN/MAX_ROUNDS=65536; legal banner in /etc/issue(.net).
#          - Verified on real hardware: Redis cap_add set sufficient (no DAC_OVERRIDE),
#            Portainer CE starts, Caddy DNS gate passed first try, msmtp delivers (250),
#            NC fail2ban filter matches real lines, IPv6 ban enters the whole /64,
#            Borg restore round-trip byte-identical + borg check --verify-data OK.
#
# Rev. 8 (2026-10-03) - CIS/USG audit + migration rehearsal on the test server:
#          - FIXED: sshd never showed a banner. /etc/issue.net was written but the
#            'Banner' directive was missing, so the legal text was dead weight for the
#            whole first install. Now set, and proven to appear on login.
#          - FIXED: fs.suid_dumpable ran at 2 although the sysctl file says 0 - apport
#            re-sets it on every boot, after sysctl. apport is now masked; the value
#            holds across reboots. Same class of silent failure as the Rev.7 sysctl bug,
#            different cause: a service, not file ordering.
#          - FIXED: /etc/ssh/sshd_config.d/60-cloudimg-settings.conf shipped 644 - the
#            chmod only covered our own drop-in. Now all of them.
#          - NEW: GRUB menu password (ENABLE_GRUB_PASSWORD, default yes) with
#            --unrestricted boot entries and a rollback if grub.cfg does not confirm
#            both. Lowercase+digits so it is typeable at the provider's VNC console.
#          - NEW: gen_secret uses pwgen -Byncs per the owner's standard, length +-4
#            around 64, minus the shell/.env/URL-active characters.
#          - NEW: CIS nachzuege - empty group wheel, INACTIVE=30, umask 027 in
#            bash.bashrc, 0740 on user init files, explicit ufw loopback rules.
#          - CHANGED: ext4 reserved blocks 1% on volumes >= 1 TB (5% of 4 TB parks
#            200 GB), disk-space-alert thresholds per mountpoint (/ at 80%).
#          - CHANGED: rsync is no longer purged in phase 12 - it is the migration tool.
#            The daemon is masked instead.
#          - verify: 44 -> 54 checks; SMTP_PASS is cleared automatically after phase 4.
#          - Rehearsed end to end: /srv/hdd moved to a second volume with
#            rsync -aHAX --numeric-ids, delta run 0 bytes, file lists identical,
#            fstab swap, borg check --verify-data RC=0 afterwards, reboot clean.
# Rev. 9 (2026-10-03) - swap:
#          - NEW: vm.swappiness = 10 in 99-zz-hardening.conf. Ubuntu's default of 60
#            pages out MariaDB and Redis while RAM is still free. On a 40 GB box swap
#            is an emergency reserve for bursts (Chromium in the immo.flow run, borg
#            compact, a Nextcloud image upgrade), never working memory.
#          - NEW: optional extra swap FILE via SWAPFILE_SIZE_GB (default 0 = off).
#            Swap areas are additive, so the panel-reserved swap can be topped up at
#            any time without rebuilding the server.
#          - verify 56 -> 58 (59 with SWAPFILE_SIZE_GB > 0).
# Rev. 10 (2026-10-03) - the three projects move onto one server:
#          - NEW phase13 immo.flow (ENABLE_IMMO, default no): system user, own
#            MariaDB on 127.0.0.1, own PHP-FPM pool on a unix socket, Caddy site,
#            systemd timer replacing the Mac launchd agent, Borg pre-hook dumping
#            the immo database - which had no automatic backup at all before.
#          - PHP 8.3 from Ubuntu main is enough: on 2026-10-03 all 42 files under
#            web/ passed 'php -l' on 8.3.6 and none used 8.4-only syntax. The
#            third-party PHP repository stays off this machine.
#          - The session cookie attributes the Nextcloud embedding needs (Secure,
#            HttpOnly, SameSite=None) are set in the FPM pool, not in the
#            application - no PHP file changes, and no later code edit can drop them.
#          - NEW phase14 further static sites (ENABLE_EXTRA_SITES, default no).
#          - NEW phase15 Talk HPB (ENABLE_TALK_HPB, default no): coturn native on
#            3478 without TLS, signaling + Janus + NATS as a compose stack, served
#            under a PATH of $NC_DOMAIN so it needs neither its own DNS record nor
#            its own certificate. NOT YET RUN ON A REAL SERVER.
#          - CHANGED: Caddy configuration split into /etc/caddy/conf.d/*.caddy, one
#            file per site. Before, phase 9 rewrote the whole Caddyfile, so a site
#            added by a later phase was silently wiped on the next phase-9 run.
#          - CHANGED: the phase-9 DNS gate is now the reusable function dns_gate,
#            used by phases 9, 13 and 14 instead of three copies.
#          - verify: 59 checks run with all three switches off, 76 exist in total.
#          - FIXED (2026-10-04, on the production server): verify reported random
#            false negatives. The checks run under 'set -o pipefail', so every
#            'producer | grep -q' check failed whenever the producer was still
#            writing when grep -q exited - SIGPIPE, status 141, pipefail. It only
#            showed up once the machine had enough listening sockets for ss to
#            overflow the pipe buffer. chk() now evaluates in a subshell with
#            pipefail off. Same class as the Rev.7 sysctl and Rev.8 banner bugs:
#            the configuration was right, the check was wrong.
#          - FIXED phase15, two faults found on first start (2026-10-04):
#            1. The signaling image drops privileges to 'spreedbackend' (uid 850)
#               in its entrypoint, so the root-owned 600 server.conf was
#               unreadable and the container crash-looped. Now chown 850:850.
#            2. Janus needs host networking for its RTP range, and a
#               host-networked container is not resolvable by name from a bridge
#               container - the signaling server died on "lookup janus ... server
#               misbehaving". All three services now run on the host network with
#               every port bound to the loopback. Mixing the two modes was the trap.
#            Talk HPB is thereby verified end to end on a real server.
# Rev. 11 (2026-10-05) = v0.6.3 - the four blockers from Urteil-Team-A.md plus the
#          decisions of 2026-10-05:
#          - B1: new gen_fixed() for the two signaling session keys. gen_secret varies
#            every length by +-4, so blockkey (base 16) came out 12 to 20 characters,
#            while the signaling server demands exactly 16, 24 or 32 bytes and otherwise
#            aborts the start - eight of nine runs would have crash-looped. phase15 also
#            drops an existing key of the wrong length so gen_fixed rebuilds it.
#          - B2: two abort conditions after the install.conf gate (ADMIN_USER=root and
#            SSH_PORT=22 each lock you out). phase2 demands the receipt file
#            $SECRETS_DIR/admin-user-password.saved, and the new password_gate() between
#            phase1 and phase2 in 'bootstrap' and 'all' shows the password on the
#            TERMINAL (never through log()/warn() into $LOGFILE), asks, and writes that
#            receipt. The old gate in 'all' asked only after phase2 - too late.
#          - B3 is a config change: SWAPFILE_SIZE_GB="8" in install.conf, panel swap 0.
#          - B4: the immo timer check is conditional on the .venv being present.
#          - CLOUD-INIT PATH: phase1 no longer ties the password to "user did not exist".
#            On a machine built from userData the user is already there with a locked
#            password and NOPASSWD sudo; phase1 now sets the password and removes the
#            NOPASSWD rule. Before this, that path ended with a machine whose root login
#            phase2 switches off while nobody can authenticate at the VNC console.
#          - PORTAINER REMOVED (owner decision 2026-10-05). It mounted
#            /var/run/docker.sock, which is root on the host for whoever reaches the UI,
#            and apt - not a container panel - is what adds software here. phase12
#            removes container, volume and image left over from an earlier run; the
#            verify check is replaced by one that asserts the container is gone.
#          - Panel CA: nameConstraints on the WireGuard subnet and the server's own FQDN,
#            so an imported private root cannot vouch for any other name. Lifetimes
#            3650/800 -> 1825/397 days, automatic reissue of the leaf 30 days before it
#            expires, and the chain is verified with 'openssl verify' after signing.
#          - Cockpit: IdleTimeout=15 (minutes, cockpit.conf(5) [Session]), banner, and
#            root written into /etc/cockpit/disallowed-users explicitly. No TOTP - the
#            panel is reachable only inside the tunnel, key-only, behind ufw.
#          - BORG: the exclude was the whole of $HDD_MOUNT, which silently left
#            $HDD_MOUNT/immo - the market reports, which exist nowhere else - out of
#            every archive. Now only $BACKUP_DIR (the repos) and $NCDATA_DIR (blobs that
#            are a copy of what the Mac syncs) are excluded.
#          - phase13 writes both env files: $IMMO_DIR/.env (600, immo) with the database
#            and the IMAP values, and $IMMO_WEB_ENV (640 root:immo) with the database and
#            the frontend keys but NO IMAP password, handed to PHP through
#            env[IMMO_WEB_ENV] in the pool. IMAP_PORT defaults to 993 - 995 is POP3.
#            New helper env_set() rewrites single keys without touching other lines.
#          - install.conf is no longer copied before SMTP_PASS is cleared: on 2026-10-04
#            that left install.conf.bak.<timestamp> with the password in the clear.
#            Existing backups are shredded, and verify fails if one is left.
#          - Lynis: new target 'lynis' and an automatic run at the end of 'rest'/'all',
#            writing $TESTS_DIR/30-lynis.log. Until now the audit was a line in the
#            closing notes and its output was lost.
#          - usage() printed the wrong block of this header (sed -n '48,67p', the change
#            history). Corrected and checked against the actual output.
#          - verify: 86 checks under silo's switches (64 unconditional, 16 immo, 4 Talk HPB,
#            1 GRUB password, 1 swap file; counted by two independent reviews on
#            2026-10-06). The 'verify' at the end of 'rest' runs 66, before the phase
#            13-15 switches are appended.
# Rev. 12 (2026-10-06) = v0.6.4 - findings of the 2x2 review before the cloud-init rebuild:
#          - umask 022 at the top: after phase 5, sudo inherits UMASK 027 via pam_umask and
#            the phase-14 placeholder pages came out 640 - Caddy answered 403.
#          - password_gate checks for a real terminal BEFORE showing the password, prints
#            it to /dev/tty only, reads from /dev/tty with -t 3600 (TMOUT=900 is inherited).
#          - phase8: the client template with the preshared key is no longer tee'd into the
#            run log; a newly generated PSK is announced (the tunnel is down until the
#            client has it).
#          - phase10: an existing repo-server that does not open with the current passphrase
#            aborts with instructions instead of leaving every backup failing silently.
#          - phase13: caddy joins group immo (static files and try_files answered 403);
#            chown -R of $HDD_MOUNT/immo (the volume survives a rebuild, the uid may not);
#            IMAP_PASS values a .env reader misreads are refused.
#          - dns_gate: '|| true' on the getent pipes - an unresolvable name ended the script
#            silently under pipefail. lynis_audit: same for the grep.
#          - phase3/'rest': ss filter instead of 'ss | grep -q' (SIGPIPE under pipefail).
#          - phase2 removes sshd drop-ins and the ssh.socket override of older userData drafts.
#          - preflight waits for cloud-init and sets a 600 s dpkg lock timeout.
#          - admin password in the owner's VNC pattern (gen_vnc_password):
#            bbBbbbbb-BBBBBB-bbbbb-bbBbbbbb-zzzzzzz-bbbbbb-bbbBbbbb, no y/z/I/O/l.
#          - phase 1 login hint names the port sshd really listens on.
#          - phase5: grub-mkpasswd-pbkdf2 under setsid -w; in a background run it read
#            /dev/tty and the whole script was stopped (SIGTTIN) on 2026-10-06.
#
# USAGE (as root on a fresh Ubuntu 24.04):
#   ./install.sh preflight        # checks + apt update/upgrade
#   ./install.sh phase1           # ... a single phase
#   ./install.sh all              # all phases (stops after SSH hardening
#                                        #  for the mandatory login test!)
#   ./install.sh bootstrap        # preflight+phase1+phase2, ends at the login-test stop.
#                                 # Needs an INTERACTIVE terminal: between phase1 and
#                                 # phase2 it shows the admin password and asks for
#                                 # confirmation. So run it in an open root session
#                                 # (ssh -t), not as ssh hih-r './install.sh bootstrap'.
#   ./install.sh rest             # phase3..phase15 + verify + lynis (AFTER a successful login test)
#   ./install.sh verify           # health check
#
# 3-STEP ROUTINE (after the prerequisites are front-loaded: DNS, HDD, WG pubkey,
# NC tag, SMTP, SSH pubkey): 'bootstrap' -> test the login in a 2nd terminal -> 'rest'.
# CLOUD-INIT PATH (v0.6.3): if userData already created the admin user and moved sshd to
# the high port, run 'bootstrap' anyway. phase1 then only does the follow-up work - set
# the admin password, drop the NOPASSWD rule - and phase2 replaces the minimal sshd
# drop-in with the full hardened configuration. Both phases are idempotent.
# FIRST RUN on a new server still phase by phase (catch Redis/Janus live).
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
# Rev.12: sudo inherits umask 027 via pam_umask once phase 5 has set UMASK 027 in
# login.defs. Files Caddy or MariaDB must read then came out 640 (403 on the phase-14
# sites). Every private file in this script gets its own explicit mode, so 022 is safe.
umask 022

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
SSH_CLIENT_KEY="${SSH_CLIENT_KEY:-}"       # path to the PRIVATE key on YOUR client (for the printed login hints)
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

# --- HDD / Borg backup on the server HDD (phase 9+10) ---
HDD_MOUNT="${HDD_MOUNT:-/srv/hdd}"         # 4 TB HDD mount point
NCDATA_DIR="${HDD_MOUNT}/ncdata"           # Nextcloud data dir (blobs, ~1 TB)
BACKUP_DIR="${HDD_MOUNT}/backup"           # Borg repos: repo-server + repo-local

# --- General ---
TIMEZONE="${TIMEZONE:-Europe/Berlin}"
SECRETS_DIR="${SECRETS_DIR:-/root/install-secrets}"
LOGFILE="${LOGFILE:-/var/log/harden-install.log}"
TESTS_DIR="${TESTS_DIR:-/root/tests}"   # run protocols (01-rest.log, 30-lynis.log, ...)
WAN_IF="${WAN_IF:-}"                       # WAN interface (Docker/ufw bypass guard, phase 9); empty = auto-detect
# GRUB boot-parameter hardening (phase5). Default OFF: boot params have the largest blast
# radius and some providers have no rescue/ISO, only the provider backup. Enable ONLY with
# a fresh provider backup: "yes" -> update-grub -> reboot -> check /proc/cmdline.
ENABLE_GRUB_HARDENING="${ENABLE_GRUB_HARDENING:-no}"

# GRUB menu password (phase5). Separate from the boot PARAMETERS above and far less
# dangerous: it only protects editing the boot menu and the GRUB shell, while the
# normal menu entries are marked --unrestricted so an unattended reboot still boots
# without input. Default ON, but only ever enable it with a WORKING rescue console
# (provider VNC) - proven on the test server 2026-10-03.
ENABLE_GRUB_PASSWORD="${ENABLE_GRUB_PASSWORD:-yes}"

# Optional ADDITIONAL swap FILE (phase5), whole GB. 0 = none.
# Rev.9: the provider panel already reserves a swap area when the server is built
# (8 GB on the production box). Linux takes swap files ON TOP of that, at any size,
# at any time, without a rebuild - so this stays 0 unless the panel's swap proves
# too small under load. See vm.swappiness in the sysctl block below.
SWAPFILE_SIZE_GB="${SWAPFILE_SIZE_GB:-0}"

# --- Rev.10: phase 13, immo.flow (second PHP project, own MariaDB) ---
# Default off: an existing installation must behave exactly as before.
ENABLE_IMMO="${ENABLE_IMMO:-no}"
IMMO_DOMAIN="${IMMO_DOMAIN:-}"             # e.g. immo.example.com
IMMO_DIR="${IMMO_DIR:-/srv/immo}"
IMMO_USER="${IMMO_USER:-immo}"
IMMO_DB="${IMMO_DB:-immo}"
IMMO_DB_USER="${IMMO_DB_USER:-immo-user}"
IMMO_RUN_TIME="${IMMO_RUN_TIME:-15:00}"    # systemd OnCalendar time, server timezone
# Playwright/Chromium system libraries: ~400 MB on disk, ~1 GB RAM while running.
# Only needed if the scrapers run ON THE SERVER instead of on the local machine.
ENABLE_IMMO_PLAYWRIGHT="${ENABLE_IMMO_PLAYWRIGHT:-no}"
# Mail RETRIEVAL for the daily immo run (phase 13). silo runs no inbound mail server:
# no MX record, no SMTP acceptance, no spam filtering - the mailbox stays at the provider
# and the run fetches from it over IMAP.
IMAP_HOST="${IMAP_HOST:-}"                 # e.g. mail.example.com
IMAP_PORT="${IMAP_PORT:-993}"              # 993 = IMAP over TLS. NOT 995 - that is POP3 over TLS.
IMAP_USER="${IMAP_USER:-}"                 # the mailbox the run reads
IMAP_PASS="${IMAP_PASS:-}"                 # ONE-TIME write to $IMMO_DIR/.env (600), then cleared here
IMAP_ORDNER="${IMAP_ORDNER:-INBOX}"
IMMO_WEB_ENV="${IMMO_WEB_ENV:-/etc/immo/web.env}"   # env file for the PHP frontend, WITHOUT the IMAP password
IMMO_MAIL_FROM="${IMMO_MAIL_FROM:-}"       # sender of the "password forgotten" mails

# --- Rev.10: phase 14, further static sites ---
ENABLE_EXTRA_SITES="${ENABLE_EXTRA_SITES:-no}"
EXTRA_SITES="${EXTRA_SITES:-}"             # space separated, e.g. "a.example.com b.example.com"

# --- Rev.10: phase 15, Nextcloud Talk High Performance Backend ---
# The signaling server is served under a PATH of $NC_DOMAIN, so it needs neither
# a DNS record nor a certificate of its own. coturn listens on 3478 without TLS.
ENABLE_TALK_HPB="${ENABLE_TALK_HPB:-no}"
TURN_PORT="${TURN_PORT:-3478}"
JANUS_RTP_MIN="${JANUS_RTP_MIN:-20000}"
JANUS_RTP_MAX="${JANUS_RTP_MAX:-20100}"
# Janus has no image published by the Nextcloud project. UNVERIFIED default -
# check it against the upstream repository before the first run.
JANUS_IMAGE="${JANUS_IMAGE:-canyan/janus-gateway:latest}"

# Fail early if the personal config was not loaded (skip when only showing usage):
if [[ -n "${1:-}" && "${1:-}" != "usage" && -z "$ADMIN_USER" ]]; then
    echo "[ERROR] No install.conf found (ADMIN_USER empty). Run: cp install.conf.example install.conf, then edit it." >&2
    exit 1
fi
# B2: both values lock you out - phase2 writes PermitRootLogin no + AllowUsers $ADMIN_USER
# and moves sshd off 22. Checked here, before the first phase touches the machine.
[[ -z "${1:-}" || "${1:-}" == usage || "$ADMIN_USER" != root ]] || { echo "[ERROR] ADMIN_USER=root locks you out (PermitRootLogin no + AllowUsers root)." >&2; exit 1; }
[[ -z "${1:-}" || "${1:-}" == usage || "$SSH_PORT" != 22 ]] || { echo "[ERROR] SSH_PORT=22 - choose a high port." >&2; exit 1; }
# =============================================================================

C_GRN='\033[0;32m'; C_RED='\033[0;31m'; C_YEL='\033[0;33m'; C_OFF='\033[0m'
log()  { echo -e "${C_GRN}[+]${C_OFF} $*" | tee -a "$LOGFILE"; }
warn() { echo -e "${C_YEL}[!]${C_OFF} $*" | tee -a "$LOGFILE"; }
die()  { echo -e "${C_RED}[ERROR]${C_OFF} $*" | tee -a "$LOGFILE"; exit 1; }

require_root() { [[ $EUID -eq 0 ]] || die "Run as root."; }

# --- login hint helpers -------------------------------------------------------
server_ip() {  # primary IPv4 of this machine (source address of the default route)
    local ip
    ip="$(ip -4 route get 1.1.1.1 2>/dev/null | sed -n 's/.* src \([0-9.]*\).*/\1/p')"
    [[ -n "$ip" ]] || ip="<server-ip>"
    printf '%s' "$ip"
}

login_cmd() {  # login_cmd [port] -> ready-to-paste ssh command for the client
    local port="${1:-$SSH_PORT}"
    local key="${SSH_CLIENT_KEY:-<path-to-your-private-key>}"
    printf 'ssh -i %s %s@%s -p %s' "$key" "$ADMIN_USER" "$(server_ip)" "$port"
}

ask_client_key() {  # asked ONCE in preflight, stored back into install.conf
    if [[ -n "$SSH_CLIENT_KEY" ]]; then return 0; fi
    if [[ -t 0 ]]; then
        echo ""
        warn "Path to the PRIVATE SSH key on YOUR machine (the counterpart of SSH_PUBKEY)."
        warn "It is only used to print ready-to-paste login commands. Example: ~/.ssh/id_ed25519"
        read -r -p "SSH_CLIENT_KEY: " SSH_CLIENT_KEY || true
    fi
    if [[ -z "$SSH_CLIENT_KEY" ]]; then
        warn "SSH_CLIENT_KEY not set - login hints will show a placeholder instead of the key path."
        return 0
    fi
    if [[ -f "$INSTALL_CONF" ]]; then
        if grep -q '^SSH_CLIENT_KEY=' "$INSTALL_CONF"; then
            sed -i "s|^SSH_CLIENT_KEY=.*|SSH_CLIENT_KEY=\"$SSH_CLIENT_KEY\"|" "$INSTALL_CONF"
        else
            printf 'SSH_CLIENT_KEY="%s"\n' "$SSH_CLIENT_KEY" >> "$INSTALL_CONF"
        fi
        log "SSH_CLIENT_KEY stored in $INSTALL_CONF"
    fi
}

backup_file() {  # backup_file <path>
    local f="$1"
    [[ -f "$f" ]] && cp -a "$f" "${f}.bak.$(date +%Y%m%d-%H%M%S)"
    return 0
}

env_set() {  # env_set <file> <key> <value> - set or add KEY=value, keep every other line
    # Rewritten instead of sed-replaced on purpose: a password may contain any of sed's
    # delimiters and metacharacters. Managed keys move to the end of the file, unmanaged
    # lines (deployed by the application) survive untouched.
    local f="$1" k="$2" v="$3" tmp
    tmp="$(umask 077; mktemp)" || die "mktemp failed."
    if [[ -f "$f" ]]; then grep -v "^${k}=" "$f" > "$tmp" || true; fi
    printf '%s=%s\n' "$k" "$v" >> "$tmp"
    cat "$tmp" > "$f"          # keeps owner and mode of an existing $f
    rm -f "$tmp"
}

append_once() {  # append_once <line> <file>  - idempotent append
    grep -qxF "$1" "$2" 2>/dev/null || echo "$1" >> "$2"
}

# --- Rev.10: Caddy configuration is split. The main Caddyfile only imports; every
# site lives in its own file under $CADDY_CONFD. Before, phase 9 wrote the whole
# Caddyfile, so any site a later phase added was silently wiped on the next phase-9
# run. One file per site also means a broken site file can be moved aside without
# touching the others.
CADDY_CONFD="/etc/caddy/conf.d"

write_caddy_base() {
    install -d -m 755 "$CADDY_CONFD"
    backup_file /etc/caddy/Caddyfile
    cat > /etc/caddy/Caddyfile <<EOF
# Managed by install.sh - do not edit by hand.
# One file per site in $CADDY_CONFD (phases 9, 13, 14).
import $CADDY_CONFD/*.caddy
EOF
    chmod 644 /etc/caddy/Caddyfile          # must be readable by user 'caddy' (Review K3)
}

write_caddy_nextcloud() {
    # Called by phase 9 and again by phase 15: the Talk signaling handle has to sit
    # INSIDE the Nextcloud site block, and one definition is better than two copies.
    local sig=""
    if [[ "$ENABLE_TALK_HPB" == "yes" ]]; then
        sig="
    handle_path /standalone-signaling/* {
        reverse_proxy 127.0.0.1:8081
    }
"
    fi
    cat > "$CADDY_CONFD/10-nextcloud.caddy" <<EOF
$NC_DOMAIN {
    header Strict-Transport-Security "max-age=15552000; includeSubDomains"
    redir /.well-known/carddav /remote.php/dav/ 301
    redir /.well-known/caldav  /remote.php/dav/ 301
$sig
    handle {
        reverse_proxy 127.0.0.1:8080
    }
}
EOF
    chmod 644 "$CADDY_CONFD/10-nextcloud.caddy"
}

caddy_apply() {  # validate, then reload - never leave a broken config running
    caddy validate --config /etc/caddy/Caddyfile || die "Caddyfile invalid - nothing reloaded."
    systemctl reload caddy 2>/dev/null || systemctl restart caddy
}

dns_gate() {  # dns_gate <domain> - abort unless the record points at THIS server
    # Caddy starts ACME attempts immediately. If the A/AAAA record still points
    # elsewhere, every failed attempt burns the Let's Encrypt rate limit
    # (5 failures/account/domain/hour).
    local dom="$1" pub4 dns4 dns6 wif
    wif="${WAN_IF:-$(ip route show default 2>/dev/null | awk '/default/{print $5; exit}')}"
    [[ -n "$wif" ]] || die "DNS gate: WAN interface not detected - set WAN_IF in install.conf."
    # Rev.12: '|| true' - under pipefail a name that does not resolve ended the script
    # silently (getent rc 2) before the message below was reached.
    pub4="$(ip -4 -o addr show dev "$wif" scope global | awk '{print $4}' | cut -d/ -f1 | head -1 || true)"
    dns4="$(getent ahostsv4 "$dom" 2>/dev/null | awk '{print $1; exit}' || true)"
    [[ -n "$dns4" ]] || die "DNS gate: $dom does not resolve. Set the A record to $pub4, wait for the TTL, then run the phase again."
    [[ "$dns4" == "$pub4" ]] || die "DNS gate: $dom -> $dns4, but this server is $pub4. Fix the A record, then run the phase again."
    # AAAA: only check a real v6 entry (::ffff: = mapped v4). An AAAA that does NOT
    # point here also makes ACME fail.
    dns6="$(getent ahostsv6 "$dom" 2>/dev/null | awk '$1 !~ /^::ffff:/ {print $1; exit}' || true)"
    if [[ -n "$dns6" ]]; then
        ip -6 -o addr show scope global | grep -qF "$dns6" \
            || die "DNS gate: AAAA($dom)=$dns6 does not belong to this server. Fix or delete the AAAA, then run the phase again."
    fi
    log "DNS gate passed: $dom -> $dns4${dns6:+ / $dns6}"
}

gen_secret() {  # gen_secret <name> [base-length]  - create/read a secret, print it to stdout
    # Rev.8: pwgen -Byncs per the owner's standard (no ambiguous chars, digits,
    # capitals, symbols, secure RNG). Length varies by +-4 around the base so not
    # every secret in $SECRETS_DIR shares one length.
    # Shell/.env/URL-active characters are excluded: these secrets travel through
    # docker-compose .env files, DB connection URLs and shell here-docs, where a
    # bare $ ` " ' \ ; & | < > would break the consumer, not the entropy budget
    # (60+ chars from the remaining set is far beyond any brute-force reach).
    local f="$SECRETS_DIR/$1"
    local base="${2:-64}"
    if [[ ! -f "$f" ]]; then
        install -d -m 700 "$SECRETS_DIR"
        local n=$(( base - 4 + RANDOM % 9 ))
        if command -v pwgen >/dev/null 2>&1; then
            pwgen -Byncs --remove-chars='$`"'"'"'\\;&|<>' "$n" 1 > "$f" \
                || die "pwgen failed for secret '$1'."
        else
            warn "pwgen missing - falling back to openssl for secret '$1'."
            openssl rand -base64 96 | tr -d '\n=+/' | cut -c1-"$n" > "$f"
        fi
        chmod 600 "$f"
    fi
    cat "$f"
}

gen_vnc_password() {  # gen_vnc_password <name> - admin password in the owner's VNC pattern
    # Rev.12: the admin password is typed at the provider's VNC console, so the owner
    # fixed its shape (2026-10-06):  bbBbbbbb-BBBBBB-bbbbb-bbBbbbbb-zzzzzzz-bbbbbb-bbbBbbbb
    # b = lower-case letter, B = upper-case letter, z = digit. y/z and Y/Z are left out
    # (swapped on a German keyboard behind US key positions), I, O and l as well
    # (mistaken for 1/0 when copied from paper). Random source: openssl rand.
    local f="$SECRETS_DIR/$1"
    if [[ ! -f "$f" ]]; then
        install -d -m 700 "$SECRETS_DIR"
        local pat='bbBbbbbb-BBBBBB-bbbbb-bbBbbbbb-zzzzzzz-bbbbbb-bbbBbbbb'
        local lo='abcdefghijkmnopqrstuvwx' up='ABCDEFGHJKLMNPQRSTUVWX' dg='0123456789'
        local plo='' pup='' pdg='' out='' i c
        while (( ${#plo} < 40 )); do plo+="$(openssl rand 256 | LC_ALL=C tr -dc "$lo")"; done
        while (( ${#pup} < 12 )); do pup+="$(openssl rand 256 | LC_ALL=C tr -dc "$up")"; done
        while (( ${#pdg} < 8 ));  do pdg+="$(openssl rand 256 | LC_ALL=C tr -dc "$dg")"; done
        for (( i = 0; i < ${#pat}; i++ )); do
            c="${pat:i:1}"
            case "$c" in
                b) out+="${plo:0:1}"; plo="${plo:1}" ;;
                B) out+="${pup:0:1}"; pup="${pup:1}" ;;
                z) out+="${pdg:0:1}"; pdg="${pdg:1}" ;;
                *) out+="$c" ;;
            esac
        done
        ( umask 077; printf '%s\n' "$out" > "$f" ) || die "could not write $f"
        [[ "$(head -1 "$f")" =~ ^[a-x][a-x][A-X][a-x]{5}-[A-X]{6}-[a-x]{5}-[a-x]{2}[A-X][a-x]{5}-[0-9]{7}-[a-x]{6}-[a-x]{3}[A-X][a-x]{4}$ ]] \
            || die "admin password does not match the pattern - $f"
    fi
    cat "$f"
}

gen_fixed() {  # gen_fixed <name> <chars> - hex secret of exactly <chars> characters (= bytes in the config)
    local f="$SECRETS_DIR/$1"
    if [[ ! -f "$f" ]]; then
        install -d -m 700 "$SECRETS_DIR"
        ( umask 077; openssl rand -hex "$(( $2 / 2 ))" > "$f" ) || die "openssl failed for '$1'."
    fi
    cat "$f"
}

# ============================ PHASE 0: PREFLIGHT =============================
preflight() {
    require_root
    log "Preflight checks"
    ask_client_key
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
    # Rev.12: right after a rebuild cloud-init and apt-daily still hold the dpkg lock.
    if command -v cloud-init >/dev/null 2>&1; then cloud-init status --wait >/dev/null 2>&1 || true; fi
    printf 'DPkg::Lock::Timeout "600";\n' > /etc/apt/apt.conf.d/99-lock-timeout
    apt-get update -q
    apt-get full-upgrade -y -q
    apt-get install -y -q openssl curl gnupg ca-certificates apt-transport-https pwgen
    log "Preflight done. If the kernel was updated: reboot after all phases are complete."
}

# ============================ PHASE 1: ADMIN USER ===========================
phase1() {
    require_root
    log "Phase 1: user $ADMIN_USER + sudo"
    if ! id "$ADMIN_USER" &>/dev/null; then
        adduser --disabled-password --gecos "" "$ADMIN_USER"
    fi

    # v0.6.3, the cloud-init path: on a machine built from userData the user already
    # EXISTS - created with a locked password and NOPASSWD sudo so the bootstrap can
    # run unattended. Before v0.6.3 this block was inside the "user does not exist"
    # branch, so on that path no password was ever set: phase2 would switch off the
    # root login while nobody could authenticate at the VNC console, and sudo would
    # stay password-free for the life of the machine. Both are undone here.
    local pwstate
    pwstate="$(passwd -S "$ADMIN_USER" 2>/dev/null | awk '{print $2}')"
    if [[ "$pwstate" != "P" ]]; then
        local pw; pw="$(gen_vnc_password admin-user-password)"
        echo "${ADMIN_USER}:${pw}" | chpasswd
        unset pw
        log "Password for $ADMIN_USER (sudo + VNC console, no SSH login) is in $SECRETS_DIR/admin-user-password"
        # Council-Fix 4 (lock-out trap): the password exists only on-box, root has none.
        # Without an offline-saved password the provider VNC console is USELESS on an
        # SSH lock-out -> the server is unrecoverable without a reinstall.
        # Rev.12: 'bootstrap' and 'all' show the password at password_gate. These lines
        # matter only when phase1 is run on its own.
        log "bootstrap/all show it before phase 2. Running phase1 alone: read it, store it"
        log "offline, then: touch $SECRETS_DIR/admin-user-password.saved (phase2 requires it)."
    else
        log "$ADMIN_USER already has a password - keeping it."
    fi

    # The bootstrap NOPASSWD rule has to go, whoever wrote it: the whole point of the
    # admin password is that sudo asks for it. /etc/sudoers.d/hardening below sets the
    # normal behaviour; a NOPASSWD file sorting after it would win.
    local sf
    for sf in /etc/sudoers.d/90-cloud-init-users /etc/sudoers.d/99-bootstrap-nopasswd; do
        if [[ -f "$sf" ]] && grep -q NOPASSWD "$sf"; then
            install -d -m 700 "$SECRETS_DIR"
            cp -a "$sf" "$SECRETS_DIR/$(basename "$sf").removed" 2>/dev/null || true
            rm -f "$sf"
            visudo -c >/dev/null || die "sudoers broken after removing $sf - fix it before continuing."
            log "NOPASSWD rule $sf removed (cloud-init bootstrap)."
        fi
    done

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
    # Rev.12: on the cloud-init path sshd already listens on SSH_PORT and 22 is closed.
    local p1port=22
    [[ -n "$(ss -Htln "sport = :${SSH_PORT}" 2>/dev/null)" ]] && p1port="$SSH_PORT"
    log "Phase 1 done. TEST in a 2nd terminal:"
    log "    $(login_cmd "$p1port")"
    log "    then:  sudo -v"
}

# ============================ PHASE 2: SSH HARDENING ========================
phase2() {
    require_root
    log "Phase 2: harden SSH (port $SSH_PORT, key-only, only $ADMIN_USER)"
    [[ -f "/home/$ADMIN_USER/.ssh/authorized_keys" ]] || die "Run phase1 first (authorized_keys missing)."
    # B2: from here on root cannot log in any more. Without the admin password saved
    # offline the provider VNC console is worthless on a lock-out, so the receipt is
    # mandatory - deliberately a manual step, it cannot be faked by the script.
    [[ -f "$SECRETS_DIR/admin-user-password.saved" ]] || die "Admin password not confirmed as saved. Read $SECRETS_DIR/admin-user-password in this root session, store it in 1Password and on paper, then: touch $SECRETS_DIR/admin-user-password.saved"

    # ufw already running (re-run/port change)? Open the new port BEFORE the sshd restart (Review M9):
    if command -v ufw &>/dev/null && ufw status 2>/dev/null | grep -q 'Status: active'; then
        ufw limit "${SSH_PORT}/tcp" comment 'SSH rate-limited' || true
    fi

    backup_file /etc/ssh/sshd_config
    # the cloud-init drop-in can re-enable PasswordAuthentication - remove it:
    rm -f /etc/ssh/sshd_config.d/50-cloud-init.conf
    # Rev.12: drop-ins and the socket override left by earlier userData drafts
    # (the final userData writes 10-hardening.conf itself, which is rewritten below).
    rm -f /etc/ssh/sshd_config.d/99-hih.conf /etc/ssh/sshd_config.d/10-haertung.conf \
          /etc/systemd/system/ssh.socket.d/10-port.conf

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
# Rev.8 (CIS sshd_enable_warning_banner_net): without this line the legal text
# written to /etc/issue.net in phase 5 is NEVER shown on an SSH login - the file
# alone does nothing. Confirmed on the test server 2026-10-03: 'sshd -T' reported
# 'banner none' through the whole first install run.
Banner /etc/issue.net
EOF
    # Rev.8: 600 on EVERY drop-in, not just our own - Ubuntu's cloud image ships
    # 60-cloudimg-settings.conf with 644 (CIS file_permissions_sshd_drop_in_config).
    chmod 600 /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf

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
    log "Phase 2 done. KEEP THE SESSION OPEN and test in a 2nd terminal:"
    log "    $(login_cmd)"
}

# ============================ PHASE 3: FIREWALL ==============================
phase3() {
    require_root
    log "Phase 3: ufw"
    # Guard against out-of-order runs (Review M8): is sshd listening on $SSH_PORT?
    local KEEP22
    # Rev.12: ss filter instead of 'ss | grep -q' - under pipefail grep -q's early exit
    # (SIGPIPE, 141) read as "not listening" once enough sockets were open.
    if [[ -z "$(ss -Htln "sport = :${SSH_PORT}" 2>/dev/null)" ]]; then
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
    # Rev.8 (CIS set_ufw_loopback_traffic): trust lo, reject spoofed loopback
    # addresses arriving on a real interface.
    ufw allow in on lo
    ufw deny in from 127.0.0.0/8
    ufw deny in from ::1
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
            # Rev.8: the old warning was printed and overlooked - a mail password then sat
            # in install.conf in the clear for days. The value is only ever needed for this
            # one write, so clear it HERE instead of asking someone to remember.
            # /etc/msmtp-pass (mode 600) is the only place it lives from now on.
            if [[ -f "$INSTALL_CONF" ]] && grep -q '^SMTP_PASS=' "$INSTALL_CONF"; then
                # v0.6.3: NO backup_file here any more. On 2026-10-04 it left
                # install.conf.bak.<timestamp> next to the config with the 128-character
                # SMTP password in the clear - a file nobody looks at again. The value
                # lives in the password manager; a copy here is only one more place to
                # forget. Existing backups are shredded, including from earlier runs.
                local bak
                for bak in "$INSTALL_CONF".bak.*; do
                    [[ -e "$bak" ]] || continue
                    shred -u "$bak" 2>/dev/null || rm -f "$bak"
                    warn "Deleted $bak - it held the SMTP password in the clear."
                done
                sed -i "s|^SMTP_PASS=.*|SMTP_PASS=''|" "$INSTALL_CONF"
                log "SMTP_PASS written to /etc/msmtp-pass and CLEARED in $INSTALL_CONF."
                warn "Re-running phase4 needs SMTP_PASS entered again (it is in the password manager)."
                warn "The COPY OF install.conf ON YOUR OWN MACHINE still holds the password - clear it there too."
            else
                warn "SMTP_PASS is now in /etc/msmtp-pass - CLEAR the variable in install.conf yourself!"
            fi
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

    # File name must sort AFTER Ubuntu's own /usr/lib/sysctl.d/99-protect-links.conf,
    # otherwise values present in both (e.g. fs.protected_fifos) are silently reverted.
    rm -f /etc/sysctl.d/99-hardening.conf
    cat > /etc/sysctl.d/99-zz-hardening.conf <<'EOF'
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
# === Core dumps (Lynis KRNL-6000) ===
# suid_dumpable is 0 above; this only makes the remaining dumps identifiable.
kernel.core_uses_pid = 1
# === Swap behaviour (Rev.9) ===
# 10, not Ubuntu's default 60: with 40 GB RAM the kernel must not page out the
# MariaDB buffer pool or Redis while physical memory is still free. Swap here is
# an emergency reserve against the OOM killer, not a second tier of memory.
vm.swappiness = 10
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

    # --- Rev.8: apport. THE reason fs.suid_dumpable kept reading 2 at runtime even
    # though 99-zz-hardening.conf sets 0: the apport init script re-sets it to 2 on
    # every boot, AFTER sysctl has run. Found on the test server 2026-10-03 via the
    # CIS audit, which flagged both facts separately. Masking apport fixes both.
    # A crash-report uploader has no business on a server anyway.
    systemctl disable --now apport.service 2>/dev/null || true
    systemctl mask apport.service 2>/dev/null || true
    if [[ -f /etc/default/apport ]]; then sed -i 's/^enabled=.*/enabled=0/' /etc/default/apport; fi
    sysctl -w fs.suid_dumpable=0 >/dev/null 2>&1 || true

    # --- Rev.8 (CIS ensure_pam_wheel_group_empty): /etc/pam.d/su already restricts
    # su to group 'sudo'. CIS additionally wants an EMPTY group named 'wheel' to
    # exist, so a future 'group=wheel' line can never match a real account. Creating
    # it is free; su stays bound to group 'sudo', which is the practical equivalent.
    getent group wheel >/dev/null || groupadd -r wheel

    # --- Rev.8 (CIS account_disable_post_pw_expiration) ---
    sed -i -E 's/^#?[[:space:]]*INACTIVE=.*/INACTIVE=30/' /etc/default/useradd

    # --- Rev.8 (CIS accounts_umask_etc_bashrc): login.defs UMASK 027 covers login
    # shells; /etc/bash.bashrc covers non-login interactive shells, /etc/profile.d
    # the rest. All three, or the umask leaks back to 022 depending on how the shell
    # was started.
    append_once "umask 027" /etc/bash.bashrc
    printf 'umask 027\n' > /etc/profile.d/99-umask.sh
    chmod 644 /etc/profile.d/99-umask.sh

    # --- Rev.8 (Lynis ACCT-9626): sysstat is installed as a dependency but ships
    # ENABLED="false", so sar collects nothing. Performance history is what answers
    # "when did the volume start filling up" and "was the load always like this" -
    # exactly the questions that come up during the volume migration and after.
    if [[ -f /etc/default/sysstat ]]; then
        sed -i 's/^ENABLED=.*/ENABLED="true"/' /etc/default/sysstat
        systemctl enable --now sysstat >/dev/null 2>&1 || warn "sysstat could not be enabled."
    fi

    # --- Rev.8 (CIS file_permission_user_init_files) ---
    for f in /root/.bashrc /root/.profile /home/"$ADMIN_USER"/.bashrc \
             /home/"$ADMIN_USER"/.profile /home/"$ADMIN_USER"/.bash_logout; do
        if [[ -f "$f" ]]; then chmod 0740 "$f"; fi
    done

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

    # --- Rev.8: GRUB menu password (CIS grub2_password) ---
    # Protects 'e' (edit entry) and 'c' (GRUB shell) in the boot menu - the route by
    # which anyone with console access boots with init=/bin/bash and owns the machine.
    # The password is lowercase+digits ON PURPOSE: it can only ever be typed at the
    # provider's VNC console, which hands GRUB raw US key positions, so anything from
    # a German keyboard arrives scrambled (test server 2026-10-03). Words beat entropy
    # per character here - 4x6 lowercase + 4 digits is ~110 bits and always typeable.
    if [[ "$ENABLE_GRUB_PASSWORD" == "yes" ]] && command -v grub-mkpasswd-pbkdf2 >/dev/null 2>&1; then
        local gpw_file="$SECRETS_DIR/grub-password"
        if [[ ! -f "$gpw_file" ]]; then
            install -d -m 700 "$SECRETS_DIR"
            local w1 w2 w3 w4
            w1="$(pwgen -B -0 -A -1 6 1)"; w2="$(pwgen -B -0 -A -1 6 1)"
            w3="$(pwgen -B -0 -A -1 6 1)"; w4="$(pwgen -B -0 -A -1 6 1)"
            printf '%s-%s-%s-%s-%04d\n' "$w1" "$w2" "$w3" "$w4" \
                "$(shuf -i 1000-9999 -n1)" > "$gpw_file"
            chmod 600 "$gpw_file"
        fi
        local gpw ghash
        gpw="$(cat "$gpw_file")"
        # Rev.12: grub-mkpasswd-pbkdf2 reads from /dev/tty when the process has a
        # controlling terminal. In a background run (nohup ... &) that stopped the whole
        # script with SIGTTIN. setsid -w drops the terminal, so the tool reads the pipe.
        ghash="$(printf '%s\n%s\n' "$gpw" "$gpw" | setsid -w grub-mkpasswd-pbkdf2 2>/dev/null \
            | awk '/pbkdf2\.sha512/{print $NF}')"
        if [[ ${#ghash} -gt 100 ]]; then
            # --unrestricted FIRST, then the password - in that order a failure of the
            # sed below can never leave a machine that stops at a password prompt on
            # an unattended reboot.
            grep -q -- '--unrestricted' /etc/grub.d/10_linux \
                || sed -i 's/^CLASS="/CLASS="--unrestricted /' /etc/grub.d/10_linux
            if grep -q -- '--unrestricted' /etc/grub.d/10_linux; then
                if ! grep -q 'password_pbkdf2 root' /etc/grub.d/40_custom; then
                    printf 'set superusers="root"\npassword_pbkdf2 root %s\n' \
                        "$ghash" >> /etc/grub.d/40_custom
                fi
                update-grub >/dev/null 2>&1 || warn "update-grub failed after the GRUB password."
                if grep -q -- '--unrestricted' /boot/grub/grub.cfg \
                   && grep -q 'password_pbkdf2' /boot/grub/grub.cfg; then
                    log "GRUB menu password set; normal boot entries stay unrestricted."
                    log "  Password file: $gpw_file  (put it in the password manager, it is NOT recoverable)"
                else
                    # Roll back rather than risk a machine that will not boot alone.
                    sed -i '/^set superusers="root"$/d;/^password_pbkdf2 root /d' /etc/grub.d/40_custom
                    update-grub >/dev/null 2>&1 || true
                    warn "GRUB password rolled back: grub.cfg lacked --unrestricted or the hash."
                fi
            else
                warn "Could not mark the GRUB entries --unrestricted - password NOT set (a reboot would stall at the prompt)."
            fi
        else
            warn "grub-mkpasswd-pbkdf2 produced no usable hash - GRUB password NOT set."
        fi
    else
        log "GRUB menu password skipped (ENABLE_GRUB_PASSWORD=no or grub-mkpasswd-pbkdf2 missing)."
    fi

    # tmp dirs without exec (malware cannot start from temp):
    append_once "tmpfs /tmp     tmpfs defaults,nosuid,nodev,noexec 0 0" /etc/fstab
    append_once "tmpfs /dev/shm tmpfs defaults,nosuid,nodev,noexec 0 0" /etc/fstab

    # --- Rev.9: optional ADDITIONAL swap file. The provider reserves a swap area at
    # build time; Linux activates further swap files alongside it, so the total is the
    # sum. SWAPFILE_SIZE_GB=0 means: rely on the panel's swap alone.
    if [[ "$SWAPFILE_SIZE_GB" =~ ^[1-9][0-9]*$ ]]; then
        if ! swapon --show=NAME --noheadings 2>/dev/null | grep -qx /swapfile; then
            rm -f /swapfile
            fallocate -l "${SWAPFILE_SIZE_GB}G" /swapfile 2>/dev/null \
                || dd if=/dev/zero of=/swapfile bs=1M count=$(( SWAPFILE_SIZE_GB * 1024 )) status=none
            chown root:root /swapfile
            chmod 600 /swapfile
            mkswap /swapfile >/dev/null
            swapon /swapfile
        fi
        append_once "/swapfile none swap sw 0 0" /etc/fstab
        log "Swap file /swapfile active (${SWAPFILE_SIZE_GB} GB), on top of the panel swap."
    else
        log "No extra swap file (SWAPFILE_SIZE_GB=0); using the provider-reserved swap only."
    fi
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
    # Password hashing rounds (Lynis AUTH-9230); effective because ENCRYPT_METHOD is SHA512:
    if grep -qE '^#?[[:space:]]*SHA_CRYPT_MIN_ROUNDS' /etc/login.defs; then
        sed -i -E 's|^#?[[:space:]]*SHA_CRYPT_MIN_ROUNDS[[:space:]]+.*|SHA_CRYPT_MIN_ROUNDS 65536|' /etc/login.defs
    else
        printf 'SHA_CRYPT_MIN_ROUNDS 65536\n' >> /etc/login.defs
    fi
    if grep -qE '^#?[[:space:]]*SHA_CRYPT_MAX_ROUNDS' /etc/login.defs; then
        sed -i -E 's|^#?[[:space:]]*SHA_CRYPT_MAX_ROUNDS[[:space:]]+.*|SHA_CRYPT_MAX_ROUNDS 65536|' /etc/login.defs
    else
        printf 'SHA_CRYPT_MAX_ROUNDS 65536\n' >> /etc/login.defs
    fi
    # Legal banner before and after login (Lynis BANN-7126/7130).
    # Rev.8: the first wording hit only FOUR of the key words Lynis looks for
    # (access, authori, log, monitor) and the test demands FIVE, so both BANN checks
    # stayed open through the first two runs - see /usr/share/lynis/include/tests_banners.
    # The sentence added below is substantive, not keyword stuffing: it states that
    # unauthorised use is prohibited and will be prosecuted, which is what makes a
    # banner legally useful in the first place. Now at seven matches.
    # No umlauts: the VNC console renders them wrong.
    cat > /etc/issue <<'BANNEREOF'
Zugang nur fuer Berechtigte. Alle Zugriffe auf dieses System werden
protokolliert und ueberwacht. Unbefugte Nutzung ist verboten und wird
strafrechtlich verfolgt.

Authorised access only. All access to this system is logged and monitored.
Unauthorised use is prohibited and will be prosecuted.
BANNEREOF
    cp /etc/issue /etc/issue.net
    chmod 644 /etc/issue /etc/issue.net
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
        [[ -f /etc/wireguard/wg0.psk ]] || { wg genpsk > /etc/wireguard/wg0.psk; touch /etc/wireguard/.psk-new; }
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

    # Rev.12: written to the file only. 'tee' put the preshared key into every log of 'rest'.
    install -m 600 /dev/null "$SECRETS_DIR/wireguard-client.conf.example"
    cat > "$SECRETS_DIR/wireguard-client.conf.example" <<EOF
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
    if [[ -f /etc/wireguard/.psk-new ]]; then
        rm -f /etc/wireguard/.psk-new
        warn "NEW preshared key: the tunnel from the client is DOWN until its [Peer] section has"
        warn "    PresharedKey = <content of /etc/wireguard/wg0.psk>  (template: $SECRETS_DIR/wireguard-client.conf.example)"
    fi
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
    # Without this block, every published container port would be open despite ufw.
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
    write_caddy_base
    write_caddy_nextcloud
    caddy validate --config /etc/caddy/Caddyfile || die "Caddyfile invalid."

    # === Council-Fix 8: DNS gate BEFORE Caddy start (Rev.10: extracted to dns_gate) ===
    dns_gate "$NC_DOMAIN"

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
            # Rev.8: 5% is right for a small volume and absurd for a large one - on the
            # 4 TB HDD it parks 200 GB that only root may ever touch. The reserve exists
            # to keep ext4 from fragmenting and to stop an unprivileged writer filling
            # the volume to the last block; 1% of 4 TB (40 GB) does both. Threshold at
            # 1 TB. The early-warning mail at 85% is the real guard rail.
            local hdd_kb hdd_res
            hdd_kb="$(df -Pk "$HDD_MOUNT" 2>/dev/null | awk 'NR==2{print $2}')"
            if [[ -n "$hdd_kb" && "$hdd_kb" -ge 1000000000 ]]; then hdd_res=1; else hdd_res=5; fi
            tune2fs -m "$hdd_res" "$hdd_dev" \
                || warn "tune2fs -m $hdd_res on $hdd_dev failed - check manually."
            log "ext4 reserved blocks on $HDD_MOUNT set to ${hdd_res}%."
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
# One mail per newly-crossed threshold, not one per timer run.
# Usage: disk-space-alert.sh <mount>[:<warn>[:<crit>]] ...
# Rev.8: thresholds per mountpoint. The root filesystem needs the earlier warning:
# Docker image layers, the journal, the apt cache and the NC DB dump can take it from
# comfortable to full inside one upgrade, and it has no second volume to spill onto.
set -euo pipefail
WARN_DEFAULT=85
CRIT_DEFAULT=95
STATE_DIR=/var/lib/disk-space-alert
install -d "$STATE_DIR"

for spec in "$@"; do
    mnt="${spec%%:*}"
    rest="${spec#"$mnt"}"; rest="${rest#:}"
    WARN="${rest%%:*}"; [[ -n "$WARN" ]] || WARN=$WARN_DEFAULT
    CRIT="${rest#*:}";  [[ -n "$CRIT" && "$CRIT" != "$rest" ]] || CRIT=$CRIT_DEFAULT
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
ExecStart=/usr/local/bin/disk-space-alert.sh ${HDD_MOUNT}:85:95 /:80:90
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
echo "Check container updates: NC tag on hub.docker.com/_/nextcloud, then per stack 'docker compose pull && up -d'. Then occ upgrade if needed." \
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
    elif ! BORG_PASSCOMMAND='cat /root/.borg-passphrase' borg info "$BACKUP_DIR/repo-server" >/dev/null 2>&1; then
        # Rev.12: after a rebuild the data volume keeps the old repo while
        # /root/install-secrets is gone - a new passphrase made every backup fail
        # while verify stayed green.
        die "$BACKUP_DIR/repo-server exists but does not open with $SECRETS_DIR/borg-passphrase. Move it aside (mv $BACKUP_DIR/repo-server $BACKUP_DIR/repo-server.alt-\$(date +%y%m%d)) or put the OLD passphrase into $SECRETS_DIR/borg-passphrase, then run phase10 again."
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

# Rev.10: pre-hooks contributed by later phases (e.g. the immo database dump in
# phase 13). They write into /var/backups, which this archive already covers.
if [[ -d /usr/local/lib/backup-pre.d ]]; then
    for hook in /usr/local/lib/backup-pre.d/*.sh; do
        [[ -x "\$hook" ]] || continue
        "\$hook" || logger -t borg-backup "WARN: backup pre-hook \$hook failed"
    done
fi

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

# Config + DB dump + system, and from v0.6.3 everything on the data volume EXCEPT
# the two things that must not be in here: the Borg repositories themselves and the
# Nextcloud blobs (a copy of what is synced on the Mac; decision 2026-07-08).
# Before v0.6.3 the whole of $HDD_MOUNT was excluded, which silently left
# $HDD_MOUNT/immo - the market reports, which exist nowhere else - unsaved.
borg create --compression zstd,6 --stats \\
    --exclude '/srv/nextcloud/db' --exclude '$BACKUP_DIR' --exclude '$NCDATA_DIR' \\
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
    log "Phase 11: Cockpit (reachable via WireGuard only)"
    wg show wg0 &>/dev/null || die "WireGuard (phase8) must be running - the panel is exposed ONLY over the tunnel."

    # === Panel CA + certificate for the WireGuard address (Rev.7, tightened in v0.6.3) ===
    # Cockpit is reached as https://<WG>.1:9090. A certificate without that IP in its SAN
    # makes every browser warn, however much the user trusts it. Apple additionally requires
    # a SAN (CN alone is ignored).
    # v0.6.3: the CA carries nameConstraints, so this root - once imported into a browser -
    # can only ever vouch for the WireGuard subnet and the server's own FQDN. Without that
    # constraint an imported private root is a universal signer for every name on the web.
    # Lifetimes shortened from 3650/800 to 1825/397 days, with an automatic reissue of the
    # leaf 30 days before it expires.
    local ca_dir="$SECRETS_DIR/panel-ca"
    install -d -m 700 "$ca_dir"
    if [[ ! -f "$ca_dir/ca.crt" ]]; then
        openssl req -x509 -newkey rsa:4096 -sha256 -days 1825 -nodes \
            -keyout "$ca_dir/ca.key" -out "$ca_dir/ca.crt" \
            -subj "/CN=${HOSTNAME_FQDN:-$(hostname)} Panel CA" \
            -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
            -addext "keyUsage=critical,keyCertSign,cRLSign" \
            -addext "nameConstraints=critical,permitted;IP:${WG_NET}.0/255.255.255.0${HOSTNAME_FQDN:+,permitted;DNS:$HOSTNAME_FQDN}" 2>/dev/null \
            || die "Panel CA could not be created."
        chmod 600 "$ca_dir/ca.key"
        log "Panel CA created (1825 days, nameConstraints on ${WG_NET}.0/24): $ca_dir/ca.crt"
    fi
    openssl x509 -checkend 7776000 -noout -in "$ca_dir/ca.crt" &>/dev/null \
        || warn "Panel CA expires within 90 days - delete $ca_dir, run phase11 again and import the new root."
    if [[ -f "$ca_dir/panel.crt" ]] && ! openssl x509 -checkend 2592000 -noout -in "$ca_dir/panel.crt" &>/dev/null; then
        warn "Panel certificate expires within 30 days - issuing a new one."
        rm -f "$ca_dir/panel.crt" "$ca_dir/panel.key"
    fi
    if [[ ! -f "$ca_dir/panel.crt" ]]; then
        cat > "$ca_dir/panel.ext" <<EXTEOF
basicConstraints=CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=IP:${WG_NET}.1${HOSTNAME_FQDN:+,DNS:$HOSTNAME_FQDN}
EXTEOF
        openssl req -newkey rsa:2048 -sha256 -nodes \
            -keyout "$ca_dir/panel.key" -out "$ca_dir/panel.csr" \
            -subj "/CN=${WG_NET}.1" 2>/dev/null \
            || die "Panel key could not be created."
        openssl x509 -req -in "$ca_dir/panel.csr" -CA "$ca_dir/ca.crt" -CAkey "$ca_dir/ca.key" \
            -CAcreateserial -days 397 -sha256 -extfile "$ca_dir/panel.ext" \
            -out "$ca_dir/panel.crt" 2>/dev/null \
            || die "Panel certificate could not be signed."
        rm -f "$ca_dir/panel.csr"
        chmod 600 "$ca_dir/panel.key"
        openssl verify -CAfile "$ca_dir/ca.crt" "$ca_dir/panel.crt" >/dev/null \
            || die "Panel certificate does not validate against its own CA - check nameConstraints and the SAN."
        log "Panel certificate created for ${WG_NET}.1 (397 days), chain verified."
    fi

    # Cockpit: socket-activated, uses practically nothing without an open session.
    apt-get install -y -q cockpit
    # Hand Cockpit the panel certificate. A higher number wins over 0-self-signed:
    install -d /etc/cockpit/ws-certs.d
    cp "$ca_dir/panel.crt" /etc/cockpit/ws-certs.d/1-panel.cert
    cp "$ca_dir/panel.key" /etc/cockpit/ws-certs.d/1-panel.key
    chmod 644 /etc/cockpit/ws-certs.d/1-panel.cert
    chmod 640 /etc/cockpit/ws-certs.d/1-panel.key
    chgrp cockpit-ws /etc/cockpit/ws-certs.d/1-panel.key 2>/dev/null || true
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

    # v0.6.3: session timeout and a login blocklist. IdleTimeout is in MINUTES
    # (cockpit.conf(5), section [Session]). /etc/cockpit/disallowed-users lists accounts
    # that may never log in; root is in it by default since Cockpit 280, written here
    # explicitly so a package update cannot quietly re-enable it.
    cat > /etc/cockpit/cockpit.conf <<EOF
[WebService]
AllowUnencrypted=false
LoginTitle=${HOSTNAME_FQDN:-$(hostname)}
LoginTo=false

[Session]
IdleTimeout=15
Banner=/etc/issue.net
EOF
    chmod 644 /etc/cockpit/cockpit.conf
    printf 'root\n' > /etc/cockpit/disallowed-users
    chmod 644 /etc/cockpit/disallowed-users
    systemctl restart cockpit.socket

    # v0.6.3: Portainer is gone. It mounted /var/run/docker.sock, which hands root on the
    # host to whoever reaches the UI, and it was never what it was installed for - apt,
    # not a container panel, is what adds software to this machine. phase12 removes a
    # container, volume and image left over from an earlier run.
    log "Phase 11 done. In the tunnel:  Cockpit https://${WG_NET}.1:9090"
    log "Import the CA root once on your client, then the browser warning is gone for good:"
    log "    $ca_dir/ca.crt"
    warn "REQUIRED after 'all': check from OUTSIDE (a foreign network) that 9090 is closed -"
    warn "    nmap -Pn <server-ipv4> -p 9090   UND   nmap -6 -Pn <server-ipv6> -p 9090"
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

    # v0.6.3: Portainer is no longer installed. On a machine built before v0.6.3 the
    # container, its volume and the image are still present - and that container has
    # /var/run/docker.sock mounted, which is root on the host for anyone reaching it.
    if command -v docker &>/dev/null; then
        if docker ps -a --format '{{.Names}}' 2>/dev/null | grep -qx portainer; then
            if docker rm -f portainer >/dev/null 2>&1; then
                log "Portainer container removed."
            else
                warn "Portainer container could not be removed - check 'docker ps -a'."
            fi
        fi
        if docker volume ls --format '{{.Name}}' 2>/dev/null | grep -qx portainer_data; then
            docker volume rm portainer_data >/dev/null 2>&1 || warn "Volume portainer_data not removed."
        fi
        if docker image ls --format '{{.Repository}}' 2>/dev/null | grep -qx portainer/portainer-ce; then
            docker image rm portainer/portainer-ce:lts >/dev/null 2>&1 || true
        fi
    fi
    if ufw status 2>/dev/null | grep -q 'Portainer via WireGuard'; then
        warn "ufw still has a 'Portainer via WireGuard' rule - remove it: ufw status numbered, then ufw delete <number>."
    fi

    # Legacy packages (rsync included on purpose - operator decision 2026-07-19; if needed: apt install rsync):
    # Rev.8: rsync STAYS. It is the tool for the transitional-NVMe -> 4 TB HDD move
    # and for every later volume change; purging it and reinstalling it under time
    # pressure during a maintenance window is the wrong trade. The daemon is the risk,
    # not the binary - so mask that instead (CIS service_rsyncd_disabled).
    apt-get purge -y -q telnet inetutils-telnet ftp tnftp 2>/dev/null || true
    systemctl mask rsync.service 2>/dev/null || true
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


phase13() {
    require_root
    if [[ "$ENABLE_IMMO" != "yes" ]]; then
        log "Phase 13 skipped (ENABLE_IMMO=no)."
        return 0
    fi
    [[ -n "$IMMO_DOMAIN" ]] || die "Phase 13: IMMO_DOMAIN is empty - set it in install.conf."
    [[ -n "$NC_DOMAIN" ]]   || die "Phase 13: NC_DOMAIN is empty - the CSP frame-ancestors rule needs it."
    log "Phase 13: immo.flow - PHP-FPM, MariaDB, Caddy site, systemd timer"

    # PHP 8.3 is what Ubuntu 24.04 ships, and it is enough: on 2026-10-03 all 42
    # files under web/ passed 'php -l' on 8.3.6 and none used 8.4-only syntax. The
    # third-party PHP repository an 8.4 would have required stays off this machine -
    # an extra apt source on a hardened box is a supply-chain decision, not a detail.
    apt-get install -y -q php8.3-fpm php8.3-mysql php8.3-mbstring php8.3-curl \
        mariadb-server poppler-utils python3-venv

    id -u "$IMMO_USER" &>/dev/null || useradd --system --create-home --home-dir "$IMMO_DIR" \
        --shell /usr/sbin/nologin --comment "immo.flow service account" "$IMMO_USER"
    install -d -o "$IMMO_USER" -g "$IMMO_USER" -m 750 "$IMMO_DIR" "$IMMO_DIR/web" "$IMMO_DIR/daten"
    # Market reports grow past 100 MB and keep growing; they belong on the data
    # volume, not on the 500 GB system NVMe.
    install -d -o "$IMMO_USER" -g "$IMMO_USER" -m 750 "$HDD_MOUNT/immo" "$HDD_MOUNT/immo/Kaufpreise"
    # Rev.12: the data volume survives a rebuild; the new system user may get another uid.
    chown -R "$IMMO_USER:$IMMO_USER" "$HDD_MOUNT/immo"
    # Rev.12: Caddy serves the static files and resolves try_files itself - without group
    # read on the 750 web root every CSS/JS file and every pretty URL answered 403.
    if id caddy &>/dev/null && ! id -nG caddy | grep -qw "$IMMO_USER"; then
        usermod -aG "$IMMO_USER" caddy
        systemctl restart caddy
    fi
    [[ -e "$IMMO_DIR/Kaufpreise" ]] || ln -s "$HDD_MOUNT/immo/Kaufpreise" "$IMMO_DIR/Kaufpreise"

    # --- MariaDB, native, loopback only. Deliberately NOT the Nextcloud container's
    # database: one shared instance would couple backup, version change and restart
    # of two unrelated applications.
    cat > /etc/mysql/mariadb.conf.d/99-immo.cnf <<'EOF'
[mysqld]
bind-address = 127.0.0.1
character-set-server = utf8mb4
collation-server = utf8mb4_unicode_ci
EOF
    systemctl enable --now mariadb
    systemctl restart mariadb

    local immo_db_pass sqlf
    immo_db_pass="$(gen_secret immo-db-pass 32)"
    sqlf="$SECRETS_DIR/.immo-grant.sql"
    install -d -m 700 "$SECRETS_DIR"
    install -m 600 /dev/null "$sqlf"      # password must never reach the process list
    cat > "$sqlf" <<EOF
CREATE DATABASE IF NOT EXISTS \`$IMMO_DB\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER IF NOT EXISTS '$IMMO_DB_USER'@'127.0.0.1' IDENTIFIED BY '$immo_db_pass';
ALTER USER '$IMMO_DB_USER'@'127.0.0.1' IDENTIFIED BY '$immo_db_pass';
GRANT ALL PRIVILEGES ON \`$IMMO_DB\`.* TO '$IMMO_DB_USER'@'127.0.0.1';
FLUSH PRIVILEGES;
EOF
    mariadb < "$sqlf" || die "Phase 13: MariaDB setup failed."
    shred -u "$sqlf"

    # --- Two env files, and the separation between them is the point: the web process
    # never sees the IMAP password. $IMMO_DIR/.env belongs to the Python run alone;
    # $IMMO_WEB_ENV is handed to PHP-FPM through env[IMMO_WEB_ENV] below and carries
    # the database credentials and the frontend keys, nothing else. This closes the
    # finding "PHP reads the Python side's secrets" (Team B, section 2.5).
    install -m 600 -o "$IMMO_USER" -g "$IMMO_USER" /dev/null "$IMMO_DIR/.env.new"
    if [[ -f "$IMMO_DIR/.env" ]]; then cat "$IMMO_DIR/.env" > "$IMMO_DIR/.env.new"; fi
    mv "$IMMO_DIR/.env.new" "$IMMO_DIR/.env"
    env_set "$IMMO_DIR/.env" DB_HOST 127.0.0.1
    env_set "$IMMO_DIR/.env" DB_PORT 3306
    env_set "$IMMO_DIR/.env" DB_NAME "$IMMO_DB"
    env_set "$IMMO_DIR/.env" DB_USER "$IMMO_DB_USER"
    env_set "$IMMO_DIR/.env" DB_PASS "$immo_db_pass"
    if [[ -n "$IMAP_HOST" ]]; then
        env_set "$IMMO_DIR/.env" IMAP_HOST "$IMAP_HOST"
        env_set "$IMMO_DIR/.env" IMAP_PORT "$IMAP_PORT"
        env_set "$IMMO_DIR/.env" IMAP_USER "$IMAP_USER"
        env_set "$IMMO_DIR/.env" IMAP_ORDNER "$IMAP_ORDNER"
        if [[ -n "$IMAP_PASS" ]]; then
            # Rev.12: values a .env reader (python-dotenv) silently misreads.
            case "$IMAP_PASS" in
                *'${'*|*' #'*|' '*|*' '|\'*|\"*)
                    die "IMAP_PASS has a leading/trailing blank, a leading quote, ' #' or '\${' - a .env reader misreads that. Enter it in $IMMO_DIR/.env by hand.";;
            esac
            env_set "$IMMO_DIR/.env" IMAP_PASS "$IMAP_PASS"
            # Same rule as for SMTP_PASS in phase 4: the value is needed for this one
            # write, so it is cleared here instead of being left in install.conf.
            if [[ -f "$INSTALL_CONF" ]] && grep -q '^IMAP_PASS=' "$INSTALL_CONF"; then
                sed -i "s|^IMAP_PASS=.*|IMAP_PASS=''|" "$INSTALL_CONF"
                log "IMAP_PASS written to $IMMO_DIR/.env and CLEARED in $INSTALL_CONF."
                warn "The COPY OF install.conf ON YOUR OWN MACHINE still holds the password - clear it there too."
            fi
        else
            warn "IMAP_PASS empty - enter it in $IMMO_DIR/.env by hand, the daily run cannot log in without it."
        fi
    else
        warn "IMAP_HOST empty - mail retrieval not configured (set IMAP_* in install.conf, then run phase13 again)."
    fi
    chown "$IMMO_USER:$IMMO_USER" "$IMMO_DIR/.env"; chmod 600 "$IMMO_DIR/.env"

    install -d -m 750 -o root -g "$IMMO_USER" /etc/immo
    install -m 640 -o root -g "$IMMO_USER" /dev/null "$IMMO_WEB_ENV.new"
    if [[ -f "$IMMO_WEB_ENV" ]]; then cat "$IMMO_WEB_ENV" > "$IMMO_WEB_ENV.new"; fi
    mv "$IMMO_WEB_ENV.new" "$IMMO_WEB_ENV"
    env_set "$IMMO_WEB_ENV" DB_HOST 127.0.0.1
    env_set "$IMMO_WEB_ENV" DB_PORT 3306
    env_set "$IMMO_WEB_ENV" DB_NAME "$IMMO_DB"
    env_set "$IMMO_WEB_ENV" DB_USER "$IMMO_DB_USER"
    env_set "$IMMO_WEB_ENV" DB_PASS "$immo_db_pass"
    env_set "$IMMO_WEB_ENV" ERFASS_SCHLUESSEL "$(gen_secret immo-erfass-schluessel 32)"
    env_set "$IMMO_WEB_ENV" MAIL_ABSENDER "${IMMO_MAIL_FROM:-${SMTP_FROM:-root@$(hostname)}}"
    chown root:"$IMMO_USER" "$IMMO_WEB_ENV"; chmod 640 "$IMMO_WEB_ENV"
    if grep -q '^IMAP_' "$IMMO_WEB_ENV"; then die "$IMMO_WEB_ENV holds IMAP values - the web side must never see them."; fi
    log "Env files written: $IMMO_DIR/.env (600 $IMMO_USER) and $IMMO_WEB_ENV (640 root:$IMMO_USER)."

    # --- PHP-FPM pool. Own pool, own user, own socket; the stock www pool is
    # switched off because nothing uses it and every listening pool is surface.
    if [[ -f /etc/php/8.3/fpm/pool.d/www.conf ]]; then
        mv /etc/php/8.3/fpm/pool.d/www.conf /etc/php/8.3/fpm/pool.d/www.conf.disabled
    fi
    cat > /etc/php/8.3/fpm/pool.d/immo.conf <<EOF
[immo]
user = $IMMO_USER
group = $IMMO_USER
listen = /run/php/immo.sock
listen.owner = caddy
listen.group = caddy
listen.mode = 0660
pm = ondemand
pm.max_children = 10
pm.process_idle_timeout = 60s
pm.max_requests = 500
php_admin_value[open_basedir] = $IMMO_DIR:$HDD_MOUNT/immo:/tmp:/usr/share/php
php_admin_value[upload_tmp_dir] = /tmp
php_admin_value[memory_limit] = 256M
php_admin_value[post_max_size] = 32M
php_admin_value[upload_max_filesize] = 32M
php_admin_value[error_log] = /var/log/php8.3-fpm-immo.log
php_admin_flag[expose_php] = off
; The session cookie attributes that the embedding into Nextcloud needs. Setting
; them in the pool rather than in the application means no PHP file has to change
; and no later code edit can silently drop them again.
php_admin_value[session.cookie_secure] = 1
php_admin_value[session.cookie_httponly] = 1
php_admin_value[session.cookie_samesite] = None
; v0.6.3: the frontend reads its database credentials and keys from this file. The
; path is passed, not the values - and the file deliberately holds no IMAP password.
env[IMMO_WEB_ENV] = $IMMO_WEB_ENV
EOF
    systemctl enable --now php8.3-fpm
    systemctl restart php8.3-fpm

    # --- Caddy site. X-Frame-Options would forbid the iframe outright; the CSP
    # frame-ancestors rule allows exactly the one origin that may embed the page.
    dns_gate "$IMMO_DOMAIN"
    cat > "$CADDY_CONFD/20-immo.caddy" <<EOF
$IMMO_DOMAIN {
    root * $IMMO_DIR/web
    encode zstd gzip
    header Strict-Transport-Security "max-age=15552000; includeSubDomains"
    header X-Content-Type-Options nosniff
    header -X-Frame-Options
    header Content-Security-Policy "frame-ancestors https://$NC_DOMAIN"
    @verborgen path /inc/* /.env* /.git/*
    respond @verborgen 404
    php_fastcgi unix//run/php/immo.sock
    file_server
}
EOF
    chmod 644 "$CADDY_CONFD/20-immo.caddy"
    caddy_apply

    # --- Python environment. Only built once the code is actually deployed; the
    # phase must not fail just because the repository has not been copied yet.
    if [[ -f "$IMMO_DIR/requirements.txt" ]]; then
        sudo -u "$IMMO_USER" python3 -m venv "$IMMO_DIR/.venv"
        sudo -u "$IMMO_USER" "$IMMO_DIR/.venv/bin/pip" install -q -r "$IMMO_DIR/requirements.txt"
        if [[ "$ENABLE_IMMO_PLAYWRIGHT" == "yes" ]]; then
            "$IMMO_DIR/.venv/bin/playwright" install-deps chromium || warn "playwright install-deps failed."
            sudo -u "$IMMO_USER" "$IMMO_DIR/.venv/bin/playwright" install chromium || warn "playwright install chromium failed."
        fi
    else
        warn "No $IMMO_DIR/requirements.txt - venv not built. Deploy the code, then run phase13 again."
    fi

    # --- Daily run. Replaces the launchd agent de.brilling.immo.lauf on the Mac.
    cat > /etc/systemd/system/immo-lauf.service <<EOF
[Unit]
Description=immo.flow daily run
After=network-online.target mariadb.service
Wants=network-online.target
OnFailure=immo-fail-mail.service

[Service]
Type=oneshot
User=$IMMO_USER
Group=$IMMO_USER
WorkingDirectory=$IMMO_DIR
Environment=PYTHONPATH=$IMMO_DIR
ExecStart=$IMMO_DIR/.venv/bin/python3 $IMMO_DIR/lauf.py
TimeoutStartSec=3600
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=$IMMO_DIR $HDD_MOUNT/immo
ProtectHome=true
ProtectKernelTunables=true
ProtectControlGroups=true
RestrictSUIDSGID=true
EOF
    cat > /etc/systemd/system/immo-lauf.timer <<EOF
[Unit]
Description=immo.flow daily run

[Timer]
OnCalendar=*-*-* $IMMO_RUN_TIME
Persistent=true
RandomizedDelaySec=300

[Install]
WantedBy=timers.target
EOF
    # Same pattern as backup-fail-mail: a silent failure is worse than no run.
    cat > /etc/systemd/system/immo-fail-mail.service <<'EOF'
[Unit]
Description=Alarm on a failed immo.flow run
[Service]
Type=oneshot
ExecStart=/bin/sh -c 'MSG="IMMO RUN FAILED on $(hostname) $(date)"; logger -t immo-lauf "$MSG"; journalctl -u immo-lauf.service -n 50 --no-pager | mail -s "$MSG" root 2>/dev/null || true'
EOF
    systemctl daemon-reload
    # Rev.10 FIX: only arm the timer once there is something to run. Without the
    # venv the service dies with 203/EXEC at the next firing and sends a failure
    # mail - every day, for a job that cannot work yet. Seen on the production
    # server 2026-10-04, where phase 13 ran hours before the code was deployed.
    if [[ -x "$IMMO_DIR/.venv/bin/python3" ]]; then
        systemctl enable --now immo-lauf.timer
    else
        systemctl disable --now immo-lauf.timer 2>/dev/null || true
        warn "immo-lauf.timer stays OFF - $IMMO_DIR/.venv is missing."
        warn "Deploy the code, then: systemctl enable --now immo-lauf.timer"
    fi

    # --- Borg pre-hook: the immo database had no automatic backup at all until now.
    install -d -m 750 /usr/local/lib/backup-pre.d
    cat > /usr/local/lib/backup-pre.d/10-immo-db.sh <<EOF
#!/bin/bash
# Dump the immo database into a directory the Borg archive already covers.
set -euo pipefail
mkdir -p /var/backups/immo
mariadb-dump --single-transaction --databases '$IMMO_DB' > /var/backups/immo/immo.sql
chmod 600 /var/backups/immo/immo.sql
EOF
    chmod 700 /usr/local/lib/backup-pre.d/10-immo-db.sh

    log "Phase 13 done. Database password: $SECRETS_DIR/immo-db-pass"
    log "Still to do by hand: deploy the code to $IMMO_DIR/web, write $IMMO_DIR/.env"
    log "  (DB_HOST=127.0.0.1, DB_NAME=$IMMO_DB, DB_USER=$IMMO_DB_USER), import the dump."
}

phase14() {
    require_root
    if [[ "$ENABLE_EXTRA_SITES" != "yes" ]]; then
        log "Phase 14 skipped (ENABLE_EXTRA_SITES=no)."
        return 0
    fi
    [[ -n "$EXTRA_SITES" ]] || die "Phase 14: EXTRA_SITES is empty - list the domains in install.conf."
    log "Phase 14: further static sites"

    local dom dir
    install -d -m 755 /srv/www
    for dom in $EXTRA_SITES; do
        dir="/srv/www/$dom"
        dns_gate "$dom"
        install -d -o www-data -g www-data -m 755 "$dir"
        if [[ ! -e "$dir/index.html" ]]; then
            printf '<!doctype html>\n<meta charset="utf-8">\n<title>%s</title>\n<p>%s ist eingerichtet.</p>\n' \
                "$dom" "$dom" > "$dir/index.html"
            chown www-data:www-data "$dir/index.html"
            chmod 644 "$dir/index.html"
        fi
        # Static only: a gallery and a portfolio need no PHP, and no interpreter is
        # the cheapest hardening there is. If one of them later needs PHP, it gets
        # its own FPM pool the way phase 13 builds one.
        cat > "$CADDY_CONFD/30-$dom.caddy" <<EOF
$dom {
    root * $dir
    encode zstd gzip
    header Strict-Transport-Security "max-age=15552000; includeSubDomains"
    header X-Content-Type-Options nosniff
    file_server
}
EOF
        chmod 644 "$CADDY_CONFD/30-$dom.caddy"
        log "Site set up: $dom -> $dir"
    done
    caddy_apply
    log "Phase 14 done."
}

phase15() {
    require_root
    if [[ "$ENABLE_TALK_HPB" != "yes" ]]; then
        log "Phase 15 skipped (ENABLE_TALK_HPB=no)."
        return 0
    fi
    [[ -n "$NC_DOMAIN" ]] || die "Phase 15: NC_DOMAIN is empty."
    log "Phase 15: Nextcloud Talk High Performance Backend (signaling, Janus, coturn)"
    warn "Phase 15 has NEVER run on a real server. Run it on the test server first."

    # B1: keys written by the old gen_secret have a random length. The signaling server
    # accepts exactly 16, 24 or 32 bytes for blockkey and aborts otherwise - drop a
    # wrong-length key here so gen_fixed writes a new one below.
    local sk sklen
    for sk in signaling-hashkey:32 signaling-blockkey:16; do
        [[ -f "$SECRETS_DIR/${sk%%:*}" ]] || continue
        sklen="$(tr -d '\n' < "$SECRETS_DIR/${sk%%:*}" | wc -c | tr -d ' ')"
        if [[ "$sklen" != "${sk##*:}" ]]; then
            warn "Session key ${sk%%:*}: length $sklen instead of ${sk##*:} - regenerating."
            rm -f "$SECRETS_DIR/${sk%%:*}"
        fi
    done

    local turn_secret sig_secret
    turn_secret="$(gen_secret turn-secret 32)"
    sig_secret="$(gen_secret signaling-secret 32)"

    # --- coturn, native. No certificate and no DNS record of its own: clients reach
    # it as $NC_DOMAIN:$TURN_PORT over plain UDP/TCP. The deny rules matter - without
    # them the relay can be used to reach this server's own private networks.
    apt-get install -y -q coturn
    cat > /etc/turnserver.conf <<EOF
listening-port=$TURN_PORT
fingerprint
use-auth-secret
static-auth-secret=$turn_secret
realm=$NC_DOMAIN
total-quota=100
bps-capacity=0
stale-nonce
no-multicast-peers
no-tls
no-dtls
no-cli
denied-peer-ip=10.0.0.0-10.255.255.255
denied-peer-ip=172.16.0.0-172.31.255.255
denied-peer-ip=192.168.0.0-192.168.255.255
denied-peer-ip=169.254.0.0-169.254.255.255
denied-peer-ip=127.0.0.0-127.255.255.255
EOF
    chmod 640 /etc/turnserver.conf
    chown root:turnserver /etc/turnserver.conf 2>/dev/null || true
    sed -i 's|^#*TURNSERVER_ENABLED=.*|TURNSERVER_ENABLED=1|' /etc/default/coturn 2>/dev/null || true
    systemctl enable --now coturn
    systemctl restart coturn

    # --- Signaling stack. IMAGE TAGS ARE UNVERIFIED: check them against
    # https://github.com/strukturag/nextcloud-spreed-signaling before the first run.
    install -d -m 750 /srv/talk
    cat > /srv/talk/server.conf <<EOF
[http]
listen = 127.0.0.1:8081

[app]
debug = false

[sessions]
hashkey = $(gen_fixed signaling-hashkey 32)
blockkey = $(gen_fixed signaling-blockkey 16)

[backend]
backends = nc1
allowall = false

[nc1]
url = https://$NC_DOMAIN
secret = $sig_secret

[nats]
url = nats://127.0.0.1:4222

[mcu]
type = janus
url = ws://127.0.0.1:8188
EOF
    # Rev.10 FIX: the signaling image drops privileges to the user 'spreedbackend'
    # (uid/gid 850) in its entrypoint. A root-owned 600 file is unreadable for it
    # and the container crash-loops with
    #   "Could not read configuration: open /config/server.conf: permission denied"
    # Found on the production server 2026-10-04. 644 is not an option - the file
    # carries the backend secret and the session keys.
    chown 850:850 /srv/talk/server.conf
    chmod 600 /srv/talk/server.conf
    cat > /srv/talk/docker-compose.yml <<EOF
# Rev.10 FIX: all three services run on the HOST network. Janus needs it anyway -
# its RTP range would otherwise require one userland proxy per UDP port - and a
# host-networked Janus is not resolvable by name from a bridge container, which
# made the signaling server crash-loop on "lookup janus ... server misbehaving".
# Mixing both modes is the trap; using one mode for all three removes it. Every
# port is bound to the loopback, so nothing new is exposed: Caddy proxies to
# 127.0.0.1:8081, and Janus on 8188 is covered by the ufw default deny.
services:
  nats:
    image: nats:2-alpine
    command: ["-a", "127.0.0.1", "-p", "4222"]
    restart: unless-stopped
    mem_limit: 256m
    pids_limit: 128
    network_mode: host
    security_opt: [ "no-new-privileges:true" ]

  janus:
    image: $JANUS_IMAGE
    restart: unless-stopped
    mem_limit: 2g
    pids_limit: 512
    network_mode: host
    security_opt: [ "no-new-privileges:true" ]

  signaling:
    image: strukturag/nextcloud-spreed-signaling:latest
    restart: unless-stopped
    mem_limit: 1g
    pids_limit: 256
    network_mode: host
    security_opt: [ "no-new-privileges:true" ]
    depends_on: [ nats ]
    volumes:
      - ./server.conf:/config/server.conf:ro
EOF
    chmod 600 /srv/talk/docker-compose.yml

    # ufw: coturn needs its port from the outside, Janus the RTP range.
    ufw allow "${TURN_PORT}/tcp" comment 'TURN'
    ufw allow "${TURN_PORT}/udp" comment 'TURN'
    ufw allow "${JANUS_RTP_MIN}:${JANUS_RTP_MAX}/udp" comment 'Janus RTP'

    # The signaling handle lives inside the Nextcloud site block, so that block is
    # rewritten - one definition, no second copy.
    write_caddy_nextcloud
    caddy_apply

    log "Phase 15 prepared. Start it by hand and check it:"
    log "  cd /srv/talk && docker compose up -d"
    log "Then in the Nextcloud container:"
    log "  occ talk:signaling:add https://$NC_DOMAIN/standalone-signaling/ <secret from $SECRETS_DIR/signaling-secret>"
    log "  occ talk:turn:add turn $NC_DOMAIN:$TURN_PORT udp,tcp --secret=<from $SECRETS_DIR/turn-secret>"
}

# ============================ VERIFY / HEALTH-CHECK ==========================
verify() {
    require_root
    echo "=== HEALTH CHECK $(date) ==="
    local ok=0 fail=0
    # no ((ok++)) - returns exit 1 at 0 and kills the script under set -e (Review K1)
    # Rev.10 FIX: the checks run under 'set -o pipefail'. A check of the form
    # 'producer | grep -q PATTERN' then reports FAILURE even on a match: grep -q
    # exits at the first hit, the producer gets SIGPIPE and ends with 141, and
    # pipefail makes that the status of the whole pipeline. The failure is
    # intermittent - it only appears once the producer writes more than fits in
    # the pipe buffer, i.e. as the machine gains listening sockets and ufw rules.
    # Found on the production server 2026-10-04: 'SSH listens on 64028' and the
    # Portainer check (removed in v0.6.3) alternated as false negatives while both
    # were demonstrably correct. The subshell keeps the change local to the check.
    chk() { if ( set +o pipefail; eval "$2" ) &>/dev/null; then echo "[OK]   $1"; ok=$((ok+1)); else echo "[MISSING] $1"; fail=$((fail+1)); fi; }

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
    chk "Cockpit on WG address only"       "ss -tln | grep -q \"${WG_NET}.1:9090\""
    chk "Cockpit IdleTimeout set"          "grep -q '^IdleTimeout=' /etc/cockpit/cockpit.conf"
    chk "Cockpit root login blocked"       "grep -qx root /etc/cockpit/disallowed-users"
    chk "no Portainer container"           "! docker ps -a --format '{{.Names}}' | grep -qx portainer"
    chk "HDD mounted ($HDD_MOUNT)"         "mountpoint -q $HDD_MOUNT"
    # Rev.8: 1% on volumes >= 1 TB, 5% below - so accept the whole band instead of
    # pinning 5%, and only reject 0 (no reserve at all) or an absurdly large reserve.
    # In PER MILLE, not percent: tune2fs rounds the reserved-block count DOWN, so at
    # -m 1 the ratio comes out at 0.99998% and an integer percent calculation yields 0,
    # failing a '>= 1' test. Measured on the test server 2026-10-03: 26214 of 2621440.
    chk "HDD ext4 reserve 8-60 per mille" "( d=\$(findmnt -no SOURCE $HDD_MOUNT 2>/dev/null) && [[ -n \"\$d\" ]] && p=\$(tune2fs -l \"\$d\" 2>/dev/null | awk '/Reserved block count/{r=\$4} /Block count:/{b=\$3} END{if(b>0) printf \"%d\", (r*1000/b)}') && [[ \"\$p\" -ge 8 && \"\$p\" -le 60 ]] )"
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
    # Rev.8 - the six findings from the CIS audit on the test server, 2026-10-03:
    chk "sshd Banner active"               "sshd -T 2>/dev/null | grep -qi '^banner /etc/issue.net'"
    chk "sshd drop-ins mode 600"           "! find /etc/ssh/sshd_config.d -name '*.conf' -perm /077 | grep -q ."
    chk "fs.suid_dumpable=0 at runtime"    "[[ \"\$(sysctl -n fs.suid_dumpable)\" == 0 ]]"
    chk "apport masked"                    "[[ \"\$(systemctl is-enabled apport 2>/dev/null)\" == masked ]]"
    chk "group wheel exists and is empty"  "getent group wheel | grep -q ':\$'"
    chk "useradd INACTIVE=30"              "grep -qE '^INACTIVE=30' /etc/default/useradd"
    chk "umask 027 in bash.bashrc"         "grep -qE '^umask 027' /etc/bash.bashrc"
    chk "banner hits >=5 Lynis keywords"   "( c=0; for w in audit access authori condition connect consent continu criminal enforce evidence forbidden intrusion law legal legislat log monitor owner penal policy policies privacy private prohibited prosecute record report restricted secure subject system terms warning; do grep -qi \"\$w\" /etc/issue && c=\$((c+1)); done; [[ \$c -ge 5 ]] )"
    chk "sysstat collecting"               "grep -qE '^ENABLED=\"?true' /etc/default/sysstat"
    # Rev.9 - swap:
    chk "vm.swappiness=10"                 "[[ \"\$(sysctl -n vm.swappiness)\" == 10 ]]"
    chk "swap area active"                 "[[ -n \"\$(swapon --show=NAME --noheadings 2>/dev/null)\" ]]"
    # Rev.10 - Caddy split into one file per site:
    chk "Caddyfile imports conf.d"         "grep -q 'import /etc/caddy/conf.d' /etc/caddy/Caddyfile"
    chk "Nextcloud site file present"      "test -f /etc/caddy/conf.d/10-nextcloud.caddy"
    if [[ "$ENABLE_IMMO" == "yes" ]]; then
        chk "immo: php8.3-fpm running"     "systemctl is-active php8.3-fpm"
        chk "immo: FPM socket present"     "test -S /run/php/immo.sock"
        chk "immo: MariaDB on loopback"    "ss -tln | grep -q '127.0.0.1:3306'"
        chk "immo: MariaDB NOT public"     "! ss -tln | grep -qE '(0\\.0\\.0\\.0|\\*):3306'"
        chk "immo: database exists"        "mariadb -N -e \"SHOW DATABASES\" | grep -qx \"$IMMO_DB\""
        chk "immo: Caddy site file"        "test -f /etc/caddy/conf.d/20-immo.caddy"
        chk "immo: frame-ancestors set"    "grep -q 'frame-ancestors' /etc/caddy/conf.d/20-immo.caddy"
        chk "immo: SameSite=None in pool"  "grep -q 'session.cookie_samesite. = None' /etc/php/8.3/fpm/pool.d/immo.conf"
        chk "immo: env[IMMO_WEB_ENV] set"   "grep -q '^env\\[IMMO_WEB_ENV\\]' /etc/php/8.3/fpm/pool.d/immo.conf"
        chk "immo: .env 600 and immo-owned" "[[ \"\$(stat -c '%a %U' \"$IMMO_DIR/.env\")\" == \"600 $IMMO_USER\" ]]"
        chk "immo: web.env 640 root:$IMMO_USER" "[[ \"\$(stat -c '%a %U:%G' \"$IMMO_WEB_ENV\")\" == \"640 root:$IMMO_USER\" ]]"
        chk "immo: web.env without IMAP"    "! grep -q '^IMAP_' \"$IMMO_WEB_ENV\""
        chk "immo: IMAP port 993 not 995"   "! grep -q '^IMAP_PORT=995' \"$IMMO_DIR/.env\""
        chk "immo: timer active (or off, no venv)" "[[ ! -x \"$IMMO_DIR/.venv/bin/python3\" ]] || systemctl is-active immo-lauf.timer"
        chk "immo: Borg pre-hook"          "test -x /usr/local/lib/backup-pre.d/10-immo-db.sh"
        chk "immo: reports on data volume" "test -d \"$HDD_MOUNT/immo/Kaufpreise\""
    fi
    if [[ "$ENABLE_TALK_HPB" == "yes" ]]; then
        chk "HPB: coturn running"          "systemctl is-active coturn"
        chk "HPB: TURN port open in ufw"   "ufw status | grep -q \"$TURN_PORT\""
        chk "HPB: turnserver.conf 640"     "[[ \"\$(stat -c %a /etc/turnserver.conf)\" == 640 ]]"
        chk "HPB: signaling handle in NC"  "grep -q 'standalone-signaling' /etc/caddy/conf.d/10-nextcloud.caddy"
    fi
    if [[ "$SWAPFILE_SIZE_GB" =~ ^[1-9][0-9]*$ ]]; then
        chk "swap file in fstab, mode 600" "grep -qE '^/swapfile[[:space:]]' /etc/fstab && [[ \"\$(stat -c %a /swapfile)\" == 600 ]]"
    fi
    if [[ "$ENABLE_GRUB_PASSWORD" == "yes" ]]; then
        chk "GRUB password + unrestricted"  "grep -q 'password_pbkdf2' /boot/grub/grub.cfg && grep -q -- '--unrestricted' /boot/grub/grub.cfg"
    fi
    chk "no install.conf.bak.* left"       "( shopt -s nullglob; f=(\"$INSTALL_CONF\".bak.*); [[ \${#f[@]} -eq 0 ]] )"
    chk "Borg: data volume included"       "grep -q \"exclude '$BACKUP_DIR'\" /usr/local/bin/backup-server.sh"
    chk "SMTP_PASS cleared in install.conf" "! grep -qE \"^SMTP_PASS=['\\\"]?[^'\\\"[:space:]]\" \"$INSTALL_CONF\" 2>/dev/null"
    chk "rsync present, daemon masked"     "command -v rsync >/dev/null && [[ \"\$(systemctl is-enabled rsync 2>/dev/null)\" != enabled ]]"

    echo "=== $ok OK, $fail open ==="
    echo "Final audit:  lynis audit system   (Lynis from the CISOfy repo, phase 4)"
    [[ $fail -eq 0 ]] || return 1
}

# ================================ DISPATCH ===================================
# v0.6.3: the final Lynis audit writes a FILE. Until now it was a line in the closing
# notes, run by hand, and its output was lost - 30-lynis.log on the production server
# was empty after the first install.
lynis_audit() {
    require_root
    command -v lynis >/dev/null 2>&1 || die "Lynis is not installed - run phase4 first."
    install -d -m 700 "$TESTS_DIR"
    log "Lynis audit running (several minutes) - output: $TESTS_DIR/30-lynis.log"
    lynis audit system --quick --no-colors > "$TESTS_DIR/30-lynis.log" 2>&1 || true
    chmod 600 "$TESTS_DIR/30-lynis.log"
    local hi
    hi="$(grep -i 'Hardening index' "$TESTS_DIR/30-lynis.log" | tail -1 | tr -s ' ' || true)"
    log "Lynis done. ${hi:-see $TESTS_DIR/30-lynis.log}"
}

# B2 (v0.6.3): the gate between phase1 and phase2. Phase 2 switches the root login off,
# so the admin password has to be in the operator's hands - not merely on the disk -
# before it runs. The password is printed to the TERMINAL only, never through log()/warn()
# into $LOGFILE. The receipt file written here is what phase2 checks.
password_gate() {
    require_root
    if [[ -f "$SECRETS_DIR/admin-user-password.saved" ]]; then
        log "Admin password already confirmed as saved - gate passed."
        return 0
    fi
    [[ -f "$SECRETS_DIR/admin-user-password" ]] || die "$SECRETS_DIR/admin-user-password missing - run phase1 first."
    # Rev.12: check for a real terminal BEFORE the password is shown - a redirected
    # stdout put it into the log file, and a piped "yes" passed the gate unattended.
    [[ -t 0 && -t 1 ]] && { : > /dev/tty; } 2>/dev/null \
        || die "No interactive terminal - run 'bootstrap' in an open session (ssh -t, sudo -i), output NOT redirected."
    echo ""
    warn "Admin password for $ADMIN_USER - into the password manager AND onto paper, now:"
    printf '    %s\n\n' "$(cat "$SECRETS_DIR/admin-user-password")" > /dev/tty
    warn "After phase 2 root can no longer log in. Without this password the VNC console is useless."
    local ans3
    # -t 3600 overrides an inherited TMOUT=900 (phase 5), which would end read early.
    read -r -t 3600 -p "Password stored in the password manager and on paper? Only then 'yes': " ans3 < /dev/tty \
        || die "No interactive terminal - run 'bootstrap' in an open root session, or: touch $SECRETS_DIR/admin-user-password.saved"
    [[ "$ans3" == "yes" ]] || die "Aborted - save the password first, then start again (the phases are idempotent)."
    : > "$SECRETS_DIR/admin-user-password.saved"
    chmod 600 "$SECRETS_DIR/admin-user-password.saved"
    log "Receipt written: $SECRETS_DIR/admin-user-password.saved"
}

usage() {
    # Pattern instead of line numbers: the numeric range silently pointed at the
    # change history once the header grew (found in v0.6.3).
    sed -n '/^# USAGE (as root/,/^# Rescue anchor on lock-out/p' "$0"
    echo "Phases: preflight phase1 ... phase12   verify"
    echo "Optional phases (each behind its own switch, all default off):"
    echo "  phase13  immo.flow (ENABLE_IMMO)        phase14  further static sites (ENABLE_EXTRA_SITES)"
    echo "  phase15  Talk HPB  (ENABLE_TALK_HPB)"
    echo "Maintenance: caddy-base  (rebuild Caddyfile + Nextcloud site after an upgrade to Rev.10)"
    echo "Meta: bootstrap (0-2, stops at the login test)  rest (3-15 + verify + lynis)  all (everything with the stop)"
    echo "Audit: lynis (writes \$TESTS_DIR/30-lynis.log)"
}

main() {
    touch "$LOGFILE" 2>/dev/null || LOGFILE=/dev/null
    case "${1:-}" in
        preflight) preflight ;;
        phase1) phase1 ;; phase2) phase2 ;; phase3) phase3 ;;
        phase4) phase4 ;; phase5) phase5 ;; phase6) phase6 ;;
        phase7) phase7 ;; phase8) phase8 ;;
        phase9) phase9 ;; phase10) phase10 ;; phase11) phase11 ;; phase12) phase12 ;;
        phase13) phase13 ;; phase14) phase14 ;; phase15) phase15 ;;
        caddy-base)
            # Rev.10: rebuild only the Caddy structure (main file + Nextcloud site).
            # Needed on a server installed before Rev.10, whose Caddyfile is still
            # the old monolithic one WITHOUT the conf.d import - without this, the
            # site files written by phases 13 and 14 are never loaded.
            require_root
            [[ -n "$NC_DOMAIN" ]] || die "caddy-base: NC_DOMAIN is empty."
            write_caddy_base; write_caddy_nextcloud; caddy_apply
            log "Caddy structure rebuilt: /etc/caddy/Caddyfile imports $CADDY_CONFD/*.caddy"
            ;;
        verify) verify || true ;;
        lynis) lynis_audit ;;
        bootstrap)
            preflight; phase1; password_gate; phase2
            echo ""
            warn "STOP: now log in from a SECOND terminal:"
            warn "    $(login_cmd)"
            warn "    then:  sudo -v"
            warn "Login OK -> continue with:  ./install.sh rest"
            ;;
        rest)
            # Continuation after a passed login test (bootstrap). Assumes the
            # prerequisites (DNS, HDD, WG pubkey, NC tag, SMTP) are set up front.
            [[ -n "$(ss -Htln "sport = :${SSH_PORT}" 2>/dev/null)" ]] || die "sshd not listening on $SSH_PORT - run 'bootstrap' + login test first."
            phase3; phase4; phase5; phase6; phase7; phase8; phase9; phase10; phase11; phase12
            phase13; phase14; phase15
            verify || true
            lynis_audit || true
            warn "Plan a reboot (boot params/fstab only take effect then): shutdown -r +1"
            ;;
        all)
            preflight; phase1; password_gate; phase2
            # Mandatory login test - 'all' must not close SSH untested (Review K4):
            echo ""
            warn "STOP: now log in from a SECOND terminal:"
            warn "    $(login_cmd)"
            read -r -t 3600 -p "Login in the second terminal successful? Only then type 'yes': " ans \
                || die "No interactive terminal - 'all' needs input. Run the phases individually."
            [[ "$ans" == "yes" ]] || die "Aborted - test the SSH login first, then run './install.sh all' again (phases are idempotent)."
            # Council-Fix 4 used to ask about the offline copy HERE, after phase2 - too
            # late to prevent a lock-out. password_gate above does it before phase2.
            phase3; phase4; phase5; phase6; phase7; phase8; phase9; phase10; phase11; phase12
            phase13; phase14; phase15
            verify || true   # one open point must not swallow the final notes (Review M7)
            lynis_audit || true
            warn "Plan a reboot (boot params, fstab, possibly the kernel): shutdown -r +1"
            ;;
        *) usage; exit 1 ;;
    esac
}
main "$@"
