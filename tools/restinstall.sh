#!/bin/bash
# restinstall.sh - bring an installed server to the state of install.sh Rev. 13 without
# re-running whole phases (Programme item 7, 2026-10-09).
#
# Whole phases would restart MariaDB, PHP-FPM, Docker and Caddy for nothing and rewrite
# files that already match. This script applies only the differences found by the
# comparison of 2026-10-09 (Pruefung-2026-10-09/261009-Abgleich-Rev13.md). Where Rev. 13
# writes a file, the code is taken from install.sh itself (blk), so script and server
# cannot drift apart again.
#
# Usage as root, one step at a time:  restinstall.sh 1|2|3|4
#   1  install.sh + install.conf, SSH (phase 2)            - test a NEW ssh login afterwards
#   2  fail2ban, password reminder, Borg, immo.flow files, websites, Caddy
#   3  Nextcloud compose (pinned images, DB tuning, clamd mount), ClamAV, base settings
#   4  AIDE excludes + new baseline, verify, Lynis
# Every file is backed up to /root/claude-sicherung/restinstall-<time>/ first.

set -uo pipefail
umask 022
INSTALL=/root/install.sh
export INSTALL_CONF=/root/install.conf
TS=$(date +%Y%m%d-%H%M%S)
BAK=/root/claude-sicherung/restinstall-$TS
mkdir -p "$BAK"
h()    { printf '\n===== %s =====\n' "$*"; }
sich() { local f; for f; do [[ -e $f ]] && cp -a --parents "$f" "$BAK/"; done; return 0; }
# Load configuration and functions of install.sh without running main.
lade() { source <(sed '$d' "$INSTALL"); set +e; }
# Print the lines of install.sh from the first line containing $1 up to and including
# the next line containing $2.
blk()  { awk -v s="$1" -v e="$2" 'index($0,s){f=1} f{print} f&&index($0,e){exit}' "$INSTALL"; }
# Run such a block inside a function, so 'local' works as it does in the phase.
lauf_blk() { eval "_b() { $(blk "$1" "$2")
}"; _b; }

schritt1() {
    h "1a install.sh und install.conf"
    [[ -s /home/hubi/install-rev13.sh ]] || { echo "ABBRUCH: /home/hubi/install-rev13.sh fehlt"; return 1; }
    bash -n /home/hubi/install-rev13.sh || { echo "ABBRUCH: Syntaxfehler"; return 1; }
    sich /root/install.sh /root/install.conf
    install -m 700 -o root -g root /home/hubi/install-rev13.sh /root/install.sh
    rm -f /home/hubi/install-rev13.sh
    local kv k
    for kv in 'IMMO_DOMAIN="silo2.brill.ing immo.brill.ing"' 'SMTP_ALARM_FROM="alarm@brill.ing"' \
              'KEEP_SNAPD="yes"' 'NC_MAIL_FROM="next"' 'NC_MAIL_DOMAIN="brill.ing"' \
              'ENABLE_OFFICE="yes"' 'EO_DOMAIN="office.brill.ing"' 'ENABLE_CLAMAV="yes"'; do
        k=${kv%%=*}
        if grep -q "^$k=" "$INSTALL_CONF"; then
            python3 - "$INSTALL_CONF" "$k" "$kv" <<'PY'
import sys
p,k,kv=sys.argv[1:4]
z=open(p).read().splitlines()
open(p,'w').write("\n".join(kv if l.startswith(k+"=") else l for l in z)+"\n")
PY
        else
            printf '%s\n' "$kv" >> "$INSTALL_CONF"
        fi
        grep "^$k=" "$INSTALL_CONF"
    done
    chmod 600 "$INSTALL_CONF"

    h "1b SSH (phase2)"
    lade
    sich /etc/ssh/sshd_config /etc/ssh/sshd_config.d
    phase2 || { echo "ABBRUCH: phase2 gescheitert"; return 1; }
    echo "ssh.socket: $(systemctl is-enabled ssh.socket 2>&1)"
    sshd -T | grep -E '^(port|allowtcpforwarding|kexalgorithms|hostkey|permitrootlogin|passwordauthentication) '
    ls /etc/ssh/sshd_config.bak.* 2>/dev/null && rm -f /etc/ssh/sshd_config.bak.*
}

schritt2() {
    lade
    h "2a fail2ban (phase6)"
    sich /etc/fail2ban
    phase6 || echo "FEHLER phase6"
    h "2b Passwort: kein Ablauf, Erinnerung"
    admin_pw_reminder
    chage -l "$ADMIN_USER" | grep -E 'Password expires|Maximum'
    systemctl list-timers admin-pw-reminder.timer --no-pager | sed -n 1,2p
    h "2c Borg (phase10)"
    sich /usr/local/bin/backup-server.sh /etc/systemd/system/borg-backup.timer /etc/systemd/system/borg-backup.service
    phase10 >/dev/null || echo "FEHLER phase10"
    grep -n 'borg compact\|^umask' /usr/local/bin/backup-server.sh
    systemctl list-timers borg-backup.timer --no-pager | sed -n 1,2p
    h "2d immo.flow: Pool-Nebendateien, Units, Caddy"
    sich /etc/php/8.3/fpm/pool.d/immo.conf /etc/immo/msmtprc /etc/logrotate.d /etc/systemd/system/immo-lauf.service \
         /etc/systemd/system/immo-lauf.timer /etc/systemd/system/immo-online.service /etc/systemd/system/immo-online.timer \
         /etc/systemd/system/immo-fail-mail@.service /etc/systemd/system/immo-fail-mail.service "$CADDY_CONFD/20-immo.caddy"
    lauf_blk '    install -d -o "$IMMO_USER" -g "$IMMO_USER" -m 700 "$IMMO_DIR/sessions"' '    systemctl enable --now php8.3-fpm'
    lauf_blk '    cat > /etc/systemd/system/immo-lauf.service <<EOF' '    rm -f /etc/systemd/system/immo-fail-mail.service'
    systemctl daemon-reload
    lauf_blk '    local immo_dom immo_sites=""' '    chmod 644 "$CADDY_CONFD/20-immo.caddy"'
    ls -l /var/log/php8.3-fpm-immo.log /etc/systemd/system/immo-fail-mail.service 2>&1
    h "2e Websites (phase14) und Caddy"
    sich /etc/caddy /srv/www
    phase14 || echo "FEHLER phase14"
    for s in immo.brill.ing silo2.brill.ing coco.brill.ing hubertus.brill.ing next.brill.ing office.brill.ing; do
        printf '  %-20s %s   /.env %s\n' "$s" "$(curl -s -o /dev/null -w '%{http_code}' https://$s/)" "$(curl -s -o /dev/null -w '%{http_code}' https://$s/.env)"
    done
}

schritt3() {
    lade
    h "3a Nextcloud-Compose aus der Rev.13-Vorlage"
    local C=/srv/nextcloud/docker-compose.yml neu
    sich "$C" /usr/local/bin/nc-post-setup.sh
    neu=$(mktemp)
    # the template of phase 9, written to a temp file instead of the real one
    eval "_c() { $(blk '    local NC_CLAMAV_MOUNT=""' '    # --- fail2ban jail for Nextcloud' | sed "s|/srv/nextcloud/docker-compose.yml|$neu|g")
}"; _c
    echo "-- Unterschiede alt -> neu:"; diff -u "$C" "$neu"
    cat "$neu" > "$C"; rm -f "$neu"     # keeps owner and mode of the existing file
    lauf_blk "    cat > /usr/local/bin/nc-post-setup.sh <<'EOF'" '    chmod 600 /etc/nc-post-setup.env'
    h "3b ClamAV installieren (vor dem Neustart des Stacks, damit der Socket existiert)"
    apt-get install -y -q clamav clamav-daemon clamav-freshclam >/dev/null && echo "Pakete installiert"
    h "3c Stack neu erstellen"
    local t0=$(date +%s)
    (cd /srv/nextcloud && docker compose up -d 2>&1 | tail -n 6)
    local i; for i in $(seq 1 60); do
        curl -s https://$NC_DOMAIN/status.php | grep -q '"installed":true' && break; sleep 2; done
    echo "Nextcloud wieder erreichbar nach $(( $(date +%s) - t0 )) s: $(curl -s https://$NC_DOMAIN/status.php)"
    docker ps --format '{{.Names}}  {{.Image}}  {{.Status}}' | grep nextcloud
    h "3d phase17 ClamAV"
    phase17 || echo "FEHLER phase17"
    h "3e Grundeinstellungen (nc-post-setup.sh)"
    /usr/local/bin/nc-post-setup.sh 2>&1 | grep -v -E '^\s*$' | tail -n 40
}

schritt4() {
    lade
    h "4a AIDE-Ausnahmen"
    sich /etc/aide/aide.conf.d/99_local_excludes
    lauf_blk "    printf '!/var/lib/docker" '        >> /etc/aide/aide.conf.d/99_local_excludes'
    cat /etc/aide/aide.conf.d/99_local_excludes
    h "4b neue AIDE-Basis im Hintergrund"
    systemd-run --unit=aide-neu --collect /bin/sh -c 'aideinit -y -f > /root/tests/aideinit-'"$TS"'.log 2>&1'
    echo "gestartet: systemd-run aide-neu, Protokoll /root/tests/aideinit-$TS.log"
    h "4c verify (Rev.13)"
    verify 2>&1 | grep -E 'MISSING|=== '
}

schritt2d() {
    lade
    h "2d (Wiederholung) immo.flow: Fehlerprotokoll, logrotate, msmtprc"
    sich /etc/immo/msmtprc /etc/logrotate.d
    lauf_blk '    install -d -o "$IMMO_USER" -g "$IMMO_USER" -m 700 "$IMMO_DIR/sessions"' '    systemctl enable --now php8.3-fpm'
    ls -l /var/log/php8.3-fpm-immo.log /etc/logrotate.d/php8.3-fpm-immo /etc/immo/msmtprc
    systemctl reload php8.3-fpm && echo "php8.3-fpm neu geladen"
    echo "immo.brill.ing: $(curl -s -o /dev/null -w '%{http_code}' https://immo.brill.ing/anmelden.php)"
}

case "${1:-}" in
    1) schritt1 ;; 2) schritt2 ;; 2d) schritt2d ;; 3) schritt3 ;; 4) schritt4 ;;
    *) echo "Aufruf: restinstall.sh 1|2|3|4"; exit 1 ;;
esac
echo "== Sicherung: $BAK"
