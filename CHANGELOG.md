# Changelog

All notable changes to this project are documented here. Versions follow a SemVer-style `0.x` scheme. The detailed pre-release script-revision log (install.sh Rev. 4 → Rev. 5) is kept at the bottom for reference.

## [0.3.0] - 2026-08-01

### Added

- **Disk-space headroom on `$HDD_MOUNT`** (phase 9): explicit `tune2fs -m 5` reserved-blocks setting keeps the last 5 % off-limits to normal writers (the NC container's mapped uid, Borg over SSH), so uploads/backups hit `ENOSPC` at 95 % instead of running the volume bit-for-bit full. Percentage-based, so it works unchanged whether `$HDD_MOUNT` is the transitional second 500 GB NVMe or, from month 5, the 4 TB HDD.
- **`disk-space-alert.sh`** + `disk-space-alert.timer` (twice daily): mails a warning at 85 % and a critical alert at 95 % for both `$HDD_MOUNT` and `/`, via the existing msmtp setup. A per-mount state file avoids re-mailing on every tick — only on a newly crossed threshold.
- `verify` extended with two checks: ext4 reserved-blocks percentage on `$HDD_MOUNT` (4–6 % tolerance), `disk-space-alert.timer` active.
- AIDE excludes extended with `/var/lib/disk-space-alert` (the alert script's state file changes constantly and would otherwise flag as a false integrity finding).
- Manual HDD setup comment (phase 9) and `Install-Guide.md` §1.8 updated to mention the reserved-blocks step; both READMEs get a short paragraph on the new headroom/alerting.

## [0.2.0] - 2026-08-01

### Changed

- Phase 11 now installs **Portainer CE** instead of Runtipi, following a four-criteria comparison (app store, real Docker deploy, real monitoring, compatible with the hardened setup) against Dokploy, Coolify, CasaOS and Cosmos — full comparison in `SCPs.md` / `SCPs.de.md`. Portainer needs neither `80` nor `443`, ships no proxy of its own, and binds directly to `${WG_NET}.1:9443`.
- AIDE excludes, the monthly update-reminder cron text, `verify`'s panel-port check, and both READMEs updated from Runtipi/8090/8445 to Portainer/9443.

### Fixed

- **Phase 3 abort bug:** `[[ "$KEEP22" == 1 ]] && ufw limit 22/tcp ...` as a bare statement returned exit code 1 under `set -e` whenever `KEEP22=0` (the normal case, SSH already listening on the hardened port), killing phase 3 right after the SSH ufw rule was set. Wrapped in an `if` block; `KEEP22` is now `local` to `phase3()`.

### Notes

- These changes were folded back after a three-agent independent review (security, idempotency/robustness, shell style) of the full `install.sh`. No other findings from that review have been acted on yet — see `Handover.md` for the open list.

## [0.1.1] - 2026-07-21

### Added

- ShellCheck GitHub Action (`.github/workflows/shellcheck.yml`) that lints `install.sh` on every push and pull request, plus a status badge in the READMEs.
- additional paragraph concerning Version History inside README.md

## [0.1.0] - 2026-07-21

### Added

- Initial public release. Includes `install.sh` (phased Ubuntu 24.04 hardening + Nextcloud stack, Rev. 5), `install.conf.example` (external, git-ignored configuration), the English and German READMEs, `Install-Guide.md`, `SCPs.md` / `SCPs.de.md` (server-control-panel comparison), `SECURITY.md`, `Handover.md`, and the GPL-3.0-or-later license.

---

# Pre-release script revision detail — install.sh Rev. 4 → Rev. 5

Basis: `2026-07-18-03-40-install.sh` (Rev. 4, in `.archiv/` gesichert).
Neu: `2026-07-19-05.31_install.sh` (Rev. 5). `bash -n` sauber.
Grundlage sind die auf dem Testserver server.example.com am 19.07. verifizierten Batch-1–6-Blöcke, NICHT die Agenten-Rohvorschläge.

---

## Entscheidungen (GO 2026-07-19)

- **a) GRUB-Boot-Params:** hinter Config-Flag, Default AUS.
- **b) Hostname:** optionale Config-Var `HOSTNAME_FQDN`.
- **c) rsync:** wird in phase12 mit-entfernt (bei Bedarf `apt install rsync`).
- **d) Compose-Limits:** direkt in die Haupt-Compose, prod-16GB-dimensioniert.

---

## Konfiguration (neu)

```
HOSTNAME_FQDN=""            # leer = Provider-Hostname belassen
ENABLE_GRUB_HARDENING="no"  # Default AUS
```

## preflight

- NTP-Server gepinnt (`/etc/systemd/timesyncd.conf.d/50-hardening.conf`).
- Hostname optional (`hostnamectl` + `127.0.1.1`-Zeile), nur wenn `HOSTNAME_FQDN` gesetzt.

## phase2 (SSH)

- NEU in `10-hardening.conf`: `HostbasedAuthentication no`, `IgnoreRhosts yes`, `PermitUserEnvironment no`, moderne `Ciphers`/`KexAlgorithms`/`MACs`. Ganze Datei per `cat` neu geschrieben → keine Doppel-Direktiven-Falle (S.1.e).
- NEU (S.1.f): `sed 's/^PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config` bereinigt die widersprüchliche Ubuntu-Default-Zeile (verhindert USG/CIS-False-Positive). `AllowTcpForwarding` bewusst auf `yes` belassen.

## phase4 (Auto-Updates)

- NEU: CISOfy-Repo für Lynis eingerichtet + `apt install lynis` (Origins-Pattern `origin=CISOfy` war schon da, greift jetzt). universe-Paket (3.0.9) wird nicht mehr gezogen.

## phase5 (Kernel/Netz/FS)

- sysctl: `secure_redirects=0` (all+default) ergänzt.
- NEU: `/etc/ufw/sysctl.conf` `log_martians` → 1 gefixt (ufw kann den sysctl.d-Wert sonst still überschreiben).
- modprobe: je Modul `install … /bin/false` **und** `blacklist`, zusätzlich `usb-storage`. KEIN overlayfs (Docker).
- **GRUB-Block hinter `if [[ "$ENABLE_GRUB_HARDENING" == "yes" ]]`** (Default: übersprungen). Havarie-Kommentar + Einschalt-Prozedur im Skript. Param-Satz unverändert (bewiesen sicher); die vier apparmor/audit-Params bleiben draußen.
- NEU (B1): `cron.allow`/`at.allow` = root (640), `cron.deny`/`at.deny` entfernt.
- NEU (B2): `libpam-pwquality`, `/etc/security/pwquality.conf`-Vollsatz (USG liest die Hauptdatei), `pwhistory remember=24` (idempotent), `nullok` aus `common-auth`, `login.defs` UMASK 027 + Aging 365/1/14, `chage` auf Admin, `profile.d` TMOUT 900 + umask 027, `su` nur für sudo-Gruppe (mit Admin-in-sudo-Gate).

## phase6 (fail2ban)

- NEU: `fail2ban.local` `allowipv6 = auto`; `jail.d/00-ignoreip.local` mit Loopback + WG-Netz (`$WG_NET.0/24`).

## phase7 (auditd)

- **OFFENE FIX #2 behoben:** Watch-Zielpfade (`/etc/wireguard`, `/etc/docker`, `/srv/nextcloud/secrets`, compose-Datei, `faillock`, `sudo.log`, `opasswd`) werden **vor** `augenrules --load` per `install -d`/`touch` angelegt → kein Abbruch mehr.
- NEU (B3): `auditd.conf` verfügbarkeitsfreundlich (`space_left_action=EMAIL`, `disk_full/error=SYSLOG`, `action_mail_acct=root`).
- NEU (B3): zweite Regeldatei `cis-l2.rules` (31 Regeln). Zusammen mit `hardening.rules` (16) = **47**.

## phase9 (Docker/Caddy/NC)

- NC-fail2ban-Filter auf die **offizielle 2FA-Regex** (`_groupsre`, Login failed / Two-factor challenge failed / Trusted domain error) — am 19.07. mit `fail2ban-regex` gegen echte NC-33-Logzeilen verifiziert (2 matched).
- NEU (B6): Caddy-systemd-Sandbox `caddy.service.d/hardening.conf`.
- NEU (B5): Compose-Limits pro Dienst — db 2g/256, redis 256m/64, app 6g/512, cron 1g/256.
- NEU (W): Warntext, NC-Updates nur über Image-Tag; Web-Updater-Button nie benutzen.

## phase12 (NEU)

- KVM-gated (`systemd-detect-virt`) Deaktivierung von NetworkManager (disable+mask), ModemManager, wpa_supplicant, multipathd; `lvm2-monitor` nur ohne LVM. **udisks2 bleibt** (Cockpit-Storage).
- `ubuntu`-User + `/etc/sudoers.d/90-cloud-init-users` entfernt (mit `visudo -c`-Prüfung).
- Alt-Pakete purge: telnet/inetutils-telnet/ftp/tnftp/**rsync**; `rc`-Leichen; autoremove.
- AIDE + Container-/Daten-Excludes (`$HDD_MOUNT`, `$RUNTIPI_DIR`, docker, containerd, NC html/db, proc/sys/run) + Audit-Tool-sha512-Regeln + `aideinit`. Läuft als letzte Phase (AIDE-DB = Endzustand).

## verify

- 10 neue Checks: secure_redirects, pwquality minlen, pwhistory 24, UMASK 027, fail2ban-WG-ignoreip, NC-2FA-Filter, Caddy-Sandbox, ubuntu-User weg, AIDE-DB, GRUB ohne apparmor-Param.
- Abschluss-Audit-Zeile: `lynis audit system` (Lynis jetzt via Phase 4 installiert).

## Dispatch

- `phase12` in `usage`, `case` und `all` (nach phase11, vor verify) verdrahtet.
- `usage()`-`sed`-Bereich auf den verschobenen AUFRUF-Block (32–45) korrigiert.

---

## Nicht eingebaut (bewusst, weiterhin manuell)

Ubuntu Pro attach + `pro enable usg`, USG/CIS-Audit-Bewertung, GRUB-Passwort, echte 4TB-HDD, WireGuard-Client (Mac), Borg-Passphrasen/Key-Exporte, iPhone-Monitoring, Reboot-Timing (S.2 der Übergabe).

## Noch zu tun vor Produktivlauf

- `SSH_PUBKEY`, `NC_IMAGE_TAG`, `WG_CLIENT_PUBKEY`, `SMTP_*`, ggf. `HOSTNAME_FQDN` eintragen.
- Redis-cap-Satz (Fix 1 aus Rev. 4) ist auf dem Testserver noch nicht durch Phase 9 bestätigt.
- Voller Testlauf `phase1 … phase12` + `verify` auf frischem Server, dann externe nmap-Kontrolle.
