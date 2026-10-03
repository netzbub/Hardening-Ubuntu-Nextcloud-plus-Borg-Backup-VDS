# Changelog

All notable changes to this project are documented here. Versions follow a SemVer-style `0.x` scheme. The detailed pre-release script-revision log (install.sh Rev. 4 → Rev. 5) is kept at the bottom for reference.

## [0.6.0] - 2026-10-03

Three previously separate projects move onto one server. All three new phases are behind their own switch and default to off, so an existing installation behaves exactly as before.

### Added
- **Phase 13, immo.flow** (`ENABLE_IMMO`): system user `immo`, a native MariaDB bound to 127.0.0.1, an own PHP-FPM pool on a unix socket, a Caddy site, and a systemd timer that replaces the launchd agent on the Mac. A Borg pre-hook dumps the immo database before every backup run - until now that database had no automatic backup at all.
- **Phase 14, further static sites** (`ENABLE_EXTRA_SITES`): one Caddy site per domain from `EXTRA_SITES`, served by `file_server` with no interpreter behind it.
- **Phase 15, Nextcloud Talk High Performance Backend** (`ENABLE_TALK_HPB`): coturn native on 3478 without TLS, signaling server plus Janus and NATS as a compose stack. The signaling server is served under a path of `$NC_DOMAIN`, so it needs neither its own DNS record nor its own certificate. **This phase has not yet run on a real server, and the Janus image tag is unverified.**
- `dns_gate <domain>` as a reusable function, and `/usr/local/lib/backup-pre.d/` as a hook directory the backup script runs before every archive.

### Changed
- **The Caddy configuration is split into `/etc/caddy/conf.d/*.caddy`, one file per site.** Phase 9 used to rewrite the whole `Caddyfile`, which meant any site added by a later phase was silently wiped the next time phase 9 ran. The main `Caddyfile` now only imports.
- The DNS gate from phase 9 became `dns_gate` and is used by phases 9, 13 and 14 instead of being copied three times.
- **Seventeen new verify checks**, 59 → 76 in total; 59 of them run with all three switches off.

### Verified
- PHP 8.3.6 - the version Ubuntu 24.04 ships - runs immo.flow: all 42 files under `web/` pass `php -l`, and nothing uses 8.4-only syntax. The third-party PHP repository that an 8.4 would have required is therefore not needed, and no extra apt source goes onto the hardened machine. Static check only; the runtime behaviour still has to be confirmed on the server.
- The generated Caddy site files adapt cleanly under Caddy 2.8.4, with and without the Talk signaling handle.

## [0.5.1] - 2026-10-03

Swap, after the provider panel turned out to offer sizes up to 8 GB at build time.

### Added
- `vm.swappiness = 10` in `/etc/sysctl.d/99-zz-hardening.conf`. Ubuntu ships 60, which pages out the MariaDB buffer pool and Redis while physical memory is still free. On the 40 GB production box swap is an emergency reserve against the OOM killer during bursts - Chromium in the immo.flow run, `borg compact`, a Nextcloud image upgrade - and never a second tier of memory.
- Optional additional swap **file** through `SWAPFILE_SIZE_GB` (phase 5, default `0` = off). Swap areas are additive, so the swap reserved by the provider at build time can be topped up at any point without rebuilding the server.

### Changed
- **Two new verify checks**, 56 -> 58: `vm.swappiness` is 10 at runtime, and at least one swap area is active. A third check (swap file present in `/etc/fstab` with mode 600) runs only when `SWAPFILE_SIZE_GB` is greater than zero.

## [0.5.0] - 2026-10-03

CIS/USG audit and migration rehearsal on the test server. Ubuntu Pro attached, `usg`
enabled, profile `cis_level1_server-v1.0.0` run: 319 pass, 50 not applicable, 38 open.
Eleven of the 38 were real gaps and are closed; the other 27 are deliberate rejections
or false positives, each documented in `Handover.md` §9. `usg fix` was deliberately NOT
run and should not be: of the 27 remaining findings it would either enforce against the
architecture (remove ufw, disable forwarding, deny outbound) or work on false positives.

### Fixed

- **sshd never showed a banner.** Phase 5 wrote the bilingual legal text to `/etc/issue.net`, but the `Banner` directive was missing from the sshd drop-in, so `sshd -T` reported `banner none` and the text was never displayed on an SSH login. Dead configuration for the whole first install run. Now set, and confirmed to appear on the first login after the reboot. Same class of silent failure as the 0.4.0 sysctl bug: configuration present, effect zero.
- **`fs.suid_dumpable` ran at 2** although `99-zz-hardening.conf` sets 0. The cause was not file ordering this time but **apport**, whose init script re-sets the value to 2 on every boot, after sysctl has run. apport is now disabled and masked and `/etc/default/apport` set to `enabled=0`; the value holds across reboots, verified. This also closes the separate CIS finding `service_apport_disabled` — one change, two findings.
- **`/etc/ssh/sshd_config.d/60-cloudimg-settings.conf` shipped mode 644.** The `chmod 600` only covered the script's own drop-in. Now applied to every `*.conf` in that directory (CIS `file_permissions_sshd_drop_in_config`).

### Added

- **GRUB menu password** (phase 5, `ENABLE_GRUB_PASSWORD`, default `yes`). Separate from the boot-PARAMETER hardening and far less dangerous: the normal menu entries are marked `--unrestricted`, so an unattended reboot still boots without input, while editing an entry and the GRUB shell — the route to `init=/bin/bash` for anyone with console access — require the password. The implementation marks the entries unrestricted *first* and rolls the password lines back out of `40_custom` if `grub.cfg` does not afterwards confirm both facts, rather than leaving a machine that stalls at a prompt. The password is lowercase letters and digits on purpose: it can only ever be typed at the provider's VNC console, which hands GRUB raw US key positions, so anything from a German keyboard arrives scrambled. Only ever enable this with a working rescue console.
- **`pwgen -Byncs` for generated secrets.** `gen_secret` now takes a base length (default 64) and varies it by ±4, so not every secret in `$SECRETS_DIR` shares one length. The shell/`.env`/URL-active characters are excluded: these secrets travel through docker-compose files, DB connection strings and here-docs, where a bare `$`, backtick, quote or backslash breaks the consumer — at 60 characters from the remaining set the entropy cost is irrelevant. `pwgen` is installed in phase 1; there is an openssl fallback.
- **Six further CIS items:** empty group `wheel` (so a future `group=wheel` can never match a real account), `INACTIVE=30` in `/etc/default/useradd`, `umask 027` additionally in `/etc/bash.bashrc` and `/etc/profile.d/99-umask.sh` (login.defs alone only covers login shells), mode `0740` on the user init files, and explicit ufw loopback rules (`allow in on lo`, `deny in from 127.0.0.0/8` and `::1`).
- **`tools/secrets-to-1pif.py`** — runs as root on the server, reads `$SECRETS_DIR` and writes ONE 1Password `.1pif` import file holding eleven items: the six passwords, both Borg key exports, the WireGuard template and the two halves of the panel CA. The point is that the passwords never pass through a chat window, a clipboard or a terminal transcript. Format and item naming follow the owner's own vault export (1Password Interchange Format, one JSON object per line, `webforms.WebForm` throughout, titles `hih - <what> > Server`), so the imported items sit beside their predecessors instead of looking foreign. The file-backed items leave the password field empty and carry the content in the note, exactly as the existing ones do. The earlier CSV script `tools/secrets-to-1password.sh` is superseded and reduced to a stub: CSV cannot carry the notes and URLs the vault uses, so it was dropped rather than kept as a second, worse path.
- **SMTP_PASS is now cleared automatically.** Phase 4 writes the mail password to `/etc/msmtp-pass` (mode 600) and then blanks the variable in the server's `install.conf`, keeping a timestamped backup of the file. The previous behaviour was a warning line in the output — it was overlooked, and the password then sat in the file in the clear for days. A `verify` check guards it. What the script cannot reach is the copy of `install.conf` on the operator's own machine; phase 4 says so in its own warning line. Re-running phase 4 needs the value entered again from the password manager.
- **Twelve new verify checks**, 44 → 56 (the first ten confirmed green individually on the test server 2026-10-03): sshd banner active, drop-ins mode 600, `fs.suid_dumpable` 0 at runtime, apport masked, group `wheel` present and empty, `INACTIVE=30`, `umask 027` in bash.bashrc, GRUB password plus `--unrestricted` (only when the flag is on), rsync present with the daemon masked, SMTP_PASS cleared in install.conf.

### Changed

- **ext4 reserved blocks now scale with the volume:** 1% at 1 TB and above, 5% below. Five percent of the 4 TB HDD would park 200 GB that only root may ever touch; 1% of 4 TB is 40 GB and serves the same purpose. The `verify` check now measures in PER MILLE and accepts 8–60. Measuring in whole percent was wrong and was caught on the test server: tune2fs rounds the reserved-block count down, so `-m 1` yields 26214 of 2621440 blocks = 0.99998%, an integer percent calculation returns 0, and a `>= 1` test fails on a correctly configured volume.
- **Disk-space alert thresholds per mountpoint.** `disk-space-alert.sh` takes `<mount>[:<warn>[:<crit>]]`; the service is called with `$HDD_MOUNT:85:95 /:80:90`. The root filesystem needs the earlier warning: Docker image layers, the journal, the apt cache and the NC DB dump can take it from comfortable to full inside one upgrade, and it has no second volume to spill onto.
- **rsync is no longer purged in phase 12.** It is the tool for the transitional-NVMe → 4 TB HDD move and for every later volume change; purging it and reinstalling under time pressure during a maintenance window is the wrong trade. `rsync.service` is masked instead (CIS `service_rsyncd_disabled`).

### Lynis

Hardening index **85 → 86 → 87**, 265 tests, zero warnings, suggestions down from 20 to 17. Three of the remaining Lynis findings turned out to be real after the CIS round:

- **BANN-7126 and BANN-7130 had never passed.** The banner existed, but the test demands at least FIVE matches from its key-word list and the old two-liner hit four (`access`, `authori`, `log`, `monitor`) - see `/usr/share/lynis/include/tests_banners` line 29. The 0.4.0 changelog claimed these two were addressed; they were not. The new wording adds that unauthorised use is prohibited and will be prosecuted, which is the sentence that makes a banner legally useful rather than keyword stuffing. Seven matches now.
- **ACCT-9626: sysstat was installed but disabled.** It ships `ENABLED="false"`, so `sar` collected nothing. Performance history is what answers "when did this volume start filling up" and "was the load always like this" - the questions that come up during a volume migration. Now enabled.
- **KRNL-6000: `kernel.core_uses_pid`** set to 1. The other two deviations Lynis names stay as they are: `net.ipv4.conf.all.forwarding` is required by Docker and WireGuard, and `kernel.modules_disabled=1` would block the on-demand module loading both rely on - setting it in phase 5 would break phase 9.

Two Lynis suggestions were proven false rather than accepted. **FINT-4402** ("use SHA256 or SHA512 in AIDE") greps the config for the literal strings and finds only `Checksums = H`; `aide --version` resolves that compound group to `md5+sha1+rmd160+tiger+crc32+haval+gost+crc32b+sha256+sha512+whirlpool`, so both hashes are in use. **SSH-7408** reduces to `AllowTcpForwarding yes`, which is deliberate; every other SSH option is reported "configured very well".

The 17 that remain are architecture (separate `/var` and `/home` partitions, external log host), duplication (process accounting next to auditd), noise (deleted files in use, unused iptables rules under Docker, automation tooling) or taste (malware scanner, apt-show-versions).

### Corrected

- The 0.5.0 entry above first described `accounts_password_set_max_life_existing` as a rejected finding. That was wrong: phase 5 has always run `chage -M 365 -m 1 -W 14` on `$ADMIN_USER`, so the password does expire - CIS objects because its rule wants a value BELOW 365. The expiry stays, with the operational caveat that it must be rotated over SSH with `passwd` well before the date: if it lapses while the VNC console is the only way in, the login there forces a password change through the console's scrambled key mapping.
- The ext4 reserve check shipped earlier in this release was itself broken, in percent arithmetic. Fixed in per mille before it reached the production run; details under *Changed*.
- verify is at **56** checks, not 54: the banner key-word count and sysstat were added after the first count.

### Rehearsed

- **Volume migration, end to end.** `/srv/hdd` moved to a second volume with `rsync -aHAX --numeric-ids` after stopping the NC stack and the Borg timer and path unit: delta run reported `Literal data: 0 bytes`, the file lists of both sides were identical, `du -sb` matched to the byte, the fstab swap and remount worked, and `borg check --verify-data` on `repo-server` returned 0 afterwards. Reboot clean. The twelve-step runbook is in `Handover.md` §5. Throughput in the rehearsal was ~100 MB/s between two loop images on one NVMe; on the real move the HDD is the bottleneck at an expected 150–200 MB/s, so 800 GB is roughly two hours — the two days of parallel operation agreed with the provider are generous, not tight.
- **Provider backup restore:** 1 min 55 s to back up, 1 min 55 s to restore. The rollback anchor for the whole install run is now a measured quantity.
- **Nextcloud quota** confirmed via `occ config:app:set files default_quota` and `occ user:setting <user> files quota`.
- **Network from the server:** 1.37 ms IPv4, 1.35 ms IPv6, no loss over 10 packets. NVMe write 1.6 GB/s with `oflag=direct`.

### Notes

- Ubuntu 24.04 ships **no `faillock` profile** in `/usr/share/pam-configs/`; `pam-auth-update --enable faillock` therefore runs through with exit code 0 and changes nothing. Enabling the three CIS faillock findings would require a hand-written PAM profile. Deliberately not done: SSH is key-only, fail2ban and `MaxAuthTries 3` already cover brute force, and a lockout would land exactly on the VNC rescue console, whose scrambled key mapping makes five failed attempts easy to reach. `/etc/security/faillock.conf` carries sane values should that decision change.
- The CIS checks `sshd_set_idle_timeout`, `sshd_set_keepalive` and `sshd_set_loglevel_info` fail although the effective values satisfy or exceed the benchmark — the check reads the main config file and does not see the drop-in. Other sshd rules in the same profile pass. Judge by `sshd -T`, not by the report.
- **`aide.db.new` is never promoted to `aide.db`** (Ubuntu default, it wants confirmation). Consequence: after every `apt upgrade` the daily report repeats the same legitimate changes and the noise grows until nobody reads it. Promote the database after confirmed system changes — an operational task, not a script one.

## [0.4.0] - 2026-10-01

First complete end-to-end run on a real machine (Hostishere test server, Ubuntu 24.04.5,
1 core / 2 GB). All thirteen phases ran in sequence, `verify` reported 44/44 before and
after the reboot, and the full mandatory validation chain of `Handover.md` §9 passed.

### Fixed

- **sysctl hardening was partly ineffective.** The settings were written to `/etc/sysctl.d/99-hardening.conf`, which sorts *before* Ubuntu's own `/usr/lib/sysctl.d/99-protect-links.conf` and was therefore overridden by it: `fs.protected_fifos` was set to 2 in the file but ran at 1 on the live system. The file is now written as `99-zz-hardening.conf` and the old name is removed on each run. This was a silent failure — `verify` never saw it, and it would have hit any future hardening value that also appears in a later-sorting system file.

### Added

- **Panel CA (phase 11).** Cockpit shipped a certificate for the host FQDN and Portainer one with a completely empty subject, while both panels are reached as `https://<WG>.1:PORT`. No browser can match either certificate to that address, so the warning persisted no matter how often the certificate was trusted. Phase 11 now creates a small CA in `$SECRETS_DIR/panel-ca`, issues one certificate carrying `IP:<WG>.1` in its SAN (plus the FQDN when set), hands it to Cockpit as `1-panel.cert` and to Portainer via `--sslcert`/`--sslkey`, and prints the path of the root certificate for a one-time import on the client. Lifetime 800 days, `serverAuth` EKU and SAN as required by Apple's certificate policy.
- **`SSH_CLIENT_KEY`** config variable plus the helpers `server_ip()` and `login_cmd()`. The login hints after phase 1, phase 2, `bootstrap` and `all` now print a ready-to-paste command including the key path and the machine's actual IPv4 instead of `<ip>` placeholders. `preflight` asks for the value once if unset and writes it back to `install.conf`.
- **Password hashing rounds** (phase 5): `SHA_CRYPT_MIN_ROUNDS`/`SHA_CRYPT_MAX_ROUNDS` set to 65536 in `login.defs`. Effective because `ENCRYPT_METHOD` is SHA512 (Lynis AUTH-9229/9230).
- **Legal banner** in `/etc/issue` and `/etc/issue.net`, bilingual (Lynis BANN-7126/7130).

### Changed

- ShellCheck workflow tightened from `--severity=error` to `--severity=warning`; `install.sh` is clean at that level (verified with ShellCheck 0.9.0, only SC2015/SC1091 remain on "info").
- `README.md`, `README.de.md` and `Install-Guide.md`: the storage-transition wording no longer names a "second 500 GB NVMe" or "month 5" — both became wrong with the change of provider.

### Notes

- Verified on real hardware for the first time: the Redis `cap_add` set (CHOWN/SETUID/SETGID) is sufficient, no `DAC_OVERRIDE` needed; Portainer CE starts and binds only to the WireGuard address; the Caddy DNS gate passed on the first attempt; msmtp delivers (status 250); the Nextcloud fail2ban filter matches real log lines and the IPv6 ban enters the whole `/64` into the `f2b-v6prefix` ipset; a Borg restore round-trip extracted byte-identical files and `borg check --verify-data` passed.
- External `nmap` from a foreign network, over IPv4 and separately over IPv6: 80, 443 and the SSH port open, port 22 and both panel ports filtered. No IPv6-only hole.
- Two Lynis findings turned out to be false alarms and were deliberately not "fixed": AIDE's `Checksums = H` already means every compiled-in hash including SHA-512, and the debsums cron job exists (phase 7) but is not where Lynis looks for it.
- `Handover.md` §4 claimed the test server runs UEFI; it does not (`/sys/firmware/efi` absent). The argument that the test run is therefore transferable to a UEFI production server does not hold.

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
