# Install Guide — Prepare · Run · Finish

The operational, step-by-step companion to [`install.sh`](install.sh) (Rev. 5). It walks a
fresh Ubuntu 24.04 VDS/VPS from bare install to a hardened host running a private Nextcloud,
with the admin panels reachable only through a WireGuard tunnel. Rescue anchor for every
SSH change: the provider's noVNC console (independent of SSH). Note that some providers have
**no** rescue mode and **no** ISO mount — there the only further lifeline is the provider
backup.

All example values below are placeholders: user `netzbub`, domain `example.com`, provider
`example-host.com`, SSH port `22022`, server IPv4 `203.0.113.10`, IPv6 `2001:db8::c`. Replace
them with your own — most of them live in your git-ignored `install.conf`.

## Guiding idea: prepare everything, then run in one go

`install.sh` has exactly **one** unavoidable interruption: the SSH login test after Phase 2
(lock-out protection). Everything else is a prerequisite that belongs **before** the run.
Hence three steps:

1. **Prepare** — Mac keys, DNS, HDD, config values. Complete, before the server is touched.
2. **Run** — `bootstrap` (phases 0–2) → login test → `rest` (phases 3–12 + verify).
3. **Finish** — Nextcloud stack + 2FA, Borg init, WireGuard client, reboot, Ubuntu Pro, external nmap.

> **First-run exception.** The assembled Rev. 5 script has not yet been run end-to-end. The
> very first real run on a new server should still be **phase by phase** (to catch any
> assembly issue live). `bootstrap`/`rest` is the routine for afterwards.

## Marking convention in this document

```
[+ Info +]     information only, nothing to do
[ ! Do ! ]     a step to carry out
```

> **Two numbering systems:** **script phases** = **Phase 0–12**; this guide is organised in
> **Parts 1–5**.

## Server data (example)

```
Hostname : server.example.com
Provider : example-host.com   (some providers offer no rescue mode, no ISO mount)
IPv4     : 203.0.113.10
IPv6     : 2001:db8::c
SSH port : 22022  (key-only)
SSH key  : ~/.ssh/server_ed25519  (on the local machine)
System mail (sender): admin@example.com
```

---

# PART 1 — PREPARE

Everything here happens BEFORE the server run. Only when all points are in place, move to Part 2.

## 1.1 Local machine: SSH admin key

`[ ! Do ! ]` If you do not have one yet — store the passphrase in your password manager:

```
ssh-keygen -t ed25519 -a 64 -f ~/.ssh/server_ed25519 -C "server-admin-key"
cat ~/.ssh/server_ed25519.pub
```

You will need the `.pub` content for `SSH_PUBKEY` in `install.conf`.

## 1.2 Local machine: WireGuard client key (for WG_CLIENT_PUBKEY)

`[ ! Do ! ]`

```
mkdir -p ~/.wireguard && chmod 700 ~/.wireguard
wg genkey | tee ~/.wireguard/wg-client.key | wg pubkey > ~/.wireguard/wg-client.pub
chmod 600 ~/.wireguard/wg-client.key
cat ~/.wireguard/wg-client.pub
```

Put the `.pub` content into `WG_CLIENT_PUBKEY`. The private key stays on the local machine
(it goes into the client config later, Part 3.4).

## 1.3 Local machine: backup keys (append-only + trigger)

`[ ! Do ! ]` Two purpose-built keys, separate from the admin key:

```
ssh-keygen -t ed25519 -a 64 -f ~/.ssh/vps_borg    -C "borg-append-only"
ssh-keygen -t ed25519 -a 64 -f ~/.ssh/vps_trigger -C "borg-trigger"
cat ~/.ssh/vps_borg.pub ~/.ssh/vps_trigger.pub
```

`[+ Info +]` These two `.pub` do NOT go into the script; they go into the server's
`authorized_keys` later (Part 3.3).

## 1.4 DNS (registrar) — before the run

`[ ! Do ! ]` A record (and, after the IPv6 test, AAAA) for `next.example.com` to the server IPv4:

```
next.example.com.  A     203.0.113.10
```

`[+ Info +]` If the record is not correct when Phase 9 starts, the DNS gate aborts in a
controlled way (protecting the Let's Encrypt rate limit). Wait for the TTL. Set AAAA only
after IPv6 is tested.

## 1.5 Determine NC_IMAGE_TAG

`[ ! Do ! ]` Look up the current stable Nextcloud tag at hub.docker.com/_/nextcloud/tags
(take the tag WITHOUT the `-apache` suffix; the base image is already Apache). Prefer a
digest comparison over trusting the `stable` tag name:

```
curl -s "https://hub.docker.com/v2/repositories/library/nextcloud/tags/?page_size=100" \
  -o /tmp/nctags.json

python3 - <<'PY'
import json
d = json.load(open('/tmp/nctags.json'))
digest = next(x['digest'] for x in d['results'] if x['name'] == 'stable')
print(sorted(x['name'] for x in d['results'] if x.get('digest') == digest))
PY
```

## 1.6 Prepare SMTP access

`[+ Info +]` For system mail (backup failures, logwatch). You need: host, port (587
STARTTLS / 465 SMTPS), user (often the full address), an app password, and a sender (= the
authenticated mailbox). Put `SMTP_PASS` in only for the one-time write; clear it again
afterwards.

## 1.7 Fetch the script and fill in the config

`[ ! Do ! ]` On the server, place `install.sh` and its config next to each other. Personal
values are NOT edited into the script — they live in a separate, git-ignored `install.conf`:

```
cd /root
# copy install.sh and install.conf.example here (scp, git clone, curl, …)
cp install.conf.example install.conf
nano install.conf
chmod +x /root/install.sh
```

Fill in `install.conf`:

| Variable | Value | Needed for |
|---|---|---|
| `ADMIN_USER` | your sudo/SSH user, e.g. `netzbub` | Phase 1 |
| `SSH_PORT` | non-standard port, e.g. `22022` | Phase 1/2 |
| `SSH_PUBKEY` | content of `~/.ssh/server_ed25519.pub` (one line) | **required, Phase 1** |
| `ADMIN_MAIL` | `admin@example.com` | required (system mail) |
| `HOSTNAME_FQDN` | `server.example.com` or empty | optional |
| `NC_DOMAIN` | `next.example.com` | Phase 9 |
| `NC_IMAGE_TAG` | current NC tag (1.5) | Phase 9 |
| `WG_CLIENT_PUBKEY` | content of `~/.wireguard/wg-client.pub` (1.2) | Phase 8 |
| `SMTP_HOST/PORT/USER/PASS/FROM` | SMTP access (1.6) | Phase 4 |
| `ENABLE_GRUB_HARDENING` | `no` (default) | see Part 4.8 |

`[+ Info +]` Paste `SSH_PUBKEY` by copy-paste, never type it — one wrong character locks you
out. Clear `SMTP_PASS` again after the run. `install.conf` is git-ignored and never uploaded.

## 1.8 Set up the HDD (before Phase 9/10)

`[ ! Do ! ]` Identify the device, then (adjust the device name; `/dev/sdb` is a placeholder):

```
lsblk
parted /dev/sdb mklabel gpt
parted /dev/sdb mkpart primary ext4 0% 100%
mkfs.ext4 /dev/sdb1
UUID=$(blkid -s UUID -o value /dev/sdb1)
echo "UUID=$UUID /srv/hdd ext4 defaults,nosuid,nodev,nofail,x-systemd.device-timeout=30 0 2" \
  >> /etc/fstab
systemctl daemon-reload
mount /srv/hdd
mountpoint -q /srv/hdd && echo "HDD ok"
```

> `nofail` prevents an emergency boot without SSH if the HDD is ever missing. Test without a
> real HDD (loopback): see Part 5.

> Phase 9 sets an explicit `tune2fs -m 5` reserved-blocks headroom on this device and installs
> a twice-daily disk-space-alert timer (85%/95% thresholds, mailed) — both keyed off whatever
> is mounted at `/srv/hdd`, so this works unchanged for the transitional second 500 GB NVMe
> and, from month 5, the 4 TB HDD. No manual step needed here beyond the mount itself.

---

# PART 2 — RUN

## 2.1 First access to the server

**Preferred (copy-paste):** SSH from the local machine.

```
ssh root@203.0.113.10
```

Root password from the provider panel. If password SSH is off by default, enable it briefly
in the panel.

**Alternative (zero network exposure):** the noVNC console as root. If pasted `/` turns into
`-`, switch the keyboard with `loadkeys us`.

## 2.2 First run — phase by phase (acceptance)

`[ ! Do ! ]` Each phase INDIVIDUALLY; check the output (red `[ERROR]` = stop).

```
/root/install.sh preflight
/root/install.sh phase1
cat /root/install-secrets/admin-user-password   # save this offline
```

**Phase 2 — SSH hardening (CRITICAL POINT):**

```
/root/install.sh phase2
```

Immediately test in a SECOND terminal — keep the first session open:

```
ssh -p 22022 -i ~/.ssh/server_ed25519 netzbub@203.0.113.10
sudo -v
```

If both work → continue. If not → repair in the still-open session / noVNC, do NOT close the
rescue session. Then:

```
/root/install.sh phase3
/root/install.sh phase4
/root/install.sh phase5      # GRUB boot params only if ENABLE_GRUB_HARDENING=yes (default no; Part 4.8)
/root/install.sh phase6
/root/install.sh phase7
/root/install.sh phase8      # DNS must be set (1.4) before Phase 9
/root/install.sh phase9      # watch the Redis start
/root/install.sh phase10
/root/install.sh phase11
/root/install.sh phase12     # AIDE init takes minutes (100 % CPU) — not a hang, don't abort
```

## 2.3 Routine for later installs (after acceptance)

`[ ! Do ! ]` Once the prerequisites (Part 1) are in place:

```
/root/install.sh bootstrap
```

→ test the login in the second terminal (Phase 2), save the admin password, then:

```
/root/install.sh rest
```

`rest` runs phases 3–12 + `verify` in one pass.

---

# PART 3 — FINISH

## 3.1 Start the Nextcloud stack + enforce 2FA

`[ ! Do ! ]` The stack does not start automatically. Once DNS is set:

```
cd /srv/nextcloud && docker compose up -d
docker compose -f /srv/nextcloud/docker-compose.yml logs -f app   # until "successfully installed"
```

The admin account is created automatically:

```
cat /srv/nextcloud/secrets/nc_admin.txt   # password; user = ADMIN_USER
```

Then enforce 2FA (once):

```
/usr/local/bin/nc-post-setup.sh
```

## 3.2 Nextcloud updates — image tag only

`[+ Info +]` Never use the update button in the NC admin backend with this compose setup (it
writes into the container filesystem and is lost on recreate). The only correct way:

```
# set the new NC_IMAGE_TAG in install.conf, then:
cd /srv/nextcloud
docker compose pull
docker compose up -d
docker compose exec -u www-data app php occ upgrade
```

## 3.3 Borg: initialise repo-local + add the keys

`[ ! Do ! ]` Mind the order.

**a) Trigger directory** (if Phase 10 did not create it):

```
mkdir -p /srv/hdd/backup/trigger && chown netzbub:netzbub /srv/hdd/backup/trigger
```

**b)** Add one line each to `/home/netzbub/.ssh/authorized_keys`. `<CONTENT …>` = the full
content of the respective `.pub`, no angle brackets:

```
command="borg serve --append-only --restrict-to-path /srv/hdd/backup/repo-local",restrict <CONTENT vps_borg.pub>
command="touch /srv/hdd/backup/trigger/.run-backup",restrict <CONTENT vps_trigger.pub>
```

The existing admin key stays as the first line, UNCHANGED.

> **Each entry is ONE physical line** — `authorized_keys` does not allow backslash
> continuation. Do not wrap, even if the lines are long. When editing `authorized_keys`,
> always keep a second root session open until the new state is tested (lock-out risk).

**c) Test the keys** (local machine):

```
ssh -p 22022 -i ~/.ssh/vps_trigger netzbub@203.0.113.10   # must disconnect immediately
```

**d) Initialise repo-local** (local machine; port/key in BORG_RSH, not in the URL):

```
BORG_RSH="ssh -p 22022 -i ~/.ssh/server_ed25519" borg init --encryption=repokey-blake2 \
  ssh://netzbub@203.0.113.10/srv/hdd/backup/repo-local
```

`[+ Info +]` Init with the admin key (full access); use the append-only `vps_borg` afterwards
for `borg create`. You choose the repo-local passphrase here — save it (Parts 4.1/4.2).

**e) Backup chain** (local machine):

```
BORG_RSH="ssh -p 22022 -i ~/.ssh/vps_borg" borg create \
  ssh://netzbub@203.0.113.10/srv/hdd/backup/repo-local::'{now}' /path/to/local/data
ssh -p 22022 -i ~/.ssh/vps_trigger netzbub@203.0.113.10   # triggers the server backup
```

**f) Restore test** (mandatory; without macFUSE via extract):

```
BORG_RSH="ssh -p 22022 -i ~/.ssh/vps_borg" borg list ssh://netzbub@203.0.113.10/srv/hdd/backup/repo-local
mkdir -p /tmp/borg-extract && cd /tmp/borg-extract
BORG_RSH="ssh -p 22022 -i ~/.ssh/vps_borg" borg extract --list \
  ssh://netzbub@203.0.113.10/srv/hdd/backup/repo-local::ARCHIVE_NAME
```

`[+ Info +]` `prune` (deleting old archives) is deliberately NOT possible with the
append-only key; that needs a separate full-access key. Tip: an `~/.ssh/config` alias on the
local machine bundling port/key/user/host.

## 3.4 WireGuard client on the local machine

`[ ! Do ! ]` Fill in `~/.wireguard/wg0-client.conf` yourself (never keys in chat/docs):

```
[Interface]
PrivateKey = <content of ~/.wireguard/wg-client.key>
Address = 10.8.0.2/24

[Peer]
PublicKey = <wg show wg0 public-key (server)>
PresharedKey = <PresharedKey from /etc/wireguard/wg0.conf (server)>
Endpoint = 203.0.113.10:51820
AllowedIPs = 10.8.0.0/24
PersistentKeepalive = 25
```

> `PublicKey`/`PresharedKey` are the SERVER values, not your own — a common mix-up.

Start / check / stop:

```
sudo wg-quick up ~/.wireguard/wg0-client.conf
ping 10.8.0.1 && sudo wg show
sudo wg-quick down ~/.wireguard/wg0-client.conf
```

In the tunnel: Portainer `https://10.8.0.1:9443`, Cockpit `https://10.8.0.1:9090`.

## 3.5 Reboot

`[ ! Do ! ]` Boot parameters/fstab take effect only after a reboot. Take a fresh provider
backup first.

```
shutdown -r +1
```

After the reboot: HDD mounted, containers up, Caddy/WG/auditd/fail2ban active, NC 200.

## 3.6 Ubuntu Pro + USG/CIS

`[ ! Do ! ]` Free for up to 5 machines (ESM + Livepatch):

```
pro attach <token>
pro enable usg
```

`[+ Info +]` `pro attach` enables `esm-apps`/`esm-infra`/`livepatch` itself. Do NOT enable
`anbox-cloud`, `cc-eal`, `fips*`, `landscape`, `realtime-kernel`, `ros*`. Only *evaluate* the
USG audit — do **not** blindly run `usg fix` (Docker/UFW/WireGuard conflicts; the deliberate
CIS deviations are documented in the README).

## 3.7 Mandatory external check

`[ ! Do ! ]` From a foreign network (phone hotspot), with the WireGuard tunnel DOWN:

```
nmap -Pn 203.0.113.10 -p 22022,80,443,9443,9090
nmap -6 -Pn 2001:db8::c -p 9443,9090
```

- MAY be open: 22022 (SSH), 80/443 (Caddy). WireGuard 51820/udp does not answer scans.
- MUST be closed: 9443 (Portainer), 9090 (Cockpit) — over IPv4 AND IPv6. The internal
  `verify` does NOT see this exposure.

Internal check:

```
/root/install.sh verify
```

---

# PART 4 — REFERENCE / OPERATION

## 4.1 Four passphrases — do not confuse

| # | Passphrase | Set by | Purpose / location |
|---|---|---|---|
| 1 | SSH key `vps_borg` | user (local) | protects the private backup SSH key |
| 2 | SSH key `vps_trigger` | user (local) | protects the trigger SSH key |
| 3 | Borg repo `repo-local` | user, at `borg init` (3.3d) | protects the repo key of the local-machine backup |
| 4 | Borg repo `repo-server` | auto (script) | `/root/.borg-passphrase`; repo the server backs itself into. Still save it externally. |

## 4.2 Borg key export + emergency restore

`[ ! Do ! ]` Export the repo key and store it externally (password manager + paper):

```
BORG_RSH="ssh -p 22022 -i ~/.ssh/vps_borg" borg key export ssh://netzbub@203.0.113.10/srv/hdd/backup/repo-local ~/borg-key-repo-local-backup
BORG_RSH="ssh -p 22022 -i ~/.ssh/vps_borg" borg key export --paper ssh://netzbub@203.0.113.10/srv/hdd/backup/repo-local ~/borg-key-repo-local-backup.txt
```

Two loss scenarios:

- **Local keys `vps_borg`/`vps_trigger` lost** → generate new SSH keys, add to
  `authorized_keys`. No Borg data affected.
- **Repo key damaged / server totally lost** → import the key (AND repo passphrase #3 needed):

```
BORG_RSH="ssh -p 22022 -i ~/.ssh/vps_borg" borg key import ssh://netzbub@203.0.113.10/srv/hdd/backup/repo-local ~/borg-key-repo-local-backup
```

## 4.3 Directories / secrets / logs

| Service | Config | Secret | Log |
|---|---|---|---|
| SSH | `/etc/ssh/sshd_config.d/10-hardening.conf` | keys under `~/.ssh/*` (local) | `/var/log/auth.log` |
| Firewall | `ufw status verbose`, `nft list ruleset` | – | `/var/log/ufw.log` |
| fail2ban | `/etc/fail2ban/jail.local`, `jail.d/` | – | `/var/log/fail2ban.log` |
| auditd | `/etc/audit/rules.d/` | – | `/var/log/audit/audit.log` |
| Mail (msmtp) | `/etc/msmtprc` | `/etc/msmtp-pass` | `/var/log/msmtp.log` |
| WireGuard | server `/etc/wireguard/wg0.conf`; local `~/.wireguard/wg0-client.conf` | keys in configs | `journalctl -u wg-quick@wg0` |
| Docker | `/etc/docker/daemon.json` | – | `docker logs <container>` |
| Nextcloud | `/srv/nextcloud/docker-compose.yml` | `/srv/nextcloud/secrets/{db_root,db_pass,nc_admin}.txt` | `docker compose -f /srv/nextcloud/docker-compose.yml logs app` |
| NC data | `/srv/hdd/ncdata` | – | `/srv/hdd/ncdata/nextcloud.log` |
| Caddy | `/etc/caddy/Caddyfile` | – | `journalctl -u caddy` |
| Borg repo-server | `/srv/hdd/backup/repo-server` | `/root/.borg-passphrase` | `journalctl -u borg-backup` |
| Borg repo-local | `/srv/hdd/backup/repo-local` | passphrase #3; key export in `~/` (local) | – |
| Portainer | `docker inspect portainer` | – | `docker logs portainer` |
| Cockpit | – | – | `journalctl -u cockpit` |
| Lynis | `/etc/lynis/default.prf` | – | `/var/log/lynis.log` |
| AIDE | `/etc/aide/aide.conf.d/` | – | `/var/lib/aide/aide.db` |

## 4.4 Maintenance — automatic vs. manual

**Runs by itself:** unattended-upgrades, `borg-backup.path` (event) + `.timer` (weekly),
logwatch daily, fail2ban bans, Caddy TLS renewal, container restart, timesyncd.

**You keep an eye on:**

- read the daily logwatch mail
- `fail2ban-client status sshd` occasionally
- weekly `docker compose ps` (all healthy)
- Borg: failure mail is automatic; occasionally check `borg list`
- `df -h` (NVMe and HDD separately)
- NC major updates manually (4.2)
- container/image updates in Portainer are run by hand, not automatic (no maintained app store)
- monthly `lynis audit system`, keep an eye on the hardening index (±1–2 points is noise)

## 4.5 Access paths

- **Nextcloud** `https://next.example.com`: public via Caddy.
- **Portainer/Cockpit**: only over WireGuard (`10.8.0.1:9443` / `:9090`), closed from outside.
- **SSH** port 22022: public, but key-only + fail2ban.

## 4.6 One-way sync local → Nextcloud

> **Project rule:** the sync local → NC must be one-way (local → remote). NC must never write
> back to the local machine (a past bidirectional sync corrupted local data).

No NC desktop client for the bulk of the data. Instead (local machine):

```
rclone copy /local/path ncwebdav:/remote/target --immutable -v
```

(`ncwebdav` = a WebDAV remote to `https://next.example.com/remote.php/dav/files/<ADMIN_USER>/`,
set up via `rclone config`.)

The only exception: EXACTLY ONE dedicated exchange folder may sync bidirectionally — and only
that folder may use the regular NC desktop client.

## 4.7 Monitoring to the phone (optional, still open)

- Simplest: read the existing mails (logwatch, Borg alarm) in the phone's mail app.
- **Uptime Kuma** (self-hosted, e.g. on a NAS): web dashboard + push (ntfy/Telegram/Pushover).
- **healthchecks.io**: dead-man's switch (alarm on a missing ping).

`[+ Info +]` Check the current availability/terms before setting these up (not verified here).

## 4.8 GRUB boot params + boot-loop warning

> **Incident:** a stacked, untested set of boot params (`apparmor=1 security=apparmor audit=1
> audit_backlog_limit=8192`) once sent the VM into a boot loop; recovery only from the provider
> backup. **Never set those four.**

`ENABLE_GRUB_HARDENING="no"` is the default. The Phase 5 param set (`slab_nomerge init_on_alloc=1
init_on_free=1 page_alloc.shuffle=1 randomize_kstack_offset=on vsyscall=none lockdown=integrity`)
is proven safe on the test VM. Enable ONLY deliberately:

```
# 1) fresh provider backup
# 2) ENABLE_GRUB_HARDENING="yes" in install.conf, then:
/root/install.sh phase5
# 3) reboot, then check:
grep -o 'apparmor=1' /proc/cmdline || echo "ok - no apparmor boot param"
```

**GRUB password** (separate, do not reuse root/admin) — only with a working rescue/VNC console:

```
grub-mkpasswd-pbkdf2
# put the hash into /etc/grub.d/40_custom, then:
update-grub
```

---

# PART 5 — Pitfalls

- **`SSH_PUBKEY` typo = lock-out.** Hence the login test after Phase 2, before the first session is closed.
- **Admin password** (`/root/install-secrets/admin-user-password`) — save it before ending the session, otherwise the VNC console is useless on lock-out.
- **DNS before Phase 9**, else Let's Encrypt rate limit.
- **Cockpit login** = system user + Unix password (`passwd <user>`, must satisfy pwquality: 14 chars, 4 classes). No separate Cockpit password.
- **noVNC keyboard:** `loadkeys us` for pasted paths (`/` → `-`); `loadkeys de` for typing.
- **noVNC is one-way** (no copy-out). Fallback: screenshot → macOS Live Text OCR (double-check `l/1/I`, `O/0` for base64).
- **Config files:** before appending a directive with `>>`, always `grep` whether it already exists (SSH takes the FIRST on duplicates — otherwise silently ineffective).
- **Check the effective sshd value** (do not trust the file): `sshd -T | grep -i permitrootlogin`.
- **Restricted Borg keys:** end hung SSH sessions cleanly with `exit`/`~.` (not Ctrl+C), and keep no more parallel sessions than needed (sporadic disconnects observed).
- **AIDE init** (Phase 12) takes minutes at 100 % CPU — normal, do not abort.
- **Remove the script after the run** (`shred -u`/`rm`) if secrets were entered; clear `SMTP_PASS`.
- **Provider console/backup** is the only lifeline on lock-out — never lose both access paths at once.
