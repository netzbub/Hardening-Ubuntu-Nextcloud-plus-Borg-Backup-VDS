# Hardening-Ubuntu-Nextcloud-plus-Borg-Backup-VDS

<p align="center">
  <img src="https://img.shields.io/github/v/tag/netzbub/Hardening-Ubuntu-Nextcloud-plus-Borg-Backup-VDS?label=version&color=blue" alt="version">
<img src="https://img.shields.io/github/license/netzbub/Hardening-Ubuntu-Nextcloud-plus-Borg-Backup-VDS?color=olive&cacheSeconds=3600" alt="license">
  <img src="https://img.shields.io/github/last-commit/netzbub/Hardening-Ubuntu-Nextcloud-plus-Borg-Backup-VDS?color=blueviolet" alt="last commit">
  <img src="https://img.shields.io/github/issues/netzbub/Hardening-Ubuntu-Nextcloud-plus-Borg-Backup-VDS?color=yellow" alt="open issues">
  <img src="https://img.shields.io/badge/Ubuntu-24.04-E95420?logo=ubuntu&logoColor=white" alt="Ubuntu 24.04">
  <img src="https://github.com/netzbub/Hardening-Ubuntu-Nextcloud-plus-Borg-Backup-VDS/actions/workflows/shellcheck.yml/badge.svg" alt="ShellCheck">
</p>

*A phased, verifiable hardening and setup recipe for a single Ubuntu 24.04 VDS/VPS that runs a Nextcloud behind Caddy, doubles as an off-site Borg backup vault on a 4 TB disk for the operator's local (Mac) data, and exposes its admin panels only through a WireGuard tunnel.*

> **Scope in one sentence.** The script — `install.sh` — turns a standard Ubuntu 24.04 install into a hardened remote server for a Nextcloud plus an event-triggered Borg backup — thoroughly checked with Lynis (index score 83), the CIS benchmark, external port scans and fail2ban-regex tests.

🇩🇪 **German version: [README.de.md](README.de.md)**

This is a personal-infrastructure project, not a product. It documents a concrete, opinionated build for **one operator, one small Nextcloud** (occasionally 2–3 read-only guests), with a strong bias toward a small attack surface and toward recoverability.

---

<p align="center">
<img src="images/Rudern-zwei-en.jpg" width="50%" alt="...">  
</p>

### Table of contents

- [Hardening-Ubuntu-Nextcloud-plus-Borg-Backup-VDS](#hardening-ubuntu-nextcloud-plus-borg-backup-vds)
    - [Table of contents](#table-of-contents)
    - [Purpose](#purpose)
  - [Architecture and components](#architecture-and-components)
    - [The stack as implemented](#the-stack-as-implemented)
    - [Nextcloud data model: one-way upload plus one exchange folder](#nextcloud-data-model-one-way-upload-plus-one-exchange-folder)
  - [Backup: 4 TB HDD plus Borg](#backup-4-tb-hdd-plus-borg)
    - [Control panels: the two we chose](#control-panels-the-two-we-chose)
    - [Hardening concept](#hardening-concept)
    - [Installation: phased, tested, verified](#installation-phased-tested-verified)
    - [Server directory structure](#server-directory-structure)
    - [How far to harden — and where we deliberately stopped](#how-far-to-harden--and-where-we-deliberately-stopped)
    - [Status and roadmap](#status-and-roadmap)
    - [Genesis](#genesis)
    - [Version History](#version-history)
    - [License](#license)
    - [Acknowledgments](#acknowledgments)
    - [Trademarks + Logos](#trademarks--logos)

---

### Purpose

`Ubuntu 24.04` on a rented virtual server is an excellent base, but a fresh install is wide open: password SSH, root login, no firewall policy worth the name, no intrusion throttling, no audit trail, no backup. This project closes that gap in a **reproducible, reviewable** way and puts a useful workload on top of it — a private Nextcloud — without sacrificing the ability to actually operate the machine day to day.

Two principles run through everything:

- **Small attack surface first.** Only Nextcloud (`443`) and SSH (a high, non-standard port) face the public internet. Every administrative surface is reachable only over a WireGuard tunnel.
- **Verify, don't trust.** No step is considered done because the script printed "OK". Firewall closure is proven with an external `nmap` (IPv4 **and** IPv6), the fail2ban filter is tested against real log lines, and the backup is proven with an actual restore before anything goes to production.

---

## Architecture and components

| Component                                   | Role                          | Why this one                                                                 |
| ------------------------------------------- | ----------------------------- | ---------------------------------------------------------------------------- |
| **Ubuntu 24.04 LTS**                  | Base OS                       | Long-term support; the operator's most familiar system                       |
| **Docker + Compose**                  | Container runtime             | Isolates the Nextcloud stack; clean deploy/teardown                          |
| **Nextcloud** (MariaDB + Redis)       | Private cloud                 | The actual workload; DB and cache as sidecar containers                      |
| **Caddy** (native, not containerized) | Reverse proxy + automatic TLS | Terminates HTTPS for`next.<domain>`, automatic Let's Encrypt               |
| **WireGuard**                         | Admin VPN                     | The only path to the admin panels; keeps them off the public net             |
| **Borg**                              | Deduplicating backup          | Server self-backup + the local machine's off-site copy, both on the 4 TB HDD |
| **Runtipi**                           | App store panel               | One-click Docker apps, reachable only via WireGuard                          |
| **Cockpit**                           | Host monitoring/control       | Logs, storage, services; socket-activated, WireGuard-only                    |
| **ufw + nftables**                    | Firewall                      | Default-deny; a`DOCKER-USER` rule closes Docker's well-known ufw bypass    |
| **fail2ban**                          | Intrusion throttling          | Bans SSH and Nextcloud brute-force, IPv6 banned as a`/64` prefix           |
| **auditd, AIDE, Lynis**               | Audit + integrity             | Kernel audit trail, file-integrity baseline, security scanner                |

The whole build is one machine. The 4 TB HDD is mounted at `/srv/hdd` and carries the heavy, non-system data: Nextcloud's file blobs and the Borg repositories. The system, databases and container images live on the fast NVMe.

---

### The stack as implemented

The state this repository reflects — the design pursued and actually installed on the test server — is:

- **Nextcloud** as a Docker Compose stack: `app` + `db` (MariaDB) + `redis` + `cron`, data directory on the 4 TB HDD, admin account created unattended at first start, TOTP two-factor **enforced**.
- **Caddy** native on the host as the public reverse proxy for `next.<domain>` (`127.0.0.1:8080` → HTTPS), with automatic certificates gated behind a DNS check so a misconfigured record can't burn the Let's Encrypt rate limit.
- **Docker** hardened at the daemon level (`no-new-privileges`, `userland-proxy: false`, IPv6 off) and behind a `DOCKER-USER` firewall rule that prevents published container ports from bypassing ufw.
- **WireGuard** as the sole route to **Runtipi** (`10.8.0.1:8090`) and **Cockpit** (`10.8.0.1:9090`); both proven closed from the public internet by external scan.

---

### Nextcloud data model: one-way upload plus one exchange folder

A hard project rule, learned the painful way: **synchronisation from the local machine to Nextcloud must be one-way (local → remote).** Nextcloud must never write back to the local machine — a past bidirectional sync corrupted local data.

- The bulk of the data is pushed one-way with `rclone copy` over WebDAV. No Nextcloud desktop client for the broad data set.
- **Exactly one** dedicated exchange folder is allowed to sync bidirectionally, and only that folder may use the regular Nextcloud desktop client.

---

## Backup: 4 TB HDD plus Borg

The 4 TB HDD is, first and foremost, an **off-site backup vault for the operator's local (Mac Studio) data** — that is its primary purpose (roughly 90–95 % of the backup volume). Backing up the server's own state is the smaller, secondary job. Two Borg repositories live on the HDD under `/srv/hdd/backup`:

- **`repo-local`** (the main one) — the operator's local machine backs up here over SSH with a restricted, **append-only** key, so a compromised local machine cannot delete or encrypt the existing backups. This is the "somewhere far away" second copy of the Mac's data.
- **`repo-server`** (the small one) — the server also backs *itself* up (Nextcloud config, DB dump, `/etc`, `/home`, system state) so the host can be rebuilt after a total loss. Passphrase auto-generated by the script.

Backups are **event-triggered, not clock-based** (the operator works at night): after the local machine finishes its push it drops a trigger file, a systemd path unit fires the server's self-backup, and a weekly timer is the fallback safety net. There is deliberately **no second provider / no StorageBox**: for the Mac's data the server itself *is* the off-site copy (`repo-local`), and locally there are three further backups. The accepted residual risk (simultaneous loss of office and server) is documented and consciously taken.

---

### Control panels: the two we chose

After surveying a field of lightweight panels (full comparison: [SCPs.md](SCPs.md) · [SCPs.de.md](SCPs.de.md)) the choice was two complementary tools rather than one heavy all-in-one:

- **Runtipi** — an app store for one-click Docker apps. Its own proxy is moved off `80/443` to `8090/8445` and bound to the WireGuard address.
- **Cockpit** — host-level monitoring and control (logs, storage, services), socket-activated so it costs almost nothing when idle.

Both are reachable **only** through the WireGuard tunnel; an earlier candidate (Dockge) was dropped. Nextcloud itself is intentionally the only public service.

---

### Hardening concept

Mid-level overview, roughly in the order the script applies it:

- **Admin user + SSH keys** — a non-root sudo user; the operator's ed25519 public key is the only way in.
- **SSH hardening** — key-only, root login off, a single allowed user, a high non-standard port, modern ciphers/KEX/MACs, strict login limits.
- **Firewall (ufw + nftables)** — default-deny inbound; only SSH, `80`, `443` and the WireGuard UDP port open; a `DOCKER-USER` rule (IPv4 **and** IPv6) closes Docker's ufw bypass so published container ports stay private.
- **Auto-updates + mail** — unattended security upgrades (incl. Docker/Caddy/CISOfy origins); system mail via msmtp for alerts.
- **Kernel / sysctl / modules** — anti-spoofing and DoS sysctls, hidden kernel pointers, disabled exotic/unused kernel modules.
- **PAM / login policy** — strong password quality, password history, sane `login.defs` aging, idle-shell timeout, `su` restricted to the sudo group.
- **fail2ban** — SSH and Nextcloud jails; IPv6 offenders banned as a whole `/64`.
- **Logging + audit** — persistent journald, an auditd rule set (~47 rules incl. a CIS Level-2 set), logwatch, weekly package-integrity checks.
- **WireGuard** — server keypair + preshared key; the admin panels live behind it.
- **Docker + Caddy + Nextcloud** — hardened daemon, sandboxed Caddy service, per-service memory/PID limits, DNS gate before TLS issuance, enforced Nextcloud 2FA.
- **Borg backup** — append-only key for the local machine, event trigger, failure alarm.
- **Admin panels** — Cockpit + Runtipi, WireGuard-only.
- **Service cleanup + AIDE** — disable unneeded VM guest services, remove the cloud-init `ubuntu` account, build the AIDE file-integrity baseline.
- **Reachability from the operator** — the public path is Nextcloud over HTTPS; everything administrative is reached through the **WireGuard tunnel** (and, for a single forwarded service port, an **SSH `-L` tunnel** on top).

---

### Installation: phased, tested, verified

Step-by-step operational companion: **[Install-Guide.md](Install-Guide.md)**.

The script runs in numbered phases and can be driven three ways:

- **Phase by phase** (`preflight`, `phase1` … `phase12`) — the recommended path for the *first* real run on a new server, so any assembly issue is caught live.
- **`bootstrap`** — phases 0–2, then stops at the mandatory SSH login test (the one unavoidable break, to prevent lock-out).
- **`rest`** — phases 3–12 plus `verify`, in one pass, once all prerequisites (DNS, HDD, keys, image tag, SMTP) are prepared up front.

Verification is not optional and not self-reported:

- external `nmap -Pn` **and** `nmap -6 -Pn` against `8090/8445/9090` — they must be filtered from the public internet;
- `verify` health check (SSH effective config via `sshd -T`, firewall, fail2ban, auditd, AppArmor, mounts, services);
- `fail2ban-regex` against **real** Nextcloud failed-login lines;
- an actual Borg **restore** (`borg extract`) before trusting the backup;
- **Lynis** (from the CISOfy repo, not the frozen distro package) and the **Ubuntu USG / CIS benchmark** as an independent audit — with a documented list of deliberate, reasoned deviations from CIS (e.g. `ip_forward=1` for Docker).

---

### Server directory structure

Only what this project sets up and configures — not the Ubuntu standard tree:

```
/srv/
├── nextcloud/
│   ├── docker-compose.yml           # NC stack: app + db (MariaDB) + redis + cron
│   ├── docker-compose.override.yml  # per-service mem/PID limits (optional)
│   ├── secrets/                     # db_root, db_pass, nc_admin
│   ├── html/                        # NC code volume
│   └── db/                          # MariaDB data
└── hdd/                             # 4 TB HDD mount (nofail)
    ├── ncdata/                      # Nextcloud data / file blobs (~1 TB)
    └── backup/
        ├── repo-server/             # Borg: server self-backup
        ├── repo-local/              # Borg: local machine → server (append-only)
        └── trigger/                 # event trigger for the server backup

/opt/runtipi/                        # Runtipi app store (WireGuard-only)

/etc/
├── ssh/sshd_config.d/10-hardening.conf
├── ufw/{after.rules, after6.rules, sysctl.conf}
├── fail2ban/{jail.local, jail.d/, filter.d/nextcloud.conf, action.d/ban6-prefix.conf}
├── audit/rules.d/{hardening.rules, cis-l2.rules}
├── wireguard/wg0.conf
├── docker/daemon.json
├── caddy/Caddyfile
├── systemd/system/{caddy.service.d, docker.service.d, borg-backup.{service,path,timer},
│                   backup-fail-mail.service, cockpit.socket.d}
├── sysctl.d/99-hardening.conf
├── modprobe.d/99-hardening-blacklist.conf
├── security/{pwquality.conf, limits.d/99-hardening.conf}
├── aide/aide.conf.d/{99_local_excludes, 99_local_audittools}
└── msmtprc, msmtp-pass

/usr/local/bin/
├── backup-server.sh                 # server backup (triggered / weekly fallback)
├── nc-post-setup.sh                 # enforce Nextcloud TOTP 2FA
└── f2b-ban6.sh                      # fail2ban IPv6 /64 ban action

/root/
├── install-secrets/                 # generated admin/DB/borg secrets
└── .borg-passphrase                 # auto-generated repo-server passphrase
```

---

### How far to harden — and where we deliberately stopped

Hardening is only useful if the machine stays operable. Several conscious *non*-hardening decisions keep it that way:

- **GRUB boot-parameter hardening is off by default.** A stacked, untested set of boot parameters once sent the VM into a boot loop recoverable only from the provider backup (no rescue console, no ISO mount on this provider). The proven-safe subset stays behind an explicit flag, enabled only with a fresh backup in hand.
- **`AllowTcpForwarding` stays on** — the admin workflow uses SSH `-L` tunnels.
- **`net.ipv4.ip_forward = 1`** — Docker requires it; CIS flags it, we keep it knowingly.
- **One partition, not the CIS-preferred separate `/home` `/var` `/tmp`** — a conscious simplicity trade-off on a single small VPS.
- **`LogLevel VERBOSE`** instead of the CIS default — more detail on purpose.

These deviations are documented so a later audit (or a second reviewer) sees them as choices, not oversights.

---

### Status and roadmap

Current status and the concrete next tasks live in **[Handover.md](Handover.md)**. In short: the individual hardening building blocks are verified on a test server, but the **assembled `install.sh` has not yet been run end-to-end**; the first production run must be phase-by-phase, followed by the external scan and restore test above.

---

### Genesis

The idea and the concept are mine and I defined the requirements for the script. The design, scripting and review grew out of close teamwork with **Claude Opus 4.8** and **Claude Fable 5** (in Cowork), including repeated use of **two or three subagents** for independent "council" reviews of the hardening script — several rounds of which are recorded in the script's own change history. The recurring theme of that collaboration was exactly the trade-off above: how far to push hardening before it starts to cost operability, and where to consciously decide against a control in order to keep the server usable.



### Version History

| Version | Changes | Date |
| :--- | :--- | :--- |
| v0.1.0 | Initial release: install.sh, READMEs (EN/DE), install guide, SCPs comparison, security policy, changelog, GPL-3.0 license | 2026.07.21 |
| v0.1.1 | ShellCheck GitHub Action (shellcheck.yml) + badge, additional paragraph concerning Version History inside README.md | 2026.07.21 |

---

### License

**GNU General Public License v3.0 or later (GPL-3.0-or-later).** You may use, redistribute, fork and modify this project, provided derivative work stays under the same license and the original source is credited. See [LICENSE](LICENSE).

Why GPL-3.0 and not a permissive license: the operator's intent is explicit share-alike plus attribution — permissive licenses (MIT/Apache) would not require keeping the license, and AGPL's network clause targets hosted web services, which a hardening script is not.

---

### Acknowledgments

- Design, scripting, documentation and review in teamwork with `Claude Opus 4.8` and `Claude Fable 5` (Cowork), with multi-agent council reviews of the hardening script.
- Built on the shoulders of the upstream projects: Ubuntu, Docker, Nextcloud, Caddy, WireGuard, BorgBackup, Runtipi, Cockpit, fail2ban, auditd, AIDE and Lynis (CISOfy).
- Not affiliated with or endorsed by any of the above projects.  

### Trademarks + Logos
All product names, logos and brands mentioned in this repository are the property of their respective owners. They are used here for identification and descriptive purposes only and do not imply any affiliation with or endorsement by their owners.
