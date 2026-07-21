# Handover — Hardening-Ubuntu-Nextcloud-plus-Borg-Backup-VDS

**Project (GitHub):** `Hardening-Ubuntu-Nextcloud-plus-Borg-Backup-VDS`
**URL:** <https://github.com/netzbub/Hardening-Ubuntu-Nextcloud-plus-Borg-Backup-VDS>
**Version:** 0.1.0
**Updated:** 2026-07-20

This is the living handover document. It replaces the earlier dated `*-Übergabe.md`
(preserved as `.history/Handover-legacy-2026-07-19.md`). From here on the project is
maintained in **VS Code with Git**, uploaded to GitHub; filenames are **no longer**
date-prefixed (`yyyy-mm-dd_hh.mm`) — Git handles versioning. Documents are kept in
**English** going forward (README additionally in German).

---

## Table of contents

- [Status of work](#status-of-work)
- [Repository layout](#repository-layout)
- [What changed in this reorganisation](#what-changed-in-this-reorganisation)
- [Next tasks](#next-tasks)
  - [1. SCP research (based on SCPs.md + the new goals)](#1-scp-research-based-on-light-scpsmd--the-new-goals)
  - [2. Translation to English](#2-translation-to-english)
  - [3. Remaining tasks from Rev. 5](#3-remaining-tasks-from-rev-5)
  - [4. README (EN + DE)](#4-readme-en--de)
  - [5. InfraPilot / Docker-deploy investigation](#5-infrapilot--docker-deploy-investigation)
  - [6. Anything else?](#6-anything-else)
- [Pre-push checklist (public repo)](#pre-push-checklist-public-repo)

---

## Status of work

- The **individual hardening building blocks are verified on the test server**
  `server.example.com` (example-host.com): external `nmap` (IPv4 **and** IPv6) proved
  `8090/8445/9090` filtered, `verify` reported 32/32, the fail2ban Nextcloud filter matched
  real failed-login lines (2 hits), and a Borg restore (`borg extract`) round-trip
  succeeded. A reboot came back clean.
- The **assembled script `install.sh` (Rev. 5) has NOT been run end-to-end.** The
  Rev.-5 changes were folded in and pass `bash -n`, but the first real production run must
  still be done **phase by phase**, followed by the external scan and restore test.
- **Redis `cap_add` set is still theory-based** — it must be confirmed by a live Phase 9;
  if Redis fails to start, `DAC_OVERRIDE` is the first thing to add.
- **SMTP auth was failing** on the test run (535). `SMTP_*` values need correcting (user =
  full address? app password? port 587/465? FROM = the authenticated mailbox), then re-run
  Phase 4 and clear `SMTP_PASS` again.
- Panel evaluation is ongoing (Cosmos, InfraPilot tried on the throwaway test server); see
  task 5.

The detailed prior history (Rev.-4/Rev.-5 notes, the phased install guide, the restore
resume, the earlier handover) lives in `.history/` and `CHANGELOG.md`.

---

## Repository layout

```
.
├── README.md              # English README (badges, TOC, architecture, hardening, tree, license)
├── README.de.md           # German README (same content)
├── Handover.md            # this document
├── SCPs.md          # lightweight server control panel comparison (research basis)
├── CHANGELOG.md        # Rev. 4 -> Rev. 5 changelog
├── install.sh       # the hardening + setup script
├── LICENSE                # GPL-3.0-or-later notice (see pre-push checklist)
├── CLAUDE.md              # private project instructions (git-ignored)
├── .gitignore
├── .archive/              # git-ignored: superseded tariff/storage comparisons etc.
└── .history/              # git-ignored: VS Code local history + legacy project docs
                           #   incl. Handover-legacy-2026-07-19.md, the phased install
                           #   guide (2026-07-19-06.40_Anleitung.md), RESUME-Re-Run.md,
                           #   README-TEXTUM-Template.md (reference from another project)
```

---

## What changed in this reorganisation

- Renamed to English, git-friendly names (done by the operator): `Handover.md`,
  `SCPs.md`, `RESUME-Re-Run.md`, `CHANGELOG.md`, `install.sh`.
- Moved to `.history/`: the legacy handover, `RESUME-Re-Run.md`, and the reference
  template `README-TEXTUM-Template.md` (belongs to another project).
- Created: `README.md`, `README.de.md`, `LICENSE`.
- `.gitignore`: fixed a typo (`.archhive/` → `.archive/`) so the archive is actually
  excluded; `CLAUDE.md`, `.history/`, `.archive/`, `.DS_Store` and `*.map` are ignored.
- **License decision (mine, per the stated intent "reuse/fork/modify, keep the license,
  credit the source"): GPL-3.0-or-later.** It is the license that matches share-alike +
  attribution; MIT/Apache would not force keeping the license, and AGPL's network clause
  targets hosted web services, which a hardening script is not. The `LICENSE` file carries
  the standard notice; drop in the full verbatim GPL text via GitHub's license picker so
  the license badge is detected.

---

## Next tasks

### 1. SCP research (based on SCPs.md + the new goals)

The operator has reconsidered the "as slim as possible" maxim. The new target is a control
panel that ideally combines **(a)** an app store like Runtipi, **(b)** real Docker
deploy/teardown/isolation, **(c)** genuine server monitoring/control, and **(d)** fits the
hardened setup. Honest finding so far: no single tool does all four well.

- Extend/complete the `SCPs.md` table against these four criteria, verified from
  primary sources (per the operator's research rule: two-step — identify candidates, then
  check each against the hard criteria; no speculation from names).
- Candidates already on the radar: **Cosmos** (closest all-in-one, but invasive:
  host-net/privileged), **Dokploy** (clean Docker deploy + built-in monitoring, ~350 MB),
  **Coolify** (richer, heavier), **CasaOS** (app store + Docker, thin monitoring),
  **Cloudron** (all-in-one, paid/proprietary, takes over the host). Realistic conclusion to
  weigh: either **Cosmos** as a dense all-in-one on a less strictly hardened box, or the
  clean split **Runtipi + Cockpit + (Dokploy | Portainer)** behind WireGuard.
- Factor in the possible move to the larger **example-host.com VDS** (dedicated Ryzen cores,
  more RAM) — the extra headroom widens the panel options and makes a heavier all-in-one or
  a combination comfortable.
- Deliver the recommendation in chat first, then write the completed table into
  `SCPs.md`.

### 2. Translation to English

- **`install.sh`: translate ALL comments to English** (currently German). Large,
  careful pass — keep the code/logic byte-for-byte, only comments; re-run `bash -n`
  afterwards.
- Any remaining German-only working docs that stay in the repo → English (README is done
  in both).

### 3. Remaining tasks from Rev. 5

- **First end-to-end run** of `install.sh` on a fresh server, **phase by phase**;
  fill the config vars first: `SSH_PUBKEY`, `NC_IMAGE_TAG`, `WG_CLIENT_PUBKEY`, `SMTP_*`,
  optionally `HOSTNAME_FQDN`.
- **Confirm the Redis `cap_add` set** in a live Phase 9 (fallback: add `DAC_OVERRIDE`).
- **Fix SMTP** (see status), re-run Phase 4, verify mail, clear `SMTP_PASS`.
- **Mandatory validation after the run:** external `nmap -Pn` and `nmap -6 -Pn` against
  `8090/8445/9090` (must be filtered) → `verify` → `fail2ban-regex` against real NC log
  lines → Borg restore test.
- **Manual, not scriptable:** Ubuntu Pro attach + `pro enable usg`; the USG/CIS audit and
  its evaluation (do not blindly `usg fix`); GRUB password (only with a working rescue
  console); the real 4 TB HDD instead of the loop image; the Mac-side WireGuard client;
  Borg passphrases / key exports; reboot timing.
- **External monitoring (still open):** decide between Uptime Kuma (e.g. on the Synology)
  and healthchecks.io as a dead-man's switch.
- **Mac side:** `borg init` on `repo-local`, two purpose-built SSH keys (append-only borg +
  trigger), one-way `rclone copy` push + exactly one bidirectional exchange folder.

### 4. README (EN + DE)

Done in this pass (`README.md`, `README.de.md`) with badges and a TOC, oriented on the
`README-TEXTUM-Template.md` style. Review the content for accuracy, adjust badges/wording,
and re-check once the repo name/URL are live so the shield URLs resolve.

### 5. InfraPilot / Docker-deploy investigation

Open side-investigation from the panel evaluation: InfraPilot's "Deploy Image" fails
reproducibly with a generic "failed to create deployment", even with no volume and a valid
CE license. Findings so far: it is **not** a license gate (CE includes container/stack
management), **not** the clock (verified correct), and `docker logs` stays silent because
the app logs to files inside the container, not stdout. **Next concrete step:** capture the
real error via the browser **DevTools → Network** tab (status code + response body of the
failing Deploy request), or via the in-container nginx/backend logs under `/data`. Note this
is a panel-evaluation aside, not core to the server itself.

### 6. Anything else?

- Consider renaming `CHANGELOG.md` → `CHANGELOG.md` and keeping it as the running
  changelog.
- Revive and translate the phased **install guide** from `.history/` (the
  `…_Anleitung.md`) as `Install-Guide.md` (English), since it is the operational
  step-by-step companion to the script.
- Optionally add `SECURITY.md` (how to report issues) and a short `CONTRIBUTING.md`.
- Add the full verbatim GPL-3.0 text to `LICENSE` (GitHub picker) so the badge resolves.

---

## Pre-push checklist (public repo)

Before the first public push, review for anything that should not be public:

- **No secrets in `install.sh`:** `SSH_PUBKEY`, `SMTP_PASS`, `WG_CLIENT_PUBKEY` and
  any generated passwords must be empty/placeholder. `CLAUDE.md` is git-ignored (contains
  private instructions) — keep it that way.
- **Decide on real identifiers:** the script defaults reference the real domain/mail
  (`next.example.com`, `server@example.com`) and the README uses `next.<domain>`. Decide
  whether to genericise the script defaults too before publishing.
- Confirm `.archive/` and `.history/` are excluded (they hold tariff comparisons, private
  legacy notes and the local VS Code history).
- Add the full GPL-3.0 text to `LICENSE`.
