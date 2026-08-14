# Security Policy

## Scope

This is a personal-infrastructure project: a hardening and setup script plus
documentation for a single Ubuntu 24.04 server. It is provided as-is, without warranty
(see [LICENSE](LICENSE)). It is not a commercial product and there is no service-level
commitment. Still, because the whole point of the project is security, credible reports
are very welcome.

## Reporting a vulnerability

Please report suspected vulnerabilities **privately**, not in a public issue:

- Preferred: GitHub's private vulnerability reporting — repository **Security** tab →
  **Report a vulnerability** (GitHub Security Advisories).

Please include, as far as you can:

- the affected file and line(s) or phase (e.g. `install.sh` phase 6),
- what the issue allows an attacker to do,
- steps to reproduce or a proof of concept,
- any suggested fix.

You will get an acknowledgement as soon as possible. This is a spare-time project, so
please allow for a reasonable response window. Fixes are made on a best-effort basis; once
a fix is available, coordinated disclosure is appreciated.

## Out of scope

- Issues in the upstream projects themselves (Ubuntu, Docker, Nextcloud, Caddy, WireGuard,
  Borg, Portainer, Cockpit, fail2ban, …) — please report those to the respective projects.
- The documented, deliberate trade-offs (see the "How far to harden" section of the
  README), which are conscious decisions rather than oversights.
- Anything that requires an attacker to already have root on the host.

## Good practice for users

- Keep the personal `install.conf` out of version control (it is git-ignored by default).
- Never commit real secrets; clear `SMTP_PASS` again after the one-time Phase 4 run.
- Run the mandatory external validation (external `nmap` over IPv4 **and** IPv6, the
  `verify` health check, a real fail2ban-regex test, and a Borg restore test) before
  trusting a production server.
