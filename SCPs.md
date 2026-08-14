# Lightweight Server Control Panels (Ubuntu 24.04)

🇩🇪 **German version: [SCPs.de.md](SCPs.de.md)**

> **Note / disclaimer.** This is a personal, subjective assessment based on publicly
> available information (vendor documentation, CVE databases, forum and GitHub reports),
> as of July 2026. It is an opinion, not a binding statement of fact about any individual
> vendor. RAM/disk figures are rough estimates. The security notes refer to **publicly
> reported, partly historical** incidents; they may be outdated or incomplete. Corrections
> are welcome — please open an issue. No warranty, no liability.

A quick overview of common server control panels, sorted from lightweight to heavyweight,
with an eye on resource footprint, focus, and publicly reported security/stability track
record.

| Panel | Class | RAM (idle/UI) | Disk | Focus | Website | Security (publicly reported) | Update stability |
|---|---|---|---|---|---|---|---|
| **Dokku** | 🪶 light | ~10 MB / — | ~50 MB | Minimal PaaS (Git deploys, DB plugins) | [dokku.com](https://dokku.com) | No web UI exposed by default → very small attack surface | Very stable; Ubuntu updates unproblematic |
| **Cosmos Cloud** | 🪶 light | ~45 MB / ~110 MB | ~120 MB | Security, VPN, Docker marketplace | [cosmos-cloud.io](https://cosmos-cloud.io) | Security-focused (zero-trust, VPN, anti-DDoS, auto-HTTPS); no major panel breaches publicly known | Very stable (everything in containers) |
| **CasaOS** | 🪶 light | ~50 MB / ~90 MB | ~100 MB | File management, home-server apps | [zimaspace.com](https://zimaspace.com) | History of publicly reported vulnerabilities (incl. auth bypass, path traversal in the file manager) | Good; panel sits loosely on top of the OS |
| **InfraPilot** | 🪶 light | ~50 MB / ~100 MB | ~120 MB | Container mgmt, Nginx proxy, analytics | [infrapilot.org](https://infrapilot.org) | Lean codebase, small attack surface; no public breaches known | Very stable; does not touch the OS |
| **Runtipi** | 🪶 light | ~60 MB / ~120 MB | ~150 MB | One-click Docker apps | [runtipi.io](https://runtipi.io) | Isolated Docker architecture; no notable incidents known | Outstanding |
| **Portainer CE** | 🪶 light | ~30 MB / ~80 MB | ~100 MB | Docker deploy + monitoring, no app store | [portainer.io](https://portainer.io) | Needs the Docker socket (root-equivalent); no proxy of its own, no public web-facing ports required | Very stable; long-lived project, LTS image tags |
| **aaPanel** | 🪶 light | ~80 MB / ~150 MB | ~300 MB | Web hosting, one-click apps | [aapanel.com](https://aapanel.com) | Repeatedly targeted; public reports of RCE/privilege-escalation chains — treat internet exposure with caution | Mixed; large updates occasionally break Nginx/PHP paths |
| **Easypanel** | 🪶 light | ~80 MB / ~140 MB | ~200 MB | Project mgmt, app marketplace | [easypanel.io](https://easypanel.io) | Docker Swarm isolation; no public breaches reported | Outstanding |
| **UmbrelOS** | 🪶 light | ~90 MB / ~160 MB | ~250 MB | Simple app store (home server) | [umbrel.com](https://umbrel.com) | Meant for the LAN; exposing to the internet without a reverse proxy/VPN is risky | Fair; forums occasionally report DB corruption on core updates |
| **Coolify** | 🪶 light | ~500 MB / ~700 MB | ~500 MB | Developers, Git, complex stacks | [coolify.io](https://coolify.io) | Runs isolated; connects to other servers via SSH keys only | Maintenance-heavy; high update frequency, forums occasionally report proxy/build issues |
| **CloudPanel** | ⚖️ medium | ~400 MB / ~700 MB | ~1.0 GB | PHP/Node hosting (no mail) | [cloudpanel.io](https://cloudpanel.io) | Lean codebase, no mail server → smaller surface; no notable incidents reported | Very stable (native packages) |
| **CyberPanel** | ⚖️ medium | ~500 MB / ~800 MB | ~1.2 GB | OpenLiteSpeed, WordPress | [cyberpanel.net](https://cyberpanel.net) | History of serious publicly reported vulnerabilities (incl. RCE); update process reportedly fragile | Reportedly error-prone (500 errors / Python breakage after updates) |
| **Virtualmin** | 🐘 heavy | ~1000 MB / ~1400 MB | ~1.8 GB | System administration, mail/DNS | [virtualmin.com](https://virtualmin.com) | Very mature, long-audited; risk mostly from misconfiguration | Complex; large OS upgrades can cause trouble without prior adaptation |
| **Plesk** | 🐘 heavy | ~1300 MB / ~2000 MB | ~3.5 GB | Commercial all-in-one | [plesk.com](https://plesk.com) | Commercial enterprise standard (Fail2ban, WAF, dedicated security team) | Very good / professional |
| **cPanel** | 🐘 heavy | ~1500 MB / ~2200 MB | ~4.0 GB | Commercial web hosting | [cpanel.net](https://cpanel.net) | Commercial standard, strict requirements | Very stable, but rigid |

**Chosen for this project (superseded 2026-07-31):** **Portainer CE** (Docker deploy + monitoring)
+ **Cockpit** (host monitoring), both reachable only over WireGuard. Runtipi was the original
pick from this table but was dropped in a later, narrower four-criteria comparison (app store,
real Docker deploy, real monitoring, compatible with the hardened setup) against Dokploy,
Coolify, CasaOS and Cosmos — see `Handover.md` section 7 for that comparison and the reasoning.
The heavier panels (from ~1 GB disk) still do not fit the lean goal.

Portainer's RAM/disk figures above are rough estimates, not independently verified against a
primary source — treat them as approximate, unlike the rest of this table.
