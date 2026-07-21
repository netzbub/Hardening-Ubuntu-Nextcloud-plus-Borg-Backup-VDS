# Hardening-Ubuntu-Nextcloud-plus-Borg-Backup-VDS

<p align="center">
  <img src="https://img.shields.io/github/v/tag/netzbub/Hardening-Ubuntu-Nextcloud-plus-Borg-Backup-VDS?label=version&color=blue" alt="Version">
  <img src="https://img.shields.io/github/license/netzbub/Hardening-Ubuntu-Nextcloud-plus-Borg-Backup-VDS?color=olive&cacheSeconds=3600" alt="license">
  <img src="https://img.shields.io/github/last-commit/netzbub/Hardening-Ubuntu-Nextcloud-plus-Borg-Backup-VDS?color=blueviolet" alt="letzter Commit">
  <img src="https://img.shields.io/github/issues/netzbub/Hardening-Ubuntu-Nextcloud-plus-Borg-Backup-VDS?color=yellow" alt="offene Issues">
  <img src="https://img.shields.io/badge/Ubuntu-24.04-E95420?logo=ubuntu&logoColor=white" alt="Ubuntu 24.04">
  <img src="https://github.com/netzbub/Hardening-Ubuntu-Nextcloud-plus-Borg-Backup-VDS/actions/workflows/shellcheck.yml/badge.svg" alt="ShellCheck">
</p>

*Ein stufenweise installierendes `bash-script` zum Härten und Einrichten eines Ubuntu-24.04-VDS/VPS, auf dem einerseits eine Nextcloud-Instanz hinter Caddy läuft, auf einer 4-TB-Platte als Off-site-Borg-Tresor für die lokalen (Mac-)Daten des Betreibers dient und seine Admin-Oberflächen ausschließlich über einen WireGuard-Tunnel erreichbar macht.*

> **Zusammenfassung:** das Skript – `install.sh` – wandelt eine Standard Ubuntu 24.04 Installation in einen gehärteten Remote Server für eine Nextcloud samt event-getriggertem Borg-Backup — eingehend überprüft mittels Lynis (Index-Score: 83), CIS-Benchmark und externer Postscans, fail2ban-Regex-Tests.

🇬🇧 **English version: [README.md](README.md)**

Dies ist ein Projekt für die eigene Infrastruktur, kein Produkt. Es dokumentiert einen konkreten, bewusst getroffenen Aufbau für **normalerweise einen Nutzer, eine kleine Nextcloud** (gelegentlich 2–3  Mitnutzer), mit starker Ausrichtung auf eine möglichst kleine Angriffsfläche und Wiederherstellbarkeit.

---

<p align="center">
<img src="images/Rudern-zwei-de.jpg" width="50%" alt="...">  
</p>


### Inhaltsverzeichnis

- [Hardening-Ubuntu-Nextcloud-plus-Borg-Backup-VDS](#hardening-ubuntu-nextcloud-plus-borg-backup-vds)
    - [Inhaltsverzeichnis](#inhaltsverzeichnis)
    - [Zielsetzung](#zielsetzung)
    - [Architektur und Komponenten](#architektur-und-komponenten)
    - [Der umgesetzte Stack](#der-umgesetzte-stack)
  - [Nextcloud-Datenmodell: One-Way-Upload plus ein Austauschordner](#nextcloud-datenmodell-one-way-upload-plus-ein-austauschordner)
    - [Backup: 4-TB-HDD plus Borg](#backup-4-tb-hdd-plus-borg)
    - [Control Panels: die zwei ausgewählten](#control-panels-die-zwei-ausgewählten)
    - [Hardening-Konzept](#hardening-konzept)
    - [Installation: phasenweise, getestet, verifiziert](#installation-phasenweise-getestet-verifiziert)
    - [Verzeichnisstruktur des Servers](#verzeichnisstruktur-des-servers)
    - [Wie weit härten — und wo wir bewusst aufgehört haben](#wie-weit-härten--und-wo-wir-bewusst-aufgehört-haben)
    - [Stand und Fahrplan](#stand-und-fahrplan)
    - [Entstehung](#entstehung)
    - [Versionsverlauf](#versionsverlauf)
    - [Lizenz](#lizenz)
    - [Danksagung](#danksagung)
    - [Markennamen und Logos](#markennamen-und-logos)

---

### Zielsetzung

`Ubuntu 24.04` auf einem gemieteten virtuellen Server ist eine ausgezeichnete Basis, aber eine frische Installation ist weit offen: Passwort-SSH, Root-Login, keine nennenswerte Firewall-Politik, keine Angriffsdrosselung, kein Audit-Protokoll, kein Backup. Dieses Projekt schließt diese Lücke auf **reproduzierbare, nachvollziehbare** Weise und setzt eine nützliche Last obendrauf — eine private Nextcloud — ohne die tägliche Bedienbarkeit der Maschine aufzugeben.

Zwei Grundsätze ziehen sich durch alles:

- **Kleine Angriffsfläche.** Nur Nextcloud (`443`) und SSH (ein hoher, nicht-standardmäßiger Port) zeigen ins öffentliche Internet. Jede administrative Oberfläche ist nur über einen WireGuard-Tunnel erreichbar.
- **Prüfen, nicht glauben.** Kein Schritt gilt als erledigt, weil das Skript „OK" ausgegeben hat. Die Firewall-Dichtheit wird mit externem `nmap` bewiesen (IPv4 **und** IPv6), der fail2ban-Filter gegen echte Logzeilen getestet, und das Backup mit einem tatsächlichen Restore belegt — bevor irgendetwas produktiv geht.

---

### Architektur und Komponenten

| Komponente | Rolle | Warum diese |
|---|---|---|
| **Ubuntu 24.04 LTS** | Basis-OS | Langzeitunterstützung; das dem Betreiber vertrauteste System |
| **Docker + Compose** | Container-Laufzeit | Kapselt den Nextcloud-Stack; sauberes Deployen/Einstampfen |
| **Nextcloud** (MariaDB + Redis) | Private Cloud | Die eigentliche Last; DB und Cache als Beistell-Container |
| **Caddy** (nativ, nicht containerisiert) | Reverse-Proxy + automatisches TLS | Terminiert HTTPS für `next.<domain>`, automatisches Let's Encrypt |
| **WireGuard** | Admin-VPN | Der einzige Weg zu den Admin-Panels; hält sie aus dem offenen Netz |
| **Borg** | Deduplizierendes Backup | Server-Selbstsicherung + Off-site-Kopie des lokalen Rechners, beide auf der 4-TB-HDD |
| **Runtipi** | App-Store-Panel | Ein-Klick-Docker-Apps, nur über WireGuard erreichbar |
| **Cockpit** | Host-Überwachung/-Steuerung | Logs, Storage, Dienste; socket-aktiviert, WireGuard-only |
| **ufw + nftables** | Firewall | Default-Deny; eine `DOCKER-USER`-Regel schließt Dockers bekannten ufw-Bypass |
| **fail2ban** | Angriffsdrosselung | Bannt SSH- und Nextcloud-Brute-Force, IPv6 als `/64`-Präfix |
| **auditd, AIDE, Lynis** | Audit + Integrität | Kernel-Audit-Trail, Datei-Integritätsbasis, Sicherheitsscanner |

Der gesamte Aufbau ist eine Maschine. Die 4-TB-HDD ist unter `/srv/hdd` gemountet und trägt die schweren Nicht-System-Daten: Nextclouds Datei-Blobs und die Borg-Repositories. System, Datenbanken und Container-Images liegen auf der schnellen NVMe.

---

### Der umgesetzte Stack

Der Stand, den dieses Repository abbildet — das bis dahin verfolgte und auf dem Testserver tatsächlich installierte Design:

- **Nextcloud** als Docker-Compose-Stack: `app` + `db` (MariaDB) + `redis` + `cron`, Datenverzeichnis auf der 4-TB-HDD, Admin-Konto beim Erststart unbeaufsichtigt angelegt, TOTP-Zwei-Faktor **erzwungen**.
- **Caddy** nativ auf dem Host als öffentlicher Reverse-Proxy für `next.<domain>` (`127.0.0.1:8080` → HTTPS), mit automatischen Zertifikaten hinter einem DNS-Gate, damit ein falscher Eintrag nicht das Let's-Encrypt-Ratelimit verbrennt.
- **Docker** auf Daemon-Ebene gehärtet (`no-new-privileges`, `userland-proxy: false`, IPv6 aus) und hinter einer `DOCKER-USER`-Firewallregel, die verhindert, dass veröffentlichte Container-Ports die ufw umgehen.
- **WireGuard** als einziger Weg zu **Runtipi** (`10.8.0.1:8090`) und **Cockpit** (`10.8.0.1:9090`); beide per externem Scan nachweislich aus dem öffentlichen Internet dicht.

---

## Nextcloud-Datenmodell: One-Way-Upload plus ein Austauschordner

Eine harte Projektregel, schmerzhaft gelernt: **Der Abgleich vom lokalen Rechner zur Nextcloud muss one-way sein (lokal → remote).** Nextcloud darf niemals auf den lokalen Rechner zurückschreiben — ein früherer bidirektionaler Sync hat lokale Daten korrumpiert.

- Die breite Datenmenge wird one-way per `rclone copy` über WebDAV geschoben. Kein Nextcloud-Desktop-Client für den großen Datenbestand.
- **Genau ein** definierter Austauschordner darf bidirektional synchronisieren, und nur dieser Ordner darf den regulären Nextcloud-Desktop-Client nutzen.

---

### Backup: 4-TB-HDD plus Borg

Die 4-TB-HDD ist in erster Linie ein **Off-site-Backup-Tresor für die lokalen (Mac-Studio-)Daten des Betreibers** — das ist ihr Hauptzweck (rund 90–95 % des Backup-Volumens). Die Sicherung des Servers selbst ist der kleinere, zweitrangige Teil. Zwei Borg-Repositories liegen auf der HDD unter `/srv/hdd/backup`:

- **`repo-local`** (das Hauptrepo) — der lokale Rechner sichert hierher, über SSH mit einem eingeschränkten, **append-only**-Schlüssel, damit ein kompromittierter lokaler Rechner die vorhandenen Backups weder löschen noch verschlüsseln kann. Das ist die „weit-weg"-Zweitkopie der Mac-Daten.
- **`repo-server`** (das kleine Repo) — der Server sichert zusätzlich *sich selbst* (Nextcloud-Konfig, DB-Dump, `/etc`, `/home`, Systemzustand), damit der Host nach einem Totalverlust wieder aufgebaut werden kann. Passphrase vom Skript automatisch erzeugt.

Backups laufen **event-getriggert, nicht nach Uhrzeit** (der Betreiber arbeitet nachts): Nach dem Push des lokalen Rechners legt dieser eine Trigger-Datei ab, eine systemd-Path-Unit stößt die Server-Selbstsicherung an, und ein wöchentlicher Timer ist das Auffangnetz. Bewusst **kein Zweitprovider / keine StorageBox**: Für die Mac-Daten *ist* der Server selbst die Off-site-Kopie (`repo-local`), und lokal existieren drei weitere Backups. Das akzeptierte Restrisiko (gleichzeitiger Verlust von Büro und Server) ist dokumentiert und bewusst getragen.

---

### Control Panels: die zwei ausgewählten

Nach der Sichtung eines Felds leichtgewichtiger Panels (vollständiger Vergleich: [SCPs.de.md](SCPs.de.md) · [SCPs.md](SCPs.md)) fiel die Wahl auf zwei sich ergänzende Werkzeuge statt eines schweren All-in-one:

- **Runtipi** — ein App-Store für Ein-Klick-Docker-Apps. Sein eigener Proxy wird von `80/443` auf `8090/8445` verlegt und an die WireGuard-Adresse gebunden.
- **Cockpit** — Überwachung und Steuerung auf Host-Ebene (Logs, Storage, Dienste), socket-aktiviert, kostet im Leerlauf also fast nichts.

Beide sind **ausschließlich** über den WireGuard-Tunnel erreichbar; ein früherer Kandidat (Dockge) wurde verworfen. Nextcloud selbst ist bewusst der einzige öffentliche Dienst.

---

### Hardening-Konzept

Überblick auf mittlerer Flughöhe, grob in der Reihenfolge, in der das Skript vorgeht:

- **Admin-Nutzer + SSH-Keys** — ein Nicht-Root-sudo-Nutzer; der ed25519-Public-Key des Betreibers ist der einzige Zugang.
- **SSH-Härtung** — nur Key, Root-Login aus, ein einziger erlaubter Nutzer, ein hoher nicht-standardmäßiger Port, moderne Ciphers/KEX/MACs, strikte Login-Limits.
- **Firewall (ufw + nftables)** — eingehend Default-Deny; offen nur SSH, `80`, `443` und der WireGuard-UDP-Port; eine `DOCKER-USER`-Regel (IPv4 **und** IPv6) schließt Dockers ufw-Bypass, damit veröffentlichte Container-Ports privat bleiben.
- **Auto-Updates + Mail** — unbeaufsichtigte Sicherheitsupdates (inkl. Docker/Caddy/CISOfy-Origins); Systemmail über msmtp für Alarme.
- **Kernel / sysctl / Module** — Anti-Spoofing- und DoS-sysctls, versteckte Kernel-Zeiger, gesperrte exotische/unnötige Kernel-Module.
- **PAM / Login-Politik** — starke Passwortqualität, Passwort-Historie, sinnvolles `login.defs`-Aging, Idle-Shell-Timeout, `su` auf die sudo-Gruppe beschränkt.
- **fail2ban** — SSH- und Nextcloud-Jails; IPv6-Angreifer als ganzes `/64` gebannt.
- **Logging + Audit** — persistentes journald, ein auditd-Regelsatz (~47 Regeln inkl. eines CIS-Level-2-Satzes), logwatch, wöchentliche Paketintegritätsprüfung.
- **WireGuard** — Server-Schlüsselpaar + PresharedKey; die Admin-Panels leben dahinter.
- **Docker + Caddy + Nextcloud** — gehärteter Daemon, sandboxed Caddy-Dienst, mem/PID- Limits pro Dienst, DNS-Gate vor TLS-Ausstellung, erzwungene Nextcloud-2FA.
- **Borg-Backup** — append-only-Key für den lokalen Rechner, Event-Trigger, Fehleralarm.
- **Admin-Panels** — Cockpit + Runtipi, WireGuard-only.
- **Dienste-Bereinigung + AIDE** — unnötige VM-Gast-Dienste deaktivieren, das cloud-init-`ubuntu`-Konto entfernen, die AIDE-Integritätsbasis erstellen.
- **Erreichbarkeit für den Betreiber** — der öffentliche Weg ist Nextcloud über HTTPS; alles Administrative erreicht man über den **WireGuard-Tunnel** (und, für einen einzelnen weitergeleiteten Dienst-Port, einen **SSH-`-L`-Tunnel** obendrauf).

---

### Installation: phasenweise, getestet, verifiziert

Schritt-für-Schritt-Begleitung: **[Install-Guide.md](Install-Guide.md)** (Englisch).

Das Skript läuft in nummerierten Phasen und lässt sich auf drei Arten fahren:

- **Phase für Phase** (`preflight`, `phase1` … `phase12`) — der empfohlene Weg für den *ersten* realen Lauf auf einem neuen Server, damit jedes Zusammenbau-Problem live auffällt.
- **`bootstrap`** — Phasen 0–2, dann Stopp am verpflichtenden SSH-Login-Test (die eine unvermeidbare Unterbrechung, gegen Aussperrung).
- **`rest`** — Phasen 3–12 plus `verify`, in einem Rutsch, sobald alle Voraussetzungen (DNS, HDD, Keys, Image-Tag, SMTP) vorab bereitstehen.

Die Verifizierung ist nicht optional und nicht selbstberichtet:

- externes `nmap -Pn` **und** `nmap -6 -Pn` gegen `8090/8445/9090` — sie müssen aus dem öffentlichen Internet gefiltert sein;
- `verify`-Health-Check (effektive SSH-Konfig via `sshd -T`, Firewall, fail2ban, auditd, AppArmor, Mounts, Dienste);
- `fail2ban-regex` gegen **echte** Nextcloud-Fehllogin-Zeilen;
- ein tatsächlicher Borg-**Restore** (`borg extract`), bevor dem Backup vertraut wird;
- **Lynis** (aus dem CISOfy-Repo, nicht dem eingefrorenen Distro-Paket) und der **Ubuntu USG / CIS-Benchmark** als unabhängiges Audit — mit einer dokumentierten Liste bewusster, begründeter Abweichungen vom CIS (z. B. `ip_forward=1` für Docker).

---

### Verzeichnisstruktur des Servers

Nur das, was dieses Projekt aufsetzt und konfiguriert — nicht der Ubuntu-Standardbaum:

```
/srv/
├── nextcloud/
│   ├── docker-compose.yml           # NC-Stack: app + db (MariaDB) + redis + cron
│   ├── docker-compose.override.yml  # mem/PID-Limits pro Dienst (optional)
│   ├── secrets/                     # db_root, db_pass, nc_admin
│   ├── html/                        # NC-Code-Volume
│   └── db/                          # MariaDB-Daten
└── hdd/                             # 4-TB-HDD-Mount (nofail)
    ├── ncdata/                      # Nextcloud-Daten / Datei-Blobs (~1 TB)
    └── backup/
        ├── repo-server/             # Borg: Server-Selbstsicherung
        ├── repo-local/              # Borg: lokaler Rechner → Server (append-only)
        └── trigger/                 # Event-Trigger fürs Server-Backup

/opt/runtipi/                        # Runtipi App-Store (WireGuard-only)

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
├── backup-server.sh                 # Server-Backup (getriggert / wöchentlicher Fallback)
├── nc-post-setup.sh                 # Nextcloud-TOTP-2FA erzwingen
└── f2b-ban6.sh                      # fail2ban IPv6-/64-Ban-Aktion

/root/
├── install-secrets/                 # generierte Admin-/DB-/Borg-Secrets
└── .borg-passphrase                 # auto-generierte repo-server-Passphrase
```

---

### Wie weit härten — und wo wir bewusst aufgehört haben

Härtung nützt nur, wenn die Maschine bedienbar bleibt. Mehrere bewusste *Nicht*-Härtungen sorgen dafür:

- **GRUB-Boot-Parameter-Härtung ist standardmäßig aus.** Ein gestapelter, ungetesteter Satz Boot-Parameter schickte die VM einmal in eine Boot-Schleife, die nur aus dem Provider-Backup zu retten war (kein Rescue, kein ISO-Mount bei diesem Provider). Der bewiesen-sichere Teilsatz bleibt hinter einem ausdrücklichen Flag, aktivierbar nur mit frischem Backup in der Hand.
- **`AllowTcpForwarding` bleibt an** — der Admin-Workflow nutzt SSH-`-L`-Tunnel.
- **`net.ipv4.ip_forward = 1`** — Docker braucht es; CIS mahnt es an, wir behalten es wissentlich.
- **Eine Partition statt der von CIS bevorzugten getrennten `/home` `/var` `/tmp`** — ein bewusster Einfachheits-Kompromiss auf einem einzelnen kleinen VPS.
- **`LogLevel VERBOSE`** statt des CIS-Defaults — mehr Detail mit Absicht.

Diese Abweichungen sind dokumentiert, damit ein späteres Audit (oder ein zweiter Prüfer) sie als Entscheidungen sieht, nicht als Versäumnisse.

---

### Stand und Fahrplan

Aktueller Stand und die konkreten nächsten Aufgaben stehen im **[Handover.md](Handover.md)**. Kurz: Die einzelnen Härtungs-Bausteine sind auf einem Testserver verifiziert, aber das **zusammengesetzte `install.sh` ist noch nicht am Stück gelaufen**; der erste Produktivlauf muss phasenweise erfolgen, gefolgt vom externen Scan und dem Restore-Test.

---

### Entstehung

Die Idee, das Konzept und die Anforderungen habe ich entwickelt. Design,Skripting und Review sind aus enger Zusammenarbeit mit `Claude Opus 4.8` und `Claude Fable 5 – Cowork` entstanden, inklusive wiederholtem Einsatz von `zwei bis drei Subagenten` für unabhängige „Council"-Reviews des Härtungsskripts — mehrere Runden davon sind in der Änderungshistorie des Skripts selbst festgehalten. Das wiederkehrende Thema dieser Zusammenarbeit war genau der Abwägungspunkt oben: wie weit man härtet, bevor es die Bedienbarkeit kostet, und wo man sich bewusst gegen eine Maßnahme entscheidet, um mit dem Server noch arbeiten zu können.

---

### Versionsverlauf

| Version | Changes | Date |
| :--- | :--- | :--- |
| v0.1.0 | Erstveröffentlichung: install.sh, READMEs (EN/DE), Installationsanleitung, SCP-Vergleich, Sicherheitsrichtlinie, Changelog, GPL-3.0-Lizenz  | 2026.07.21 |
| v0.1.1 |  ShellCheck-GitHub-Action (shellcheck.yml) + Badge, zusätzlicher Absatz zum Versionsverlauf in der README.md | 2026.07.21 |

---

### Lizenz

**GNU General Public License v3.0 oder später (GPL-3.0-or-later).** Du darfst dieses Projekt nutzen, weitergeben, forken und modifizieren, sofern abgeleitete Werke unter derselben Lizenz bleiben und die ursprüngliche Quelle genannt wird. Siehe [LICENSE](LICENSE).

Warum GPL-3.0 und keine permissive Lizenz: Der ausdrückliche Wunsch ist Share-alike plus Namensnennung — permissive Lizenzen (MIT/Apache) würden das Beibehalten der Lizenz nicht verlangen, und AGPLs Netzwerk-Klausel zielt auf gehostete Web-Dienste, was ein Härtungsskript nicht ist.

---

### Danksagung

- Design, Skripting, Dokumentation und Review in Teamarbeit mit **Claude Opus 4.8** und **Claude Fable 5** (Cowork), mit Multi-Agenten-Council-Reviews des Härtungsskripts.
- Aufgebaut auf den Schultern der Upstream-Projekte: Ubuntu, Docker, Nextcloud, Caddy, WireGuard, BorgBackup, Runtipi, Cockpit, fail2ban, auditd, AIDE und Lynis (CISOfy).
- In keiner Weise mit den genannten Projekten affiliiert oder von ihnen unterstützt.


### Markennamen und Logos

Alle in diesem Repository genannten Produktnamen, Logos und Marken sind Eigentum ihrer jeweiligen Inhaber. Sie werden ausschließlich zu Identifikations- und Beschreibungszwecken verwendet und implizieren weder eine Verbindung zu noch eine Billigung durch die jeweiligen Inhaber.
