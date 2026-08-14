# Leichtgewichtige Server Control Panels (Ubuntu 24.04)

🇬🇧 **English version: [SCPs.md](SCPs.md)**

> **Hinweis / Haftungsausschluss.** Dies ist eine persönliche, subjektive Einschätzung auf
> Basis öffentlich verfügbarer Informationen (Hersteller-Dokumentation, CVE-Datenbanken,
> Foren- und GitHub-Berichte), Stand Juli 2026. Es handelt sich um eine Meinungsäußerung,
> nicht um verbindliche Tatsachenbehauptungen über einzelne Anbieter. RAM-/Speicherangaben
> sind grobe Schätzwerte. Die Sicherheitsnotizen verweisen auf **öffentlich berichtete,
> teils historische** Vorfälle; sie können veraltet oder unvollständig sein. Korrekturen
> sind willkommen — bitte per Issue. Keine Gewähr, keine Haftung.

Kurzüberblick über verbreitete Server-Control-Panels, sortiert von Leicht- zu
Schwergewicht, mit Blick auf Ressourcenbedarf, Ausrichtung und öffentlich berichtete
Sicherheits-/Stabilitätshistorie.

| Panel | Klasse | RAM (Leerlauf/UI) | Disk | Fokus | Website | Sicherheit (öffentlich berichtet) | Update-Stabilität |
|---|---|---|---|---|---|---|---|
| **Dokku** | 🪶 leicht | ~10 MB / — | ~50 MB | Minimal-PaaS (Git-Deploys, DB-Plugins) | [dokku.com](https://dokku.com) | Standardmäßig kein Web-UI im Netz → sehr kleine Angriffsfläche | Sehr stabil; Ubuntu-Updates unkritisch |
| **Cosmos Cloud** | 🪶 leicht | ~45 MB / ~110 MB | ~120 MB | Sicherheit, VPN, Docker-Marktplatz | [cosmos-cloud.io](https://cosmos-cloud.io) | Sicherheitsfokus (Zero-Trust, VPN, Anti-DDoS, Auto-HTTPS); keine großen Panel-Breaches öffentlich bekannt | Sehr stabil (alles in Containern) |
| **CasaOS** | 🪶 leicht | ~50 MB / ~90 MB | ~100 MB | Dateimanagement, Homeserver-Apps | [zimaspace.com](https://zimaspace.com) | In der Vergangenheit öffentlich berichtete Schwachstellen (u. a. Auth-Bypass, Path-Traversal im Dateimanager) | Gut; Panel liegt lose über dem OS |
| **InfraPilot** | 🪶 leicht | ~50 MB / ~100 MB | ~120 MB | Container-Mgmt, Nginx-Proxy, Analytics | [infrapilot.org](https://infrapilot.org) | Schlanke Codebasis, kleine Angriffsfläche; keine öffentlichen Breaches bekannt | Sehr stabil; berührt das OS nicht |
| **Runtipi** | 🪶 leicht | ~60 MB / ~120 MB | ~150 MB | One-Click-Docker-Apps | [runtipi.io](https://runtipi.io) | Isolierte Docker-Architektur; keine nennenswerten Vorfälle bekannt | Herausragend |
| **Portainer CE** | 🪶 leicht | ~30 MB / ~80 MB | ~100 MB | Docker-Deploy + Monitoring, kein App-Store | [portainer.io](https://portainer.io) | Braucht den Docker-Socket (root-äquivalent); kein eigener Proxy, keine öffentlich erreichbaren Ports nötig | Sehr stabil; langjähriges Projekt, LTS-Image-Tags |
| **aaPanel** | 🪶 leicht | ~80 MB / ~150 MB | ~300 MB | Webhosting, 1-Klick-Apps | [aapanel.com](https://aapanel.com) | In der Vergangenheit mehrfach Ziel öffentlich berichteter Schwachstellen (u. a. RCE-/Rechteausweitungs-Ketten) — Internet-Exposition mit Vorsicht | Durchwachsen; große Updates brechen gelegentlich Nginx-/PHP-Pfade |
| **Easypanel** | 🪶 leicht | ~80 MB / ~140 MB | ~200 MB | Projekt-Mgmt, App-Marktplatz | [easypanel.io](https://easypanel.io) | Docker-Swarm-Isolierung; keine öffentlichen Breaches berichtet | Herausragend |
| **UmbrelOS** | 🪶 leicht | ~90 MB / ~160 MB | ~250 MB | Einfacher App-Store (Homeserver) | [umbrel.com](https://umbrel.com) | Für LAN gedacht; Internet-Exposition ohne Reverse-Proxy/VPN riskant | Befriedigend; Foren berichten vereinzelt DB-Korruption bei Core-Updates |
| **Coolify** | 🪶 leicht | ~500 MB / ~700 MB | ~500 MB | Entwickler, Git, komplexe Stacks | [coolify.io](https://coolify.io) | Läuft isoliert; Verbindungen zu anderen Servern nur über SSH-Keys | Wartungsintensiv; hohe Update-Frequenz, Foren berichten gelegentlich Proxy-/Build-Probleme |
| **CloudPanel** | ⚖️ mittel | ~400 MB / ~700 MB | ~1,0 GB | PHP-/Node-Hosting (kein Mail) | [cloudpanel.io](https://cloudpanel.io) | Schlanke Codebasis, kein Mailserver → kleinere Fläche; keine nennenswerten Vorfälle berichtet | Sehr stabil (native Pakete) |
| **CyberPanel** | ⚖️ mittel | ~500 MB / ~800 MB | ~1,2 GB | OpenLiteSpeed, WordPress | [cyberpanel.net](https://cyberpanel.net) | In der Vergangenheit schwerwiegende öffentlich berichtete Schwachstellen (u. a. RCE); Update-Prozess laut Berichten fragil | Laut Foren fehleranfällig (500-Fehler/Python-Brüche nach Updates) |
| **Virtualmin** | 🐘 schwer | ~1000 MB / ~1400 MB | ~1,8 GB | Systemadministration, Mail/DNS | [virtualmin.com](https://virtualmin.com) | Sehr reif, langjährig geprüft; Risiko meist durch Fehlkonfiguration | Komplex; große OS-Upgrades können ohne Anpassung Probleme machen |
| **Plesk** | 🐘 schwer | ~1300 MB / ~2000 MB | ~3,5 GB | Kommerzielles All-in-One | [plesk.com](https://plesk.com) | Kommerzieller Enterprise-Standard (Fail2ban, WAF, eigenes Security-Team) | Sehr gut / professionell |
| **cPanel** | 🐘 schwer | ~1500 MB / ~2200 MB | ~4,0 GB | Kommerzielles Webhosting | [cpanel.net](https://cpanel.net) | Kommerzieller Standard, strenge Vorgaben | Sehr stabil, aber starr |

**Für dieses Projekt gewählt (abgelöst am 2026-07-31):** **Portainer CE** (Docker-Deploy +
Monitoring) + **Cockpit** (Host-Monitoring), beide ausschließlich über WireGuard erreichbar.
Runtipi war die ursprüngliche Wahl aus dieser Tabelle, wurde aber in einem späteren, engeren
Vier-Kriterien-Vergleich (App-Store, echtes Docker-Deploy, echtes Monitoring, Verträglichkeit
mit dem gehärteten Setup) gegen Dokploy, Coolify, CasaOS und Cosmos verworfen — siehe
`Handover.md` Abschnitt 7 für diesen Vergleich und die Begründung. Die schwereren Panels
(ab ~1 GB Disk) passen weiterhin nicht zur schlanken Zielsetzung.

Die RAM-/Disk-Angaben zu Portainer oben sind grobe Schätzungen, nicht gegen eine Primärquelle
verifiziert — im Unterschied zum Rest dieser Tabelle als ungefähr zu behandeln.
