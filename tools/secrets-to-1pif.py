#!/usr/bin/env python3
# =============================================================================
# secrets-to-1pif.py - turn /root/install-secrets/ into a 1Password .1pif import
#
# Runs AS ROOT ON THE SERVER. Writes ONE file next to the secrets:
#
#   /root/install-secrets/install-secrets.1pif
#
# The format and the item naming follow Hubertus' own 1Password export
# (b7e545a9-data.1pif, 2026-10-03): one JSON object per line, each followed by
# the separator line ***5642bee8-a5ff-11dc-8314-0800200c9a66***, every item of
# typeName "webforms.WebForm", titles "hih - <what> > Server" for anything that
# comes out of $SECRETS_DIR.
#
# Why .1pif and not CSV: it carries the title, the URLs and the note exactly as
# written, and it is the format the existing vault items already use - so the
# imported items sit next to their predecessors instead of looking foreign.
#
# The point of this script: the passwords never pass through a chat window, a
# clipboard or a terminal transcript. It reads the files, writes one import
# file, and that file is moved once over scp.
#
# WARNUNG: install-secrets.1pif enthaelt alle Passwoerter im Klartext.
# Nach dem Import ZWINGEND vernichten, auf dem Server und auf dem Mac:
#   shred -u /root/install-secrets/install-secrets.1pif
#
# Usage:  sudo ./secrets-to-1pif.py [--prefix hih]
# =============================================================================
import argparse
import hashlib
import json
import os
import socket
import sys
import time

SEP = "***5642bee8-a5ff-11dc-8314-0800200c9a66***"
SECRETS_DIR = os.environ.get("SECRETS_DIR", "/root/install-secrets")


def read_secret(name):
    """Return a secret's content, or None when the file is absent or empty."""
    path = os.path.join(SECRETS_DIR, name)
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            value = fh.read().strip()
    except OSError:
        return None
    return value or None


def read_conf():
    """Pull the few config values that belong in titles and URLs."""
    conf = {}
    for candidate in (os.path.join(SECRETS_DIR, os.pardir, "install.conf"),
                      "/root/install.conf"):
        if not os.path.isfile(candidate):
            continue
        with open(candidate, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, raw = line.partition("=")
                conf[key.strip()] = raw.split("#")[0].strip().strip("'\"")
        break
    return conf


def item(title, password=None, username=None, urls=None, notes=None,
         location=None, location_key=None):
    """Build one .1pif item in the shape of the existing vault items."""
    now = int(time.time())
    secure = {}
    fields = []
    if username is not None:
        fields.append({"value": username, "name": "username",
                       "type": "T", "designation": "username"})
    # The password field is present even when empty - that is how the existing
    # key-export items look, where the payload sits in the note.
    fields.append({"value": password or "", "name": "password",
                   "type": "P", "designation": "password"})
    secure["fields"] = fields
    if notes:
        secure["notesPlain"] = notes
    if urls:
        secure["URLs"] = [{"label": "Webseite %d" % (i + 1), "url": u}
                          for i, u in enumerate(urls)]
    body = {
        "uuid": hashlib.sha1((title + str(now)).encode()).hexdigest()[:32].upper(),
        "updatedAt": now,
        "createdAt": now,
        "txTimestamp": now,
        "securityLevel": "SL5",
        "contentsHash": hashlib.sha1(json.dumps(secure, sort_keys=True).encode()).hexdigest()[:8],
        "title": title,
        "typeName": "webforms.WebForm",
        "secureContents": secure,
    }
    if location:
        body["location"] = location
    if location_key:
        body["locationKey"] = location_key
    return body


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--prefix", default=os.environ.get("ITEM_PREFIX", "hih"),
                        help="title prefix, as in 'hih - ...' (default: hih)")
    parser.add_argument("--out", default=os.path.join(SECRETS_DIR, "install-secrets.1pif"))
    args = parser.parse_args()

    if os.geteuid() != 0:
        sys.exit("Run as root - the secrets are mode 600.")
    if not os.path.isdir(SECRETS_DIR):
        sys.exit("%s not found." % SECRETS_DIR)

    conf = read_conf()
    host = socket.getfqdn()
    nc_domain = conf.get("NC_DOMAIN", "next.example.org")
    admin_user = conf.get("ADMIN_USER", "hubi")
    ssh_port = conf.get("SSH_PORT", "22")
    wg_net = conf.get("WG_NET", "10.8.0")
    pfx = args.prefix
    today = time.strftime("%Y-%m-%d")
    domain_key = ".".join(host.split(".")[-2:]) if "." in host else host

    items = []

    pw = read_secret("admin-user-password")
    if pw:
        items.append(item(
            "%s - user %s + Cockpit Login" % (pfx, admin_user),
            password=pw, username=admin_user,
            urls=["https://%s.1:9090" % wg_net, "https://%s" % host],
            location="https://%s.1:9090" % wg_net, location_key=domain_key,
            notes="sudo-Passwort fuer %s.\n\n"
                  "Gilt zugleich fuer:\n"
                  "- die VNC-Rettungskonsole im Hostishere-Panel (Notausgang beim Aussperren)\n"
                  "- das Cockpit-Login auf https://%s.1:9090 (nur im WireGuard-Tunnel)\n\n"
                  "Bewusst tippbar gehalten: Die VNC-Konsole uebertraegt rohe US-Tastenpositionen,\n"
                  "ein deutsches Layout kommt dort verdreht an.\n\n"
                  "SSH selbst ist key-only auf Port %s - dieses Passwort hilft dort nicht.\n"
                  "Zusaetzlich auf Papier notieren.\n\nErzeugt %s auf %s."
                  % (admin_user, wg_net, ssh_port, today, host)))

    pw = read_secret("grub-password")
    if pw:
        items.append(item(
            "%s - GRUB Boot-Menue > Server" % pfx,
            password=pw, username="root",
            notes="Schuetzt das Bearbeiten eines Boot-Eintrags und die GRUB-Shell - also den Weg,\n"
                  "auf dem jemand mit Konsolenzugang init=/bin/bash bootet.\n\n"
                  "Die normalen Menueeintraege sind --unrestricted: Ein Reboot braucht keine Eingabe.\n\n"
                  "Nur aus Kleinbuchstaben und Ziffern, weil es ausschliesslich ueber die VNC-Konsole\n"
                  "eingegeben wird und GRUB dort rohe US-Tastenpositionen bekommt.\n\n"
                  "NICHT WIEDERHERSTELLBAR. Geht es verloren, bleibt das Boot-Menue gesperrt.\n\n"
                  "Erzeugt %s auf %s." % (today, host)))

    pw = read_secret("nc-admin-pass")
    if pw:
        items.append(item(
            "%s - nc - %s @ %s" % (pfx, admin_user, nc_domain),
            password=pw, username=admin_user,
            urls=["https://%s" % nc_domain],
            location="https://%s" % nc_domain, location_key=domain_key,
            notes="Nextcloud-Administrator.\n\n"
                  "Zwei-Faktor ist erzwungen - das TOTP-Geheimnis nach der Einrichtung in das\n"
                  "Einmalkennwort-Feld DIESES Objekts legen, nicht in ein eigenes.\n\n"
                  "Erzeugt %s auf %s." % (today, host)))

    pw = read_secret("nc-db-root")
    if pw:
        items.append(item(
            "%s - nc-db-root > Server" % pfx,
            password=pw, username="root",
            urls=["https://%s" % nc_domain],
            location="https://%s" % nc_domain, location_key=domain_key,
            notes="MariaDB root im Container nextcloud-db.\n\n"
                  "Erreichbar nur aus dem Docker-Netz, es gibt keinen veroeffentlichten Port.\n"
                  "Gebraucht fuer Dumps und Schemaarbeiten.\n\n"
                  "Erzeugt %s auf %s." % (today, host)))

    pw = read_secret("nc-db-pass")
    if pw:
        items.append(item(
            "%s - nc-db-pass > Server" % pfx,
            password=pw, username="nextcloud",
            urls=["https://%s" % nc_domain],
            location="https://%s" % nc_domain, location_key=domain_key,
            notes="Anwendungskonto, das der Nextcloud-Container benutzt.\n\n"
                  "Liegt zusaetzlich unter /srv/nextcloud/secrets/ auf dem Server.\n\n"
                  "Erzeugt %s auf %s." % (today, host)))

    pw = read_secret("borg-passphrase")
    if pw:
        items.append(item(
            "%s - borg Password > Server" % pfx,
            password=pw, username="borg",
            notes="Passphrase fuer /srv/hdd/backup/repo-server - das Repository, in das der\n"
                  "Server seine eigene Sicherung schreibt.\n\n"
                  "OHNE DIESE PASSPHRASE UND DEN SCHLUESSELEXPORT IST DAS BACKUP UNLESBAR.\n"
                  "Passphrase und Schluesselexport bewusst in getrennten Objekten halten.\n\n"
                  "Erzeugt %s auf %s." % (today, host)))

    # 2026-10-06: secrets of phases 13 and 15, until now not carried over.
    for fname, label, user, extra in (
            ("immo-db-pass", "immo MariaDB", "immo",
             "Datenbankkonto immo auf der nativen MariaDB (127.0.0.1:3306), Datenbank immo.\n"
             "Steht auch in /srv/immo/.env und /etc/immo/web.env."),
            ("immo-erfass-schluessel", "immo Erfassungsschluessel", None,
             "ERFASS_SCHLUESSEL des immo.flow-Frontends (Bookmarklet). Steht in /etc/immo/web.env."),
            ("turn-secret", "Talk TURN secret", None,
             "Gemeinsames Geheimnis zwischen Nextcloud Talk und coturn (Port 3478)."),
            ("signaling-secret", "Talk signaling secret", None,
             "Geheimnis zwischen Nextcloud Talk und dem Signaling-Server."),
            ("signaling-hashkey", "Talk signaling hashkey", None,
             "Sitzungsschluessel des Signaling-Servers (hashkey)."),
            ("signaling-blockkey", "Talk signaling blockkey", None,
             "Sitzungsschluessel des Signaling-Servers (blockkey)."),
    ):
        pw = read_secret(fname)
        if pw:
            items.append(item(
                "%s - %s > Server" % (pfx, label), password=pw, username=user,
                notes="%s\n\nQuelle: %s/%s\n\nErzeugt %s auf %s."
                      % (extra, SECRETS_DIR, fname, today, host)))

    for fname, label, extra in (
            ("borg-repo-server-key.txt", "borg-repo-server-key.txt",
             "Schluesselexport des Repositorys repo-server."),
            ("borg-repo-server-key-paper.txt", "borg-repo-server-key-paper.txt",
             "Papierfassung desselben Schluessels, zum Ausdrucken."),
            ("wireguard-client.conf.example", "wireguard-client.conf",
             "Vorlage fuer den WireGuard-Client auf dem Mac."),
            ("panel-ca/ca.crt", "panel-ca ca.crt",
             "Wurzelzertifikat der Panel-CA, im macOS-Schluesselbund zu vertrauen."),
            ("panel-ca/ca.key", "panel-ca ca.key",
             "PRIVATER Schluessel der Panel-CA. Wer ihn hat, kann Zertifikate fuer die\n"
             "Panels ausstellen. Nicht wiederherstellbar."),
    ):
        content = read_secret(fname)
        if content:
            items.append(item(
                "%s - %s > Server" % (pfx, label),
                notes="%s\n\nQuelle: %s/%s\n\n%s\n\nErzeugt %s auf %s."
                      % (extra, SECRETS_DIR, fname,
                         "-" * 60 + "\n" + content, today, host)))

    if not items:
        sys.exit("No secrets found in %s - nothing written." % SECRETS_DIR)

    old_umask = os.umask(0o077)
    try:
        with open(args.out, "w", encoding="utf-8") as fh:
            for body in items:
                fh.write(json.dumps(body, ensure_ascii=False) + "\n")
                fh.write(SEP + "\n")
    finally:
        os.umask(old_umask)
    os.chmod(args.out, 0o600)

    print("Written: %s" % args.out)
    print("%d items:" % len(items))
    for body in items:
        print("  %s" % body["title"])
    print()
    print("1. Auf den Mac holen (als %s, root kann sich nicht per SSH anmelden):" % admin_user)
    print("   sudo install -m 600 -o %s %s /home/%s/install-secrets.1pif"
          % (admin_user, args.out, admin_user))
    print("   scp -P %s %s@%s:install-secrets.1pif ~/Downloads/" % (ssh_port, admin_user, host))
    print("2. In 1Password 8: Datei > Importieren > 1Password > .1pif")
    print("3. WARNUNG: Die Datei enthaelt alle Passwoerter im Klartext. Danach zwingend:")
    print("   shred -u %s" % args.out)
    print("   shred -u /home/%s/install-secrets.1pif" % admin_user)
    print("   und auf dem Mac: rm -P ~/Downloads/install-secrets.1pif")


if __name__ == "__main__":
    main()
