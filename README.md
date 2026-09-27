# FRITZ!Box DNS-Blockliste aus drei Quellen

Dieses Repository erstellt täglich eine Domain-only-Liste für die DNS-Blocklisten-Funktion der FRITZ!Box. Die fertige Datei ist nach dem ersten erfolgreichen GitHub-Actions-Lauf unter folgender Adresse erreichbar:

`https://raw.githubusercontent.com/DEIN-GITHUB-NAME/DEIN-REPOSITORY/main/domains.txt`

## Quellen und Konvertierung

- AdGuard DNS Filter: `https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt`
- HaGeZi Pro: `https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/pro-onlydomains.txt`
- HaGeZi TIF: `https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/tif-onlydomains.txt`

Die beiden HaGeZi-Quellen werden als Domainzeilen verarbeitet. Bei AdGuard werden nur nackte Domainzeilen und Regeln der exakten Form `||domain.example^` übernommen. Diese AdGuard-Regel blockiert die angegebene Domain und ihre Subdomains. Ausnahmen (`@@`), Modifikatoren (`$...`), Wildcards, Regex, URL-Pfade und sonstige Filterregeln werden ignoriert, weil sie keine sichere, gleichwertige Domain-only-Darstellung haben. Kommentare und Kopfzeilen werden ignoriert.

Domains werden kleingeschrieben, IDN-Namen in ASCII/Punycode überführt und syntaktisch validiert. Exakte Duplikate und Subdomains einer bereits enthaltenen übergeordneten Domain werden entfernt. Die Ausgabe enthält ausschließlich Kommentare und eine Domain pro Zeile.

## Einrichtung unter Windows

1. Melde dich bei [GitHub](https://github.com/) an oder erstelle ein Konto.
2. Öffne [github.com/new](https://github.com/new), lege ein Repository an, zum Beispiel `fritzbox-dns-blocklist`, und wähle **Public**. Eine öffentliche Raw-URL ist für die FRITZ!Box ohne Anmeldung erreichbar.
3. Lade den Inhalt dieses Projektordners herunter oder kopiere die Dateien in einen gleichnamigen lokalen Ordner. Achte darauf, auch den Ordner `.github\workflows` samt `update.yml` zu übernehmen. Windows blendet Ordner, deren Namen mit einem Punkt beginnen, gelegentlich aus.
4. Installiere [Git for Windows](https://git-scm.com/download/win), falls Git noch nicht installiert ist.
5. Öffne im Projektordner den Datei-Explorer, klicke in die Adressleiste, tippe `powershell` und drücke Enter.
6. Führe in PowerShell die folgenden Befehle aus. Ersetze `DEIN-GITHUB-NAME` durch deinen GitHub-Benutzernamen:

   ```powershell
   git init -b main
   git add .
   git commit -m "Initial DNS blocklist project"
   git remote add origin https://github.com/DEIN-GITHUB-NAME/fritzbox-dns-blocklist.git
   git push -u origin main
   ```

   GitHub kann beim ersten Push eine Anmeldung im Browser verlangen.
7. Öffne im Repository auf GitHub **Actions** und aktiviere Workflows, falls GitHub danach fragt. Wähle **Update FRITZ!Box DNS blocklist** und klicke **Run workflow**, um den ersten Lauf sofort zu starten. Danach läuft der Workflow täglich um 04:17 UTC (im Sommer 06:17 Uhr, im Winter 05:17 Uhr in Deutschland).
8. Nach einem erfolgreichen Lauf findest du `domains.txt` im Repository. Die FRITZ!Box-URL lautet:

   `https://raw.githubusercontent.com/DEIN-GITHUB-NAME/fritzbox-dns-blocklist/main/domains.txt`

   Trage diese Adresse in die DNS-Blocklisten-Funktion deiner FRITZ!Box ein. Für eine dauerhafte Nutzung muss das Repository öffentlich bleiben.

## Aktualisierung

Der tägliche Workflow lädt alle drei Quellen erneut. Er schreibt nur dann einen Commit, wenn sich `domains.txt` tatsächlich geändert hat. Du kannst ihn jederzeit unter **Actions → Update FRITZ!Box DNS blocklist → Run workflow** manuell starten.

Downloads müssen erfolgreich, nicht leer, UTF-8-kodiert und kleiner als 20 MiB sein. Jede Quelle muss standardmäßig mindestens 1.000 gültige Domains liefern. Schlägt eine Quelle fehl oder unterschreitet sie den Mindestwert, endet der Lauf mit Fehler und die zuletzt veröffentlichte Liste bleibt erhalten. Falls eine Quelle dauerhaft unter diesen Mindestwert fällt, kann der Repository-Inhaber den Workflow-Parameter `MIN_DOMAINS_PER_SOURCE` niedriger setzen; der Schutz sollte dabei nicht auf null gesetzt werden.

## Lokal manuell bauen

Mit Python 3.10 oder neuer im Projektordner:

```powershell
py -3 build.py
```

Die Ausgabe wird in `domains.txt` geschrieben. Es werden keine zusätzlichen Python-Pakete benötigt.
