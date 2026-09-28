# FRITZ!Box DNS-Blockliste aus drei Quellen

Dieses Repository erstellt ca. alle 8 Stunden eine Domain-only-Liste für die DNS-Blocklisten-Funktion der FRITZ!Box. Die fertige Datei ist unter folgender Adresse erreichbar:

`https://raw.githubusercontent.com/DaBear78/DNS_Blocklist/main/domains.txt`

## Quellen und Konvertierung

- AdGuard DNS Filter: `https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt`
- HaGeZi Pro: `https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/pro-onlydomains.txt`
- HaGeZi TIF: `https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/tif-onlydomains.txt`

Die beiden HaGeZi-Quellen werden als Domainzeilen verarbeitet. Bei AdGuard werden nur nackte Domainzeilen und Regeln der exakten Form `||domain.example^` übernommen. Diese AdGuard-Regel blockiert die angegebene Domain und ihre Subdomains. Ausnahmen (`@@`), Modifikatoren (`$...`), Wildcards, Regex, URL-Pfade und sonstige Filterregeln werden ignoriert, weil sie keine sichere, gleichwertige Domain-only-Darstellung haben. Kommentare und Kopfzeilen werden ignoriert.

Domains werden kleingeschrieben, IDN-Namen in ASCII/Punycode überführt und syntaktisch validiert. Exakte Duplikate und Subdomains einer bereits enthaltenen übergeordneten Domain werden entfernt. Die Ausgabe enthält ausschließlich Kommentare und eine Domain pro Zeile.
