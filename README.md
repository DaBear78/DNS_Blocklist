# FRITZ!Box DNS-Filterliste

Diese regelmäßig aktualisierte Sperrliste bündelt AdGuard DNS Filter, HaGeZi Pro, HaGeZi TIF und OISD Big. Sie ist für die DNS-Filterfunktion geeigneter FRITZ!Box-Modelle mit passender FRITZ!OS-Version vorgesehen.

**Filterlisten-URL:** [https://raw.githubusercontent.com/DaBear78/DNS_Blocklist/main/domains.txt](https://raw.githubusercontent.com/DaBear78/DNS_Blocklist/main/domains.txt)

## In der FRITZ!Box einrichten

1. Öffne die FRITZ!Box-Benutzeroberfläche unter `http://fritz.box`.
2. Gehe zu **Heimnetz → Netzwerk → Netzwerkeinstellungen → Erweiterte Netzwerkeinstellungen ändern → DNS-Filter**.
3. Füge eine Filterliste hinzu, trage die oben angegebene Filterlisten-URL ein und speichere die Liste.

Die genaue Position der DNS-Filter-Einstellungen beschreibt [AVM in der FRITZ!Box-Hilfe](https://fritzhelp.avm.de/help/de/FRITZ-Box-7590-AX/avm/026p1/hilfe_netzwerk_dns_filterlisten). Die Funktion setzt ein FRITZ!Box-Modell und FRITZ!OS voraus, die DNS-Filterlisten unterstützen.

## Format und Inhalt

Die Datei wird im **Adblock-Format** bereitgestellt. Der Merger übernimmt eindeutige Domain-Blockregeln wie `||example.com^` und Domain-Ausnahmen wie `@@||example.com^`. Regeln mit Modifikatoren, URL-Mustern, Wildcards oder Regex, die sich nicht sicher übertragen lassen, werden ausgelassen. Domains werden normalisiert; doppelte Einträge und von einer bereits enthaltenen Domain abgedeckte Subdomains werden entfernt.

Der Kommentarblock am Anfang der Liste zeigt, wie viele Quellen erfolgreich verarbeitet wurden, wie viele Regeln beim Zusammenführen als Duplikate oder redundante Subdomains entfielen und wie viele Regeln aus anderen Gründen verworfen wurden. Die verworfenen Regeln werden zusätzlich nach Quelle aufgeschlüsselt.

Die Liste wird mehrmals täglich aus diesen Quellen aktualisiert:

- [AdGuard DNS Filter](https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt)
- [HaGeZi Pro](https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/pro.txt)
- [HaGeZi TIF](https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/tif.txt)
- [OISD Big](https://big.oisd.nl/)

Wenn die FRITZ!Box eine Filterliste als fehlerhaft meldet oder eine gewünschte Internetseite nicht erreichbar ist, prüfe zuerst den Listenstatus in der DNS-Filter-Einstellung. Bei einer fälschlich gesperrten Domain kannst du sie über die Ausnahmen der FRITZ!Box wieder freigeben.


