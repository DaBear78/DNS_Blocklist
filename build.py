#!/usr/bin/env python3
"""Build a conservative domain-only DNS blocklist for FRITZ!Box."""
from __future__ import annotations

import ipaddress
import os
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent
OUTPUT = ROOT / "domains.txt"
MAX_BYTES = 80 * 1024 * 1024
TIMEOUT_SECONDS = 45
MIN_DOMAINS_PER_SOURCE = int(os.environ.get("MIN_DOMAINS_PER_SOURCE", "1000"))

SOURCES = {
    "AdGuard DNS Filter": (
        "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt",
        "adguard",
    ),
    "HaGeZi Pro": (
        "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/pro-onlydomains.txt",
        "domains",
    ),
    "HaGeZi TIF": (
        "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/tif-onlydomains.txt",
        "domains",
    ),
}

# AdGuard's ||domain^ rule matches the exact hostname and its subdomains.
# Keep this grammar deliberately narrow: no exceptions, modifiers, wildcards,
# URL paths, regex rules, or other filter syntax can be represented safely as
# a plain FRITZ!Box domain entry.
ADGUARD_DOMAIN_RULE = re.compile(r"^\|\|([A-Za-z0-9.-]+)\^$")
DOMAIN_LINE = re.compile(r"^[A-Za-z0-9.-]+\.?$")


def normalize_domain(value: str) -> str | None:
    value = value.strip().rstrip(".").lower()
    if not value or len(value) > 253:
        return None
    try:
        value = value.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    if ":" in value or "*" in value:
        return None
    try:
        ipaddress.ip_address(value)
        return None
    except ValueError:
        pass
    labels = value.split(".")
    if len(labels) < 2 or any(not 1 <= len(label) <= 63 for label in labels):
        return None
    if any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label) for label in labels):
        return None
    return value


def fetch(name: str, url: str) -> str:
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "fritzbox-dns-list-builder/1.0", "Accept": "text/plain,*/*;q=0.8"},
    )
    with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:
        status = getattr(response, "status", 200)
        if status != 200:
            raise RuntimeError(f"{name}: HTTP-Status {status}")
        body = response.read(MAX_BYTES + 1)
    if len(body) > MAX_BYTES:
        raise RuntimeError(f"{name}: Download überschreitet {MAX_BYTES} Bytes")
    if not body.strip():
        raise RuntimeError(f"{name}: Quelle ist leer")
    try:
        text = body.decode("utf-8-sig", errors="strict")
    except UnicodeDecodeError as exc:
        raise RuntimeError(f"{name}: keine gültige UTF-8-Datei") from exc
    sample = text[:500].lstrip().lower()
    if sample.startswith("<!doctype html") or sample.startswith("<html"):
        raise RuntimeError(f"{name}: statt einer Liste wurde HTML geliefert")
    return text


def parse_source(name: str, text: str, kind: str) -> set[str]:
    found: set[str] = set()
    candidates = 0
    rejected = 0
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(("!", "#")):
            continue
        # Strip a UTF-8 BOM if a source placed one after its header/comments.
        line = line.lstrip("\ufeff").strip()
        if not line or line.startswith(("!", "#")):
            continue
        candidates += 1
        domain: str | None = None
        if kind == "adguard":
            if DOMAIN_LINE.fullmatch(line):
                domain = normalize_domain(line)
            else:
                match = ADGUARD_DOMAIN_RULE.fullmatch(line)
                if match:
                    domain = normalize_domain(match.group(1))
        elif DOMAIN_LINE.fullmatch(line):
            domain = normalize_domain(line)
        if domain is None:
            rejected += 1
        else:
            found.add(domain)
    if len(found) < MIN_DOMAINS_PER_SOURCE:
        raise RuntimeError(
            f"{name}: nur {len(found)} gültige Domains (Mindestwert: {MIN_DOMAINS_PER_SOURCE}); "
            "Veröffentlichung wird abgebrochen"
        )
    if candidates and rejected / candidates > 0.90:
        raise RuntimeError(f"{name}: mehr als 90 % der Listeneinträge waren nicht verwertbar")
    print(f"{name}: {len(found):,} eindeutige Domains; {rejected:,} Zeilen verworfen")
    return found


def remove_redundant_subdomains(domains: set[str]) -> list[str]:
    # Visiting shorter parent domains first makes suffix checks straightforward.
    kept: list[str] = []
    kept_set: set[str] = set()
    for domain in sorted(domains, key=lambda item: (item.count("."), item)):
        labels = domain.split(".")
        has_parent = any(
            ".".join(labels[index:]) in kept_set
            for index in range(1, len(labels) - 1)
        )
        if not has_parent:
            kept.append(domain)
            kept_set.add(domain)
    return sorted(kept)


def main() -> int:
    combined: set[str] = set()
    for name, (url, kind) in SOURCES.items():
        try:
            content = fetch(name, url)
            combined.update(parse_source(name, content, kind))
        except (urllib.error.URLError, TimeoutError, OSError, RuntimeError) as exc:
            print(f"FEHLER: {exc}", file=sys.stderr)
            return 1
    final = remove_redundant_subdomains(combined)
    if len(final) < MIN_DOMAINS_PER_SOURCE:
        print(f"FEHLER: Endliste hat nur {len(final)} Domains; keine Datei wird geschrieben", file=sys.stderr)
        return 1
    header = [
        "# FRITZ!Box DNS blocklist — domain-only format",
        "# Generated automatically from AdGuard DNS Filter, HaGeZi Pro and HaGeZi TIF.",
        "# Source rules that cannot be represented safely as domains are omitted.",
        f"# Domains: {len(final)}",
        "",
    ]
    content = "\n".join(header + final) + "\n"
    OUTPUT.write_text(content, encoding="utf-8", newline="\n")
    print(f"Erstellt: {OUTPUT.name} mit {len(final):,} Domains")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

