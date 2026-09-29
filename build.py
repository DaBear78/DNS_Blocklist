#!/usr/bin/env python3
"""Merge safe Adblock domain rules for the FRITZ!Box DNS filter."""
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
MIN_RULES_PER_SOURCE = int(os.environ.get("MIN_RULES_PER_SOURCE", "1000"))

SOURCES = {
    "AdGuard DNS Filter": "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt",
    "HaGeZi Pro": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/pro.txt",
    "HaGeZi TIF": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/tif.txt",
    "OISD Big": "https://big.oisd.nl/",
}

# Deliberately accept only plain domain-anchored rules. Other Adblock rules
# (modifiers, wildcards, regex, URL patterns, etc.) must not be simplified by
# trimming away syntax because that can change which names they block.
BLOCK_RULE = re.compile(r"^\|\|([^\s|^$*/\\]+)\^$")
ALLOW_RULE = re.compile(r"^@@\|\|([^\s|^$*/\\]+)\^$")


def normalize_domain(value: str) -> str | None:
    value = value.strip().lower()
    if value.endswith("."):
        value = value[:-1]
    if not value or value.endswith(".") or len(value) > 253:
        return None
    try:
        value = value.encode("idna").decode("ascii")
    except UnicodeError:
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


def parse_source(name: str, text: str) -> tuple[set[str], set[str]]:
    blocks: set[str] = set()
    allows: set[str] = set()
    candidates = 0
    rejected = 0
    for raw in text.splitlines():
        line = raw.strip().lstrip("\ufeff").strip()
        if not line or line.startswith(("!", "#", "[")):
            continue
        candidates += 1
        block_match = BLOCK_RULE.fullmatch(line)
        allow_match = ALLOW_RULE.fullmatch(line)
        if block_match:
            domain = normalize_domain(block_match.group(1))
            if domain is not None:
                blocks.add(domain)
                continue
        elif allow_match:
            domain = normalize_domain(allow_match.group(1))
            if domain is not None:
                allows.add(domain)
                continue
        rejected += 1

    if len(blocks) < MIN_RULES_PER_SOURCE:
        raise RuntimeError(
            f"{name}: nur {len(blocks)} gültige Blockregeln "
            f"(Mindestwert: {MIN_RULES_PER_SOURCE}); Veröffentlichung wird abgebrochen"
        )
    if candidates and rejected / candidates > 0.90:
        raise RuntimeError(f"{name}: mehr als 90 % der Listeneinträge waren nicht verwertbar")
    print(
        f"{name}: {len(blocks):,} Blockdomains, {len(allows):,} Ausnahmen; "
        f"{rejected:,} nicht unterstützte Zeilen verworfen"
    )
    return blocks, allows


def remove_redundant_subdomains(domains: set[str]) -> list[str]:
    """Keep a parent domain only once when it already covers its subdomains."""
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
    all_blocks: set[str] = set()
    all_allows: set[str] = set()
    for name, url in SOURCES.items():
        try:
            content = fetch(name, url)
            blocks, allows = parse_source(name, content)
            all_blocks.update(blocks)
            all_allows.update(allows)
        except (urllib.error.URLError, TimeoutError, OSError, RuntimeError) as exc:
            print(f"FEHLER: {exc}", file=sys.stderr)
            return 1

    blocks = remove_redundant_subdomains(all_blocks)
    allows = remove_redundant_subdomains(all_allows)
    if len(blocks) < MIN_RULES_PER_SOURCE:
        print(
            f"FEHLER: Endliste enthält nur {len(blocks)} Blockregeln; "
            "domains.txt wird nicht verändert",
            file=sys.stderr,
        )
        return 1

    lines = [
        "[Adblock Plus 2.0]",
        "! FRITZ!Box DNS blocklist, combined from the sources below.",
        "! Only exact domain block and exception rules are retained.",
        "! Unsupported rules are discarded instead of being rewritten unsafely.",
        f"! Block rules: {len(blocks)}; exception rules: {len(allows)}",
        "! Sources:",
        "! - AdGuard DNS Filter: https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt",
        "! - HaGeZi Pro: https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/pro.txt",
        "! - HaGeZi TIF: https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/tif.txt",
        "! - OISD Big: https://big.oisd.nl/",
        "",
    ]
    lines.extend(f"||{domain}^" for domain in blocks)
    lines.extend(f"@@||{domain}^" for domain in allows)
    OUTPUT.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    print(f"Erstellt: {OUTPUT.name} mit {len(blocks):,} Blockregeln und {len(allows):,} Ausnahmen")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
