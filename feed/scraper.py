#!/usr/bin/env python3
"""
Security feed scraper for rainfantry.github.io
Runs via GitHub Actions every 6 hours, writes feed/data.json

Sources (all public, no auth required):
  - CISA KEV:      https://www.cisa.gov/known-exploited-vulnerabilities-catalog
  - NVD CVE API:   https://services.nvd.nist.gov/rest/json/cves/2.0
  - Hacker News:   https://hn.algolia.com (Algolia public search API)
  - BleepingComp:  https://www.bleepingcomputer.com/feed/ (RSS)
"""

import json
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
import requests

OUTFILE = Path(__file__).parent / "data.json"
MAX_ITEMS = 50
TIMEOUT = 20
HEADERS = {"User-Agent": "Mozilla/5.0 (security-research-feed/1.0; +https://rainfantry.github.io)"}

SOURCES = {
    "hn":      "https://hn.algolia.com/api/v1/search_by_date?tags=story&query=security+exploit+vulnerability&hitsPerPage=20",
    "nvd":     "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=10",
    "cisa":    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    "bleeping":"https://www.bleepingcomputer.com/feed/",
}


def fetch(url, xml=False):
    try:
        r = requests.get(url, headers=HEADERS, timeout=TIMEOUT)
        r.raise_for_status()
        return ET.fromstring(r.text) if xml else r.json()
    except Exception as e:
        print(f"  FAIL {url}: {e}")
        return None


def scrape_hn(data):
    items = []
    if not data:
        return items
    for hit in data.get("hits", []):
        title = hit.get("title", "")
        url = hit.get("url") or f"https://news.ycombinator.com/item?id={hit.get('objectID')}"
        points = hit.get("points") or 0
        published = hit.get("created_at")
        if points < 10:  # filter low-engagement posts
            continue
        items.append({
            "id": f"hn-{hit.get('objectID')}",
            "source": "Hacker News",
            "source_icon": "🔶",
            "title": title,
            "url": url,
            "points": points,
            "published": published,
        })
    return items


def scrape_nvd(data):
    items = []
    if not data:
        return items
    for vuln in data.get("vulnerabilities", []):
        cve = vuln.get("cve", {})
        cve_id = cve.get("id", "")
        descs = cve.get("descriptions", [])
        desc = next((d["value"] for d in descs if d.get("lang") == "en"), "")
        metrics = cve.get("metrics", {})
        score = None
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if key in metrics and metrics[key]:
                score = metrics[key][0].get("cvssData", {}).get("baseScore")
                break
        published = cve.get("published")
        items.append({
            "id": f"nvd-{cve_id}",
            "source": "NVD",
            "source_icon": "🛡️",
            "title": f"{cve_id}: {desc[:120]}{'...' if len(desc) > 120 else ''}",
            "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            "points": int(score * 10) if score else 0,
            "published": published,
        })
    return items


def scrape_cisa(data):
    items = []
    if not data:
        return items
    vulns = data.get("vulnerabilities", [])
    # Most recently added first
    for v in reversed(vulns[-20:]):
        cve_id = v.get("cveID", "")
        vendor = v.get("vendorProject", "")
        product = v.get("product", "")
        name = v.get("vulnerabilityName", "")
        due = v.get("dueDate", "")
        items.append({
            "id": f"kev-{cve_id}",
            "source": "CISA KEV",
            "source_icon": "⚠️",
            "title": f"[EXPLOITED] {cve_id}: {vendor} {product} — {name}",
            "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            "points": 100,
            "vendor": vendor,
            "published": due,
        })
    return items


def scrape_bleeping(root):
    items = []
    if root is None:
        return items
    channel = root.find("channel")
    if not channel:
        return items
    for item in channel.findall("item")[:15]:
        title = item.findtext("title", "")
        url = item.findtext("link", "")
        pub = item.findtext("pubDate", "")
        try:
            from email.utils import parsedate_to_datetime
            published = parsedate_to_datetime(pub).isoformat() if pub else None
        except Exception:
            published = None
        items.append({
            "id": f"bc-{abs(hash(url))}",
            "source": "BleepingComputer",
            "source_icon": "📰",
            "title": title,
            "url": url,
            "points": 0,
            "published": published,
        })
    return items


def dedupe(items):
    seen = set()
    out = []
    for item in items:
        key = item.get("id") or item.get("url")
        if key and key not in seen:
            seen.add(key)
            out.append(item)
    return out


def main():
    all_items = []

    print("Fetching CISA KEV...")
    all_items += scrape_cisa(fetch(SOURCES["cisa"]))
    time.sleep(1)

    print("Fetching NVD...")
    all_items += scrape_nvd(fetch(SOURCES["nvd"]))
    time.sleep(1)

    print("Fetching Hacker News...")
    all_items += scrape_hn(fetch(SOURCES["hn"]))
    time.sleep(1)

    print("Fetching BleepingComputer...")
    all_items += scrape_bleeping(fetch(SOURCES["bleeping"], xml=True))

    all_items = dedupe(all_items)
    all_items = all_items[:MAX_ITEMS]

    output = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "item_count": len(all_items),
        "sources": ["cisa_kev", "nvd", "hn", "bleeping"],
        "items": all_items,
    }

    OUTFILE.write_text(json.dumps(output, indent=2, ensure_ascii=False))
    print(f"Written {len(all_items)} items to {OUTFILE}")


if __name__ == "__main__":
    main()
