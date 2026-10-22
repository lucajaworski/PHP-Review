#!/usr/bin/env python3
"""
Sharp External Website Exposure Check (passive)

Takes a list of client email domains and, for each one:
  1. Finds websites and subdomains from public sources only
     (DNS over HTTPS and certificate transparency logs via crt.sh).
  2. Makes one normal page request to each web host, the same as a browser,
     and records the server software and PHP version where the site reveals it.
  3. Flags PHP versions that are end of life or below the PHP2Shell fixed versions
     (CVE-2026-109618 / CVE-2026-109619).
  4. Writes a CSV and an Excel report.

It does NOT scan ports, probe for vulnerabilities, try logins or send exploit traffic.
A site that hides its version is reported as UNKNOWN, never as safe.

Usage:
  python website_exposure_check.py domains.csv [-o report] [--max-hosts 25]

domains.csv: columns "client,domain" (header optional), e.g.
  Contoso Ltd,contoso.co.uk
  Fabrikam,fabrikam.com
If the header row includes an "opted_in" column, only rows marked Yes are checked.
Other columns (region, notes and so on) are ignored. *.onmicrosoft.com names are skipped.

Requires: Python 3.9+, requests (pip install requests). openpyxl optional for Excel.
"""
import argparse
import csv
import re
import socket
import sys
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from urllib.parse import urlparse

import requests

VERSION = "2026-10-22c (opt-in required)"
RISK_ORDER = {"HIGH": 0, "REVIEW": 1, "UNKNOWN": 2, "INFO": 3, "UNREACHABLE": 4, "NO WEBSITE": 5, "OK": 6}
USER_AGENT = "Sharp-IT-Services-ExposureCheck/1.0 (passive; contact security@sharp.co.uk)"
TIMEOUT = 10

# PHP2Shell fixed versions per branch. Branches not listed (8.1 and older) are end of life.
FIXED = {(8, 5): 12, (8, 4): 27, (8, 3): 36, (8, 2): 35}

COMMON_PREFIXES = ["", "www.", "shop.", "store.", "blog.", "portal.", "dev.", "staging.", "test."]

session = requests.Session()
session.headers["User-Agent"] = USER_AGENT


def doh(name, rtype="A"):
    """DNS lookup over HTTPS (Cloudflare), no extra libraries needed."""
    try:
        r = session.get("https://cloudflare-dns.com/dns-query",
                        params={"name": name, "type": rtype},
                        headers={"accept": "application/dns-json"}, timeout=TIMEOUT)
        return [a["data"].rstrip(".") for a in r.json().get("Answer", []) if a.get("type") in (1, 5, 15, 16, 28)]
    except Exception:
        return []


def ct_subdomains(domain):
    """Hostnames seen in public certificate transparency logs (crt.sh)."""
    for attempt in range(3):
        try:
            r = session.get("https://crt.sh/", params={"q": f"%.{domain}", "output": "json"}, timeout=45)
            if r.status_code == 200:
                names = set()
                for row in r.json():
                    for n in row.get("name_value", "").splitlines():
                        n = n.strip().lower()
                        if n.startswith("*."):
                            n = n[2:]
                        if in_scope(n, domain) and " " not in n:
                            names.add(n)
                return names, "ok"
        except Exception:
            pass
        time.sleep(3 * (attempt + 1))
    return set(), "crt.sh unavailable"


def in_scope(host, domain):
    """True only for the domain itself or a real subdomain of it (not notclient.co.uk)."""
    host = (host or "").lower().rstrip(".")
    return host == domain or host.endswith("." + domain)


def normalise_domain(value):
    """Accepts contoso.co.uk, https://www.contoso.co.uk/page or name@contoso.co.uk."""
    d = value.strip().lower()
    d = d.split("@")[-1]
    d = re.sub(r"^[a-z]+://", "", d)
    d = d.split("/")[0].split(":")[0].rstrip(".")
    if d.startswith("www."):
        d = d[4:]
    return d


def resolves(host):
    try:
        return socket.gethostbyname(host)
    except Exception:
        return None


def classify_php(ver):
    if not ver:
        return "UNKNOWN", "PHP version not disclosed. Ask web provider to confirm."
    m = re.match(r"(\d+)\.(\d+)(?:\.(\d+))?", ver)
    if not m:
        return "UNKNOWN", f"Unparsed version {ver}"
    major, minor = int(m.group(1)), int(m.group(2))
    patch = int(m.group(3)) if m.group(3) is not None else None
    if (major, minor) < (8, 2):
        return "HIGH", f"PHP {ver} is end of life. No fix available. Upgrade required."
    fixed = FIXED.get((major, minor))
    if fixed is None:
        return "REVIEW", f"PHP {ver} is a branch not in the advisory. Confirm with provider."
    if patch is None:
        return "UNKNOWN", (f"Site shows PHP {ver} without the full version. "
                           f"Ask provider to confirm it is {major}.{minor}.{fixed} or later.")
    if patch < fixed:
        return "HIGH", f"PHP {ver} is below the fixed version {major}.{minor}.{fixed}. Update required."
    return "OK", f"PHP {ver} is at or above the fixed version {major}.{minor}.{fixed}."


def probe(host, domain=""):
    """One normal GET request, HTTPS first then HTTP. Reads response headers only."""
    out = {"host": host, "ip": resolves(host), "url": "", "status": "", "server": "",
           "x_powered_by": "", "php_version": "", "cms_hint": "", "off_domain_redirect": "", "error": ""}
    if not out["ip"]:
        out["error"] = "Does not resolve"
        return out
    for scheme in ("https", "http"):
        try:
            r = session.get(f"{scheme}://{host}/", timeout=TIMEOUT, allow_redirects=True, stream=True)
            body = r.raw.read(65536, decode_content=True).decode("utf-8", "ignore") if r.ok else ""
            r.close()
            out["url"], out["status"] = r.url, r.status_code
            final_host = urlparse(r.url).hostname or ""
            out["off_domain_redirect"] = ("Yes: " + final_host) if domain and not in_scope(final_host, domain) else "No"
            out["server"] = r.headers.get("Server", "")
            out["x_powered_by"] = r.headers.get("X-Powered-By", "")
            m = re.search(r"PHP/(\d+\.\d+(?:\.\d+)?)", out["x_powered_by"] + " " + out["server"])
            out["php_version"] = m.group(1) if m else ""
            hints = []
            if "wp-content" in body or "wp-json" in r.headers.get("Link", ""):
                hints.append("WordPress (uses PHP)")
            gen = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', body, re.I)
            if gen:
                hints.append(gen.group(1)[:60])
            if "PHPSESSID" in r.headers.get("Set-Cookie", ""):
                hints.append("PHP session cookie")
            out["cms_hint"] = "; ".join(hints)
            out["error"] = ""
            return out
        except Exception as e:
            out["error"] = type(e).__name__
    return out


def check_domain(client, domain, max_hosts):
    domain = normalise_domain(domain)
    guessed = {p + domain for p in COMMON_PREFIXES}
    ct, ct_status = ct_subdomains(domain)
    hosts = guessed | ct
    mx = doh(domain, "MX")
    # Wildcard DNS: if a made-up name resolves, guessed names like dev./test. prove nothing.
    wildcard_ip = resolves(f"sharp-check-{uuid.uuid4().hex[:10]}.{domain}")
    skipped_wildcard = 0
    if wildcard_ip:
        keep = set()
        for h in hosts:
            if h in (domain, "www." + domain) or h in ct or resolves(h) != wildcard_ip:
                keep.add(h)
            else:
                skipped_wildcard += 1
        hosts = keep
    ordered = sorted(hosts, key=lambda h: (h not in (domain, "www." + domain), len(h), h))[:max_hosts]
    with ThreadPoolExecutor(max_workers=8) as ex:
        results = list(ex.map(lambda h: probe(h, domain), ordered))

    # One row per real website: names that land on the same page with the same software are merged.
    groups = {}
    for r in results:
        if r["error"] == "Does not resolve":
            continue
        key = (r["url"], r["server"], r["x_powered_by"]) if r["status"] else ("unreachable", r["host"])
        groups.setdefault(key, []).append(r)

    rows = []
    wc_note = f"Wildcard DNS ({skipped_wildcard} guessed names ignored)" if wildcard_ip else "No"
    for members in groups.values():
        members.sort(key=lambda m: (m["host"] not in (domain, "www." + domain), len(m["host"]), m["host"]))
        r = dict(members[0])
        r["also_reached_via"] = ", ".join(m["host"] for m in members[1:])
        uses_php = bool(r["php_version"] or "PHP" in r["cms_hint"] or "WordPress" in r["cms_hint"]
                        or "php" in r["x_powered_by"].lower())
        risk, note = classify_php(r["php_version"])
        if r["error"] and not r["status"]:
            risk, note = "UNREACHABLE", f"Host resolved but gave no web response ({r['error']}). Not checked."
        elif risk == "UNKNOWN" and not uses_php:
            risk, note = "INFO", "No sign of PHP from outside. Provider should still confirm."
        if r.get("off_domain_redirect", "").startswith("Yes"):
            note += " Site redirects to another domain: confirm the client owns it."
        rows.append({"client": client, "domain": domain, **r, "uses_php": "Yes" if uses_php else "Not seen",
                     "risk": risk, "note": note, "mx": " ".join(mx[:3]), "ct_lookup": ct_status,
                     "wildcard_dns": wc_note})
    if not rows:
        rows.append({"client": client, "domain": domain, "host": domain, "risk": "NO WEBSITE",
                     "note": f"None of the {len(ordered)} names checked has a website. "
                             "The domain may be used for email only. Confirm with the client.",
                     "mx": " ".join(mx[:3]), "ct_lookup": ct_status, "wildcard_dns": wc_note,
                     "uses_php": "", "also_reached_via": ""})
    return rows, len(guessed | ct)


def write_reports(rows, base):
    cols = ["client", "domain", "host", "ip", "url", "status", "server", "x_powered_by", "php_version",
            "cms_hint", "uses_php", "off_domain_redirect", "risk", "note", "also_reached_via", "error", "mx",
            "ct_lookup", "wildcard_dns"]
    with open(base + ".csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)
    try:
        from openpyxl import Workbook
        from openpyxl.styles import Font, PatternFill
        wb = Workbook()
        ws = wb.active
        ws.title = "Findings"
        ws.append([c.replace("_", " ").title() for c in cols])
        for c in ws[1]:
            c.font = Font(bold=True, color="FFFFFF")
            c.fill = PatternFill("solid", fgColor="C8102E")
        fills = {"HIGH": "F8CBAD", "REVIEW": "FFE699", "UNKNOWN": "FFF2CC", "OK": "C6EFCE", "INFO": "DDEBF7",
                 "UNREACHABLE": "D9D9D9",
                 "NO WEBSITE": "EDEDED"}
        for r in rows:
            ws.append([r.get(c, "") for c in cols])
            ws.cell(ws.max_row, cols.index("risk") + 1).fill = PatternFill("solid", fgColor=fills.get(r["risk"], "FFFFFF"))
        for col in ws.columns:
            ws.column_dimensions[col[0].column_letter].width = min(50, max(10, max(len(str(c.value or "")) for c in col) + 2))
        ws.freeze_panes = "A2"
        ws.auto_filter.ref = ws.dimensions
        sm = wb.create_sheet("Summary", 0)
        sm.append(["Client", "Domains", "Websites", "Worst rating", "PHP versions seen", "Next step"])
        for c in sm[1]:
            c.font = Font(bold=True, color="FFFFFF")
            c.fill = PatternFill("solid", fgColor="C8102E")
        steps = {"HIGH": "Send the advisory to the client now and ask their web provider to upgrade PHP.",
                 "REVIEW": "Ask the web provider to confirm the PHP version.",
                 "UNKNOWN": "Uses PHP but hides the version. Ask the web provider for written confirmation.",
                 "INFO": "No PHP seen. Ask the web provider to confirm.",
                 "UNREACHABLE": "Site did not respond. Re-run later or confirm with the client.",
                 "NO WEBSITE": "No website found. Confirm with the client whether they have one elsewhere.",
                 "OK": "Patched version shown. No action beyond normal maintenance."}
        by_client = {}
        for r in rows:
            by_client.setdefault(r["client"], []).append(r)
        for client in sorted(by_client):
            rs = by_client[client]
            worst = min((r["risk"] for r in rs), key=lambda k: RISK_ORDER.get(k, 9))
            sm.append([client, ", ".join(sorted({r["domain"] for r in rs})),
                       sum(1 for r in rs if r["risk"] != "NO WEBSITE"), worst,
                       ", ".join(sorted({r.get("php_version", "") for r in rs if r.get("php_version")})) or "Not shown",
                       steps.get(worst, "")])
            sm.cell(sm.max_row, 4).fill = PatternFill("solid", fgColor=fills.get(worst, "FFFFFF"))
        for col, wdt in zip("ABCDEF", (40, 40, 10, 14, 18, 80)):
            sm.column_dimensions[col].width = wdt
        sm.freeze_panes = "A2"
        n = wb.create_sheet("About")
        for line in [
            "Sharp External Website Exposure Check (passive)",
            f"Run: {datetime.now():%d %B %Y %H:%M}",
            "Method: public DNS, certificate transparency logs and one normal page request per host.",
            "No vulnerability scanning, exploitation or login attempts were made.",
            "UNKNOWN means the site does not reveal its version. It does not mean the site is safe.",
            "UNREACHABLE means the name exists but no web page came back, so it was not checked.",
            "Off Domain Redirect shows sites that send visitors to another platform (e.g. a hosted shop).",
            "Websites: names that land on the same page with the same software are merged into one row (see Also Reached Via).",
            "Wildcard DNS: where every made-up name resolves, guessed names (dev, test, shop...) are ignored.",
            "NO WEBSITE: none of the names checked has a website; the domain may be email only.",
            "This is a point in time snapshot. It is advisory and is not a warranty or guarantee.",
            "Website security and remediation remain the responsibility of the client and their web provider.",
        ]:
            n.append([line])
        n.column_dimensions["A"].width = 110
        wb.save(base + ".xlsx")
    except ImportError:
        pass


def read_targets(path):
    """Reads the client list. The header row MUST contain client, domain and opted_in.
    Only rows with opted_in = Yes are returned."""
    with open(path, newline="", encoding="utf-8-sig") as f:
        text = f.read()
    try:
        dialect = csv.Sniffer().sniff(text.splitlines()[0], delimiters=",;\t")
    except Exception:
        dialect = csv.excel
    rows = [r for r in csv.reader(text.splitlines(), dialect) if r and any(c.strip() for c in r)]
    if not rows:
        sys.exit("STOPPED: the file is empty.")
    header = [h.strip().lower() for h in rows.pop(0)]
    missing = [c for c in ("client", "domain", "opted_in") if c not in header]
    if missing:
        sys.exit(f"STOPPED: the first row must be a header containing client, domain and opted_in. "
                 f"Missing: {', '.join(missing)}. Found: {header}. Nothing was checked.")
    ci, di, oi = header.index("client"), header.index("domain"), header.index("opted_in")
    targets, seen = [], set()
    skipped = {"not opted in": 0, "no domain": 0, "Microsoft tenant name only": 0, "duplicate": 0}
    for row in rows:
        cell = lambda i: row[i].strip() if i < len(row) else ""
        if cell(ci).startswith("#"):
            continue
        if cell(oi).lower() not in ("yes", "y", "true"):
            skipped["not opted in"] += 1
            continue
        domain = normalise_domain(cell(di))
        if domain.endswith(".onmicrosoft.com"):
            skipped["Microsoft tenant name only"] += 1
            continue
        if not domain or "." not in domain:
            skipped["no domain"] += 1
            continue
        if (cell(ci), domain) in seen:
            skipped["duplicate"] += 1
            continue
        seen.add((cell(ci), domain))
        targets.append((cell(ci), domain))
    return targets, skipped


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("domains_csv")
    ap.add_argument("-o", "--output", default=f"exposure_report_{datetime.now():%Y%m%d_%H%M}")
    ap.add_argument("--max-hosts", type=int, default=25, help="Max hosts checked per domain")
    ap.add_argument("--yes", action="store_true", help="Skip the confirmation prompt")
    a = ap.parse_args()

    print(f"Sharp External Website Exposure Check, version {VERSION}", flush=True)
    targets, skipped = read_targets(a.domains_csv)
    print(f"Skipped: {skipped}")
    if not targets:
        print("Nothing to check. Put Yes in the opted_in column for the clients who have agreed, "
              "then save as CSV UTF-8.")
        return
    clients = sorted({c for c, _ in targets})
    print(f"\n{len(targets)} websites for {len(clients)} opted-in clients:")
    for c, d in targets:
        print(f"  - {c}: {d}")
    if not a.yes:
        if input("\nCheck ONLY these? Type yes to continue: ").strip().lower() not in ("yes", "y"):
            print("Cancelled. Nothing was checked.")
            return

    order = RISK_ORDER
    all_rows = []

    def save(note=""):
        all_rows.sort(key=lambda r: (r["client"], order.get(r["risk"], 9), r["host"]))
        write_reports(all_rows, a.output)
        print(f"Report written{note}: {a.output}.csv / {a.output}.xlsx")

    done = 0
    try:
        for client, domain in targets:
            print(f"Checking {client} ({domain}) ...", flush=True)
            rows, found = check_domain(client, domain, a.max_hosts)
            all_rows += rows
            done += 1
            summary = {k: sum(1 for r in rows if r["risk"] == k) for k in order}
            print(f"  {found} names found, {len(rows)} live hosts. {summary}")
            save(" (progress saved)") if done < len(targets) else None
    except KeyboardInterrupt:
        print(f"\nStopped by user after {done} of {len(targets)} websites.")
        save(" with partial results")
        return
    save()


if __name__ == "__main__":
    main()
