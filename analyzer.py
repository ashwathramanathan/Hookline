"""URL analysis for Hookline: lexical, domain-structure and TLS checks."""
import ipaddress, re, socket, ssl, time
from urllib.parse import urlparse

SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
              "rebrand.ly", "cutt.ly", "shorturl.at", "tiny.cc", "rb.gy"}
RISKY_TLDS = {"zip", "mov", "xyz", "top", "click", "country", "gq", "tk", "ml", "cf",
              "ga", "work", "support", "loan", "rest", "icu", "cam", "monster"}
KEYWORDS = ["login", "signin", "verify", "secure", "account", "update", "confirm",
            "banking", "password", "wallet", "invoice", "suspend", "unlock", "billing"]
BRANDS = {"paypal": "paypal.com", "apple": "apple.com", "microsoft": "microsoft.com",
          "google": "google.com", "amazon": "amazon.com", "netflix": "netflix.com",
          "facebook": "facebook.com", "instagram": "instagram.com", "linkedin": "linkedin.com",
          "dropbox": "dropbox.com", "coinbase": "coinbase.com", "binance": "binance.com",
          "chase": "chase.com", "wellsfargo": "wellsfargo.com", "dhl": "dhl.com"}
TWO_PART_SUFFIXES = {"co.uk", "org.uk", "com.au", "co.in", "co.jp", "com.br", "co.nz", "com.mx"}
TOTAL_CHECKS = 14


def split_host(host):
    parts = host.split(".")
    n = 3 if len(parts) >= 3 and ".".join(parts[-2:]) in TWO_PART_SUFFIXES else 2
    return ".".join(parts[-n:]), parts[:-n]


def check_certificate(host, port=443):
    """Open a TLS connection and read the certificate. Returns (info, problem)."""
    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        return None, "The domain does not resolve."
    if not all(ipaddress.ip_address(i[4][0]).is_global for i in infos):
        return None, "Skipped: the host points to a private address."
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=4) as s:
            with ctx.wrap_socket(s, server_hostname=host) as t:
                cert, version = t.getpeercert(), t.version()
    except ssl.SSLCertVerificationError as e:
        return None, f"Certificate failed verification: {e.verify_message}."
    except (OSError, ssl.SSLError):
        return None, "Could not complete a secure connection."
    issuer = dict(x[0] for x in cert.get("issuer", ()))
    start, end = ssl.cert_time_to_seconds(cert["notBefore"]), ssl.cert_time_to_seconds(cert["notAfter"])
    return {"issuer": issuer.get("organizationName") or issuer.get("commonName", "Unknown"),
            "age_days": int((time.time() - start) // 86400),
            "days_left": int((end - time.time()) // 86400), "protocol": version}, None


def analyze(raw, live=True):
    raw = raw.strip()
    assumed = "://" not in raw
    url = ("https://" + raw) if assumed else raw
    p = urlparse(url)
    host = (p.hostname or "").lower()
    if not host or " " in raw:
        raise ValueError("That doesn't look like a URL.")
    try:
        port = p.port
    except ValueError:
        raise ValueError("The port in that URL isn't valid.")

    found, add = [], lambda t, d, pts: found.append({"title": t, "detail": d, "points": pts})
    try:
        ipaddress.ip_address(host); is_ip = True
    except ValueError:
        is_ip = False
    reg, subs = split_host(host) if not is_ip else (host, [])
    tld = host.rsplit(".", 1)[-1]
    low = url.lower()

    if p.scheme != "https":
        add("No HTTPS", "The page is served without encryption.", 15)
    if is_ip:
        add("IP address as host", "Legitimate sites almost always use a domain name.", 30)
    if "@" in (p.netloc or ""):
        add("@ in the address", "Everything before the @ is ignored by browsers and can hide the real host.", 20)
    if "xn--" in host or not host.isascii():
        add("Look-alike characters", "The domain uses punycode or non-ASCII letters that can imitate a known name.", 25)
    if tld in RISKY_TLDS:
        add(f"Uncommon ending (.{tld})", "This ending is heavily used in throwaway domains.", 12)
    if host in SHORTENERS:
        add("Link shortener", "The real destination is hidden behind a redirect.", 15)
    if len(subs) >= 3:
        add("Deep subdomain nesting", f"{len(subs)} subdomain levels before {reg}.", 12)
    elif len(subs) == 2:
        add("Extra subdomains", f"Two subdomain levels before {reg}.", 5)
    if host.count("-") >= 2:
        add("Hyphens in the domain", f"{host.count('-')} hyphens, common in made-up names.", 8)
    if len(url) > 120:
        add("Very long URL", f"{len(url)} characters.", 14)
    elif len(url) > 75:
        add("Long URL", f"{len(url)} characters.", 8)
    hits = [k for k in KEYWORDS if k in low]
    if hits:
        add("Account-related words", "Found: " + ", ".join(hits[:5]) + ".", min(6 * len(hits), 18))
    for brand, real in BRANDS.items():
        if brand in host and reg != real and not is_ip:
            add(f"Imitates {brand.capitalize()}", f"The name appears in the host, but the site belongs to {reg}, not {real}.", 30)
            break
    if port not in (None, 80, 443):
        add("Unusual port", f"Connects on port {port}.", 10)
    if low.count("%") >= 3 or "//" in (p.path or ""):
        add("Obscured path", "Heavy percent-encoding or a double slash in the path.", 8)
    if sum(c.isdigit() for c in host) >= 5 and not is_ip:
        add("Many digits in the domain", "Auto-generated domains tend to contain long number runs.", 8)

    cert, note = None, None
    if live and not is_ip and p.scheme == "https":
        cert, problem = check_certificate(host, port or 443)
        if problem and problem.startswith(("Certificate failed", "Could not")):
            add("Certificate problem", problem, 25)
        elif problem:
            note = problem
        elif cert["age_days"] < 14:
            add("Brand-new certificate", f"Issued {cert['age_days']} days ago.", 10)
    elif live:
        note = "Certificate check needs an https address with a domain name."

    score = min(sum(f["points"] for f in found), 100)
    verdict = "Looks fine" if score < 25 else "Suspicious" if score < 55 else "Likely phishing"
    return {"url": url, "host": host, "assumed_https": assumed, "score": score, "verdict": verdict,
            "findings": sorted(found, key=lambda f: -f["points"]), "checked": TOTAL_CHECKS,
            "cert": cert, "cert_note": note}
