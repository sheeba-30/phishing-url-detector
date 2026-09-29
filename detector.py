import ipaddress
import sys
from urllib.parse import urlparse

SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly"}


def inspect_url(value):
    raw = value.strip()
    parsed = urlparse(raw if "://" in raw else f"http://{raw}")
    host = (parsed.hostname or "").lower().rstrip(".")
    signals = []
    if parsed.scheme != "https":
        signals.append("URL does not use HTTPS")
    if "@" in parsed.netloc:
        signals.append("@ in authority can hide the actual destination")
    try:
        ipaddress.ip_address(host)
        signals.append("Host is a raw IP address")
    except ValueError:
        pass
    if host.startswith("xn--") or ".xn--" in host:
        signals.append("Internationalized/punycode hostname")
    if host in SHORTENERS:
        signals.append("URL shortener hides the final destination")
    if parsed.port and parsed.port not in (80, 443):
        signals.append(f"Unusual port: {parsed.port}")
    if len(host.split(".")) > 4:
        signals.append("Many hostname levels")
    if len(raw) > 120:
        signals.append("Unusually long URL")
    return host, signals


if __name__ == "__main__":
    url = " ".join(sys.argv[1:]) or input("URL to inspect: ")
    host, signals = inspect_url(url)
    print(f"Host: {host or '(could not parse)'}")
    if signals:
        print("Review these signals:")
        for signal in signals:
            print(f"- {signal}")
    else:
        print("No basic warning signals found. This does not prove the URL is safe.")
