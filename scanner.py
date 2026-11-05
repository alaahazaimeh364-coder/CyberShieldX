
import urllib.request
import urllib.error
import ssl
import socket
import ipaddress
from urllib.parse import urlparse


def validate_website(url):
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    try:
        parsed = urlparse(url)

        if parsed.scheme not in ("http", "https"):
            return None, "Unsupported protocol"

        if not parsed.hostname:
            return None, "Invalid website address"

        if parsed.username or parsed.password:
            return None, "Invalid website address"

        if parsed.port not in (None, 80, 443):
            return None, "Port not allowed"

        host = parsed.hostname.lower()

        if host == "localhost" or host.endswith(
            (".localhost", ".local")
        ):
            return None, "Local addresses are not allowed"

        addresses = socket.getaddrinfo(
            host, None, socket.AF_UNSPEC
        )

        if not addresses:
            return None, "Website address not found"

        for address in addresses:
            ip = ipaddress.ip_address(address[4][0])

            if not ip.is_global:
                return None, "Private or unsafe IP address"

        return parsed, None

    except Exception:
        return None, "Invalid or unreachable website"


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def scan_website(url):
    results = []

    parsed, error = validate_website(url)

    if error:
        return {"error": error}

    results.append({
        "check": "HTTPS",
        "status": "PASS" if parsed.scheme == "https" else "WARNING",
        "details": "HTTPS connection" if parsed.scheme == "https"
        else "Website does not use HTTPS"
    })

    try:
        context = ssl.create_default_context()

        opener = urllib.request.build_opener(
            NoRedirect,
            urllib.request.HTTPSHandler(context=context)
        )

        request = urllib.request.Request(
            parsed.geturl(),
            headers={"User-Agent": "CyberShieldX/1.0"}
        )

        response = opener.open(request, timeout=8)

        headers = response.headers

        security_headers = [
            "Strict-Transport-Security",
            "Content-Security-Policy",
            "X-Content-Type-Options",
            "X-Frame-Options",
            "Referrer-Policy"
        ]

        for header in security_headers:
            results.append({
                "check": header,
                "status": "PASS" if headers.get(header) else "WARNING",
                "details": "Present" if headers.get(header) else "Missing"
            })

        cookies = headers.get_all("Set-Cookie") or []

        for cookie in cookies:
            results.append({
                "check": "Cookie Security",
                "status": "INFO",
                "details": (
                    "Secure: " + str("secure" in cookie.lower()) +
                    " | HttpOnly: " + str("httponly" in cookie.lower()) +
                    " | SameSite: " + str("samesite" in cookie.lower())
                )
            })

        response.close()

    except Exception as error:
        return {"error": "Could not scan website: " + str(error)}

    return results
