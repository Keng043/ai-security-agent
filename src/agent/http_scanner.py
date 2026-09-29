from urllib.request import Request, urlopen
from urllib.parse import urlparse

from .models import Finding

REQUIRED_HEADERS = {
    "content-security-policy": ("Content-Security-Policy", "medium", "Add a restrictive Content-Security-Policy."),
    "x-content-type-options": ("X-Content-Type-Options", "low", "Set X-Content-Type-Options: nosniff."),
    "x-frame-options": ("X-Frame-Options", "low", "Set X-Frame-Options or use frame-ancestors in CSP."),
}


def scan_http(url: str, timeout: float = 5.0) -> tuple[dict, list[Finding]]:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("target must be an HTTP or HTTPS URL")

    request = Request(url, method="GET", headers={"User-Agent": "AI-Security-Agent/0.1"})
    with urlopen(request, timeout=timeout) as response:
        headers = {k.lower(): v for k, v in response.headers.items()}
        body = response.read(0)
        metadata = {"url": response.geturl(), "status": response.status, "headers": dict(response.headers)}

    findings: list[Finding] = []
    for key, (header_name, severity, recommendation) in REQUIRED_HEADERS.items():
        if key not in headers:
            findings.append(Finding("http_headers", f"Missing {header_name}", severity, f"{header_name} was not present in the response.", recommendation))

    if parsed.scheme == "https" and "strict-transport-security" not in headers:
        findings.append(Finding("http_headers", "Missing Strict-Transport-Security", "medium", "HTTPS response did not include Strict-Transport-Security.", "Add HSTS with an appropriate max-age after confirming HTTPS is enforced."))

    return metadata, findings
