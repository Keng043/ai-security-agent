from pathlib import Path
import sys
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from agent.http_scanner import scan_http

class FakeResponse:
    status = 200
    headers = {"Content-Type": "text/html"}
    def __enter__(self): return self
    def __exit__(self, *args): return None
    def geturl(self): return "http://127.0.0.1:8080/"
    def read(self, *args): return b""


def test_missing_security_headers_are_reported():
    with patch("agent.http_scanner.urlopen", return_value=FakeResponse()):
        target, findings = scan_http("http://127.0.0.1:8080")
    assert target["status"] == 200
    titles = {item.title for item in findings}
    assert "Missing Content-Security-Policy" in titles
    assert "Missing X-Content-Type-Options" in titles
    assert "Missing X-Frame-Options" in titles


def test_invalid_target_is_rejected():
    try:
        scan_http("ftp://127.0.0.1/file")
    except ValueError as exc:
        assert "HTTP or HTTPS" in str(exc)
    else:
        raise AssertionError("invalid scheme was accepted")
