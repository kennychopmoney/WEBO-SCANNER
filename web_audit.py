#!/usr/bin/env python3
"""A small, passive website configuration checker for authorized assessments."""

from __future__ import annotations

import argparse
import html
import ipaddress
import json
import socket
import ssl
import sys
from datetime import datetime, timezone
from http.client import HTTPConnection, HTTPSConnection, HTTPResponse
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

MAX_RESPONSE_BYTES = 1_000_000
TIMEOUT_SECONDS = 10
SQL_ERROR_MARKERS = (
    "you have an error in your sql syntax",
    "sqlstate[",
    "uncaught sql exception",
    "odbc sql",
    "mysql_fetch",
    "postgresql query failed",
    "sqlite3.operationalerror",
    "ora-00933",
)


def normalize_headers(headers: Any) -> dict[str, str]:
    items = headers.items() if hasattr(headers, "items") else headers
    normalized: dict[str, str] = {}
    for key, value in items:
        name = str(key).lower()
        text = str(value).strip()
        normalized[name] = f"{normalized[name]}, {text}" if name in normalized else text
    return normalized


def add_finding(
    findings: list[dict[str, str]], severity: str, title: str, detail: str
) -> None:
    findings.append(
        {"severity": severity, "title": title, "detail": detail}
    )


def analyze_response(
    headers: dict[str, str], scheme: str, body: bytes
) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []

    checks = [
        (
            "content-security-policy",
            "MEDIUM",
            "Content-Security-Policy is missing",
            "Set a Content-Security-Policy suited to the site's resources to reduce "
            "the impact of content injection.",
        ),
        (
            "x-content-type-options",
            "LOW",
            "X-Content-Type-Options is missing",
            "Set X-Content-Type-Options: nosniff to prevent MIME-type sniffing.",
        ),
        (
            "referrer-policy",
            "LOW",
            "Referrer-Policy is missing",
            "Set a Referrer-Policy that avoids leaking sensitive URL details.",
        ),
        (
            "permissions-policy",
            "INFO",
            "Permissions-Policy is missing",
            "Consider restricting browser features the site does not need.",
        ),
    ]
    for header, severity, title, detail in checks:
        if not headers.get(header):
            add_finding(findings, severity, title, detail)

    csp = headers.get("content-security-policy", "").lower()
    if not headers.get("x-frame-options") and "frame-ancestors" not in csp:
        add_finding(
            findings,
            "LOW",
            "Clickjacking protection is not apparent",
            "Set X-Frame-Options or a Content-Security-Policy frame-ancestors "
            "directive if the site should not be embedded.",
        )

    if scheme == "https" and not headers.get("strict-transport-security"):
        add_finding(
            findings,
            "MEDIUM",
            "Strict-Transport-Security is missing",
            "After confirming HTTPS works across the site, consider enabling HSTS "
            "with an appropriate max-age.",
        )

    server = headers.get("server")
    if server:
        add_finding(
            findings,
            "LOW",
            "Web server header is exposed",
            f"The Server header discloses: {server}",
        )
    powered_by = headers.get("x-powered-by")
    if powered_by:
        add_finding(
            findings,
            "LOW",
            "Technology header is exposed",
            f"The X-Powered-By header discloses: {powered_by}",
        )

    body_text = body.decode("utf-8", errors="replace").lower()
    matched_markers = [marker for marker in SQL_ERROR_MARKERS if marker in body_text]
    if matched_markers:
        add_finding(
            findings,
            "MEDIUM",
            "Possible database error details in response",
            "The fetched page contains text resembling a database error. This is "
            "passive evidence only; it does not establish SQL injection. Review "
            "the response and keep detailed errors out of public pages.",
        )

    if not findings:
        add_finding(
            findings,
            "INFO",
            "No issues detected by these checks",
            "This limited passive scan is not a full security assessment.",
        )
    return findings


def resolve_addresses(host: str, port: int) -> list[str]:
    results = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    addresses = sorted({str(result[4][0]) for result in results})
    return addresses


def get_tls_details(connection: HTTPSConnection) -> dict[str, str]:
    sock = connection.sock
    if sock is None:
        return {}
    details: dict[str, str] = {}
    version = sock.version()
    if version:
        details["protocol"] = version
    certificate = sock.getpeercert()
    if certificate.get("notAfter"):
        details["expires"] = certificate["notAfter"]
    issuer = certificate.get("issuer")
    if issuer:
        details["issuer"] = ", ".join(
            f"{key}={value}" for group in issuer for key, value in group
        )
    return details


def read_limited(response: HTTPResponse) -> tuple[bytes, bool]:
    body = response.read(MAX_RESPONSE_BYTES + 1)
    truncated = len(body) > MAX_RESPONSE_BYTES
    return body[:MAX_RESPONSE_BYTES], truncated


def scan_url(url: str) -> dict[str, Any]:
    parsed = urlsplit(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("Provide a complete http:// or https:// URL.")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("URLs containing embedded credentials are not supported.")

    scheme = parsed.scheme
    host = parsed.hostname
    port = parsed.port or (443 if scheme == "https" else 80)
    target = parsed.path or "/"
    if parsed.query:
        target += f"?{parsed.query}"

    addresses = resolve_addresses(host, port)
    connection_type = HTTPSConnection if scheme == "https" else HTTPConnection
    connection_kwargs: dict[str, Any] = {"timeout": TIMEOUT_SECONDS}
    if scheme == "https":
        connection_kwargs["context"] = ssl.create_default_context()
    connection = connection_type(host, port, **connection_kwargs)
    try:
        connection.request(
            "GET",
            target,
            headers={
                "User-Agent": "WebAudit/1.0 (passive configuration check)",
                "Accept": "text/html,application/xhtml+xml,*/*;q=0.1",
                "Connection": "close",
            },
        )
        response = connection.getresponse()
        body, truncated = read_limited(response)
        headers = normalize_headers(response.getheaders())
        tls = get_tls_details(connection) if scheme == "https" else {}
        findings = analyze_response(headers, scheme, body)
        return {
            "url": url,
            "host": host,
            "port": port,
            "scheme": scheme,
            "resolved_ips": addresses,
            "scanned_at": datetime.now(timezone.utc).isoformat(),
            "http_status": response.status,
            "http_reason": response.reason,
            "headers": dict(sorted(headers.items())),
            "tls": tls,
            "response_truncated": truncated,
            "findings": findings,
            "notes": [
                "Only one GET request was sent to the supplied URL; redirects were not followed.",
                "No crawling, form submissions, authentication attempts, or SQL payloads were used.",
                "Only the URL's web-service port was contacted; no other ports were scanned.",
                "SQL injection was not tested. Database-error text checks are passive and may be false positives.",
            ],
        }
    finally:
        connection.close()


def escape(value: Any) -> str:
    return html.escape(str(value), quote=True)


def render_report(result: dict[str, Any]) -> str:
    findings = "".join(
        "<tr>"
        f"<td><span class='severity {escape(item['severity'].lower())}'>"
        f"{escape(item['severity'])}</span></td>"
        f"<td>{escape(item['title'])}</td><td>{escape(item['detail'])}</td>"
        "</tr>"
        for item in result["findings"]
    )
    headers = "".join(
        f"<tr><th>{escape(key)}</th><td>{escape(value)}</td></tr>"
        for key, value in result["headers"].items()
    )
    tls = "".join(
        f"<tr><th>{escape(key)}</th><td>{escape(value)}</td></tr>"
        for key, value in result["tls"].items()
    ) or "<tr><td colspan='2'>Not applicable or unavailable</td></tr>"
    notes = "".join(f"<li>{escape(note)}</li>" for note in result["notes"])
    ips = ", ".join(result["resolved_ips"])
    truncated_note = (
        "<p class='notice'>The response body exceeded the 1 MB inspection limit "
        "and was truncated.</p>"
        if result["response_truncated"]
        else ""
    )
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Website Assessment - {escape(result['host'])}</title>
<style>
body{{font:16px/1.5 system-ui,sans-serif;max-width:1000px;margin:2rem auto;padding:0 1rem;color:#17212b}}
h1,h2{{line-height:1.2}} table{{width:100%;border-collapse:collapse;margin:1rem 0 2rem}}
th,td{{text-align:left;padding:.65rem;border:1px solid #d5dce2;vertical-align:top;overflow-wrap:anywhere}}
th{{background:#f2f5f7}} .severity{{font-weight:700}} .critical{{color:#a40000}}
.high{{color:#b54708}} .medium{{color:#8a6100}} .low{{color:#245b9e}}
.info{{color:#52616b}} .notice{{background:#fff4d6;padding:.8rem}}
.muted{{color:#52616b}}
</style>
</head>
<body>
<h1>Website Assessment Report</h1>
<p><strong>Target:</strong> {escape(result['url'])}<br>
<strong>Scanned:</strong> {escape(result['scanned_at'])}<br>
<strong>HTTP response:</strong> {escape(result['http_status'])} {escape(result['http_reason'])}<br>
<strong>Resolved IP address(es):</strong> {escape(ips)}<br>
<strong>Endpoint port:</strong> {escape(result['port'])} (other ports were not scanned)</p>
{truncated_note}
<h2>Findings</h2>
<table><thead><tr><th>Severity</th><th>Check</th><th>Details / recommendation</th></tr></thead>
<tbody>{findings}</tbody></table>
<h2>Response headers</h2>
<table><tbody>{headers or '<tr><td>No headers received</td></tr>'}</tbody></table>
<h2>TLS</h2>
<table><tbody>{tls}</tbody></table>
<h2>Scope and limitations</h2>
<ul>{notes}</ul>
<p class="muted">This report reflects a limited, point-in-time passive check. It is not proof that a site is secure or vulnerable.</p>
</body>
</html>
"""


def render_json_report(result: dict[str, Any]) -> str:
    return json.dumps(result, indent=2, ensure_ascii=False) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Passively check HTTP security headers, DNS, TLS and error disclosure."
    )
    parser.add_argument("url", help="Single http:// or https:// URL you are authorized to assess")
    parser.add_argument(
        "-o",
        "--output",
        default="web-audit-report.html",
        help="HTML report output path (default: web-audit-report.html)",
    )
    parser.add_argument(
        "--json-output",
        default="web-audit-report.json",
        help="JSON report output path (default: web-audit-report.json)",
    )
    args = parser.parse_args(argv)
    try:
        if Path(args.output).resolve() == Path(args.json_output).resolve():
            raise ValueError("HTML and JSON reports must use different output paths.")
        result = scan_url(args.url)
        Path(args.output).write_text(render_report(result), encoding="utf-8")
        Path(args.json_output).write_text(render_json_report(result), encoding="utf-8")
    except (OSError, ValueError, socket.error, ssl.SSLError) as exc:
        print(f"Scan failed: {exc}", file=sys.stderr)
        return 1

    print(f"HTTP {result['http_status']} from {result['host']}:{result['port']}")
    print(f"Resolved IPs: {', '.join(result['resolved_ips'])}")
    print(f"Findings: {len(result['findings'])}")
    print(f"HTML report: {Path(args.output).resolve()}")
    print(f"JSON report: {Path(args.json_output).resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
