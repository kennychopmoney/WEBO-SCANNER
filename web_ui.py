#!/usr/bin/env python3
"""Loopback-only web interface for WebAudit."""

from __future__ import annotations

import argparse
import html
import secrets
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

from web_audit import render_json_report, render_report, scan_url

MAX_FORM_BYTES = 4096
MAX_URL_LENGTH = 2048


def create_server(port: int = 8765) -> ThreadingHTTPServer:
    csrf_token = secrets.token_urlsafe(32)
    state_lock = threading.Lock()
    latest_report: dict[str, str] = {}

    class WebAuditHandler(BaseHTTPRequestHandler):
        server_version = "WebAudit"
        sys_version = ""

        def send_html(self, status: int, content: str, *, download: bool = False) -> None:
            body = content.encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
            self.send_header("Cache-Control", "no-store")
            if download:
                self.send_header(
                    "Content-Disposition",
                    'attachment; filename="web-audit-report.html"',
                )
            self.end_headers()
            self.wfile.write(body)

        def send_json_download(self, content: str) -> None:
            body = content.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Cache-Control", "no-store")
            self.send_header(
                "Content-Disposition",
                'attachment; filename="web-audit-report.json"',
            )
            self.end_headers()
            self.wfile.write(body)

        def send_error_page(self, status: int, message: str) -> None:
            self.send_html(
                status,
                "<!doctype html><html lang='en'><meta charset='utf-8'>"
                "<title>WebAudit - Error</title><body>"
                f"<h1>Scan failed</h1><p>{html.escape(message)}</p>"
                "<p><a href='/'>Return to scanner</a></p></body></html>",
            )

        def do_GET(self) -> None:
            path = urlsplit(self.path).path
            if path == "/":
                self.send_html(
                    200,
                    f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>WebAudit</title>
<style>
body{{font:16px/1.5 system-ui,sans-serif;max-width:760px;margin:3rem auto;padding:0 1rem;color:#17212b}}
input,button{{font:inherit;padding:.65rem}}input{{box-sizing:border-box;width:100%;margin:.5rem 0 1rem}}
button{{background:#175ea8;color:white;border:0;border-radius:4px;cursor:pointer}}
.muted{{color:#52616b}}
</style></head><body>
<h1>WebAudit</h1>
<p>Run a limited passive check against a website you own or are authorized to assess.</p>
<form method="post" action="/scan">
<input type="hidden" name="csrf_token" value="{csrf_token}">
<label for="url">Website URL</label>
<input id="url" name="url" type="url" maxlength="{MAX_URL_LENGTH}"
placeholder="https://example.com" required>
<button type="submit">Run passive scan</button>
</form>
<p class="muted">One GET request only. No crawling, SQL payloads, or additional port scans.</p>
</body></html>""",
                )
                return

            prefix = "/report/"
            if path.startswith(prefix):
                report_path = path[len(prefix):]
                download_json = report_path.endswith(".json")
                requested_id = report_path[:-5] if download_json else report_path
                with state_lock:
                    report = (
                        latest_report.get("json" if download_json else "html")
                        if secrets.compare_digest(
                            requested_id, latest_report.get("id", "")
                        )
                        else None
                    )
                if report is None:
                    self.send_error_page(404, "This report is unavailable or has expired.")
                    return
                if download_json:
                    self.send_json_download(report)
                    return
                self.send_html(200, report, download=True)
                return

            self.send_error_page(404, "Page not found.")

        def do_POST(self) -> None:
            if urlsplit(self.path).path != "/scan":
                self.send_error_page(404, "Page not found.")
                return

            try:
                content_length = int(self.headers.get("Content-Length", ""))
            except ValueError:
                self.send_error_page(400, "A valid form request is required.")
                return
            if content_length < 0 or content_length > MAX_FORM_BYTES:
                self.send_error_page(413, "The submitted form is too large.")
                return
            if self.headers.get_content_type() != "application/x-www-form-urlencoded":
                self.send_error_page(415, "Submit the scanner form from this page.")
                return
            form_data = self.rfile.read(content_length)
            try:
                fields = parse_qs(
                    form_data.decode("utf-8", errors="replace"), max_num_fields=4
                )
            except ValueError:
                self.send_error_page(400, "The submitted form contains too many fields.")
                return
            submitted_token = fields.get("csrf_token", [""])[0]
            if not secrets.compare_digest(submitted_token, csrf_token):
                self.send_error_page(403, "The form token is invalid. Reload the scanner and try again.")
                return

            url = fields.get("url", [""])[0].strip()
            if not url or len(url) > MAX_URL_LENGTH:
                self.send_error_page(400, f"Enter a URL no longer than {MAX_URL_LENGTH} characters.")
                return
            try:
                result = scan_url(url)
            except ValueError as exc:
                self.send_error_page(400, str(exc))
                return
            except OSError as exc:
                self.send_error_page(502, f"The website could not be reached: {exc}")
                return

            report_id = secrets.token_urlsafe(24)
            report_html = render_report(result)
            html_download_url = f"/report/{report_id}"
            json_download_url = f"/report/{report_id}.json"
            report_html = report_html.replace(
                "<body>",
                "<body><p><a href='/'>Run another scan</a> | "
                f"<a href='{html_download_url}'>Download HTML report</a> | "
                f"<a href='{json_download_url}'>Download JSON report</a></p>",
                1,
            )
            with state_lock:
                latest_report.clear()
                latest_report.update(
                    {
                        "id": report_id,
                        "html": report_html,
                        "json": render_json_report(result),
                    }
                )
            self.send_html(200, report_html)

        def log_message(self, format: str, *args: object) -> None:
            return

    class LocalhostServer(ThreadingHTTPServer):
        daemon_threads = True
        allow_reuse_address = True

    return LocalhostServer(("127.0.0.1", port), WebAuditHandler)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Start the loopback-only WebAudit interface."
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8765,
        help="Local interface port (default: 8765)",
    )
    args = parser.parse_args()
    if not 0 <= args.port <= 65535:
        parser.error("--port must be between 0 and 65535")

    server = create_server(args.port)
    print(f"WebAudit is available at http://127.0.0.1:{server.server_port}/")
    print("Press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping WebAudit.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
