import unittest
import json
import tempfile
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from threading import Thread
from unittest.mock import patch

from web_audit import analyze_response, main, render_json_report, render_report, scan_url


class AnalyzeResponseTests(unittest.TestCase):
    def test_reports_missing_security_headers(self):
        findings = analyze_response({}, "https", b"<html>ok</html>")
        titles = {finding["title"] for finding in findings}
        self.assertIn("Content-Security-Policy is missing", titles)
        self.assertIn("Strict-Transport-Security is missing", titles)

    def test_does_not_claim_sql_injection_from_passive_error_marker(self):
        findings = analyze_response(
            {"content-security-policy": "default-src 'self'"},
            "http",
            b"SQLSTATE[42000]: database error",
        )
        database_finding = next(
            finding for finding in findings
            if finding["title"] == "Possible database error details in response"
        )
        self.assertIn("does not establish SQL injection", database_finding["detail"])

    def test_accepts_frame_ancestors_as_clickjacking_protection(self):
        findings = analyze_response(
            {"content-security-policy": "default-src 'self'; frame-ancestors 'none'"},
            "http",
            b"ok",
        )
        self.assertNotIn(
            "Clickjacking protection is not apparent",
            {finding["title"] for finding in findings},
        )

    def test_report_escapes_untrusted_header_values(self):
        report = render_report(
            {
                "host": "example.test",
                "url": "https://example.test/",
                "scanned_at": "2026-01-01T00:00:00+00:00",
                "http_status": 200,
                "http_reason": "OK",
                "port": 443,
                "resolved_ips": ["192.0.2.1"],
                "headers": {"server": "<script>alert(1)</script>"},
                "tls": {},
                "response_truncated": False,
                "findings": [],
                "notes": ["No crawling."],
            }
        )
        self.assertNotIn("<script>", report)
        self.assertIn("&lt;script&gt;", report)

    def test_json_report_is_valid_and_preserves_structured_data(self):
        result = {
            "url": "https://example.test/",
            "findings": [{"severity": "LOW", "title": "Header", "detail": "Missing"}],
            "resolved_ips": ["192.0.2.1"],
        }
        rendered = render_json_report(result)
        self.assertEqual(json.loads(rendered), result)
        self.assertTrue(rendered.endswith("\n"))

    def test_cli_writes_html_and_json_reports(self):
        result = {
            "url": "http://example.test/",
            "host": "example.test",
            "port": 80,
            "scheme": "http",
            "resolved_ips": ["192.0.2.1"],
            "scanned_at": "2026-01-01T00:00:00+00:00",
            "http_status": 200,
            "http_reason": "OK",
            "headers": {},
            "tls": {},
            "response_truncated": False,
            "findings": [],
            "notes": [],
        }
        with tempfile.TemporaryDirectory() as directory:
            html_path = Path(directory) / "report.html"
            json_path = Path(directory) / "report.json"
            with patch("web_audit.scan_url", return_value=result):
                self.assertEqual(
                    main([
                        result["url"],
                        "--output",
                        str(html_path),
                        "--json-output",
                        str(json_path),
                    ]),
                    0,
                )
            self.assertIn("Website Assessment Report", html_path.read_text(encoding="utf-8"))
            self.assertEqual(json.loads(json_path.read_text(encoding="utf-8")), result)

    def test_cli_rejects_identical_report_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            output_path = Path(directory) / "report"
            with patch("web_audit.scan_url") as scan:
                self.assertEqual(
                    main([
                        "http://example.test/",
                        "--output",
                        str(output_path),
                        "--json-output",
                        str(output_path),
                    ]),
                    1,
                )
            scan.assert_not_called()


class ScanUrlTests(unittest.TestCase):
    def test_scans_only_the_supplied_endpoint_and_records_its_ip(self):
        requests = []

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                requests.append(self.path)
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(b"<html>ok</html>")

            def log_message(self, format, *args):
                pass

        server = HTTPServer(("127.0.0.1", 0), Handler)
        thread = Thread(target=server.serve_forever)
        thread.start()
        try:
            result = scan_url(f"http://127.0.0.1:{server.server_port}/check?mode=passive")
        finally:
            server.shutdown()
            thread.join()
            server.server_close()

        self.assertEqual(result["http_status"], 200)
        self.assertEqual(result["resolved_ips"], ["127.0.0.1"])
        self.assertEqual(requests, ["/check?mode=passive"])


if __name__ == "__main__":
    unittest.main()
