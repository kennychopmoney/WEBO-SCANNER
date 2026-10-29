import re
import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from web_ui import create_server


class WebUiTests(unittest.TestCase):
    def setUp(self):
        self.server = create_server(0)
        self.thread = threading.Thread(target=self.server.serve_forever)
        self.thread.start()
        self.base_url = f"http://127.0.0.1:{self.server.server_port}"

    def tearDown(self):
        self.server.shutdown()
        self.thread.join()
        self.server.server_close()

    def test_scanner_page_is_local_and_protected(self):
        self.assertEqual(self.server.server_address[0], "127.0.0.1")
        with urlopen(self.base_url) as response:
            page = response.read().decode("utf-8")
            self.assertEqual(response.status, 200)
            self.assertEqual(response.headers["Content-Security-Policy"].split(";")[0], "default-src 'none'")
        self.assertIn('action="/scan"', page)
        self.assertRegex(page, r'name="csrf_token" value="[A-Za-z0-9_-]+"')

    def test_scan_requires_form_token(self):
        request = Request(
            f"{self.base_url}/scan",
            data=urlencode({"url": "http://127.0.0.1/"}).encode(),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            method="POST",
        )
        with self.assertRaises(HTTPError) as error:
            urlopen(request)
        self.assertEqual(error.exception.code, 403)

    def test_scan_shows_report_and_supports_download(self):
        requested = []

        class TargetHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                requested.append(self.path)
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(b"<html>local test</html>")

            def log_message(self, format, *args):
                pass

        target = HTTPServer(("127.0.0.1", 0), TargetHandler)
        target_thread = threading.Thread(target=target.serve_forever)
        target_thread.start()
        try:
            with urlopen(self.base_url) as response:
                page = response.read().decode("utf-8")
            token = re.search(r'name="csrf_token" value="([^"]+)"', page).group(1)
            target_url = f"http://127.0.0.1:{target.server_port}/"
            request = Request(
                f"{self.base_url}/scan",
                data=urlencode({"url": target_url, "csrf_token": token}).encode(),
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                method="POST",
            )
            with urlopen(request) as response:
                report_page = response.read().decode("utf-8")
                self.assertEqual(response.status, 200)
            self.assertIn("Website Assessment Report", report_page)
            self.assertIn("Download HTML report", report_page)
            self.assertIn("Download JSON report", report_page)
            report_path = re.search(
                r"""href=['"](/report/[A-Za-z0-9_-]+)['"]""", report_page
            ).group(1)
            with urlopen(self.base_url + report_path) as response:
                downloaded = response.read().decode("utf-8")
                self.assertIn("attachment;", response.headers["Content-Disposition"])
            self.assertIn("Website Assessment Report", downloaded)
            json_path = re.search(
                r"""href=['"](/report/[A-Za-z0-9_-]+\.json)['"]""", report_page
            ).group(1)
            with urlopen(self.base_url + json_path) as response:
                json_report = json.loads(response.read().decode("utf-8"))
                self.assertEqual(
                    response.headers.get_content_type(), "application/json"
                )
                self.assertIn("attachment;", response.headers["Content-Disposition"])
            self.assertEqual(json_report["http_status"], 200)
            self.assertEqual(json_report["url"], target_url)
            self.assertEqual(requested, ["/"])
        finally:
            target.shutdown()
            target_thread.join()
            target.server_close()


if __name__ == "__main__":
    unittest.main()
