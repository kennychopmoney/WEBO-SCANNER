# WebAudit

WebAudit is a small, dependency-free Python command-line utility for a limited,
passive review of a website you are authorized to assess. It resolves the
target's IP address, makes one bounded HTTP `GET` request, reviews common
security headers and technology-disclosure headers, records basic TLS
certificate details for HTTPS, and creates a readable HTML report.

## Requirements

- Python 3.10 or later
- Network access to the supplied host

## Run

```powershell
python .\web_audit.py https://your-site.example --output .\report.html
```

The command writes both `web-audit-report.html` and
`web-audit-report.json` by default. Override either output path with
`--output` or `--json-output`, for example:

```powershell
python .\web_audit.py https://your-site.example --output .\report.html --json-output .\report.json
```

Open the HTML report in a browser or use the JSON file for integrations and
further analysis. Use `--help` to see command options.

## Local web interface

Start the browser-based interface, which listens only on your own computer:

```powershell
python .\web_ui.py
```

Open `http://127.0.0.1:8765/`, submit an authorized website URL, review the
results, and use the separate **Download HTML report** and **Download JSON
report** links. Choose a different local port with `--port`, for example
`python .\web_ui.py --port 8766`. Stop the interface with Ctrl+C. The most
recent report stays available only while the local server is running.

## Scope and limitations

- Use only on sites you own or have explicit permission to assess.
- The browser interface binds to `127.0.0.1` and uses a per-server form token;
  it is not intended to be exposed to a network.
- The tool makes one `GET` request to the exact URL. It does not follow
  redirects, crawl pages, submit forms, authenticate, or change server state.
- It contacts only the web-service port specified by the URL (or the default
  HTTP/HTTPS port). It does not scan other ports.
- SQL injection is not tested: no payloads are sent. The report only flags
  certain database-error text if it happens to appear in the fetched response;
  that signal may be a false positive.
- A missing header or a disclosed version is a configuration observation,
  not proof of an exploitable vulnerability. This is not a penetration test
  and does not establish that a site is secure.
- At most 1 MB of response content is inspected, and the request times out
  after 10 seconds.

## Tests

```powershell
python -m unittest .\test_web_audit.py
python -m unittest .\test_web_ui.py
```
