#!/usr/bin/env python3
"""Intentionally unsafe LOCAL demo endpoint: never deploy to the Internet."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit, parse_qs


class XSSFixture(BaseHTTPRequestHandler):
    def do_GET(self):
        q = parse_qs(urlsplit(self.path).query).get('q', [''])[0]
        html = '<!doctype html><html><head><title>Dalfox Test</title></head><body><h1>XSS fixture</h1><p>' + q + '</p></body></html>'
        data = html.encode('utf-8')
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *_):
        pass  # scan payloads do not enter public CI logs


if __name__ == '__main__':
    ThreadingHTTPServer(('127.0.0.1', 39991), XSSFixture).serve_forever()
