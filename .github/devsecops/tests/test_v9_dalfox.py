"""Contract tests of Dalfox v3 CLI integration; no pretend live Dalfox binary."""
import json
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import dalfox_scan as d


class Fixture(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass
    def do_GET(self):
        path = self.path.split('?', 1)[0]
        if path == '/login':
            self.send_response(302)
            self.send_header('Location', '/')
            self.end_headers()
            return
        if path == '/json':
            text, mime = '{}', 'application/json'
        else:
            text, mime = '<html><p>security-test</p></html>', 'text/html'
        content = text.encode()
        self.send_response(200)
        self.send_header('Content-Type', mime)
        self.send_header('Content-Length', str(len(content)))
        self.end_headers()
        self.wfile.write(content)


class DalfoxContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(('127.0.0.1', 0), Fixture)
        cls.base = f'http://127.0.0.1:{cls.server.server_port}/'
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def test_real_xss_selftest_fixture_is_intentionally_reflected(self):
        import selftest_xss_server
        from urllib.request import urlopen
        from urllib.parse import quote
        vuln = ThreadingHTTPServer(('127.0.0.1', 0), selftest_xss_server.XSSFixture)
        thread = threading.Thread(target=vuln.serve_forever, daemon=True)
        thread.start()
        try:
            payload = '<svg onload=alert(1)>'
            url = f'http://127.0.0.1:{vuln.server_port}/?q=' + quote(payload)
            with urlopen(url, timeout=3) as response:
                self.assertIn(payload, response.read().decode())
                self.assertEqual(response.headers.get_content_type(), 'text/html')
        finally:
            vuln.shutdown(); vuln.server_close(); thread.join()

    def test_loopback_only_targets(self):
        with self.assertRaises(ValueError):
            d.canonical_target('https://external.invalid:443/', {'path':'/','param':'x'})
        with self.assertRaises(ValueError):
            d.canonical_target(self.base, {'path':'//external.invalid','param':'x'})
        with self.assertRaises(ValueError):
            d.canonical_target(self.base, {'path':'/','param':'cookie=x'})

    def test_query_generation_stable(self):
        url = d.canonical_target(self.base, {'path':'/search?tag=book&q=old','param':'q'})
        self.assertIn('tag=book',url)
        self.assertIn('q=security-test',url)
        self.assertNotIn('q=old',url)

    def test_html_preflight_ready(self):
        p = d.check_target(self.base+'?q=test', {})
        self.assertEqual(p['status'], 'READY')
        self.assertEqual(p['http'], 200)

    def test_json_is_explicitly_skipped(self):
        p = d.check_target(self.base+'json?q=test', {})
        self.assertEqual(p['status'], 'SKIP')
        self.assertEqual(p['content_type'], 'application/json')

    def test_redirect_not_followed(self):
        p = d.check_target(self.base+'login?q=test', {})
        self.assertEqual(p['status'], 'SKIP')
        self.assertEqual(p['http'], 302)

    def test_dalfox_json_envelope_good(self):
        value = {'meta':{'dalfox_version':'3.2.4','target_summary':[{'status':'findings'}],
                         'total_requests':123,'incomplete':False},
                 'findings':[{'type':'V','param':'q','evidence':'verified reflection',
                              'severity':'High','confidence':'high'}]}
        result = d.sanitize_json(value, self.base+'?q=x')
        self.assertEqual(result['requests'],123)
        self.assertEqual(result['findings'][0]['risk'],'Hoch')
        self.assertEqual(result['findings'][0]['target'],self.base)

    def test_no_report_or_incomplete_is_not_clean(self):
        for data in ({'findings':[]},
                     {'findings':[], 'meta':{'target_summary':[], 'total_requests':0}},
                     {'findings':[], 'meta':{'target_summary':[{'status':'incomplete'}],
                                             'total_requests':55}}):
            with self.subTest(data=data), self.assertRaises((ValueError,RuntimeError)):
                d.sanitize_json(data, self.base)

    def test_invalid_findings_rejected(self):
        with self.assertRaises(ValueError):
            d.sanitize_json({'findings':[{'type':'unknown'}],
                             'meta':{'target_summary':[{'status':'clean'}], 'total_requests':50}}, self.base)

    def test_exit_1_is_finding_not_tool_error(self):
        with tempfile.TemporaryDirectory() as td:
            def runner(cmd, **kw):
                self.assertEqual(cmd[1], 'scan')
                self.assertIn('--skip-discovery',cmd)
                self.assertIn('--rate-limit',cmd)
                path = Path(cmd[cmd.index('--output')+1])
                path.write_text(json.dumps({'findings':[{'type':'V','param':'q'}],
                   'meta':{'total_requests':30, 'target_summary':[{'status':'findings'}]}}))
                return SimpleNamespace(returncode=1,stdout='',stderr='')
            with patch.object(d.subprocess, 'run', side_effect=runner):
                result=d.invoke_dalfox(self.base+'?q=test', {}, Path(td), 1)
            self.assertEqual(result['findings'][0]['type'],'V')

    def test_exit_2_is_technical_error(self):
        with tempfile.TemporaryDirectory() as td:
            with patch.object(d.subprocess, 'run', return_value=SimpleNamespace(
                    returncode=2,stdout='',stderr='untrusted output')):
                with self.assertRaises(RuntimeError):
                    d.invoke_dalfox(self.base, {}, Path(td), 1)
            self.assertNotIn('untrusted', (Path(td)/'dalfox-target-01.log').read_text())

    def test_json_without_findings_but_exit1_is_error(self):
        with tempfile.TemporaryDirectory() as td:
            def runner(cmd, **kw):
                Path(cmd[cmd.index('--output')+1]).write_text(json.dumps({
                  'findings':[], 'meta':{'total_requests':10,'target_summary':[{'status':'clean'}]}}))
                return SimpleNamespace(returncode=1,stdout='',stderr='')
            with patch.object(d.subprocess, 'run', side_effect=runner):
                with self.assertRaises(RuntimeError):
                    d.invoke_dalfox(self.base, {}, Path(td), 1)

    def test_cookie_header_not_printed_or_logged(self):
        with tempfile.TemporaryDirectory() as td:
            def runner(cmd, **kw):
                self.assertIn('Cookie: SESSION-SUPER-SECRET',cmd)
                Path(cmd[cmd.index('--output')+1]).write_text(json.dumps({
                  'findings':[], 'meta':{'total_requests':11,'target_summary':[{'status':'clean'}]}}))
                return SimpleNamespace(returncode=0,stdout='',stderr='Cookie: SESSION-SUPER-SECRET')
            with patch.object(d.subprocess, 'run', side_effect=runner):
                result=d.invoke_dalfox(self.base, {'Cookie':'SESSION-SUPER-SECRET'},Path(td),1)
            self.assertEqual(result['requests'],11)
            self.assertNotIn('SUPER-SECRET',(Path(td)/'dalfox-target-01.log').read_text())

    def test_mixed_html_and_json_have_honest_coverage(self):
        with tempfile.TemporaryDirectory() as td:
            def mocked(url, headers, output, idx):
                return {'findings': [], 'requests':44, 'failed_requests':0}
            with patch.object(d, 'invoke_dalfox', side_effect=mocked) as runner:
                results=d.scan({'targets':[{'name':'local','url':self.base,
                    'input_queries':[{'path':'/','param':'q'}, {'path':'/json','param':'q'}]}]}, Path(td))
            self.assertEqual(runner.call_count,1)
            self.assertEqual(results['scanned'],1)
            self.assertEqual(results['skipped'],1)
            self.assertEqual(results['requests'],44)
            self.assertEqual(results['status'],'OK')

    def test_no_html_input_is_not_false_green(self):
        with tempfile.TemporaryDirectory() as td:
            with self.assertRaises(RuntimeError):
                d.scan({'targets':[{'name':'api','url':self.base,
                   'input_queries':[{'path':'/json','param':'q'}]}]},Path(td))

if __name__ == '__main__':
    unittest.main()
