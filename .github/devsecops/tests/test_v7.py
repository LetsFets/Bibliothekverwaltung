"""V7 regression tests: project adapters, real HTTP auth, ZAP contract failures."""
import importlib
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch, MagicMock
from types import SimpleNamespace

ROOT=Path(__file__).resolve().parents[3]
sys.path.insert(0,str(ROOT/'.github/devsecops'))
import profiles, web_scan, session_setup, zap_hooks


class Profiles(unittest.TestCase):
    def fixture(self,root,kind):
        (root/'package.json').write_text(json.dumps({'dependencies':{'express':'5','sql.js':'1'} if kind=='library' else {'next':'15','better-auth':'1'}}))
        if kind=='library':
            (root/'frontend').mkdir(); (root/'frontend/package.json').write_text('{}')
        else:
            (root/'src/db').mkdir(parents=True); (root/'src/db/schema.ts').write_text('schema')
            marker=root/('src/app/api/flatmates/route.ts' if kind=='flatmate' else 'src/lib/sqlite-entries.ts')
            marker.parent.mkdir(parents=True); marker.write_text('')

    def test_auto_matrix_all_three_and_no_duplicate_frontend(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            for name in ('library','flatmate','entertainment'):
                p=root/name;p.mkdir();self.fixture(p,name)
            result=profiles.discover(root)
            self.assertEqual(len(result),3)
            self.assertEqual({profiles.detect(p) for p in result},{'library','flatmate','entertainment'})

    def test_no_existing_db_env_or_symlinks_copied(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);src=root/'src';src.mkdir()
            for name in ('.env','.env.local','test.sqlite','package.json'): (src/name).write_text('private')
            (src/'escape').symlink_to('/etc/passwd')
            profiles.copy_project(src,root/'copy')
            self.assertEqual([p.name for p in (root/'copy').iterdir()],['package.json'])

    def test_config_uses_exact_fresh_db_and_both_library_services(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            for name in ('library','flatmate','entertainment'):
                conf=profiles.configuration(root,name,root)
                if name=='library':
                    self.assertEqual(len(conf['services']),2)
                    self.assertEqual(len(conf['targets']),2)
                    self.assertEqual(conf['services'][0]['env']['PORT'],'5000')
                else:
                    self.assertEqual(conf['services'][0]['env']['DATABASE_URL'],'file:'+str(root/'test.sqlite'))
                    self.assertIn('--config=devsecops.drizzle.config.ts',conf['services'][0]['setup'])
                    self.assertIn('process.env.DATABASE_URL',(root/'devsecops.drizzle.config.ts').read_text())

    def test_path_escape_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ValueError):profiles.discover(Path(tmp),'../')

    def test_npm_exec_has_option_separator(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);(root/'package.json').write_text('{"dependencies":{"next":"16"}}')
            self.assertEqual(web_scan.auto_start(root,root,'http://127.0.0.1:3000/','npm')[:4],['npm','exec','--','next'])


class AuthHTTP(unittest.TestCase):
    def test_real_cookie_signup_session_wg_and_redirect(self):
        # Real HTTP + CookieJar, no Node dependencies or ZAP simulated as successful.
        visited=[]
        class App(BaseHTTPRequestHandler):
            def log_message(self,*args):pass
            def reply(self,data,cookie=False):
                self.send_response(200);self.send_header('Content-Type','application/json')
                if cookie:self.send_header('Set-Cookie','better-auth.session_token=test; Path=/; HttpOnly')
                self.end_headers();self.wfile.write(json.dumps(data).encode())
            def do_POST(self):
                data=json.loads(self.rfile.read(int(self.headers['Content-Length'])))
                visited.append((self.path,self.headers.get('Cookie')))
                if self.path.endswith('sign-up/email'):self.reply({'user':{'id':'1'}},True)
                elif self.path in ('/api/flatmates','/api/tasks','/api/shopping'):
                    self.reply({'flatmate':{'id':'wg'}} if self.headers.get('Cookie') else {})
                else:self.send_error(404)
            def do_GET(self):
                visited.append((self.path,self.headers.get('Cookie')))
                if self.path=='/':
                    self.send_response(307);self.send_header('Location','/dashboard');self.end_headers()
                elif self.path.endswith('get-session'):
                    self.reply({'user':{'id':'1'}} if self.headers.get('Cookie') else None)
                else:self.reply({})
        server=ThreadingHTTPServer(('127.0.0.1',3000),App)
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        try:
            conf={'_profile':'flatmate','targets':[{'url':'http://127.0.0.1:3000/','routes':['/','/dashboard','/api/flatmates']}]}
            session_setup.prepare(conf);session_setup.verify(conf)
            self.assertTrue(conf['targets'][0]['headers']['Cookie'])
            self.assertTrue(any(p=='/api/flatmates' and c for p,c in visited))
            self.assertEqual(len(conf['coverage']),3)
        finally:server.shutdown();server.server_close();thread.join()


class ZapContract(unittest.TestCase):
    def fake_run(self,argv,**kwargs):
        if argv[1]=='rm':return SimpleNamespace(returncode=0)
        stage=Path(next(x.split(':/zap/wrk/')[0] for x in argv if ':/zap/wrk/' in x))
        (stage/'zap.json').write_text('{"site":[{"alerts":[]}]}')
        return SimpleNamespace(returncode=0)

    def test_report_without_completed_hook_is_error(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(web_scan,'reachable',return_value=True), patch.object(web_scan.subprocess,'run',side_effect=self.fake_run):
            with self.assertRaises(OSError):
                web_scan.run_zap({'url':'http://127.0.0.1:3000/'},[],Path(tmp),'baseline')

    def test_timeout_removes_container_and_preserves_logs(self):
        calls=[]
        def run(argv,**kwargs):
            calls.append(argv)
            if argv[1]=='run':raise web_scan.subprocess.TimeoutExpired(argv,10)
            return SimpleNamespace(returncode=0)
        with tempfile.TemporaryDirectory() as tmp, patch.object(web_scan,'reachable',return_value=True), patch.object(web_scan.subprocess,'run',side_effect=run):
            with self.assertRaises(web_scan.subprocess.TimeoutExpired):
                web_scan.run_zap({'url':'http://127.0.0.1:3000/'},[],Path(tmp),'baseline')
            self.assertEqual(calls[-1][1:3],['rm','-f'])
            self.assertTrue((Path(tmp)/'zap-zap-run.log').exists())

    def test_hook_rejects_protected_redirect_and_pending_passive_scan(self):
        with tempfile.TemporaryDirectory() as tmp:
            control=Path(tmp)/'control.json';coverage=Path(tmp)/'coverage.json'
            control.write_text(json.dumps({'url':'http://127.0.0.1:3000/','routes':['/dashboard'],'headers':{'Cookie':'test'},'ajax':False}))
            zap=MagicMock();zap.replacer.add_rule.return_value='OK'
            zap.core.access_url.return_value=[{'responseHeader':'HTTP/1.1 307 Temporary Redirect\r\n'}]
            with patch.object(zap_hooks,'CONTROL',control),patch.object(zap_hooks,'COVERAGE',coverage),patch.dict(sys.modules,{'zap_common':SimpleNamespace()}):
                with self.assertRaisesRegex(RuntimeError,'307'):zap_hooks.zap_started(zap,'unused')
                zap.core.access_url.return_value=[{'responseHeader':'HTTP/1.1 200 OK\r\n'}]
                zap_hooks.zap_started(zap,'unused')
                self.assertTrue(coverage.is_file())
                self.assertIn('^http',zap.replacer.add_rule.call_args.kwargs['url'])
                zap.pscan.records_to_scan='4'
                with self.assertRaisesRegex(RuntimeError,'nicht abgeschlossen'):zap_hooks.zap_pre_shutdown(zap)
                self.assertNotIn('completed',json.loads(coverage.read_text()))

if __name__=='__main__':unittest.main()
