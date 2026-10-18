"""Adapter and lifecycle regressions for all 3 supplied repository shapes."""
import errno
import json
from pathlib import Path
import os
import sys
import tempfile
import unittest
from unittest import mock
from types import SimpleNamespace

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import runtime, profiles, project_scan


def fixture(root, name):
    root.mkdir(parents=True)
    deps = {'express':'5','sql.js':'1'} if name=='library' else {'next':'15','better-auth':'1'}
    (root/'package.json').write_text(json.dumps({'dependencies':deps}))
    if name=='library':
        (root/'frontend').mkdir(); (root/'frontend/package.json').write_text('{}')
    else:
        (root/'src/db').mkdir(parents=True); (root/'src/db/schema.ts').write_text('export {};')
        marker=root/('src/app/api/flatmates/route.ts' if name=='flatmate' else 'src/lib/sqlite-entries.ts')
        marker.parent.mkdir(parents=True);marker.write_text('export {};')


class Adapters(unittest.TestCase):
    def test_auto_discovers_three_without_nested_frontend(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            for name in ('library','flatmate','entertainment'):fixture(root/name,name)
            paths=profiles.discover(root)
            self.assertEqual(len(paths),3)
            self.assertEqual({profiles.detect(p) for p in paths},{'library','flatmate','entertainment'})

    def test_copy_never_includes_env_database_or_symlink(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);src=root/'src';src.mkdir()
            for name in ('.env','.env.local','data.sqlite','package.json'):(src/name).write_text('test')
            (src/'escape').symlink_to('/etc/passwd')
            profiles.copy_project(src,root/'out')
            self.assertEqual({p.name for p in (root/'out').iterdir()},{'package.json'})

    def test_project_profiles_are_isolated(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            for name in ('library','flatmate','entertainment'):
                conf=profiles.configuration(root,name,root)
                self.assertEqual(conf['_profile'],name)
                if name=='library':
                    self.assertEqual(len(conf['services']),2)
                    self.assertEqual(conf['targets'][1]['input_queries'][0]['param'],'title')
                else:
                    self.assertEqual(conf['services'][0]['env']['DATABASE_URL'],'file:'+str(root/'test.sqlite'))
                    self.assertIn('--config=devsecops.drizzle.config.ts',conf['services'][0]['setup'])
                if name=='flatmate':
                    self.assertIn('/api/tasks',conf['targets'][0]['protected_routes'])

    def test_escape_path_fails(self):
        with tempfile.TemporaryDirectory() as td:
            with self.assertRaises(ValueError):profiles.discover(Path(td),'../')

    def test_npm_and_pnpm_scripts(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);(root/'package.json').write_text('{"dependencies":{"next":"15"}}')
            self.assertEqual(runtime.auto_start(root,root,'http://127.0.0.1:3000/','npm')[:4],['npm','exec','--','next'])
            (root/'pnpm-lock.yaml').write_text("lockfileVersion: '9.0'\n")
            self.assertEqual(runtime.package_info(root,root)[0],'pnpm')
            self.assertEqual(runtime.installed_command('pnpm',None,root),['pnpm','install','--frozen-lockfile'])

    def test_reject_mixed_lockfiles(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);(root/'pnpm-lock.yaml').write_text('')
            (root/'package-lock.json').write_text('{}')
            with self.assertRaises(ValueError):runtime.package_info(root,root)

    def test_loopback_only(self):
        for url in ('https://localhost:3000/','http://example.com:3000/','http://localhost/',
                    'http://localhost:3000/#bad','http://user:pass@localhost:3000/'):
            with self.subTest(url=url),self.assertRaises(ValueError):runtime.local_url(url)
        self.assertEqual(runtime.local_url('http://localhost:3000/'),'http://localhost:3000/')

    def test_selftest_does_not_parse_app_json(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); (root/'.github/devsecops').mkdir(parents=True)
            (root/'.github/devsecops/app.json').write_text('bad JSON')
            self.assertIn('39991',runtime.read_config(root,True)['target_url'])

    def test_process_group_killed_even_if_launcher_exited(self):
        proc=SimpleNamespace(pid=123456, wait=lambda **kw:None)
        with mock.patch.object(runtime.os,'killpg') as kill, mock.patch.object(runtime.time,'sleep'):
            runtime.stop_process_group(proc)
        self.assertEqual(kill.call_count,2)

    def test_cleanup_retry(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); folder=root/'copy';folder.mkdir();report=root/'report';report.mkdir()
            actual=project_scan.shutil.rmtree
            calls=[]
            def flaky(path):
                calls.append(1)
                if len(calls)==1: raise OSError(errno.ENOTEMPTY,'busy')
                actual(path)
            with mock.patch.object(project_scan.shutil,'rmtree',side_effect=flaky),mock.patch.object(project_scan.time,'sleep'):
                project_scan.remove_runtime(folder,report)
            self.assertFalse(folder.exists())
            self.assertEqual(len(calls),2)

    def test_persistent_cleanup_warning_no_failure(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);folder=root/'app';folder.mkdir();report=root/'report';report.mkdir()
            with mock.patch.object(project_scan.shutil,'rmtree',side_effect=OSError(errno.ENOTEMPTY,'busy')),\
                 mock.patch.object(project_scan.time,'sleep'):
                project_scan.remove_runtime(folder,report)
            self.assertIn('nicht vollständig', (report/'cleanup-warning.txt').read_text())

    def test_all_profiles_generate_project_summary(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            for name in ('library','flatmate','entertainment'):
                project=root/name;fixture(project,name)
                (project/'.env').write_text('test_token=should-not-be-copied')
                out=root/(name+'-out')
                def fake_execute(copy, output, config=None, selftest=False):
                    self.assertEqual(config['_profile'],name)
                    self.assertFalse((copy/'.env').exists())
                    (output/'coverage.json').write_text(json.dumps({'preflight':[], 'authentication':'Testnutzer'}))
                    return {'tool':'dalfox','status':'FINDINGS','count':1, 'verified':1,
                            'candidates':1,'scanned':1,'skipped':0,'requests':42,
                            'by_type':{'V':1,'A':0,'R':0,'I':0},
                            'findings':[{'type':'V','param':'q','risk':'Hoch',
                            'target':'http://localhost:3000/','evidence':'Reflected XSS detected'}],
                            'tested':[], 'tested_urls':['http://localhost:3000/?q=test']}
                with mock.patch.object(sys,'argv',['script','--project',name,'--output',str(out)]),\
                     mock.patch('pathlib.Path.cwd',return_value=root),\
                     mock.patch.object(project_scan,'execute',side_effect=fake_execute):
                    self.assertEqual(project_scan.main(),0)
                self.assertIn(name,(out/'summary.md').read_text())
                self.assertIn('Reflected XSS',(out/'summary.md').read_text())
                self.assertNotIn('should-not-be-copied',(out/'summary.md').read_text())

if __name__=='__main__':unittest.main()
