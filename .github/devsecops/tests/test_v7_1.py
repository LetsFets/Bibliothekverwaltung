"""V7.1 regressions for ENOTEMPTY teardown, coverage and report fidelity."""
import errno
import importlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace

ROOT=Path(__file__).resolve().parents[3]
sys.path.insert(0,str(ROOT/'.github/devsecops'))
import project_scan, profiles, reporting, session_setup, web_scan


class RuntimeLifecycle(unittest.TestCase):
    def test_enotempty_retried_after_scan_and_does_not_mark_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'temp'; path.mkdir()
            (path/'next-file').write_text('written by background next process')
            report=Path(tmp)/'reports'; report.mkdir()
            original=project_scan.shutil.rmtree
            calls=[]
            def rmtree(target):
                calls.append(target)
                if len(calls) == 1:
                    raise OSError(errno.ENOTEMPTY,'Directory not empty',str(target))
                return original(target)
            with patch.object(project_scan.shutil, 'rmtree', side_effect=rmtree):
                project_scan.remove_runtime(path,report)
            self.assertEqual(len(calls),2)
            self.assertFalse(path.exists())
            self.assertFalse((report/'cleanup-warning.txt').exists())

    def test_persistent_cleanup_failure_is_warning_not_scan_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'test';path.mkdir()
            report=Path(tmp)/'reports';report.mkdir()
            with patch.object(project_scan.shutil,'rmtree',side_effect=OSError(errno.ENOTEMPTY,'Directory not empty')):
                with patch.object(project_scan.time,'sleep'):
                    project_scan.remove_runtime(path,report)
            self.assertIn('Bereinigung', (report/'cleanup-warning.txt').read_text())
            self.assertTrue(path.exists())

    def test_group_kill_uses_pid_even_after_parent_exits(self):
        process=SimpleNamespace(pid=123456,returncode=0)
        process.wait=lambda **kwargs: 0
        with patch.object(web_scan.os,'killpg',side_effect=[None, None]) as kill, patch.object(web_scan.time,'sleep'):
            web_scan.stop_process_group(process)
        self.assertEqual(kill.call_count,2)
        self.assertEqual(kill.call_args.args[0],process.pid)

    def test_each_profile_runs_on_copy_with_accurate_summary(self):
        with tempfile.TemporaryDirectory() as temp:
            base=Path(temp)
            for kind in ('library','flatmate','entertainment'):
                project=base/kind;project.mkdir()
                (project/'package.json').write_text(json.dumps({'dependencies':
                    {'express':'4','sql.js':'1'} if kind=='library' else {'next':'15','better-auth':'1'}}))
                if kind=='library':
                    (project/'frontend').mkdir();(project/'frontend/package.json').write_text('{}')
                else:
                    (project/'src/db').mkdir(parents=True)
                    (project/'src/db/schema.ts').write_text('export {}')
                    name='src/app/api/flatmates/route.ts' if kind=='flatmate' else 'src/lib/sqlite-entries.ts'
                    f=project/name; f.parent.mkdir(parents=True,exist_ok=True);f.write_text('')
                (project/'.env').write_text('SENSITIVE=should-never-be-copied')
                out=base/(kind+'-results')
                seen=[]
                def fake_execute(copy,output,mode,config=None):
                    seen.append(copy)
                    self.assertFalse((copy/'.env').exists())
                    self.assertEqual(config['_profile'],kind)
                    (output/'coverage.json').write_text(json.dumps({'profile':kind,'authentication':'test session',
                        'preflight':[{'url':'http://127.0.0.1/','status':200}], 'targets':[{'name':'web','url':'http://127.0.0.1:3000/','count':1,'instances':3,'visited':7}]}))
                    return {'tool':'zap','status':'FINDINGS','count':1,'instances':3,'mode':'baseline',
                            'risks':{'Hoch':0,'Mittel':1,'Niedrig':0,'Informativ':0},
                            'top_alerts':[{'id':'10020','name':'Missing Security Header','risk':'Mittel','instances':3}]}
                argv=['project_scan.py','--project',kind,'--mode','baseline','--output',str(out)]
                with patch.object(sys,'argv',argv), patch('pathlib.Path.cwd',return_value=base),\
                    patch.object(project_scan,'execute',side_effect=fake_execute):
                    rc=project_scan.main()
                self.assertEqual(rc,0)
                self.assertEqual(len(seen),1)
                self.assertFalse(seen[0].exists())
                summary=(out/'summary.md').read_text()
                self.assertIn(kind,summary)
                self.assertIn('Missing Security Header',summary)
                self.assertIn('Vorkommen',summary)
                self.assertNotIn('SENSITIVE',summary)


class ZAPReport(unittest.TestCase):
    def fake_container(self, argv, **kwargs):
        if argv[1:3] == ['rm','-f']:
            return SimpleNamespace(returncode=0)
        self.command=argv
        stage=Path(next(x.split(':/zap/wrk/')[0] for x in argv if ':/zap/wrk/' in x))
        (stage/'zap.json').write_text(json.dumps({'site':[{'alerts':[
            {'pluginid':'10020','name':'Missing Header','riskcode':'2','instances':[{},{}]},
            {'pluginid':'40000','name':'Information Disclosure','riskcode':'1','instances':[{}]}
        ]}]}))
        (stage/'hook-coverage.json').write_text(json.dumps({'completed':True,
            'seeded':[{'url':'http://127.0.0.1:3000/','status':200}],
            'visited_urls':['http://127.0.0.1:3000/'], 'ajax_results':2}))
        (stage/'zap.html').write_text('<html></html>')
        return SimpleNamespace(returncode=2)

    def test_full_mode_command_supported_no_baseline_only_flag(self):
        with tempfile.TemporaryDirectory() as td:
            directory=Path(td)
            with patch.object(web_scan,'reachable',return_value=True),patch.object(web_scan.subprocess,'run',side_effect=self.fake_container):
                outcome=web_scan.run_zap({'url':'http://127.0.0.1:3000/','name':'web'},
                                         [{'url':'http://127.0.0.1:3000/'}],directory,'full')
            self.assertIn('zap-full-scan.py',self.command)
            self.assertNotIn('--autooff',self.command)
            self.assertEqual(outcome['count'],2)
            self.assertEqual(outcome['instances'],3)
            self.assertEqual(outcome['risks']['Mittel'],1)
            self.assertEqual(outcome['visited'],1)
            self.assertTrue((directory/'web-zap.json').exists())

    def test_baseline_has_explicit_legacy_hooks_and_ajax(self):
        with tempfile.TemporaryDirectory() as td:
            directory=Path(td)
            with patch.object(web_scan,'reachable',return_value=True),patch.object(web_scan.subprocess,'run',side_effect=self.fake_container):
                web_scan.run_zap({'url':'http://127.0.0.1:3000/','name':'web','ajax':True},
                                 [{'url':'http://127.0.0.1:3000/'}],directory,'baseline')
            self.assertIn('--autooff',self.command)
            self.assertIn('--ajax-spider',self.command)
            self.assertIn('--hook=/zap/private/zap_hooks.py',self.command)

    def test_report_has_no_sensitive_payload_from_alert(self):
        report={'project':'library','profile':'library','status':'FINDINGS','count':2,
                'mode':'baseline','top_alerts':[{'id':'10020','name':'Header','risk':'Niedrig','instances':3}]}
        with tempfile.TemporaryDirectory() as td:
            md=reporting.zap_markdown(report,Path(td))
        self.assertIn('Header',md)
        self.assertIn('Keine bestätigte Scanabdeckung',md)


if __name__ == '__main__':
    unittest.main()


class AggregateDashboard(unittest.TestCase):
    def test_three_projects_appear_and_missing_scan_is_red(self):
        import aggregate
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            matrix={'include':[
                {'path':'library','id':'1','profile':'library'},
                {'path':'flatmate','id':'2','profile':'flatmate'},
                {'path':'entertainment','id':'3','profile':'entertainment'}]}
            for idx,name in enumerate(('library','flatmate','entertainment'),1):
                static=root/f'v7-static-{idx}-12'; static.mkdir()
                zap=root/f'v7-zap-{idx}-12'; zap.mkdir()
                (static/'summary.json').write_text(json.dumps({'projects':[{'project':name,'scans':[
                    {'tool':'semgrep','status':'OK','count':0},
                    {'tool':'gitleaks','status':'FINDINGS','count':idx,'examples':['generic-secret']},
                    {'tool':'trivy','status':'OK','count':0}]}]}))
                (zap/'summary.json').write_text(json.dumps({'profile':name,'status':'OK','count':0,'mode':'baseline'}))
            rows=aggregate.collect(root,matrix)
            md,missing=aggregate.markdown(rows,False)
            self.assertFalse(missing)
            self.assertIn('library',md)
            self.assertIn('flatmate',md)
            self.assertIn('entertainment',md)
            self.assertIn('⚠️ 3',md)
            (root/'v7-zap-2-12'/'summary.json').unlink()
            md,missing=aggregate.markdown(aggregate.collect(root,matrix),False)
            self.assertTrue(missing)
            self.assertIn('❌ Fehlender Bericht',md)

    def test_summary_job_always_runs_after_matrix_and_uses_pin(self):
        import yaml
        flow=yaml.load((ROOT/'.github/workflows/security-scan.yml').read_text(),Loader=yaml.BaseLoader)
        job=flow['jobs']['security-summary']
        self.assertEqual(job['if'],'always()')
        self.assertIn('zap-project',job['needs'])
        self.assertIn('d3f86a106a0bac45b974a628896c90dbdf5c8093',str(job))

