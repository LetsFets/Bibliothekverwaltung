"""Regression tests for the exact failure reported on GitHub Actions."""
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock
from types import SimpleNamespace
ROOT=Path(__file__).resolve().parents[3]
sys.path.insert(0,str(ROOT/'.github/devsecops'))
import web_scan
import scan

class Tests(unittest.TestCase):
    def test_selftest_does_not_read_broken_app_config(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            (root/'.github/devsecops/zap-selftest-site').mkdir(parents=True)
            (root/'.github/devsecops/app.json').write_text('{ this is NOT json }')
            cfg=web_scan.read_config(root, selftest=True)
            self.assertEqual(cfg['services'][0]['install'], '')
            self.assertIn('39991',cfg['target_url'])
            self.assertEqual(cfg['services'][0]['directory'],'.github/devsecops/zap-selftest-site')

    def test_required_database_variable_fail_fast(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            (root/'.github/devsecops').mkdir(parents=True)
            (root/'.github/devsecops/app.json').write_text(json.dumps({
                'target_url':'http://127.0.0.1:3000/',
                'services':[{'name':'next', 'directory':'.', 'start':'auto', 'install':'auto',
                             'ready_url':'http://127.0.0.1:3000/', 'required_env':['DATABASE_URL']}] }))
            with mock.patch.dict(os.environ, {'DATABASE_URL':''}):
                result=web_scan.execute(root,root/'reports','baseline')
            self.assertEqual(result['status'],'ERROR')
            self.assertIn('DATABASE_URL', result['message'])
            self.assertFalse((root/'reports/next-install.log').exists())

    def test_http_500_rejected_early(self):
        server=SimpleNamespace(poll=lambda:None)
        with mock.patch.object(web_scan,'probe_status', side_effect=[200,500,500,500]):
            with mock.patch.object(web_scan.time,'sleep'):
                ok,reason=web_scan.await_ready('http://127.0.0.1:3000/',server,timeout=30)
        self.assertFalse(ok)
        self.assertIn('HTTP 500',reason)

    def test_three_stable_200_required(self):
        server=SimpleNamespace(poll=lambda:None)
        with mock.patch.object(web_scan,'probe_status', side_effect=[200,500,200,200,200]):
            with mock.patch.object(web_scan.time,'sleep'):
                ok,reason=web_scan.await_ready('http://127.0.0.1:3000/',server,timeout=30)
        self.assertTrue(ok)
        self.assertIn('dreimal',reason)

    def test_zap_job_is_not_called_in_static_only(self):
        with tempfile.TemporaryDirectory() as d:
            out=Path(d)
            with mock.patch.object(scan,'scan_one',return_value={'tool':'x','status':'OK','count':0,'examples':[]}), \
                 mock.patch.object(scan,'web_execute',side_effect=AssertionError('ZAP MUST NOT RUN')):
                code=scan.execute_scans([('.',ROOT)],out,False,'baseline',static_only=True)
            self.assertEqual(code,0)
            self.assertIn('separater GitHub-Job',(out/'summary.md').read_text())

    def test_workflow_runs_project_by_default_selftest_optional(self):
        import yaml
        data=yaml.load((ROOT/'.github/workflows/security-scan.yml').read_text(),Loader=yaml.BaseLoader)
        jobs=data['jobs']
        self.assertEqual(set(jobs),{'discover','code-security','zap-selftest','zap-project'})
        self.assertIn('inputs.selftest',jobs['zap-selftest']['if'])
        self.assertNotIn('if',jobs['zap-project'])
        self.assertIn('fromJSON',jobs['zap-project']['strategy']['matrix'])

    def test_selftest_only_uses_baseline(self):
        workflow=(ROOT/'.github/workflows/security-scan.yml').read_text()
        self.assertIn('--target selftest',workflow)
        self.assertIn('--mode baseline',workflow)
        self.assertNotIn('setup-node',str(__import__('yaml').load(workflow,Loader=__import__('yaml').BaseLoader)['jobs']['zap-selftest']))

if __name__=='__main__': unittest.main()
