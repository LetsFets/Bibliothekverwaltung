"""Regression tests for the DevSecOps V5 drop-in pipeline. No Docker required."""
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / '.github' / 'devsecops'))
import web_scan
spec = importlib.util.spec_from_file_location('scan', ROOT / '.github' / 'devsecops' / 'scan.py')
scan = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scan)


class TestStaticPipeline(unittest.TestCase):
    def test_tool_count(self):
        self.assertEqual(scan.TOOLS, ('semgrep', 'gitleaks', 'trivy'))

    def test_docker_as_expected(self):
        for name in scan.TOOLS:
            args = scan.docker_args(name, ROOT, Path('/tmp/testing-output'))
            self.assertIn('docker', args[0])
            self.assertIn(':ro', ' '.join(args))
            self.assertIn('/out:rw', ' '.join(args))
            self.assertIn('--user', args)

    def test_invalid_path(self):
        with self.assertRaises(ValueError):
            scan.select_projects(ROOT, '../')

    def test_select_root_and_example(self):
        result = scan.select_projects(ROOT, '.,.github/devsecops')
        self.assertEqual([r[0] for r in result], ['.', '.github/devsecops'])

    def test_script_report_parser(self):
        self.assertEqual(scan.parse_findings('semgrep', {'results': [{'check_id': 'a'}]})[0], 1)
        self.assertEqual(scan.parse_findings('gitleaks', [{'RuleID': 'r'}])[0], 1)
        self.assertEqual(scan.parse_findings('trivy', {'Results': [{'Vulnerabilities': [{'VulnerabilityID': 'a'}]}]})[0], 1)

    def test_trivy_empty_result(self):
        self.assertEqual(scan.parse_findings('trivy', {'ArtifactType': 'filesystem'})[0], 0)

    def test_trivy_image_cache(self):
        with tempfile.TemporaryDirectory() as td:
            dest = Path(td) / 'reports' / 'web'
            args = scan.docker_args('trivy', ROOT, dest)
            self.assertIn('--cache-dir', args)
            self.assertIn('vuln', args)
            self.assertIn('/cache:rw', ' '.join(args))

    def test_gitleaks_no_plain_report(self):
        self.assertIn('--redact', scan.docker_args('gitleaks', ROOT, Path('/tmp/out')))

    def test_summary_reports_zap(self):
        static = [{'project': '.', 'scans': [
            {'tool': 'semgrep', 'count': 0, 'status': 'OK', 'examples': []},
            {'tool': 'gitleaks', 'count': 2, 'status': 'FINDINGS', 'examples': ['generic-secret']},
            {'tool': 'trivy', 'count': 1, 'status': 'FINDINGS', 'examples': []}]}]
        z = {'tool': 'zap', 'count': 3, 'status': 'FINDINGS', 'examples': ['10020'], 'mode': 'baseline'}
        md = scan.markdown_summary(static, z, False)
        self.assertIn('OWASP ZAP (baseline, project)', md)
        self.assertIn('**Gesamtzahl (ueber verschiedene Kategorien, nicht dedupliziert): 6**', md)

    def test_excludes(self):
        self.assertIn('.git', scan.EXCLUDES)

    def test_demo_exists(self):
        self.assertTrue((ROOT / '.github/devsecops' / 'web_scan.py').exists())

    def test_semgrep_rules(self):
        self.assertIn('eval(...)', (ROOT / '.github/devsecops/semgrep.yml').read_text())

    def test_yaml_syntax(self):
        import yaml
        conf = yaml.load((ROOT / '.github/workflows/security-scan.yml').read_text(), Loader=yaml.BaseLoader)
        self.assertIn('push', conf['on'])
        self.assertIn('pull_request', conf['on'])
        self.assertIn('workflow_dispatch', conf['on'])
        self.assertEqual(set(conf['jobs']), {'discover', 'code-security', 'zap-selftest', 'zap-project'})


class TestZapPipeline(unittest.TestCase):
    def test_reject_external_targets(self):
        for url in ('https://127.0.0.1:3000/', 'http://example.com:3000/',
                    'http://127.0.0.1/', 'http://127.0.0.1:3000/#fragment'):
            with self.subTest(url=url), self.assertRaises(ValueError):
                web_scan.local_url(url)

    def test_local_allowed(self):
        self.assertEqual(web_scan.local_url('http://127.0.0.1:3000/search'),
                         'http://127.0.0.1:3000/search')

    def test_reject_path_escape(self):
        with self.assertRaises(ValueError):
            web_scan.config_path(ROOT, '../../')

    def test_parse_zap(self):
        sample = {'site': [{'alerts': [{'alertRef': '10020', 'instances': [{}, {}]},
                                       {'pluginid': '40012', 'instances': [{}]}]}]}
        self.assertEqual(web_scan.parse_zap(sample), (2, ['10020', '40012'], 3))

    def test_parse_zap_empty_is_not_success(self):
        with self.assertRaises(ValueError):
            web_scan.parse_zap({'site': []})

    def test_config_valid(self):
        conf = web_scan.read_config(ROOT)
        self.assertEqual(conf['target_url'], 'http://127.0.0.1:3000/')

    def test_failed_reports_error_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)
            result = web_scan.failed(path, 'test error')
            self.assertEqual(result['status'], 'ERROR')
            self.assertTrue((path / 'zap.error.txt').exists())

    def test_zap_exit_2_with_report_counts_findings(self):
        # Simulates ZAP container return code 2 (WARN), not a scanner error.
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp)
            (folder / '.github/devsecops').mkdir(parents=True)
            (folder / '.github/devsecops/app.json').write_text(json.dumps({
                'target_url': 'http://127.0.0.1:39021/',
                'services': [{'name': 'web', 'directory': '.', 'install': '',
                              'start': 'python3 -m http.server 39021 --bind 127.0.0.1',
                              'ready_url': 'http://127.0.0.1:39021/', 'env': {}}]}))
            out = folder.parent / (folder.name + '-reports')
            try:
                def fake_subprocess(argv, **kw):
                    if argv[1]=='rm':return mock.Mock(returncode=0)
                    stage=Path(next(x for x in argv if x.endswith(':/zap/wrk/:rw')).split(':/zap/wrk/')[0])
                    (stage / 'hook-coverage.json').write_text(json.dumps({'completed':True,'seeded':[{}]}))
                    (stage / 'zap.json').write_text(json.dumps({'site': [{'alerts': [
                        {'alertRef': '10020', 'instances': [{}]}]}]}))
                    (stage / 'zap.html').write_text('html')
                    return mock.Mock(returncode=2)
                with mock.patch('web_scan.subprocess.run', side_effect=fake_subprocess):
                    result = web_scan.execute(folder, out, 'baseline')
                self.assertEqual(result['status'], 'FINDINGS', result)
                self.assertEqual(result['count'], 1)
            finally:
                import shutil
                shutil.rmtree(out, ignore_errors=True)


if __name__ == '__main__':
    unittest.main()
