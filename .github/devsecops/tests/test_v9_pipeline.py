"""Workflow, aggregation, reporting and static scanner tests (Dalfox v3)."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / '.github/devsecops'))
import aggregate, runtime, scan, reporting


class Pipeline(unittest.TestCase):
    def test_three_static_scanners(self):
        self.assertEqual(scan.TOOLS, ('semgrep', 'gitleaks', 'trivy'))

    def test_static_tools_read_only_source(self):
        for tool in scan.TOOLS:
            args = scan.docker_args(tool, ROOT, Path('/tmp/reports'))
            self.assertIn('docker', args[0])
            self.assertIn(':ro', ' '.join(args))
            self.assertIn('--user', args)
            self.assertIn('/out:rw', ' '.join(args))

    def test_gitleaks_redaction(self):
        self.assertIn('--redact', scan.docker_args('gitleaks', ROOT, Path('/tmp/reports')))

    def test_trivy_cache(self):
        args = scan.docker_args('trivy', ROOT, Path('/tmp/reports'))
        self.assertIn('--cache-dir', args)
        self.assertIn('/cache:rw', ' '.join(args))

    def test_select_invalid_path(self):
        with self.assertRaises(ValueError):
            scan.select_projects(ROOT, '../')

    def test_findings_parser(self):
        for tool, report in [('semgrep', {'results': [{}]}), ('gitleaks', [{}]),
                             ('trivy', {'Results': [{'Vulnerabilities': [{}]}]})]:
            self.assertEqual(scan.parse_findings(tool, report)[0], 1)

    def test_static_only_report_mentions_dalfox_job(self):
        with tempfile.TemporaryDirectory() as td:
            with mock.patch.object(scan, 'scan_one', side_effect=lambda tool, *args: {
                     'tool': tool, 'count': 0, 'status': 'OK', 'examples': []}):
                self.assertEqual(scan.execute_scans([('.', ROOT)], Path(td), False), 0)
            obj = json.loads((Path(td) / 'summary.json').read_text())
            self.assertEqual(obj['dalfox']['status'], 'SKIPPED')
            self.assertEqual(obj['dalfox']['tool'], 'dalfox')
            self.assertIn('separater GitHub-Job', (Path(td) / 'summary.md').read_text())

    def test_workflow_valid_all_five_jobs(self):
        import yaml
        flow = yaml.load((ROOT / '.github/workflows/security-scan.yml').read_text(),
                         Loader=yaml.BaseLoader)
        self.assertEqual(set(flow['jobs']), {'discover', 'code-security', 'dalfox-project',
                                             'dalfox-selftest', 'security-summary'})
        self.assertEqual(set(flow['on']), {'push','pull_request','workflow_dispatch'})
        self.assertNotIn('if', flow['jobs']['dalfox-project'])
        self.assertIn('fromJSON', str(flow['jobs']['dalfox-project']['strategy']['matrix']))
        self.assertEqual(flow['jobs']['security-summary']['if'], 'always()')
        self.assertIn('dalfox-project', flow['jobs']['security-summary']['needs'])
        self.assertIn('verify_selftest.py', str(flow['jobs']['dalfox-selftest']))
        self.assertIn('install_dalfox.sh', str(flow['jobs']['dalfox-selftest']))
        self.assertNotIn('setup-node', str(flow['jobs']['dalfox-selftest']))

    def test_no_old_scanner(self):
        flow = (ROOT / '.github/workflows/security-scan.yml').read_text().lower()
        self.assertNotIn('owasp zap', flow)
        self.assertNotIn('http-security', flow)
        self.assertIn('dalfox', flow)

    def test_dalfox_summary_visible(self):
        result = {'project': 'library', 'profile': 'library', 'status': 'FINDINGS',
                  'count': 1, 'candidates': 2, 'scanned': 1, 'skipped': 1,
                  'verified': 1, 'requests': 55, 'by_type': {'V': 1},
                  'findings': [{'type': 'V', 'risk': 'Hoch', 'param': 'q',
                                'target': 'http://localhost:5000/', 'evidence': 'DOM XSS'}],
                  'tested': [{'url':'http://localhost:5000/?q=security-test',
                              'status':'SCANNED', 'http':200, 'requests':55},
                             {'url':'http://localhost:5000/books?title=security-test',
                              'status':'SKIP', 'reason':'JSON'}]}
        with tempfile.TemporaryDirectory() as td:
            md = reporting.dalfox_markdown(result, Path(td))
        self.assertIn('Dalfox XSS-Scan', md)
        self.assertIn('DOM XSS', md)
        self.assertIn('55', md)
        self.assertIn('SKIP', md)

    def test_aggregate_three_projects_missing_report_is_error(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            matrix = {'include':[{'path':name,'id':str(i),'profile':name}
                      for i,name in enumerate(('library','flatmate','entertainment'),1)]}
            for i,name in enumerate(('library','flatmate','entertainment'),1):
                static = root/f'v9-static-{i}-42'; static.mkdir()
                dalfox = root/f'v9-dalfox-{i}-42'; dalfox.mkdir()
                (static/'summary.json').write_text(json.dumps({'projects':[{'scans':[
                    {'tool':tool,'status':'FINDINGS' if tool=='gitleaks' else 'OK',
                     'count':i if tool=='gitleaks' else 0}
                    for tool in ('semgrep','gitleaks','trivy')]}]}))
                (dalfox/'summary.json').write_text(json.dumps({'tool':'dalfox','status':'OK',
                   'count':0, 'candidates':1, 'scanned':1, 'requests':123, 'verified':0}))
            rows = aggregate.collect(root,matrix)
            md,incomplete = aggregate.markdown(rows,False)
            self.assertFalse(incomplete)
            for name in ('library','flatmate','entertainment'):
                self.assertIn(name,md)
            self.assertIn('Dalfox XSS',md)
            self.assertIn('123',md)
            (root/'v9-dalfox-2-42/summary.json').unlink()
            md,incomplete = aggregate.markdown(aggregate.collect(root,matrix),False)
            self.assertTrue(incomplete)
            self.assertIn('❌ Bericht fehlt',md)

    def test_workflow_artifacts_matching_paths(self):
        import yaml
        flow = yaml.load((ROOT/'.github/workflows/security-scan.yml').read_text(),
                         Loader=yaml.BaseLoader)
        steps = flow['jobs']['dalfox-project']['steps']
        step = next(x for x in steps if x.get('name','').startswith('Dalfox-Reports'))
        self.assertIn('devsecops-dalfox/',step['with']['path'])
        self.assertIn('v9-dalfox-',step['with']['name'])

    def test_aggregate_empty_matrix_is_error(self):
        md,incomplete=aggregate.markdown([],False)
        self.assertTrue(incomplete)
        self.assertIn('Keine Projekte erkannt',md)

if __name__ == '__main__':
    unittest.main()
