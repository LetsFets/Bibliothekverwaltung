"""Additional V5.1 regression tests, including a real local webserver."""
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
from types import SimpleNamespace

ROOT=Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / '.github' / 'devsecops'))
import web_scan


class PackageAutoDetection(unittest.TestCase):
    def test_pnpm_lock_without_package_manager(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            (root / 'package.json').write_text('{"scripts":{"dev":"next dev"},"dependencies":{"next":"15.0.0"}}')
            (root / 'pnpm-lock.yaml').write_text("lockfileVersion: '9.0'\n")
            pm, spec, lockdir=web_scan.package_info(root, root)
            self.assertEqual(pm, 'pnpm')
            self.assertIsNone(spec)
            self.assertEqual(web_scan.installed_command(pm, spec, lockdir), ['pnpm','install','--frozen-lockfile'])
            self.assertEqual(web_scan.auto_start(root,root,'http://127.0.0.1:3000/',pm),
                             ['pnpm','exec','next','dev','--hostname','127.0.0.1','--port','3000'])

    def test_pnpm_workspace_nested(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d); nested=root/'frontend'; nested.mkdir()
            (root/'pnpm-lock.yaml').write_text("lockfileVersion: '9.0'\n")
            (root/'package.json').write_text('{"packageManager":"pnpm@9.15.9"}')
            (nested/'package.json').write_text('{"dependencies":{"vite":"6.0.0"}}')
            pm, spec, lockdir=web_scan.package_info(root,nested)
            self.assertEqual((pm,spec,lockdir),('pnpm','pnpm@9.15.9',root))
            self.assertEqual(web_scan.auto_start(root,nested,'http://127.0.0.1:5173/',pm),
                             ['pnpm','exec','vite','--host','127.0.0.1','--port','5173','--strictPort'])

    def test_npm_and_yarn(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            (root/'package.json').write_text('{}')
            (root/'package-lock.json').write_text('{}')
            pm, spec, p=web_scan.package_info(root,root)
            self.assertEqual(web_scan.installed_command(pm,spec,p)[:2],['npm','ci'])
            (root/'package-lock.json').unlink()
            (root/'yarn.lock').write_text('')
            pm,spec,p=web_scan.package_info(root,root)
            self.assertEqual(web_scan.installed_command(pm,spec,p),['yarn','install','--frozen-lockfile'])

    def test_mixed_lockfiles_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            (root/'pnpm-lock.yaml').write_text('')
            (root/'package-lock.json').write_text('')
            with self.assertRaisesRegex(ValueError,'Lockfile'):
                web_scan.package_info(root,root)

    def test_selftest_local_webserver_and_mocked_docker(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            (root/'.github/devsecops/zap-selftest-site').mkdir(parents=True)
            (root/'.github/devsecops/zap-selftest-site/index.html').write_text('<html><body>Hi</body></html>')
            dest=root/'reports'
            def fake_docker(argv, **kwargs):
                if argv[1]=='rm':return SimpleNamespace(returncode=0)
                stage=Path(next(x for x in argv if x.endswith(':/zap/wrk/:rw')).split(':/zap/wrk/')[0])
                self.assertIn('--network',argv)
                self.assertIn('host',argv)
                self.assertIn('zap-baseline.py',argv)
                (stage/'zap.json').write_text(json.dumps({'site':[{'alerts':[{'alertRef':'10020','instances':[{}]}]}]}))
                return SimpleNamespace(returncode=2)
            with patch.object(web_scan.subprocess, 'run', side_effect=fake_docker):
                result=web_scan.execute(root,dest,'baseline',selftest=True)
            self.assertEqual(result['status'],'FINDINGS',result)
            self.assertEqual(result['count'],1)
            self.assertEqual(result['target'],'selftest')
            self.assertTrue((dest/'zap-selftest-server.log').exists())
            self.assertTrue((dest/'zap-zap-run.log').exists())

if __name__=='__main__':unittest.main()
