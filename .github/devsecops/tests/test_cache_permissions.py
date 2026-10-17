"""Cache placement must not depend on output path depth or root privileges."""
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import scan


class CachePermissions(unittest.TestCase):
    def test_shallow_output_and_no_filesystem_side_effects(self):
        with mock.patch.object(Path, 'mkdir', side_effect=AssertionError('unexpected mkdir')):
            args = scan.docker_args('trivy', scan.ROOT, Path('/tmp/testing-output'))
        self.assertIn('/tmp/testing-output/.devsecops-trivy-cache:/cache:rw', args)
        self.assertNotIn('/.devsecops-trivy-cache:/cache:rw', args)

    def test_relative_output_cache_is_absolute(self):
        args = scan.docker_args('trivy', scan.ROOT, Path('reports'))
        self.assertIn(f'{Path("reports").resolve()}/.devsecops-trivy-cache:/cache:rw', args)

    def test_scan_prepares_writable_cache_before_docker(self):
        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp) / 'out'

            def run(*args, **kwargs):
                cache = dest / '.devsecops-trivy-cache'
                (cache / 'write-probe').write_text('ok')
                (dest / 'trivy.json').write_text('{"SchemaVersion": 2, "ArtifactType": "filesystem", "Results": []}')
                return mock.Mock(returncode=0, stdout='', stderr='')

            with mock.patch.object(scan.subprocess, 'run', side_effect=run):
                result = scan.scan_one('trivy', scan.ROOT, dest)
            self.assertEqual(result['status'], 'OK')

    def test_cache_failure_is_reported_without_running_docker(self):
        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp)
            (dest / '.devsecops-trivy-cache').write_text('blocks directory creation')
            with mock.patch.object(scan.subprocess, 'run') as run:
                result = scan.scan_one('trivy', scan.ROOT, dest)
            run.assert_not_called()
            self.assertEqual(result['status'], 'ERROR')
            self.assertTrue((dest / 'trivy.error.txt').is_file())
