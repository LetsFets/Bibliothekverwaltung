"""Prove the real installed Dalfox scanned the reflected-XSS fixture."""
import json
import sys
from pathlib import Path

if __name__ == '__main__':
    report = json.loads(Path(sys.argv[1]).read_text(encoding='utf-8'))
    assert report.get('tool') == 'dalfox', 'Wrong scanner'
    assert report.get('status') == 'FINDINGS', 'Fixture XSS must produce findings'
    assert report.get('scanned',0) >= 1 and report.get('requests',0) > 0, 'No actual Dalfox HTTP scan'
    assert any(f.get('type') in ('V','R') and f.get('param') == 'q'
               for f in report.get('findings',[])), 'Reflected q parameter not detected'
    print(f'DALFOX SELBSTTEST OK: {report["requests"]} Scanner-Requests; '
          f'{report["count"]} erwartete Befunde')
