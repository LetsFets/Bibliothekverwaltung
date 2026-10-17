#!/usr/bin/env python3
"""OWASP ZAP scan of a disposable project copy, with race-safe teardown."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import tempfile
import time
from profiles import copy_project, detect, configuration
from web_scan import execute
from reporting import zap_markdown


def remove_runtime(path: Path, report_dir: Path) -> None:
    """Dev servers may briefly create .next files during shutdown.

    Cleanup is not part of the scanner's success criteria. Retries handle the
    Linux ENOTEMPTY race. Runner-local leftovers are recorded for diagnosis.
    """
    last_error = None
    for attempt in range(8):
        try:
            shutil.rmtree(path)
            return
        except FileNotFoundError:
            return
        except OSError as exc:
            last_error = exc
            time.sleep(min(0.15 * (attempt + 1), 1.0))
    msg = (f'Bereinigung nach abgeschlossenem Scan unvollständig: {last_error}. '
           'Temporäre Testkopie liegt nur auf dem kurzlebigen CI-Runner.\n')
    (report_dir / 'cleanup-warning.txt').write_text(msg, encoding='utf-8')
    print('[cleanup] WARNUNG: ' + msg, flush=True)


def main() -> int:
    cli = argparse.ArgumentParser(description='DAST gegen echte isolierte Testkopie')
    cli.add_argument('--project', default='.')
    cli.add_argument('--mode', choices=['baseline', 'full'], default='baseline')
    cli.add_argument('--enforce', choices=['true', 'false'], default='false')
    cli.add_argument('--output', type=Path, required=True)
    args = cli.parse_args()
    source = (Path.cwd() / args.project).resolve()
    if not source.is_relative_to(Path.cwd().resolve()):
        cli.error('Projekt außerhalb des Repositorys')
    if args.mode == 'full' and os.environ.get('GITHUB_ACTIONS') == 'true' and os.environ.get('GITHUB_EVENT_NAME') != 'workflow_dispatch':
        cli.error('Full Scan nur manuell')
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    profile = 'unknown'
    runtime = None
    result = None
    try:
        if not source.is_dir():
            raise FileNotFoundError(f'Projektordner fehlt: {args.project}')
        profile = detect(source) or 'custom'
        # The application MUST be outside the original checkout and report folder.
        base = Path(os.environ.get('RUNNER_TEMP', tempfile.gettempdir())).resolve()
        base.mkdir(parents=True, exist_ok=True)
        runtime = Path(tempfile.mkdtemp(prefix='devsecops-app-', dir=base))
        copy = runtime / 'app'
        copy_project(source, copy)
        if profile == 'custom':
            pipeline = Path(__file__).parent
            (copy / '.github/devsecops').mkdir(parents=True, exist_ok=True)
            (copy / '.github/devsecops/app.json').write_bytes((pipeline / 'app.json').read_bytes())
            conf = None
        else:
            conf = configuration(copy, profile, runtime)
        result = execute(copy, output, args.mode, config=conf)
    except Exception as exc:
        (output / 'zap.error.txt').write_text(str(exc) + '\n', encoding='utf-8')
        result = {'tool': 'zap', 'status': 'ERROR', 'count': None, 'message': str(exc), 'mode': args.mode}
    finally:
        if runtime is not None:
            remove_runtime(runtime, output)

    result['profile'] = profile
    result['project'] = args.project
    (output / 'summary.json').write_text(json.dumps(result, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
    summary = zap_markdown(result, output, args.enforce == 'true')
    (output / 'summary.md').write_text(summary, encoding='utf-8')
    print('\n' + summary, flush=True)
    if os.environ.get('GITHUB_STEP_SUMMARY'):
        with open(os.environ['GITHUB_STEP_SUMMARY'], 'a', encoding='utf-8') as handle:
            handle.write(summary + '\n')
    return 2 if result['status'] == 'ERROR' else int(args.enforce == 'true' and result['status'] == 'FINDINGS')


if __name__ == '__main__':
    raise SystemExit(main())
