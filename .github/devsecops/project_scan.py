#!/usr/bin/env python3
"""Start isolated application and run the official Dalfox XSS scanner."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import tempfile
import time
from profiles import copy_project, detect, configuration
from runtime import serving
from dalfox_scan import scan
from reporting import dalfox_markdown


def remove_runtime(path: Path, report_dir: Path):
    last_error = None
    for attempt in range(8):
        try:
            shutil.rmtree(path)
            return
        except FileNotFoundError:
            return
        except OSError as exc:
            last_error=exc
            time.sleep(min(.15*(attempt+1),1))
    (report_dir/'cleanup-warning.txt').write_text(
        f'Temporäre Testkopie nach Scan nicht vollständig entfernt: {last_error}\n', encoding='utf-8')
    print(f'[cleanup] WARNUNG: {type(last_error).__name__}; siehe cleanup-warning.txt', flush=True)


def execute(copy: Path, output: Path, config=None, selftest=False):
    from session_setup import prepare, verify
    with serving(copy, output, config=config, selftest=selftest) as conf:
        if not selftest:
            prepare(conf)
        result=scan(conf, output)
        if not selftest:
            verify(conf)
        coverage={'profile':conf.get('_profile','selftest' if selftest else 'custom'),
                  'preflight':conf.get('coverage',[]),
                  'authentication':conf.get('auth_note','anonym'),
                  'seed_notes':conf.get('seed_notes',[]),
                  'tested_urls':result['tested_urls']}
        (output/'coverage.json').write_text(json.dumps(coverage, indent=2, ensure_ascii=False)+'\n',encoding='utf-8')
        return result


def main() -> int:
    cli=argparse.ArgumentParser(description='Dalfox v3 XSS: isolierte lokale Testkopie')
    cli.add_argument('--project',default='.')
    cli.add_argument('--selftest',action='store_true')
    cli.add_argument('--enforce',choices=['true','false'],default='false')
    cli.add_argument('--output',type=Path,required=True)
    args=cli.parse_args()
    output=args.output.resolve();output.mkdir(parents=True,exist_ok=True)
    root=Path.cwd().resolve()
    source=(root/args.project).resolve()
    profile='selftest' if args.selftest else 'unknown'
    runtime=None
    try:
        if args.selftest:
            result=execute(root,output,selftest=True)
        else:
            if not source.is_relative_to(root) or not source.is_dir():
                raise ValueError('Projektordner fehlt oder liegt außerhalb des Repositories')
            profile=detect(source) or 'custom'
            base=Path(os.environ.get('RUNNER_TEMP', tempfile.gettempdir())).resolve()
            base.mkdir(parents=True,exist_ok=True)
            runtime=Path(tempfile.mkdtemp(prefix='devsecops-dalfox-',dir=base))
            copy=runtime/'app'
            copy_project(source,copy)
            conf=configuration(copy,profile,runtime) if profile!='custom' else None
            if profile=='custom':
                folder=copy/'.github/devsecops'
                folder.mkdir(parents=True,exist_ok=True)
                if not (folder/'app.json').exists():
                    (folder/'app.json').write_bytes((Path(__file__).parent/'app.json').read_bytes())
            result=execute(copy,output,config=conf)
    except Exception as exc:
        message=f'{type(exc).__name__}: {exc}'
        (output/'dalfox.error.txt').write_text(message+'\n',encoding='utf-8')
        result={'tool':'dalfox','status':'ERROR','count':None,'message':message[:350],
                'scanned':0,'candidates':0,'skipped':0,'verified':0,'by_type':{},
                'findings':[],'tested':[],'tested_urls':[],'requests':0}
    finally:
        if runtime is not None:
            remove_runtime(runtime,output)
    result['profile']=profile
    result['project']=('selftest' if args.selftest else args.project)
    (output/'summary.json').write_text(json.dumps(result,indent=2,ensure_ascii=False)+'\n',encoding='utf-8')
    summary=dalfox_markdown(result,output,args.enforce=='true')
    (output/'summary.md').write_text(summary,encoding='utf-8')
    print(summary,flush=True)
    if os.environ.get('GITHUB_STEP_SUMMARY'):
        with open(os.environ['GITHUB_STEP_SUMMARY'],'a',encoding='utf-8') as handle:
            handle.write(summary+'\n')
    return 2 if result['status']=='ERROR' else int(args.enforce=='true' and result['status']=='FINDINGS')


if __name__=='__main__':
    raise SystemExit(main())
