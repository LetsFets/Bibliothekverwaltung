#!/usr/bin/env python3
"""Run one detected application from a disposable copy, not from the checkout."""
import argparse
import json
import os
from pathlib import Path
import tempfile
from profiles import copy_project, detect, configuration
from web_scan import execute


def main():
    cli=argparse.ArgumentParser()
    cli.add_argument('--project',default='.')
    cli.add_argument('--mode',choices=['baseline','full'],default='baseline')
    cli.add_argument('--enforce',choices=['true','false'],default='false')
    cli.add_argument('--output',type=Path,required=True)
    args=cli.parse_args()
    source=(Path.cwd()/args.project).resolve()
    if not source.is_relative_to(Path.cwd().resolve()):cli.error('Projekt außerhalb des Repositorys')
    if args.mode=='full' and os.environ.get('GITHUB_ACTIONS')=='true' and os.environ.get('GITHUB_EVENT_NAME')!='workflow_dispatch':
        cli.error('Full Scan nur manuell')
    output=args.output.resolve(); output.mkdir(parents=True,exist_ok=True)
    try:
        profile=detect(source)
        with tempfile.TemporaryDirectory(prefix='devsecops-app-') as tmp:
            runtime=Path(tmp); copy=runtime/'app'; copy_project(source,copy)
            conf=configuration(copy,profile,runtime) if profile else None
            if not profile:
                pipeline=Path(__file__).parent
                (copy/'.github/devsecops').mkdir(parents=True,exist_ok=True)
                (copy/'.github/devsecops/app.json').write_bytes((pipeline/'app.json').read_bytes())
            result=execute(copy,output,args.mode,config=conf)
            result['profile']=profile or 'custom'
    except Exception as exc:
        result={'status':'ERROR','count':None,'message':str(exc),'profile':'unknown'}
    (output/'summary.json').write_text(json.dumps(result,indent=2,ensure_ascii=False)+'\n')
    summary=f"## ZAP: {args.project}\n\nProfil: {result['profile']}\n\nStatus: **{result['status']}**\n\n{result.get('message','')}\n\n"
    summary+='Details: `coverage.json`, `*-zap.html`, `*-zap.json` und Service-Logs im Artefakt.\n'
    (output/'summary.md').write_text(summary)
    print(summary)
    if os.environ.get('GITHUB_STEP_SUMMARY'):
        with open(os.environ['GITHUB_STEP_SUMMARY'],'a') as f:f.write(summary)
    return 2 if result['status']=='ERROR' else int(args.enforce=='true' and result['status']=='FINDINGS')

if __name__=='__main__':raise SystemExit(main())
