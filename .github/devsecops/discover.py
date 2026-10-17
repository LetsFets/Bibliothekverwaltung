#!/usr/bin/env python3
import argparse
import json
import os
from pathlib import Path
from profiles import discover, detect

if __name__ == '__main__':
    cli=argparse.ArgumentParser()
    cli.add_argument('--projects',default='auto')
    args=cli.parse_args()
    root=Path.cwd()
    entries=[{'path':p.relative_to(root).as_posix(), 'id':str(i), 'profile':detect(p) or 'custom'}
             for i,p in enumerate(discover(root,args.projects),1)]
    matrix=json.dumps({'include':entries})
    print(matrix)
    if os.environ.get('GITHUB_OUTPUT'):
        with open(os.environ['GITHUB_OUTPUT'],'a') as f:f.write('matrix='+matrix+'\n')
