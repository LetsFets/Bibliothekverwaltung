#!/usr/bin/env python3
"""Combine matrix-job artifacts into a grading-friendly all-project overview."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

NAMES = {'semgrep':'Semgrep', 'gitleaks':'Gitleaks', 'trivy':'Trivy'}
STATE = {'OK':'✅ 0', 'FINDINGS':'⚠️', 'ERROR':'❌ Fehler', 'SKIPPED':'➖'}


def escape(value):
    return str(value).replace('|', '\\|').replace('\n',' ').replace('`', "'")


def result_state(scan):
    if scan is None:
        return '❌ Fehlender Bericht'
    status = scan.get('status','ERROR')
    if status in ('OK','FINDINGS'):
        return ('✅ ' if status == 'OK' else '⚠️ ') + str(scan.get('count',0))
    return STATE.get(status, '❌ Fehler')


def read_json(path):
    try:
        return json.loads(path.read_text(encoding='utf-8'))
    except (ValueError, OSError):
        return None


def collect(directory: Path, matrix: dict):
    report_dirs = [p for p in directory.iterdir() if p.is_dir()] if directory.is_dir() else []
    results=[]
    entries=matrix.get('include', []) if isinstance(matrix,dict) else []
    for item in entries:
        ident=str(item.get('id',''))
        project=item.get('path','?')
        static_dir=next((p for p in report_dirs if p.name.startswith('v7-static-'+ident+'-')),None)
        zap_dir=next((p for p in report_dirs if p.name.startswith('v7-zap-'+ident+'-')),None)
        static=read_json(static_dir/'summary.json') if static_dir else None
        zap=read_json(zap_dir/'summary.json') if zap_dir else None
        scans = ((static.get('projects') or [{}])[0].get('scans') or []) if isinstance(static,dict) else []
        by_tool={s.get('tool'):s for s in scans if isinstance(s,dict)}
        results.append({'name':project,'profile':item.get('profile','custom'),
                        'static':by_tool,'zap':zap,'artifacts':{'static':static_dir.name if static_dir else None,
                        'zap':zap_dir.name if zap_dir else None}})
    return results


def markdown(rows, enforce: bool, workflow_state: str=''):
    unfinished = not rows or any(any(row['static'].get(tool) is None or
                        row['static'][tool].get('status') == 'ERROR' for tool in NAMES)
                        or row['zap'] is None or row['zap'].get('status') == 'ERROR' for row in rows)
    found = any(any((row['static'].get(tool) or {}).get('status')=='FINDINGS' for tool in NAMES)
                or (row['zap'] or {}).get('status')=='FINDINGS' for row in rows)
    headline = ('❌ Unvollständig – mindestens ein Scan fehlt oder ist fehlgeschlagen' if unfinished else
                ('⚠️ Abgeschlossen mit Sicherheitsfunden' if found else '✅ Alle Scanner technisch abgeschlossen'))
    lines = ['# 🛡️ DevSecOps · Gesamtauswertung', '',
             '**'+headline+'**', '',
             f'**Projekte:** {len(rows)} · **Auswertung:** '
             + ('Enforce (Findings blockieren)' if enforce else 'Report-only (Findings melden)')
             + (f' · **Vorjobs:** {escape(workflow_state)}' if workflow_state else ''), '',
             '## Alle Projekte auf einen Blick', '',
             '| Projekt | Profil | Semgrep | Gitleaks | Trivy | OWASP ZAP |',
             '|:--|:--|--:|--:|--:|--:|']
    for row in rows:
        cells = [escape(row['name']),escape(row['profile'])] + [
            result_state(row['static'].get(tool)) for tool in NAMES]
        cells.append(result_state(row['zap']))
        lines.append('| '+' | '.join(cells)+' |')
    if not rows:
        lines += ['', '**Keine Projektmatrix gefunden.** Siehe Job `Projekte erkennen`.']
    lines += ['', '## Findings je Anwendung', '']
    for row in rows:
        lines += [f'### {escape(row["name"])}', '',
                  '| Art | Anzahl | Hinweise |', '|:--|--:|:--|']
        for tool in NAMES:
            item=row['static'].get(tool)
            lines.append('| '+NAMES[tool]+' | '+(
                str(item.get('count')) if item and item.get('count') is not None else '–')+' | '+
                (escape(', '.join(map(str,item.get('examples',[])))[:120]) if item else 'Bericht fehlt')+' |')
        zap=row['zap']
        lines.append('| OWASP ZAP | '+(str(zap.get('count')) if zap and zap.get('count') is not None else '–')+
                     ' | '+(escape(zap.get('message','')) if zap else 'Bericht fehlt')+' |')
        if zap and zap.get('risks'):
            lines += ['', 'ZAP-Risiken: '+', '.join(f'**{risk}: {zap["risks"].get(risk,0)}**'
                for risk in ('Hoch','Mittel','Niedrig','Informativ'))+'.']
        lines += ['', '**Report-Dateien:** '+', '.join('`'+escape(name)+'`' for name in
                  row['artifacts'].values() if name) if any(row['artifacts'].values()) else
                  '**Report-Dateien:** Es wurde kein Artefakt gefunden.', '']
    lines += ['## Bewertungsmaßstab', '',
              '- **✅ 0:** Scanner wurde erfolgreich durchgeführt, ohne erkannte Funde.',
              '- **⚠️ N:** Scanner wurde ausgeführt und hat N Funde gemeldet.',
              '- **❌ Fehler:** Scanner / Webstart / Abdeckungsprüfung technisch fehlgeschlagen.',
              '- **❌ Fehlender Bericht:** Der Matrix-Job hat keinen auswertbaren Report bereitgestellt.',
              '', 'Wichtig: Zahlen verschiedener Scanner lassen sich **nicht** als identische Risiken addieren.',
              'ZAP-Baseline führt passive Sicherheitsprüfungen durch; aktive DAST-Prüfungen nur bei `full`.',
              'Ein grüner technischer Scan ist kein Nachweis vollständiger Sicherheit.', '',
              '*Details einschließlich HTML-/JSON-Berichten unter Actions → Artifacts.*', '']
    return '\n'.join(lines), unfinished


def main():
    cli=argparse.ArgumentParser()
    cli.add_argument('--input',type=Path,required=True)
    cli.add_argument('--output',type=Path,required=True)
    cli.add_argument('--matrix',default='')
    cli.add_argument('--enforce',choices=['true','false'],default='false')
    args=cli.parse_args()
    output=args.output.resolve();output.mkdir(parents=True,exist_ok=True)
    try:
        matrix=json.loads(args.matrix) if args.matrix else {}
    except ValueError:
        matrix={}
    rows=collect(args.input.resolve(),matrix)
    md, incomplete=markdown(rows,args.enforce=='true',os.environ.get('PREVIOUS_JOBS',''))
    (output/'summary.md').write_text(md,encoding='utf-8')
    (output/'summary.json').write_text(json.dumps(rows,indent=2,ensure_ascii=False)+'\n',encoding='utf-8')
    print(md,flush=True)
    if os.environ.get('GITHUB_STEP_SUMMARY'):
        with open(os.environ['GITHUB_STEP_SUMMARY'],'a',encoding='utf-8') as f:
            f.write(md+'\n')
    # A missing result is a technical error, never represented as green.
    if incomplete:
        return 2
    has_findings=any(any((r['static'].get(t) or {}).get('status')=='FINDINGS' for t in NAMES)
                     or (r['zap'] or {}).get('status')=='FINDINGS' for r in rows)
    return int(args.enforce=='true' and has_findings)

if __name__ == '__main__':
    raise SystemExit(main())
