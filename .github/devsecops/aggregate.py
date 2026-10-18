#!/usr/bin/env python3
"""Grading-friendly combined report for the four independent security tools."""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path

TOOLS = ('semgrep', 'gitleaks', 'trivy')
LABELS = {'semgrep': 'Semgrep', 'gitleaks': 'Gitleaks', 'trivy': 'Trivy'}


def escape(value):
    return str(value).replace('|', '\\|').replace('`', "'").replace('\n', ' ')


def result_state(scan):
    if scan is None:
        return '❌ Bericht fehlt'
    if scan.get('status') == 'OK':
        return f'✅ {scan.get("count", 0)}'
    if scan.get('status') == 'FINDINGS':
        return f'⚠️ {scan.get("count", 0)}'
    return '❌ Scannerfehler'


def read_json(path):
    try:
        return json.loads(path.read_text(encoding='utf-8'))
    except (OSError, ValueError):
        return None


def collect(directory: Path, matrix: dict):
    candidates = [p for p in directory.iterdir() if p.is_dir()] if directory.is_dir() else []
    rows = []
    for item in matrix.get('include', []) if isinstance(matrix, dict) else []:
        ident = str(item.get('id', ''))
        static_dir = next((p for p in candidates if p.name.startswith('v9-static-' + ident + '-')), None)
        dalfox_dir = next((p for p in candidates if p.name.startswith('v9-dalfox-' + ident + '-')), None)
        static = read_json(static_dir / 'summary.json') if static_dir else None
        dyna = read_json(dalfox_dir / 'summary.json') if dalfox_dir else None
        scans = ((static.get('projects') or [{}])[0].get('scans') or []) if isinstance(static, dict) else []
        rows.append({'name': item.get('path', '?'), 'profile': item.get('profile', 'custom'),
                     'static': {s['tool']: s for s in scans if isinstance(s, dict) and 'tool' in s},
                     'dalfox': dyna,
                     'artifacts': {'static': static_dir.name if static_dir else None,
                                   'dalfox': dalfox_dir.name if dalfox_dir else None}})
    return rows


def markdown(rows, enforce: bool, workflow_state: str = ''):
    unfinished = not rows or any(
        any((row['static'].get(tool) or {}).get('status') not in ('OK', 'FINDINGS') for tool in TOOLS)
        or (row['dalfox'] or {}).get('status') not in ('OK', 'FINDINGS')
        for row in rows)
    found = any(any((r['static'].get(t) or {}).get('status') == 'FINDINGS' for t in TOOLS)
                or (r['dalfox'] or {}).get('status') == 'FINDINGS' for r in rows)
    heading = ('❌ Unvollständig: mindestens ein technischer Scanfehler / Bericht fehlt' if unfinished else
               '⚠️ Abgeschlossen mit Sicherheitsbefunden' if found else
               '✅ Vier Sicherheitswerkzeuge technisch abgeschlossen')
    out = ['# 🛡️ DevSecOps V9 · Gesamtauswertung', '', '**' + heading + '**', '',
           f'**Projekte:** {len(rows)} · **Modus:** {"Enforce" if enforce else "Report-only"}' +
           (f' · **Vorjobs:** {escape(workflow_state)}' if workflow_state else ''), '',
           '## Vergleich der Anwendungen', '',
           '| Anwendung | Profil | Semgrep | Gitleaks | Trivy | Dalfox XSS |',
           '|:--|:--|--:|--:|--:|--:|']
    for row in rows:
        out.append('| ' + ' | '.join([escape(row['name']), escape(row['profile'])] +
                   [result_state(row['static'].get(t)) for t in TOOLS] +
                   [result_state(row['dalfox'])]) + ' |')
    if not rows:
        out += ['', '**Keine Projekte erkannt.** Siehe Job `Projekte erkennen`.']
    out += ['', '## Erkenntnisse pro Projekt', '']
    for row in rows:
        out += [f'### {escape(row["name"])}', '',
                '| Werkzeug | Funde | Detail |', '|:--|--:|:--|']
        for tool in TOOLS:
            s = row['static'].get(tool)
            out.append('| ' + LABELS[tool] + ' | ' +
                       (str(s.get('count')) if s and s.get('count') is not None else '–') + ' | ' +
                       (escape(', '.join(map(str, s.get('examples', [])))[:150]) if s else 'Bericht fehlt') + ' |')
        d = row['dalfox']
        out.append('| Dalfox (XSS) | ' + (str(d.get('count')) if d and d.get('count') is not None else '–') +
                   ' | ' + (escape(', '.join(f.get('type','?') + ': ' + f.get('param', '?')
                        for f in d.get('findings', [])[:5]) or 'Keine Funde') if d else 'Bericht fehlt') + ' |')
        if d:
            out += ['', f'**Dalfox-Abdeckung:** {d.get("scanned",0)} / {d.get("candidates",0)} HTML-Eingabepunkte, '
                    f'{d.get("requests",0)} HTTP-Requests, {d.get("skipped",0)} übersprungen. '
                    f'Verifizierte Hinweise [V]: **{d.get("verified",0)}**.', '']
            if d.get('status') == 'ERROR':
                out += ['**Scannerfehler:** ' + escape(d.get('message', 'Unbekannt')), '']
            if d.get('findings'):
                out += ['| XSS-Klasse | Risiko | Parameter | Ziel |', '|:--|:--|:--|:--|']
                for f in d['findings'][:10]:
                    out.append('| ' + ' | '.join(escape(f.get(k, ''))
                                                  for k in ('type','risk','param','target')) + ' |')
        names = [n for n in row['artifacts'].values() if n]
        out += ['', '**Belege:** ' + (', '.join('`'+escape(n)+'`' for n in names)
                                    if names else 'Keine Artefakte erzeugt.'), '']
    out += ['## Bewertungslegende', '',
            '- **✅ 0:** Werkzeug wurde technisch erfolgreich abgeschlossen und meldete 0 Funde.',
            '- **⚠️ N:** Ausführung abgeschlossen, N Befunde (manuell validieren).',
            '- **❌:** Technischer Fehler, fehlender Bericht oder ungeprüfter Eingang.',
            '- Dalfox ist ein **etablierter, XSS-spezialisierter DAST-Scanner**. Getestet werden '
            'lokale HTML-Query-Eingaben; API-JSON und authentifizierte POST-Formulare sind nicht automatisch XSS-abgedeckt.',
            '- [V] ≠ beobachtete Browser-Ausführung; [R] ist zunächst nur reflektierter Text.',
            '- Findings verschiedener Tools sind nicht direkt addierbar; 0 Findings beweist keine Sicherheit.', '',
            '*JSON, Markdown, Installationslogs und Einzelberichte: GitHub Actions → Artifacts.*', '']
    return '\n'.join(out), unfinished


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--input', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--matrix', default='')
    parser.add_argument('--enforce', choices=('true', 'false'), default='false')
    a = parser.parse_args()
    a.output.mkdir(parents=True, exist_ok=True)
    try:
        matrix = json.loads(a.matrix) if a.matrix else {}
    except ValueError:
        matrix = {}
    rows = collect(a.input, matrix)
    md, incomplete = markdown(rows, a.enforce == 'true', os.environ.get('PREVIOUS_JOBS', ''))
    (a.output / 'summary.md').write_text(md, encoding='utf-8')
    (a.output / 'summary.json').write_text(json.dumps(rows, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(md, flush=True)
    if os.environ.get('GITHUB_STEP_SUMMARY'):
        with open(os.environ['GITHUB_STEP_SUMMARY'], 'a', encoding='utf-8') as f:
            f.write(md + '\n')
    if incomplete:
        return 2
    findings = any(any((r['static'].get(t) or {}).get('status') == 'FINDINGS' for t in TOOLS)
                   or (r['dalfox'] or {}).get('status') == 'FINDINGS' for r in rows)
    return int(a.enforce == 'true' and findings)

if __name__ == '__main__':
    raise SystemExit(main())
