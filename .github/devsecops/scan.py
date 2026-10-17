#!/usr/bin/env python3
"""Universeller, read-only DevSecOps-Scanner fuer lokale Projektordner.

Voraussetzung: Python 3.10+ und Docker. Keine Ausfuehrung von Projekt-Code.
Vier Scanner: Semgrep, Gitleaks, Trivy und OWASP ZAP (DAST).
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
from typing import Any
import secrets
import string
from web_scan import execute as web_execute

ROOT = Path(__file__).resolve().parents[2]
# Versionierte Images; per Umgebungsvariable ueberschreibbar.
# Fuer noch strengere Supply-Chain-Sicherheit koennen Image-Digests genutzt werden.
IMAGES = {
    'semgrep': os.environ.get('SEMGREP_IMAGE', 'semgrep/semgrep:1.181.0'),
    'gitleaks': os.environ.get('GITLEAKS_IMAGE', 'ghcr.io/gitleaks/gitleaks:v8.30.1'),
    'trivy': os.environ.get('TRIVY_IMAGE', 'aquasec/trivy:0.74.0'),
}
TOOLS = tuple(IMAGES)
EXCLUDES = ('node_modules', '.next', 'dist', 'build', '.venv', '.git', '.github/devsecops')


def select_projects(root: Path, selection: str) -> list[tuple[str, Path]]:
    """Nur Verzeichnisse innerhalb des Repositories erlauben (auch keine Symlink-Flucht)."""
    parts = [p.strip() for p in selection.split(',')]
    if not parts or any(not p for p in parts):
        raise ValueError('Projektpfade duerfen nicht leer sein.')
    result = []
    seen = set()
    base = root.resolve()
    for raw in parts:
        name = raw.replace('\\', '/')
        p = Path(name)
        if p.is_absolute() or re.match(r'^[A-Za-z]:', name):
            raise ValueError(f'Absoluter Pfad nicht erlaubt: {raw}')
        resolved = (base / p).resolve()
        try:
            rel = resolved.relative_to(base)
        except ValueError as exc:
            raise ValueError(f'Pfad liegt ausserhalb des Repositories: {raw}') from exc
        if not resolved.is_dir():
            raise ValueError(f'Projektordner nicht gefunden: {raw}')
        key = rel.as_posix() if rel.parts else '.'
        if key not in seen:
            result.append((key, resolved))
            seen.add(key)
    return result


def parse_findings(tool: str, data: Any) -> tuple[int, list[str]]:
    """Extrahiert Anzahl und bis zu drei harmlose Bezeichnungen, NIE Secret-Werte."""
    if tool == 'semgrep':
        results = data.get('results', []) if isinstance(data, dict) else []
        return len(results), [str(f.get('check_id', '?')) for f in results[:3]]
    if tool == 'gitleaks':
        results = data if isinstance(data, list) else []
        return len(results), [str(f.get('RuleID', '?')) for f in results[:3]]
    if tool == 'trivy':
        results = (data.get('Results') or []) if isinstance(data, dict) else []
        vulns = [v for r in results for v in (r.get('Vulnerabilities') or [])]
        return len(vulns), [str(v.get('VulnerabilityID', '?')) for v in vulns[:3]]
    raise ValueError(f'Unbekanntes Tool: {tool}')


def docker_args(tool: str, project: Path, output: Path) -> list[str]:
    """Kommandos in voneinander isolierten Containern, Quellcode nur read-only."""
    mounts = [
        '-v', f'{project}:/src:ro',
        '-v', f'{output}:/out:rw',
    ]
    if tool == 'semgrep':
        mounts += ['-v', f'{ROOT / ".github" / "devsecops" / "semgrep.yml"}:/rules/semgrep.yml:ro']
    if tool == 'trivy':
        cache = output.parent.parent / '.devsecops-trivy-cache'
        cache.mkdir(parents=True, exist_ok=True)
        mounts += ['-v', f'{cache}:/cache:rw']
    cmd = ['docker', 'run', '--rm', '--security-opt', 'no-new-privileges',
           '--cap-drop', 'ALL']
    # Alle Scanner koennen Reports und Cache schreiben, weil Container und
    # Verzeichnisse denselben Host-Benutzer (GitHub Actions runner) verwenden.
    # Dies behebt /out (Semgrep/Gitleaks) und /cache (Trivy). Kein chmod 777!
    if hasattr(os, 'getuid') and hasattr(os, 'getgid'):
        cmd += ['--user', f'{os.getuid()}:{os.getgid()}']
    # Ein beschreibbares Home/Cache ohne Schreibzugriff auf Quellcode.
    cmd += ['--env', 'HOME=/tmp', '--env', 'XDG_CACHE_HOME=/tmp/.cache']
    cmd += [*mounts, IMAGES[tool]]
    if tool == 'semgrep':
        return cmd + [
            'semgrep', 'scan', '--config', 'p/default', '--config', '/rules/semgrep.yml',
            '--json', '--output', '/out/semgrep.json', '--metrics', 'off',
            *[part for folder in EXCLUDES for part in ('--exclude', folder)], '/src',
        ]
    if tool == 'gitleaks':
        return cmd + [
            'dir', '/src', '--no-banner', '--redact', '--report-format', 'json',
            '--report-path', '/out/gitleaks.json', '--exit-code', '0',
        ]
    if tool == 'trivy':
        return cmd + [
            'fs', '--cache-dir', '/cache', '--scanners', 'vuln', '--format', 'json',
            '--output', '/out/trivy.json', '--exit-code', '0', '--no-progress',
            *[part for folder in EXCLUDES for part in ('--skip-dirs', '**/' + folder)],
            '/src',
        ]
    raise ValueError(tool)


def scan_one(tool: str, project: Path, dest: Path) -> dict[str, Any]:
    """Scannerfehler getrennt von Findings behandeln; keinen stillen Erfolg melden."""
    dest.mkdir(parents=True, exist_ok=True)
    report = dest / (tool + '.json')
    cmd = docker_args(tool, project, dest)
    try:
        completed = subprocess.run(cmd, capture_output=True, text=True, timeout=900,
                                   encoding='utf-8', errors='replace', check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        (dest / (tool + '.error.txt')).write_text(str(exc) + '\n', encoding='utf-8')
        return {'tool': tool, 'status': 'ERROR', 'count': None, 'examples': [],
                'message': str(exc)[:250]}

    log = (completed.stderr or '')[-5000:]
    if completed.returncode != 0:
        (dest / (tool + '.error.txt')).write_text(
            f'Exit-Code {completed.returncode}\n{log}\n', encoding='utf-8')
        return {'tool': tool, 'status': 'ERROR', 'count': None, 'examples': [],
                'message': f'Scanner mit Exit-Code {completed.returncode} fehlgeschlagen'}

    if not report.exists() or not report.stat().st_size:
        # Gitleaks erstellt in einigen Versionen bei 0 Findings keine Reportdatei.
        if tool == 'gitleaks':
            report.write_text('[]\n', encoding='utf-8')
        else:
            message = 'Scanner hat keinen JSON-Report geliefert'
            (dest / (tool + '.error.txt')).write_text(message + '\n', encoding='utf-8')
            return {'tool': tool, 'status': 'ERROR', 'count': None, 'examples': [],
                    'message': message}
    try:
        data = json.loads(report.read_text(encoding='utf-8'))
        if tool == 'gitleaks' and data is None:
            data = []
            report.write_text('[]\n', encoding='utf-8')
        if data is None and tool != 'gitleaks':
            raise ValueError('JSON-Ergebnis ist null')
        if tool == 'semgrep' and (not isinstance(data, dict) or 'results' not in data):
            raise ValueError('Semgrep-results fehlen')
        # Trivy laesst 'Results' bei 0 Schwachstellen oft komplett weg.
        # Das ist ein gueltiger Report, wenn SchemaVersion und ArtifactType da sind.
        if tool == 'trivy' and (not isinstance(data, dict) or
                                'SchemaVersion' not in data or 'ArtifactType' not in data):
            raise ValueError('Trivy: SchemaVersion/ArtifactType fehlen')
        # Niemals Treffertext/Secrets von Gitleaks im Artefakt speichern.
        # --redact redigiert beim Scannen; diese zweite Schicht entfernt
        # zusaetzlich potenziell sensible Originalfelder im Ergebnis.
        if tool == 'gitleaks':
            if not isinstance(data, list):
                raise ValueError('Gitleaks: erwartete Liste fehlt')
            for finding in data:
                if isinstance(finding, dict):
                    for key in ('Secret', 'Match', 'Line'):
                        if key in finding:
                            finding[key] = '[REDACTED]'
            report.write_text(json.dumps(data, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
        count, examples = parse_findings(tool, data)
        status = 'FINDINGS' if count else 'OK'
    except (ValueError, TypeError, KeyError) as exc:
        message = f'Ungueltiges JSON-Ergebnis: {exc}'
        (dest / (tool + '.error.txt')).write_text(message + '\n', encoding='utf-8')
        return {'tool': tool, 'status': 'ERROR', 'count': None, 'examples': [],
                'message': message}
    message = ''
    return {'tool': tool, 'status': status, 'count': count,
            'examples': examples, 'message': message}


def safe_slug(path: str) -> str:
    return 'root' if path == '.' else re.sub(r'[^a-zA-Z0-9._-]', '_', path).strip('._')


def markdown_summary(projects: list[dict[str, Any]], zap: dict[str, Any], enforce: bool) -> str:
    lines = [
        '# DevSecOps V6 Security Report', '',
        'Semgrep (SAST), Gitleaks (Secrets), Trivy (SCA), OWASP ZAP (DAST).', '',
        '| Projekt | Semgrep | Gitleaks | Trivy |',
        '|---|---:|---:|---:|',
    ]
    total = 0
    errors = []
    def fmt(scan: dict[str, Any]) -> str:
        nonlocal total
        if scan['status'] == 'SKIPPED':
            return 'separater Job'
        if scan['status'] == 'ERROR':
            errors.append(f"{scan['tool']}: {scan['message']}")
            return 'ERROR'
        total += scan['count'] or 0
        return str(scan['count'])
    for item in projects:
        lines.append('| ' + ' | '.join([item['project'], *(fmt(s) for s in item['scans'])]) + ' |')
    lines += ['', (f'**OWASP ZAP:** separater GitHub-Job' if zap['status'] == 'SKIPPED' else f'**OWASP ZAP ({zap.get("mode", "unbekannt")}, {zap.get("target", "project")}):** {fmt(zap)} Alerts'), '']
    lines += [f'**Gesamtzahl (ueber verschiedene Kategorien, nicht dedupliziert): {total}**', '',
              f'**Modus:** {"Enforce" if enforce else "Report-only"} (Scannerfehler schlagen IMMER fehl).', '']
    for item in projects:
        for scan in item['scans']:
            if scan.get('examples'):
                lines.append(f"- **{item['project']} / {scan['tool']}**: " + ', '.join(scan['examples']))
    if zap.get('examples'):
        lines.append('- **ZAP**: ' + ', '.join(zap['examples']))
    if errors:
        lines += ['', '## Fehler bei Scannern oder Web-Start', '']
        lines.extend('- ' + e for e in errors)
    lines += ['', 'ZAP-Baseline ist PASSIV: kein gezielter XSS-/SQLi-Angriffstest. '
              'Nur manuell gestarteter Full Scan ist aktiv und darf AUSSCHLIESSLICH '
              'gegen eine isolierte Testinstanz mit Testdaten laufen.', '']
    return '\n'.join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description='V5: 3 statische Scanner + ZAP gegen lokal gestartete Web-App')
    parser.add_argument('--static-only', action='store_true', help='Nur Semgrep/Gitleaks/Trivy')
    parser.add_argument('--projects', default='.', help='Kommagetrennte relative Ordner, z.B. . oder examples/01-js-auth,examples/02-python-api')
    parser.add_argument('--mode', choices=['baseline', 'full'], default='baseline')
    parser.add_argument('--output', type=Path, default=None,
                        help='Reportordner AUSSERHALB des zu scannenden Projektbaums')
    parser.add_argument('--enforce', choices=['true', 'false'], default='false')
    parser.add_argument('--zap-selftest', choices=['true', 'false'], default='false',
                        help='ZAP gegen lokale Python-Testseite statt echter Web-App ausfuehren')
    parser.add_argument('--demo-secret', choices=['true', 'false'], default='false',
                        help='Nur fuer Live-Demo: temporaerer, ungueltiger Schluessel im ersten Projekt')
    args = parser.parse_args()
    root = ROOT.resolve()
    output = (args.output or root.parent / f'{root.name}-security-reports').resolve()
    enforce = args.enforce == 'true'
    if not (root / '.github' / 'devsecops' / 'semgrep.yml').is_file():
        print(f'Unvollstaendiges Pipeline-Repository (.github/devsecops/semgrep.yml fehlt): {root}', file=sys.stderr)
        return 2
    try:
        projects = select_projects(root, args.projects)
    except ValueError as exc:
        print(f'Fehler: {exc}', file=sys.stderr)
        return 2
    for _, path in projects:
        if output == path or output.is_relative_to(path):
            print('Fehler: Reportordner darf nicht innerhalb eines Scan-Projektordners liegen.', file=sys.stderr)
            return 2
    if args.mode == 'full' and os.environ.get('GITHUB_ACTIONS') == 'true' and os.environ.get('GITHUB_EVENT_NAME') != 'workflow_dispatch':
        print('Full Scan ist nur bei manuellem workflow_dispatch zulaessig.', file=sys.stderr)
        return 2
    if not shutil.which('docker'):
        print('Fehler: Docker CLI nicht gefunden. Installiere Docker oder nutze GitHub Actions.', file=sys.stderr)
        return 2
    # Demo-Secret ist zufaellig und UNGUELTIG, wird niemals committed.
    # Nur bei manuell gestarteter Demo verwenden und nach dem Scan aufraeumen.
    demo_file = None
    if args.demo_secret == 'true':
        demo_file = projects[0][1] / 'devsecops-demo-test-token.txt'
        if demo_file.exists():
            print('Demo-Datei existiert bereits; wird nicht ueberschrieben.', file=sys.stderr)
            return 2
        token_chars = string.ascii_letters + string.digits
        fake_token = 'ghp_' + ''.join(secrets.choice(token_chars) for _ in range(36))
        demo_file.write_text('test_token = "' + fake_token + '"\n', encoding='utf-8')
        print('Demo-Modus: ungueltiger Test-Token voruebergehend erzeugt (Wert verborgen).', flush=True)
    try:
        return execute_scans(projects, output, enforce, args.mode, args.zap_selftest == 'true', static_only=args.static_only)
    finally:
        if demo_file is not None:
            demo_file.unlink(missing_ok=True)


def execute_scans(projects: list[tuple[str, Path]], output: Path, enforce: bool, mode: str, selftest: bool = False, static_only: bool = False) -> int:
    output.mkdir(parents=True, exist_ok=True)
    results = []
    for n, (name, path) in enumerate(projects, 1):
        dest = output / f'{n:02d}-{safe_slug(name)}'
        print(f'\n=== Projekt {n}/{len(projects)}: {name} ===', flush=True)
        scans = []
        for tool in TOOLS:
            print(f'  [{tool}] startet ...', flush=True)
            outcome = scan_one(tool, path, dest)
            scans.append(outcome)
            print(f'  [{tool}] {outcome["status"]} '
                  f'({outcome["count"] if outcome["count"] is not None else "?"} Findings)',
                  flush=True)
        results.append({'project': name, 'scans': scans})
    if static_only:
        zap = {'tool':'zap','status':'SKIPPED','count':None,'examples':[],
               'message':'Separater GitHub-Job', 'mode':mode}
    else:
        print('\n=== OWASP ZAP: temporaere Webanwendung starten ===', flush=True)
        zap = web_execute(ROOT, output / 'web-zap', mode, selftest=selftest)
    print(f'  [zap] {zap["status"]} ({zap["count"] if zap["count"] is not None else "?"} Alerts)', flush=True)
    markdown = markdown_summary(results, zap, enforce)
    (output / 'summary.md').write_text(markdown, encoding='utf-8')
    (output / 'summary.json').write_text(json.dumps({'projects': results, 'zap': zap}, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print('\n' + markdown, flush=True)
    if os.environ.get('GITHUB_STEP_SUMMARY'):
        with open(os.environ['GITHUB_STEP_SUMMARY'], 'a', encoding='utf-8') as handle:
            handle.write(markdown + '\n')
    errored = zap['status'] == 'ERROR' or any(s['status'] == 'ERROR' for item in results for s in item['scans'])
    found = zap['status'] == 'FINDINGS' or any(s['status'] == 'FINDINGS' for item in results for s in item['scans'])
    return 2 if errored else (1 if enforce and found else 0)


if __name__ == '__main__':
    raise SystemExit(main())
