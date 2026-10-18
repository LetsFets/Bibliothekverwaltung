#!/usr/bin/env python3
"""Dalfox v3 XSS scan runner. Only disposable loopback test applications.

Dalfox is the scanner; Python here only selects explicitly scoped targets,
starts the subprocess, and converts its machine-readable results for CI.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from urllib.request import Request, build_opener, HTTPRedirectHandler
from urllib.error import HTTPError, URLError

from runtime import local_url

ALLOWED_TYPES = {'V': 'Verifiziert', 'A': 'AST-Indikator', 'R': 'Reflektiert', 'I': 'Informativ'}


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def canonical_target(base: str, spec: dict) -> str:
    """Construct one URL containing one explicit injectable query argument."""
    base = local_url(base)
    path = spec.get('path', '/')
    param = spec.get('param')
    if not isinstance(path, str) or not path.startswith('/') or path.startswith('//'):
        raise ValueError('Dalfox-Route muss mit einem einzelnen / beginnen')
    if not isinstance(param, str) or not param.isidentifier() or len(param) > 50:
        raise ValueError('Dalfox benötigt einen gültigen Query-Parameternamen')
    if '#' in path or '\\' in path:
        raise ValueError('Dalfox-Routen dürfen kein Fragment oder Backslash enthalten')
    root = urlsplit(base)
    raw = urlsplit(path)
    # Relative path must not override origin. No network targets from config.
    if raw.scheme or raw.netloc:
        raise ValueError('Nur relative lokale Dalfox-Routen erlaubt')
    query = [(k, v) for k, v in parse_qsl(raw.query, keep_blank_values=True) if k != param]
    query.append((param, 'security-test'))
    url = urlunsplit((root.scheme, root.netloc, raw.path, urlencode(query), ''))
    local_url(url)
    return url


def check_target(url: str, headers: dict) -> dict:
    """Skip nonexistent and JSON-only endpoints, never mark these as scanned."""
    local_url(url)
    req = Request(url, headers={**headers, 'User-Agent': 'DevSecOps-Dalfox-Preflight/1.0'})
    try:
        with build_opener(NoRedirect()).open(req, timeout=20) as res:
            status = res.status
            mime = res.headers.get_content_type()
    except HTTPError as ex:
        status = ex.code
        mime = ex.headers.get_content_type()
    except (OSError, URLError) as ex:
        return {'status': 'ERROR', 'reason': type(ex).__name__}
    if not 200 <= status < 300:
        return {'status': 'SKIP', 'http': status, 'reason': 'HTTP-Antwort nicht 2xx (z. B. Login-Weiterleitung)'}
    if mime not in ('text/html', 'application/xhtml+xml', 'image/svg+xml'):
        return {'status': 'SKIP', 'http': status, 'content_type': mime,
                'reason': 'Kein HTML-/SVG-Kontext; API-JSON ist allein kein Browser-XSS-Sink'}
    return {'status': 'READY', 'http': status, 'content_type': mime}


def sanitize_json(obj: dict, target: str) -> dict:
    """Validate Dalfox's v3 JSON envelope. A broken report is a scanner ERROR."""
    if not isinstance(obj, dict) or not isinstance(obj.get('findings'), list):
        raise ValueError('Dalfox JSON: findings fehlt oder ist keine Liste')
    meta = obj.get('meta')
    if not isinstance(meta, dict) or not isinstance(meta.get('target_summary'), list):
        raise ValueError('Dalfox JSON: meta.target_summary fehlt')
    if meta.get('incomplete') is True or any(isinstance(t, dict) and (
            t.get('status') in ('incomplete', 'error', 'failed') or t.get('incomplete') is True)
            for t in meta['target_summary']):
        raise RuntimeError('Dalfox meldet einen unvollständigen Scan / Session-Verlust')
    if not isinstance(meta.get('total_requests'), int) or meta['total_requests'] < 1:
        raise RuntimeError('Dalfox hat keine nachgewiesenen HTTP-Anfragen gesendet')
    findings = []
    for entry in obj['findings']:
        if not isinstance(entry, dict) or entry.get('type') not in ALLOWED_TYPES:
            raise ValueError('Dalfox JSON: unbekannte Befundstruktur / Typ')
        severity = str(entry.get('severity', '')).lower()
        risks = {'high': 'Hoch', 'critical': 'Kritisch', 'medium': 'Mittel',
                 'low': 'Niedrig', 'info': 'Informativ', 'informational': 'Informativ'}
        findings.append({
            'type': entry['type'],
            'name': ALLOWED_TYPES[entry['type']],
            'risk': risks.get(severity) or ('Hoch' if entry['type'] == 'V' else
                      'Mittel' if entry['type'] == 'A' else 'Niedrig' if entry['type'] == 'R' else 'Informativ'),
            'param': str(entry.get('param', '-'))[:80],
            'method': str(entry.get('method', 'GET'))[:15],
            'confidence': str(entry.get('confidence', 'unbekannt'))[:30],
            'target': target.split('?', 1)[0],
            'evidence': str(entry.get('evidence') or entry.get('type_description') or '')[:260],
            'cwe': str(entry.get('cwe', ''))[:30],
        })
    return {'findings': findings, 'requests': meta['total_requests'],
            'failed_requests': meta.get('failed_requests', 0),
            'version': str(meta.get('dalfox_version', ''))[:30]}


def invoke_dalfox(url: str, headers: dict, output: Path, ordinal: int,
                  *, bin_path: str | None = None) -> dict:
    """Code 0 clean, 1 findings, 2 error (Dalfox v3). Never log session headers."""
    binary = bin_path or os.environ.get('DALFOX_BIN', 'dalfox')
    dest = output / f'dalfox-target-{ordinal:02}.json'
    cmd = [binary, 'scan', url, '--format', 'json', '--output', str(dest),
           '--workers', '3', '--max-concurrent-targets', '1', '--rate-limit', '12',
           '--timeout', '8', '--scan-timeout', '150', '--max-payloads-per-param', '180',
           '--skip-discovery', '--skip-mining', '--no-color', '--insecure=false',
           '--exclude-url', '(?i)(logout|sign-out|signout|delete|remove|payment|checkout)']
    for k, v in headers.items():
        if k.lower() in ('cookie', 'authorization') and v:
            cmd.extend(['--headers', f'{k}: {v}'])
    # Never print full command or stderr with credentials / returned payloads.
    try:
        done = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              text=True, timeout=290, check=False,
                              env={**os.environ, 'NO_COLOR': '1'})
    except subprocess.TimeoutExpired as ex:
        raise RuntimeError(f'Dalfox Ziel {ordinal}: Zeitlimit überschritten') from ex
    except FileNotFoundError as ex:
        raise RuntimeError('Dalfox-Binary fehlt; Installation im Workflow prüfen') from ex
    (output / f'dalfox-target-{ordinal:02}.log').write_text(
        f'Dalfox Exit-Code: {done.returncode}\nAusgabedatei vorhanden: {dest.is_file()}\n'
        'CLI-Ausgabe bewusst nicht gespeichert (könnte Sessionwerte enthalten).\n', encoding='utf-8')
    if done.returncode not in (0, 1):
        # Do not persist attacker controlled stdout / secret-bearing header values.
        raise RuntimeError(f'Dalfox Ziel {ordinal} technisch fehlgeschlagen (Exit {done.returncode}); '
                           'CLI-Parameter, Netzstatus und Version prüfen')
    if not dest.is_file() or dest.stat().st_size == 0:
        raise RuntimeError(f'Dalfox Ziel {ordinal}: JSON-Report fehlt / ist leer')
    try:
        raw = json.loads(dest.read_text(encoding='utf-8'))
    except (ValueError, UnicodeDecodeError) as ex:
        raise RuntimeError(f'Dalfox Ziel {ordinal}: JSON-Report ungültig') from ex
    parsed = sanitize_json(raw, url)
    if done.returncode == 0 and parsed['findings']:
        raise RuntimeError('Dalfox Exit 0, obwohl findings im JSON enthalten sind')
    if done.returncode == 1 and not parsed['findings']:
        raise RuntimeError('Dalfox Exit 1, aber JSON enthält keine Findings')
    return parsed


def scan(conf: dict, output: Path) -> dict:
    targets = conf.get('targets') or [{'name': 'web', 'url': conf['target_url'],
                                       'input_queries': conf.get('input_queries', [])}]
    options = []
    for item in targets:
        origin = local_url(item['url'])
        for spec in item.get('input_queries', []):
            url = canonical_target(origin, spec)
            options.append((url, item.get('headers') or {}, item.get('name','web')))
    # Avoid duplicates; each target may produce hundreds of HTTP requests.
    options = list({url: (url, headers, name) for url, headers, name in options}.values())
    if not options:
        raise ValueError('Keine Dalfox-Input-Queries konfiguriert. '
                         'Setze targets[].input_queries (path + param) in app.json.')
    results, findings, tested = [], [], []
    requests, failures = 0, 0
    for idx, (url, headers, name) in enumerate(options, 1):
        probe = check_target(url, headers)
        row = {'url': url, 'service': name, **probe}
        results.append(row)
        print(f'[dalfox] {name}: {url} -> {probe["status"]}', flush=True)
        if probe['status'] == 'ERROR':
            raise RuntimeError(f'Dalfox-Preflight: {url}: {probe.get("reason", "unbekannt")}')
        if probe['status'] == 'SKIP':
            continue
        parsed = invoke_dalfox(url, headers, output, idx)
        tested.append(url)
        row['status'] = 'SCANNED'
        row['requests'] = parsed['requests']
        row['findings'] = len(parsed['findings'])
        requests += parsed['requests']
        failures += parsed['failed_requests']
        findings.extend(parsed['findings'])
    if not tested:
        raise RuntimeError('Kein geeigneter HTML-Eingabepunkt für Dalfox gefunden. '
                           'Keine XSS-Abdeckung. Prüfe app.json / Routen / Anmeldung.')
    by_type = {k: sum(f['type'] == k for f in findings) for k in ALLOWED_TYPES}
    return {'tool': 'dalfox', 'status': 'FINDINGS' if findings else 'OK',
            'count': len(findings), 'verified': by_type['V'], 'by_type': by_type,
            'findings': findings, 'tested_urls': tested, 'candidates': len(results),
            'scanned': len(tested), 'skipped': len(results)-len(tested),
            'tested': results, 'requests': requests, 'failed_requests': failures,
            'message': 'Nur explizit konfigurierte lokale HTML-Query-Inputs; keine Browser-Ausführung.'}
