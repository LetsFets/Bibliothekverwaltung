#!/usr/bin/env python3
"""Starts a short-lived local web app and tests it with OWASP ZAP.

Only loopback HTTP URLs are allowed. ZAP uses host networking so that localhost
inside the container reaches the test service on the GitHub Ubuntu runner.
"""
from __future__ import annotations

import argparse

import json
import os
from pathlib import Path
import re
import shlex
import signal
import subprocess
import time
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import urlopen

ZAP_IMAGE = os.environ.get('ZAP_IMAGE', 'ghcr.io/zaproxy/zaproxy:stable')


def local_url(value: str) -> str:
    parsed = urlparse(value)
    if parsed.scheme != 'http' or parsed.hostname not in ('127.0.0.1', 'localhost'):
        raise ValueError('ZAP testet nur lokale HTTP-Adressen (localhost/127.0.0.1).')
    if parsed.username or parsed.password or parsed.fragment or not parsed.port:
        raise ValueError('Lokale Ziel-URL braucht Port und darf keine Zugangsdaten/Fragmente enthalten.')
    return value


def config_path(root: Path, item: str) -> Path:
    if not isinstance(item, str) or not item or Path(item).is_absolute():
        raise ValueError('Ungueltiger Projektpfad')
    target = (root / item).resolve()
    if not target.is_dir() or not target.is_relative_to(root.resolve()):
        raise ValueError('Projektordner muss innerhalb des Repositories liegen: ' + item)
    return target


def read_config(root: Path, selftest: bool = False) -> dict[str, Any]:
    if selftest:
        # Self-test MUST NOT read app.json or require Node/DB/secrets.
        return {'target_url': 'http://127.0.0.1:39991/index.html',
                'services': [{'name': 'zap-selftest', 'directory': '.github/devsecops/zap-selftest-site',
                              'install': '',
                              'start': 'python3 -m http.server 39991 --bind 127.0.0.1',
                              'ready_url': 'http://127.0.0.1:39991/index.html',
                              'env': {}, 'required_env': []}]}
    data = json.loads((root / '.github/devsecops/app.json').read_text(encoding='utf-8'))
    if not isinstance(data, dict) or not isinstance(data.get('services'), list) or not data['services']:
        raise ValueError('app.json braucht mindestens einen Service in services[].')
    local_url(data.get('target_url', ''))
    for item in data['services']:
        if not isinstance(item, dict) or not isinstance(item.get('start'), str) or not item['start'].strip():
            raise ValueError('Jeder Service braucht start="auto" oder einen expliziten Startbefehl.')
        config_path(root, item.get('directory', '.'))
        local_url(item.get('ready_url', ''))
        if not isinstance(item.get('env', {}), dict):
            raise ValueError('env muss ein Objekt sein.')
        if not isinstance(item.get('setup', ''), str):
            raise ValueError('setup muss ein Shell-Befehl als String sein.')
        required = item.get('required_env', [])
        if not isinstance(required, list) or any(not isinstance(x, str) or not x for x in required):
            raise ValueError('required_env muss eine Liste von Umgebungsvariablennamen sein.')
    return data


def package_info(root: Path, directory: Path) -> tuple[str, str | None, Path]:
    """Return package manager, pinned declaration and detected lockfile directory.

    Search parents as far as the repository root to support workspace-based apps.
    Never use npm ci for a pnpm/yarn lockfile.
    """
    root = root.resolve()
    directory = directory.resolve()
    if not directory.is_relative_to(root):
        raise ValueError('Package path is outside repository')
    ancestors = [directory, *list(directory.parents)]
    ancestors = ancestors[:ancestors.index(root) + 1]
    selected = None
    for p in ancestors:
        manifest = p / 'package.json'
        if manifest.exists():
            pkg = json.loads(manifest.read_text(encoding='utf-8'))
            decl = pkg.get('packageManager', '')
            if isinstance(decl, str) and re.match(r'^(pnpm|npm|yarn)@', decl):
                return decl.split('@', 1)[0], decl, p
        # detect actual lockfile (closest first)
        matches = [(name, pm) for name, pm in [('pnpm-lock.yaml', 'pnpm'),
                     ('yarn.lock', 'yarn'), ('package-lock.json', 'npm'),
                     ('npm-shrinkwrap.json', 'npm')] if (p / name).exists()]
        if len(matches) > 1:
            raise ValueError(f'Mehrere verschiedene Lockfile-Formate in {p}: {matches}. Bitte bereinigen.')
        if matches and selected is None:
            selected = (matches[0][1], None, p)
    return selected if selected is not None else ('npm', None, directory)


def installed_command(pm: str, declaration: str | None, lockdir: Path) -> list[str]:
    if pm == 'npm':
        has_lock = (lockdir / 'package-lock.json').exists() or (lockdir / 'npm-shrinkwrap.json').exists()
        return ['npm', 'ci', '--no-audit', '--no-fund'] if has_lock else ['npm', 'install', '--no-audit', '--no-fund']
    if pm == 'pnpm':
        return ['pnpm', 'install', '--frozen-lockfile'] if (lockdir / 'pnpm-lock.yaml').exists() else ['pnpm', 'install']
    if pm == 'yarn':
        modern = bool(declaration and re.match(r'^yarn@[2-9]', declaration)) or (lockdir / '.yarnrc.yml').exists()
        return ['yarn', 'install', '--immutable'] if modern else ['yarn', 'install', '--frozen-lockfile']
    raise ValueError('Nicht unterstuetzter Paketmanager: ' + pm)


def run_logged(command: list[str], cwd: Path, env: dict[str, str], dest: Path, timeout: int = 420) -> None:
    with dest.open('a', encoding='utf-8') as f:
        f.write('$ ' + shlex.join(command) + '\n')
        f.flush()
        done = subprocess.run(command, cwd=cwd, env=env, stdout=f,
                              stderr=subprocess.STDOUT, timeout=timeout, check=False)
    if done.returncode:
        raise RuntimeError(f'Befehl fehlgeschlagen (Exit-Code {done.returncode}): {shlex.join(command)}. Siehe {dest.name}')


def prepare_package_manager(pm: str, declaration: str | None, lockdir: Path,
                            cwd: Path, env: dict[str, str], log: Path) -> None:
    if pm == 'npm':
        return
    # Corepack is bundled with Node.js 22 in GitHub Actions. It respects
    # the exact "packageManager" version declared in package.json.
    # Bundled Corepack versions in older Node 22 can fail to verify
    # recent pnpm signatures ('Cannot find matching keyid').
    # Install a fixed, recent Corepack release on the disposable runner.
    run_logged(['npm', 'install', '--global', 'corepack@0.34.7',
                '--no-audit', '--no-fund'], cwd, env, log, 180)
    run_logged(['corepack', 'enable'], cwd, env, log, 120)
    if declaration:
        # Corepack resolves the version from the repository's packageManager.
        # Explicit preparation helps surface registry/signature errors early.
        run_logged(['corepack', '--version'], cwd, env, log, 60)
    elif pm == 'pnpm':
        lock = lockdir / 'pnpm-lock.yaml'
        header = lock.read_text(encoding='utf-8')[:300] if lock.exists() else ''
        if re.search(r'lockfileVersion:\s*[\'\"]?9(?:\.0)?', header):
            version = '9.15.9'
        elif re.search(r'lockfileVersion:\s*[\'\"]?6(?:\.|\b)', header):
            version = '8.15.9'
        else:
            raise RuntimeError('pnpm-lock.yaml hat unbekannte Version. Trage "packageManager": "pnpm@<version>" in package.json ein.')
        run_logged(['corepack', 'prepare', f'pnpm@{version}', '--activate'], cwd, env, log, 180)
    else:
        if (lockdir / '.yarnrc.yml').exists():
            raise RuntimeError('Yarn Berry braucht packageManager: "yarn@<version>" in package.json.')
        run_logged(['corepack', 'prepare', 'yarn@1.22.22', '--activate'], cwd, env, log, 180)


def auto_start(root: Path, directory: Path, ready_url: str, pm: str) -> list[str]:
    manifest = directory / 'package.json'
    if not manifest.exists():
        raise ValueError(f'start=auto benoetigt package.json in {directory}. Sonst start-Befehl konfigurieren.')
    data = json.loads(manifest.read_text(encoding='utf-8'))
    deps = {**data.get('dependencies', {}), **data.get('devDependencies', {})}
    port = str(urlparse(ready_url).port)
    if 'next' in deps:
        return [pm, 'exec', 'next', 'dev', '--hostname', '127.0.0.1', '--port', port]
    if 'vite' in deps:
        return [pm, 'exec', 'vite', '--host', '127.0.0.1', '--port', port, '--strictPort']
    scripts = data.get('scripts', {})
    if 'dev' in scripts:
        return [pm, 'run', 'dev']
    if 'start' in scripts:
        return [pm, 'run', 'start']
    raise ValueError('Kein Next/Vite und weder dev- noch start-Skript gefunden. Bitte start explizit setzen.')


def reachable(url: str) -> bool:
    try:
        with urlopen(url, timeout=2) as response:
            return 200 <= response.status < 400
    except HTTPError as exc:
        return exc.code in (401, 403)
    except (OSError, URLError):
        return False


def probe_status(url: str) -> int | None:
    try:
        with urlopen(url, timeout=3) as response:
            return response.status
    except HTTPError as exc:
        return exc.code
    except (OSError, URLError):
        return None


def await_ready(url: str, proc: subprocess.Popen, timeout: int = 100) -> tuple[bool, str]:
    deadline = time.monotonic() + timeout
    server_errors = 0
    successes = 0
    last = None
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            return False, f'Serverprozess ist vorzeitig beendet (Exit-Code {proc.returncode})'
        status = probe_status(url)
        last = status
        if status is not None and 200 <= status < 400:
            successes += 1
            if successes >= 3:
                return True, f'HTTP {status}, dreimal stabil erreichbar'
        elif status in (401, 403):
            successes += 1
            if successes >= 3:
                return True, f'HTTP {status}: geschuetzte Seite; nur erreichbare Routen testbar'
        else:
            successes = 0
        if status is not None and 500 <= status <= 599:
            server_errors += 1
            if server_errors >= 3:
                return False, f'HTTP {status} (Serverfehler); pruefe DB/ENV und Server-Log'
        else:
            server_errors = 0
        time.sleep(2)
    return False, f'Timeout ohne erfolgreiche HTTP-Antwort (letzter Status: {last})' 


def parse_zap(data: Any) -> tuple[int, list[str], int]:
    if not isinstance(data, dict) or not isinstance(data.get('site'), list) or not data['site']:
        raise ValueError('ZAP-JSON enthaelt keine besuchte Site; siehe zap-run.log')
    alerts = []
    instances = 0
    for site in data['site']:
        if not isinstance(site, dict) or not isinstance(site.get('alerts', []), list):
            raise ValueError('ZAP-JSON: site.alerts ist ungueltig')
        for alert in site['alerts']:
            if isinstance(alert, dict):
                alerts.append(alert)
                instances += len(alert.get('instances', []) or [])
    examples = [str(a.get('alertRef') or a.get('pluginid') or a.get('alert') or '?') for a in alerts[:5]]
    return len(alerts), examples, instances


def execute(root: Path, dest: Path, mode: str, selftest: bool = False) -> dict[str, Any]:
    dest.mkdir(parents=True, exist_ok=True)
    report = dest / 'zap.json'
    try:
        conf = read_config(root, selftest)
    except (OSError, ValueError, TypeError) as exc:
        return failed(dest, 'Konfiguration: ' + str(exc), mode)
    processes: list[subprocess.Popen] = []
    streams = []
    try:
        print(f'[ZAP] Zielmodus: {"SELFTEST" if selftest else "PROJECT"}; Scanmodus: {mode}', flush=True)
        for service in conf['services']:
            name = safe_name(str(service.get('name', 'service')))
            directory = config_path(root, service.get('directory', '.'))
            env = os.environ.copy()
            env.update({'CI': 'true', 'DEVSECOPS_TEST': 'true'})
            for key, value in service.get('env', {}).items():
                if not isinstance(key, str) or not isinstance(value, str):
                    raise ValueError('env-Schluessel und -Werte muessen Strings sein.')
                env[key] = value
            missing = [key for key in service.get('required_env', []) if not env.get(key)]
            if missing:
                raise RuntimeError(f'{name}: Pflicht-Umgebungsvariablen fehlen: {", ".join(missing)}. '
                                   'Bitte GitHub Repository Secrets (DEVSECOPS_*) mit ISOLIERTER Testdatenbank setzen.')
            install = service.get('install', '')
            pm = None
            if install == 'auto' or service['start'] == 'auto':
                pm, declaration, lockdir = package_info(root, directory)
            if install:
                log = dest / f'{name}-install.log'
                log.touch()
                print(f'  [web] {name}: Installation ({pm if install == "auto" else "benutzerdefiniert"}) ...', flush=True)
                if install == 'auto':
                    prepare_package_manager(pm, declaration, lockdir, directory, env, log)
                    run_logged(installed_command(pm, declaration, lockdir), directory, env, log)
                else:
                    run_logged(['bash', '-lc', install], directory, env, log)
            if service.get('setup'):
                setup_log = dest / f'{name}-setup.log'
                print(f'  [web] {name}: Testumgebung initialisieren', flush=True)
                run_logged(['bash', '-lc', service['setup']], directory, env, setup_log, 300)
            if service['start'] == 'auto':
                command = auto_start(root, directory, service['ready_url'], pm)
            else:
                command = ['bash', '-lc', service['start']]
            print(f'  [web] {name}: starte {shlex.join(command)}', flush=True)
            stream = (dest / f'{name}-server.log').open('w', encoding='utf-8')
            streams.append(stream)
            proc = subprocess.Popen(command, cwd=directory, env=env, stdout=stream,
                                    stderr=subprocess.STDOUT, start_new_session=True)
            processes.append(proc)
            ok, reason = await_ready(service['ready_url'], proc)
            if not ok:
                raise RuntimeError(f'{name}: Nicht scanbereit: {service["ready_url"]} – {reason}. Siehe {name}-server.log')
            print(f'  [web] {name}: erreichbar ({reason})', flush=True)

        url = local_url(conf['target_url'])
        if not reachable(url):
            raise RuntimeError('Test-URL antwortet nicht: ' + url)
        # ZAP uses its own non-root user. Restrict writable permissions to an
        # ephemeral report folder OUTSIDE the repository, never the source tree.
        if os.environ.get('GITHUB_ACTIONS') == 'true' and not dest.resolve().is_relative_to(Path(os.environ.get('RUNNER_TEMP', '/tmp')).resolve()):
            raise RuntimeError('ZAP Reportverzeichnis muss innerhalb RUNNER_TEMP liegen.')
        os.chmod(dest, 0o777)
        tool = 'zap-baseline.py' if mode == 'baseline' else 'zap-full-scan.py'
        args = ['docker', 'run', '--rm', '--network', 'host',
                '--security-opt', 'no-new-privileges', '--cap-drop', 'ALL',
                '-v', f'{dest}:/zap/wrk/:rw', ZAP_IMAGE, tool,
                '-t', url, '-J', 'zap.json', '-r', 'zap.html', '-I']
        if mode == 'baseline':
            args += ['-m', '1', '-T', '5']
        elif conf.get('zap_ajax_spider', False):
            args += ['-j']
        print(f'  [zap] Starte {mode} gegen {url} ...', flush=True)
        runlog = dest / 'zap-run.log'
        with runlog.open('w', encoding='utf-8') as handle:
            result = subprocess.run(args, stdout=handle, stderr=subprocess.STDOUT,
                                    timeout=1200 if mode == 'full' else 600, check=False)
        if result.returncode not in (0, 1, 2):
            raise RuntimeError(f'ZAP Exit-Code {result.returncode}, siehe zap-run.log')
        if not report.exists() or not report.stat().st_size:
            raise RuntimeError('ZAP hat keinen JSON-Report geschrieben, siehe zap-run.log')
        n, ids, instances = parse_zap(json.loads(report.read_text(encoding='utf-8')))
        return {'tool': 'zap', 'status': 'FINDINGS' if n else 'OK', 'count': n,
                'examples': ids, 'message': f'{mode}: {instances} betroffene URLs/Instanzen',
                'mode': mode, 'target': 'selftest' if selftest else 'project'}
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as exc:
        return failed(dest, str(exc), mode)
    finally:
        for proc in reversed(processes):
            if proc.poll() is None:
                try:
                    os.killpg(proc.pid, signal.SIGTERM)
                    proc.wait(timeout=6)
                except (ProcessLookupError, subprocess.TimeoutExpired):
                    try:
                        os.killpg(proc.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
        for stream in streams:
            stream.close()


def safe_name(name: str) -> str:
    return ''.join(c if c.isalnum() or c in '-_' else '_' for c in name)[:50] or 'service'


def failed(dest: Path, message: str, mode: str = 'baseline') -> dict[str, Any]:
    (dest / 'zap.error.txt').write_text(message + '\n', encoding='utf-8')
    return {'tool': 'zap', 'status': 'ERROR', 'count': None,
            'examples': [], 'message': message[:300], 'mode': mode}


def main() -> int:
    cli = argparse.ArgumentParser(description='Eigenstaendiger ZAP-Job: selftest oder project')
    cli.add_argument('--root', type=Path, default=Path.cwd())
    cli.add_argument('--target', choices=['selftest', 'project'], required=True)
    cli.add_argument('--mode', choices=['baseline', 'full'], default='baseline')
    cli.add_argument('--enforce', choices=['true', 'false'], default='false')
    cli.add_argument('--output', type=Path, required=True)
    args = cli.parse_args()
    output = args.output.resolve()
    if args.target == 'selftest' and args.mode != 'baseline':
        cli.error('Self-Test ist ausschliesslich baseline.')
    if args.mode == 'full' and os.environ.get('GITHUB_ACTIONS') == 'true' and os.environ.get('GITHUB_EVENT_NAME') != 'workflow_dispatch':
        cli.error('Aktiver Full Scan nur per workflow_dispatch.')
    outcome = execute(args.root.resolve(), output, args.mode, selftest=(args.target == 'selftest'))
    count = outcome.get('count')
    summary = (f'## OWASP ZAP – {args.target} ({args.mode})\n\n'
               f'**Status:** {outcome["status"]}\n\n'
               f'**Alerts:** {count if count is not None else "nicht ermittelbar"}\n\n'
               f'**Details:** {outcome.get("message", "")}\n\n'
               'Der Self-Test prueft nur den Scanner. Die eigentliche Webanwendung '
               'wird getrennt unter zap-project gescannt.\n')
    (output / 'summary.md').write_text(summary, encoding='utf-8')
    (output / 'summary.json').write_text(json.dumps(outcome, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
    if os.environ.get('GITHUB_STEP_SUMMARY'):
        with Path(os.environ['GITHUB_STEP_SUMMARY']).open('a', encoding='utf-8') as handle:
            handle.write(summary + '\n')
    print(summary, flush=True)
    if outcome['status'] == 'ERROR':
        return 2
    return 1 if args.enforce == 'true' and outcome['status'] == 'FINDINGS' else 0


if __name__ == '__main__':
    raise SystemExit(main())
