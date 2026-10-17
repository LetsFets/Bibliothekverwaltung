"""Security report presentation; no credentials, payloads or secrets are rendered."""
from __future__ import annotations

import json
from pathlib import Path


STATUS = {'OK': '✅ Erfolgreich', 'FINDINGS': '⚠️ Funde',
          'ERROR': '❌ Technischer Fehler', 'SKIPPED': '➖ Übersprungen'}
RISKS = ('Hoch', 'Mittel', 'Niedrig', 'Informativ')


def cell(value):
    return str(value).replace('|', '\\|').replace('\n', ' ').replace('`', "'")


def risk_level(alert):
    number = str(alert.get('riskcode', ''))
    if number == '3':
        return 'Hoch'
    if number == '2':
        return 'Mittel'
    if number == '1':
        return 'Niedrig'
    if number == '0':
        return 'Informativ'
    desc = str(alert.get('riskdesc') or '').lower()
    for pattern, label in (('high', 'Hoch'), ('medium', 'Mittel'),
                           ('low', 'Niedrig'), ('informational', 'Informativ')):
        if desc.startswith(pattern):
            return label
    return 'Unbekannt'


def zap_findings(data):
    risks = {name: 0 for name in (*RISKS, 'Unbekannt')}
    top = []
    for site in data.get('site', []):
        for alert in site.get('alerts', []):
            risk = risk_level(alert)
            risks[risk] += 1
            top.append({'id': str(alert.get('pluginid') or alert.get('alertRef') or '?'),
                        'name': str(alert.get('name') or alert.get('alert') or 'Unbenannter Befund')[:140],
                        'risk': risk,
                        'instances': len(alert.get('instances') or [])})
    order = dict(zip((*RISKS, 'Unbekannt'), range(5)))
    return risks, sorted(top, key=lambda a: (order[a['risk']], -a['instances'], a['name']))[:12]


def zap_markdown(result, directory: Path, enforce=False):
    state = result.get('status', 'ERROR')
    count = result.get('count')
    total = count if isinstance(count, int) else 'nicht ermittelt'
    project = result.get('project', '.')
    mode = result.get('mode', 'baseline')
    lines = [
        f'# 🔐 OWASP ZAP – {cell(project)}', '',
        f'**{STATUS.get(state, state)}** · Profil `{cell(result.get("profile", "custom"))}`'
        f' · `{mode}` · {"Befunde blockieren" if enforce else "Report-Modus"}', '',
        '| Kennzahl | Ergebnis |', '|:--|--:|',
        f'| ZAP-Warnungstypen / Alerts | **{total}** |',
        f'| Betroffene URL-/Parameter-Vorkommen | **{result.get("instances", "–")}** |',
    ]
    risks = result.get('risks') or {}
    for risk in RISKS:
        lines.append(f'| {risk} | {risks.get(risk, "–")} |')
    lines += ['', '## Geprüfte Webanwendung', '']
    coverage_file = directory / 'coverage.json'
    if coverage_file.exists():
        try:
            coverage = json.loads(coverage_file.read_text(encoding='utf-8'))
            lines += [f'**Testprofil:** `{cell(coverage.get("profile", "custom"))}`  ',
                      f'**Anmeldung:** {cell(coverage.get("authentication", "anonym"))}', '']
            lines += ['| Ziel | HTTP-Ziel | Alarmtypen | Vorkommen | Besuchte URLs |',
                      '|:--|:--|--:|--:|--:|']
            for item in coverage.get('targets', []):
                lines.append('| ' + ' | '.join(map(cell, (item.get('name','web'),
                    item.get('url','?'), item.get('count',0), item.get('instances',0),
                    item.get('visited', '–')))) + ' |')
            checks = coverage.get('preflight') or []
            succeeded = [x for x in checks if x.get('status', 0) in (200,201,202,204)]
            lines += ['', f'**HTTP-Vorabprüfung:** {len(succeeded)} erfolgreiche Routen'
                      f' von {len(checks)} geprüften Einstiegen.']
            omitted = [x for x in checks if x.get('status') not in (200,201,202,204)]
            if omitted:
                lines += ['', '<details><summary>Übersprungene / abweichende Einstiegsrouten</summary>', '']
                for item in omitted[:20]:
                    lines.append(f'- `{cell(item.get("url", "?"))}` → HTTP {cell(item.get("status", "?"))}')
                lines += ['', '</details>']
        except (ValueError, OSError, TypeError) as exc:
            lines += [f'Abdeckungsdatei konnte nicht gelesen werden: {cell(exc)}']
    else:
        lines += ['**Keine bestätigte Scanabdeckung.** Bei Fehlern die Start- und ZAP-Logs prüfen.']
    top = result.get('top_alerts') or []
    if top:
        lines += ['', '## Wichtigste Sicherheitsfunde', '',
                  '| Risiko | Regel | Name | Vorkommen |', '|:--|:--|:--|--:|']
        for finding in top:
            lines.append('| ' + ' | '.join(map(cell, (finding['risk'], finding['id'],
                finding['name'], finding['instances']))) + ' |')
        lines += ['', 'Die Tabelle enthält **Regel-/Risikometadaten**, keine Cookies, JWTs oder Angriffspayloads.']
    if state == 'ERROR':
        lines += ['', '## Fehlerursache', '',
                  '> ' + cell(result.get('message','Unbekannter Fehler')), '',
                  'Siehe `zap.error.txt`, `*-install.log`, `*-setup.log`, `*-server.log` und `*-zap-run.log` im Artefakt.']
    else:
        lines += ['', '## Einordnung', '',
                  ('Die Anwendung wurde lokal gestartet und ZAP hat Berichte erzeugt.'
                   if state == 'OK' else 'Die Webanwendung wurde gescannt; erkannte Auffälligkeiten müssen bewertet werden.'),
                  ('**Baseline:** passiver HTTP-Sicherheitscheck, kein vollständiger SQLi-/XSS-Pentest.'
                   if mode == 'baseline' else '**Full Scan:** aktive Prüfungen gegen isolierte Testkopie mit Testdaten.'),
                  'Ein erfolgreicher Lauf ist **keine Garantie für eine sichere Anwendung**.']
    lines += ['', '## Artefakte', '',
              '`coverage.json` · `*-zap.html` · `*-zap.json` · `*-hook-coverage.json` · `*-zap-run.log`',
              '', '*Die einzelnen Berichte stehen nach Ende des Workflows unter Actions → Artifacts.*', '']
    if (directory / 'cleanup-warning.txt').exists():
        lines += ['**Hinweis:** Temporäre Dateien konnten nach dem Scan nicht vollständig gelöscht werden. '
                  'Der GitHub-Runner wird anschließend verworfen.', '']
    return '\n'.join(lines)
