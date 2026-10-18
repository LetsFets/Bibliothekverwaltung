"""Reproducible review-friendly Markdown for Dalfox v3."""
import json
from pathlib import Path


def esc(value):
    return str(value).replace('|', '\\|').replace('`', "'").replace('\n', ' ').replace('\r',' ')


def dalfox_markdown(result: dict, report_dir: Path, enforce: bool = False) -> str:
    state = result.get('status', 'ERROR')
    name = esc(result.get('project', '.'))
    banner = {'OK': '✅ Dalfox technisch abgeschlossen – keine Funde in getesteten Eingaben',
              'FINDINGS': '⚠️ Dalfox hat Hinweise / mögliche XSS-Schwachstellen gefunden',
              'ERROR': '❌ Technischer Scanfehler – keine Entwarnung möglich'}.get(state, state)
    lines = [f'# 🦊 Dalfox XSS-Scan · {name}', '',f'**{banner}**', '',
             f'Profil: `{esc(result.get("profile", "custom"))}` · '
             f'Bewertungsmodus: {"Enforce" if enforce else "Report-only"}', '',
             '## Kurzüberblick', '',
             '| Kennzahl | Wert |', '|:--|--:|',
             f'| HTML-Testziele konfiguriert | {result.get("candidates",0)} |',
             f'| **Mit Dalfox geprüft** | **{result.get("scanned",0)}** |',
             f'| Übersprungen | {result.get("skipped",0)} |',
             f'| **Dalfox-HTTP-Anfragen** | **{result.get("requests",0)}** |',
             f'| Fehlgeschlagene Dalfox-HTTP-Anfragen | {result.get("failed_requests",0)} |',
             f'| **Sicherheitsbefunde insgesamt** | **{result.get("count") if result.get("count") is not None else "–"}** |',
             f'| Hoch eingestufte XSS-Befunde [V] | {result.get("by_type",{}).get("V",0)} |',
             f'| AST-Hinweise [A] | {result.get("by_type",{}).get("A",0)} |',
             f'| Reflektionen [R] | {result.get("by_type",{}).get("R",0)} |',
             f'| Informative Hinweise [I] | {result.get("by_type",{}).get("I",0)} |', '']
    if state == 'ERROR':
        lines += ['## Technischer Fehler', '',esc(result.get('message', 'Unbekannter Fehler')),
                  '', 'Bitte zuerst Installations-, Server- und Setup-Logs prüfen. '
                  'Keine erfolgreichen Scans dürfen aus diesem Ergebnis abgeleitet werden.', '']
    else:
        lines += ['## XSS-Befunde', '',
                  '| Typ | Risiko | Parameter | Methode | Eingabepunkt | Beleg |',
                  '|:--|:--|:--|:--|:--|:--|']
        findings = result.get('findings', [])
        if findings:
            for f in findings[:50]:
                lines.append('| ' + ' | '.join(esc(f.get(key, '')) for key in
                             ('type', 'risk', 'param', 'method', 'target', 'evidence')) + ' |')
            if len(findings) > 50:
                lines.append(f'Weitere {len(findings)-50} Funde im JSON-Artefakt.')
        else:
            lines.append('| – | – | – | – | – | Kein XSS-Indikator für die getesteten Eingaben |')
        lines += ['', '## Reale Dalfox-Abdeckung', '',
                  '| Ziel / Parameter | Ergebnis | HTTP | Dalfox-Anfragen | Begründung |',
                  '|:--|:--|--:|--:|:--|']
        for row in result.get('tested', []):
            lines.append('| ' + ' | '.join(esc(v) for v in (
                row.get('url'), row.get('status'), row.get('http','–'),
                row.get('requests','–'), row.get('reason','–'))) + ' |')
    cov = report_dir / 'coverage.json'
    if cov.exists():
        try:
            data = json.loads(cov.read_text(encoding='utf-8'))
            lines += ['', '## Start- und Anmeldungskontrolle', '',
                      '**Testbenutzer:** ' + esc(data.get('authentication', 'nicht eingerichtet')),
                      '', f'**Vorab geprüfte HTTP-Routen:** {len(data.get("preflight",[]))}', '',
                      '| Route | HTTP-Status | Authentifiziert |','|:--|--:|:--|']
            for row in data.get('preflight', []):
                lines.append('| ' + ' | '.join(esc(v) for v in (
                    row.get('url'), row.get('status'), 'Ja' if row.get('authenticated') else 'Nein'))+' |')
            if data.get('seed_notes'):
                lines += ['', '**Testdaten-Hinweise:** ' + '; '.join(esc(v) for v in data['seed_notes'])]
        except (ValueError, OSError):
            lines += ['', 'coverage.json ist nicht lesbar.']
    lines += ['', '## Interpretation für die Studienarbeit', '',
              '- **[V]** Dalfox bewertet eine XSS-Ausnutzbarkeit als wahrscheinlich. Kein Browser wird ausgeführt; Befund manuell prüfen.',
              '- **[A]** mögliche Source-Sink-Beziehung im JavaScript (statische AST-Analyse).',
              '- **[R]** reflektierter Parameter – allein noch **kein** bestätigtes XSS.',
              '- **[I]** informativer Hinweis.',
              '- **SKIP** bedeutet nicht getestet. Nur tatsächlich erfolgreiche HTML-Ziele zählen zur Abdeckung.',
              '- Dalfox untersucht gezielte GET-/Query-Eingaben auf einer **isolierten lokalen App-Kopie**; '
              'authentifizierte POST-Formulare / gespeichertes XSS werden hier nicht automatisch abgedeckt.',
              '- 0 Funde bedeutet **nicht**, dass alle XSS-Risiken ausgeschlossen sind.', '',
              '*Artefakte: summary.json, summary.md, coverage.json und Dalfox-JSON pro Ziel.*', '']
    return '\n'.join(lines)
