"""Set up real test accounts and evidence of HTTP coverage for disposable apps.

Known routes are candidates, not an assertion that every app revision exposes
all URLs. Auth failures remain fatal; missing optional features are recorded.
"""
from __future__ import annotations

import json
import secrets
from http.cookiejar import CookieJar
from urllib.error import HTTPError
from urllib.request import build_opener, HTTPCookieProcessor, Request
from urllib.parse import urlsplit


def seed_entertainment(conf):
    import sqlite3
    from pathlib import Path
    dbfile = Path(conf['_runtime'])/'test.sqlite'
    notes = conf.setdefault('seed_notes', [])
    with sqlite3.connect(dbfile) as db:
        for table in ('books', 'series', 'movies', 'videogames', 'podcasts'):
            # Schema may vary among application versions. Never change an
            # existing schema: only insert if the columns actually exist.
            try:
                exists = db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone()
                if not exists:
                    notes.append(table + ': Medientabelle nicht vorhanden')
                    continue
                cols = {x[1] for x in db.execute(f'PRAGMA table_info("{table}")')}
                if 'title' not in cols:
                    notes.append(table + ': Titelspalte nicht vorhanden')
                    continue
                fields = ['title'] + (['created_at'] if 'created_at' in cols else [])
                vals = ['Security Test ' + table] + ([1700000000000] if 'created_at' in cols else [])
                db.execute(f'INSERT INTO "{table}" ({", ".join(fields)}) VALUES ({", ".join("?" for _ in fields)})', vals)
            except sqlite3.Error as exc:
                # Seed failure must not hide actual scan ability, but is reported.
                notes.append(table + ': Testdatensatz nicht eingefügt (' + type(exc).__name__ + ')')


def prepare(conf):
    profile = conf.get('_profile')
    if not profile:
        return
    if profile == 'entertainment':
        seed_entertainment(conf)
    jar = CookieJar()
    client = build_opener(HTTPCookieProcessor(jar))
    base = 'http://127.0.0.1:3000'
    password = secrets.token_urlsafe(24)
    notes = conf.setdefault('seed_notes', [])

    def request(url, body=None, headers=None, method=None):
        h = {'Content-Type':'application/json',
             'Origin':urlsplit(url).scheme+'://'+urlsplit(url).netloc}
        h.update(headers or {})
        req = Request(url, data=json.dumps(body).encode() if body is not None else None,
                      headers=h, method=method)
        with client.open(req, timeout=120) as response:
            raw = response.read()
            root_redirect = url == base+'/' and response.url in (base+'/dashboard', base+'/home')
            if not 200 <= response.status < 300 or (response.url != url and not root_redirect):
                raise RuntimeError('HTTP-Anmelde-/Testdatenoperation fehlgeschlagen: ' + url)
            return json.loads(raw) if 'json' in response.headers.get('Content-Type', '') and raw else raw

    def optional_seed(url, data, headers=None):
        try:
            return request(url, data, headers)
        except (HTTPError, OSError, ValueError, RuntimeError) as exc:
            status = getattr(exc, 'code', type(exc).__name__)
            notes.append(f'Testaktion {urlsplit(url).path}: {status}; nicht als erfolgreich gezählt')
            return None

    if profile == 'library':
        base = 'http://localhost:5000'
        account = request(base+'/auth/register',
                          {'username':'security-'+secrets.token_hex(5),'password':password})
        token = account.get('token') if isinstance(account, dict) else None
        if not token:
            raise RuntimeError('Bibliothek: Registrierung liefert keinen Test-JWT')
        headers = {'Authorization':'Bearer '+token}
        books = request(base+'/books')
        if isinstance(books, list) and books and isinstance(books[0], dict) and 'id' in books[0]:
            bookid = books[0]['id']
            reserved = optional_seed(base+f'/books/{bookid}/reserve', {}, headers)
            conf['targets'][1]['requests'] = [
                {'path':'/auth/login', 'method':'POST', 'body':'{}'},
                {'path':'/auth/register', 'method':'POST', 'body':'{}'},
                {'path':'/user/password', 'method':'PUT', 'body':'{}'},
                {'path':'/user/account', 'method':'DELETE', 'body':'{}'},
                {'path':f'/books/{bookid}/reserve', 'method':'POST', 'body':'{}'}]
            if reserved is not None:
                notes.append('Bibliothek: Testreservierung erfolgreich')
        else:
            notes.append('Bibliothek: keine Bücher zum Reservieren vorhanden; API bleibt scanbar')
        conf['targets'][1]['headers'] = headers
        conf['targets'][1]['post_inputs'] = [{'path':'/auth/login', 'field':'username',
                'body':{'username':'invalid','password':'not-the-user-password'}}]
        conf['auth_note'] = 'JWT-Testnutzer erstellt; Frontend anonym, API mit Test-JWT.'
    else:
        account = request(base+'/api/auth/sign-up/email',
                          {'name':'Security Test','email':'scan-'+secrets.token_hex(6)+'@example.test',
                           'password':password})
        if not isinstance(account, dict):
            raise RuntimeError('Better Auth: Registrierung ohne JSON-Antwort')
        session = request(base+'/api/auth/get-session')
        if not isinstance(session, dict) or not (session.get('user') or {}).get('id'):
            raise RuntimeError('Better Auth: keine gültige Sitzung nach Registrierung')
        if profile == 'flatmate':
            optional_seed(base+'/api/flatmates', {'action':'create','name':'Security Test WG'})
            from datetime import date, timedelta
            task = {'description':'Security Test Aufgabe',
                    'assignedUsers':[session['user']['id']],
                    'dueDate':str(date.today()+timedelta(days=7)), 'isRecurring':False}
            shopping = {'description':'Security Test Einkauf'}
            optional_seed(base+'/api/tasks', task)
            optional_seed(base+'/api/shopping', shopping)
            conf['targets'][0]['post_inputs'] = [
                {'path':'/api/tasks','field':'description','body':task,'authenticated':True},
                {'path':'/api/shopping','field':'description','body':shopping,'authenticated':True}]
            conf['targets'][0]['requests'] = [
                {'path':'/api/tasks', 'method':'POST', 'body':json.dumps(task)},
                {'path':'/api/shopping', 'method':'POST', 'body':json.dumps(shopping)}]
        if profile == 'entertainment':
            conf['targets'][0]['post_inputs'] = [
                {'path':'/api/auth/sign-up/email','field':'name', 'unique_email':True,
                 'body':{'name':'probe','email':'probe@example.test','password':secrets.token_urlsafe(24)}}]
        headers = {'Cookie':'; '.join(c.name+'='+c.value for c in jar)}
        if not headers['Cookie']:
            raise RuntimeError('Better Auth: Session-Cookie fehlt')
        for target in conf['targets']:
            target['headers'] = headers
        conf['verify_url'] = base+'/api/auth/get-session'
        conf['verify_headers'] = headers
        conf['auth_note'] = 'Better Auth: gültiger Testnutzer mit Session-Cookie; nach Scan erneut geprüft.'

    # Candidate routes: HTTP 404/405/403 do not invalidate a successful scan;
    # instead they must appear visibly in preflight evidence. HTTP 5xx is fatal.
    coverage = []
    for target in conf['targets']:
        origin = target['url'].rstrip('/')
        success = 0
        for route in target.get('routes', ['/']):
            url = origin + route
            req = Request(url, headers=target.get('headers', {}))
            status = None
            try:
                with client.open(req, timeout=45) as response:
                    status = response.status if response.url == url or (route == '/' and response.url in
                            (origin+'/dashboard', origin+'/home')) else 302
            except HTTPError as exc:
                status = exc.code
            if status is not None and status >= 500:
                raise RuntimeError(f'HTTP {status} auf {url}; Server-/DB-Fehler, siehe Serverlog')
            if status in (200, 201, 202, 204):
                success += 1
            coverage.append({'url':url, 'status':status,
                             'authenticated':bool(target.get('headers'))})
        if not success:
            raise RuntimeError('Kein funktionsfähiger HTTP-Einstieg für '+origin)
    conf['coverage'] = coverage
    if notes:
        conf['auth_note'] += ' Testdatenhinweise in coverage.json.'


def verify(conf):
    if not conf.get('verify_url'):
        return
    req = Request(conf['verify_url'], headers=conf['verify_headers'])
    from urllib.request import urlopen
    with urlopen(req, timeout=30) as response:
        data = json.load(response)
    if not isinstance(data, dict) or not (data.get('user') or {}).get('id'):
        raise RuntimeError('Testsitzung nach Scan ungültig; authentifizierte Abdeckung unvollständig')
