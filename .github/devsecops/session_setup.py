"""Create fresh test identities and verify real protected routes before ZAP."""
import json
import secrets
from http.cookiejar import CookieJar
from urllib.request import build_opener, HTTPCookieProcessor, Request
from urllib.parse import urlsplit


def prepare(conf):
    profile=conf.get('_profile')
    if not profile:return
    if profile=='entertainment':
        import sqlite3
        from pathlib import Path
        with sqlite3.connect(Path(conf['_runtime'])/'test.sqlite') as db:
            for table in ('books','series','movies','videogames','podcasts'):
                db.execute(f'CREATE TABLE IF NOT EXISTS {table} (id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL, completed INTEGER NOT NULL DEFAULT 0, abandoned INTEGER NOT NULL DEFAULT 0, created_at INTEGER)')
                db.execute(f'INSERT INTO {table}(title,created_at) VALUES (?,?)',('Security Test '+table,1700000000000))
    jar=CookieJar(); client=build_opener(HTTPCookieProcessor(jar))
    base='http://127.0.0.1:3000'
    password=secrets.token_urlsafe(24)
    def request(url, body=None, headers=None, method=None):
        h={'Content-Type':'application/json','Origin':urlsplit(url).scheme+'://'+urlsplit(url).netloc}
        h.update(headers or {})
        req=Request(url, data=json.dumps(body).encode() if body is not None else None, headers=h, method=method)
        with client.open(req,timeout=120) as response:
            raw=response.read()
            allowed_root_redirect = url == base+'/' and response.url in (base+'/dashboard',base+'/home')
            if response.status!=200 or (response.url!=url and not allowed_root_redirect):
                raise RuntimeError('Login-/Routenprüfung fehlgeschlagen: '+url)
            return json.loads(raw) if 'json' in response.headers.get('Content-Type','') else raw
    if profile=='library':
        base='http://localhost:5000'
        account=request(base+'/auth/register', {'username':'security-'+secrets.token_hex(5),'password':password})
        token=account.get('token')
        if not token:raise RuntimeError('Registrierung liefert keinen JWT')
        headers={'Authorization':'Bearer '+token}
        books=request(base+'/books')
        # Confirm a real authenticated operation, not merely a public endpoint.
        if not books:raise RuntimeError('Bibliothek-Testdaten fehlen')
        bookid=books[0]['id']
        request(base+f'/books/{bookid}/reserve',{},headers)
        conf['targets'][1]['headers']=headers
        conf['targets'][1]['requests']=[
            {'path':'/auth/login','method':'POST','body':'{}'},
            {'path':'/auth/register','method':'POST','body':'{}'},
            {'path':'/user/password','method':'PUT','body':'{}'},
            {'path':'/user/account','method':'DELETE','body':'{}'},
            {'path':f'/books/{bookid}/reserve','method':'POST','body':'{}'}]
        conf['auth_note']='JWT-Testnutzer angelegt; Reservierung bestätigt. Frontend anonym, API mit JWT; kein Admin-Scan.'
    else:
        account=request(base+'/api/auth/sign-up/email',
                        {'name':'Security Test','email':'scan-'+secrets.token_hex(6)+'@example.test','password':password})
        session=request(base+'/api/auth/get-session')
        if not isinstance(session,dict) or not session.get('user',{}).get('id'):
            raise RuntimeError('Better Auth: keine gültige Sitzung nach Registrierung')
        if profile=='flatmate':
            request(base+'/api/flatmates',{'action':'create','name':'Security Test WG'})
            from datetime import date, timedelta
            task={'description':'Security Test Aufgabe','assignedUsers':[session['user']['id']],
                  'dueDate':str(date.today()+timedelta(days=7)), 'isRecurring':False}
            shopping={'description':'Security Test Einkauf'}
            request(base+'/api/tasks',task)
            request(base+'/api/shopping',shopping)
            conf['targets'][0]['requests']=[
                {'path':'/api/tasks','method':'POST','body':json.dumps(task)},
                {'path':'/api/shopping','method':'POST','body':json.dumps(shopping)}]
        headers={'Cookie':'; '.join(c.name+'='+c.value for c in jar)}
        if not headers['Cookie']:raise RuntimeError('Better Auth: Session-Cookie fehlt')
        for t in conf['targets']:t['headers']=headers
        conf['verify_url']=base+'/api/auth/get-session'
        conf['verify_headers']=headers
        conf['auth_note']='Better-Auth-Testsitzung verifiziert; geschützte Routen vor und nach Scan geprüft.'
    # Warm all known pages, fail on redirects back to login and server errors.
    coverage=[]
    for target in conf['targets']:
        origin=target['url'].rstrip('/')
        for route in target['routes']:
            request(origin+route,headers=target.get('headers'))
            coverage.append({'url':origin+route,'status':200,'authenticated':bool(target.get('headers'))})
    conf['coverage']=coverage


def verify(conf):
    if not conf.get('verify_url'):return
    req=Request(conf['verify_url'],headers=conf['verify_headers'])
    from urllib.request import urlopen
    with urlopen(req,timeout=30) as response:data=json.load(response)
    if not isinstance(data,dict) or not data.get('user',{}).get('id'):
        raise RuntimeError('Testsitzung nach Scan ungültig; authentifizierte Abdeckung unvollständig')
