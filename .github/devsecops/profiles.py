"""Adapters for the three supplied projects; all mutations happen in a temp copy."""
import json
import os
from pathlib import Path
import secrets
import shlex
import shutil
import tempfile

IGNORED = {'.git', 'node_modules', '.next', 'dist', 'build', '.venv', '__pycache__'}


def detect(path):
    pkg = json.loads((path / 'package.json').read_text())
    deps = {**pkg.get('dependencies', {}), **pkg.get('devDependencies', {})}
    if 'express' in deps and 'sql.js' in deps and (path/'frontend/package.json').is_file():
        return 'library'
    if 'next' in deps and 'better-auth' in deps and (path/'src/db/schema.ts').is_file():
        if (path/'src/app/api/flatmates/route.ts').is_file():
            return 'flatmate'
        if (path/'src/lib/sqlite-entries.ts').is_file():
            return 'entertainment'
    return None


def discover(root, selection='auto'):
    root = root.resolve()
    if selection != 'auto':
        result = []
        for item in selection.split(','):
            p = (root/item.strip()).resolve()
            if not item.strip() or not p.is_relative_to(root) or not p.is_dir():
                raise ValueError('Projektpfad muss innerhalb des Repositorys liegen')
            if not (p/'package.json').is_file():
                raise ValueError(f'package.json fehlt in {item}')
            result.append(p)
        return list(dict.fromkeys(result))
    found = []
    for directory, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = sorted(d for d in dirs if d not in IGNORED and not d.startswith('.'))
        p = Path(directory)
        if 'package.json' in files and detect(p):
            found.append(p)
            dirs[:] = []  # library frontend belongs to its parent, not a separate project
    if not found:
        raise ValueError('Kein unterstütztes Projekt gefunden. projects manuell setzen und app.json konfigurieren.')
    return found


def copy_project(source, destination):
    def ignore(directory, names):
        return [n for n in names if n in IGNORED or n.startswith('.env')
                or n.endswith(('.sqlite', '.sqlite3', '.db', '.db-wal', '.db-shm'))
                or Path(directory, n).is_symlink()]
    shutil.copytree(source, destination, ignore=ignore)


def configuration(root, profile, runtime):
    """runtime is outside report artifacts; never copy user DBs or .env files."""
    base = 'http://127.0.0.1:3000'
    env = {'DATABASE_URL': 'file:' + str(runtime/'test.sqlite'),
           'DATABASE_AUTH_SECRET': '', 'BETTER_AUTH_SECRET': secrets.token_urlsafe(48),
           'BETTER_AUTH_URL': base, 'NEXT_PUBLIC_BETTER_AUTH_URL': base,
           'NEXT_TELEMETRY_DISABLED': '1', 'PORT': '3000'}
    service = {'name':'web', 'directory':'.', 'install':'auto', 'start':'auto',
               'ready_url':base+'/login', 'env':env, 'required_env':[]}
    conf = {'target_url':base+'/', 'services':[service], '_profile':profile,
            '_runtime':str(runtime), 'zap_ajax_spider':True}
    if profile == 'library':
        api = 'http://localhost:5000'
        env = {'PORT':'5000', 'SQLITE_FILE':str(runtime/'library.sqlite'),
               'JWT_SECRET':secrets.token_urlsafe(48)}
        conf['services'] = [
            {'name':'api', 'directory':'.', 'install':'auto', 'start':'node server.js',
             'ready_url':api+'/books', 'env':env},
            {'name':'frontend', 'directory':'frontend', 'install':'auto',
             'start':'npm exec -- vite --host 127.0.0.1 --port 5173 --strictPort',
             'ready_url':'http://127.0.0.1:5173/', 'env':{}}]
        conf['target_url'] = 'http://127.0.0.1:5173/'
        conf['targets'] = [
            {'name':'frontend', 'url':conf['target_url'], 'routes':['/'], 'ajax':True},
            {'name':'api', 'url':api+'/', 'routes':['/', '/books', '/books?title=Security'], 'ajax':False}]
    else:
        # Dedicated config overrides the hardcoded DB path in the uploaded drizzle.config.ts.
        (root/'devsecops.drizzle.config.ts').write_text(
            'import { defineConfig } from "drizzle-kit";\nexport default defineConfig({'
            'dialect:"sqlite", schema:"./src/db/schema.ts", '
            'dbCredentials:{url:process.env.DATABASE_URL!}});\n')
        extra = ''
        if profile == 'entertainment':
            # These are missing direct dependencies in the supplied manifest.
            # Added ONLY after frozen install, ONLY to the disposable scan copy.
            extra = 'pnpm add --save-exact @libsql/client@0.15.15 && pnpm add -D --save-exact drizzle-kit@0.31.5 && '
        service['setup'] = extra + 'pnpm exec drizzle-kit push --config=devsecops.drizzle.config.ts --force'
        routes = ['/','/login','/signup','/privacy','/terms']
        routes += (['/dashboard','/dashboard/tasks','/dashboard/shopping','/dashboard/flatmates',
                    '/dashboard/settings','/api/flatmates','/api/flatmates/users','/api/tasks','/api/shopping','/api/user']
                   if profile == 'flatmate' else ['/home'])
        conf['targets'] = [{'name':'web', 'url':base+'/', 'routes':routes, 'ajax':True}]
    return conf
