"""Loaded inside the official ZAP container. No credentials in reports."""
import json
from pathlib import Path
import re

CONTROL=Path('/zap/private/control.json')
COVERAGE=Path('/zap/wrk/hook-coverage.json')


def zap_started(zap,target):
    conf=json.loads(CONTROL.read_text())
    origin=conf['url'].rstrip('/')
    expression=re.escape(origin)+r'/.*'
    context=zap.context.new_context('isolated-test')
    zap.context.include_in_context('isolated-test',expression)
    zap.context.set_context_in_scope('isolated-test','true')
    # Packaged scans use these context globals for all three spiders/scanners.
    import zap_common
    zap_common.context_name='isolated-test'
    zap_common.context_id=context
    logout=r'.*/(?:logout|sign-out)(?:[/?].*)?$'
    zap.context.exclude_from_context('isolated-test',logout)
    zap.spider.exclude_from_scan(logout)
    zap.ascan.exclude_from_scan(logout)
    zap.ajaxSpider.set_option_scope_check('Strict')
    if conf.get('ajax'):
        for allowed in conf.get('allowed_origins',[]):
            if allowed.rstrip('/')!=origin:
                zap.ajaxSpider.add_allowed_resource('^'+re.escape(allowed.rstrip('/'))+'/.*$',enabled='true')
        for tag in ('a','button'):
            zap.ajaxSpider.add_excluded_element('isolated-test','avoid-logout-'+tag,tag,
                xpath="//"+tag+"[contains(.,'Abmelden') or contains(.,'Logout') or contains(.,'Log out') or contains(.,'Sign out')]", enabled='true')
    for header,value in conf.get('headers',{}).items():
        result=zap.replacer.add_rule('test-session-'+header,'true','REQ_HEADER','false',header,
                                    value,url='^'+expression+'$')
        if result!='OK':raise RuntimeError('Session-Replacer konnte nicht gesetzt werden')
    seeded=[]
    for path in conf.get('routes',['/']):
        url=origin+path
        responses=zap.core.access_url(url,followredirects=False)
        if not isinstance(responses,list) or not responses:
            raise RuntimeError('ZAP hat keine Antwort für '+url)
        header=responses[0].get('responseHeader','')
        status=int(header.split(' ',2)[1])
        if status!=200 and not (path=='/' and status in (301,302,303,307,308)):raise RuntimeError(f'ZAP-Routenprüfung: {url} HTTP {status}')
        seeded.append({'url':url,'status':status})
    for req in conf.get('requests',[]):
        from urllib.parse import urlsplit
        body=req.get('body','')
        raw=(f"{req['method']} {origin+req['path']} HTTP/1.1\r\nHost: {urlsplit(origin).netloc}\r\n"
             f"Content-Type: application/json\r\nContent-Length: {len(body.encode())}\r\n\r\n{body}")
        zap.core.send_request(raw,followredirects=False)
    COVERAGE.write_text(json.dumps({'seeded':seeded,'session_header_applied':bool(conf.get('headers'))},indent=2))


def zap_ajax_spider(zap,target,max_time):
    conf=json.loads(CONTROL.read_text())
    zap.ajaxSpider.set_option_max_duration(2)
    zap.ajaxSpider.set_option_max_crawl_depth(4)
    zap.ajaxSpider.set_option_browser_id('firefox-headless')
    if any(x=='/dashboard' for x in conf.get('routes',[])):
        target=conf['url'].rstrip('/')+'/dashboard'
    elif '/home' in conf.get('routes',[]):
        target=conf['url'].rstrip('/')+'/home'
    return zap,target,max_time


def zap_pre_shutdown(zap):
    data=json.loads(COVERAGE.read_text())
    conf=json.loads(CONTROL.read_text())
    if int(zap.pscan.records_to_scan) != 0:
        raise RuntimeError('Passiver Scan nicht abgeschlossen')
    data['visited_urls']=zap.core.urls(baseurl=conf['url'])
    if conf.get('ajax'):
        data['ajax_results']=int(zap.ajaxSpider.number_of_results)
        if data['ajax_results']==0:raise RuntimeError('AJAX-Spider hat keine Ergebnisse')
    data['completed']=True
    COVERAGE.write_text(json.dumps(data,indent=2))
