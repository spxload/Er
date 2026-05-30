#!/usr/bin/env python3
# Диагностика ИИ-доступности: через 10 узлов разных типов сходить на все
# 5 сервисов, вывести код + начало ответа. По этим данным строится единый
# детектор. Запуск в GitHub Actions (там узлы доступны).
import os, sys, json, base64, socket, subprocess, tempfile, time, re, random
from urllib.parse import urlparse, parse_qs, unquote
import requests

XRAY_BIN='./xray'; SOCKS=10808

PROBES = {
    'chatgpt':    ('GET',  'https://chatgpt.com/'),
    'chatgpt_req':('POST', 'https://chatgpt.com/backend-anon/sentinel/chat-requirements'),
    'claude':     ('GET',  'https://claude.ai/'),
    'gemini':     ('GET',  'https://gemini.google.com/app'),
    'grok':       ('GET',  'https://grok.com/'),
    'perplexity': ('GET',  'https://www.perplexity.ai/'),
}

def parse_vless(url):
    body=url[8:]; name='unknown'
    if '#' in body: body,frag=body.split('#',1); name=unquote(frag)
    main,query=(body.split('?',1)+[''])[:2]
    if '@' not in main: return None
    uuid,hp=main.split('@',1)
    if ':' not in hp: return None
    host,port=hp.rsplit(':',1)
    p=parse_qs(query); g=lambda k,d='':p.get(k,[d])[0]
    try: port=int(port)
    except: return None
    return {'name':name.strip(),'uuid':uuid,'host':host,'port':port,
            'security':g('security','none'),'type':g('type','tcp'),'flow':g('flow',''),
            'sni':g('sni',''),'fp':g('fp','chrome'),'alpn':g('alpn',''),
            'pbk':g('pbk',''),'sid':g('sid',''),'path':unquote(g('path','')),
            'hostHeader':g('host',''),'allowInsecure':g('allowInsecure','0'),
            'serviceName':g('serviceName','')}

def xray_cfg(n,port):
    st={'network':n['type']}
    if n['security']=='tls':
        st['security']='tls'
        tls={'allowInsecure':n['allowInsecure'] in ('1','true'),
             'serverName':n['sni'] or n['hostHeader'] or n['host']}
        if n['fp']: tls['fingerprint']=n['fp']
        if n['alpn']: tls['alpn']=[a.strip() for a in n['alpn'].split(',') if a.strip()]
        st['tlsSettings']=tls
    elif n['security']=='reality':
        st['security']='reality'
        st['realitySettings']={'serverName':n['sni'],'fingerprint':n['fp'] or 'chrome',
                               'publicKey':n['pbk'],'shortId':n['sid']}
    if n['type']=='ws':
        ws={'path':n['path'] or '/'}
        if n['hostHeader']: ws['headers']={'Host':n['hostHeader']}
        st['wsSettings']=ws
    elif n['type']=='grpc':
        st['grpcSettings']={'serviceName':n['serviceName']}
    u={'id':n['uuid'],'encryption':'none'}
    if n['flow']: u['flow']=n['flow']
    return {'log':{'loglevel':'error'},
            'inbounds':[{'tag':'in','port':port,'listen':'127.0.0.1','protocol':'socks',
                         'settings':{'udp':True,'auth':'noauth'}}],
            'outbounds':[{'protocol':'vless','settings':{'vnext':[{'address':n['host'],
                          'port':n['port'],'users':[u]}]},'streamSettings':st}]}

def wait_port(port,t=8):
    t0=time.time()
    while time.time()-t0<t:
        try: socket.create_connection(('127.0.0.1',port),timeout=1).close(); return True
        except: time.sleep(0.3)
    return False

UA='Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1'
def fetch(port,meth,url):
    px={'http':f'socks5h://127.0.0.1:{port}','https':f'socks5h://127.0.0.1:{port}'}
    h={'User-Agent':UA,'Accept-Language':'en-US,en'}
    try:
        if meth=='POST':
            h['Content-Type']='application/json'; h['Oai-Device-Id']='00000000-0000-4000-8000-000000000000'
            r=requests.post(url,headers=h,json={},proxies=px,timeout=12)
        else:
            r=requests.get(url,headers=h,proxies=px,timeout=12,allow_redirects=True)
        body=re.sub(r'\s+',' ',r.text)[:200]
        return r.status_code, str(r.url), body
    except Exception as e:
        return None, '', str(e)[:60]

def main():
    url=os.environ['SUBSCRIPTION_URL']; hwid=os.environ.get('SUB_HWID','')
    H={'X-HWID':hwid,'User-Agent':'Shadowrocket/3274 CFNetwork/3860.400.51 Darwin/25.3.0 iPhone14,7',
       'Host':urlparse(url).netloc,'Accept':'*/*'}
    txt=requests.get(url,headers=H,timeout=30).text
    body=''.join(txt.split())
    try:
        norm=body.replace('-','+').replace('_','/'); norm+='='*(-len(norm)%4)
        dec=base64.b64decode(norm).decode('utf-8','ignore')
        if 'vless://' in dec: txt=dec
    except: pass
    nodes=[parse_vless(l.strip()) for l in txt.splitlines() if l.strip().startswith('vless://')]
    nodes=[n for n in nodes if n]

    icons='💫⭐🟢🚀⚡🕹️🙏✈️'
    single=[n for n in nodes if '[VPN]' in n['name'] and '#' not in n['name'] and not any(i in n['name'] for i in icons)]
    russian=[n for n in nodes if 'Россия' in n['name']]
    other=[n for n in nodes if n not in single and n not in russian]
    random.shuffle(single); random.shuffle(russian); random.shuffle(other)
    picks = single[:4] + russian[:3] + other[:3]

    print(f"=== Диагностика {len(picks)} узлов ===\n")
    for i,n in enumerate(picks):
        port=SOCKS+i
        cfg=xray_cfg(n,port)
        f=tempfile.NamedTemporaryFile('w',suffix='.json',delete=False); json.dump(cfg,f); f.close()
        p=subprocess.Popen([XRAY_BIN,'run','-c',f.name],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        print(f"### {n['name']}  [{n['security']}/{n['type']}/{n['flow'] or '-'}]")
        if not wait_port(port,8):
            print("   xray не поднялся\n"); p.terminate(); os.unlink(f.name); continue
        time.sleep(0.5)
        for gurl in ('https://api.ip.sb/geoip','http://ip-api.com/json/?fields=countryCode,city'):
            st,_,gb=fetch(port,'GET',gurl)
            if st==200:
                try:
                    d=json.loads(gb); cc=d.get('country_code') or d.get('countryCode'); city=d.get('city')
                    print(f"   ГЕО: {cc} / {city}"); break
                except: pass
        else:
            print("   ГЕО: не определилась")
        for svc,(meth,u) in PROBES.items():
            st,final,b=fetch(port,meth,u)
            redir = f" -> {final[:40]}" if final and final!=u else ""
            print(f"   {svc:12} {meth:4} {st}{redir}")
            print(f"        {b[:150]}")
        print()
        p.terminate()
        try: p.wait(timeout=3)
        except: p.kill()
        os.unlink(f.name)

if __name__=='__main__': main()
