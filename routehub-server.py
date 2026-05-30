#!/usr/bin/env python3
# =====================================================================
#  routehub-server.py — серверная часть RouteHub (Этап B плана v3).
#  ИИ-доступность — ФАКТИЧЕСКАЯ проверка доступа, не блок-лист стран:
#   - ChatGPT: POST chat-requirements (200+token=pass, 403 unsupported=block).
#   - Gemini:  живая страница /app (детект «not available»).
#   - Claude/Grok/Perplexity: страна по их cdn-cgi/trace (сервис гейтит
#     по ней; их probe-эндпоинты не отличают гео-блок от no-auth).
#   - Любой при сбое -> fallback на блок-лист стран; manual_block в конфиге.
#  Гео: cf_loc (точка Cloudflare) и country/geo — РЕАЛЬНЫЙ выходной IP
#  через КАСКАД из 4 гео-сервисов (страна+город, резерв при недоступности).
#  Нейтральный trace (cloudflare.com) — блок одного ИИ не валит весь узел.
#  Параллельность (concurrency): пул Xray-портов. Скорость НЕ меряет.
#  Рейтинг: EWMA, светофор 4 цвета. Лог стерильный: имена, без URI.
# =====================================================================

import os, sys, json, base64, socket, subprocess, tempfile, time, re, random
from urllib.parse import urlparse, parse_qs, unquote

try:
    import requests
except ImportError:
    print("ОШИБКА: нужен requests. pip install 'requests[socks]'")
    sys.exit(1)

XRAY_BIN    = os.environ.get('XRAY_BIN', './xray')
OUTPUT      = os.environ.get('OUTPUT_FILE', 'routehub-ratings.json')
HISTORY     = os.environ.get('HISTORY_FILE', 'routehub-history.json')
CONFIG_FILE = os.environ.get('CONFIG_FILE', 'routehub-config.json')
SOCKS_PORT  = 10808

DEFAULTS = {
    "verify_ai": True, "pause_min_sec": 0.5, "pause_max_sec": 3.0,
    "ewma_fresh": 0.7, "ewma_old": 0.3, "stale_hours": 4, "history_len": 20,
    "concurrency": 6, "manual_block": {},
    "block_lists": {
        "chatgpt":    ["RU","BY","CN","KP","SY","IR","VE","CU","AF","UA"],
        "claude":     ["RU","BY","CN","KP","SY","IR","VE","CU","AF"],
        "gemini":     ["RU","BY","CN","KP","SY","IR","CU"],
        "grok":       ["RU","BY","CN","KP","IR"],
        "perplexity": ["RU","BY","CN","KP","IR"],
    },
    "country_priority": ["DE","FI","NL","PL","EE","SE","US"],
    "subscriptions": [
        {"name": "Lastdep", "url_env": "SUBSCRIPTION_URL",
         "hwid_env": "SUB_HWID", "prefix": "Lastdep"}
    ],
}

# Страна, которую видит сам сервис (его cdn-cgi/trace -> loc=).
SERVICE_TRACE = {
    'claude':     'https://claude.ai/cdn-cgi/trace',
    'grok':       'https://grok.com/cdn-cgi/trace',
    'perplexity': 'https://www.perplexity.ai/cdn-cgi/trace',
}
TRACE_URL = 'https://www.cloudflare.com/cdn-cgi/trace'  # нейтральный, не ИИ-домен
SERVICES  = ['chatgpt', 'claude', 'gemini', 'grok', 'perplexity']
BYPASS_MARKERS = ['\U0001f64f', 'Обход', 'обход']


def log(msg):
    print(f'[{time.strftime("%H:%M:%S")}] {msg}', flush=True)


def load_config():
    cfg = dict(DEFAULTS)
    try:
        with open(CONFIG_FILE, encoding='utf-8') as f:
            cfg.update(json.load(f))
        log(f'Конфиг {CONFIG_FILE} загружен.')
    except FileNotFoundError:
        log(f'{CONFIG_FILE} не найден — значения по умолчанию.')
    except Exception as e:
        log(f'Ошибка чтения {CONFIG_FILE}: {e}; по умолчанию.')
    if os.environ.get('VERIFY_AI', '') in ('0', '1'):
        cfg['verify_ai'] = os.environ['VERIFY_AI'] == '1'
    return cfg


def fetch_subscription(url, hwid):
    headers = {
        'X-HWID': hwid,
        'User-Agent': 'Shadowrocket/3274 CFNetwork/3860.400.51 Darwin/25.3.0 iPhone14,7',
        'X-VER-OS': '26.3.1', 'X-DEVICE-MODEL': 'iPhone', 'X-DEVICE-OS': 'iOS',
        'Accept': '*/*', 'Accept-Language': 'ru', 'Connection': 'keep-alive',
        'Host': urlparse(url).netloc,
    }
    log('Скачиваю подписку...')
    r = requests.get(url, headers=headers, timeout=30)
    r.raise_for_status()
    body = ''.join(r.text.split())
    if not body:
        return ''
    try:
        norm = body.replace('-', '+').replace('_', '/')
        norm += '=' * (-len(norm) % 4)
        dec = base64.b64decode(norm).decode('utf-8', 'ignore')
        if any(p in dec for p in ('vless://', 'vmess://', 'trojan://', 'ss://')):
            return dec
    except Exception:
        pass
    return r.text


def parse_vless(url):
    body = url[len('vless://'):]
    name = 'unknown'
    if '#' in body:
        body, frag = body.split('#', 1); name = unquote(frag)
    main, query = (body.split('?', 1) + [''])[:2]
    if '@' not in main:
        return None
    uuid, hostport = main.split('@', 1)
    if ':' not in hostport:
        return None
    host, port = hostport.rsplit(':', 1)
    p = parse_qs(query); g = lambda k, d='': p.get(k, [d])[0]
    try: port = int(port)
    except ValueError: return None
    return {'proto': 'vless', 'name': name.strip(), 'uuid': uuid, 'host': host,
            'port': port, 'security': g('security', 'none'), 'type': g('type', 'tcp'),
            'flow': g('flow', ''), 'sni': g('sni', ''), 'fp': g('fp', 'chrome'),
            'alpn': g('alpn', ''), 'pbk': g('pbk', ''), 'sid': g('sid', ''),
            'path': unquote(g('path', '')), 'hostHeader': g('host', ''),
            'allowInsecure': g('allowInsecure', '0'), 'serviceName': g('serviceName', ''),
            'tested': True}


def parse_unsupported(url, proto):
    name = 'unknown'
    if '#' in url:
        name = unquote(url.split('#', 1)[1]).strip()
    return {'proto': proto, 'name': name, 'tested': False,
            'reason': f'{proto}: парсер не активирован (все узлы подписки — vless)'}


def parse_subscription(text):
    nodes = []
    for line in text.strip().splitlines():
        line = line.strip()
        if line.startswith('vless://'):
            n = parse_vless(line)
            if n: nodes.append(n)
        elif line.startswith('vmess://'):  nodes.append(parse_unsupported(line, 'vmess'))
        elif line.startswith('trojan://'): nodes.append(parse_unsupported(line, 'trojan'))
        elif line.startswith('ss://'):     nodes.append(parse_unsupported(line, 'ss'))
        elif line.startswith(('hysteria2://', 'hy2://', 'wireguard://', 'wg://')):
            name = unquote(line.split('#', 1)[1]).strip() if '#' in line else 'unknown'
            nodes.append({'proto': 'hysteria2/wg', 'name': name, 'tested': False,
                          'reason': 'Xray не тестирует Hysteria2/Wireguard (И7)'})
    return nodes


def is_bypass(name):
    return any(m in name for m in BYPASS_MARKERS)


def make_xray_config(node, socks_port):
    stream = {'network': node['type']}
    sec = node['security']
    if sec == 'tls':
        stream['security'] = 'tls'
        tls = {'allowInsecure': node['allowInsecure'] in ('1', 'true'),
               'serverName': node['sni'] or node['hostHeader'] or node['host']}
        if node['fp']:   tls['fingerprint'] = node['fp']
        if node['alpn']: tls['alpn'] = [a.strip() for a in node['alpn'].split(',') if a.strip()]
        stream['tlsSettings'] = tls
    elif sec == 'reality':
        stream['security'] = 'reality'
        stream['realitySettings'] = {'serverName': node['sni'],
                                     'fingerprint': node['fp'] or 'chrome',
                                     'publicKey': node['pbk'], 'shortId': node['sid']}
    if node['type'] == 'ws':
        ws = {'path': node['path'] or '/'}
        if node['hostHeader']: ws['headers'] = {'Host': node['hostHeader']}
        stream['wsSettings'] = ws
    elif node['type'] == 'grpc':
        stream['grpcSettings'] = {'serviceName': node['serviceName']}
    user = {'id': node['uuid'], 'encryption': 'none'}
    if node['flow']: user['flow'] = node['flow']
    return {'log': {'loglevel': 'error'},
            'inbounds': [{'tag': 'socks-in', 'port': socks_port, 'listen': '127.0.0.1',
                          'protocol': 'socks', 'settings': {'udp': True, 'auth': 'noauth'}}],
            'outbounds': [{'protocol': 'vless',
                           'settings': {'vnext': [{'address': node['host'], 'port': node['port'],
                                                   'users': [user]}]},
                           'streamSettings': stream}]}


def wait_port(port, timeout=8):
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            socket.create_connection(('127.0.0.1', port), timeout=1).close()
            return True
        except (OSError, socket.timeout):
            time.sleep(0.3)
    return False


def via_socks(port, url, timeout=8):
    proxies = {'http': f'socks5h://127.0.0.1:{port}', 'https': f'socks5h://127.0.0.1:{port}'}
    headers = {'User-Agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) '
               'AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1',
               'Accept-Language': 'en-US,en', 'Cache-Control': 'no-cache'}
    t0 = time.time()
    try:
        r = requests.get(url, proxies=proxies, headers=headers, timeout=timeout, allow_redirects=True)
        return r.status_code, r.text, int((time.time() - t0) * 1000)
    except Exception as e:
        return None, str(e), int((time.time() - t0) * 1000)


def extract_trace(body):
    loc = re.search(r'loc=([A-Z]{2})', body or '')
    ip = re.search(r'ip=([0-9a-fA-F:.]+)', body or '')
    return (loc.group(1) if loc else None), (ip.group(1) if ip else None)


# Каскад гео-сервисов (страна РЕАЛЬНОГО выходного IP, как 2ip). Запрос
# ЧЕРЕЗ туннель. Несколько источников: если один недоступен или не дал
# город — берём следующий. Возвращаем первый со страной И городом,
# а если города нигде нет — первую страну.
GEO_APIS = [
    ('https://api.ip.sb/geoip',                               'country_code', 'city'),
    ('http://ip-api.com/json/?fields=countryCode,city,status', 'countryCode', 'city'),
    ('https://ipwho.is/',                                     'country_code', 'city'),
    ('https://ipinfo.io/json',                                'country',      'city'),
]

def geo_via_proxy(port):
    best_cc = None
    for url, kc, kk in GEO_APIS:
        status, body, _ = via_socks(port, url, timeout=8)
        if not (status and body):
            continue
        try:
            d = json.loads(body)
        except Exception:
            continue
        cc = (d.get(kc) or '').strip().upper() or None
        city = (d.get(kk) or '').strip()
        if cc and city:
            return cc, city          # полный результат — сразу
        if cc and not best_cc:
            best_cc = cc             # страна есть, города нет — запомним
    return best_cc, ''


def chatgpt_live(port):
    # Фактическая проверка ChatGPT: POST chat-requirements. Из рабочего
    # региона -> 200 + token; из заблокированного -> 403 unsupported_country.
    # Проверяет ДОСТУП, а не страну (ловит зарубежные узлы с «ru» в имени).
    proxies = {'http': f'socks5h://127.0.0.1:{port}', 'https': f'socks5h://127.0.0.1:{port}'}
    headers = {'Content-Type': 'application/json',
               'Oai-Device-Id': '00000000-0000-4000-8000-000000000000',
               'User-Agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) '
               'AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1'}
    try:
        r = requests.post('https://chatgpt.com/backend-anon/sentinel/chat-requirements',
                          headers=headers, json={}, proxies=proxies, timeout=12)
    except Exception:
        return 'unknown'
    if r.status_code == 200 and ('token' in r.text or 'persona' in r.text):
        return 'pass'
    if r.status_code == 403 and re.search(r'unsupported_country|not available|VPN', r.text, re.I):
        return 'block'
    return 'unknown'


def service_country(port, svc):
    # Страна, которую видит сам сервис (через его cdn-cgi/trace). None если нет связи.
    url = SERVICE_TRACE.get(svc)
    if not url:
        return None
    status, body, _ = via_socks(port, url, timeout=10)
    if status is None:
        return None
    m = re.search(r'loc=([A-Z]{2})', body or '')
    return m.group(1) if m else None


# Маркеры страницы недоступности Gemini (Google блокирует по IP даже в
# разрешённой стране — напр. на «голых» VPN-узлах). Детект по живому ответу.
GEMINI_BLOCK_RE = re.compile(
    r"(isn'?t|is not|aren'?t|are not) (currently )?(available|supported)"
    r"|not (currently )?(available|supported) (in your|here)"
    r"|unsupported_country", re.I)


def gemini_live(port):
    # Прямая проверка Gemini: 'block' если страница говорит о недоступности,
    # 'pass' если приложение грузится (есть bard-frontend), 'unknown' при сбое.
    status, body, _ = via_socks(port, 'https://gemini.google.com/app', timeout=12)
    if status is None:
        return 'unknown'
    body = body or ''
    if GEMINI_BLOCK_RE.search(body):
        return 'block'
    if status == 200 and ('bard-frontend' in body or 'WIZ_global_data' in body):
        return 'pass'
    return 'unknown'


def decide_by_country(svc, svc_cc, fallback_cc, blocklist):
    # block если страна в блок-листе; pass если страна известна и НЕ в блоке;
    # unknown если страну определить не удалось.
    cc = svc_cc or fallback_cc
    if not cc:
        return 'unknown'
    return 'block' if cc in blocklist.get(svc, []) else 'pass'


def test_node(node, cfg, port=SOCKS_PORT):
    udp_guess = node['type'] != 'ws'
    xcfg = make_xray_config(node, port)
    with tempfile.NamedTemporaryFile('w', suffix='.json', delete=False) as f:
        json.dump(xcfg, f); cfg_path = f.name
    proc = None
    try:
        proc = subprocess.Popen([XRAY_BIN, 'run', '-c', cfg_path],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if not wait_port(port, timeout=8):
            return {'ok': False, 'cf_loc': None, 'country': None, 'geo': '', 'latency': 99999,
                    'error': 'xray-port-timeout', 'services': {}, 'udp': udp_guess}
        time.sleep(0.5)
        status, body, latency = via_socks(port, TRACE_URL, timeout=8)
        if status is None:
            return {'ok': False, 'cf_loc': None, 'country': None, 'geo': '', 'latency': latency,
                    'error': body[:80], 'services': {}, 'udp': udp_guess}
        cf_loc, _out_ip = extract_trace(body)
        country, city = geo_via_proxy(port)
        if country is None:
            country = cf_loc
        block = cfg['block_lists']
        manual = cfg.get('manual_block', {})
        services = {}
        for s in SERVICES:
            if not cfg['verify_ai']:
                services[s] = decide_by_country(s, None, country, block)
                continue
            if s == 'chatgpt':
                live = chatgpt_live(port)
                services[s] = live if live != 'unknown' else decide_by_country(s, None, country, block)
            elif s == 'gemini':
                live = gemini_live(port)
                services[s] = live if live != 'unknown' else decide_by_country(s, None, country, block)
            else:
                svc_cc = service_country(port, s)
                services[s] = decide_by_country(s, svc_cc, country, block)
        # ручные исключения (Диана видит блок — дописывает в конфиг)
        for s in manual.get(node['name'], []):
            if s in services:
                services[s] = 'block'
        return {'ok': True, 'cf_loc': cf_loc, 'country': country, 'geo': city,
                'latency': latency, 'services': services, 'udp': udp_guess,
                'verified': cfg['verify_ai']}
    finally:
        if proc:
            proc.terminate()
            try: proc.wait(timeout=3)
            except subprocess.TimeoutExpired: proc.kill()
        try: os.unlink(cfg_path)
        except OSError: pass


def ewma(old, fresh, wf, wo):
    if old is None: return fresh
    return round(wf * fresh + wo * old, 1)


def update_metrics(name, res, hist, cfg):
    h = hist.get(name, {})
    wf, wo = cfg['ewma_fresh'], cfg['ewma_old']
    health = ewma(h.get('health'), 100 if res.get('ok') else 0, wf, wo)
    prev_stab = h.get('stability')
    if res.get('ok'):
        stability = round(0.9 * (prev_stab if prev_stab is not None else 60) + 0.1 * 100, 1)
    else:
        stability = round(0.5 * (prev_stab if prev_stab is not None else 60), 1)
    svc_scores = dict(h.get('service_scores', {}))
    svc_status = res.get('services', {})
    for s in SERVICES:
        st = svc_status.get(s)
        if st == 'pass':    svc_scores[s] = ewma(svc_scores.get(s), 100, wf, wo)
        elif st == 'block': svc_scores[s] = ewma(svc_scores.get(s), 0, wf, wo)
    samples = (h.get('samples', []) + [{'t': int(time.time()), 'ok': bool(res.get('ok')),
               'country': res.get('country')}])[-cfg['history_len']:]
    hist[name] = {'health': health, 'stability': stability,
                  'service_scores': svc_scores, 'samples': samples,
                  'last_t': int(time.time())}
    return health, stability, svc_scores


def light_of(health, stability, svc_status, last_t, cfg):
    if last_t and (time.time() - last_t) > cfg['stale_hours'] * 3600:
        return 'unknown'
    if any(v == 'block' for v in svc_status.values()): return 'red'
    if health is not None and health < 50:             return 'red'
    tested = [v for v in svc_status.values() if v in ('pass', 'block')]
    all_pass = tested and all(v == 'pass' for v in tested)
    if health and health > 80 and all_pass and stability and stability > 60:
        return 'green'
    return 'yellow'


def main():
    t0 = time.time()
    log('=== routehub-server.py запущен ===')
    cfg = load_config()
    try:
        with open(HISTORY, encoding='utf-8') as f: hist = json.load(f)
    except Exception: hist = {}

    nodes = []
    for sub in cfg['subscriptions']:
        url = os.environ.get(sub.get('url_env', ''), '').strip()
        hwid = os.environ.get(sub.get('hwid_env', ''), '').strip()
        prefix = sub.get('prefix', sub.get('name', ''))
        if not url:
            log(f"Подписка {sub.get('name')}: нет URL в ENV — пропуск.")
            continue
        text = fetch_subscription(url, hwid)
        parsed = parse_subscription(text)
        for n in parsed:
            n['display'] = f"[{prefix}] {n['name']}"
        nodes.extend(parsed)

    if not nodes:
        log('ОШИБКА: узлов не найдено.'); sys.exit(1)
    log(f'Узлов всего: {len(nodes)}')

    random.shuffle(nodes)
    results = {}
    counts = {'green': 0, 'yellow': 0, 'red': 0, 'unknown': 0}
    countries = set()

    testable = []
    for node in nodes:
        name = node['display']
        ntype = 'bypass' if is_bypass(node['name']) else 'normal'
        if not node.get('tested', False):
            results[name] = {'country': None, 'cf_loc': None, 'geo': '', 'type': ntype,
                             'tested': False, 'reason': node.get('reason', 'не тестируется'),
                             'light': 'unknown', 'health': None, 'stability': None,
                             'udp': None, 'services': {}}
            counts['unknown'] += 1
            log(f'  x {name[:42]} -> {results[name]["reason"][:40]}')
        else:
            testable.append((node, ntype))

    workers = max(1, int(cfg.get('concurrency', 1)))
    log(f'Тестирую {len(testable)} узлов, потоков: {workers}')

    import threading
    port_pool = list(range(SOCKS_PORT, SOCKS_PORT + workers))
    pool_lock = threading.Lock()

    def work(item):
        node, ntype = item
        with pool_lock:
            port = port_pool.pop()
        try:
            res = test_node(node, cfg, port)
        except Exception as e:
            res = {'ok': False, 'cf_loc': None, 'country': None, 'geo': '', 'latency': 99999,
                   'error': str(e)[:80], 'services': {}, 'udp': None}
        finally:
            with pool_lock:
                port_pool.append(port)
        return node['display'], ntype, res

    from concurrent.futures import ThreadPoolExecutor, as_completed
    done = 0
    total = len(testable)
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = [ex.submit(work, item) for item in testable]
        for fut in as_completed(futs):
            name, ntype, res = fut.result()
            done += 1
            health, stability, svc_scores = update_metrics(name, res, hist, cfg)
            svc_status = res.get('services', {})
            light = light_of(health, stability, svc_status, hist[name]['last_t'], cfg)
            counts[light] = counts.get(light, 0) + 1
            if res.get('ok') and res.get('country'): countries.add(res['country'])
            results[name] = {
                'country': res.get('country'), 'cf_loc': res.get('cf_loc'),
                'geo': res.get('geo', ''), 'type': ntype, 'udp': res.get('udp'),
                'light': light, 'health': health, 'stability': stability,
                'services': {s: {'status': svc_status.get(s, 'unknown'),
                                 'score': svc_scores.get(s, 0)} for s in SERVICES},
            }
            log(f'  [{done}/{total}] {light} {name[:36]} -> '
                f'cf={res.get("cf_loc")} real={res.get("country")} city={res.get("geo","")[:14]} '
                f'ai={"".join((svc_status.get(s,"?") or "?")[0] for s in SERVICES)} '
                f'h{health} ({res.get("latency","?")}ms)')

    output = {
        'version': 2, 'updated': int(time.time()),
        'updated_iso': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        'verified': cfg['verify_ai'],
        'stats': {'total': len(nodes), 'green': counts['green'],
                  'yellow': counts['yellow'], 'red': counts['red'],
                  'unknown': counts['unknown'], 'countries': len(countries)},
        'nodes': results,
    }
    with open(OUTPUT, 'w', encoding='utf-8') as f:
        json.dump(output, f, ensure_ascii=False, indent=2)
    with open(HISTORY, 'w', encoding='utf-8') as f:
        json.dump(hist, f, ensure_ascii=False, indent=2)
    log(f"Готово за {int(time.time()-t0)}с. "
        f"g{counts['green']} y{counts['yellow']} r{counts['red']} u{counts['unknown']}")


if __name__ == '__main__':
    main()
