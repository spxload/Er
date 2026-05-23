#!/usr/bin/env python3
# =====================================================================
#  test_nodes.py — серверное тестирование узлов Lastdep через Xray.
#
#  Что делает:
#   1. Скачивает подписку Lastdep (с подменой заголовков, как Shadowrocket).
#   2. Парсит все vless-узлы.
#   3. Для каждого узла: поднимает Xray с локальным SOCKS, проверяет
#      страну выхода (chat.openai.com/cdn-cgi/trace) и, опционально,
#      реальную доступность каждого AI.
#   4. Пишет результат в ai-ratings.json.
#
#  Запускается в GitHub Actions или на любом Linux-сервере.
#  Зависимости: requests[socks], бинарь xray в ./xray
#
#  Переменные окружения:
#   SUBSCRIPTION_URL  — ссылка на подписку (обязательно)
#   SUB_HWID          — X-HWID для заголовков (обязательно)
#   XRAY_BIN          — путь к бинарю xray (по умолч. ./xray)
#   OUTPUT_FILE       — куда писать JSON (по умолч. ai-ratings.json)
#   VERIFY_AI         — "1" чтобы делать глубокую проверку AI (медленнее)
# =====================================================================

# --- PATCH: universal node parser ---
import base64

SUPPORTED_SCHEMES = (
    "vless://",
    "vmess://",
    "trojan://",
    "ss://",
    "ssr://",
    "hy2://",
    "hysteria2://",
    "tuic://",
    "wireguard://",
)

def extract_nodes(subscription_text: str):
    text = subscription_text.strip()

    # Попытка decode base64
    decoded_variants = [text]

    for decoder in (
        base64.b64decode,
        base64.urlsafe_b64decode,
    ):
        try:
            padded = text + "=" * (-len(text) % 4)
            decoded = decoder(padded).decode("utf-8", errors="ignore")
            if "://" in decoded:
                decoded_variants.append(decoded)
        except Exception:
            pass

    all_nodes = []

    for variant in decoded_variants:
        for scheme in SUPPORTED_SCHEMES:
            pattern = rf"{re.escape(scheme)}[^\s\"'<>]+"
            matches = re.findall(pattern, variant, flags=re.IGNORECASE)
            all_nodes.extend(matches)

    # Удаляем дубли с сохранением порядка
    unique_nodes = list(dict.fromkeys(all_nodes))

    return unique_nodes

# --- END PATCH ---


import os
import sys
import json
import base64
import socket
import subprocess
import tempfile
import time
from urllib.parse import urlparse, parse_qs, unquote

try:
    import requests
except ImportError:
    print("ОШИБКА: нужен requests. Установите: pip install 'requests[socks]'")
    sys.exit(1)

# ===== КОНФИГ =====
SUB_URL    = os.environ.get('SUBSCRIPTION_URL', '').strip()
SUB_HWID   = os.environ.get('SUB_HWID', '').strip()
XRAY_BIN   = os.environ.get('XRAY_BIN', './xray')
OUTPUT     = os.environ.get('OUTPUT_FILE', 'ai-ratings.json')
VERIFY_AI  = os.environ.get('VERIFY_AI', '0') == '1'
SOCKS_PORT = 10808

# Блок-листы стран для каждого AI
SERVICES = {
    'chatgpt':    ['RU','BY','CN','KP','SY','IR','VE','CU','AF','UA'],
    'claude':     ['RU','BY','CN','KP','SY','IR','VE','CU','AF'],
    'gemini':     ['RU','BY','CN','KP','SY','IR','CU'],
    'grok':       ['RU','BY','CN','KP','IR'],
    'perplexity': ['RU','BY','CN','KP','IR'],
}

# Эндпоинты для глубокой проверки AI (только если VERIFY_AI=1)
VERIFY_ENDPOINTS = {
    'chatgpt':    'https://api.openai.com/compliance/cookie_requirements',
    'claude':     'https://claude.ai/api/bootstrap',
    'gemini':     'https://gemini.google.com/',
    'grok':       'https://grok.com/',
    'perplexity': 'https://www.perplexity.ai/api/auth/session',
}

TRACE_URL = 'https://chat.openai.com/cdn-cgi/trace'

SUB_HEADERS = {
    'X-HWID': SUB_HWID,
    'User-Agent': 'Shadowrocket/3237 CFNetwork/3860.400.51 Darwin/25.3.0 iPhone14,7',
    'X-VER-OS': '26.3.1',
    'X-DEVICE-MODEL': 'iPhone',
    'X-DEVICE-OS': 'iOS',
    'Accept': '*/*',
    'Accept-Language': 'ru',
    'Accept-Encoding': 'gzip, deflate, br',
    'Connection': 'keep-alive',
}


def log(msg):
    print(f'[{time.strftime("%H:%M:%S")}] {msg}', flush=True)


# ===== СКАЧИВАНИЕ ПОДПИСКИ =====
def fetch_subscription():
    if not SUB_URL:
        log('ОШИБКА: не задан SUBSCRIPTION_URL')
        sys.exit(1)
    headers = dict(SUB_HEADERS)
    headers['Host'] = urlparse(SUB_URL).netloc
    log(f'Скачиваю подписку: {SUB_URL[:50]}...')
    r = requests.get(SUB_URL, headers=headers, timeout=30)
    r.raise_for_status()
    body = r.text.strip()
    # Подписка обычно base64
    try:
        decoded = base64.b64decode(body + '=' * (-len(body) % 4)).decode('utf-8', 'ignore')
        if 'vless://' in decoded or 'vmess://' in decoded:
            return decoded
    except Exception:
        pass
    return body


# ===== ПАРСИНГ VLESS =====
def parse_vless(url):
    body = url[len('vless://'):]
    name = 'unknown'
    if '#' in body:
        body, frag = body.split('#', 1)
        name = unquote(frag)
    if '?' in body:
        main, query = body.split('?', 1)
    else:
        main, query = body, ''
    if '@' not in main:
        return None
    uuid, hostport = main.split('@', 1)
    if ':' not in hostport:
        return None
    host, port = hostport.rsplit(':', 1)
    p = parse_qs(query)
    g = lambda k, d='': p.get(k, [d])[0]
    try:
        port = int(port)
    except ValueError:
        return None
    return {
        'name': name, 'uuid': uuid, 'host': host, 'port': port,
        'security': g('security', 'none'),
        'type': g('type', 'tcp'),
        'flow': g('flow', ''),
        'sni': g('sni', ''),
        'fp': g('fp', 'chrome'),
        'alpn': g('alpn', ''),
        'pbk': g('pbk', ''),
        'sid': g('sid', ''),
        'path': unquote(g('path', '')),
        'hostHeader': g('host', ''),
        'allowInsecure': g('allowInsecure', '0'),
        'serviceName': g('serviceName', ''),
    }


def parse_subscription(text):
    nodes = []
    for line in text.strip().splitlines():
        line = line.strip()
        if line.startswith('vless://'):
            n = parse_vless(line)
            if n:
                nodes.append(n)
    return nodes


# ===== ГЕНЕРАЦИЯ XRAY-КОНФИГА =====
def make_xray_config(node, socks_port):
    stream = {'network': node['type']}
    sec = node['security']

    if sec == 'tls':
        stream['security'] = 'tls'
        tls = {'allowInsecure': node['allowInsecure'] in ('1', 'true')}
        sni = node['sni'] or node['hostHeader'] or node['host']
        tls['serverName'] = sni
        if node['fp']:
            tls['fingerprint'] = node['fp']
        if node['alpn']:
            tls['alpn'] = [a.strip() for a in node['alpn'].split(',') if a.strip()]
        stream['tlsSettings'] = tls
    elif sec == 'reality':
        stream['security'] = 'reality'
        stream['realitySettings'] = {
            'serverName': node['sni'],
            'fingerprint': node['fp'] or 'chrome',
            'publicKey': node['pbk'],
            'shortId': node['sid'],
        }

    if node['type'] == 'ws':
        ws = {'path': node['path'] or '/'}
        if node['hostHeader']:
            ws['headers'] = {'Host': node['hostHeader']}
        stream['wsSettings'] = ws
    elif node['type'] == 'grpc':
        stream['grpcSettings'] = {'serviceName': node['serviceName']}

    user = {'id': node['uuid'], 'encryption': 'none'}
    if node['flow']:
        user['flow'] = node['flow']

    return {
        'log': {'loglevel': 'error'},
        'inbounds': [{
            'tag': 'socks-in',
            'port': socks_port,
            'listen': '127.0.0.1',
            'protocol': 'socks',
            'settings': {'udp': False, 'auth': 'noauth'},
        }],
        'outbounds': [{
            'protocol': 'vless',
            'settings': {
                'vnext': [{
                    'address': node['host'],
                    'port': node['port'],
                    'users': [user],
                }]
            },
            'streamSettings': stream,
        }],
    }


# ===== ОЖИДАНИЕ ПОРТА =====
def wait_port(port, timeout=8):
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            s = socket.create_connection(('127.0.0.1', port), timeout=1)
            s.close()
            return True
        except (OSError, socket.timeout):
            time.sleep(0.3)
    return False


# ===== ЗАПРОС ЧЕРЕЗ SOCKS =====
def via_socks(port, url, timeout=8):
    proxies = {
        'http':  f'socks5h://127.0.0.1:{port}',
        'https': f'socks5h://127.0.0.1:{port}',
    }
    headers = {
        'User-Agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) '
                      'AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 '
                      'Mobile/15E148 Safari/604.1',
        'Cache-Control': 'no-cache',
    }
    t0 = time.time()
    try:
        r = requests.get(url, proxies=proxies, headers=headers,
                         timeout=timeout, allow_redirects=True)
        elapsed = int((time.time() - t0) * 1000)
        return r.status_code, r.text, elapsed
    except Exception as e:
        elapsed = int((time.time() - t0) * 1000)
        return None, str(e), elapsed


def extract_country(body):
    import re
    m = re.search(r'loc=([A-Z]{2})', body or '')
    return m.group(1) if m else None


# ===== ПРОВЕРКА AI-ЭНДПОИНТОВ =====
def verify_ai(port, svc):
    url = VERIFY_ENDPOINTS.get(svc)
    if not url:
        return 'unknown'
    status, body, _ = via_socks(port, url, timeout=10)
    if status is None:
        return 'unknown'
    body = body or ''
    import re
    if svc == 'chatgpt':
        if status == 403 and re.search(r'unsupported_country|not supported', body, re.I):
            return 'block'
        if status in (200, 401, 405, 400):
            return 'pass'
    elif svc == 'claude':
        if status == 451:
            return 'block'
        if status == 403 and re.search(r'region|country|unsupported', body, re.I):
            return 'block'
        if status in (200, 401, 400):
            return 'pass'
    elif svc == 'gemini':
        if re.search(r'not (currently )?supported in your (country|region)', body, re.I):
            return 'block'
        if status == 200:
            return 'pass'
    elif svc == 'grok':
        if status in (403, 451):
            return 'block'
        if status == 200:
            return 'pass'
    elif svc == 'perplexity':
        if status in (403, 451):
            return 'block'
        if status in (200, 401):
            return 'pass'
    return 'unknown'


# ===== ТЕСТ ОДНОГО УЗЛА =====
def test_node(node):
    cfg = make_xray_config(node, SOCKS_PORT)
    with tempfile.NamedTemporaryFile('w', suffix='.json', delete=False) as f:
        json.dump(cfg, f)
        cfg_path = f.name

    proc = None
    try:
        proc = subprocess.Popen(
            [XRAY_BIN, 'run', '-c', cfg_path],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        if not wait_port(SOCKS_PORT, timeout=8):
            return {'ok': False, 'country': None, 'latency': 99999,
                    'error': 'xray-port-timeout', 'services': {}}

        time.sleep(0.5)  # дать xray прогреться

        # 1. Страна выхода
        status, body, latency = via_socks(SOCKS_PORT, TRACE_URL, timeout=8)
        if status is None:
            return {'ok': False, 'country': None, 'latency': latency,
                    'error': body[:80], 'services': {}}
        country = extract_country(body)
        if not country:
            return {'ok': False, 'country': None, 'latency': latency,
                    'error': 'no-loc-in-response', 'services': {}}

        # 2. Услуги по стране
        services = {}
        for svc, blocked in SERVICES.items():
            services[svc] = 'block' if country in blocked else 'pass'

        # 3. Глубокая проверка AI (опционально)
        if VERIFY_AI:
            for svc in SERVICES:
                if services[svc] == 'pass':
                    v = verify_ai(SOCKS_PORT, svc)
                    if v == 'block':
                        services[svc] = 'block'

        return {'ok': True, 'country': country, 'latency': latency,
                'services': services, 'verified': VERIFY_AI}
    finally:
        if proc:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
        try:
            os.unlink(cfg_path)
        except OSError:
            pass


# ===== MAIN =====
def main():
    t0 = time.time()
    log('=== test_nodes.py запущен ===')

    text = fetch_subscription()
    nodes = parse_subscription(text)
    log(f'Узлов в подписке: {len(nodes)}')
    if not nodes:
        log('ОШИБКА: не найдено поддерживаемых узлов')
        sys.exit(1)

    results = {}
    countries = set()
    ok_count = 0

    for i, node in enumerate(nodes, 1):
        name = node['name']
        try:
            r = test_node(node)
        except Exception as e:
            r = {'ok': False, 'country': None, 'latency': 99999,
                 'error': str(e)[:80], 'services': {}}
        results[name] = r
        if r['ok']:
            ok_count += 1
            countries.add(r['country'])
        flag = '✓' if r['ok'] else '✗'
        log(f'  [{i}/{len(nodes)}] {flag} {name[:40]} → '
            f'{r.get("country") or r.get("error","?")} ({r["latency"]}ms)')

    output = {
        'updated': int(time.time()),
        'updated_iso': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        'verified': VERIFY_AI,
        'stats': {
            'total': len(nodes),
            'ok': ok_count,
            'failed': len(nodes) - ok_count,
            'countries': len(countries),
        },
        'nodes': results,
    }

    with open(OUTPUT, 'w', encoding='utf-8') as f:
        json.dump(output, f, ensure_ascii=False, indent=2)

    elapsed = int(time.time() - t0)
    log(f'=== Готово за {elapsed}с · {ok_count}/{len(nodes)} ok · '
        f'{len(countries)} стран · файл: {OUTPUT} ===')


if __name__ == '__main__':
    main()
