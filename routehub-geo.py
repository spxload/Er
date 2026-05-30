#!/usr/bin/env python3
# =====================================================================
#  routehub-geo.py — достоверное определение гео и типа выходного IP.
#  Используется routehub-server.py. Запросы идут ЧЕРЕЗ туннель узла.
#
#  СТРАНА: взвешенное голосование независимых источников (~99%).
#    ip-api, ipinfo, ipwho.is, ipapi.co, freeipapi, Cloudflare loc=,
#    + офлайн MaxMind (если базы скачаны). ip.sb/geojs НЕ голосуют
#    отдельно (берут данные из MaxMind — коррелируют).
#  ТИП IP: datacenter/hosting (ASN-списки + поле hosting) | vpn/proxy | residential.
#  ГОРОД: reverse-DNS (OVH/Hetzner/IATA коды) -> базы -> уровень уверенности.
#  Возвращает: country, country_conf, city, city_conf, ip_type, asn, org.
#  Честно: страна ~99%, город хуже, тип «датацентр» надёжен, «VPN» — нет.
# =====================================================================
import json, re, socket

# reverse-DNS коды дата-центров -> город (OVH 3-буквенные + IATA + Hetzner)
DC_CODE_CITY = {
    'gra':'Gravelines','rbx':'Roubaix','sbg':'Strasbourg','bhs':'Beauharnois',
    'waw':'Warsaw','fra':'Frankfurt','lon':'London','par':'Paris','sgp':'Singapore',
    'syd':'Sydney','vin':'Vint Hill','hil':'Hillsboro','fsn1':'Falkenstein',
    'nbg1':'Nuremberg','hel1':'Helsinki','ash':'Ashburn','sin':'Singapore',
    'ams':'Amsterdam','lhr':'London','cdg':'Paris','iad':'Ashburn','sjc':'San Jose',
    'sfo':'San Francisco','nrt':'Tokyo','hnd':'Tokyo','yyz':'Toronto','ord':'Chicago',
    'dfw':'Dallas','lax':'Los Angeles','mia':'Miami','arn':'Stockholm','vie':'Vienna',
    'zrh':'Zurich','mad':'Madrid','mil':'Milan','dub':'Dublin',
}

# Крупные дата-центр/хостинг ASN (для типа IP).
DATACENTER_ASNS = {
    16276:'OVH', 24940:'Hetzner', 14061:'DigitalOcean', 20473:'Vultr/Choopa',
    63949:'Linode', 16509:'AWS', 14618:'AWS', 8075:'Microsoft', 15169:'Google',
    45102:'Alibaba', 132203:'Tencent', 51167:'Contabo', 49505:'Selectel',
    200019:'Alexhost', 9009:'M247', 49981:'WorldStream', 60781:'LeaseWeb',
}


def parse_geo_response(url, body):
    """Нормализует ответ известных гео-API к (cc, city, asn, org, hosting, proxy)."""
    try:
        d = json.loads(body)
    except Exception:
        return None
    cc = city = org = None; asn = None; hosting = proxy = False
    if 'ip-api.com' in url:
        cc=d.get('countryCode'); city=d.get('city'); org=d.get('isp') or d.get('org')
        m=re.match(r'AS(\d+)', d.get('as') or ''); asn=int(m.group(1)) if m else None
        hosting=bool(d.get('hosting')); proxy=bool(d.get('proxy'))
    elif 'ipwho.is' in url:
        cc=d.get('country_code'); city=d.get('city')
        conn=d.get('connection') or {}; org=conn.get('org') or conn.get('isp'); asn=conn.get('asn')
        sec=d.get('security') or {}; hosting=bool(sec.get('hosting')); proxy=bool(sec.get('proxy') or sec.get('vpn'))
    elif 'ipinfo.io' in url:
        cc=d.get('country') or d.get('country_code'); city=d.get('city'); org=d.get('org') or d.get('as_name')
        m=re.search(r'AS(\d+)', (d.get('org') or d.get('asn') or '')); asn=int(m.group(1)) if m else None
    elif 'ipapi.co' in url:
        cc=d.get('country_code'); city=d.get('city'); org=d.get('org'); asn_s=d.get('asn') or ''
        m=re.match(r'AS(\d+)',asn_s); asn=int(m.group(1)) if m else None
    elif 'freeipapi' in url:
        cc=d.get('countryCode'); city=d.get('cityName'); org=d.get('asnOrganization'); asn=d.get('asn')
        proxy=bool(d.get('isProxy'))
    if cc: cc=cc.strip().upper()
    return {'cc':cc,'city':(city or '').strip() or None,'asn':asn,'org':org,
            'hosting':hosting,'proxy':proxy} if cc else None


def reverse_dns(ip):
    try:
        return socket.gethostbyaddr(ip)[0].lower()
    except Exception:
        return ''


def city_from_ptr(ptr):
    """Город из reverse-DNS по кодам дата-центров (OVH/Hetzner/IATA)."""
    if not ptr:
        return None
    for t in re.split(r'[.\-_]', ptr):
        if t in DC_CODE_CITY:
            return DC_CODE_CITY[t]
    return None


def consolidate(sources, cf_loc, maxmind, ptr):
    """
    sources: нормализованные dict из parse_geo_response (онлайн API через туннель).
    cf_loc: страна из cloudflare cdn-cgi/trace (или None).
    maxmind: dict {'cc','city','asn','org'} из офлайн MaxMind (или None).
    ptr: reverse-DNS хостнейм выходного IP.
    Возвращает консолидированный результат с уровнями уверенности.
    """
    # ---- СТРАНА: взвешенное голосование ----
    votes = {}
    def add(cc, w):
        if cc: votes[cc] = votes.get(cc, 0) + w
    if maxmind: add(maxmind.get('cc'), 2)
    for s in sources:
        add(s['cc'], 2 if s.get('_src') in ('ip-api','ipinfo') else 1)
    add(cf_loc, 1)
    country = None; country_conf = 0.0
    if votes:
        total = sum(votes.values())
        country = max(votes, key=votes.get)
        country_conf = round(votes[country] / total, 2)

    # ---- ASN / ORG ----
    asn = org = None
    pool = ([maxmind] + sources) if maxmind else sources
    for s in pool:
        if s and s.get('asn'): asn = asn or s['asn']
        if s and s.get('org'): org = org or s['org']

    # ---- ТИП IP ----
    hosting = any(s.get('hosting') for s in sources)
    proxy   = any(s.get('proxy') for s in sources)
    if asn in DATACENTER_ASNS:
        hosting = True
    ip_type = 'datacenter' if hosting else ('vpn/proxy' if proxy else 'residential?')

    # ---- ГОРОД: PTR -> MaxMind -> консенсус онлайн ----
    city = city_from_ptr(ptr); city_conf = 'high' if city else None
    if not city and maxmind and maxmind.get('city'):
        city = maxmind['city']; city_conf = 'medium'
    if not city:
        ccities = {}
        for s in sources:
            if s.get('city'): ccities[s['city']] = ccities.get(s['city'],0)+1
        if ccities:
            city = max(ccities, key=ccities.get)
            city_conf = 'medium' if ccities[city] > 1 else 'low'
    if not city:
        city_conf = 'none'

    return {'country':country,'country_conf':country_conf,
            'city':city or '','city_conf':city_conf,
            'ip_type':ip_type,'asn':asn,'org':org}
