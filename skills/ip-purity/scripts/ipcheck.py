#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ipcheck —— 一键 IP 纯净度检测

并发查询多家主流免费 IP 库，汇总后给出：IP 类型（住宅 / 机房 / 移动）、
代理/VPN 标记、风险分、黑名单、是否原生 IP，以及 0-100 的综合评分和使用建议。

只依赖 Python 3.7+ 标准库。

用法：
    python3 ipcheck.py                      # 检测本机出口 IP
    python3 ipcheck.py 1.2.3.4 5.6.7.8      # 检测指定 IP
    python3 ipcheck.py -f ips.txt           # 批量检测（每行一个 IP，或 ip:port:user:pass 代理）
    python3 ipcheck.py -x http://u:p@h:port # 经代理取出口 IP 再检测（socks5 需要系统有 curl）
    python3 ipcheck.py --json               # 输出 JSON（给脚本 / AI 用）

可选 API Key（环境变量，有就自动启用）：
    IPQS_KEY        IPQualityScore
    ABUSEIPDB_KEY   AbuseIPDB
    IPINFO_TOKEN    ipinfo.io（提高额度）
"""
from __future__ import annotations

import argparse
import concurrent.futures as cf
import ipaddress
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

__version__ = "1.1.0"

UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"
TIMEOUT = 10

# ASN / 运营商名称里出现这些词，基本可以认定是机房 / 云
HOSTING_KEYWORDS = [
    "amazon", "aws", "google cloud", "google llc", "microsoft", "azure", "oracle", "alibaba", "aliyun",
    "tencent", "huawei cloud", "digitalocean", "linode", "akamai", "vultr", "choopa", "hetzner", "ovh",
    "contabo", "leaseweb", "m247", "datacamp", "cdn77", "cloudflare", "fastly", "hostinger", "ionos",
    "scaleway", "online s.a.s", "dmit", "bandwagon", "it7", "racknerd", "colocrossing", "psychz",
    "quadranet", "multacom", "zenlayer", "cogent", "gtt", "hosting", "host", "server", "datacenter",
    "data center", "cloud", "vps", "dedicated", "colo", "idc", "internet data center", "ucloud",
    "kamatera", "upcloud", "buyvm", "frantech", "g-core", "gcore", "stark industries", "aeza",
]
RESIDENTIAL_HINTS = ["comcast", "charter", "spectrum", "verizon", "at&t", "cox ", "frontier", "centurylink",
                     "bt ", "virgin media", "sky ", "telekom", "orange", "vodafone", "ntt", "softbank", "kddi",
                     "chunghwa", "hinet", "rogers", "bell canada", "telstra", "optus", "singtel", "starhub",
                     "china telecom", "china unicom", "china mobile", "pldt", "telus", "shaw", "kt corp",
                     "sk broadband", "lg uplus", "hkbn", "hong kong broadband", "pccw", "netvigator"]

TYPE_CN = {"residential": "住宅", "datacenter": "机房", "mobile": "移动", "business": "商业",
           "education": "教育", "government": "政府", None: "未知"}


# ───────────────────────────── 工具函数 ─────────────────────────────

def http_get(url, headers=None, timeout=None, raw=False):
    h = {"User-Agent": UA, "Accept": "application/json, text/html;q=0.9, */*;q=0.8"}
    if headers:
        h.update(headers)
    req = urllib.request.Request(url, headers=h)
    with urllib.request.urlopen(req, timeout=timeout or TIMEOUT) as r:
        data = r.read().decode("utf-8", "replace")
    return data if raw else json.loads(data)


def is_public_ip(s):
    try:
        ip = ipaddress.ip_address(s.strip())
        return ip.is_global
    except ValueError:
        return False


def keyword_type(name):
    """按名称关键词粗判类型，作为补充信号。"""
    if not name:
        return None
    n = " " + name.lower() + " "
    for k in HOSTING_KEYWORDS:
        if k in n:
            return "datacenter"
    for k in RESIDENTIAL_HINTS:
        if k in n:
            return "residential"
    return None


def yesno(v):
    if isinstance(v, bool):
        return v
    if isinstance(v, str):
        v = v.strip().lower()
        if v in ("yes", "true", "1", "y"):
            return True
        if v in ("no", "false", "0", "n"):
            return False
    if isinstance(v, (int, float)):
        return bool(v)
    return None


def empty(name):
    return {"source": name, "ok": False, "error": None, "country": None, "country_code": None,
            "region": None, "city": None, "asn": None, "org": None, "isp": None, "type": None,
            "proxy": None, "vpn": None, "tor": None, "hosting": None, "abuser": None, "risk": None,
            "asn_country": None, "note": None,
            # 该来源"类型判断"的可信度：有专门检测数据的 = 1.0，只按名称关键词猜的 = 0.5
            "w": 1.0}


# ───────────────────────────── 各数据源 ─────────────────────────────
# 每个函数返回统一结构（见 empty()）。失败时 ok=False 并写 error。

def src_ipapi_com(ip):
    r = empty("ip-api.com")
    d = http_get(f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,regionName,city,"
                 f"isp,org,as,mobile,proxy,hosting,query")
    if d.get("status") != "success":
        r["error"] = d.get("message", "failed")
        return r
    r.update(ok=True, country=d.get("country"), country_code=d.get("countryCode"), region=d.get("regionName"),
             city=d.get("city"), isp=d.get("isp"), org=d.get("org"), proxy=d.get("proxy"),
             hosting=d.get("hosting"))
    m = re.match(r"AS(\d+)", d.get("as") or "")
    r["asn"] = int(m.group(1)) if m else None
    if d.get("hosting"):
        r["type"] = "datacenter"
    elif d.get("mobile"):
        r["type"] = "mobile"
    else:
        # "不是机房"不等于"是住宅"，只算半票
        r["type"], r["w"] = "residential", 0.5
    return r


def src_ipapi_is(ip):
    r = empty("ipapi.is")
    d = http_get(f"https://api.ipapi.is/?q={ip}")
    if d.get("error"):
        r["error"] = str(d.get("error"))
        return r
    loc = d.get("location") if isinstance(d.get("location"), dict) else {}
    comp = d.get("company") if isinstance(d.get("company"), dict) else {}
    asn = d.get("asn") if isinstance(d.get("asn"), dict) else {}
    r.update(ok=True,
             country=loc.get("country") or d.get("country"),
             country_code=loc.get("country_code"),
             region=loc.get("state") or d.get("region"),
             city=loc.get("city") or d.get("city"),
             org=comp.get("name") or (d.get("company") if isinstance(d.get("company"), str) else None),
             isp=asn.get("org"),
             asn_country=(asn.get("country") or "").upper() or None)
    if asn.get("asn"):
        r["asn"] = asn.get("asn")
    elif isinstance(d.get("asn"), str):
        m = re.match(r"AS(\d+)", d["asn"])
        r["asn"] = int(m.group(1)) if m else None
    if "is_datacenter" in d:  # 完整版字段（部分 IP / 额度下才返回）
        r.update(hosting=d.get("is_datacenter"), proxy=d.get("is_proxy"), vpn=d.get("is_vpn"),
                 tor=d.get("is_tor"), abuser=d.get("is_abuser"))
        ctype = (comp.get("type") or asn.get("type") or "").lower()
        if d.get("is_datacenter") or ctype == "hosting":
            r["type"] = "datacenter"
        elif d.get("is_mobile"):
            r["type"] = "mobile"
        elif ctype in ("isp",):
            r["type"] = "residential"
        elif ctype in ("business", "education", "government", "banking"):
            r["type"] = "business" if ctype == "banking" else ctype
        s = str(comp.get("abuser_score") or "")
        m = re.match(r"([\d.]+)", s)
        if m:
            r["risk"] = min(100, round(float(m.group(1)) * 100))
    else:
        r["note"] = "免费额度只返回地理信息"
    return r


def src_proxycheck(ip):
    r = empty("proxycheck.io")
    d = http_get(f"https://proxycheck.io/v2/{ip}?vpn=1&asn=1&risk=1")
    if d.get("status") not in ("ok", "warning") or ip not in d:
        r["error"] = d.get("message", d.get("status", "failed"))
        return r
    x = d[ip]
    t = (x.get("type") or "").lower()
    r.update(ok=True, country=x.get("country"), country_code=x.get("isocode"), region=x.get("region"),
             city=x.get("city"), org=x.get("organisation"), isp=x.get("provider"),
             proxy=yesno(x.get("proxy")), risk=x.get("risk"))
    m = re.match(r"AS(\d+)", x.get("asn") or "")
    r["asn"] = int(m.group(1)) if m else None
    r["vpn"] = t == "vpn"
    r["tor"] = t == "tor"
    if t in ("hosting", "vpn", "socks", "socks4", "socks5", "http", "https", "compromised server"):
        r["type"] = "datacenter" if t in ("hosting", "vpn") else None
        r["hosting"] = t == "hosting"
    elif t == "residential":
        r["type"] = "residential"
    elif t == "wireless":
        r["type"] = "mobile"
    elif t == "business":
        r["type"] = "business"
    if t:
        r["note"] = f"type={x.get('type')}"
    return r


def src_ipinfo(ip):
    r = empty("ipinfo.io")
    tok = os.environ.get("IPINFO_TOKEN")
    d = http_get(f"https://ipinfo.io/{ip}/json" + (f"?token={tok}" if tok else ""))
    if d.get("error") or d.get("bogon"):
        r["error"] = str(d.get("error") or "bogon")
        return r
    org = d.get("org") or ""
    m = re.match(r"AS(\d+)\s*(.*)", org)
    r.update(ok=True, country_code=d.get("country"), region=d.get("region"), city=d.get("city"),
             asn=int(m.group(1)) if m else None, org=m.group(2) if m else org)
    host = d.get("hostname") or ""
    r["type"] = keyword_type(r["org"])
    r["w"] = 0.5
    # 反解析主机名里的线索：住宅宽带常带 dsl/cable/fiber/dyn/pool/res 等
    if host:
        r["note"] = f"hostname={host}"
        hl = host.lower()
        if re.search(r"(dsl|cable|fiber|fios|ftth|dyn|dhcp|pool|res\.|residential|broadband|cpe|home|pppoe)", hl):
            r["type"] = r["type"] or "residential"
        elif re.search(r"(vps|server|host|cloud|compute|ec2|static\.|colo|dedi)", hl):
            r["type"] = "datacenter"
    if d.get("privacy"):
        p = d["privacy"]
        r.update(vpn=p.get("vpn"), proxy=p.get("proxy"), tor=p.get("tor"), hosting=p.get("hosting"))
        if p.get("hosting"):
            r["type"] = "datacenter"
    return r


def src_ipwhois(ip):
    r = empty("ipwho.is")
    d = http_get(f"https://ipwho.is/{ip}")
    if not d.get("success"):
        r["error"] = d.get("message", "failed")
        return r
    c = d.get("connection") or {}
    r.update(ok=True, country=d.get("country"), country_code=d.get("country_code"), region=d.get("region"),
             city=d.get("city"), asn=c.get("asn"), org=c.get("org"), isp=c.get("isp"))
    r["type"] = keyword_type(c.get("org")) or keyword_type(c.get("isp"))
    r["w"] = 0.5
    return r


def src_ipsb(ip):
    r = empty("ip.sb")
    d = http_get(f"https://api.ip.sb/geoip/{ip}")
    r.update(ok=True, country=d.get("country"), country_code=d.get("country_code"), region=d.get("region"),
             city=d.get("city"), asn=d.get("asn"), org=d.get("organization"), isp=d.get("asn_organization"))
    r["type"] = keyword_type(d.get("organization")) or keyword_type(d.get("asn_organization"))
    r["w"] = 0.5
    return r


def src_scamalytics(ip):
    r = empty("scamalytics")
    html = http_get(f"https://scamalytics.com/ip/{ip}", raw=True)
    m = re.search(r'"score"\s*:\s*"(\d+)"', html) or re.search(r"Fraud Score:\s*(\d+)", html)
    if not m:
        r["error"] = "页面解析失败（可能被限流）"
        return r
    r["ok"] = True
    r["risk"] = int(m.group(1))
    lvl = re.search(r'"risk"\s*:\s*"(\w+)"', html)
    flags = dict((k.strip(), v) for k, v in
                 re.findall(r"<th>([^<]+)</th>\s*<td><div class=\"risk (yes|no)\">", html))

    def f(name):
        return {"yes": True, "no": False}.get(flags.get(name))

    r.update(vpn=f("Anonymizing VPN"), tor=f("Tor Exit Node"), hosting=f("Server"),
             proxy=(f("Public Proxy") or f("Web Proxy") or f("Residential Proxy")) if flags else None)
    bl = [k for k in ("Firehol", "IP2ProxyLite", "IPsum", "Spamhaus", "X4Bnet Spambot") if f(k)]
    if bl:
        r["abuser"] = True
    if r["hosting"]:
        r["type"] = "datacenter"
    org = re.search(r"<th>Organization Name</th>\s*<td>([^<]*)</td>", html)
    if org:
        r["org"] = org.group(1).strip()
    r["note"] = f"risk={lvl.group(1) if lvl else '?'}" + (f"; 命中: {','.join(bl)}" if bl else "")
    return r


DNSBLS = ["zen.spamhaus.org", "bl.spamcop.net", "b.barracudacentral.org", "psbl.surriel.com"]


def src_dnsbl(ip):
    r = empty("DNSBL")
    try:
        if ipaddress.ip_address(ip).version != 4:
            r["error"] = "仅支持 IPv4"
            return r
    except ValueError:
        r["error"] = "invalid"
        return r
    rev = ".".join(reversed(ip.split(".")))
    hits, checked = [], 0

    def q(bl):
        try:
            a = socket.gethostbyname(f"{rev}.{bl}")
            # 127.255.255.x 是 Spamhaus 对公共 DNS 的拒绝码，不算命中
            return bl, (None if a.startswith("127.255.255.") else a.startswith("127."))
        except socket.gaierror:
            return bl, False
        except Exception:
            return bl, None

    with cf.ThreadPoolExecutor(len(DNSBLS)) as ex:
        for bl, hit in ex.map(q, DNSBLS):
            if hit is None:
                continue
            checked += 1
            if hit:
                hits.append(bl)
    # 邮件黑名单单独计分，不计入"滥用"投票
    r.update(ok=checked > 0, note=f"{len(hits)}/{checked} 命中" + (f": {', '.join(hits)}" if hits else ""))
    if not checked:
        r["error"] = "DNS 查询全部失败"
    r["dnsbl_hits"] = hits
    r["dnsbl_checked"] = checked
    return r


def src_ipquery(ip):
    r = empty("ipquery.io")
    d = http_get(f"https://api.ipquery.io/{ip}?format=json")
    isp, loc, risk = d.get("isp") or {}, d.get("location") or {}, d.get("risk") or {}
    if not risk and not isp:
        r["error"] = "无数据"
        return r
    m = re.match(r"AS(\d+)", str(isp.get("asn") or ""))
    r.update(ok=True, country=loc.get("country"), country_code=loc.get("country_code"), region=loc.get("state"),
             city=loc.get("city"), asn=int(m.group(1)) if m else None, org=isp.get("org"), isp=isp.get("isp"),
             proxy=risk.get("is_proxy"), vpn=risk.get("is_vpn"), tor=risk.get("is_tor"),
             hosting=risk.get("is_datacenter"), risk=risk.get("risk_score"))
    if risk.get("is_datacenter"):
        r["type"] = "datacenter"
    elif risk.get("is_mobile"):
        r["type"] = "mobile"
    elif "is_datacenter" in risk:
        r["type"], r["w"] = "residential", 0.5
    return r


def src_iplocate(ip):
    r = empty("iplocate.io")
    d = http_get(f"https://www.iplocate.io/api/lookup/{ip}")
    if d.get("error"):
        r["error"] = str(d["error"])
        return r
    asn, pv, comp = d.get("asn") or {}, d.get("privacy") or {}, d.get("company") or {}
    m = re.match(r"AS(\d+)", str(asn.get("asn") or ""))
    r.update(ok=True, country=d.get("country"), country_code=d.get("country_code"), region=d.get("subdivision"),
             city=d.get("city"), asn=int(m.group(1)) if m else None, org=comp.get("name"), isp=asn.get("name"),
             asn_country=(asn.get("country_code") or "").upper() or None,
             proxy=pv.get("is_proxy"), vpn=pv.get("is_vpn"), tor=pv.get("is_tor"),
             hosting=pv.get("is_hosting"), abuser=pv.get("is_abuser"))
    at = (asn.get("type") or comp.get("type") or "").lower()
    if pv.get("is_hosting") or at == "hosting":
        r["type"] = "datacenter"
    elif at == "isp":
        r["type"] = "residential"
    elif at in ("business", "education", "government"):
        r["type"] = at
    if pv.get("is_icloud_relay"):
        r["note"] = "iCloud 私人中继"
    return r


def src_ip2location(ip):
    r = empty("ip2location.io")
    d = http_get(f"https://api.ip2location.io/?ip={ip}")
    if d.get("error"):
        r["error"] = str((d["error"] or {}).get("error_message", d["error"]))
        return r
    r.update(ok=True, country=d.get("country_name"), country_code=d.get("country_code"), region=d.get("region_name"),
             city=d.get("city_name"), asn=int(d["asn"]) if str(d.get("asn") or "").isdigit() else None,
             isp=d.get("as"), proxy=d.get("is_proxy"))
    r["type"] = keyword_type(d.get("as"))
    r["w"] = 0.5
    return r


def src_blackbox(ip):
    # ipinfo.app Blackbox：Y/N。它把机房网段也算进去，所以只当"机房"信号，不当"代理"
    r = empty("ipinfo-blackbox")
    t = http_get(f"https://blackbox.ipinfo.app/lookup/{ip}", raw=True).strip().upper()
    if t not in ("Y", "N"):
        r["error"] = f"未知返回：{t[:20]}"
        return r
    r.update(ok=True, hosting=t == "Y", note="Y=代理/机房网段" if t == "Y" else None)
    if t == "Y":
        r["type"], r["w"] = "datacenter", 0.5
    return r


_TOR = {"set": None}


def src_tor(ip):
    r = empty("Tor 官方出口列表")
    if _TOR["set"] is None:
        txt = http_get("https://check.torproject.org/torbulkexitlist", raw=True)
        _TOR["set"] = set(x.strip() for x in txt.splitlines() if x.strip())
    r.update(ok=True, tor=ip in _TOR["set"])
    return r


def src_greynoise(ip):
    r = empty("GreyNoise")
    try:
        d = http_get(f"https://api.greynoise.io/v3/community/{ip}")
    except urllib.error.HTTPError as e:
        if e.code == 404:  # 没见过这个 IP 在扫描互联网 = 好事
            r.update(ok=True, abuser=False, note="未观察到扫描行为")
            return r
        raise
    cls = d.get("classification")
    r.update(ok=True, note=f"classification={cls}; noise={d.get('noise')}; riot={d.get('riot')}")
    r["abuser"] = cls == "malicious"
    return r


def src_sfs(ip):
    r = empty("StopForumSpam")
    d = http_get(f"https://api.stopforumspam.org/api?ip={ip}&json")
    x = d.get("ip") or {}
    if not d.get("success"):
        r["error"] = d.get("error", "failed")
        return r
    n = int(x.get("frequency") or 0)
    r.update(ok=True, abuser=bool(x.get("appears")), note=f"垃圾注册举报 {n} 次" if n else None)
    if x.get("torexit"):
        r["tor"] = True
    return r


def src_shodan(ip):
    r = empty("Shodan InternetDB")
    try:
        d = http_get(f"https://internetdb.shodan.io/{ip}")
    except urllib.error.HTTPError as e:
        if e.code == 404:
            r.update(ok=True, note="无开放端口记录")
            return r
        raise
    tags = [t.lower() for t in d.get("tags") or []]
    ports = d.get("ports") or []
    r["ok"] = True
    if "proxy" in tags:
        r["proxy"] = True
    if "vpn" in tags:
        r["vpn"] = True
    if "tor" in tags:
        r["tor"] = True
    if "cloud" in tags:
        r["type"], r["w"], r["hosting"] = "datacenter", 0.5, True
    if "malware" in tags or "compromised" in tags:
        r["abuser"] = True
    r["note"] = (f"tags={','.join(tags)}; " if tags else "") + f"ports={','.join(map(str, ports[:12]))}"
    return r


def src_ipqs(ip):
    r = empty("IPQualityScore")
    d = http_get(f"https://ipqualityscore.com/api/json/ip/{os.environ['IPQS_KEY']}/{ip}?strictness=1")
    if not d.get("success"):
        r["error"] = d.get("message", "failed")
        return r
    ct = (d.get("connection_type") or "").lower()
    r.update(ok=True, country_code=d.get("country_code"), region=d.get("region"), city=d.get("city"),
             asn=d.get("ASN"), isp=d.get("ISP"), org=d.get("organization"), proxy=d.get("proxy"),
             vpn=d.get("vpn"), tor=d.get("tor"), abuser=d.get("recent_abuse"), risk=d.get("fraud_score"),
             note=f"connection_type={d.get('connection_type')}")
    r["type"] = {"residential": "residential", "mobile": "mobile", "corporate": "business",
                 "data center": "datacenter", "education": "education"}.get(ct)
    r["hosting"] = ct == "data center"
    return r


def src_abuseipdb(ip):
    r = empty("AbuseIPDB")
    d = http_get(f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90",
                 headers={"Key": os.environ["ABUSEIPDB_KEY"], "Accept": "application/json"})
    x = d.get("data") or {}
    if not x:
        r["error"] = str(d.get("errors") or "failed")
        return r
    ut = (x.get("usageType") or "").lower()
    r.update(ok=True, country_code=x.get("countryCode"), isp=x.get("isp"), tor=x.get("isTor"),
             risk=x.get("abuseConfidenceScore"), abuser=(x.get("abuseConfidenceScore") or 0) >= 25,
             note=f"usage={x.get('usageType')}; reports={x.get('totalReports')}")
    if "data center" in ut or "hosting" in ut:
        r["type"] = "datacenter"
    elif "mobile" in ut:
        r["type"] = "mobile"
    elif "fixed line" in ut or "isp" in ut:
        r["type"] = "residential"
    elif ut:
        r["type"] = "business"
    return r


SOURCES = {
    "ipapi": src_ipapi_com,
    "ipapiis": src_ipapi_is,
    "proxycheck": src_proxycheck,
    "ipinfo": src_ipinfo,
    "ipwhois": src_ipwhois,
    "ipsb": src_ipsb,
    "scamalytics": src_scamalytics,
    "ipquery": src_ipquery,
    "iplocate": src_iplocate,
    "ip2location": src_ip2location,
    "blackbox": src_blackbox,
    "tor": src_tor,
    "greynoise": src_greynoise,
    "sfs": src_sfs,
    "shodan": src_shodan,
    "dnsbl": src_dnsbl,
}
KEYED = {"ipqs": ("IPQS_KEY", src_ipqs), "abuseipdb": ("ABUSEIPDB_KEY", src_abuseipdb)}


def active_sources(only=None):
    s = dict(SOURCES)
    for k, (env, fn) in KEYED.items():
        if os.environ.get(env):
            s[k] = fn
    if only:
        want = [x.strip().lower() for x in only.split(",") if x.strip()]
        s = {k: v for k, v in s.items() if k in want}
    return s


def run_source(name, fn, ip):
    t = time.time()
    try:
        r = fn(ip)
    except urllib.error.HTTPError as e:
        r = empty(name)
        r["error"] = f"HTTP {e.code}" + (" (限流)" if e.code == 429 else "")
    except Exception as e:  # 超时 / 网络问题
        r = empty(name)
        r["error"] = type(e).__name__ + (f": {e}" if str(e) else "")
    r["ms"] = int((time.time() - t) * 1000)
    return r


# ───────────────────────────── 获取出口 IP ─────────────────────────────

MYIP_URLS = ["https://api.ipify.org", "https://ifconfig.me/ip", "https://api.ip.sb/ip", "https://icanhazip.com"]


def normalize_proxy(p):
    """支持 scheme://user:pass@host:port，也支持 Webshare 列表格式 host:port:user:pass。"""
    p = p.strip()
    if "://" in p:
        return p
    parts = p.split(":")
    if len(parts) == 4:
        h, port, u, pw = parts
        return f"http://{urllib.parse.quote(u)}:{urllib.parse.quote(pw)}@{h}:{port}"
    if len(parts) == 2:
        return f"http://{p}"
    return p


def get_my_ip(proxy=None, v6=False):
    urls = ["https://api64.ipify.org", "https://api6.ipify.org"] if v6 else MYIP_URLS
    if proxy:
        proxy = normalize_proxy(proxy)
        scheme = proxy.split("://", 1)[0].lower()
        if scheme.startswith("socks") or shutil.which("curl"):
            if not shutil.which("curl"):
                raise RuntimeError("socks 代理需要系统安装 curl")
            for u in urls:
                try:
                    out = subprocess.run(["curl", "-s", "-m", str(TIMEOUT), "-x", proxy, u],
                                         capture_output=True, text=True, timeout=TIMEOUT + 3).stdout.strip()
                    if is_public_ip(out):
                        return out
                except Exception:
                    continue
            raise RuntimeError("通过代理获取出口 IP 失败（检查代理地址、账号密码）")
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
        for u in urls:
            try:
                out = opener.open(urllib.request.Request(u, headers={"User-Agent": UA}),
                                  timeout=TIMEOUT).read().decode().strip()
                if is_public_ip(out):
                    return out
            except Exception:
                continue
        raise RuntimeError("通过代理获取出口 IP 失败（检查代理地址、账号密码）")
    for u in urls:
        try:
            out = http_get(u, raw=True).strip()
            if is_public_ip(out):
                return out
        except Exception:
            continue
    raise RuntimeError("获取本机出口 IP 失败，请检查网络")


# ───────────────────────────── 汇总与判断 ─────────────────────────────

def _vote(results, key):
    vals = [r[key] for r in results if r["ok"] and r.get(key) is not None]
    return sum(1 for v in vals if v), len(vals)


def analyze(ip, results):
    ok = [r for r in results if r["ok"]]

    # 位置：多数票
    def majority(key):
        c = {}
        for r in ok:
            v = r.get(key)
            if v:
                c[v] = c.get(v, 0) + 1
        return max(c, key=c.get) if c else None

    cc_votes = {}
    for r in ok:
        if r.get("country_code"):
            cc_votes[r["country_code"].upper()] = cc_votes.get(r["country_code"].upper(), 0) + 1
    country_code = max(cc_votes, key=cc_votes.get) if cc_votes else None
    asn = majority("asn")
    org = majority("org")
    isp = majority("isp")

    # ── 类型：加权投票。专门检测数据 = 1 票，按名称关键词猜的 = 0.5 票 ──
    # 机房信号优先（风控偏保守）：机房票数占 40% 及以上就判为机房
    tv = {}
    for r in ok:
        if r.get("type"):
            tv[r["type"]] = round(tv.get(r["type"], 0) + r.get("w", 1.0), 1)
    type_total = sum(tv.values())
    dc = tv.get("datacenter", 0)
    dc_ratio = dc / type_total if type_total else 0
    if not type_total:
        ip_type = None
    elif dc_ratio >= 0.4:
        ip_type = "datacenter"
    else:
        ip_type = max(tv, key=tv.get)

    proxy_y, proxy_n = _vote(results, "proxy")
    vpn_y, vpn_n = _vote(results, "vpn")
    tor_y, tor_n = _vote(results, "tor")
    abuse_y, abuse_n = _vote(results, "abuser")
    hit_by = {k: [r["source"] for r in ok if r.get(k)] for k in ("proxy", "vpn", "tor", "abuser")}
    risks = {r["source"]: r["risk"] for r in ok if isinstance(r.get("risk"), (int, float))}
    avg_risk = round(sum(risks.values()) / len(risks)) if risks else None
    max_risk = max(risks.values()) if risks else None
    dnsbl = next((r for r in ok if r["source"] == "DNSBL"), None)
    dnsbl_hits = len(dnsbl.get("dnsbl_hits", [])) if dnsbl else 0

    # 原生 / 广播：ASN 注册国 ≠ IP 定位国，或各库定位国不一致
    asn_cc = next((r["asn_country"] for r in ok if r.get("asn_country")), None)
    native = None
    native_note = None
    if country_code:
        if asn_cc and asn_cc != country_code:
            native, native_note = False, f"ASN 注册在 {asn_cc}，IP 定位在 {country_code}，疑似广播 IP"
        elif len(cc_votes) > 1 and max(cc_votes.values()) / sum(cc_votes.values()) < 0.75:
            native, native_note = False, "各库定位国家不一致（" + "/".join(f"{k}:{v}" for k, v in cc_votes.items()) + "），疑似广播 IP"
        elif asn_cc:
            native, native_note = True, "ASN 注册国与定位国一致"
        else:
            native, native_note = True, "各库定位国家基本一致"

    # ── 评分 ──
    # 规则 1（一票否决）：任一来源标记为 代理 / VPN / Tor → 直接 0 分
    # 规则 2（扣分制）：从 100 开始按下面扣
    #   机房          -(30 + 20×机房票占比)     即 -38 ~ -50
    #   商业/教育/政府 -10
    #   类型无法判断   -10
    #   滥用记录       每个来源 -10，最多 -30
    #   风险分         平均分 >10 时 -平均分×0.4；任一来源 ≥75 再 -10
    #   邮件黑名单     每命中一个 -5，最多 -15
    #   疑似广播 IP    -8
    score = 100.0
    reasons = []
    flagged = sorted(set(hit_by["proxy"] + hit_by["vpn"] + hit_by["tor"]))
    if flagged:
        score = 0
        kinds = "/".join(k for k, y in (("代理", proxy_y), ("VPN", vpn_y), ("Tor", tor_y)) if y)
        reasons.append(f"被标记为{kinds}（{', '.join(flagged)}）→ 直接归零")
    else:
        if ip_type == "datacenter":
            pen = 30 + 20 * dc_ratio
            score -= pen
            reasons.append(f"机房 IP（机房票 {dc:g}/{type_total:g}）-{pen:.0f}")
        elif ip_type in ("business", "education", "government"):
            score -= 10
            reasons.append(f"{TYPE_CN[ip_type]}线路 -10")
        elif ip_type is None:
            score -= 10
            reasons.append("无法判断类型 -10")
        if abuse_y:
            pen = min(30, 10 * abuse_y)
            score -= pen
            reasons.append(f"滥用记录（{', '.join(hit_by['abuser'])}）-{pen}")
        if avg_risk is not None and avg_risk > 10:
            pen = round(avg_risk * 0.4)
            score -= pen
            reasons.append(f"平均风险分 {avg_risk} -{pen}")
        if max_risk is not None and max_risk >= 75:
            score -= 10
            reasons.append(f"有来源风险分 ≥75（{max_risk}）-10")
        if dnsbl_hits:
            pen = min(15, 5 * dnsbl_hits)
            score -= pen
            reasons.append(f"邮件黑名单 {dnsbl_hits} 个 -{pen}")
        if native is False:
            score -= 8
            reasons.append("疑似广播 IP -8")
    score = max(0, min(100, round(score)))

    if flagged:
        level, emoji = "代理", "⛔"
    elif score >= 80:
        level, emoji = "纯净", "🟢"
    elif score >= 60:
        level, emoji = "良好", "🟡"
    elif score >= 40:
        level, emoji = "一般", "🟠"
    else:
        level, emoji = "较差", "🔴"

    # ── 用途建议 ──
    advice = []
    if tor_y:
        advice.append("Tor 出口：几乎所有网站都会拦截，不要用于任何账号操作。")
    elif flagged:
        advice.append("已被风控库标记为代理 / VPN：银行、支付、注册、AI 服务大概率会识别，建议换 IP。")
    elif ip_type in ("residential", "mobile") and score >= 80:
        advice.append("住宅 / 移动 IP 且无代理标记：适合银行、支付、注册账号、AI 服务（ChatGPT / Claude）等对风控敏感的场景。")
    elif ip_type in ("residential", "mobile"):
        advice.append("住宅 IP，但有风险分或黑名单记录：日常可用，银行 / 支付类可能偶尔触发验证。")
    elif ip_type == "datacenter":
        advice.append("机房 IP（未被标记代理）：看视频、一般网站没问题；银行、支付、新号注册容易被识别为 VPN。")
    else:
        advice.append("类型不明或为企业线路：一般使用没问题，敏感场景建议先小额 / 小范围试用。")
    if native is False:
        advice.append("疑似广播 IP：部分流媒体 / 地区限定服务可能按 ASN 注册国判断地区。")
    if dnsbl_hits:
        advice.append(f"命中 {dnsbl_hits} 个邮件黑名单：不适合做邮件服务器出口。")
    if len(ok) < 6:
        advice.append(f"只有 {len(ok)} 个来源成功（可能被限流），结论仅供参考，稍后可重试。")

    return {
        "ip": ip,
        "score": score, "level": level, "emoji": emoji, "flagged_by": flagged,
        "type": ip_type, "type_cn": TYPE_CN.get(ip_type, ip_type), "type_votes": tv,
        "country_code": country_code, "country": majority("country"), "city": majority("city"),
        "asn": asn, "org": org, "isp": isp,
        "native": native, "native_note": native_note,
        "proxy": [proxy_y, proxy_n], "vpn": [vpn_y, vpn_n], "tor": [tor_y, tor_n], "abuse": [abuse_y, abuse_n],
        "hit_by": hit_by,
        "risk_scores": risks, "avg_risk": avg_risk, "max_risk": max_risk,
        "dnsbl": dnsbl.get("note") if dnsbl else None,
        "reasons": reasons, "advice": advice,
        "sources_ok": len(ok), "sources_total": len(results),
        "sources": results,
    }


def check_ip(ip, only=None):
    srcs = active_sources(only)
    with cf.ThreadPoolExecutor(max(1, len(srcs))) as ex:
        futs = [ex.submit(run_source, n, f, ip) for n, f in srcs.items()]
        results = [f.result() for f in futs]
    return analyze(ip, results)


# ───────────────────────────── 输出 ─────────────────────────────

class C:
    on = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None
    @classmethod
    def w(cls, code, s):
        return f"\033[{code}m{s}\033[0m" if cls.on else str(s)


def flag_str(pair, bad_word, who=None):
    y, n = pair
    if not n:
        return C.w("2", "无数据")
    if y:
        return C.w("31", f"{bad_word}（{y}/{n}：{', '.join(who or [])}）")
    return C.w("32", f"未标记（0/{n}）")


def render(a):
    L = []
    color = {"纯净": "32", "良好": "33", "一般": "33", "较差": "31", "代理": "31"}[a["level"]]
    L.append(C.w("1;36", f"━━━━━━━━ IP 纯净度检测 · {a['ip']} ━━━━━━━━"))
    loc = " ".join(x for x in [a.get("country") or a.get("country_code"), a.get("city")] if x) or "未知"
    L.append(f"位置    {loc}")
    asn = f"AS{a['asn']}" if a.get("asn") else ""
    L.append(f"运营商  {' '.join(x for x in [asn, a.get('isp') or '', ('/ ' + a['org']) if a.get('org') and a.get('org') != a.get('isp') else ''] if x) or '未知'}")
    tv = "、".join(f"{TYPE_CN.get(k, k)}{v:g}" for k, v in sorted(a["type_votes"].items(), key=lambda x: -x[1]))
    tcol = {"residential": "32", "mobile": "32", "datacenter": "31"}.get(a["type"], "33")
    L.append(f"类型    {C.w(tcol, a['type_cn'])}" + (C.w("2", f"  （投票：{tv}）") if tv else ""))
    if a["native"] is not None:
        L.append(f"原生    {C.w('32', '原生 IP') if a['native'] else C.w('33', '广播 IP')}" + C.w("2", f"  {a['native_note']}"))
    L.append(f"代理    {flag_str(a['proxy'], '被标记为代理', a['hit_by']['proxy'])}")
    L.append(f"VPN     {flag_str(a['vpn'], '被标记为 VPN', a['hit_by']['vpn'])}")
    L.append(f"Tor     {flag_str(a['tor'], 'Tor 出口', a['hit_by']['tor'])}")
    L.append(f"滥用    {flag_str(a['abuse'], '有滥用记录', a['hit_by']['abuser'])}")
    if a["risk_scores"]:
        rs = "  ".join(f"{k} {v}" for k, v in a["risk_scores"].items())
        L.append(f"风险分  {rs}" + C.w("2", "  （0-100，越低越好）"))
    if a.get("dnsbl"):
        L.append(f"黑名单  DNSBL {a['dnsbl']}")
    L.append(C.w("2", "─" * 52))
    L.append(f"综合评分  {C.w('1;' + color, str(a['score']) + '/100')}  {a['emoji']} {C.w('1;' + color, a['level'])}")
    if a["reasons"]:
        L.append(C.w("2", "扣分项    " + "；".join(a["reasons"])))
    for x in a["advice"]:
        L.append(f"建议      {x}")
    return "\n".join(L)


def render_sources(a):
    L = [C.w("2", f"来源明细（{a['sources_ok']}/{a['sources_total']} 成功）")]

    def b(v):
        return "-" if v is None else ("是" if v else "否")

    for r in a["sources"]:
        if not r["ok"]:
            L.append(C.w("2", f"  ✗ {r['source']:<18} {r['error']}"))
            continue
        L.append(f"  ✓ {r['source']:<18} 类型={TYPE_CN.get(r['type'], r['type'])} 代理={b(r['proxy'])} VPN={b(r['vpn'])} "
                 f"机房={b(r['hosting'])} 风险={r['risk'] if r['risk'] is not None else '-'}"
                 + C.w("2", f"  {r['country_code'] or r['country'] or ''} {r['org'] or r['isp'] or ''}"
                       + (f"  [{r['note']}]" if r.get("note") else "")))
    return "\n".join(L)


def render_table(items):
    L = [C.w("1", f"{'IP':<40} {'评分':>4}  {'等级':<4} {'类型':<4} {'代理':<5} {'国家':<4} 运营商")]
    for a in items:
        if "error" in a:
            L.append(f"{a['input']:<40} {C.w('31', '错误: ' + a['error'])}")
            continue
        px = f"{a['proxy'][0]}/{a['proxy'][1]}"
        L.append(f"{a['ip']:<40} {a['score']:>4}  {a['emoji']}{a['level']:<2} {a['type_cn']:<4} {px:<5} "
                 f"{a.get('country_code') or '':<4} {a.get('org') or a.get('isp') or ''}")
    return "\n".join(L)


# ───────────────────────────── 主程序 ─────────────────────────────

def parse_target(line):
    """返回 (标签, ip 或 None, proxy 或 None)。"""
    s = line.strip()
    if not s or s.startswith("#"):
        return None
    if is_public_ip(s):
        return s, s, None
    try:
        ipaddress.ip_address(s)
        return s, None, None  # 内网 / 保留地址
    except ValueError:
        pass
    if "://" in s or s.count(":") in (1, 3):
        return s, None, s
    try:  # 域名
        return s, socket.gethostbyname(s), None
    except Exception:
        return s, None, None


def run_target(label, ip, proxy, only):
    try:
        if proxy:
            ip = get_my_ip(proxy)
        if not ip or not is_public_ip(ip):
            return {"input": label, "error": "不是公网 IP / 无法解析"}
        a = check_ip(ip, only)
        a["input"] = label
        return a
    except Exception as e:
        return {"input": label, "error": str(e)}


def main(argv=None):
    global TIMEOUT
    p = argparse.ArgumentParser(description="一键 IP 纯净度检测（多源免费 IP 库汇总）")
    p.add_argument("targets", nargs="*", help="IP / 域名 / 代理（host:port:user:pass 或 scheme://...）；留空检测本机")
    p.add_argument("-f", "--file", help="批量文件，每行一个 IP 或代理")
    p.add_argument("-x", "--proxy", help="经此代理获取出口 IP 再检测")
    p.add_argument("-6", "--ipv6", action="store_true", help="检测本机 IPv6 出口")
    p.add_argument("-j", "--json", action="store_true", help="输出 JSON")
    p.add_argument("-v", "--verbose", action="store_true", help="显示每个来源的明细")
    p.add_argument("-s", "--sources", help="只用指定来源，逗号分隔：" + ",".join(list(SOURCES) + list(KEYED)))
    p.add_argument("-t", "--timeout", type=int, default=TIMEOUT, help="单个请求超时秒数（默认 10）")
    p.add_argument("--no-color", action="store_true")
    p.add_argument("-V", "--version", action="version", version=__version__)
    args = p.parse_args(argv)
    TIMEOUT = args.timeout
    if args.no_color or args.json:
        C.on = False

    targets = []
    for t in args.targets:
        x = parse_target(t)
        if x:
            targets.append(x)
    if args.file:
        with open(args.file, encoding="utf-8") as fh:
            for line in fh:
                x = parse_target(line)
                if x:
                    targets.append(x)
    if args.proxy:
        targets.append((args.proxy, None, args.proxy))
    if not targets:
        try:
            ip = get_my_ip(v6=args.ipv6)
        except Exception as e:
            print(f"错误：{e}", file=sys.stderr)
            return 2
        targets.append(("本机出口", ip, None))

    # 批量时限制并发，避免被免费接口限流
    workers = 1 if len(targets) == 1 else 3
    with cf.ThreadPoolExecutor(workers) as ex:
        items = list(ex.map(lambda t: run_target(t[0], t[1], t[2], args.sources), targets))

    if args.json:
        out = items[0] if len(items) == 1 else items
        print(json.dumps(out, ensure_ascii=False, indent=2))
        return 0 if all("error" not in a for a in items) else 1

    if len(items) == 1:
        a = items[0]
        if "error" in a:
            print(f"错误：{a['input']}：{a['error']}", file=sys.stderr)
            return 1
        print(render(a))
        if args.verbose:
            print(render_sources(a))
        else:
            print(C.w("2", f"（{a['sources_ok']}/{a['sources_total']} 个来源成功，加 -v 看明细）"))
        return 0
    print(render_table(items))
    if args.verbose:
        for a in items:
            if "error" not in a:
                print()
                print(render(a))
                print(render_sources(a))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
