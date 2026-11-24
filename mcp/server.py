#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ip-purity MCP server（stdio，零依赖）

工具：
  check_ip      检测单个 IP / 代理出口 / 本机出口
  check_ips     批量检测（IP 或代理），返回对比表
  get_my_ip     只取本机（或代理）出口 IP

接入：
  Claude Code:    claude mcp add ip-purity -- python3 /绝对路径/mcp/server.py
  Claude Desktop / Cursor / Codex 等：command=python3, args=[/绝对路径/mcp/server.py]
"""
import concurrent.futures as cf
import json
import os
import sys
import traceback

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "skills", "ip-purity", "scripts"))
import ipcheck  # noqa: E402

ipcheck.C.on = False
PROTOCOL = "2025-06-18"

TOOLS = [
    {
        "name": "check_ip",
        "description": (
            "检测 IP 纯净度：并发查询 ip-api、proxycheck、ipquery、iplocate、ipapi.is、scamalytics、ip2location、ipinfo、Shodan、GreyNoise、Tor 出口列表等 16 个免费源 "
            "（配置了 IPQS_KEY / ABUSEIPDB_KEY 时还会查 IPQualityScore / AbuseIPDB），汇总判断 IP 类型（住宅/机房/移动）、"
            "代理/VPN/Tor 标记（任一来源标记即 0 分）、风险分、黑名单、原生/广播，给出 0-100 综合评分与银行/支付/注册等场景的使用建议。"
            "ip 和 proxy 都不填时检测运行本服务的机器的出口 IP。"
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "ip": {"type": "string", "description": "要检测的 IPv4/IPv6 或域名"},
                "proxy": {"type": "string",
                          "description": "经此代理取出口 IP 再检测。支持 http://user:pass@host:port、socks5://...、"
                                         "或 Webshare 格式 host:port:user:pass"},
                "verbose": {"type": "boolean", "description": "附带每个来源的原始判断", "default": False},
            },
        },
    },
    {
        "name": "check_ips",
        "description": "批量检测多个 IP 或代理出口（最多 30 个），返回按评分排序的对比表和每个 IP 的结论，适合从一批代理里挑最干净的。",
        "inputSchema": {
            "type": "object",
            "properties": {
                "targets": {"type": "array", "items": {"type": "string"},
                            "description": "IP、域名或代理（host:port:user:pass / scheme://...）"},
            },
            "required": ["targets"],
        },
    },
    {
        "name": "get_my_ip",
        "description": "获取本机或指定代理的出口 IP（不做检测）。",
        "inputSchema": {
            "type": "object",
            "properties": {
                "proxy": {"type": "string", "description": "可选代理"},
                "ipv6": {"type": "boolean", "default": False},
            },
        },
    },
]


def slim(a):
    """去掉体积大的来源原始数据，保留结论。"""
    if "error" in a:
        return a
    b = {k: v for k, v in a.items() if k != "sources"}
    b["sources"] = [{k: s.get(k) for k in ("source", "ok", "error", "type", "proxy", "vpn", "tor", "hosting",
                                            "abuser", "risk", "note")} for s in a["sources"]]
    return b


def tool_check_ip(args):
    ip, proxy = args.get("ip"), args.get("proxy")
    if ip:
        t = ipcheck.parse_target(ip)
        if not t:
            raise ValueError("ip 为空")
        label, ip_, proxy_ = t
    elif proxy:
        label, ip_, proxy_ = proxy, None, proxy
    else:
        ip_ = ipcheck.get_my_ip()
        label, proxy_ = "本机出口", None
    a = ipcheck.run_target(label, ip_, proxy_, None)
    if "error" in a:
        return f"检测失败：{a['input']}：{a['error']}", a, True
    text = ipcheck.render(a)
    if args.get("verbose"):
        text += "\n" + ipcheck.render_sources(a)
    return text, slim(a), False


def tool_check_ips(args):
    targets = [t for t in (args.get("targets") or []) if str(t).strip()][:30]
    if not targets:
        raise ValueError("targets 为空")
    parsed = [ipcheck.parse_target(t) or (t, None, None) for t in targets]
    with cf.ThreadPoolExecutor(3) as ex:
        items = list(ex.map(lambda t: ipcheck.run_target(t[0], t[1], t[2], None), parsed))
    items.sort(key=lambda a: -a.get("score", -1))
    lines = [ipcheck.render_table(items), ""]
    for a in items:
        if "error" not in a:
            lines.append(f"- {a['input']} → {a['ip']}：{a['score']}/100 {a['level']}，{a['type_cn']}；"
                         + "；".join(a["advice"][:1]))
    return "\n".join(lines), {"results": [slim(a) for a in items]}, False


def tool_get_my_ip(args):
    ip = ipcheck.get_my_ip(args.get("proxy"), bool(args.get("ipv6")))
    return ip, {"ip": ip}, False


HANDLERS = {"check_ip": tool_check_ip, "check_ips": tool_check_ips, "get_my_ip": tool_get_my_ip}


def handle(msg):
    method, mid = msg.get("method"), msg.get("id")
    params = msg.get("params") or {}
    if method == "initialize":
        return {"protocolVersion": params.get("protocolVersion") or PROTOCOL,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "ip-purity", "version": ipcheck.__version__}}
    if method == "ping":
        return {}
    if method == "tools/list":
        return {"tools": TOOLS}
    if method == "tools/call":
        name = params.get("name")
        fn = HANDLERS.get(name)
        if not fn:
            raise LookupError(f"未知工具：{name}")
        try:
            text, data, is_err = fn(params.get("arguments") or {})
        except Exception as e:
            return {"content": [{"type": "text", "text": f"出错：{e}"}], "isError": True}
        if not isinstance(data, dict):
            data = {"result": data}
        return {"content": [{"type": "text", "text": text},
                            {"type": "text", "text": json.dumps(data, ensure_ascii=False)}],
                "structuredContent": data, "isError": is_err}
    if mid is None:  # 通知，不回复
        return None
    raise LookupError(f"Method not found: {method}")


def send(obj):
    sys.stdout.write(json.dumps(obj, ensure_ascii=False) + "\n")
    sys.stdout.flush()


def main():
    try:
        sys.stdin.reconfigure(encoding="utf-8")
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            send({"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Parse error"}})
            continue
        mid = msg.get("id")
        try:
            res = handle(msg)
            if mid is not None and res is not None:
                send({"jsonrpc": "2.0", "id": mid, "result": res})
        except LookupError as e:
            if mid is not None:
                send({"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": str(e)}})
        except Exception as e:
            traceback.print_exc(file=sys.stderr)
            if mid is not None:
                send({"jsonrpc": "2.0", "id": mid, "error": {"code": -32603, "message": str(e)}})


if __name__ == "__main__":
    main()
