#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ip-purity MCP server（stdio，零依赖）

工具：
  check_ip      检测单个 IP / 代理出口 / 本机出口
  check_ips     批量检测（IP 或代理），返回按评分排序的对比表
  denylist      查看 / 添加 / 移除负面清单
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
            "代理/VPN/Tor 标记（任一来源标记即自动进负面清单、0 分）、ASN 人机流量比（需 CF_API_TOKEN）、风险分、黑名单、原生/广播，给出 0-100 综合评分与银行/支付/注册等场景的使用建议。"
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
                "recheck": {"type": "boolean", "description": "忽略负面清单重新检测", "default": False},
            },
        },
    },
    {
        "name": "check_ips",
        "description": "批量检测多个 IP 或代理出口（最多 200 个），返回按评分排序的对比表、分级统计和每个 IP 的结论，适合从一批代理里挑最干净的。已在负面清单的直接 0 分、不重复查询。",
        "inputSchema": {
            "type": "object",
            "properties": {
                "targets": {"type": "array", "items": {"type": "string"},
                            "description": "IP、域名或代理（host:port:user:pass / scheme://...）"},
                "recheck": {"type": "boolean", "description": "忽略负面清单重新检测", "default": False},
                "min_score": {"type": "integer", "description": "达标分数线，结果里单独列出达标的", "default": 80},
            },
            "required": ["targets"],
        },
    },
    {
        "name": "denylist",
        "description": "管理负面清单（被标记为代理 / VPN / Tor 的 IP 会自动加入，命中直接 0 分）。action=list 查看，add 加入，remove 移除。",
        "inputSchema": {
            "type": "object",
            "properties": {
                "action": {"type": "string", "enum": ["list", "add", "remove"], "default": "list"},
                "targets": {"type": "array", "items": {"type": "string"}, "description": "IP 或 CIDR 网段"},
                "reason": {"type": "string", "description": "add 时的备注"},
            },
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


def _deny():
    return None if os.environ.get("IPCHECK_NO_DENYLIST") else ipcheck.Denylist()


def tool_check_ip(args):
    ip, proxy = args.get("ip"), args.get("proxy")
    if ip:
        t = ipcheck.parse_target(ip)
        if not t:
            raise ValueError("ip 为空")
        targets, via_self = [t], False
    elif proxy:
        targets, via_self = [(proxy, None, proxy)], False
    else:
        targets, via_self = [("本机出口", ipcheck.get_my_ip(), None)], True
    a = ipcheck.run_batch(targets, None, _deny(), bool(args.get("recheck")), 1, via_self)[0]
    a["input"] = ipcheck.mask(a["input"])
    if "error" in a:
        return f"检测失败：{a['input']}：{a['error']}", a, True
    text = ipcheck.render(a)
    if args.get("verbose") and a.get("sources"):
        text += "\n" + ipcheck.render_sources(a)
    return text, slim(a), False


def tool_check_ips(args):
    raw = [str(t) for t in (args.get("targets") or []) if str(t).strip()][:200]
    if not raw:
        raise ValueError("targets 为空")
    targets, seen = [], set()
    for t in raw:
        x = ipcheck.parse_target(t) or (t, None, None)
        if x[0] not in seen:
            seen.add(x[0])
            targets.append(x)
    items = ipcheck.run_batch(targets, None, _deny(), bool(args.get("recheck")), 3)
    for a in items:
        a["input"] = ipcheck.mask(a["input"])
    items.sort(key=ipcheck.sort_key, reverse=True)
    m = int(args.get("min_score") or 80)
    good = [a for a in items if "error" not in a and a["score"] >= m]
    lines = [ipcheck.render_table(items), ipcheck.summary(items), ""]
    lines.append(f"≥{m} 分达标 {len(good)} 个：" + ("、".join(a["input"] for a in good) if good else "无"))
    for a in items:
        if "error" not in a:
            lines.append(f"- {a['input']} → {a['ip']}：{a['score']}/100 {a['level']}，{a['type_cn']}；"
                         + "；".join((a["reasons"] or a["advice"])[:1]))
    return "\n".join(lines), {"summary": ipcheck.summary(items), "results": [slim(a) for a in items]}, False


def tool_denylist(args):
    d = ipcheck.Denylist()
    act = args.get("action") or "list"
    out = []
    for t in args.get("targets") or []:
        try:
            if act == "add":
                out.append(("已加入：" if d.add(t, "manual" + (f": {args['reason']}" if args.get("reason") else "")) else "已存在：") + t)
            elif act == "remove":
                out.append(("已移除：" if d.remove(t) else "不在清单中：") + t)
        except ValueError:
            out.append(f"无效的 IP / 网段：{t}")
    items = d.items()
    out.append(f"负面清单：{d.path}（{len(items)} 条）")
    out += [f"  {e['target']}  {e['date']}  {e['reason']}" for e in items]
    return "\n".join(out), {"path": d.path, "entries": items}, False


def tool_get_my_ip(args):
    ip = ipcheck.get_my_ip(args.get("proxy"), bool(args.get("ipv6")))
    return ip, {"ip": ip}, False


HANDLERS = {"check_ip": tool_check_ip, "check_ips": tool_check_ips, "denylist": tool_denylist,
            "get_my_ip": tool_get_my_ip}


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
