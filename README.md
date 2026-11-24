# IP 纯净度一键检测

一条命令就能知道这个 IP 干不干净：**是住宅还是机房，有没有被标记代理 / VPN，风险分多少，是原生还是广播 IP**。最后给出 0-100 分，并说明能不能用于银行、支付、注册、AI 服务。

- **一键脚本**：VPS 和本机都能跑，只需要 Python 3.7+，不用装任何依赖。
- **MCP**：接到 Claude Code、Claude Desktop、Cursor、Codex 等，直接对 AI 说"查一下这个 IP"就行。
- **Skill**：Claude Code / Claude.ai 的技能包，教 AI 怎么跑、怎么解读结果、怎么给结论。

```
━━━━━━━━ IP 纯净度检测 · 73.15.2.10 ━━━━━━━━
位置    United States San Jose
运营商  AS7922 Comcast Cable Communications, LLC / Comcast IP Services, L.L.C.
类型    住宅  （投票：住宅5）
原生    原生 IP  各库定位国家一致
代理    未标记（0/3）
VPN     未标记（0/2）
Tor     未标记（0/2）
滥用    未标记（0/1）
风险分  proxycheck.io 0  scamalytics 16  （0-100，越低越好）
黑名单  DNSBL 0/4 命中
────────────────────────────────────────────────────
综合评分  100/100  🟢 纯净
建议      住宅 / 移动 IP 且无代理标记：适合银行、支付、注册账号、AI 服务（ChatGPT / Claude）等对风控敏感的场景。
```

## 1. 一键脚本

```bash
# 检测本机出口
bash <(curl -fsSL https://raw.githubusercontent.com/cc6pzupa/ip-purity-detect/main/ipcheck.sh)

# 检测指定 IP，-v 显示每个来源的明细
bash <(curl -fsSL https://raw.githubusercontent.com/cc6pzupa/ip-purity-detect/main/ipcheck.sh) 1.2.3.4 -v

# 检测代理出口（Webshare 列表格式可直接粘贴）
bash <(curl -fsSL https://raw.githubusercontent.com/cc6pzupa/ip-purity-detect/main/ipcheck.sh) -x 'host:port:user:pass'

# 安装成 ipcheck 命令，以后直接敲 ipcheck
bash <(curl -fsSL https://raw.githubusercontent.com/cc6pzupa/ip-purity-detect/main/ipcheck.sh) --install
```

| 参数 | 作用 |
|---|---|
| `IP / 域名 / 代理 …` | 可以一次传多个，多个时输出对比表 |
| `-f list.txt` | 批量检测。每行一个 IP，或一个代理（`host:port:user:pass`、`http://`、`socks5://`） |
| `-x 代理` | 先通过这个代理拿到出口 IP，再检测这个 IP。socks5 代理需要系统装有 curl |
| `-6` | 检测本机的 IPv6 出口 |
| `-v` | 显示每个来源的判断 |
| `--json` | 输出 JSON，方便给脚本或 AI 用 |
| `-s ipapi,proxycheck` | 只用指定的来源 |
| `-t 秒` | 单个请求的超时时间，默认 10 秒 |

**从一批 Webshare 代理里挑干净的：** 把后台下载的列表存成 `list.txt`，然后跑 `ipcheck -f list.txt`。

## 2. MCP

提供 3 个工具：`check_ip`（单个 IP、代理或本机）、`check_ips`（批量，按评分排序）、`get_my_ip`。

```bash
git clone https://github.com/cc6pzupa/ip-purity-detect.git ~/ip-purity-detect

# Claude Code
claude mcp add ip-purity -- python3 ~/ip-purity-detect/mcp/server.py
```

Claude Desktop、Cursor 等客户端在配置文件的 `mcpServers` 里加上下面这段（路径要写绝对路径）：

```json
{
  "mcpServers": {
    "ip-purity": { "command": "python3", "args": ["/home/你/ip-purity-detect/mcp/server.py"] }
  }
}
```

Codex（`~/.codex/config.toml`）：

```toml
[mcp_servers.ip-purity]
command = "python3"
args = ["/home/你/ip-purity-detect/mcp/server.py"]
```

> MCP 跑在哪台机器上，"本机出口"就是哪台机器的 IP。想测 VPS 的出口，就在 VPS 上的 Claude Code 里接这个 MCP；也可以在本地用 `proxy` 参数，测经过代理后的出口。

## 3. Skill 和 Claude Code 插件

**作为插件安装（skill 和 MCP 一起装好）：**

```
/plugin marketplace add cc6pzupa/ip-purity-detect
/plugin install ip-purity@ip-purity-detect
```

**只装 skill：** 把 `skills/ip-purity` 整个目录复制到 `~/.claude/skills/`。在 Claude.ai 上用的话，把这个目录打成 zip，在"设置 → 功能 → Skills"里上传。

装好后直接说"帮我查下这个 IP 干不干净""银行提示我用了 VPN，看看节点 IP"，AI 会自动调用这个 skill。

## 数据来源

都是免费的，不用注册，有 key 会更准：

| 来源 | 提供的信息 |
|---|---|
| ip-api.com | 是否机房、是否代理、是否移动网络 |
| ipapi.is | 机房 / VPN / Tor / 滥用标记（免费额度有时只返回地理信息） |
| proxycheck.io | 代理类型（VPN / 住宅 / 机房 / 商业）、风险分 |
| ipinfo.io | ASN、运营商、反向解析的主机名 |
| ipwho.is、ip.sb | ASN、运营商（按名称关键词识别是不是机房） |
| scamalytics | 欺诈风险分；是否 VPN、Tor、服务器、公共代理；是否在 Firehol / IP2Proxy / Spamhaus 等名单里 |
| DNSBL | Spamhaus、SpamCop、Barracuda、PSBL 邮件黑名单 |
| IPQualityScore（可选） | 需设置 `IPQS_KEY`：欺诈分、连接类型 |
| AbuseIPDB（可选） | 需设置 `ABUSEIPDB_KEY`：被举报次数、用途类型 |

## 评分规则

满分 100，按下面的规则扣分：

| 情况 | 扣分 |
|---|---|
| 判为机房（40% 及以上的来源说是机房） | 25-40，说是机房的来源越多扣得越多 |
| 商业 / 企业线路 | 8 |
| 每个标记为代理的来源 | 12，最多 36 |
| 每个标记为 VPN 的来源 | 10，最多 30 |
| Tor 出口节点 | 50 |
| 每个滥用 / 黑名单记录 | 8，最多 20 |
| 平均风险分 × 0.3 | 平均风险分超过 10 才扣 |
| 疑似广播 IP | 5 |

等级：**≥80 纯净 🟢**，60-79 良好 🟡，40-59 一般 🟠，<40 较差 🔴。

> 说明：这里查的都是免费库。银行、支付平台用的是付费风控库（如 MaxMind、IPQS 企业版），数据更全、更新也更快。所以高分只代表"大概率干净"，不保证一定能过风控。结果不好时，先换同组的其他 IP 再测。
