# IP 纯净度一键检测

一条命令就能知道这个 IP 干不干净：**是住宅还是机房，有没有被标记代理 / VPN，风险分多少，是原生还是广播 IP**。只要被任何一家标记为代理，就直接进**负面清单**、0 分；否则给出 0-100 分，并说明能不能用于银行、支付、注册、AI 服务。支持**批量**检测，可选查看 ASN 的**人机流量比**。

- **一键脚本**：VPS 和本机都能跑，只需要 Python 3.7+，不用装任何依赖。
- **MCP**：接到 Claude Code、Claude Desktop、Cursor、Codex 等，直接对 AI 说"查一下这个 IP"就行。
- **Skill**：Claude Code / Claude.ai 的技能包，教 AI 怎么跑、怎么解读结果、怎么给结论。

```
━━━━━━━━ IP 纯净度检测 · 73.15.2.10 ━━━━━━━━
位置    United States San Jose
运营商  AS7922 Comcast Cable Communications, LLC / Comcast IP Services, L.L.C.
类型    住宅  （投票：住宅5）
原生    原生 IP  ASN 注册国与定位国一致
代理    未标记（0/6）
VPN     未标记（0/4）
Tor     未标记（0/5）
滥用    未标记（0/3）
风险分  proxycheck.io 0  scamalytics 16  ipquery.io 0  （0-100，越低越好）
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
| `-f list.txt` | 批量检测。每行一个 IP 或代理（`host:port:user:pass`、`http://`、`socks5://`），`#` 开头是注释；`-f -` 从管道读。可以写多个 `-f` |
| `-x 代理` | 先通过这个代理拿到出口 IP，再检测这个 IP，可以写多个。socks5 代理需要系统装有 curl |
| `-6` | 检测本机的 IPv6 出口 |
| `-v` | 显示每个来源的判断 |
| `--json` | 输出 JSON，方便给脚本或 AI 用 |
| `-s ipapi,proxycheck` | 只用指定的来源 |
| `-t 秒` | 单个请求的超时时间，默认 10 秒 |
| `-c 3` | 批量时同时检测几个 IP，默认 3。调太大容易被免费接口限流 |

### 批量检测

```bash
ipcheck -f list.txt                                # 输出按评分排序的对比表和分级统计
ipcheck -f list.txt --csv result.csv               # 另存 CSV，Excel 可直接打开
ipcheck -f list.txt --clean-out good.txt           # ≥80 分的原样写进 good.txt，可直接导入
ipcheck -f list.txt --clean-out good.txt --min-score 90
cat ips.txt | ipcheck                              # 也可以从管道读
```

```
IP                                        评分  等级    类型      人机  国家   运营商 / 标记
73.15.2.10                               100  🟢纯净   住宅       -  US   Comcast IP Services, L.L.C.
24.5.10.20                               100  🟢纯净   住宅       -  US   Comcast Cable Communications
1.1.1.1                                   35  🔴较差   机房       -  AU   Cloudflare, Inc.
8.8.8.8                                    0  ⛔负面清单 机房       -  US   代理（ip-api.com）
98.97.1.1                                  0  ⛔负面清单 住宅       -  US   代理（scamalytics）
共 5 个：🟢 纯净 2  🔴 较差 1  ⛔ 负面清单 2
```

- **去重**：重复的 IP 或代理只查一次。
- **合并请求**：ip-api 和 proxycheck 的批量接口一次能查 100 个，所以 6 个 IP 大约 2 秒就能查完。
- **限流保护**：同一个来源最多同时发 2 个请求，遇到限流会自动等一下再重试。
- **隐藏密码**：代理密码在输出里显示成 `***`。不过 `--clean-out` 写出的是原样，方便直接导入。

### 负面清单

任何一家把 IP 标记为代理、VPN 或 Tor，这个 IP 就**自动加入负面清单**。以后再查到它，直接 0 分，不再请求接口。

```bash
ipcheck --deny-list                       # 查看
ipcheck --deny-add 1.2.3.4 5.6.7.0/24     # 手动加入，支持网段
ipcheck --deny-rm 1.2.3.4                 # 移除
ipcheck 1.2.3.4 --recheck                 # 忽略清单重新检测：自动加入的条目，复查干净就移出
ipcheck -f list.txt --no-denylist         # 本次不读也不写清单
```

- **文件位置**：默认是 `~/.config/ipcheck/denylist.txt`，可以用 `--denylist 路径` 或环境变量 `IPCHECK_DENYLIST` 改。
- **文件格式**：纯文本，每行是"IP 或网段、日期、原因"，用 Tab 分隔，可以直接编辑。
- **自动和手动条目**：自动加入的条目，原因以 `auto:` 开头。手动加入的不会被 `--recheck` 自动移除。

### 人机流量比

人机流量比是这个 IP 所属 ASN 在 Cloudflare 上的流量里，真人和机器人各占多少，数据来自 Cloudflare Radar 近 7 天的统计。家宽和移动运营商的真人流量通常在 60% 以上，云厂商和机房通常低于 20%。

这个功能需要一个免费的 Cloudflare API Token，没有 token 时自动跳过，不影响其他检测：

1. 登录 dash.cloudflare.com，进入"My Profile → API Tokens → Create Token → Custom token"，权限选 **Radar: Read**。
2. 运行 `export CF_API_TOKEN=你的token`，然后照常运行 `ipcheck`。

**参与判断的方式**：
- 真人流量低于 20%：算 1 票机房，扣 10 分。
- 真人流量低于 40%：扣 5 分。
- 真人流量 60% 及以上：算 0.5 票住宅。

**从一批 Webshare 代理里挑干净的：** 把后台下载的列表存成 `list.txt`，然后跑 `ipcheck -f list.txt --clean-out good.txt`。

## 2. MCP

提供 4 个工具：
- `check_ip`：检测单个 IP、代理出口或本机出口。
- `check_ips`：批量检测，最多 200 个，按评分排序，并列出达标的 IP。
- `denylist`：查看、加入、移除负面清单。
- `get_my_ip`：只取本机或代理的出口 IP，不做检测。

和命令行共用同一份负面清单。

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

免 key 的来源有 16 个，检测本机或代理出口时会再加上 IPPure，所有来源并发查询。有 key 的话会更准。

| 来源 | 提供的信息 | 类型票权重 |
|---|---|---|
| ip-api.com | 代理、机房、移动网络 | 1；判为住宅时 0.5 |
| proxycheck.io | 代理类型（VPN / 住宅 / 机房 / 商业）、风险分 | 1 |
| ipquery.io | 代理 / VPN / Tor / 机房 / 移动、风险分 | 1；判为住宅时 0.5 |
| iplocate.io | 代理 / VPN / Tor / 机房 / 滥用、ASN 类型 | 1 |
| ipapi.is | 机房 / 代理 / VPN / Tor / 滥用（免费额度有时只返回地理信息） | 1 |
| scamalytics | 欺诈风险分；VPN、Tor、服务器、公共代理、住宅代理；Firehol / IP2Proxy / Spamhaus 等名单 | 1 |
| ip2location.io | 是否代理（IP2Proxy） | 0.5，按名称猜 |
| ipinfo.io | ASN、运营商、反向解析的主机名 | 0.5，按名称猜 |
| ipwho.is、ip.sb | ASN、运营商 | 0.5，按名称猜 |
| ipinfo Blackbox | 是否属于代理或机房网段（只当机房信号用，不算代理） | 0.5 |
| Shodan InternetDB | 开放端口；cloud、vpn、proxy、tor 等标签 | 0.5 |
| Tor 官方出口列表 | 是否为 Tor 出口 | — |
| GreyNoise | 是否在扫描互联网，是否为恶意 IP | — |
| StopForumSpam | 是否有垃圾注册记录 | — |
| DNSBL | Spamhaus、SpamCop、Barracuda、PSBL 邮件黑名单 | — |
| IPQualityScore（可选） | 需设置 `IPQS_KEY`：欺诈分、连接类型、代理 / VPN | 1 |
| IPPure | 欺诈分、是否住宅、是否广播（只能查自己的 IP，所以只在检测本机或代理出口时用） | 1；判为非住宅时 0.5 |
| Cloudflare Radar（可选） | 需设置 `CF_API_TOKEN`：ASN 的人机流量比 | 1 / 0.5 |
| AbuseIPDB（可选） | 需设置 `ABUSEIPDB_KEY`：被举报次数、用途类型 | 1 |

## 评分规则

**规则 1：一票否决，进负面清单。** 只要任何一个来源把这个 IP 标记为代理、VPN 或 Tor，就直接 0 分，等级记为 ⛔ 负面清单，并把它写进负面清单。报告里会写明是哪个来源标记的。以后再查到这个 IP，或者它落在你手动加入的网段里，都直接 0 分。

**规则 2：扣分制。** 没有被标记的 IP，从 100 分开始按下表扣：

| 情况 | 扣分 |
|---|---|
| 机房（机房票占 40% 及以上就判为机房） | 30 + 20 × 机房票占比，即 38-50 |
| 商业 / 教育 / 政府线路 | 10 |
| 无法判断类型 | 10 |
| 滥用记录 | 每个来源 10，最多 30 |
| 平均风险分大于 10 | 平均风险分 × 0.4 |
| 任一来源风险分 ≥ 75 | 再扣 10 |
| 邮件黑名单 | 每命中一个扣 5，最多 15 |
| 疑似广播 IP | 8 |
| ASN 真人流量低于 20% / 低于 40%（需 `CF_API_TOKEN`） | 10 / 5 |

**类型投票：** 有专门检测数据的来源算 1 票。只按运营商名称猜的来源算 0.5 票，"不是机房所以算住宅"这类推断也算 0.5 票。判机房的门槛设得比较低，偏保守。

**等级：** ≥80 纯净 🟢，60-79 良好 🟡，40-59 一般 🟠，<40 较差 🔴，被标记的直接是 ⛔ 负面清单。

参考分数：干净的住宅 IP 通常是 100 分。没被标记的机房 IP 大约 50 分，有滥用记录或是广播 IP 会更低。

> 一票否决很严格，会有误伤。比如 Starlink、部分移动网络 CGNAT（运营商级共享 IP）、企业出口，经常被某一家库标成代理。看到 ⛔ 时，报告会写出是哪家标记的，可以自己判断要不要信。确认是误判的话，用 `--deny-rm` 移出负面清单，或者用 `--recheck` 重新检测。
>
> 这里查的都是免费库。银行、支付平台用的是付费风控库，所以高分只代表"大概率干净"，不保证一定能过风控。结果不好时，先换同组的其他 IP 再测。
