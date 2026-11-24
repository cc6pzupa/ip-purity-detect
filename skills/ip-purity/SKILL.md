---
name: ip-purity
description: 一键检测 IP 纯净度 / IP 质量——判断住宅还是机房、有没有被标记代理/VPN/Tor、风险分、黑名单、原生还是广播，并给出银行、支付、注册、AI 服务能不能用的结论。用户说"查一下 IP""这个 IP 干不干净""节点是不是家宽""银行提示 VPN""帮我从这批代理里挑干净的""检测 Webshare 出口"时使用。
---

# IP 纯净度检测

脚本：`${CLAUDE_SKILL_DIR}/scripts/ipcheck.py`（纯 Python 标准库，无需安装依赖）。
如果 `${CLAUDE_SKILL_DIR}` 没有被替换，就在本 skill 所在目录下找 `scripts/ipcheck.py`。

如果当前会话里有 `ip-purity` MCP 的 `check_ip` / `check_ips` 工具，直接用工具即可，效果相同。

## 怎么跑

| 场景 | 命令 |
|---|---|
| 本机出口 | `python3 ipcheck.py --json` |
| 指定 IP / 域名 | `python3 ipcheck.py 1.2.3.4 --json` |
| 代理出口（http / socks5 / Webshare `host:port:user:pass`） | `python3 ipcheck.py -x 'host:port:user:pass' --json` |
| 一批 IP 或代理挑最干净的 | `python3 ipcheck.py -f list.txt --json` |
| 给用户看的彩色报告 | 去掉 `--json`，加 `-v` 显示各来源明细 |

- 自己分析时用 `--json`，给用户直接看就用文本输出。
- 批量时脚本会限制并发，免费接口有限流，超过约 30 个 IP 时分批跑。
- 有 `IPQS_KEY`、`ABUSEIPDB_KEY`、`IPINFO_TOKEN` 环境变量时会自动多查这几家。不要向用户索要，用户主动提供才用。
- 不要把用户的代理密码写进回复或日志。转述结果时只说 IP。

## 数据来源（免费、免注册）

ip-api.com、proxycheck.io、ipquery.io、iplocate.io、ipapi.is、scamalytics、ip2location.io、ipinfo.io、ipwho.is、ip.sb、ipinfo Blackbox、Shodan InternetDB、Tor 官方出口列表、GreyNoise、StopForumSpam、DNSBL，共 16 个。

## 怎么读结果

JSON 关键字段：
- `score`：0-100 分。**任一来源标记为代理、VPN 或 Tor，就直接 0 分**，`level` 为"代理"，标记的来源列在 `flagged_by`。其余按扣分算，`level` 分 纯净 ≥80、良好 60-79、一般 40-59、较差 <40。
- `type`：residential / mobile / datacenter / business。`type_votes` 是加权票数，有专门检测数据的来源算 1 票，按名称猜的算 0.5 票。机房票占 40% 及以上就判为机房。
- `hit_by`：每一项标记分别是哪些来源给出的。
- `proxy`、`vpn`、`tor`、`abuse`：`[被标记的来源数, 给出判断的来源数]`。
- `risk_scores`：各家风险分（越低越好），`avg_risk` 是平均值。
- `native`：false 表示疑似广播 IP。判断依据是 ASN 注册国和定位国不一致，或者各库定位不一致。
- `reasons`：扣分项。`advice`：用途建议。
- `sources[]`：每个来源的原始判断，`ok=false` 的那条是失败或被限流了。

## 给用户的结论怎么写

1. 第一句给结论：评分、等级、住宅还是机房、能不能用于用户关心的场景（银行、支付、注册、ChatGPT 等）。
2. 再列关键证据：几个来源说是机房、谁标记了代理、风险分多少。
3. 结果是 0 分（⛔ 代理）时，要说出是哪个来源标记的（看 `flagged_by`）。只有一家标记、其他都没标的，要提醒可能是误判。Starlink、移动网络 CGNAT、企业出口常被误标。
4. 来源之间有分歧要直说，比如"proxycheck 标为 VPN，其余 3 家未标记"，不要只挑好听的说。
5. 成功的来源少于 6 个时，要说明结论不可靠，建议稍后重试。
6. 结果不好时给下一步：换同组的其他出口 IP 再测，改用住宅 / ISP 静态代理，或者用真实家庭宽带做出口。
7. 要提醒一句：各家库的数据有延迟，银行实际用的是付费风控库，这里的高分不代表一定能过。
