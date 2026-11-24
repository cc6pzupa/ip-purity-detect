#!/usr/bin/env bash
# 一键 IP 纯净度检测
#   bash <(curl -fsSL https://raw.githubusercontent.com/cc6pzupa/ip-purity-detect/main/ipcheck.sh)
#   bash <(curl -fsSL .../ipcheck.sh) 1.2.3.4
#   bash <(curl -fsSL .../ipcheck.sh) -x host:port:user:pass
#   bash <(curl -fsSL .../ipcheck.sh) --install     # 安装成 ipcheck 命令
set -euo pipefail

REPO="${IPCHECK_REPO:-cc6pzupa/ip-purity-detect}"
BRANCH="${IPCHECK_BRANCH:-main}"
RAW="https://raw.githubusercontent.com/${REPO}/${BRANCH}/skills/ip-purity/scripts/ipcheck.py"

PY=""
for c in python3 python; do
  if command -v "$c" >/dev/null 2>&1 && "$c" -c 'import sys; sys.exit(sys.version_info < (3, 7))' 2>/dev/null; then
    PY="$c"; break
  fi
done
if [ -z "$PY" ]; then
  echo "需要 Python 3.7+。安装：apt install -y python3 / yum install -y python3 / apk add python3" >&2
  exit 1
fi

# 在仓库里直接运行时用本地文件，否则下载
SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd || true)"
LOCAL="${SELF_DIR}/skills/ip-purity/scripts/ipcheck.py"

fetch() {
  if command -v curl >/dev/null 2>&1; then curl -fsSL "$RAW" -o "$1"
  elif command -v wget >/dev/null 2>&1; then wget -qO "$1" "$RAW"
  else echo "需要 curl 或 wget" >&2; exit 1; fi
}

if [ "${1:-}" = "--install" ]; then
  DEST="${IPCHECK_DEST:-/usr/local/bin/ipcheck}"
  TMP="$(mktemp)"
  if [ -f "$LOCAL" ]; then cp "$LOCAL" "$TMP"; else fetch "$TMP"; fi
  sed -i "1s|.*|#!/usr/bin/env $PY|" "$TMP"
  install -m 755 "$TMP" "$DEST" 2>/dev/null || sudo install -m 755 "$TMP" "$DEST"
  rm -f "$TMP"
  echo "已安装：$DEST    用法：ipcheck [IP|代理] [-v] [--json]"
  exit 0
fi

if [ -f "$LOCAL" ]; then
  exec "$PY" "$LOCAL" "$@"
fi
TMP="$(mktemp -t ipcheck.XXXXXX.py)"
trap 'rm -f "$TMP"' EXIT
fetch "$TMP"
"$PY" "$TMP" "$@"
