#!/usr/bin/env bash
set -euo pipefail

# Realm 首连超时一键修复（强制 IPv4 + MSS 钳制 + 安全 TCP 调优 + DNS 纠偏）
# 适用：仅在本机使用 realm 做转发的场景（非三层路由/NAT）

log()  { echo -e "\e[32m[+]\e[0m $*"; }
warn() { echo -e "\e[33m[!]\e[0m $*"; }
err()  { echo -e "\e[31m[✗]\e[0m $*"; }

require_root() {
  if [[ ${EUID:-0} -ne 0 ]]; then
    err "请以 root 身份运行（sudo -i 或 sudo bash）。"; exit 1
  fi
}

ts() { date +%Y%m%d-%H%M%S; }

BACKUP_DIR="/root/.realm_oneclick_backup/$(ts)"
mkdir -p "$BACKUP_DIR"

require_root

log "加载/持久化 nf_conntrack（连接跟踪）"
if command -v modprobe >/dev/null 2>&1; then
  modprobe nf_conntrack 2>/dev/null || true
else
  warn "未发现 modprobe，跳过内核模块即时加载"
fi
mkdir -p /etc/modules-load.d
if ! grep -q '^nf_conntrack$' /etc/modules-load.d/conntrack.conf 2>/dev/null; then
  echo nf_conntrack >> /etc/modules-load.d/conntrack.conf
fi

log "写入安全 TCP 调优（/etc/sysctl.d/60-realm-tune.conf）"
# 动态决定 default_qdisc：若当前已为 cake/fq_codel，则不强改；否则设为 fq
current_qdisc=$(sysctl -n net.core.default_qdisc 2>/dev/null || echo "")
qdisc_line="# 保持现状"
case "$current_qdisc" in
  cake|fq_codel) qdisc_line="# 已存在 $current_qdisc，不覆盖" ;;
  fq)            qdisc_line="net.core.default_qdisc=fq" ;;
  *)             qdisc_line="net.core.default_qdisc=fq" ;;
esac

cat >/etc/sysctl.d/60-realm-tune.conf <<SYSC
# 连接跟踪容量
net.netfilter.nf_conntrack_max = 262144

# 监听队列/半连接队列
net.core.somaxconn = 4096
net.ipv4.tcp_max_syn_backlog = 8192
net.ipv4.tcp_syncookies = 1

# 端口范围更宽，避免耗尽
net.ipv4.ip_local_port_range = 10000 65535

# FIN/TIME_WAIT 收敛
net.ipv4.tcp_fin_timeout = 30

# 避免部分线路 TFO 不兼容引发首连异常
net.ipv4.tcp_fastopen = 0

# 拥塞控制（如已安装 BBR v3，此处依然使用 bbr 名称）
net.ipv4.tcp_congestion_control = bbr

# 队列算法（如已是 cake/fq_codel 将不覆盖）
$qdisc_line
SYSC

log "应用 sysctl 配置"
sysctl --system >/dev/null

realm_cfg="/etc/realm/config.json"
if [[ -f "$realm_cfg" ]]; then
  log "备份 Realm 配置到 $BACKUP_DIR/$(basename "$realm_cfg")"
  cp -a "$realm_cfg" "$BACKUP_DIR/"

  log "强制 IPv4 + 优化 listen/nodelay/reuse_port"
  if command -v jq >/dev/null 2>&1; then
    tmpfile=$(mktemp)
    # 仅用 jq 设置顶层键，避免因 endpoints 结构差异导致失败
    jq '.resolve = "ipv4" | .nodelay = true | .reuse_port = true' \
      "$realm_cfg" >"$tmpfile" && mv "$tmpfile" "$realm_cfg"
  else
    warn "未安装 jq，改用保守文本方式写入顶层键（推荐安装 jq）"
    if ! grep -q '"resolve"\s*:\s*"ipv4"' "$realm_cfg"; then
      sed -i.bak '0,/{/s//{\n  "resolve": "ipv4",/' "$realm_cfg" || true
    fi
    grep -q '"nodelay"' "$realm_cfg" || sed -i.bak '0,/{/s//{\n  "nodelay": true,/' "$realm_cfg"
    grep -q '"reuse_port"' "$realm_cfg" || sed -i.bak '0,/{/s//{\n  "reuse_port": true,/' "$realm_cfg"
  fi
  # 统一用文本替换确保 IPv6 监听改为 IPv4（兼容各种 JSON 排版）
  sed -i.bak -E 's/"listen"\s*:\s*":::(\d+)"/"listen": "0.0.0.0:\1"/g' "$realm_cfg" || true
  sed -i.bak -E 's/"listen"\s*:\s*"\[::\]:(\d+)"/"listen": "0.0.0.0:\1"/g' "$realm_cfg" || true
else
  warn "未找到 $realm_cfg，跳过 Realm 配置修改。"
fi

log "备份并纠偏 /etc/resolv.conf（仅保留 IPv4 DNS）"
if [[ -e /etc/resolv.conf ]]; then
  cp -a /etc/resolv.conf "$BACKUP_DIR/resolv.conf"
  ipv4_dns=$(grep -E "^nameserver\s+[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" /etc/resolv.conf || true)
  if [[ -z "$ipv4_dns" ]]; then
    cat >/etc/resolv.conf <<DNS
nameserver 1.1.1.1
nameserver 8.8.8.8
DNS
  else
    printf "%s\n" "$ipv4_dns" > /etc/resolv.conf
  fi
else
  warn "/etc/resolv.conf 不存在，跳过。"
fi

log "为 SYN 包配置 MSS 钳制（优先 iptables，nft 作为后备）"
added_mss_rule=false

# 优先使用 iptables（兼容性最佳）
set +e
if command -v iptables >/dev/null 2>&1; then
  iptables -t mangle -C OUTPUT -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null
  rc=$?
  if [ $rc -ne 0 ]; then
    iptables -t mangle -A OUTPUT -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
    rc=$?
  fi
  if [ $rc -eq 0 ]; then added_mss_rule=true; fi

  # 路由转发场景可附加 FORWARD（可选）
  iptables -t mangle -C FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null
  [ $? -ne 0 ] && iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu >/dev/null 2>&1
fi

# 若未能使用 iptables，再尝试 nft（自动在 pmtu 与 mtu 间回退）
if [ "$added_mss_rule" != true ] && command -v nft >/dev/null 2>&1; then
  nft add table inet mangle 2>/dev/null
  nft add chain inet mangle output '{ type route hook output priority mangle; }' 2>/dev/null
  nft list chain inet mangle output 2>/dev/null | grep -q 'maxseg.*clamp'
  if [ $? -ne 0 ]; then
    nft add rule inet mangle output tcp flags syn tcp option maxseg size set clamp to pmtu 2>/dev/null
    rc=$?
    if [ $rc -ne 0 ]; then
      nft add rule inet mangle output tcp flags syn tcp option maxseg size set clamp to mtu 2>/dev/null
      rc=$?
    fi
    if [ $rc -eq 0 ]; then added_mss_rule=true; fi
  else
    added_mss_rule=true
  fi

  nft add chain inet mangle forward '{ type filter hook forward priority mangle; }' 2>/dev/null
  nft list chain inet mangle forward 2>/dev/null | grep -q 'maxseg.*clamp' || \
    nft add rule inet mangle forward tcp flags syn tcp option maxseg size set clamp to pmtu 2>/dev/null || \
    nft add rule inet mangle forward tcp flags syn tcp option maxseg size set clamp to mtu 2>/dev/null
fi
set -e

if [[ "$added_mss_rule" == true ]]; then
  log "MSS 钳制规则已确保存在（OUTPUT）。"
else
  warn "未能添加 MSS 钳制规则，请手动使用 iptables 或 nft 添加。"
fi

# systemd: 提升 realm 服务文件句柄并重启
if systemctl list-unit-files | grep -q '^realm\.service'; then
  log "提升 realm.service 文件句柄限制并重启"
  mkdir -p /etc/systemd/system/realm.service.d
  cat >/etc/systemd/system/realm.service.d/override.conf <<OVR
[Service]
LimitNOFILE=1048576
OVR
  systemctl daemon-reload
  systemctl restart realm || warn "realm 重启失败，请手动检查 journalctl -u realm"
else
  warn "未发现 realm.service，跳过重启与句柄限制设置。"
fi

log "完成。备份位于：$BACKUP_DIR"
echo
log "快速验证："
echo "- 查看 Realm 监听是否为 IPv4：   ss -tlnp | grep realm"
echo "- 查看 DNS（仅 IPv4）：          grep nameserver /etc/resolv.conf"
echo "- 查看 MSS 钳制（OUTPUT）：       iptables -t mangle -S OUTPUT || nft list chain inet mangle output | sed -n '1,50p'"
echo "- 再用 Loon 首次连接节点测试是否已无 timeout"

if command -v iptables >/dev/null 2>&1; then
  echo
  warn "如需持久化 iptables 规则（可选）："
  echo "  apt-get update && apt-get install -y iptables-persistent"
  echo "  netfilter-persistent save && systemctl enable netfilter-persistent"
fi
