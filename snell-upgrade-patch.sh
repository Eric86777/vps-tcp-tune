#!/bin/bash
# Snell 一键升级补丁
# 适用：已经用 net-tcp-tune.sh 部署过 Snell 的机器
# 作用：把主脚本 fix（systemd start-limit + 内核保留端口）应用到现有 Snell 实例
#       + 加每日北京时间 04:00 自动重启 cron
# 不会卸载/重装任何 Snell 实例，不影响 BBR/DNS/IPv6 等其他配置
#
# 用法（VPS root 上跑）：
#   bash <(curl -fsSL https://raw.githubusercontent.com/Eric86777/vps-tcp-tune/main/snell-upgrade-patch.sh)
#
# 卸载本补丁带来的改动：
#   rm -rf /etc/systemd/system/snell-*.service.d/99-net-tcp-tune-fix.conf
#   rm -f /etc/sysctl.d/99-zzz-snell-reserved-ports.conf
#   crontab -l | grep -v "# Snell每日重启" | crontab -
#   systemctl daemon-reload && systemctl restart 'snell-*.service'

set +e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}请以 root 身份运行：sudo bash $0${NC}"
    exit 1
fi

echo -e "${CYAN}===================================================="
echo -e "  Snell 一键升级补丁"
echo -e "====================================================${NC}"
echo ""

# === 1. 给现有 snell-*.service 加 systemd drop-in ===
echo -e "${YELLOW}[1/4] 修补 systemd 服务配置（防止 5 次失败永久死锁）${NC}"
PORTS=""
PATCHED=0
for svc in /etc/systemd/system/snell-*.service; do
    [ -f "$svc" ] || continue
    name=$(basename "$svc")
    port=$(echo "$name" | sed -E 's/snell-([0-9]+)\.service/\1/')
    [[ "$port" =~ ^[0-9]+$ ]] || continue
    PORTS="${PORTS:+$PORTS,}${port}"
    drop_dir="/etc/systemd/system/${name}.d"
    mkdir -p "$drop_dir"
    if ! cat > "${drop_dir}/99-net-tcp-tune-fix.conf" <<EOF
# 由 snell-upgrade-patch.sh 自动写入
[Unit]
StartLimitIntervalSec=0
StartLimitBurst=0

[Service]
RestartSec=10
EOF
    then
        echo -e "  ${RED}✗${NC} 写入 ${drop_dir}/99-net-tcp-tune-fix.conf 失败（磁盘满/只读 fs？）"
        continue
    fi
    PATCHED=$((PATCHED + 1))
    echo -e "  ${GREEN}✓${NC} 已修补 $name (端口 $port)"
done

if [ "$PATCHED" -eq 0 ]; then
    echo -e "  ${YELLOW}⚠ 未找到任何 snell-*.service，跳过${NC}"
fi
echo ""

# === 2. 写入内核保留端口（合并其他 sysctl.d 已设置的端口，避免覆盖丢失） ===
echo -e "${YELLOW}[2/4] 注册内核保留端口（防止内核临时端口抢占 Snell 监听端口）${NC}"
if [ -n "$PORTS" ]; then
    # 扫描其他 sysctl.d 文件和 /etc/sysctl.conf，收集已设置的 ip_local_reserved_ports
    EXTRA_PORTS=""
    for sysctl_file in /etc/sysctl.d/*.conf /etc/sysctl.conf; do
        [ -f "$sysctl_file" ] || continue
        [ "$(basename "$sysctl_file")" = "99-zzz-snell-reserved-ports.conf" ] && continue
        line=$(grep -E '^[[:space:]]*net\.ipv4\.ip_local_reserved_ports' "$sysctl_file" 2>/dev/null | tail -n 1)
        [ -z "$line" ] && continue
        val=$(echo "$line" | sed -E 's/^[^=]+=[[:space:]]*//' | tr -d ' ')
        [ -z "$val" ] && continue
        EXTRA_PORTS="${EXTRA_PORTS:+$EXTRA_PORTS,}${val}"
    done

    # 合并 Snell 端口 + 其他端口，去重排序
    if [ -n "$EXTRA_PORTS" ]; then
        ALL_PORTS=$(echo "${PORTS},${EXTRA_PORTS}" | tr ',' '\n' | grep -E '^[0-9]+$' | sort -un | paste -sd, -)
        echo -e "  ${CYAN}ℹ${NC} 检测到其他 sysctl 文件已设保留端口: ${EXTRA_PORTS}，已合并保留"
    else
        ALL_PORTS="$PORTS"
    fi

    if ! cat > /etc/sysctl.d/99-zzz-snell-reserved-ports.conf <<EOF
# Snell 监听端口保留列表（由 snell-upgrade-patch.sh 自动管理）
# 作用：让内核 outbound 临时端口分配跳过这些端口，避免 bind 冲突
# 包含：所有 Snell 端口 + 其他 sysctl 文件中已设置的保留端口（合并去重）
net.ipv4.ip_local_reserved_ports = ${ALL_PORTS}
EOF
    then
        echo -e "  ${RED}✗${NC} 写入 /etc/sysctl.d/99-zzz-snell-reserved-ports.conf 失败"
    elif sysctl -p /etc/sysctl.d/99-zzz-snell-reserved-ports.conf >/dev/null 2>&1; then
        echo -e "  ${GREEN}✓${NC} 已注册保留端口: ${ALL_PORTS}"
    else
        echo -e "  ${YELLOW}⚠${NC} 文件已写入但 sysctl -p 应用失败，重启后会自动生效"
    fi
else
    echo -e "  ${YELLOW}⚠ 没有 Snell 端口需要保护，跳过${NC}"
fi
echo ""

# === 3. 重载 systemd + 重启所有 Snell ===
echo -e "${YELLOW}[3/4] 应用配置 + 重启所有 Snell 实例${NC}"
if [ "$PATCHED" -gt 0 ]; then
    systemctl daemon-reload
    systemctl reset-failed 'snell-*.service' 2>/dev/null
    systemctl restart 'snell-*.service'
    sleep 2
    ACTIVE=$(systemctl is-active 'snell-*.service' 2>/dev/null | grep -c "^active$")
    echo -e "  ${GREEN}✓${NC} 已重载 + 重启，当前 active 实例: ${ACTIVE}/${PATCHED}"
else
    echo -e "  ${YELLOW}⚠ 跳过${NC}"
fi
echo ""

# === 4. 加每日北京时间 04:00 自动重启 cron（兜底 Snell v5 mux fd 泄漏）===
echo -e "${YELLOW}[4/4] 注册每日北京时间 04:00 自动重启 cron${NC}"

if [ "$PATCHED" -eq 0 ]; then
    echo -e "  ${YELLOW}⚠${NC} 没有 Snell 实例，跳过 cron 注册"
elif ! command -v crontab >/dev/null 2>&1; then
    echo -e "  ${RED}✗${NC} 未安装 crontab 命令（需要 cron/cronie 包），跳过 cron 注册"
else
    # 北京时间 → 系统本地时间换算（照搬 Eric_port-traffic-dog 实现）
    bj2local() {
        local bh=$1 bm=$2 base td epoch lh lm
        base=$(TZ='Asia/Shanghai' date +%Y-%m-%d 2>/dev/null || date +%Y-%m-%d)
        td=$base
        epoch=$(TZ='Asia/Shanghai' date -d "$td $bh:$bm:00" +%s 2>/dev/null \
                || date -d "$td $bh:$bm:00" +%s 2>/dev/null)
        if [ -n "$epoch" ]; then
            lh=$(date -d "@$epoch" +%H 2>/dev/null || date -r "$epoch" +%H 2>/dev/null)
            lm=$(date -d "@$epoch" +%M 2>/dev/null || date -r "$epoch" +%M 2>/dev/null)
        fi
        if ! [[ "$lh" =~ ^[0-9]{1,2}$ ]]; then
            lh=$((10#$bh - 8)); lm=$((10#$bm))
            [ $lh -lt 0 ] && lh=$((lh+24))
        fi
        printf "%02d %02d\n" $((10#$lh)) $((10#$lm))
    }

    read -r LOCAL_H LOCAL_M < <(bj2local 04 00)
    TMP_CRON=$(mktemp)
    crontab -l 2>/dev/null | grep -v "# Snell每日重启" > "$TMP_CRON" || true
    echo "${LOCAL_M} ${LOCAL_H} * * * systemctl restart 'snell-*.service' >/dev/null 2>&1  # Snell每日重启" >> "$TMP_CRON"
    if crontab "$TMP_CRON" 2>/dev/null; then
        rm -f "$TMP_CRON"
        echo -e "  ${GREEN}✓${NC} 已注册：北京时间 04:00 = 本地时间 ${LOCAL_H}:${LOCAL_M}"
        # 检查 cron 服务是否运行
        if ! (systemctl is-active --quiet cron 2>/dev/null || systemctl is-active --quiet crond 2>/dev/null); then
            echo -e "  ${YELLOW}⚠${NC} cron 服务未运行，定时任务不会触发"
            echo -e "      Debian/Ubuntu: ${CYAN}systemctl enable --now cron${NC}"
            echo -e "      CentOS/Rocky:  ${CYAN}systemctl enable --now crond${NC}"
        fi
    else
        echo -e "  ${RED}✗${NC} 注册 cron 失败（临时文件保留: $TMP_CRON）"
    fi
fi
echo ""

# === 验证 ===
echo -e "${CYAN}===================================================="
echo -e "  ✅ 升级完成"
echo -e "====================================================${NC}"
echo ""
echo -e "${CYAN}Snell 实例状态:${NC}"
if [ "$PATCHED" -gt 0 ]; then
    systemctl --no-pager status 'snell-*.service' 2>/dev/null | grep -E "Active:|snell-[0-9]+\.service" | head -20
else
    echo "  （无）"
fi
echo ""
echo -e "${CYAN}内核保留端口:${NC}"
sysctl net.ipv4.ip_local_reserved_ports 2>/dev/null || echo "  （无）"
echo ""
echo -e "${CYAN}每日重启 cron:${NC}"
crontab -l 2>/dev/null | grep "Snell每日重启" || echo "  （无）"
echo ""
echo -e "${GREEN}补丁已生效。如需后续装新 Snell，请先把 net-tcp-tune.sh 主脚本更新到最新版（重跑 bbr 命令即可拉最新）。${NC}"
