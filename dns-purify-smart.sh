#!/usr/bin/env bash
#
# DNS净化与安全加固脚本 - 智能修复版
# 作者：NSdesk (原始版本) + AI优化
# 功能：自动检测并修复systemd-resolved问题，然后配置DoT+DNSSEC
#
set -euo pipefail

readonly TARGET_DNS="8.8.8.8#dns.google 1.1.1.1#cloudflare-dns.com"
readonly SECURE_RESOLVED_CONFIG="[Resolve]
DNS=${TARGET_DNS}
LLMNR=no
MulticastDNS=no
DNSSEC=allow-downgrade
DNSOverTLS=yes
"
readonly GREEN="\033[0;32m"
readonly YELLOW="\033[1;33m"
readonly RED="\033[0;31m"
readonly BLUE="\033[0;34m"
readonly NC="\033[0m"

log() { echo -e "${GREEN}--> $1${NC}"; }
log_warn() { echo -e "${YELLOW}--> $1${NC}"; }
log_error() { echo -e "${RED}--> $1${NC}" >&2; }
log_info() { echo -e "${BLUE}--> $1${NC}"; }

# 新增：智能检测并修复 systemd-resolved
fix_systemd_resolved() {
    log_info "正在检测 systemd-resolved 服务状态..."
    
    # 检查服务是否被 masked
    if systemctl is-enabled systemd-resolved &>/dev/null; then
        log "✅ systemd-resolved 服务状态正常"
        return 0
    fi
    
    # 检查是否被 masked
    if systemctl status systemd-resolved 2>&1 | grep -q "masked"; then
        log_warn "检测到 systemd-resolved 被屏蔽 (masked)，正在修复..."
        
        # 解除屏蔽
        if systemctl unmask systemd-resolved 2>/dev/null; then
            log "✅ 已成功解除 systemd-resolved 的屏蔽状态"
        else
            log_error "解除屏蔽失败，尝试手动修复..."
            # 手动删除屏蔽链接
            rm -f /etc/systemd/system/systemd-resolved.service 2>/dev/null || true
            systemctl daemon-reload
            log "✅ 已手动移除屏蔽链接"
        fi
        
        # 启用服务
        if systemctl enable systemd-resolved 2>/dev/null; then
            log "✅ 已启用 systemd-resolved 服务"
        else
            log_error "启用服务失败"
            return 1
        fi
        
        # 启动服务
        if systemctl start systemd-resolved 2>/dev/null; then
            log "✅ 已启动 systemd-resolved 服务"
        else
            log_error "启动服务失败"
            return 1
        fi
        
        # 等待服务完全启动
        sleep 2
        
        # 验证服务状态
        if systemctl is-active --quiet systemd-resolved; then
            log "✅ systemd-resolved 服务运行正常"
            return 0
        else
            log_error "服务启动后状态异常"
            systemctl status systemd-resolved --no-pager || true
            return 1
        fi
    else
        log_warn "systemd-resolved 未启用，正在启用..."
        systemctl enable systemd-resolved 2>/dev/null || true
        systemctl start systemd-resolved 2>/dev/null || true
        return 0
    fi
}

purify_and_harden_dns() {
    echo -e "\n--- 开始执行DNS净化与安全加固流程 ---"
    local debian_version
    debian_version=$(grep "VERSION_ID" /etc/os-release | cut -d'=' -f2 | tr -d '"' || echo "unknown")
    
    log "阶段一：正在清除所有潜在的DNS冲突源..."
    
    # 处理 dhclient
    local dhclient_conf="/etc/dhcp/dhclient.conf"
    if [[ -f "$dhclient_conf" ]]; then
        if ! grep -q "ignore domain-name-servers;" "$dhclient_conf" || ! grep -q "ignore domain-search;" "$dhclient_conf"; then
            log "正在驯服 DHCP 客户端 (dhclient)..."
            echo "" >> "$dhclient_conf"
            echo "ignore domain-name-servers;" >> "$dhclient_conf"
            echo "ignore domain-search;" >> "$dhclient_conf"
            log "✅ 已确保 'ignore' 指令存在于 ${dhclient_conf}"
        fi
    fi
    
    # 处理 if-up.d 脚本
    local ifup_script="/etc/network/if-up.d/resolved"
    if [[ -f "$ifup_script" ]] && [[ -x "$ifup_script" ]]; then
        log "正在禁用有冲突的 if-up.d 兼容性脚本..."
        chmod -x "$ifup_script"
        log "✅ 已移除 ${ifup_script} 的可执行权限。"
    fi
    
    # 处理 /etc/network/interfaces
    local interfaces_file="/etc/network/interfaces"
    if [[ -f "$interfaces_file" ]] && grep -qE '^[[:space:]]*dns-(nameservers|search|domain)' "$interfaces_file"; then
        log "正在净化 /etc/network/interfaces 中的厂商残留DNS配置..."
        sed -i -E 's/^[[:space:]]*(dns-(nameservers|search|domain).*)/# \1/' "$interfaces_file"
        log "✅ 旧有DNS配置已成功注释禁用。"
    fi
    
    log "阶段二：正在配置 systemd-resolved..."
    
    # 安装 systemd-resolved（如果需要）
    if ! command -v resolvectl &> /dev/null; then
        log "正在安装 systemd-resolved..."
        apt-get update -y > /dev/null
        apt-get install -y systemd-resolved > /dev/null
    fi
    
    # 处理 Debian 11 的 resolvconf 冲突
    if [[ "$debian_version" == "11" ]] && dpkg -s resolvconf &> /dev/null; then
        log "检测到 Debian 11 上的 'resolvconf'，正在卸载..."
        apt-get remove -y resolvconf > /dev/null
        rm -f /etc/resolv.conf
        log "✅ 'resolvconf' 已成功卸载。"
    fi
    
    # 🔧 关键修复：调用智能修复函数
    if ! fix_systemd_resolved; then
        log_error "无法修复 systemd-resolved 服务，脚本终止"
        exit 1
    fi
    
    log "正在应用最终的DNS安全配置 (DoT, DNSSEC...)"
    echo -e "${SECURE_RESOLVED_CONFIG}" > /etc/systemd/resolved.conf
    ln -sf /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf
    systemctl restart systemd-resolved
    sleep 2
    
    log "阶段三：正在安全地重启网络服务以应用所有更改..."
    if systemctl is-enabled --quiet networking.service 2>/dev/null; then
        systemctl restart networking.service
        log "✅ networking.service 已安全重启。"
    fi
    
    echo -e "\n${GREEN}✅ 全部操作完成！以下是最终的 DNS 配置状态：${NC}"
    echo "===================================================="
    resolvectl status
    echo "===================================================="
    echo -e "\n${GREEN}DNS净化脚本执行完成${NC}"
    echo -e "贡献者：NSdesk (原始) + AI优化"
    echo -e "更多信息：https://www.nodeseek.com/space/23129/"
    echo "===================================================="
}

main() {
    if [[ $EUID -ne 0 ]]; then
       log_error "错误: 此脚本必须以 root 用户身份运行。"
       exit 1
    fi
    
    echo "╔════════════════════════════════════════════════════════════╗"
    echo "║       DNS净化与安全加固脚本 - 智能修复版                    ║"
    echo "╚════════════════════════════════════════════════════════════╝"
    echo ""
    
    echo "--- 开始执行全面系统DNS健康检查 ---"
    local is_perfect=true
    
    echo -n "1. 检查 systemd-resolved 实时状态... "
    if ! command -v resolvectl &> /dev/null || ! resolvectl status &> /dev/null; then
        echo -e "${YELLOW}服务未运行或无响应。${NC}"
        is_perfect=false
    else
        local status_output
        status_output=$(resolvectl status)
        local current_dns
        current_dns=$(echo "${status_output}" | sed -n '/Global/,/^\s*$/{/DNS Servers:/s/.*DNS Servers:[[:space:]]*//p}' | tr -d '\r\n' | xargs)
        if [[ "${current_dns}" != "${TARGET_DNS}" ]] || ! echo "${status_output}" | grep -q -- "-LLMNR" || ! echo "${status_output}" | grep -q -- "-mDNS" || ! echo "${status_output}" | grep -q -- "+DNSOverTLS" || ! echo "${status_output}" | grep -q "DNSSEC=allow-downgrade"; then
            echo -e "${YELLOW}实时配置与安全目标不符。${NC}"
            is_perfect=false
        else
            echo -e "${GREEN}配置正确。${NC}"
        fi
    fi
    
    echo -n "2. 检查 dhclient.conf 配置... "
    local dhclient_conf="/etc/dhcp/dhclient.conf"
    if [[ -f "$dhclient_conf" ]]; then
        if grep -q "ignore domain-name-servers;" "$dhclient_conf" && grep -q "ignore domain-search;" "$dhclient_conf"; then
            echo -e "${GREEN}已净化。${NC}"
        else
            echo -e "${YELLOW}未发现 'ignore' 净化参数。${NC}"
            is_perfect=false
        fi
    else
        echo -e "${GREEN}文件不存在，无需净化。${NC}"
    fi
    
    echo -n "3. 检查 if-up.d 冲突脚本... "
    local ifup_script="/etc/network/if-up.d/resolved"
    if [[ ! -f "$ifup_script" ]] || [[ ! -x "$ifup_script" ]]; then
        echo -e "${GREEN}已禁用或不存在。${NC}"
    else
        echo -e "${YELLOW}脚本存在且可执行。${NC}"
        is_perfect=false
    fi
    
    # 🔧 新增：检查 systemd-resolved 是否被 masked
    echo -n "4. 检查 systemd-resolved 屏蔽状态... "
    if systemctl status systemd-resolved 2>&1 | grep -q "masked"; then
        echo -e "${YELLOW}服务被屏蔽 (masked)。${NC}"
        is_perfect=false
    else
        echo -e "${GREEN}未被屏蔽。${NC}"
    fi
    
    if [[ "$is_perfect" == true ]]; then
        echo -e "\n${GREEN}✅ 全面检查通过！系统DNS配置稳定且安全。无需任何操作。${NC}"
        echo -e "贡献者：NSdesk (原始) + AI优化"
        echo -e "更多信息：https://www.nodeseek.com/space/23129/"
        exit 0
    else
        echo -e "\n${YELLOW}--> 一项或多项检查未通过。为了确保系统的长期稳定，将执行完整的净化与加固流程...${NC}"
        purify_and_harden_dns
    fi
}

main "$@"

