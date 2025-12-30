#!/bin/bash
#=============================================================================
# 脚本名称: install-alias.sh
# 功能描述: 为 net-tcp-tune 脚本创建/卸载快捷别名
# 使用方法: 
#   安装: bash install-alias.sh [install]
#   卸载: bash install-alias.sh uninstall
#=============================================================================

YELLOW='\033[1;33m'
GREEN='\033[1;32m'
CYAN='\033[1;36m'
RED='\033[1;31m'
NC='\033[0m' # No Color

# 检测操作模式（安装或卸载）
MODE="${1:-install}"
if [ "$MODE" != "install" ] && [ "$MODE" != "uninstall" ]; then
    echo -e "${RED}错误: 未知参数 '$MODE'${NC}"
    echo "使用方法:"
    echo "  安装: bash install-alias.sh [install]"
    echo "  卸载: bash install-alias.sh uninstall"
    exit 1
fi

# 检测当前使用的 shell
CURRENT_SHELL=$(basename "$SHELL")

# 根据不同的 shell 设置配置文件（检查多个可能的配置文件）
detect_rc_file() {
    if [ "$CURRENT_SHELL" = "zsh" ]; then
        RC_FILE="$HOME/.zshrc"
    elif [ "$CURRENT_SHELL" = "bash" ]; then
        RC_FILE="$HOME/.bashrc"
        # 如果 .bashrc 不存在，使用 .bash_profile
        if [ ! -f "$RC_FILE" ]; then
            RC_FILE="$HOME/.bash_profile"
        fi
    else
        RC_FILE="$HOME/.bashrc"
    fi
    
    # 如果文件不存在，创建它
    if [ ! -f "$RC_FILE" ]; then
        touch "$RC_FILE"
    fi
}

detect_rc_file

# 卸载功能
uninstall_alias() {
    echo -e "${CYAN}=== 卸载 net-tcp-tune 快捷别名 ===${NC}"
    echo ""
    echo -e "检测到 Shell: ${GREEN}${CURRENT_SHELL}${NC}"
    echo -e "配置文件: ${GREEN}${RC_FILE}${NC}"
    echo ""
    
    # 检查别名是否已存在
    if ! grep -q "net-tcp-tune 快捷别名" "$RC_FILE" 2>/dev/null; then
        echo -e "${YELLOW}未找到已安装的别名，无需卸载${NC}"
        echo ""
        return 0
    fi
    
    # 创建临时文件来存储清理后的内容
    TEMP_FILE=$(mktemp)
    
    # 删除包含 "net-tcp-tune 快捷别名" 的整个块（包括注释和别名）
    # 先尝试删除从分隔线开始到别名结束的整个块
    # 如果失败，则只删除别名块本身
    if grep -q "^# ================" "$RC_FILE" 2>/dev/null; then
        # 尝试删除从分隔线开始到别名结束的整个块
        sed '/^# ================/,/^alias dog=/d' "$RC_FILE" > "$TEMP_FILE" 2>/dev/null
        # 兼容旧版本只有 bbr 的情况
        if grep -q "net-tcp-tune 快捷别名" "$TEMP_FILE" 2>/dev/null; then
             sed '/^# ================/,/^alias bbr=/d' "$RC_FILE" > "$TEMP_FILE" 2>/dev/null
        fi

        # 检查是否还有别名残留
        if grep -q "net-tcp-tune 快捷别名" "$TEMP_FILE" 2>/dev/null; then
            # 如果还有残留，使用更精确的删除
            sed '/net-tcp-tune 快捷别名/,/^alias dog=/d' "$RC_FILE" > "$TEMP_FILE"
        fi
    else
        # 直接删除别名块
        sed '/net-tcp-tune 快捷别名/,/^alias dog=/d' "$RC_FILE" > "$TEMP_FILE"
    fi
    
    # 检查是否有变更
    if ! diff -q "$RC_FILE" "$TEMP_FILE" > /dev/null 2>&1; then
        # 备份原文件
        cp "$RC_FILE" "${RC_FILE}.bak.$(date +%Y%m%d_%H%M%S)"
        
        # 替换原文件
        mv "$TEMP_FILE" "$RC_FILE"
        echo -e "${GREEN}✅ 别名已从 ${RC_FILE} 中移除${NC}"
        echo ""
        echo -e "${YELLOW}提示: 原配置文件已备份为 ${RC_FILE}.bak.*${NC}"
        echo ""
        echo -e "${CYAN}=== 现在生效（执行以下命令）===${NC}"
        echo ""
        echo -e "${YELLOW}source ${RC_FILE}${NC}"
        echo ""
        echo "或者关闭终端重新打开，卸载即生效。"
        echo ""
    else
        rm -f "$TEMP_FILE"
        echo -e "${YELLOW}未找到需要删除的内容${NC}"
        echo ""
    fi
}

# 安装功能
install_alias() {
    echo -e "${CYAN}=== 安装 net-tcp-tune 快捷别名 ===${NC}"
    echo ""
    echo -e "检测到 Shell: ${GREEN}${CURRENT_SHELL}${NC}"
    echo ""
    echo -e "配置文件: ${GREEN}${RC_FILE}${NC}"
    echo ""
    
    # 定义要添加的别名（带时间戳参数，确保每次获取最新版本）
    ALIAS_CONTENT='
# ========================================
# net-tcp-tune 快捷别名 (自动添加)
# 使用时间戳参数确保每次都获取最新版本，避免缓存
# ========================================
alias bbr="bash <(curl -fsSL \"https://raw.githubusercontent.com/Eric86777/vps-tcp-tune/main/net-tcp-tune.sh?\$(date +%s)\")"
alias dog="bash <(curl -fsSL \"https://raw.githubusercontent.com/Eric86777/vps-tcp-tune/main/Eric_port-traffic-dog.sh?\$(date +%s)\")"
'
    
    # 检查别名是否已存在
    if grep -q "net-tcp-tune 快捷别名" "$RC_FILE" 2>/dev/null; then
        echo -e "${YELLOW}配置已存在，正在更新...${NC}"
        
        # 备份文件
        cp "$RC_FILE" "${RC_FILE}.bak"
        
        # 方案：读取文件，过滤掉原来的 alias dog= 行，然后再追加新的
        # 1. 如果有旧的块结构，尝试整体替换（兼容旧版）
        if grep -q "^# ================" "$RC_FILE" 2>/dev/null; then
             sed -i '/^# ================/,/^alias dog=/d' "$RC_FILE" 2>/dev/null || sed -i '/^# ================/,/^alias bbr=/d' "$RC_FILE"
        else
             sed -i '/net-tcp-tune 快捷别名/,/^alias bbr=/d' "$RC_FILE"
        fi

        # 2. ⚡️暴力清理：确保没有残留的 alias dog= 行 (这是为了修复之前 sed 没删干净的情况)
        if grep -q "alias dog=" "$RC_FILE"; then
            grep -v "alias dog=" "$RC_FILE" > "${RC_FILE}.tmp" && mv "${RC_FILE}.tmp" "$RC_FILE"
        fi
        
        # 再添加新的
        echo "$ALIAS_CONTENT" >> "$RC_FILE"
        echo -e "${GREEN}✅ 别名已更新到 ${RC_FILE}${NC}"
        echo ""
    else
        # 添加别名到配置文件
        echo "$ALIAS_CONTENT" >> "$RC_FILE"
        echo -e "${GREEN}✅ 别名已添加到 ${RC_FILE}${NC}"
        echo ""
    fi
    
    echo -e "${CYAN}=== 快捷命令 ===${NC}"
    echo ""
    echo -e "  ${GREEN}bbr${NC}   - 一键运行系统优化脚本"
    echo -e "  ${GREEN}dog${NC}   - 一键运行端口流量狗"
    echo ""
    echo -e "${CYAN}=== 使用方法 ===${NC}"
    echo ""
    echo "1. 重新加载配置："
    echo -e "   ${YELLOW}source ${RC_FILE}${NC}"
    echo ""
    echo "2. 或者关闭终端重新打开"
    echo ""
    echo "3. 然后直接输入快捷命令："
    echo -e "   ${GREEN}bbr${NC}  (系统优化)"
    echo -e "   ${GREEN}dog${NC}  (端口监控)"
    echo ""
    echo -e "${CYAN}=== 卸载方法 ===${NC}"
    echo ""
    echo "如需卸载别名，请运行："
    echo -e "   ${YELLOW}bash install-alias.sh uninstall${NC}"
    echo ""
    echo -e "${CYAN}=== 现在就生效（执行以下命令）===${NC}"
    echo ""
    echo -e "${YELLOW}source ${RC_FILE}${NC}"
    echo ""
}

# 根据模式执行相应操作
case "$MODE" in
    install)
        install_alias
        ;;
    uninstall)
        uninstall_alias
        ;;
esac

