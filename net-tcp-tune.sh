#!/bin/bash
#=============================================================================
# BBR v3 终极优化脚本 - Ultimate Edition
# 功能：结合 XanMod 官方内核的稳定性 + 专业队列算法调优
# 特点：安全性 + 性能 双优化
#=============================================================================
# 版本管理规则：
# 1. 大版本更新时修改 SCRIPT_VERSION，并更新版本备注（保留最新5条）
# 2. 小修复时只修改 SCRIPT_LAST_UPDATE，用于快速识别脚本是否已更新
#=============================================================================
# v4.9.0 更新: OpenClaw全面重构：对照官方文档修正服务名/配置格式/频道插件，新增Antigravity预设+模型列表更新+查看部署信息 (by Eric86777)
# v4.8.7 更新: OpenClaw新增频道管理功能，支持Telegram/WhatsApp/Discord/Slack一键配置 (by Eric86777)
# v4.8.6 更新: AI代理工具箱新增OpenAI Responses API转换代理，支持Chat Completions客户端对接Responses API服务 (by Eric86777)
# v4.8.4 更新: 新增功能66一键全自动优化（两阶段：安装内核→重启→全自动调优3→4→5→6→8） (by Eric86777)
# v4.8.3 更新: 功能5入口添加配置状态检测+老版持久化风险警告+README更新 (by Eric86777)

SCRIPT_VERSION="4.9.0"
SCRIPT_LAST_UPDATE="OpenClaw全面重构+Antigravity预设+模型更新+部署信息查看"
#=============================================================================

#=============================================================================
# 📋 推荐配置方案（基于实测优化）
#=============================================================================
# 
# 💡 测试环境：经过本人十几二十几台不同服务器的测试
#    包括酷雪云北京9929等多个节点的实测验证
# 
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 
# ⭐ 首选方案（推荐）：
#    步骤1 → 执行菜单选项 1：BBR v3 内核安装
#    步骤2 → 执行菜单选项 3：BBR 直连/落地优化（智能带宽检测）
#            选择子选项 1 进行自动检测
#    步骤3 → 执行菜单选项 6：Realm转发timeout修复（如使用 Realm 转发）
# 
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 
# 🔧 次选方案（备用）：
#    步骤1 → 执行菜单选项 1：BBR v3 内核安装
#    步骤2 → 执行菜单选项 5：NS论坛CAKE调优
#    步骤3 → 执行菜单选项 6：科技lion高性能模式内核参数优化
#            选择第一个选项
# 
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 
#=============================================================================

# 颜色定义（保留中文变量名以兼容现有代码）
gl_hong='\033[31m'      # 红色
gl_lv='\033[32m'        # 绿色
gl_huang='\033[33m'     # 黄色
gl_bai='\033[0m'        # 重置
gl_kjlan='\033[96m'     # 亮青色
gl_zi='\033[35m'        # 紫色
gl_hui='\033[90m'       # 灰色

# 英文别名（供新代码使用）
readonly COLOR_RED="$gl_hong"
readonly COLOR_GREEN="$gl_lv"
readonly COLOR_YELLOW="$gl_huang"
readonly COLOR_RESET="$gl_bai"
readonly COLOR_CYAN="$gl_kjlan"
readonly COLOR_PURPLE="$gl_zi"
readonly COLOR_GRAY="$gl_hui"

# 显示宽度计算（中文占2列，ASCII占1列）
get_display_width() {
    local str="$1"
    local byte_len=$(printf '%s' "$str" | LC_ALL=C wc -c | tr -d ' ')
    local char_len=${#str}
    local extra=$((byte_len - char_len))
    local wide=$((extra / 2))
    echo $((char_len + wide))
}

# 格式化字符串到固定显示宽度（截断+填充，确保宽度精确）
format_fixed_width() {
    local str="$1"
    local target_width=$2
    local current_width=$(get_display_width "$str")

    # 如果太长，截断
    if [ "$current_width" -gt "$target_width" ]; then
        local result=""
        local i=0
        local len=${#str}
        while [ $i -lt $len ]; do
            local char="${str:$i:1}"
            local test_str="${result}${char}"
            local test_width=$(get_display_width "$test_str")
            if [ "$test_width" -gt $((target_width - 2)) ]; then
                str="${result}.."
                break
            fi
            result="$test_str"
            i=$((i + 1))
        done
        current_width=$(get_display_width "$str")
    fi

    # 填充到目标宽度
    local padding=$((target_width - current_width))
    if [ $padding -gt 0 ]; then
        printf "%s%*s" "$str" "$padding" ""
    else
        printf "%s" "$str"
    fi
}

# GitHub 代理设置
gh_proxy="https://"

# 配置文件路径（使用独立文件，不破坏系统配置）
SYSCTL_CONF="/etc/sysctl.d/99-bbr-ultimate.conf"

#=============================================================================
# 常量定义（版本号、URL 等集中管理）
#=============================================================================

# 版本号（SCRIPT_VERSION / SCRIPT_LAST_UPDATE 在文件头部定义）
readonly CADDY_DEFAULT_VERSION="2.10.2"
readonly SNELL_DEFAULT_VERSION="5.0.1"

# IP 查询服务 URL（按优先级排序）
readonly IP_CHECK_V4_URLS=(
    "https://api.ipify.org"
    "https://ip.sb"
    "https://checkip.amazonaws.com"
    "https://ipinfo.io/ip"
)
readonly IP_CHECK_V6_URLS=(
    "https://api64.ipify.org"
    "https://v6.ipinfo.io/ip"
    "https://ip.sb"
)

# IP 信息查询
readonly IP_INFO_URL="https://ipinfo.io"

#=============================================================================
# 日志系统
#=============================================================================

readonly LOG_FILE="/var/log/net-tcp-tune.log"
LOG_LEVEL="${LOG_LEVEL:-INFO}"

# 统一日志函数
log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')

    # 写入日志文件（静默失败）
    echo "[$timestamp] [$level] $message" >> "$LOG_FILE" 2>/dev/null || true

    # 根据级别输出到终端
    case "$level" in
        ERROR)
            echo -e "${gl_hong}[ERROR] $message${gl_bai}" >&2
            ;;
        WARN)
            echo -e "${gl_huang}[WARN] $message${gl_bai}"
            ;;
        INFO)
            [ "$LOG_LEVEL" != "ERROR" ] && echo -e "${gl_lv}[INFO] $message${gl_bai}"
            ;;
        DEBUG)
            [ "$LOG_LEVEL" = "DEBUG" ] && echo -e "${gl_hui}[DEBUG] $message${gl_bai}"
            ;;
    esac
}

# 便捷日志函数
log_error() { log "ERROR" "$@"; }
log_warn()  { log "WARN" "$@"; }
log_info()  { log "INFO" "$@"; }
log_debug() { log "DEBUG" "$@"; }

#=============================================================================
# 错误处理
#=============================================================================

# 清理临时文件
cleanup_temp_files() {
    rm -f /tmp/net-tcp-tune.* 2>/dev/null || true
    rm -f /tmp/caddy.tar.gz 2>/dev/null || true
}

# 全局错误处理器（可选启用）
error_handler() {
    local exit_code=$1
    local line_no=$2
    local command="$3"

    log_error "脚本执行失败"
    log_error "  退出码: $exit_code"
    log_error "  行号: $line_no"
    log_error "  命令: $command"

    cleanup_temp_files
}

# 启用严格模式（用于调试）
enable_strict_mode() {
    set -euo pipefail
    trap 'error_handler $? $LINENO "$BASH_COMMAND"' ERR
}

# 退出时清理
trap cleanup_temp_files EXIT

#=============================================================================
# 工具函数
#=============================================================================

check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo -e "${gl_hong}错误: ${gl_bai}此脚本需要 root 权限运行！"
        echo "请使用: sudo bash $0"
        exit 1
    fi
}

break_end() {
    [ "$AUTO_MODE" = "1" ] && return
    echo -e "${gl_lv}操作完成${gl_bai}"
    echo "按任意键继续..."
    read -n 1 -s -r -p ""
    echo ""
}

clean_sysctl_conf() {
    # 备份主配置文件
    if [ -f /etc/sysctl.conf ] && ! [ -f /etc/sysctl.conf.bak.original ]; then
        cp /etc/sysctl.conf /etc/sysctl.conf.bak.original
    fi
    
    # 注释所有冲突参数
    sed -i '/^net\.core\.rmem_max/s/^/# /' /etc/sysctl.conf 2>/dev/null
    sed -i '/^net\.core\.wmem_max/s/^/# /' /etc/sysctl.conf 2>/dev/null
    sed -i '/^net\.ipv4\.tcp_rmem/s/^/# /' /etc/sysctl.conf 2>/dev/null
    sed -i '/^net\.ipv4\.tcp_wmem/s/^/# /' /etc/sysctl.conf 2>/dev/null
    sed -i '/^net\.core\.default_qdisc/s/^/# /' /etc/sysctl.conf 2>/dev/null
    sed -i '/^net\.ipv4\.tcp_congestion_control/s/^/# /' /etc/sysctl.conf 2>/dev/null
}

install_package() {
    local packages=("$@")
    local missing_packages=()
    local os_release="/etc/os-release"
    local os_id=""
    local os_like=""
    local pkg_manager=""
    local update_cmd=()
    local install_cmd=()

    for package in "${packages[@]}"; do
        if ! command -v "$package" &>/dev/null; then
            missing_packages+=("$package")
        fi
    done

    if [ "${#missing_packages[@]}" -eq 0 ]; then
        return 0
    fi

    if [ -r "$os_release" ]; then
        # shellcheck disable=SC1091
        . "$os_release"
        os_id="${ID,,}"
        os_like="${ID_LIKE,,}"
    fi

    local detection="${os_id} ${os_like}"

    if [[ "$detection" =~ (debian|ubuntu) ]]; then
        pkg_manager="apt"
        update_cmd=(apt-get update)
        install_cmd=(apt-get install -y)
    elif [[ "$detection" =~ (rhel|centos|fedora|rocky|alma|redhat) ]]; then
        if command -v dnf &>/dev/null; then
            pkg_manager="dnf"
            update_cmd=(dnf makecache)
            install_cmd=(dnf install -y)
        elif command -v yum &>/dev/null; then
            pkg_manager="yum"
            update_cmd=(yum makecache)
            install_cmd=(yum install -y)
        else
            echo "错误: 未找到可用的 RHEL 系包管理器 (dnf 或 yum)" >&2
            return 1
        fi
    else
        echo "错误: 未支持的 Linux 发行版，无法自动安装依赖。请手动安装: ${missing_packages[*]}" >&2
        return 1
    fi

    if [ ${#update_cmd[@]} -gt 0 ]; then
        echo -e "${gl_huang}正在更新软件仓库...${gl_bai}"
        if ! "${update_cmd[@]}"; then
            echo "错误: 使用 ${pkg_manager} 更新软件仓库失败。" >&2
            return 1
        fi
    fi

    for package in "${missing_packages[@]}"; do
        echo -e "${gl_huang}正在安装 $package...${gl_bai}"
        if ! "${install_cmd[@]}" "$package"; then
            echo "错误: ${pkg_manager} 安装 $package 失败，请检查上方输出信息。" >&2
            return 1
        fi
    done
}

safe_download_script() {
    local url=$1
    local output_file=$2

    if command -v curl &>/dev/null; then
        curl -fsSL --connect-timeout 10 --max-time 60 "$url" -o "$output_file"
    elif command -v wget &>/dev/null; then
        wget -qO "$output_file" "$url"
    else
        return 1
    fi

    [ -s "$output_file" ]
}

verify_downloaded_script() {
    local file=$1

    if [ ! -s "$file" ]; then
        return 1
    fi

    if head -n 1 "$file" | grep -qiE '<!DOCTYPE|<html'; then
        return 1
    fi

    # 检查 shebang，同时处理 UTF-8 BOM (ef bb bf) 开头的情况
    head -n 5 "$file" | sed 's/^\xef\xbb\xbf//' | grep -q '^#!'
}

run_remote_script() {
    local url=$1
    local interpreter=${2:-bash}
    shift 2

    local tmp_file
    tmp_file=$(mktemp /tmp/net-tcp-tune.XXXXXX) || {
        echo -e "${gl_hong}❌ 无法创建临时文件${gl_bai}"
        return 1
    }

    if ! safe_download_script "$url" "$tmp_file"; then
        echo -e "${gl_hong}❌ 下载脚本失败: ${url}${gl_bai}"
        rm -f "$tmp_file"
        return 1
    fi

    if ! verify_downloaded_script "$tmp_file"; then
        echo -e "${gl_hong}❌ 脚本校验失败，已取消执行${gl_bai}"
        rm -f "$tmp_file"
        return 1
    fi

    chmod +x "$tmp_file"
    "$interpreter" "$tmp_file" "$@"
    local rc=$?
    rm -f "$tmp_file"
    return $rc
}

check_disk_space() {
    local required_gb=$1
    local required_space_mb=$((required_gb * 1024))
    local available_space_mb=$(df -m / | awk 'NR==2 {print $4}')

    if [ "$available_space_mb" -lt "$required_space_mb" ]; then
        echo -e "${gl_huang}警告: ${gl_bai}磁盘空间不足！"
        echo "当前可用: $((available_space_mb/1024))G | 最低需求: ${required_gb}G"
        read -e -p "是否继续？(Y/N): " continue_choice
        case "$continue_choice" in
            [Yy]) return 0 ;;
            *) return 1 ;;
        esac
    fi
}

check_swap() {
    local swap_total=$(free -m | awk 'NR==3{print $2}')

    if [ "$swap_total" -eq 0 ]; then
        echo -e "${gl_huang}检测到无虚拟内存，正在创建 1G SWAP...${gl_bai}"
        if fallocate -l $((1025 * 1024 * 1024)) /swapfile 2>/dev/null || dd if=/dev/zero of=/swapfile bs=1M count=1025 2>/dev/null; then
            chmod 600 /swapfile
            mkswap /swapfile > /dev/null 2>&1
            if swapon /swapfile 2>/dev/null; then
                # 防止重复写入 fstab
                if ! grep -q '/swapfile' /etc/fstab 2>/dev/null; then
                    echo '/swapfile none swap sw 0 0' >> /etc/fstab
                fi
                echo -e "${gl_lv}虚拟内存创建成功${gl_bai}"
            else
                echo -e "${gl_huang}⚠️  SWAP 激活失败，但不影响安装${gl_bai}"
            fi
        else
            echo -e "${gl_huang}⚠️  SWAP 文件创建失败，但不影响安装${gl_bai}"
        fi
    fi
}

add_swap() {
    local new_swap=$1  # 获取传入的参数（单位：MB）

    echo -e "${gl_kjlan}=== 调整虚拟内存（仅管理 /swapfile） ===${gl_bai}"

    # 检测是否存在活跃的 /dev/* swap 分区
    local dev_swap_list
    dev_swap_list=$(awk 'NR>1 && $1 ~ /^\/dev\// {printf "  • %s (大小: %d MB, 已用: %d MB)\n", $1, int(($3+512)/1024), int(($4+512)/1024)}' /proc/swaps)

    if [ -n "$dev_swap_list" ]; then
        echo -e "${gl_huang}检测到以下 /dev/ 虚拟内存处于激活状态：${gl_bai}"
        echo "$dev_swap_list"
        echo ""
        echo -e "${gl_huang}提示:${gl_bai} 本脚本不会修改 /dev/ 分区，请使用 ${gl_zi}swapoff <设备>${gl_bai} 等命令手动处理。"
        echo ""
    fi

    # 确保 /swapfile 不再被使用
    swapoff /swapfile 2>/dev/null
    
    # 删除旧的 /swapfile
    rm -f /swapfile
    
    echo "正在创建 ${new_swap}MB 虚拟内存..."
    
    # 创建新的 swap 分区
    fallocate -l $(( (new_swap + 1) * 1024 * 1024 )) /swapfile || dd if=/dev/zero of=/swapfile bs=1M count=$((new_swap + 1))
    chmod 600 /swapfile
    mkswap /swapfile > /dev/null 2>&1
    swapon /swapfile
    
    # 更新 /etc/fstab
    sed -i '/\/swapfile/d' /etc/fstab
    echo "/swapfile swap swap defaults 0 0" >> /etc/fstab
    
    # Alpine Linux 特殊处理
    if [ -f /etc/alpine-release ]; then
        echo "nohup swapon /swapfile" > /etc/local.d/swap.start
        chmod +x /etc/local.d/swap.start
        rc-update add local 2>/dev/null
    fi
    
    echo -e "${gl_lv}虚拟内存大小已调整为 ${new_swap}MB${gl_bai}"
}

calculate_optimal_swap() {
    # 获取物理内存（MB）
    local mem_total=$(free -m | awk 'NR==2{print $2}')
    local recommended_swap
    local reason
    
    echo -e "${gl_kjlan}=== 智能计算虚拟内存大小 ===${gl_bai}"
    echo ""
    echo -e "检测到物理内存: ${gl_huang}${mem_total}MB${gl_bai}"
    echo ""
    echo "计算过程："
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
    # 根据内存大小计算推荐 SWAP
    if [ "$mem_total" -lt 512 ]; then
        # < 512MB: SWAP = 1GB（固定）
        recommended_swap=1024
        reason="内存极小（< 512MB），固定推荐 1GB"
        echo "→ 内存 < 512MB"
        echo "→ 推荐固定 1GB SWAP"
        
    elif [ "$mem_total" -lt 1024 ]; then
        # 512MB ~ 1GB: SWAP = 内存 × 2
        recommended_swap=$((mem_total * 2))
        reason="内存较小（512MB-1GB），推荐 2 倍内存"
        echo "→ 内存在 512MB - 1GB 之间"
        echo "→ 计算公式: SWAP = 内存 × 2"
        echo "→ ${mem_total}MB × 2 = ${recommended_swap}MB"
        
    elif [ "$mem_total" -lt 2048 ]; then
        # 1GB ~ 2GB: SWAP = 内存 × 1.5
        recommended_swap=$((mem_total * 3 / 2))
        reason="内存适中（1-2GB），推荐 1.5 倍内存"
        echo "→ 内存在 1GB - 2GB 之间"
        echo "→ 计算公式: SWAP = 内存 × 1.5"
        echo "→ ${mem_total}MB × 1.5 = ${recommended_swap}MB"
        
    elif [ "$mem_total" -lt 4096 ]; then
        # 2GB ~ 4GB: SWAP = 内存 × 1
        recommended_swap=$mem_total
        reason="内存充足（2-4GB），推荐与内存同大小"
        echo "→ 内存在 2GB - 4GB 之间"
        echo "→ 计算公式: SWAP = 内存 × 1"
        echo "→ ${mem_total}MB × 1 = ${recommended_swap}MB"
        
    elif [ "$mem_total" -lt 8192 ]; then
        # 4GB ~ 8GB: SWAP = 4GB（固定）
        recommended_swap=4096
        reason="内存较多（4-8GB），固定推荐 4GB"
        echo "→ 内存在 4GB - 8GB 之间"
        echo "→ 固定推荐 4GB SWAP"
        
    else
        # >= 8GB: SWAP = 4GB（固定）
        recommended_swap=4096
        reason="内存充裕（≥ 8GB），固定推荐 4GB"
        echo "→ 内存 ≥ 8GB"
        echo "→ 固定推荐 4GB SWAP"
    fi
    
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    echo -e "${gl_lv}计算结果：${gl_bai}"
    echo -e "  物理内存:   ${gl_huang}${mem_total}MB${gl_bai}"
    echo -e "  推荐 SWAP:  ${gl_huang}${recommended_swap}MB${gl_bai}"
    echo -e "  总可用内存: ${gl_huang}$((mem_total + recommended_swap))MB${gl_bai}"
    echo ""
    echo -e "${gl_zi}推荐理由: ${reason}${gl_bai}"
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    
    # 确认是否应用
    read -e -p "$(echo -e "${gl_huang}是否应用此配置？(Y/N): ${gl_bai}")" confirm
    
    case "$confirm" in
        [Yy])
            add_swap "$recommended_swap"
            return 0
            ;;
        *)
            echo "已取消"
            sleep 2
            return 1
            ;;
    esac
}

manage_swap() {
    while true; do
        clear
        echo -e "${gl_kjlan}=== 虚拟内存管理（仅限 /swapfile） ===${gl_bai}"
        echo -e "${gl_huang}提示:${gl_bai} 如需调整 /dev/ swap 分区，请手动执行 swapoff/swap 分区工具。"

        local mem_total=$(free -m | awk 'NR==2{print $2}')
        local swap_used=$(free -m | awk 'NR==3{print $3}')
        local swap_total=$(free -m | awk 'NR==3{print $2}')
        local swap_info=$(free -m | awk 'NR==3{used=$3; total=$2; if (total == 0) {percentage=0} else {percentage=used*100/total}; printf "%dM/%dM (%d%%)", used, total, percentage}')
        
        echo -e "物理内存:     ${gl_huang}${mem_total}MB${gl_bai}"
        echo -e "当前虚拟内存: ${gl_huang}$swap_info${gl_bai}"
        echo "------------------------------------------------"
        echo "1. 分配 1024M (1GB) - 固定配置"
        echo "2. 分配 2048M (2GB) - 固定配置"
        echo "3. 分配 4096M (4GB) - 固定配置"
        echo "4. 智能计算推荐值 - 自动计算最佳配置"
        echo "0. 返回主菜单"
        echo "------------------------------------------------"
        read -e -p "请输入选择: " choice
        
        case "$choice" in
            1)
                add_swap 1024
                break_end
                ;;
            2)
                add_swap 2048
                break_end
                ;;
            3)
                add_swap 4096
                break_end
                ;;
            4)
                calculate_optimal_swap
                if [ $? -eq 0 ]; then
                    break_end
                fi
                ;;
            0)
                return
                ;;
            *)
                echo "无效选择"
                sleep 2
                ;;
        esac
    done
}

# 通用 IP 优先级设置函数
# 参数: $1 = "ipv4" 或 "ipv6"
set_ip_priority() {
    local ip_type="$1"

    # 参数校验
    if [ "$ip_type" != "ipv4" ] && [ "$ip_type" != "ipv6" ]; then
        echo -e "${gl_hong}错误：参数必须是 ipv4 或 ipv6${gl_bai}"
        return 1
    fi

    # 根据类型设置变量
    if [ "$ip_type" = "ipv4" ]; then
        local title="IPv4"
        local ipv4_precedence=100
        local ipv6_precedence=10
        local curl_flag="-4"
        local secondary_flag="-6"
        local primary="IPv4"
        local secondary="IPv6"
    else
        local title="IPv6"
        local ipv4_precedence=10
        local ipv6_precedence=100
        local curl_flag="-6"
        local secondary_flag="-4"
        local primary="IPv6"
        local secondary="IPv4"
    fi

    clear
    echo -e "${gl_kjlan}=== 设置${title}优先 ===${gl_bai}"
    echo ""

    # 备份原配置文件并记录原始状态
    if [ -f /etc/gai.conf ]; then
        cp /etc/gai.conf /etc/gai.conf.bak.$(date +%Y%m%d_%H%M%S)
        echo "已备份原配置文件到 /etc/gai.conf.bak.*"
        # 记录原先存在文件
        echo "existed" > /etc/gai.conf.original_state
    else
        # 记录原先不存在文件
        echo "not_existed" > /etc/gai.conf.original_state
        echo "原先无配置文件，已记录原始状态"
    fi

    echo "正在设置 ${title} 优先..."

    # 创建配置文件
    cat > /etc/gai.conf << EOF
# Configuration for getaddrinfo(3).
#
# 设置 ${title} 优先

# IPv4 addresses
precedence ::ffff:0:0/96  ${ipv4_precedence}

# IPv6 addresses
precedence ::/0           ${ipv6_precedence}

# IPv4-mapped IPv6 addresses
precedence ::1/128        50

# Link-local addresses
precedence fe80::/10      1
precedence fec0::/10      1
precedence fc00::/7       1

# Site-local addresses (deprecated)
precedence 2002::/16      30
EOF

    # 刷新 nscd 缓存（如果安装了）
    if command -v nscd &> /dev/null; then
        systemctl restart nscd 2>/dev/null || service nscd restart 2>/dev/null || true
        echo "已刷新 nscd DNS 缓存"
    fi

    # 刷新 systemd-resolved 缓存（如果使用）
    if command -v resolvectl &> /dev/null; then
        resolvectl flush-caches 2>/dev/null || true
        echo "已刷新 systemd-resolved DNS 缓存"
    fi

    echo -e "${gl_lv}✅ ${title} 优先已设置${gl_bai}"
    echo ""
    echo "当前出口 IP 地址："
    echo "------------------------------------------------"
    curl ${curl_flag} ip.sb 2>/dev/null || curl ip.sb
    echo ""
    echo "------------------------------------------------"
    echo ""
    echo -e "${gl_huang}提示：${gl_bai}"
    echo "1. 配置已生效，无需重启系统"
    echo "2. 新启动的程序将自动使用 ${title} 优先"
    echo "3. 如需强制指定，可使用: curl ${curl_flag} ip.sb (强制${primary}) 或 curl ${secondary_flag} ip.sb (强制${secondary})"
    echo "4. 已运行的长连接服务（如Nginx、Docker容器）可能需要重启服务才能应用"
    echo ""

    break_end
}

manage_ip_priority() {
    while true; do
        clear
        echo -e "${gl_kjlan}=== 设置IPv4/IPv6优先级 ===${gl_bai}"
        echo ""
        echo "1. 设置IPv4优先"
        echo "2. 设置IPv6优先"
        echo "3. 恢复IP优先级配置"
        echo "0. 返回主菜单"
        echo ""
        echo "------------------------------------------------"
        read -p "请选择操作 [0-3]: " ip_priority_choice
        echo ""
        
        case $ip_priority_choice in
            1)
                set_ip_priority "ipv4"
                ;;
            2)
                set_ip_priority "ipv6"
                ;;
            3)
                restore_gai_conf
                ;;
            0)
                break
                ;;
            *)
                echo -e "${gl_hong}无效选择，请重新输入${gl_bai}"
                sleep 2
                ;;
        esac
    done
}

restore_gai_conf() {
    clear
    echo -e "${gl_kjlan}=== 恢复 IP 优先级配置 ===${gl_bai}"
    echo ""

    # 检查是否有原始状态记录
    if [ ! -f /etc/gai.conf.original_state ]; then
        echo -e "${gl_huang}⚠️  未找到原始状态记录${gl_bai}"
        echo "可能的原因："
        echo "1. 从未使用过本脚本设置过 IPv4/IPv6 优先级"
        echo "2. 原始状态记录文件已被删除"
        echo ""
        
        # 列出所有备份文件
        if ls /etc/gai.conf.bak.* 2>/dev/null; then
            echo "发现以下备份文件："
            ls -lh /etc/gai.conf.bak.* 2>/dev/null
            echo ""
            echo "是否要手动恢复最新的备份？[y/n]"
            read -p "请选择: " manual_restore
            if [[ "$manual_restore" == "y" || "$manual_restore" == "Y" ]]; then
                latest_backup=$(ls -t /etc/gai.conf.bak.* 2>/dev/null | head -1)
                if [ -n "$latest_backup" ]; then
                    cp "$latest_backup" /etc/gai.conf
                    echo -e "${gl_lv}✅ 已从备份恢复: $latest_backup${gl_bai}"
                fi
            fi
        else
            echo "也未找到任何备份文件。"
            echo ""
            echo "是否要删除当前的 gai.conf 文件（恢复到系统默认）？[y/n]"
            read -p "请选择: " delete_conf
            if [[ "$delete_conf" == "y" || "$delete_conf" == "Y" ]]; then
                rm -f /etc/gai.conf
                echo -e "${gl_lv}✅ 已删除 gai.conf，系统将使用默认配置${gl_bai}"
            fi
        fi
    else
        # 读取原始状态
        original_state=$(cat /etc/gai.conf.original_state)
        
        if [ "$original_state" == "not_existed" ]; then
            echo "检测到原先${gl_huang}没有${gl_bai} gai.conf 文件"
            echo "恢复操作将${gl_hong}删除${gl_bai}当前的 gai.conf 文件"
            echo ""
            echo "确认要恢复到原始状态吗？[y/n]"
            read -p "请选择: " confirm
            
            if [[ "$confirm" == "y" || "$confirm" == "Y" ]]; then
                rm -f /etc/gai.conf
                rm -f /etc/gai.conf.original_state
                echo -e "${gl_lv}✅ 已删除 gai.conf，恢复到原始状态（无配置文件）${gl_bai}"
                
                # 刷新缓存
                if command -v nscd &> /dev/null; then
                    systemctl restart nscd 2>/dev/null || service nscd restart 2>/dev/null || true
                fi
                if command -v resolvectl &> /dev/null; then
                    resolvectl flush-caches 2>/dev/null || true
                fi
            else
                echo "已取消恢复操作"
            fi
            
        elif [ "$original_state" == "existed" ]; then
            echo "检测到原先${gl_lv}存在${gl_bai} gai.conf 文件"
            
            # 查找最新的备份
            latest_backup=$(ls -t /etc/gai.conf.bak.* 2>/dev/null | head -1)
            
            if [ -n "$latest_backup" ]; then
                echo "找到备份文件: $latest_backup"
                echo ""
                echo "确认要从备份恢复吗？[y/n]"
                read -p "请选择: " confirm
                
                if [[ "$confirm" == "y" || "$confirm" == "Y" ]]; then
                    cp "$latest_backup" /etc/gai.conf
                    rm -f /etc/gai.conf.original_state
                    echo -e "${gl_lv}✅ 已从备份恢复配置${gl_bai}"
                    
                    # 刷新缓存
                    if command -v nscd &> /dev/null; then
                        systemctl restart nscd 2>/dev/null || service nscd restart 2>/dev/null || true
                        echo "已刷新 nscd DNS 缓存"
                    fi
                    if command -v resolvectl &> /dev/null; then
                        resolvectl flush-caches 2>/dev/null || true
                        echo "已刷新 systemd-resolved DNS 缓存"
                    fi
                    
                    echo ""
                    echo "当前出口 IP 地址："
                    echo "------------------------------------------------"
                    curl ip.sb
                    echo ""
                    echo "------------------------------------------------"
                else
                    echo "已取消恢复操作"
                fi
            else
                echo -e "${gl_hong}错误: 未找到备份文件${gl_bai}"
            fi
        fi
    fi
    
    echo ""
    break_end
}

set_temp_socks5_proxy() {
    clear
    echo -e "${gl_kjlan}=== 设置临时SOCKS5代理 ===${gl_bai}"
    echo ""
    echo "此代理配置仅对当前终端会话有效，重启后自动失效"
    echo "------------------------------------------------"
    echo ""
    
    # 输入代理服务器IP
    local proxy_ip=""
    while true; do
        read -e -p "$(echo -e "${gl_huang}请输入代理服务器IP: ${gl_bai}")" proxy_ip

        if [ -z "$proxy_ip" ]; then
            echo -e "${gl_hong}❌ IP地址不能为空${gl_bai}"
        elif [[ "$proxy_ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
            # 验证IP格式和范围（每段0-255）
            local valid_ip=true
            IFS='.' read -ra octets <<< "$proxy_ip"
            for octet in "${octets[@]}"; do
                if [ "$octet" -gt 255 ]; then
                    valid_ip=false
                    break
                fi
            done
            if [ "$valid_ip" = true ]; then
                echo -e "${gl_lv}✅ IP地址: ${proxy_ip}${gl_bai}"
                break
            else
                echo -e "${gl_hong}❌ IP地址范围无效（每段必须在0-255之间）${gl_bai}"
            fi
        else
            echo -e "${gl_hong}❌ 无效的IP地址格式${gl_bai}"
        fi
    done
    
    echo ""
    
    # 输入端口
    local proxy_port=""
    while true; do
        read -e -p "$(echo -e "${gl_huang}请输入端口: ${gl_bai}")" proxy_port
        
        if [ -z "$proxy_port" ]; then
            echo -e "${gl_hong}❌ 端口不能为空${gl_bai}"
        elif [[ "$proxy_port" =~ ^[0-9]+$ ]] && [ "$proxy_port" -ge 1 ] && [ "$proxy_port" -le 65535 ]; then
            echo -e "${gl_lv}✅ 端口: ${proxy_port}${gl_bai}"
            break
        else
            echo -e "${gl_hong}❌ 无效端口，请输入 1-65535 之间的数字${gl_bai}"
        fi
    done
    
    echo ""
    
    # 输入用户名（可选）
    local proxy_user=""
    read -e -p "$(echo -e "${gl_huang}请输入用户名（留空跳过）: ${gl_bai}")" proxy_user
    
    if [ -n "$proxy_user" ]; then
        echo -e "${gl_lv}✅ 用户名: ${proxy_user}${gl_bai}"
    else
        echo -e "${gl_zi}未设置用户名（无认证模式）${gl_bai}"
    fi
    
    echo ""
    
    # 输入密码（可选）
    local proxy_pass=""
    if [ -n "$proxy_user" ]; then
        read -e -p "$(echo -e "${gl_huang}请输入密码: ${gl_bai}")" proxy_pass
        
        if [ -n "$proxy_pass" ]; then
            echo -e "${gl_lv}✅ 密码已设置${gl_bai}"
        else
            echo -e "${gl_huang}⚠️  密码为空${gl_bai}"
        fi
    fi
    
    # 生成代理URL
    local proxy_url=""
    if [ -n "$proxy_user" ] && [ -n "$proxy_pass" ]; then
        proxy_url="socks5://${proxy_user}:${proxy_pass}@${proxy_ip}:${proxy_port}"
    elif [ -n "$proxy_user" ]; then
        proxy_url="socks5://${proxy_user}@${proxy_ip}:${proxy_port}"
    else
        proxy_url="socks5://${proxy_ip}:${proxy_port}"
    fi
    
    # 生成临时配置文件（安全模式）
    local timestamp=$(date +%Y%m%d_%H%M%S)
    # 优先使用用户私有目录，回退到 /tmp
    local secure_tmp="${XDG_RUNTIME_DIR:-/tmp}"
    local config_file="${secure_tmp}/socks5_proxy_${timestamp}.sh"

    # 设置安全的 umask（仅所有者可读写）
    local old_umask=$(umask)
    umask 077

    # 生成配置文件（不在文件中输出完整密码）
    cat > "$config_file" << PROXYEOF
#!/bin/bash
# SOCKS5 代理配置 - 生成于 $(date '+%Y-%m-%d %H:%M:%S')
# 此配置仅对当前终端会话有效
# 警告: 使用后请删除此文件 (rm $config_file)

export http_proxy="${proxy_url}"
export https_proxy="${proxy_url}"
export all_proxy="${proxy_url}"

echo "SOCKS5 代理已启用："
echo "  服务器: ${proxy_ip}:${proxy_port}"
echo "  用户: ${proxy_user:-无}"
echo "  (代理 URL 已设置到环境变量)"
PROXYEOF

    # 恢复 umask 并确保文件权限安全
    umask "$old_umask"
    chmod 600 "$config_file"
    
    echo ""
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo -e "${gl_lv}✅ 代理配置文件已生成！${gl_bai}"
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo ""
    echo -e "${gl_huang}使用方法：${gl_bai}"
    echo ""
    echo -e "1. ${gl_lv}应用代理配置：${gl_bai}"
    echo "   source ${config_file}"
    echo ""
    echo -e "2. ${gl_lv}测试代理是否生效：${gl_bai}"
    echo "   curl ip.sb"
    echo "   （应该显示代理服务器的IP地址）"
    echo ""
    echo -e "3. ${gl_lv}取消代理：${gl_bai}"
    echo "   unset http_proxy https_proxy all_proxy"
    echo ""
    echo -e "${gl_zi}注意事项：${gl_bai}"
    echo "  - 此配置仅对执行 source 命令的终端会话有效"
    echo "  - 关闭终端或重启系统后代理自动失效"
    echo "  - 配置文件保存在 /tmp 目录，重启后会被清除"
    echo ""
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo ""
    
    break_end
}

disable_ipv6_temporary() {
    clear
    echo -e "${gl_kjlan}=== 临时禁用IPv6 ===${gl_bai}"
    echo ""
    echo "此操作将临时禁用IPv6，重启后自动恢复"
    echo "------------------------------------------------"
    echo ""
    
    read -e -p "$(echo -e "${gl_huang}确认临时禁用IPv6？(Y/N): ${gl_bai}")" confirm
    
    case "$confirm" in
        [Yy])
            echo ""
            echo "正在禁用IPv6..."
            
            # 临时禁用IPv6
            sysctl -w net.ipv6.conf.all.disable_ipv6=1 >/dev/null 2>&1
            sysctl -w net.ipv6.conf.default.disable_ipv6=1 >/dev/null 2>&1
            sysctl -w net.ipv6.conf.lo.disable_ipv6=1 >/dev/null 2>&1
            
            # 验证状态
            local ipv6_status=$(sysctl -n net.ipv6.conf.all.disable_ipv6 2>/dev/null)
            
            echo ""
            if [ "$ipv6_status" = "1" ]; then
                echo -e "${gl_lv}✅ IPv6 已临时禁用${gl_bai}"
                echo ""
                echo -e "${gl_zi}注意：${gl_bai}"
                echo "  - 此设置仅在当前会话有效"
                echo "  - 重启后 IPv6 将自动恢复"
                echo "  - 如需永久禁用，请选择'永久禁用IPv6'选项"
            else
                echo -e "${gl_hong}❌ IPv6 禁用失败${gl_bai}"
            fi
            ;;
        *)
            echo "已取消"
            ;;
    esac
    
    echo ""
    break_end
}

disable_ipv6_permanent() {
    clear
    echo -e "${gl_kjlan}=== 永久禁用IPv6 ===${gl_bai}"
    echo ""
    echo "此操作将永久禁用IPv6，重启后仍然生效"
    echo "------------------------------------------------"
    echo ""
    
    # 检查是否已经永久禁用
    if [ -f /etc/sysctl.d/99-disable-ipv6.conf ]; then
        echo -e "${gl_huang}⚠️  检测到已存在永久禁用配置${gl_bai}"
        echo ""
        if [ "$AUTO_MODE" = "1" ]; then
            confirm=Y
        else
            read -e -p "$(echo -e "${gl_huang}是否重新执行永久禁用？(Y/N): ${gl_bai}")" confirm
        fi

        case "$confirm" in
            [Yy])
                ;;
            *)
                echo "已取消"
                break_end
                return 1
                ;;
        esac
    fi
    
    echo ""
    if [ "$AUTO_MODE" = "1" ]; then
        confirm=Y
    else
        read -e -p "$(echo -e "${gl_huang}确认永久禁用IPv6？(Y/N): ${gl_bai}")" confirm
    fi

    case "$confirm" in
        [Yy])
            echo ""
            echo -e "${gl_zi}[步骤 1/3] 备份当前IPv6状态...${gl_bai}"
            
            # 读取当前IPv6状态并备份
            local ipv6_all=$(sysctl -n net.ipv6.conf.all.disable_ipv6 2>/dev/null || echo "0")
            local ipv6_default=$(sysctl -n net.ipv6.conf.default.disable_ipv6 2>/dev/null || echo "0")
            local ipv6_lo=$(sysctl -n net.ipv6.conf.lo.disable_ipv6 2>/dev/null || echo "0")
            
            # 创建备份文件
            cat > /etc/sysctl.d/.ipv6-state-backup.conf << BACKUPEOF
# IPv6 State Backup - Created on $(date '+%Y-%m-%d %H:%M:%S')
# This file is used to restore IPv6 state when canceling permanent disable
net.ipv6.conf.all.disable_ipv6=${ipv6_all}
net.ipv6.conf.default.disable_ipv6=${ipv6_default}
net.ipv6.conf.lo.disable_ipv6=${ipv6_lo}
BACKUPEOF
            
            echo -e "${gl_lv}✅ 状态已备份${gl_bai}"
            echo ""
            
            echo -e "${gl_zi}[步骤 2/3] 创建永久禁用配置...${gl_bai}"
            
            # 创建永久禁用配置文件
            cat > /etc/sysctl.d/99-disable-ipv6.conf << EOF
# Permanently Disable IPv6
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
EOF
            
            echo -e "${gl_lv}✅ 配置文件已创建${gl_bai}"
            echo ""
            
            echo -e "${gl_zi}[步骤 3/3] 应用配置...${gl_bai}"
            
            # 应用配置
            sysctl --system >/dev/null 2>&1
            
            # 验证状态
            local ipv6_status=$(sysctl -n net.ipv6.conf.all.disable_ipv6 2>/dev/null)
            
            echo ""
            if [ "$ipv6_status" = "1" ]; then
                echo -e "${gl_lv}✅ IPv6 已永久禁用${gl_bai}"
                echo ""
                echo -e "${gl_zi}说明：${gl_bai}"
                echo "  - 配置文件: /etc/sysctl.d/99-disable-ipv6.conf"
                echo "  - 备份文件: /etc/sysctl.d/.ipv6-state-backup.conf"
                echo "  - 重启后此配置仍然生效"
                echo "  - 如需恢复，请选择'取消永久禁用'选项"
            else
                echo -e "${gl_hong}❌ IPv6 禁用失败${gl_bai}"
                # 如果失败，删除配置文件
                rm -f /etc/sysctl.d/99-disable-ipv6.conf
                rm -f /etc/sysctl.d/.ipv6-state-backup.conf
            fi
            ;;
        *)
            echo "已取消"
            ;;
    esac
    
    echo ""
    break_end
}

cancel_ipv6_permanent_disable() {
    clear
    echo -e "${gl_kjlan}=== 取消永久禁用IPv6 ===${gl_bai}"
    echo ""
    echo "此操作将完全还原到执行永久禁用前的状态"
    echo "------------------------------------------------"
    echo ""
    
    # 检查是否存在永久禁用配置
    if [ ! -f /etc/sysctl.d/99-disable-ipv6.conf ]; then
        echo -e "${gl_huang}⚠️  未检测到永久禁用配置${gl_bai}"
        echo ""
        echo "可能原因："
        echo "  - 从未执行过'永久禁用IPv6'操作"
        echo "  - 配置文件已被手动删除"
        echo ""
        break_end
        return 1
    fi
    
    read -e -p "$(echo -e "${gl_huang}确认取消永久禁用并恢复原始状态？(Y/N): ${gl_bai}")" confirm
    
    case "$confirm" in
        [Yy])
            echo ""
            echo -e "${gl_zi}[步骤 1/4] 删除永久禁用配置...${gl_bai}"
            
            # 删除永久禁用配置文件
            rm -f /etc/sysctl.d/99-disable-ipv6.conf
            echo -e "${gl_lv}✅ 配置文件已删除${gl_bai}"
            echo ""
            
            echo -e "${gl_zi}[步骤 2/4] 检查备份文件...${gl_bai}"
            
            # 检查备份文件
            if [ -f /etc/sysctl.d/.ipv6-state-backup.conf ]; then
                echo -e "${gl_lv}✅ 找到备份文件${gl_bai}"
                echo ""
                
                echo -e "${gl_zi}[步骤 3/4] 从备份还原原始状态...${gl_bai}"
                
                # 读取备份的原始值
                local backup_all=$(grep 'net.ipv6.conf.all.disable_ipv6' /etc/sysctl.d/.ipv6-state-backup.conf | awk -F'=' '{print $2}')
                local backup_default=$(grep 'net.ipv6.conf.default.disable_ipv6' /etc/sysctl.d/.ipv6-state-backup.conf | awk -F'=' '{print $2}')
                local backup_lo=$(grep 'net.ipv6.conf.lo.disable_ipv6' /etc/sysctl.d/.ipv6-state-backup.conf | awk -F'=' '{print $2}')
                
                # 恢复原始值
                sysctl -w net.ipv6.conf.all.disable_ipv6=${backup_all} >/dev/null 2>&1
                sysctl -w net.ipv6.conf.default.disable_ipv6=${backup_default} >/dev/null 2>&1
                sysctl -w net.ipv6.conf.lo.disable_ipv6=${backup_lo} >/dev/null 2>&1
                
                # 删除备份文件
                rm -f /etc/sysctl.d/.ipv6-state-backup.conf
                
                echo -e "${gl_lv}✅ 已从备份还原原始状态${gl_bai}"
            else
                echo -e "${gl_huang}⚠️  未找到备份文件${gl_bai}"
                echo ""
                
                echo -e "${gl_zi}[步骤 3/4] 恢复到系统默认（启用IPv6）...${gl_bai}"
                
                # 恢复到系统默认（启用IPv6）
                sysctl -w net.ipv6.conf.all.disable_ipv6=0 >/dev/null 2>&1
                sysctl -w net.ipv6.conf.default.disable_ipv6=0 >/dev/null 2>&1
                sysctl -w net.ipv6.conf.lo.disable_ipv6=0 >/dev/null 2>&1
                
                echo -e "${gl_lv}✅ 已恢复到系统默认（IPv6启用）${gl_bai}"
            fi
            
            echo ""
            echo -e "${gl_zi}[步骤 4/4] 应用配置...${gl_bai}"
            
            # 应用配置
            sysctl --system >/dev/null 2>&1
            
            # 验证状态
            local ipv6_status=$(sysctl -n net.ipv6.conf.all.disable_ipv6 2>/dev/null)
            
            echo ""
            if [ "$ipv6_status" = "0" ]; then
                echo -e "${gl_lv}✅ IPv6 已恢复启用${gl_bai}"
                echo ""
                echo -e "${gl_zi}说明：${gl_bai}"
                echo "  - 所有相关配置文件已清理"
                echo "  - IPv6 已完全恢复到执行永久禁用前的状态"
                echo "  - 重启后此状态依然保持"
            else
                echo -e "${gl_huang}⚠️  IPv6 状态: 禁用（值=${ipv6_status}）${gl_bai}"
                echo ""
                echo "可能原因："
                echo "  - 系统中存在其他IPv6禁用配置"
                echo "  - 手动执行 sysctl -w 命令重新启用IPv6"
            fi
            ;;
        *)
            echo "已取消"
            ;;
    esac
    
    echo ""
    break_end
}

manage_ipv6() {
    while true; do
        clear
        echo -e "${gl_kjlan}=== IPv6 管理 ===${gl_bai}"
        echo ""
        
        # 显示当前IPv6状态
        local ipv6_status=$(sysctl -n net.ipv6.conf.all.disable_ipv6 2>/dev/null)
        local status_text=""
        local status_color=""
        
        if [ "$ipv6_status" = "0" ]; then
            status_text="启用"
            status_color="${gl_lv}"
        else
            status_text="禁用"
            status_color="${gl_hong}"
        fi
        
        echo -e "当前状态: ${status_color}${status_text}${gl_bai}"
        echo ""
        
        # 检查是否存在永久禁用配置
        if [ -f /etc/sysctl.d/99-disable-ipv6.conf ]; then
            echo -e "${gl_huang}⚠️  检测到永久禁用配置文件${gl_bai}"
            echo ""
        fi
        
        echo "------------------------------------------------"
        echo "1. 临时禁用IPv6（重启后恢复）"
        echo "2. 永久禁用IPv6（重启后仍生效）"
        echo "3. 取消永久禁用（完全还原）"
        echo "0. 返回主菜单"
        echo "------------------------------------------------"
        read -e -p "请输入选择: " choice
        
        case "$choice" in
            1)
                disable_ipv6_temporary
                ;;
            2)
                disable_ipv6_permanent
                ;;
            3)
                cancel_ipv6_permanent_disable
                ;;
            0)
                return
                ;;
            *)
                echo "无效选择"
                sleep 2
                ;;
        esac
    done
}

#=============================================================================
# MTU/MSS 检测与优化功能
# 用于消除国际链路重传问题
#=============================================================================

# 多地区 MTU 路径探测
detect_path_mtu_multi_region() {
    clear >&2
    echo -e "${gl_kjlan}==========================================${gl_bai}" >&2
    echo "      MTU 路径探测（多地区检测）" >&2
    echo -e "${gl_kjlan}==========================================${gl_bai}" >&2
    echo "" >&2
    
    echo -e "${gl_zi}正在探测到全球多个地区的路径 MTU...${gl_bai}" >&2
    echo -e "${gl_huang}注意: 已排除 Anycast IP (如 1.1.1.1/8.8.8.8)，确保检测真实物理路径${gl_bai}" >&2
    echo "" >&2
    
    # 定义测试目标 (主IP + 备选IP，确保高可用)
    # 策略：混合使用大学、ISP骨干网、商业云(非Anycast) IP
    declare -A targets=(
        ["香港"]="147.8.17.13 202.45.170.1 103.16.228.1 118.143.1.1"          # HKU, HKIX, HostHatch, PCCW
        ["日本-东京"]="133.11.0.1 202.232.2.1 103.201.129.1 203.104.128.1"    # U-Tokyo, JAIST, GMO, KDDI
        ["日本-大阪"]="133.1.138.1 203.178.148.19 61.211.224.1"               # Osaka U, WIDE, K-Opticom
        ["新加坡"]="137.132.80.25 202.156.0.1 103.25.202.1 118.201.1.1"       # NUS, Singtel, StarHub, M1
        ["韩国"]="147.46.10.20 211.233.0.1 168.126.63.1 210.117.65.1"         # SNU, KT, KT-DNS, SK Broadband
        ["美国-西海岸"]="128.97.27.37 128.32.155.2 198.148.161.11 64.125.0.1"  # UCLA, Berkeley, QuadraNet, Zayo
        ["美国-东海岸"]="18.9.22.69 128.112.128.15 108.61.10.10 23.29.64.1"    # MIT, Princeton, Vultr, Choopa
        ["欧洲-德国"]="141.14.16.1 194.25.0.125 134.130.4.1 85.10.240.1"      # DFN, Telekom, RWTH, Hetzner
        ["欧洲-英国"]="131.111.8.46 163.1.0.1 212.58.244.20 193.136.1.1"       # Cambridge, Oxford, BBC, LINX
        ["澳洲"]="139.130.4.5 203.50.0.1 150.203.1.10 203.2.218.1"             # Telstra, Telstra-2, ANU, Optus
    )

    # 防御性验证：确保目标数组不为空
    if [ ${#targets[@]} -eq 0 ]; then
        echo -e "${gl_hong}❌ MTU 检测目标列表为空，无法继续${gl_bai}" >&2
        return 1
    fi

    # 定义显示顺序
    local regions_order=("香港" "日本-东京" "日本-大阪" "新加坡" "韩国" "美国-西海岸" "美国-东海岸" "欧洲-德国" "欧洲-英国" "澳洲")
    
    # 存储每个目标的 MSS
    declare -A mss_values
    local test_count=0
    local success_count=0
    
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >&2
    
    for region in "${regions_order[@]}"; do
        test_count=$((test_count + 1))
        local target_list="${targets[$region]}"
        local active_target=""
        
        # 1. 连通性检查 (选择可用的 IP)
        for ip in $target_list; do
            if ping -c 1 -W 1 "$ip" &>/dev/null; then
                active_target="$ip"
                break
            fi
        done
        
        echo -e "${gl_huang}[${test_count}/${#regions_order[@]}] ${gl_bai}测试目标: ${gl_kjlan}${region}${gl_bai}" >&2
        
        if [ -z "$active_target" ]; then
             echo -e "  ${gl_huang}⚠️  无法探测 (所有测试IP均不可达，不参与计算)${gl_bai}" >&2
             echo "" >&2
             continue
        fi

        # 2. 开始 MTU 探测（从1472开始=标准1500 MTU，向下探测到1200覆盖多层隧道）
        local found=0
        for size in 1472 1460 1452 1440 1420 1400 1380 1360 1340 1320 1300 1280 1260 1240 1220 1200; do
            if ping -M do -s "$size" -c 1 -W 1 "$active_target" &>/dev/null; then
                local mtu=$((size + 28))
                local mss=$((size + 28 - 40))
                echo -e "  ${gl_lv}✅ MTU=${mtu}, MSS=${mss}${gl_bai} (Target: $active_target)" >&2
                mss_values[$region]=$mss
                found=1
                success_count=$((success_count + 1))
                break
            fi
        done

        if [ $found -eq 0 ]; then
            echo -e "  ${gl_huang}⚠️  探测失败 (ICMP分片被拦截，不参与计算)${gl_bai}" >&2
        fi
        echo "" >&2
    done
    
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >&2
    echo "" >&2
    
    # 检查是否有任何成功的探测结果
    if [ ${#mss_values[@]} -eq 0 ]; then
        echo -e "${gl_hong}❌ 所有地区均探测失败，无法确定MSS值${gl_bai}" >&2
        echo -e "${gl_huang}建议检查网络连接或使用手动设置${gl_bai}" >&2
        return 1
    fi

    # 找出最小的 MSS（只计算成功探测的地区）
    local min_mss=9999
    local max_mss=0
    local min_region=""
    local max_region=""

    for region in "${!mss_values[@]}"; do
        local mss=${mss_values[$region]}
        if [ "$mss" -lt "$min_mss" ]; then
            min_mss=$mss
            min_region=$region
        fi
        if [ "$mss" -gt "$max_mss" ]; then
            max_mss=$mss
            max_region=$region
        fi
    done

    # 显示汇总结果
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}" >&2
    echo -e "${gl_lv}✅ 探测完成！${gl_bai}" >&2
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}" >&2
    echo "" >&2
    echo "各地区 MSS 检测结果：" >&2
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >&2
    for region in "${regions_order[@]}"; do
        if [ -n "${mss_values[$region]}" ]; then
            local mss=${mss_values[$region]}
            echo -e "  ${gl_zi}${region}:${gl_bai} ${mss} bytes" >&2
        fi
    done
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >&2
    echo "" >&2
    
    # 判断是否一致
    if [ $min_mss -eq $max_mss ]; then
        echo -e "${gl_lv}✅ 所有地区 MSS 完全一致！${gl_bai}" >&2
        echo -e "${gl_kjlan}推荐 MSS:${gl_bai} ${gl_lv}${min_mss}${gl_bai} bytes" >&2
        echo -e "${gl_zi}说明: 所有地区MTU相同，使用此值性能最优${gl_bai}" >&2
    else
        local diff=$((max_mss - min_mss))
        echo -e "${gl_huang}⚠️  不同地区 MSS 有差异（${diff} bytes）${gl_bai}" >&2
        echo "" >&2
        echo -e "  最小值: ${gl_huang}${min_mss}${gl_bai} (${min_region})" >&2
        echo -e "  最大值: ${gl_huang}${max_mss}${gl_bai} (${max_region})" >&2
        echo "" >&2
        echo -e "${gl_kjlan}推荐策略：${gl_bai}" >&2
        echo -e "  1. ${gl_lv}保守方案:${gl_bai} 使用最小值 ${min_mss} (兼容所有地区)" >&2
        echo -e "  2. ${gl_huang}激进方案:${gl_bai} 使用最大值 ${max_mss} (性能最优，部分地区可能丢包)" >&2
        echo -e "  3. ${gl_zi}折中方案:${gl_bai} 使用中间值 $(( (min_mss + max_mss) / 2 ))" >&2
    fi
    echo "" >&2
    
    # 返回推荐的MSS值（最小值，最大值）
    echo "$min_mss $max_mss"
}

# 应用 MTU/MSS 优化（方案A：设置路由 MTU，让 clamp-to-pmtu 自动生效）
apply_mss_clamp_with_value() {
    local mss=$1

    # 验证 MSS 值
    if ! [[ "$mss" =~ ^[0-9]+$ ]] || [ "$mss" -lt 536 ] || [ "$mss" -gt 9000 ]; then
        echo -e "${gl_hong}错误: MSS 值无效 (${mss})，有效范围 536-9000${gl_bai}"
        return 1
    fi

    local mtu=$((mss + 40))

    echo -e "${gl_zi}正在应用 MTU/MSS 优化...${gl_bai}"
    echo ""

    # 获取默认路由信息
    local default_route
    default_route=$(ip -4 route show default | head -1)
    if [ -z "$default_route" ]; then
        echo -e "${gl_hong}错误: 无法获取默认路由信息${gl_bai}"
        return 1
    fi

    local default_iface
    default_iface=$(echo "$default_route" | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')
    if [ -z "$default_iface" ]; then
        echo -e "${gl_hong}错误: 无法获取默认网卡${gl_bai}"
        return 1
    fi

    # 记录原始 MTU 用于回滚
    local original_mtu
    original_mtu=$(ip link show "$default_iface" 2>/dev/null | sed -nE 's/.*mtu ([0-9]+).*/\1/p' | head -1)

    # 清理旧版本的 iptables set-mss 规则（兼容性：从旧版本升级时自动清理）
    if command -v iptables &>/dev/null; then
        local comment_tag="net-tcp-tune-mss"
        local old_rule_mss
        while read -r old_rule_mss; do
            [ -n "$old_rule_mss" ] || continue
            iptables -t mangle -D OUTPUT -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss "$old_rule_mss" -m comment --comment "$comment_tag" 2>/dev/null || true
        done < <(iptables -t mangle -S OUTPUT 2>/dev/null | grep "$comment_tag" | sed -n 's/.*--set-mss \([0-9]\+\).*/\1/p')
        while read -r old_rule_mss; do
            [ -n "$old_rule_mss" ] || continue
            iptables -t mangle -D POSTROUTING -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss "$old_rule_mss" -m comment --comment "$comment_tag" 2>/dev/null || true
        done < <(iptables -t mangle -S POSTROUTING 2>/dev/null | grep "$comment_tag" | sed -n 's/.*--set-mss \([0-9]\+\).*/\1/p')
    fi

    # 保存配置文件（用于持久化和回滚）
    mkdir -p /usr/local/etc
    cat > /usr/local/etc/mtu-optimize.conf << EOF
# MTU优化配置 - 由 net-tcp-tune.sh 自动生成
# 生成时间: $(date)
OPTIMIZED_MTU=$mtu
OPTIMIZED_MSS=$mss
ORIGINAL_MTU=${original_mtu:-1500}
DEFAULT_IFACE=$default_iface
FALLBACK_LINK_MTU=false
EOF
    if [ ! -f /usr/local/etc/mtu-optimize.conf ]; then
        echo -e "${gl_hong}错误: 配置文件写入失败（磁盘满或权限不足）${gl_bai}"
        return 1
    fi

    # 设置默认路由 MTU（核心操作：让功能3/6的 clamp-to-pmtu 自动使用正确的值）
    echo "设置路由 MTU = ${mtu} (对应 MSS = ${mss}) ..."
    local clean_route
    clean_route=$(echo "$default_route" | sed 's/ mtu lock [0-9]*//;s/ mtu [0-9]*//')
    if ip route replace $clean_route mtu "$mtu" 2>/dev/null; then
        echo -e "${gl_lv}✅ 默认路由 MTU 已设置为 ${mtu}${gl_bai}"
    else
        # 回退：直接设置网卡 MTU（影响该网卡上所有流量，包括 Docker bridge 等）
        echo -e "${gl_huang}⚠️ 路由 MTU 设置失败，尝试设置网卡链路 MTU...${gl_bai}"
        if docker ps &>/dev/null || [ -d /sys/class/net/docker0 ]; then
            echo -e "${gl_huang}⚠️ 检测到 Docker 环境，降低链路 MTU 可能影响容器网络通信${gl_bai}"
        fi
        if ip link set dev "$default_iface" mtu "$mtu" 2>/dev/null; then
            echo -e "${gl_lv}✅ 网卡 ${default_iface} 链路 MTU 已设置为 ${mtu}${gl_bai}"
            # 标记使用了链路MTU回退，持久化脚本需要知道
            sed -i 's/^FALLBACK_LINK_MTU=.*/FALLBACK_LINK_MTU=true/' /usr/local/etc/mtu-optimize.conf 2>/dev/null
        else
            echo -e "${gl_hong}❌ MTU 设置失败${gl_bai}"
            return 1
        fi
    fi
    echo ""

    # 确保 clamp-to-pmtu 规则存在（与功能3/6协同，不再使用 set-mss）
    if command -v iptables &>/dev/null; then
        if ! iptables -t mangle -C OUTPUT -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null; then
            iptables -t mangle -A OUTPUT -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null
        fi
        if ! iptables -t mangle -C FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null; then
            iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null
        fi
        echo -e "${gl_lv}✅ clamp-to-pmtu 规则已确认（与功能3/6协同）${gl_bai}"
    fi
    echo ""

    # 持久化 - 使用独立服务（与功能3彻底解耦）
    echo "配置重启持久化..."

    # 兼容旧版本：若历史上把 MTU 恢复逻辑写入了 bbr-optimize-apply.sh，则移除
    if [ -f /usr/local/bin/bbr-optimize-apply.sh ] && grep -q "MTU 优化恢复 (mtu-optimize)" /usr/local/bin/bbr-optimize-apply.sh 2>/dev/null; then
        sed -i '/# MTU 优化恢复 (mtu-optimize)/,/^[[:space:]]*fi[[:space:]]*$/d' /usr/local/bin/bbr-optimize-apply.sh 2>/dev/null || true
    fi

    cat > /usr/local/bin/mtu-optimize-apply.sh << 'MTUAPPLYEOF'
#!/bin/bash
# MTU Optimize 重启恢复脚本 - 自动生成，勿手动编辑
if [ ! -f /usr/local/etc/mtu-optimize.conf ]; then
    exit 0
fi
. /usr/local/etc/mtu-optimize.conf
[ -n "$OPTIMIZED_MTU" ] || exit 0

sleep 2

# 恢复路由 MTU
route_ok=false
default_route=$(ip -4 route show default | head -1)
if [ -n "$default_route" ]; then
    clean_route=$(echo "$default_route" | sed 's/ mtu lock [0-9]*//;s/ mtu [0-9]*//')
    if ip route replace $clean_route mtu "$OPTIMIZED_MTU" 2>/dev/null; then
        route_ok=true
    fi
fi

# 路由MTU失败或之前使用了链路MTU回退，则设置链路MTU
if [ "$route_ok" = false ] || [ "${FALLBACK_LINK_MTU:-false}" = "true" ]; then
    iface="${DEFAULT_IFACE:-$(ip -4 route show default | head -1 | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')}"
    if [ -n "$iface" ]; then
        ip link set dev "$iface" mtu "$OPTIMIZED_MTU" 2>/dev/null || true
    fi
fi

# 确保 clamp-to-pmtu 规则存在（OUTPUT + FORWARD 链）
if command -v iptables >/dev/null 2>&1; then
    iptables -t mangle -C OUTPUT -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu >/dev/null 2>&1 \
      || iptables -t mangle -A OUTPUT -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null
    iptables -t mangle -C FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu >/dev/null 2>&1 \
      || iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null
fi
MTUAPPLYEOF
    chmod +x /usr/local/bin/mtu-optimize-apply.sh
    cat > /etc/systemd/system/mtu-optimize-persist.service << 'MTUSVCEOF'
[Unit]
Description=MTU Optimize - Restore route MTU after boot
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/bin/mtu-optimize-apply.sh

[Install]
WantedBy=multi-user.target
MTUSVCEOF
    if command -v systemctl &>/dev/null; then
        systemctl daemon-reload 2>/dev/null
        systemctl enable mtu-optimize-persist.service 2>/dev/null
        echo -e "${gl_lv}✅ 已配置独立 mtu-optimize-persist 服务（与功能3解耦）${gl_bai}"
    else
        echo -e "${gl_huang}⚠️ 未检测到 systemd，重启持久化不可用，MTU优化仅当前会话生效${gl_bai}"
    fi
    echo ""

    # 验证
    echo "验证配置..."
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    local actual_route_mtu
    actual_route_mtu=$(ip -4 route show default | head -1 | sed -nE 's/.* mtu ([0-9]+).*/\1/p')
    if [ -n "$actual_route_mtu" ] && [ "$actual_route_mtu" = "$mtu" ]; then
        echo -e "  路由 MTU:  ${gl_lv}${actual_route_mtu} ✓${gl_bai}"
    else
        echo -e "  路由 MTU:  ${gl_huang}${actual_route_mtu:-未设置} (期望: ${mtu}) ⚠${gl_bai}"
    fi
    echo -e "  对应 MSS:  ${gl_lv}${mss}${gl_bai}"
    if command -v iptables &>/dev/null; then
        local clamp_out clamp_fwd
        clamp_out=$(iptables -t mangle -S OUTPUT 2>/dev/null | grep -c 'clamp-mss-to-pmtu')
        clamp_fwd=$(iptables -t mangle -S FORWARD 2>/dev/null | grep -c 'clamp-mss-to-pmtu')
        [ "$clamp_out" -gt 0 ] && echo -e "  OUTPUT:    ${gl_lv}clamp-to-pmtu ✓${gl_bai}" || echo -e "  OUTPUT:    ${gl_huang}clamp-to-pmtu 未设置 ⚠${gl_bai}"
        [ "$clamp_fwd" -gt 0 ] && echo -e "  FORWARD:   ${gl_lv}clamp-to-pmtu ✓${gl_bai}" || echo -e "  FORWARD:   ${gl_huang}clamp-to-pmtu 未设置 ⚠${gl_bai}"
    fi
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    echo -e "${gl_lv}✅ MTU/MSS 优化完成！${gl_bai}"
    echo -e "${gl_zi}原理: 路由MTU=${mtu} → 功能3/6的clamp-to-pmtu自动使用 → MSS=${mss}${gl_bai}"

    return 0
}

# 验证优化效果
verify_mss_optimization() {
    echo ""
    echo -e "${gl_kjlan}==========================================${gl_bai}"
    echo "      验证优化效果"
    echo -e "${gl_kjlan}==========================================${gl_bai}"
    echo ""
    
    echo -e "${gl_zi}等待 30 秒让配置生效...${gl_bai}"
    sleep 30
    
    echo ""
    echo -e "${gl_huang}当前重传统计:${gl_bai}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    ss -s | grep -i "retrans\|segs"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    
    echo -e "${gl_zi}建议:${gl_bai}"
    echo "  1. 运行网络测试观察重传率变化"
    echo "  2. 如果重传率显著降低（80%+），说明优化成功"
    echo "  3. 如果仍有重传，可能是其他问题（线路质量等）"
    echo ""
}

# 主菜单函数
mtu_mss_optimization() {
    while true; do
        clear
        echo -e "${gl_kjlan}==========================================${gl_bai}"
        echo "    MTU检测与MSS优化（消除重传）"
        echo -e "${gl_kjlan}==========================================${gl_bai}"
        echo ""
        
        # 显示当前状态
        echo -e "${gl_zi}当前状态:${gl_bai}"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        
        # 检查 MTU 优化是否已设置
        local route_mtu=$(ip -4 route show default 2>/dev/null | head -1 | sed -nE 's/.* mtu ([0-9]+).*/\1/p')
        if [ -n "$route_mtu" ]; then
            local route_mss=$((route_mtu - 40))
            echo -e "  MTU优化:  ${gl_lv}✅ 已设置 (MTU=${route_mtu}, MSS=${route_mss})${gl_bai}"
        else
            echo -e "  MTU优化:  ${gl_huang}❌ 未设置（使用默认MTU）${gl_bai}"
        fi

        # 显示重传统计
        local retrans=$(ss -s 2>/dev/null | sed -nE 's/.*retrans[:[:space:]]*([0-9]+).*/\1/p' | head -1)
        [ -z "$retrans" ] && retrans="0"
        echo -e "  当前重传: ${retrans} 个"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo ""

        echo -e "${gl_huang}提示: 本功能仅优化 IPv4 路由，IPv6 流量不受影响${gl_bai}"
        echo ""
        echo -e "${gl_kjlan}功能菜单:${gl_bai}"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "1. 自动检测并优化 ⭐ 推荐"
        echo "   （多地区MTU探测 + 设置路由MTU）"
        echo ""
        echo "2. 移除MTU优化"
        echo "   （恢复默认路由MTU）"
        echo ""
        echo "0. 返回主菜单"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo ""
        
        if [ "$AUTO_MODE" = "1" ]; then
            choice=1
        else
            read -e -p "请选择操作 [1]: " choice
            choice=${choice:-1}
        fi

        case $choice in
            1)
                # 自动检测并优化
                # 执行MTU检测
                local mss_result=$(detect_path_mtu_multi_region)
                local min_mss=$(echo "$mss_result" | awk '{print $1}')
                local max_mss=$(echo "$mss_result" | awk '{print $2}')
                
                if [ -z "$min_mss" ] || [ -z "$max_mss" ] || \
                   ! [[ "$min_mss" =~ ^[0-9]+$ ]] || ! [[ "$max_mss" =~ ^[0-9]+$ ]]; then
                     echo -e "${gl_hong}检测失败，无法获取有效的MSS值${gl_bai}"
                     sleep 2
                     break_end
                     [ "$AUTO_MODE" = "1" ] && return
                     continue
                fi

                local mid_mss=$(( (min_mss + max_mss) / 2 ))

                echo ""
                echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                
                if [ "$min_mss" -eq "$max_mss" ]; then
                    if [ "$AUTO_MODE" = "1" ]; then
                        confirm=Y
                    else
                        read -e -p "是否应用推荐的 MSS = ${min_mss}？(Y/N) [Y]: " confirm
                        confirm=${confirm:-Y}
                    fi
                    if [[ "$confirm" =~ ^[Yy]$ ]]; then
                        echo ""
                        apply_mss_clamp_with_value "$min_mss"
                        if [ $? -eq 0 ]; then
                            verify_mss_optimization
                        fi
                        break_end
                        [ "$AUTO_MODE" = "1" ] && return
                    else
                         echo -e "${gl_huang}已取消应用${gl_bai}"
                         sleep 2
                    fi
                else
                    echo "请选择优化策略:"
                    echo "  1) 保守方案 (${min_mss})"
                    echo "  2) 激进方案 (${max_mss})"
                    echo "  3) 折中方案 (${mid_mss})"
                    echo "  0) 取消"
                    echo ""
                    read -e -p "请输入选择 [1]: " strategy
                    strategy=${strategy:-1}
                    
                    local selected_mss=""
                    case $strategy in
                        1) selected_mss=$min_mss ;;
                        2) selected_mss=$max_mss ;;
                        3) selected_mss=$mid_mss ;;
                        0) echo -e "${gl_huang}已取消${gl_bai}"; sleep 2; ;;
                        *) echo -e "${gl_hong}无效选择${gl_bai}"; sleep 2; ;;
                    esac
                    
                    if [ -n "$selected_mss" ]; then
                        echo ""
                        apply_mss_clamp_with_value "$selected_mss"
                        if [ $? -eq 0 ]; then
                            verify_mss_optimization
                        fi
                        break_end
                        [ "$AUTO_MODE" = "1" ] && return
                    fi
                fi
                ;;
            2)
                # 移除MTU优化
                clear
                echo -e "${gl_kjlan}==========================================${gl_bai}"
                echo "      移除 MTU 优化"
                echo -e "${gl_kjlan}==========================================${gl_bai}"
                echo ""

                read -e -p "确认要移除 MTU 优化吗？(Y/N) [N]: " confirm
                if [[ "$confirm" =~ ^[Yy]$ ]]; then
                    echo ""
                    echo "正在移除..."

                    # 恢复默认路由 MTU（移除自定义 mtu 设置）
                    local default_route
                    default_route=$(ip -4 route show default | head -1)
                    if [ -n "$default_route" ]; then
                        local clean_route
                        clean_route=$(echo "$default_route" | sed 's/ mtu lock [0-9]*//;s/ mtu [0-9]*//')
                        ip route replace $clean_route 2>/dev/null
                        echo -e "${gl_lv}✓ 默认路由 MTU 已恢复${gl_bai}"
                    fi

                    # 恢复链路 MTU（应对 ip link set 回退场景）
                    if [ -f /usr/local/etc/mtu-optimize.conf ]; then
                        local saved_iface saved_original_mtu
                        saved_iface=$(grep '^DEFAULT_IFACE=' /usr/local/etc/mtu-optimize.conf | cut -d= -f2)
                        saved_original_mtu=$(grep '^ORIGINAL_MTU=' /usr/local/etc/mtu-optimize.conf | cut -d= -f2)
                        if [ -n "$saved_iface" ] && [ -n "$saved_original_mtu" ]; then
                            ip link set dev "$saved_iface" mtu "$saved_original_mtu" 2>/dev/null && \
                                echo -e "${gl_lv}✓ 网卡 ${saved_iface} MTU 已恢复为 ${saved_original_mtu}${gl_bai}"
                        fi
                    fi

                    # 清理旧版 iptables set-mss 规则（兼容旧版本）
                    if command -v iptables &>/dev/null; then
                        local comment_tag="net-tcp-tune-mss"
                        local del_mss
                        while read -r del_mss; do
                            [ -n "$del_mss" ] || continue
                            iptables -t mangle -D OUTPUT -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss "$del_mss" -m comment --comment "$comment_tag" 2>/dev/null || true
                        done < <(iptables -t mangle -S OUTPUT 2>/dev/null | grep "$comment_tag" | sed -n 's/.*--set-mss \([0-9]\+\).*/\1/p')
                        while read -r del_mss; do
                            [ -n "$del_mss" ] || continue
                            iptables -t mangle -D POSTROUTING -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss "$del_mss" -m comment --comment "$comment_tag" 2>/dev/null || true
                        done < <(iptables -t mangle -S POSTROUTING 2>/dev/null | grep "$comment_tag" | sed -n 's/.*--set-mss \([0-9]\+\).*/\1/p')
                    fi

                    # 清理配置文件和持久化
                    rm -f /usr/local/etc/mtu-optimize.conf
                    # 兼容旧版本残留：移除 bbr-optimize-apply.sh 里的 MTU 恢复段
                    if [ -f /usr/local/bin/bbr-optimize-apply.sh ] && grep -q "MTU 优化恢复 (mtu-optimize)" /usr/local/bin/bbr-optimize-apply.sh 2>/dev/null; then
                        sed -i '/# MTU 优化恢复 (mtu-optimize)/,/^[[:space:]]*fi[[:space:]]*$/d' /usr/local/bin/bbr-optimize-apply.sh 2>/dev/null || true
                    fi
                    # 移除独立的 mtu-optimize 服务
                    if [ -f /etc/systemd/system/mtu-optimize-persist.service ]; then
                        systemctl disable mtu-optimize-persist.service 2>/dev/null
                        rm -f /etc/systemd/system/mtu-optimize-persist.service
                        rm -f /usr/local/bin/mtu-optimize-apply.sh
                        systemctl daemon-reload 2>/dev/null
                    fi

                    echo -e "${gl_lv}✅ MTU 优化已移除，已恢复默认配置${gl_bai}"
                else
                    echo -e "${gl_huang}已取消${gl_bai}"
                fi
                sleep 2
                ;;
            0)
                return 0
                ;;
            *)
                echo -e "${gl_hong}无效选择${gl_bai}"
                sleep 1
                ;;
        esac
    done
}
server_reboot() {
    read -e -p "$(echo -e "${gl_huang}提示: ${gl_bai}现在重启服务器使配置生效吗？(Y/N): ")" rboot
    case "$rboot" in
        [Yy])
            echo "正在重启..."
            reboot
            ;;
        *)
            echo "已取消，请稍后手动执行: reboot"
            ;;
    esac
}

#=============================================================================
# 带宽检测和缓冲区计算函数
#=============================================================================

# 带宽检测函数
detect_bandwidth() {
    # 所有交互式输出重定向到stderr，避免被命令替换捕获
    echo "" >&2
    echo -e "${gl_kjlan}=== 服务器带宽检测 ===${gl_bai}" >&2
    echo "" >&2
    echo "请选择带宽配置方式：" >&2
    echo "1. 自动检测（推荐，自动选择最近服务器）" >&2
    echo "2. 手动指定测速服务器（指定服务器ID）" >&2
    echo "3. 手动选择预设档位（9个常用带宽档位）" >&2
    echo "" >&2
    
    read -e -p "请输入选择 [1]: " bw_choice
    bw_choice=${bw_choice:-1}

    case "$bw_choice" in
        1)
            # 自动检测带宽 - 选择最近服务器
            echo "" >&2
            echo -e "${gl_huang}正在运行 speedtest 测速...${gl_bai}" >&2
            echo -e "${gl_zi}提示: 自动选择距离最近的服务器${gl_bai}" >&2
            echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >&2
            echo "" >&2
            
            # 检查speedtest是否安装
            if ! command -v speedtest &>/dev/null; then
                echo -e "${gl_huang}speedtest 未安装，正在安装...${gl_bai}" >&2
                # 调用脚本中已有的安装逻辑（简化版）
                local cpu_arch=$(uname -m)
                local download_url
                case "$cpu_arch" in
                    x86_64)
                        download_url="https://install.speedtest.net/app/cli/ookla-speedtest-1.2.0-linux-x86_64.tgz"
                        ;;
                    aarch64)
                        download_url="https://install.speedtest.net/app/cli/ookla-speedtest-1.2.0-linux-aarch64.tgz"
                        ;;
                    *)
                        echo -e "${gl_hong}错误: 不支持的架构 ${cpu_arch}${gl_bai}" >&2
                        echo "将使用通用值 16MB" >&2
                        echo "500"
                        return 1
                        ;;
                esac
                
                cd /tmp
                wget -q "$download_url" -O speedtest.tgz && \
                tar -xzf speedtest.tgz && \
                mv speedtest /usr/local/bin/ && \
                rm -f speedtest.tgz
                
                if [ $? -ne 0 ]; then
                    echo -e "${gl_hong}安装失败，将使用通用值${gl_bai}" >&2
                    echo "500"
                    return 1
                fi
            fi
            
            # 智能测速：获取附近服务器列表，按距离依次尝试
            echo -e "${gl_zi}正在搜索附近测速服务器...${gl_bai}" >&2
            
            # 获取附近服务器列表（按延迟排序）
            local servers_list=$(speedtest --accept-license --servers 2>/dev/null | sed -nE 's/^[[:space:]]*([0-9]+).*/\1/p' | head -n 10)
            
            if [ -z "$servers_list" ]; then
                echo -e "${gl_huang}无法获取服务器列表，使用自动选择...${gl_bai}" >&2
                servers_list="auto"
            else
                local server_count=$(echo "$servers_list" | wc -l)
                echo -e "${gl_lv}✅ 找到 ${server_count} 个附近服务器${gl_bai}" >&2
            fi
            echo "" >&2
            
            local speedtest_output=""
            local upload_speed=""
            local attempt=0
            local max_attempts=5  # 最多尝试5个服务器
            
            # 逐个尝试服务器
            for server_id in $servers_list; do
                attempt=$((attempt + 1))
                
                if [ $attempt -gt $max_attempts ]; then
                    echo -e "${gl_huang}已尝试 ${max_attempts} 个服务器，停止尝试${gl_bai}" >&2
                    break
                fi
                
                if [ "$server_id" = "auto" ]; then
                    echo -e "${gl_zi}[尝试 ${attempt}] 自动选择最近服务器...${gl_bai}" >&2
                    speedtest_output=$(speedtest --accept-license 2>&1)
                else
                    echo -e "${gl_zi}[尝试 ${attempt}] 测试服务器 #${server_id}...${gl_bai}" >&2
                    speedtest_output=$(speedtest --accept-license --server-id="$server_id" 2>&1)
                fi
                
                echo "$speedtest_output" >&2
                echo "" >&2
                
                # 提取上传速度
                upload_speed=""
                if echo "$speedtest_output" | grep -q "Upload:"; then
                    upload_speed=$(echo "$speedtest_output" | sed -nE 's/.*[Uu]pload:[[:space:]]*([0-9]+(\.[0-9]+)?).*/\1/p' | head -n1)
                fi
                if [ -z "$upload_speed" ]; then
                    upload_speed=$(echo "$speedtest_output" | grep -i "Upload:" | awk '{for(i=1;i<=NF;i++) if($i ~ /^[0-9]+\.[0-9]+$/) {print $i; exit}}')
                fi
                
                # 检查是否成功
                if [ -n "$upload_speed" ] && ! echo "$speedtest_output" | grep -qi "FAILED\|error"; then
                    local success_server=$(echo "$speedtest_output" | grep "Server:" | head -n1 | sed 's/.*Server: //')
                    echo -e "${gl_lv}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}" >&2
                    echo -e "${gl_lv}✅ 测速成功！${gl_bai}" >&2
                    echo -e "${gl_zi}使用服务器: ${success_server}${gl_bai}" >&2
                    echo -e "${gl_lv}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}" >&2
                    echo "" >&2
                    break
                else
                    local failed_server=$(echo "$speedtest_output" | grep "Server:" | head -n1 | sed 's/.*Server: //' | sed 's/[[:space:]]*$//')
                    if [ -n "$failed_server" ]; then
                        echo -e "${gl_huang}⚠️  失败: ${failed_server}${gl_bai}" >&2
                    else
                        echo -e "${gl_huang}⚠️  此服务器失败${gl_bai}" >&2
                    fi
                    echo -e "${gl_zi}继续尝试下一个服务器...${gl_bai}" >&2
                    echo "" >&2
                fi
            done
            
            echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >&2
            echo "" >&2
            
            # 所有尝试都失败了
            if [ -z "$upload_speed" ] || echo "$speedtest_output" | grep -qi "FAILED\|error"; then
                echo -e "${gl_huang}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}" >&2
                echo -e "${gl_huang}⚠️  无法自动检测带宽${gl_bai}" >&2
                echo -e "${gl_huang}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}" >&2
                echo "" >&2
                echo -e "${gl_zi}原因: 测速服务器可能暂时不可用${gl_bai}" >&2
                echo "" >&2
                echo -e "${gl_kjlan}默认配置方案：${gl_bai}" >&2
                echo -e "  带宽:       ${gl_huang}1000 Mbps (1 Gbps)${gl_bai}" >&2
                echo -e "  缓冲区:     ${gl_huang}16 MB${gl_bai}" >&2
                echo -e "  适用场景:   ${gl_zi}标准 1Gbps 服务器（覆盖大多数场景）${gl_bai}" >&2
                echo "" >&2
                echo -e "${gl_huang}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}" >&2
                echo "" >&2
                
                # 询问用户确认
                read -e -p "是否使用默认值 1000 Mbps？(Y/N) [Y]: " use_default
                use_default=${use_default:-Y}
                
                case "$use_default" in
                    [Yy])
                        echo "" >&2
                        echo -e "${gl_lv}✅ 使用默认配置: 1000 Mbps（16 MB 缓冲区）${gl_bai}" >&2
                        echo "1000"
                        return 0
                        ;;
                    [Nn])
                        echo "" >&2
                        echo -e "${gl_zi}请手动输入带宽值${gl_bai}" >&2
                        local manual_bandwidth=""
                        while true; do
                            read -e -p "请输入上传带宽（单位：Mbps，如 500、1000、2000）: " manual_bandwidth
                            if [[ "$manual_bandwidth" =~ ^[0-9]+$ ]] && [ "$manual_bandwidth" -gt 0 ]; then
                                echo "" >&2
                                echo -e "${gl_lv}✅ 使用自定义值: ${manual_bandwidth} Mbps${gl_bai}" >&2
                                echo "$manual_bandwidth"
                                return 0
                            else
                                echo -e "${gl_hong}❌ 请输入有效的数字${gl_bai}" >&2
                            fi
                        done
                        ;;
                    *)
                        echo "" >&2
                        echo -e "${gl_huang}输入无效，使用默认值 1000 Mbps${gl_bai}" >&2
                        echo "1000"
                        return 0
                        ;;
                esac
            fi
            
            # 转为整数并验证
            local upload_mbps=${upload_speed%.*}
            if ! [[ "$upload_mbps" =~ ^[0-9]+$ ]] || [ "$upload_mbps" -le 0 ] 2>/dev/null; then
                echo -e "${gl_huang}⚠️ 检测到的带宽值异常 (${upload_speed})，使用默认值 1000 Mbps${gl_bai}" >&2
                upload_mbps=1000
            fi

            echo -e "${gl_lv}✅ 检测到上传带宽: ${upload_mbps} Mbps${gl_bai}" >&2
            echo "" >&2

            # 返回带宽值
            echo "$upload_mbps"
            return 0
            ;;
        2)
            # 手动指定测速服务器ID
            echo "" >&2
            echo -e "${gl_kjlan}=== 手动指定测速服务器 ===${gl_bai}" >&2
            echo "" >&2
            
            # 检查speedtest是否安装
            if ! command -v speedtest &>/dev/null; then
                echo -e "${gl_huang}speedtest 未安装，正在安装...${gl_bai}" >&2
                local cpu_arch=$(uname -m)
                local download_url
                case "$cpu_arch" in
                    x86_64)
                        download_url="https://install.speedtest.net/app/cli/ookla-speedtest-1.2.0-linux-x86_64.tgz"
                        ;;
                    aarch64)
                        download_url="https://install.speedtest.net/app/cli/ookla-speedtest-1.2.0-linux-aarch64.tgz"
                        ;;
                    *)
                        echo -e "${gl_hong}错误: 不支持的架构 ${cpu_arch}${gl_bai}" >&2
                        echo "将使用通用值 1000 Mbps" >&2
                        echo "1000"
                        return 1
                        ;;
                esac
                
                cd /tmp
                wget -q "$download_url" -O speedtest.tgz && \
                tar -xzf speedtest.tgz && \
                mv speedtest /usr/local/bin/ && \
                rm -f speedtest.tgz
                
                if [ $? -ne 0 ]; then
                    echo -e "${gl_hong}安装失败，将使用默认值 1000 Mbps${gl_bai}" >&2
                    echo "1000"
                    return 1
                fi
                echo -e "${gl_lv}✅ speedtest 安装成功${gl_bai}" >&2
                echo "" >&2
            fi
            
            # 显示如何查看服务器列表
            echo -e "${gl_zi}📋 如何查看可用的测速服务器：${gl_bai}" >&2
            echo "" >&2
            echo -e "  方法1：查看所有服务器列表" >&2
            echo -e "  ${gl_huang}speedtest --servers${gl_bai}" >&2
            echo "" >&2
            echo -e "  方法2：只显示附近服务器（推荐）" >&2
            echo -e "  ${gl_huang}speedtest --servers | head -n 20${gl_bai}" >&2
            echo "" >&2
            echo -e "${gl_zi}💡 服务器列表格式说明：${gl_bai}" >&2
            echo -e "  每行开头的数字就是服务器ID" >&2
            echo -e "  例如: ${gl_huang}12345${gl_bai}) 服务商名称 (位置, 距离)" >&2
            echo "" >&2
            echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >&2
            echo "" >&2
            
            # 询问是否现在查看服务器列表
            read -e -p "是否现在查看附近的测速服务器列表？(Y/N) [Y]: " show_list
            show_list=${show_list:-Y}
            
            if [[ "$show_list" =~ ^[Yy]$ ]]; then
                echo "" >&2
                echo -e "${gl_kjlan}附近的测速服务器列表：${gl_bai}" >&2
                echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >&2
                speedtest --accept-license --servers 2>/dev/null | head -n 20 >&2
                echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >&2
                echo "" >&2
            fi
            
            # 输入服务器ID
            local server_id=""
            while true; do
                read -e -p "$(echo -e "${gl_huang}请输入测速服务器ID（纯数字）: ${gl_bai}")" server_id
                
                if [[ "$server_id" =~ ^[0-9]+$ ]]; then
                    break
                else
                    echo -e "${gl_hong}❌ 无效输入，请输入纯数字的服务器ID${gl_bai}" >&2
                fi
            done
            
            # 使用指定服务器测速
            echo "" >&2
            echo -e "${gl_huang}正在使用服务器 #${server_id} 测速...${gl_bai}" >&2
            echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >&2
            echo "" >&2
            
            local speedtest_output=$(speedtest --accept-license --server-id="$server_id" 2>&1)
            echo "$speedtest_output" >&2
            echo "" >&2
            
            # 提取上传速度
            local upload_speed=""
            if echo "$speedtest_output" | grep -q "Upload:"; then
                upload_speed=$(echo "$speedtest_output" | sed -nE 's/.*[Uu]pload:[[:space:]]*([0-9]+(\.[0-9]+)?).*/\1/p' | head -n1)
            fi
            if [ -z "$upload_speed" ]; then
                upload_speed=$(echo "$speedtest_output" | grep -i "Upload:" | awk '{for(i=1;i<=NF;i++) if($i ~ /^[0-9]+\.[0-9]+$/) {print $i; exit}}')
            fi
            
            # 检查测速是否成功
            if [ -n "$upload_speed" ] && ! echo "$speedtest_output" | grep -qi "FAILED\|error"; then
                local upload_mbps=${upload_speed%.*}
                if ! [[ "$upload_mbps" =~ ^[0-9]+$ ]] || [ "$upload_mbps" -le 0 ] 2>/dev/null; then
                    echo -e "${gl_huang}⚠️ 检测到的带宽值异常 (${upload_speed})，使用默认值 1000 Mbps${gl_bai}" >&2
                    upload_mbps=1000
                fi
                echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >&2
                echo -e "${gl_lv}✅ 测速成功！${gl_bai}" >&2
                echo -e "${gl_lv}检测到上传带宽: ${upload_mbps} Mbps${gl_bai}" >&2
                echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >&2
                echo "" >&2
                echo "$upload_mbps"
                return 0
            else
                echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >&2
                echo -e "${gl_hong}❌ 测速失败${gl_bai}" >&2
                echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >&2
                echo "" >&2
                echo -e "${gl_zi}可能原因：${gl_bai}" >&2
                echo "  - 服务器ID不存在或已下线" >&2
                echo "  - 网络连接问题" >&2
                echo "  - 该服务器暂时不可用" >&2
                echo "" >&2
                
                read -e -p "是否使用默认值 1000 Mbps？(Y/N) [Y]: " use_default
                use_default=${use_default:-Y}
                
                if [[ "$use_default" =~ ^[Yy]$ ]]; then
                    echo "" >&2
                    echo -e "${gl_lv}✅ 使用默认配置: 1000 Mbps（16 MB 缓冲区）${gl_bai}" >&2
                    echo "1000"
                    return 0
                else
                    echo "" >&2
                    echo -e "${gl_zi}请手动输入带宽值${gl_bai}" >&2
                    local manual_bandwidth=""
                    while true; do
                        read -e -p "请输入上传带宽（单位：Mbps，如 500、1000、2000）: " manual_bandwidth
                        if [[ "$manual_bandwidth" =~ ^[0-9]+$ ]] && [ "$manual_bandwidth" -gt 0 ]; then
                            echo "" >&2
                            echo -e "${gl_lv}✅ 使用自定义值: ${manual_bandwidth} Mbps${gl_bai}" >&2
                            echo "$manual_bandwidth"
                            return 0
                        else
                            echo -e "${gl_hong}❌ 请输入有效的数字${gl_bai}" >&2
                        fi
                    done
                fi
            fi
            ;;
        3)
            # 手动选择预设档位
            echo "" >&2
            echo -e "${gl_kjlan}=== 手动选择带宽档位 ===${gl_bai}" >&2
            echo "" >&2
            echo "请选择带宽档位：" >&2
            echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >&2
            echo "" >&2
            echo -e "${gl_huang}【小带宽 VPS】${gl_bai}" >&2
            echo "1. 100 Mbps   → 缓冲区 6 MB   (NAT/极小带宽)" >&2
            echo "2. 200 Mbps   → 缓冲区 8 MB   (小型VPS)" >&2
            echo "3. 300 Mbps   → 缓冲区 10 MB  (入门服务器)" >&2
            echo "" >&2
            echo -e "${gl_huang}【中等带宽】${gl_bai}" >&2
            echo "4. 500 Mbps   → 缓冲区 12 MB  (标准小带宽)" >&2
            echo "5. 700 Mbps   → 缓冲区 14 MB  (准千兆)" >&2
            echo "6. 1 Gbps ⭐  → 缓冲区 16 MB  (标准VPS/最常见)" >&2
            echo "" >&2
            echo -e "${gl_huang}【高带宽服务器】${gl_bai}" >&2
            echo "7. 1.5 Gbps   → 缓冲区 20 MB  (中高端VPS)" >&2
            echo "8. 2 Gbps     → 缓冲区 24 MB  (高性能VPS)" >&2
            echo "9. 2.5 Gbps   → 缓冲区 28 MB  (准万兆)" >&2
            echo "" >&2
            echo -e "${gl_zi}【其他选项】${gl_bai}" >&2
            echo "10. 自定义输入（手动指定任意带宽值）" >&2
            echo "0. 返回上级菜单" >&2
            echo "" >&2
            echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >&2
            echo "" >&2
            
            # 读取用户选择
            local preset_choice=""
            read -e -p "请输入选择 [6]: " preset_choice
            preset_choice=${preset_choice:-6}  # 默认选择6 (1 Gbps)
            
            case "$preset_choice" in
                1)
                    echo "" >&2
                    echo -e "${gl_lv}✅ 已选择: 100 Mbps (缓冲区 6 MB)${gl_bai}" >&2
                    echo "100"
                    return 0
                    ;;
                2)
                    echo "" >&2
                    echo -e "${gl_lv}✅ 已选择: 200 Mbps (缓冲区 8 MB)${gl_bai}" >&2
                    echo "200"
                    return 0
                    ;;
                3)
                    echo "" >&2
                    echo -e "${gl_lv}✅ 已选择: 300 Mbps (缓冲区 10 MB)${gl_bai}" >&2
                    echo "300"
                    return 0
                    ;;
                4)
                    echo "" >&2
                    echo -e "${gl_lv}✅ 已选择: 500 Mbps (缓冲区 12 MB)${gl_bai}" >&2
                    echo "500"
                    return 0
                    ;;
                5)
                    echo "" >&2
                    echo -e "${gl_lv}✅ 已选择: 700 Mbps (缓冲区 14 MB)${gl_bai}" >&2
                    echo "700"
                    return 0
                    ;;
                6)
                    echo "" >&2
                    echo -e "${gl_lv}✅ 已选择: 1000 Mbps (缓冲区 16 MB)${gl_bai}" >&2
                    echo "1000"
                    return 0
                    ;;
                7)
                    echo "" >&2
                    echo -e "${gl_lv}✅ 已选择: 1500 Mbps (缓冲区 20 MB)${gl_bai}" >&2
                    echo "1500"
                    return 0
                    ;;
                8)
                    echo "" >&2
                    echo -e "${gl_lv}✅ 已选择: 2000 Mbps (缓冲区 24 MB)${gl_bai}" >&2
                    echo "2000"
                    return 0
                    ;;
                9)
                    echo "" >&2
                    echo -e "${gl_lv}✅ 已选择: 2500 Mbps (缓冲区 28 MB)${gl_bai}" >&2
                    echo "2500"
                    return 0
                    ;;
                10)
                    # 自定义输入
                    echo "" >&2
                    echo -e "${gl_zi}=== 自定义输入 ===${gl_bai}" >&2
                    echo "" >&2
                    local manual_bandwidth=""
                    while true; do
                        read -e -p "请输入带宽值（单位：Mbps，如 750、1200）: " manual_bandwidth
                        if [[ "$manual_bandwidth" =~ ^[0-9]+$ ]] && [ "$manual_bandwidth" -gt 0 ]; then
                            echo "" >&2
                            echo -e "${gl_lv}✅ 使用自定义值: ${manual_bandwidth} Mbps${gl_bai}" >&2
                            echo "$manual_bandwidth"
                            return 0
                        else
                            echo -e "${gl_hong}❌ 请输入有效的正整数${gl_bai}" >&2
                        fi
                    done
                    ;;
                0)
                    # 返回上级菜单
                    echo "" >&2
                    echo -e "${gl_huang}已取消选择，返回上级菜单${gl_bai}" >&2
                    echo "1000"  # 返回默认值，避免空值
                    return 1
                    ;;
                *)
                    echo "" >&2
                    echo -e "${gl_hong}无效选择，使用默认值 1000 Mbps${gl_bai}" >&2
                    echo "1000"
                    return 1
                    ;;
            esac
            ;;
        *)
            echo -e "${gl_huang}无效选择，使用默认值 1000 Mbps${gl_bai}" >&2
            echo "1000"
            return 1
            ;;
    esac
}

# 缓冲区大小计算函数
calculate_buffer_size() {
    local bandwidth=$1
    local buffer_mb
    local bandwidth_level

    # 输入验证：确保 bandwidth 是正整数
    if ! [[ "$bandwidth" =~ ^[0-9]+$ ]] || [ "$bandwidth" -le 0 ] 2>/dev/null; then
        echo -e "${gl_huang}⚠️ 带宽值无效 (${bandwidth})，使用默认值 16MB${gl_bai}" >&2
        echo "16"
        return 0
    fi

    # 优先匹配预设档位（精确匹配）
    if [ "$bandwidth" -eq 100 ]; then
        buffer_mb=6
        bandwidth_level="预设档位（100 Mbps）"
    elif [ "$bandwidth" -eq 200 ]; then
        buffer_mb=8
        bandwidth_level="预设档位（200 Mbps）"
    elif [ "$bandwidth" -eq 300 ]; then
        buffer_mb=10
        bandwidth_level="预设档位（300 Mbps）"
    elif [ "$bandwidth" -eq 500 ]; then
        buffer_mb=12
        bandwidth_level="预设档位（500 Mbps）"
    elif [ "$bandwidth" -eq 700 ]; then
        buffer_mb=14
        bandwidth_level="预设档位（700 Mbps）"
    elif [ "$bandwidth" -eq 1000 ]; then
        buffer_mb=16
        bandwidth_level="预设档位（1 Gbps）"
    elif [ "$bandwidth" -eq 1500 ]; then
        buffer_mb=20
        bandwidth_level="预设档位（1.5 Gbps）"
    elif [ "$bandwidth" -eq 2000 ]; then
        buffer_mb=24
        bandwidth_level="预设档位（2 Gbps）"
    elif [ "$bandwidth" -eq 2500 ]; then
        buffer_mb=28
        bandwidth_level="预设档位（2.5 Gbps）"
    # 否则使用原有的范围判断（用于自动检测和自定义值）
    elif [ "$bandwidth" -lt 500 ]; then
        buffer_mb=8
        bandwidth_level="小带宽（< 500 Mbps）"
    elif [ "$bandwidth" -lt 1000 ]; then
        buffer_mb=12
        bandwidth_level="中等带宽（500-1000 Mbps）"
    elif [ "$bandwidth" -lt 2000 ]; then
        buffer_mb=16
        bandwidth_level="标准带宽（1-2 Gbps）"
    elif [ "$bandwidth" -lt 5000 ]; then
        buffer_mb=24
        bandwidth_level="高带宽（2-5 Gbps）"
    elif [ "$bandwidth" -lt 10000 ]; then
        buffer_mb=28
        bandwidth_level="超高带宽（5-10 Gbps）"
    else
        buffer_mb=32
        bandwidth_level="极高带宽（> 10 Gbps）"
    fi
    
    # 显示计算结果（输出到stderr）
    echo "" >&2
    echo -e "${gl_kjlan}根据带宽计算最优缓冲区:${gl_bai}" >&2
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >&2
    echo -e "  检测带宽: ${gl_huang}${bandwidth} Mbps${gl_bai}" >&2
    echo -e "  带宽等级: ${bandwidth_level}" >&2
    echo -e "  推荐缓冲区: ${gl_lv}${buffer_mb} MB${gl_bai}" >&2
    echo -e "  说明: 适合该带宽的最优配置" >&2
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >&2
    echo "" >&2
    
    # 询问确认
    if [ "$AUTO_MODE" = "1" ]; then
        confirm=Y
    else
        read -e -p "$(echo -e "${gl_huang}是否使用推荐值 ${buffer_mb}MB？(Y/N) [Y]: ${gl_bai}")" confirm
        confirm=${confirm:-Y}
    fi

    case "$confirm" in
        [Yy])
            # 返回缓冲区大小（MB）
            echo "$buffer_mb"
            return 0
            ;;
        *)
            echo "" >&2
            echo -e "${gl_huang}已取消，将使用通用值 16MB${gl_bai}" >&2
            echo "16"
            return 1
            ;;
    esac
}

#=============================================================================
# SWAP智能检测和建议函数（集成到选项2/3）
#=============================================================================
check_and_suggest_swap() {
    local mem_total=$(free -m | awk 'NR==2{print $2}')
    local swap_total=$(free -m | awk 'NR==3{print $2}')
    local recommended_swap
    local need_swap=0
    
    # 判断是否需要SWAP
    if [ "$mem_total" -lt 2048 ]; then
        # 小于2GB内存，强烈建议配置SWAP
        need_swap=1
    elif [ "$mem_total" -lt 4096 ] && [ "$swap_total" -eq 0 ]; then
        # 2-4GB内存且没有SWAP，建议配置
        need_swap=1
    fi
    
    # 如果不需要SWAP，直接返回
    if [ "$need_swap" -eq 0 ]; then
        return 0
    fi
    
    # 计算推荐的SWAP大小
    if [ "$mem_total" -lt 512 ]; then
        recommended_swap=1024
    elif [ "$mem_total" -lt 1024 ]; then
        recommended_swap=$((mem_total * 2))
    elif [ "$mem_total" -lt 2048 ]; then
        recommended_swap=$((mem_total * 3 / 2))
    elif [ "$mem_total" -lt 4096 ]; then
        recommended_swap=$mem_total
    else
        recommended_swap=4096
    fi
    
    # 显示建议信息
    echo ""
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo -e "${gl_huang}检测到虚拟内存（SWAP）需要优化${gl_bai}"
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo ""
    echo -e "  物理内存:       ${gl_huang}${mem_total}MB${gl_bai}"
    echo -e "  当前 SWAP:      ${gl_huang}${swap_total}MB${gl_bai}"
    echo -e "  推荐 SWAP:      ${gl_lv}${recommended_swap}MB${gl_bai}"
    echo ""
    
    if [ "$mem_total" -lt 1024 ]; then
        echo -e "${gl_zi}原因: 小内存机器（<1GB）强烈建议配置SWAP，避免内存不足导致程序崩溃${gl_bai}"
    elif [ "$mem_total" -lt 2048 ]; then
        echo -e "${gl_zi}原因: 1-2GB内存建议配置SWAP，提供缓冲空间${gl_bai}"
    elif [ "$mem_total" -lt 4096 ]; then
        echo -e "${gl_zi}原因: 2-4GB内存建议配置少量SWAP作为保险${gl_bai}"
    fi
    
    echo ""
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo ""
    
    # 询问用户
    if [ "$AUTO_MODE" = "1" ]; then
        confirm=Y
    else
        read -e -p "$(echo -e "${gl_huang}是否现在配置虚拟内存？(Y/N): ${gl_bai}")" confirm
    fi

    case "$confirm" in
        [Yy])
            echo ""
            echo -e "${gl_lv}开始配置虚拟内存...${gl_bai}"
            echo ""
            add_swap "$recommended_swap"
            echo ""
            echo -e "${gl_lv}✅ 虚拟内存配置完成！${gl_bai}"
            echo ""
            echo -e "${gl_zi}继续执行 BBR 优化配置...${gl_bai}"
            sleep 2
            return 0
            ;;
        [Nn])
            echo ""
            echo -e "${gl_huang}已跳过虚拟内存配置${gl_bai}"
            echo -e "${gl_zi}继续执行 BBR 优化配置...${gl_bai}"
            echo ""
            sleep 2
            return 1
            ;;
        *)
            echo ""
            echo -e "${gl_huang}输入无效，已跳过虚拟内存配置${gl_bai}"
            echo -e "${gl_zi}继续执行 BBR 优化配置...${gl_bai}"
            echo ""
            sleep 2
            return 1
            ;;
    esac
}

#=============================================================================
# 配置冲突检测与清理（避免被其他 sysctl 覆盖）
#=============================================================================
check_and_clean_conflicts() {
    echo -e "${gl_kjlan}=== 检查 sysctl 配置冲突 ===${gl_bai}"
    local conflicts=()
    # 搜索 /etc/sysctl.d/ 下可能覆盖 tcp_rmem/tcp_wmem 的高序号文件
    for conf in /etc/sysctl.d/[0-9]*-*.conf /etc/sysctl.d/[0-9][0-9][0-9]-*.conf; do
        [ -f "$conf" ] || continue
        [ "$conf" = "$SYSCTL_CONF" ] && continue
        if grep -qE "(^|\s)net\.ipv4\.tcp_(rmem|wmem)" "$conf" 2>/dev/null; then
            base=$(basename "$conf")
            num=$(echo "$base" | sed -n 's/^\([0-9]\+\).*/\1/p')
            # 99 及以上优先生效，可能覆盖本脚本
            if [ -n "$num" ] && [ "$num" -ge 99 ]; then
                conflicts+=("$conf")
            fi
        fi
    done

    # 主配置文件直接设置也会覆盖
    local has_sysctl_conflict=0
    if [ -f /etc/sysctl.conf ] && grep -qE "(^|\s)net\.ipv4\.tcp_(rmem|wmem)" /etc/sysctl.conf 2>/dev/null; then
        has_sysctl_conflict=1
    fi

    if [ ${#conflicts[@]} -eq 0 ] && [ $has_sysctl_conflict -eq 0 ]; then
        echo -e "${gl_lv}✓ 未发现可能的覆盖配置${gl_bai}"
        return 0
    fi

    echo -e "${gl_huang}发现可能的覆盖配置：${gl_bai}"
    for f in "${conflicts[@]}"; do
        echo "  - $f"; grep -E "net\.ipv4\.tcp_(rmem|wmem)" "$f" | sed 's/^/      /'
    done
    [ $has_sysctl_conflict -eq 1 ] && echo "  - /etc/sysctl.conf (含 tcp_rmem/tcp_wmem)"

    if [ "$AUTO_MODE" = "1" ]; then
        ans=Y
    else
        read -e -p "是否自动禁用/注释这些覆盖配置？(Y/N): " ans
    fi
    case "$ans" in
        [Yy])
            # 注释 /etc/sysctl.conf 中相关行
            if [ $has_sysctl_conflict -eq 1 ]; then
                # 先创建一次备份，再用 sed -i 逐行注释（避免多次 .bak 覆盖）
                cp /etc/sysctl.conf /etc/sysctl.conf.bak.conflict 2>/dev/null
                sed -i '/^net\.ipv4\.tcp_wmem/s/^/# /' /etc/sysctl.conf 2>/dev/null
                sed -i '/^net\.ipv4\.tcp_rmem/s/^/# /' /etc/sysctl.conf 2>/dev/null
                sed -i '/^net\.core\.rmem_max/s/^/# /' /etc/sysctl.conf 2>/dev/null
                sed -i '/^net\.core\.wmem_max/s/^/# /' /etc/sysctl.conf 2>/dev/null
                echo -e "${gl_lv}✓ 已注释 /etc/sysctl.conf 中的相关配置（备份: .bak.conflict）${gl_bai}"
            fi
            # 将高优先级冲突文件重命名禁用
            for f in "${conflicts[@]}"; do
                if mv "$f" "${f}.disabled.$(date +%Y%m%d_%H%M%S)" 2>/dev/null; then
                    echo -e "${gl_lv}✓ 已禁用: $(basename "$f")${gl_bai}"
                else
                    echo -e "${gl_hong}✗ 无法禁用: $(basename "$f")，请手动处理${gl_bai}"
                fi
            done
            ;;
        *)
            echo -e "${gl_huang}已跳过自动清理，可能导致新配置未完全生效${gl_bai}"
            ;;
    esac
}

#=============================================================================
# 立即生效与防分片函数（无需重启）
#=============================================================================

# 获取需应用 qdisc 的网卡（排除常见虚拟接口）
eligible_ifaces() {
    for d in /sys/class/net/*; do
        [ -e "$d" ] || continue
        dev=$(basename "$d")
        case "$dev" in
            lo|docker*|veth*|br-*|virbr*|zt*|tailscale*|wg*|tun*|tap*) continue;;
        esac
        echo "$dev"
    done
}

# tc fq 立即生效（无需重启）
apply_tc_fq_now() {
    if ! command -v tc >/dev/null 2>&1; then
        echo -e "${gl_huang}警告: 未检测到 tc（iproute2），跳过 fq 应用${gl_bai}"
        return 0
    fi
    local applied=0
    for dev in $(eligible_ifaces); do
        tc qdisc replace dev "$dev" root fq 2>/dev/null && applied=$((applied+1))
    done
    [ $applied -gt 0 ] && echo -e "${gl_lv}已对 $applied 个网卡应用 fq（即时生效）${gl_bai}" || echo -e "${gl_huang}未发现可应用 fq 的网卡${gl_bai}"
}

# MSS clamp（防分片）自动启用
apply_mss_clamp() {
    local action=$1  # enable|disable
    if ! command -v iptables >/dev/null 2>&1; then
        echo -e "${gl_huang}警告: 未检测到 iptables，跳过 MSS clamp${gl_bai}"
        return 0
    fi
    if [ "$action" = "enable" ]; then
        iptables -t mangle -C FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu >/dev/null 2>&1 \
          || iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
    else
        iptables -t mangle -D FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu >/dev/null 2>&1 || true
    fi
}

#=============================================================================
# BBR 配置函数（智能检测版）
#=============================================================================

# 直连/落地优化配置
bbr_configure_direct() {
    echo -e "${gl_kjlan}=== 配置 BBR v3 + FQ 直连/落地优化（智能检测版） ===${gl_bai}"
    echo ""
    
    # 步骤 0：SWAP智能检测和建议
    echo -e "${gl_zi}[步骤 1/6] 检测虚拟内存（SWAP）配置...${gl_bai}"
    check_and_suggest_swap
    
    # 步骤 0.5：带宽检测和缓冲区计算
    echo ""
    echo -e "${gl_zi}[步骤 2/6] 检测服务器带宽并计算最优缓冲区...${gl_bai}"
    
    local detected_bandwidth=$(detect_bandwidth)
    local buffer_mb=$(calculate_buffer_size "$detected_bandwidth")
    local buffer_bytes=$((buffer_mb * 1024 * 1024))
    
    echo -e "${gl_lv}✅ 将使用 ${buffer_mb}MB 缓冲区配置${gl_bai}"
    sleep 2
    
    echo ""
    echo -e "${gl_zi}[步骤 3/6] 清理配置冲突...${gl_bai}"
    echo "正在检查配置冲突..."
    
    # 备份主配置文件（如果还没备份）
    if [ -f /etc/sysctl.conf ] && ! [ -f /etc/sysctl.conf.bak.original ]; then
        cp /etc/sysctl.conf /etc/sysctl.conf.bak.original
        echo "已备份: /etc/sysctl.conf -> /etc/sysctl.conf.bak.original"
    fi
    
    # 注释掉 /etc/sysctl.conf 中的 TCP 缓冲区配置（避免覆盖）
    if [ -f /etc/sysctl.conf ]; then
        clean_sysctl_conf
        echo "已清理 /etc/sysctl.conf 中的冲突配置"
    fi
    
    # 删除可能存在的软链接
    if [ -L /etc/sysctl.d/99-sysctl.conf ]; then
        rm -f /etc/sysctl.d/99-sysctl.conf
        echo "已删除配置软链接"
    fi
    
    # 检查并清理可能覆盖的新旧配置冲突
    check_and_clean_conflicts

    # 步骤 3：创建独立配置文件（使用动态缓冲区）
    echo ""
    echo -e "${gl_zi}[步骤 4/6] 创建配置文件...${gl_bai}"
    echo "正在创建新配置..."
    
    # 获取物理内存用于虚拟内存参数调整
    local mem_total=$(free -m | awk 'NR==2{print $2}')
    local vm_swappiness=5
    local vm_dirty_ratio=15
    local vm_min_free_kbytes=65536
    
    # 根据内存大小微调虚拟内存参数
    if [ "$mem_total" -lt 2048 ]; then
        vm_swappiness=20
        vm_dirty_ratio=20
        vm_min_free_kbytes=32768
    fi
    
    cat > "$SYSCTL_CONF" << EOF
# BBR v3 Direct/Endpoint Configuration (Intelligent Detection Edition)
# Generated on $(date)
# Bandwidth: ${detected_bandwidth} Mbps | Buffer: ${buffer_mb} MB

# 队列调度算法
net.core.default_qdisc=fq

# 拥塞控制算法
net.ipv4.tcp_congestion_control=bbr

# TCP 缓冲区优化（智能检测：${buffer_mb}MB）
net.core.rmem_max=${buffer_bytes}
net.core.wmem_max=${buffer_bytes}
net.ipv4.tcp_rmem=4096 87380 ${buffer_bytes}
net.ipv4.tcp_wmem=4096 65536 ${buffer_bytes}

# ===== 直连/落地优化参数 =====

# TIME_WAIT 重用（启用，提高并发）
net.ipv4.tcp_tw_reuse=1

# 端口范围（最大化）
net.ipv4.ip_local_port_range=1024 65535

# 连接队列（高性能）
net.core.somaxconn=4096
net.ipv4.tcp_max_syn_backlog=8192

# 网络队列（高带宽优化）
net.core.netdev_max_backlog=5000

# 高级TCP优化
net.ipv4.tcp_slow_start_after_idle=0
net.ipv4.tcp_mtu_probing=1

# ===== Reality终极优化参数 =====

# 发送低水位（上传速度优化关键）
net.ipv4.tcp_notsent_lowat=16384

# 连接回收优化
net.ipv4.tcp_fin_timeout=15
net.ipv4.tcp_max_tw_buckets=5000

# TCP Fast Open（节省1个RTT，加速连接建立）
net.ipv4.tcp_fastopen=3

# TCP保活优化（更快检测死连接）
net.ipv4.tcp_keepalive_time=300
net.ipv4.tcp_keepalive_intvl=30
net.ipv4.tcp_keepalive_probes=5

# UDP缓冲区（QUIC/Hysteria 支持）
net.ipv4.udp_rmem_min=8192
net.ipv4.udp_wmem_min=8192

# TCP安全增强
net.ipv4.tcp_syncookies=1

# 虚拟内存优化（根据物理内存调整）
vm.swappiness=${vm_swappiness}
vm.dirty_ratio=${vm_dirty_ratio}
vm.dirty_background_ratio=5
vm.overcommit_memory=1
vm.min_free_kbytes=${vm_min_free_kbytes}
vm.vfs_cache_pressure=50

# CPU调度优化
kernel.sched_autogroup_enabled=0
kernel.numa_balancing=0
EOF

    # 检查配置文件是否创建成功
    if [ ! -f "$SYSCTL_CONF" ] || [ ! -s "$SYSCTL_CONF" ]; then
        echo -e "${gl_hong}❌ 配置文件创建失败！请检查磁盘空间和权限${gl_bai}"
        return 1
    fi

    # 步骤 4：应用配置
    echo ""
    echo -e "${gl_zi}[步骤 5/6] 应用所有优化参数...${gl_bai}"
    echo "正在应用配置..."
    local sysctl_output
    sysctl_output=$(sysctl -p "$SYSCTL_CONF" 2>&1)
    local sysctl_rc=$?
    if [ $sysctl_rc -ne 0 ]; then
        echo -e "${gl_huang}⚠️ sysctl 部分参数应用失败（可能有不支持的参数）:${gl_bai}"
        echo "$sysctl_output" | grep -i "error\|invalid\|unknown\|cannot" | head -5
        echo -e "${gl_zi}已支持的参数仍然生效，不影响整体优化${gl_bai}"
    else
        echo -e "${gl_lv}✓ 所有 sysctl 参数已成功应用${gl_bai}"
    fi

    # 立即应用 fq，并启用 MSS clamp（无需重启）
    echo "正在应用队列与防分片（无需重启）..."
    apply_tc_fq_now >/dev/null 2>&1
    apply_mss_clamp enable >/dev/null 2>&1

    # 持久化 tc fq 和 iptables MSS clamp（重启后自动恢复）
    echo "正在配置重启持久化..."
    # 创建 systemd 服务实现 tc fq + MSS clamp 开机恢复
    cat > /etc/systemd/system/bbr-optimize-persist.service << 'PERSISTEOF'
[Unit]
Description=BBR Optimize - Restore tc fq and MSS clamp after boot
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/bin/bbr-optimize-apply.sh

[Install]
WantedBy=multi-user.target
PERSISTEOF

    cat > /usr/local/bin/bbr-optimize-apply.sh << 'APPLYEOF'
#!/bin/bash
# BBR Optimize 重启恢复脚本 - 自动生成，勿手动编辑
# 应用 tc fq 到所有物理网卡
for d in /sys/class/net/*; do
    [ -e "$d" ] || continue
    dev=$(basename "$d")
    case "$dev" in
        lo|docker*|veth*|br-*|virbr*|zt*|tailscale*|wg*|tun*|tap*) continue;;
    esac
    tc qdisc replace dev "$dev" root fq 2>/dev/null
done
# 应用 iptables MSS clamp
if command -v iptables >/dev/null 2>&1; then
    iptables -t mangle -C FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu >/dev/null 2>&1 \
      || iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
fi
# 禁用透明大页
if [ -f /sys/kernel/mm/transparent_hugepage/enabled ]; then
    echo never > /sys/kernel/mm/transparent_hugepage/enabled 2>/dev/null
fi
# 优化 TCP 初始拥塞窗口（加速连接起步）
DEF_ROUTE=$(ip route show default 2>/dev/null | head -1)
if [ -n "$DEF_ROUTE" ]; then
    CLEAN_ROUTE=$(echo "$DEF_ROUTE" | sed 's/ initcwnd [0-9]*//g; s/ initrwnd [0-9]*//g')
    ip route change $CLEAN_ROUTE initcwnd 32 initrwnd 32 2>/dev/null
fi
# RPS/RFS 多核网络优化（遍历所有物理网卡）
CPU_COUNT=$(nproc 2>/dev/null || echo 1)
if [ "$CPU_COUNT" -gt 1 ]; then
    RPS_MASK=$(printf '%x' $((2**CPU_COUNT - 1)))
    FLOW_ENTRIES=$((4096 * CPU_COUNT))
    echo "$FLOW_ENTRIES" > /proc/sys/net/core/rps_sock_flow_entries 2>/dev/null
    for D in /sys/class/net/*; do
        [ -e "$D" ] || continue
        DEV=$(basename "$D")
        case "$DEV" in
            lo|docker*|veth*|br-*|virbr*|zt*|tailscale*|wg*|tun*|tap*) continue;;
        esac
        [ -d "/sys/class/net/$DEV/queues" ] || continue
        for RXQ in /sys/class/net/$DEV/queues/rx-*/rps_cpus; do
            [ -f "$RXQ" ] && echo "$RPS_MASK" > "$RXQ" 2>/dev/null
        done
        for RXQ_DIR in /sys/class/net/$DEV/queues/rx-*/; do
            [ -f "${RXQ_DIR}rps_flow_cnt" ] && echo "$((FLOW_ENTRIES / CPU_COUNT))" > "${RXQ_DIR}rps_flow_cnt" 2>/dev/null
        done
    done
fi
APPLYEOF
    chmod +x /usr/local/bin/bbr-optimize-apply.sh
    systemctl daemon-reload 2>/dev/null
    systemctl enable bbr-optimize-persist.service 2>/dev/null
    echo -e "${gl_lv}✓ tc fq / MSS clamp / 透明大页 重启持久化已配置${gl_bai}"

    # 配置文件描述符限制
    echo "正在优化文件描述符限制..."
    if ! grep -q "^\* soft nofile 524288" /etc/security/limits.conf 2>/dev/null && \
       ! grep -q "BBR - 文件描述符优化" /etc/security/limits.conf 2>/dev/null; then
        cat >> /etc/security/limits.conf << 'LIMITSEOF'
# BBR - 文件描述符优化
* soft nofile 524288
* hard nofile 524288
LIMITSEOF
    fi
    ulimit -n 524288 2>/dev/null

    # 禁用透明大页面（当前运行时）
    if [ -f /sys/kernel/mm/transparent_hugepage/enabled ]; then
        echo never > /sys/kernel/mm/transparent_hugepage/enabled 2>/dev/null
    fi

    # 优化 TCP 初始拥塞窗口（加速连接起步，节省1-2个RTT）
    echo "正在优化 TCP 初始拥塞窗口..."
    local def_route
    def_route=$(ip route show default 2>/dev/null | head -1)
    if [ -n "$def_route" ]; then
        # 清除已有的 initcwnd/initrwnd 再重新设置，避免重复
        local clean_route
        clean_route=$(echo "$def_route" | sed 's/ initcwnd [0-9]*//g; s/ initrwnd [0-9]*//g')
        if ip route change $clean_route initcwnd 32 initrwnd 32 2>/dev/null; then
            echo -e "${gl_lv}✓ initcwnd=32 initrwnd=32 已应用（加速 TCP 连接起步）${gl_bai}"
        else
            echo -e "${gl_huang}⚠️ initcwnd 设置失败（不影响其他优化）${gl_bai}"
        fi
    else
        echo -e "${gl_huang}⚠️ 未检测到默认路由，跳过 initcwnd 优化${gl_bai}"
    fi

    # RPS/RFS 多核网络优化（将网卡收包分散到所有 CPU 核心）
    local cpu_count
    cpu_count=$(nproc 2>/dev/null || echo 1)
    if [ "$cpu_count" -gt 1 ]; then
        echo "正在配置 RPS/RFS 多核网络优化..."
        # 计算 CPU 掩码（所有核心参与）：2核=3, 4核=f, 8核=ff
        local rps_mask
        rps_mask=$(printf '%x' $((2**cpu_count - 1)))
        local flow_entries=$((4096 * cpu_count))
        echo "$flow_entries" > /proc/sys/net/core/rps_sock_flow_entries 2>/dev/null
        # 遍历所有物理网卡（排除虚拟/隧道接口）
        local rps_ok=0
        local rps_devs=""
        local dev
        for d in /sys/class/net/*; do
            [ -e "$d" ] || continue
            dev=$(basename "$d")
            case "$dev" in
                lo|docker*|veth*|br-*|virbr*|zt*|tailscale*|wg*|tun*|tap*) continue;;
            esac
            [ -d "/sys/class/net/$dev/queues" ] || continue
            # 设置 RPS：将收包分散到所有核心
            for rxq in /sys/class/net/$dev/queues/rx-*/rps_cpus; do
                if [ -f "$rxq" ]; then
                    echo "$rps_mask" > "$rxq" 2>/dev/null
                    # 写入后读回验证（有些环境 echo 返回0但内核没接受）
                    local verify_val
                    verify_val=$(cat "$rxq" 2>/dev/null | tr -d ',' | sed 's/^0*//')
                    [ -z "$verify_val" ] && verify_val="0"
                    [ "$verify_val" = "$rps_mask" ] && rps_ok=1
                fi
            done
            # 设置 RFS：同一连接的包尽量在同一核处理（减少 cache miss）
            for rxq_dir in /sys/class/net/$dev/queues/rx-*/; do
                if [ -f "${rxq_dir}rps_flow_cnt" ]; then
                    echo "$((flow_entries / cpu_count))" > "${rxq_dir}rps_flow_cnt" 2>/dev/null
                fi
            done
            rps_devs="${rps_devs} ${dev}"
        done
        if [ $rps_ok -eq 1 ]; then
            echo -e "${gl_lv}✓ RPS/RFS 已启用（${cpu_count} 核，掩码: 0x${rps_mask}，网卡:${rps_devs}）${gl_bai}"
        else
            echo -e "${gl_huang}⚠️ RPS 设置未生效（当前虚拟化环境可能不支持，不影响其他优化）${gl_bai}"
        fi
    else
        echo -e "${gl_zi}ℹ 单核 CPU，跳过 RPS/RFS（单核无需分担）${gl_bai}"
    fi

    # 步骤 5：验证配置是否真正生效
    echo ""
    echo -e "${gl_zi}[步骤 6/6] 验证配置...${gl_bai}"
    
    local actual_qdisc=$(sysctl -n net.core.default_qdisc 2>/dev/null)
    local actual_cc=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)
    local actual_wmem=$(sysctl -n net.ipv4.tcp_wmem 2>/dev/null | awk '{print $3}')
    local actual_rmem=$(sysctl -n net.ipv4.tcp_rmem 2>/dev/null | awk '{print $3}')
    
    echo ""
    echo -e "${gl_kjlan}=== 配置验证 ===${gl_bai}"
    
    # 验证队列算法
    if [ "$actual_qdisc" = "fq" ]; then
        echo -e "队列算法: ${gl_lv}$actual_qdisc ✓${gl_bai}"
    else
        echo -e "队列算法: ${gl_huang}$actual_qdisc (期望: fq) ⚠${gl_bai}"
    fi
    
    # 验证拥塞控制
    if [ "$actual_cc" = "bbr" ]; then
        echo -e "拥塞控制: ${gl_lv}$actual_cc ✓${gl_bai}"
    else
        echo -e "拥塞控制: ${gl_huang}$actual_cc (期望: bbr) ⚠${gl_bai}"
    fi
    
    # 验证缓冲区（动态）
    local actual_wmem_mb=$((actual_wmem / 1048576))
    local actual_rmem_mb=$((actual_rmem / 1048576))
    
    if [ "$actual_wmem" = "$buffer_bytes" ]; then
        echo -e "发送缓冲区: ${gl_lv}${buffer_mb}MB ✓${gl_bai}"
    else
        echo -e "发送缓冲区: ${gl_huang}${actual_wmem_mb}MB (期望: ${buffer_mb}MB) ⚠${gl_bai}"
    fi
    
    if [ "$actual_rmem" = "$buffer_bytes" ]; then
        echo -e "接收缓冲区: ${gl_lv}${buffer_mb}MB ✓${gl_bai}"
    else
        echo -e "接收缓冲区: ${gl_huang}${actual_rmem_mb}MB (期望: ${buffer_mb}MB) ⚠${gl_bai}"
    fi

    # 验证 initcwnd
    local actual_initcwnd
    actual_initcwnd=$(ip route show default 2>/dev/null | head -1 | grep -oP 'initcwnd \K[0-9]+')
    if [ "$actual_initcwnd" = "32" ]; then
        echo -e "初始窗口:   ${gl_lv}initcwnd=$actual_initcwnd ✓${gl_bai}"
    elif [ -n "$actual_initcwnd" ]; then
        echo -e "初始窗口:   ${gl_huang}initcwnd=$actual_initcwnd (期望: 32) ⚠${gl_bai}"
    else
        echo -e "初始窗口:   ${gl_huang}未设置 (期望: initcwnd=32) ⚠${gl_bai}"
    fi

    # 验证 RPS
    if [ "$cpu_count" -gt 1 ]; then
        local expected_mask
        expected_mask=$(printf '%x' $((2**cpu_count - 1)))
        local rps_verify_devs=""
        local rps_all_ok=1
        for d in /sys/class/net/*; do
            [ -e "$d" ] || continue
            local vdev=$(basename "$d")
            case "$vdev" in
                lo|docker*|veth*|br-*|virbr*|zt*|tailscale*|wg*|tun*|tap*) continue;;
            esac
            [ -f "/sys/class/net/$vdev/queues/rx-0/rps_cpus" ] || continue
            local rps_val
            # rps_cpus 可能返回 "3" 或 "00000003" 或 "00000000,00000003"
            rps_val=$(cat /sys/class/net/$vdev/queues/rx-0/rps_cpus 2>/dev/null | tr -d ',' | sed 's/^0*//')
            [ -z "$rps_val" ] && rps_val="0"
            if [ "$rps_val" = "$expected_mask" ]; then
                rps_verify_devs="${rps_verify_devs} ${vdev}✓"
            else
                rps_verify_devs="${rps_verify_devs} ${vdev}✗"
                rps_all_ok=0
            fi
        done
        if [ -n "$rps_verify_devs" ]; then
            if [ $rps_all_ok -eq 1 ]; then
                echo -e "RPS/RFS:    ${gl_lv}${cpu_count}核分担 (0x${expected_mask})${rps_verify_devs} ✓${gl_bai}"
            else
                echo -e "RPS/RFS:    ${gl_huang}部分网卡未生效:${rps_verify_devs} ⚠${gl_bai}"
            fi
        else
            echo -e "RPS/RFS:    ${gl_huang}未检测到物理网卡 ⚠${gl_bai}"
        fi
    else
        echo -e "RPS/RFS:    ${gl_zi}单核跳过${gl_bai}"
    fi

    echo ""

    # 最终判断
    if [ "$actual_qdisc" = "fq" ] && [ "$actual_cc" = "bbr" ] && \
       [ "$actual_wmem" = "$buffer_bytes" ] && [ "$actual_rmem" = "$buffer_bytes" ]; then
        echo -e "${gl_lv}✅ BBR v3 直连/落地优化配置完成并已生效！${gl_bai}"
        echo -e "${gl_zi}配置说明: ${buffer_mb}MB 缓冲区（${detected_bandwidth} Mbps 带宽），适合直连/落地场景${gl_bai}"
    else
        echo -e "${gl_huang}⚠️ 配置已保存但部分参数未生效${gl_bai}"
        echo -e "${gl_huang}建议执行以下操作：${gl_bai}"
        echo "1. 检查是否有其他配置文件冲突"
        echo "2. 重启服务器使配置完全生效: reboot"
    fi
}

#=============================================================================
# 状态检查函数
#=============================================================================

check_bbr_status() {
    echo -e "${gl_kjlan}=== 当前系统状态 ===${gl_bai}"
    local kernel_release
    kernel_release=$(uname -r)
    echo "内核版本: $kernel_release"
    
    local congestion="未知"
    local qdisc="未知"
    local bbr_version=""
    local bbr_active=0
    
    if command -v sysctl &>/dev/null; then
        congestion=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo "未知")
        qdisc=$(sysctl -n net.core.default_qdisc 2>/dev/null || echo "未知")
        echo "拥塞控制算法: $congestion"
        echo "队列调度算法: $qdisc"
        
        if command -v modinfo &>/dev/null; then
            bbr_version=$(modinfo tcp_bbr 2>/dev/null | awk '/^version:/ {print $2}')
            if [ -n "$bbr_version" ]; then
                if [ "$bbr_version" = "3" ]; then
                    echo -e "BBR 版本: ${gl_lv}v${bbr_version} ✓${gl_bai}"
                else
                    echo -e "BBR 版本: ${gl_huang}v${bbr_version} (不是 v3)${gl_bai}"
                fi
            fi
        fi
    fi
    
    if [ "$congestion" = "bbr" ] && [ "$bbr_version" = "3" ]; then
        bbr_active=1
    fi
    
    local xanmod_pkg_installed=0
    local dpkg_available=0
    if command -v dpkg &>/dev/null; then
        dpkg_available=1
        if dpkg -l 2>/dev/null | grep -qE '^ii\s+linux-.*xanmod'; then
            xanmod_pkg_installed=1
        fi
    fi
    
    local xanmod_running=0
    if echo "$kernel_release" | grep -qi 'xanmod'; then
        xanmod_running=1
    fi
    
    local status=1
    
    if [ $xanmod_pkg_installed -eq 1 ]; then
        echo -e "XanMod 内核: ${gl_lv}已安装 ✓${gl_bai}"
        status=0
    elif [ $xanmod_running -eq 1 ]; then
        echo -e "XanMod 内核: ${gl_huang}内核包已卸载，但当前运行版本仍为 ${kernel_release}，请重启系统使卸载完全生效${gl_bai}"
    else
        echo -e "XanMod 内核: ${gl_huang}未安装${gl_bai}"
    fi
    
    if [ $status -ne 0 ] && [ $bbr_active -eq 1 ]; then
        echo -e "${gl_kjlan}提示: 当前仍在运行 BBR v3 模块，重启后将恢复系统默认配置${gl_bai}"
    fi
    
    if [ $status -ne 0 ] && [ $dpkg_available -eq 0 ]; then
        # 非 Debian 系统：仅当内核名确实含 xanmod 时才认为已安装
        # BBR v3 活跃不等于 XanMod（用户可能自编译内核），避免误触发 update 流程
        if [ $xanmod_running -eq 1 ]; then
            status=0
        fi
    fi
    
    return $status
}

#=============================================================================
# XanMod 内核安装（官方源）
#=============================================================================

install_xanmod_kernel() {
    clear
    echo -e "${gl_kjlan}=== 安装 XanMod 内核与 BBR v3 ===${gl_bai}"
    echo "视频教程: https://www.bilibili.com/video/BV14K421x7BS"
    echo "------------------------------------------------"
    echo "支持系统: Debian/Ubuntu (x86_64 & ARM64)"
    echo -e "${gl_huang}警告: 将升级 Linux 内核，请提前备份重要数据！${gl_bai}"
    echo "------------------------------------------------"
    read -e -p "确定继续安装吗？(Y/N): " choice

    case "$choice" in
        [Yy])
            ;;
        *)
            echo "已取消安装"
            return 1
            ;;
    esac
    
    # 检测 CPU 架构
    local cpu_arch=$(uname -m)
    
    # ARM 架构特殊处理
    if [ "$cpu_arch" = "aarch64" ]; then
        echo -e "${gl_kjlan}检测到 ARM64 架构，使用专用安装脚本${gl_bai}"

        install_package curl coreutils || return 1

        local tmp_dir
        tmp_dir=$(mktemp -d 2>/dev/null)
        if [ -z "$tmp_dir" ]; then
            echo -e "${gl_hong}错误: 无法创建临时目录用于下载 ARM64 脚本${gl_bai}"
            return 1
        fi

        local script_url="https://jhb.ovh/jb/bbrv3arm.sh"
        local sha256_url="${script_url}.sha256"
        local sha512_url="${script_url}.sha512"
        local script_path="${tmp_dir}/bbrv3arm.sh"
        local sha256_path="${tmp_dir}/bbrv3arm.sh.sha256"
        local sha512_path="${tmp_dir}/bbrv3arm.sh.sha512"

        echo "日志: 正在下载 ARM64 安装脚本到临时目录 ${tmp_dir}"

        if ! curl -fsSL "$script_url" -o "$script_path"; then
            echo -e "${gl_hong}错误: ARM64 安装脚本下载失败${gl_bai}"
            rm -rf "$tmp_dir"
            return 1
        fi

        if ! curl -fsSL "$sha256_url" -o "$sha256_path"; then
            echo -e "${gl_hong}错误: 未能获取发布方提供的 SHA256 校验文件${gl_bai}"
            rm -rf "$tmp_dir"
            return 1
        fi

        if ! curl -fsSL "$sha512_url" -o "$sha512_path"; then
            echo -e "${gl_hong}错误: 未能获取发布方提供的 SHA512 校验文件${gl_bai}"
            rm -rf "$tmp_dir"
            return 1
        fi

        local expected_sha256 expected_sha512 actual_sha256 actual_sha512
        expected_sha256=$(awk 'NR==1 {print $1}' "$sha256_path")
        expected_sha512=$(awk 'NR==1 {print $1}' "$sha512_path")

        if [ -z "$expected_sha256" ] || [ -z "$expected_sha512" ]; then
            echo -e "${gl_hong}错误: 校验文件内容无效${gl_bai}"
            rm -rf "$tmp_dir"
            return 1
        fi

        actual_sha256=$(sha256sum "$script_path" | awk '{print $1}')
        actual_sha512=$(sha512sum "$script_path" | awk '{print $1}')

        if [ "$expected_sha256" != "$actual_sha256" ]; then
            echo -e "${gl_hong}错误: SHA256 校验失败，已中止${gl_bai}"
            rm -rf "$tmp_dir"
            return 1
        fi

        if [ "$expected_sha512" != "$actual_sha512" ]; then
            echo -e "${gl_hong}错误: SHA512 校验失败，已中止${gl_bai}"
            rm -rf "$tmp_dir"
            return 1
        fi

        echo -e "${gl_lv}SHA256 与 SHA512 校验通过${gl_bai}"
        echo -e "${gl_huang}安全提示:${gl_bai} ARM64 脚本已下载至 ${script_path}"
        echo "如需，您可在继续前使用 cat/less 等命令手动审查脚本内容。"
        read -s -r -p "审查完成后按 Enter 继续执行（Ctrl+C 取消）..." _
        echo ""

        if bash "$script_path"; then
            rm -rf "$tmp_dir"
            echo -e "${gl_lv}ARM BBR v3 安装完成${gl_bai}"
            return 0
        else
            echo -e "${gl_hong}安装失败${gl_bai}"
            rm -rf "$tmp_dir"
            return 1
        fi
    fi
    
    # 显式检查 x86_64 架构
    if [ "$cpu_arch" != "x86_64" ]; then
        echo -e "${gl_hong}错误: 不支持的 CPU 架构: ${cpu_arch}${gl_bai}"
        echo "本脚本仅支持 x86_64 和 aarch64 架构"
        return 1
    fi

    # x86_64 架构安装流程
    # 检查系统支持
    if [ -r /etc/os-release ]; then
        . /etc/os-release
        if [ "$ID" != "debian" ] && [ "$ID" != "ubuntu" ]; then
            echo -e "${gl_hong}错误: 仅支持 Debian 和 Ubuntu 系统${gl_bai}"
            return 1
        fi
    else
        echo -e "${gl_hong}错误: 无法确定操作系统类型${gl_bai}"
        return 1
    fi

    # 环境准备
    check_disk_space 3 || return 1
    check_swap
    install_package wget gnupg || { echo -e "${gl_hong}错误: 无法安装必要依赖 wget/gnupg${gl_bai}"; return 1; }

    # 添加 XanMod GPG 密钥（分步执行，避免管道 $? 只检查最后一条命令）
    echo "正在添加 XanMod 仓库密钥..."
    local gpg_key_file="/usr/share/keyrings/xanmod-archive-keyring.gpg"
    local key_tmp=$(mktemp)
    local gpg_ok=false

    # 尝试1: 从镜像源下载
    if wget -qO "$key_tmp" "${gh_proxy}raw.githubusercontent.com/kejilion/sh/main/archive.key" 2>/dev/null && \
       [ -s "$key_tmp" ]; then
        if gpg --dearmor -o "$gpg_key_file" --yes < "$key_tmp" 2>/dev/null; then
            gpg_ok=true
        fi
    fi

    # 尝试2: 从 XanMod 官方源下载
    if [ "$gpg_ok" = false ]; then
        echo -e "${gl_huang}镜像源失败，尝试 XanMod 官方源...${gl_bai}"
        if wget -qO "$key_tmp" "https://dl.xanmod.org/archive.key" 2>/dev/null && \
           [ -s "$key_tmp" ]; then
            if gpg --dearmor -o "$gpg_key_file" --yes < "$key_tmp" 2>/dev/null; then
                gpg_ok=true
            fi
        fi
    fi

    rm -f "$key_tmp"

    if [ "$gpg_ok" = false ]; then
        echo -e "${gl_hong}错误: GPG 密钥导入失败，无法继续安装${gl_bai}"
        echo "请检查网络连接后重试"
        return 1
    fi
    echo -e "${gl_lv}✅ GPG 密钥导入成功${gl_bai}"

    local xanmod_repo_file="/etc/apt/sources.list.d/xanmod-release.list"

    # 添加 XanMod 仓库（使用 HTTPS）
    echo "deb [signed-by=${gpg_key_file}] https://deb.xanmod.org releases main" | \
        tee "$xanmod_repo_file" > /dev/null

    # 检测 CPU 架构版本（使用安全临时目录）
    echo "正在检测 CPU 支持的最优内核版本..."
    local detect_dir=$(mktemp -d)
    local detect_script="${detect_dir}/check_x86-64_psabi.sh"
    local version=""

    if wget -qO "$detect_script" "${gh_proxy}raw.githubusercontent.com/kejilion/sh/main/check_x86-64_psabi.sh" 2>/dev/null && \
       [ -s "$detect_script" ]; then
        chmod +x "$detect_script"
        version=$("$detect_script" 2>/dev/null | sed -nE 's/.*x86-64-v([1-4]).*/\1/p' | head -1)
    fi
    rm -rf "$detect_dir"

    # 验证版本号合法性（只允许 1-4）
    if ! [[ "$version" =~ ^[1-4]$ ]]; then
        echo -e "${gl_huang}自动检测失败或版本不合法，使用默认版本 v3${gl_bai}"
        version="3"
    fi

    echo -e "${gl_lv}将安装: linux-xanmod-x64v${version}${gl_bai}"

    # 安装 XanMod 内核
    echo "正在更新软件包列表..."
    if ! apt-get update; then
        echo -e "${gl_huang}⚠️  apt-get update 部分失败，尝试继续安装...${gl_bai}"
    fi

    apt-get install -y "linux-xanmod-x64v${version}"

    if [ $? -ne 0 ]; then
        echo -e "${gl_hong}内核安装失败！${gl_bai}"
        rm -f "$xanmod_repo_file"
        return 1
    fi

    # 验证内核是否真正安装成功
    if ! dpkg -l 2>/dev/null | grep -qE "^ii\s+linux-xanmod-x64v${version}"; then
        echo -e "${gl_hong}内核包安装验证失败！${gl_bai}"
        rm -f "$xanmod_repo_file"
        return 1
    fi

    echo -e "${gl_lv}XanMod 内核安装成功！${gl_bai}"
    echo -e "${gl_huang}提示: 请先重启系统加载新内核，然后再配置 BBR${gl_bai}"
    echo ""
    echo -e "${gl_kjlan}━━━━━━━━━━ CPU 架构信息 ━━━━━━━━━━${gl_bai}"
    echo -e "  CPU 架构等级: ${gl_lv}x86-64-v${version}${gl_bai}"
    echo -e "  安装内核版本: ${gl_lv}linux-xanmod-x64v${version}${gl_bai}"
    echo -e "  ${gl_huang}说明: 本机 CPU 最高支持 v${version}，已安装该等级的最新内核${gl_bai}"
    echo -e "  ${gl_huang}不同等级(v1-v4)的内核更新进度可能不同，以 XanMod 官方仓库为准${gl_bai}"
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo ""
    echo -e "${gl_kjlan}后续更新: 再次运行选项1即可检查并安装最新内核${gl_bai}"

    rm -f "$xanmod_repo_file"
    echo -e "${gl_lv}已自动清理 XanMod 软件源（如需更新可再次运行选项1）${gl_bai}"

    return 0
}


#=============================================================================
# IP地址获取函数
#=============================================================================

ip_address() {
    local public_ip=""
    local candidate=""
    local external_api_success=false
    local last_curl_status=0
    local external_api_notice=""

    if candidate=$(curl -4 -fsS --max-time 2 https://ipinfo.io/ip 2>/dev/null); then
        candidate=$(echo "$candidate" | tr -d '\r\n')
        if [ -n "$candidate" ]; then
            public_ip="$candidate"
            external_api_success=true
        fi
    else
        last_curl_status=$?
    fi

    if [ "$external_api_success" = false ]; then
        if candidate=$(curl -4 -fsS --max-time 2 https://api.ip.sb/ip 2>/dev/null); then
            candidate=$(echo "$candidate" | tr -d '\r\n')
            if [ -n "$candidate" ]; then
                public_ip="$candidate"
                external_api_success=true
            fi
        else
            last_curl_status=$?
        fi
    fi

    if [ "$external_api_success" = false ]; then
        if candidate=$(curl -4 -fsS --max-time 2 https://ifconfig.me/ip 2>/dev/null); then
            candidate=$(echo "$candidate" | tr -d '\r\n')
            if [ -n "$candidate" ]; then
                public_ip="$candidate"
                external_api_success=true
            fi
        else
            last_curl_status=$?
        fi
    fi

    if [ "$external_api_success" = false ]; then
        public_ip=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for (i=1; i<=NF; i++) if ($i == "src") {print $(i+1); exit}}')
    fi

    if [ -z "$public_ip" ]; then
        public_ip=$(hostname -I 2>/dev/null | awk '{print $1}')
    fi

    if [ -z "$public_ip" ]; then
        public_ip="外部接口不可达"
    fi

    if [ "$external_api_success" = false ]; then
        external_api_notice="外部接口不可达"
        if [ "$last_curl_status" -ne 0 ]; then
            external_api_notice+=" (curl 返回码 $last_curl_status)"
        fi
    fi

    local local_ipv4=""
    local_ipv4=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for (i=1; i<=NF; i++) if ($i == "src") {print $(i+1); exit}}')
    if [ -z "$local_ipv4" ]; then
        local_ipv4=$(hostname -I 2>/dev/null | awk '{print $1}')
    fi
    if [ -z "$local_ipv4" ]; then
        local_ipv4="外部接口不可达"
    fi

    if ! isp_info=$(curl -fsS --max-time 2 http://ipinfo.io/org 2>/dev/null); then
        isp_info=""
    else
        isp_info=$(echo "$isp_info" | tr -d '\r\n')
    fi

    if [ -z "$isp_info" ] && [ -n "$external_api_notice" ]; then
        isp_info="$external_api_notice"
    fi

    if echo "$isp_info" | grep -Eiq 'mobile|unicom|telecom'; then
        ipv4_address="$local_ipv4"
    else
        ipv4_address="$public_ip"
    fi

    if [ -z "$ipv4_address" ]; then
        ipv4_address="$local_ipv4"
    fi

    if ! ipv6_address=$(curl -fsS --max-time 2 https://v6.ipinfo.io/ip 2>/dev/null); then
        ipv6_address=""
    else
        ipv6_address=$(echo "$ipv6_address" | tr -d '\r\n')
    fi

    if [ -n "$external_api_notice" ] && [ -z "$isp_info" ]; then
        isp_info="$external_api_notice"
    fi

    if [ -z "$isp_info" ]; then
        isp_info="未获取到运营商信息"
    fi
}
#=============================================================================
# 网络流量统计函数
#=============================================================================

output_status() {
    output=$(awk 'BEGIN { rx_total = 0; tx_total = 0 }
        $1 ~ /^(eth|ens|enp|eno)[0-9]+/ {
            rx_total += $2
            tx_total += $10
        }
        END {
            rx_units = "Bytes";
            tx_units = "Bytes";
            if (rx_total > 1024) { rx_total /= 1024; rx_units = "K"; }
            if (rx_total > 1024) { rx_total /= 1024; rx_units = "M"; }
            if (rx_total > 1024) { rx_total /= 1024; rx_units = "G"; }

            if (tx_total > 1024) { tx_total /= 1024; tx_units = "K"; }
            if (tx_total > 1024) { tx_total /= 1024; tx_units = "M"; }
            if (tx_total > 1024) { tx_total /= 1024; tx_units = "G"; }

            printf("%.2f%s %.2f%s\n", rx_total, rx_units, tx_total, tx_units);
        }' /proc/net/dev)

    rx=$(echo "$output" | awk '{print $1}')
    tx=$(echo "$output" | awk '{print $2}')
}

#=============================================================================
# 时区获取函数
#=============================================================================

current_timezone() {
    if grep -q 'Alpine' /etc/issue 2>/dev/null; then
        date +"%Z %z"
    else
        timedatectl | grep "Time zone" | awk '{print $3}'
    fi
}

#=============================================================================
# 详细系统信息显示
#=============================================================================

show_detailed_status() {
    clear

    ip_address

    local cpu_info=$(lscpu | awk -F': +' '/Model name:/ {print $2; exit}')

    local cpu_usage_percent=$(awk '{u=$2+$4; t=$2+$4+$5; if (NR==1){u1=u; t1=t;} else printf "%.0f\n", (($2+$4-u1) * 100 / (t-t1))}' \
        <(grep 'cpu ' /proc/stat) <(sleep 1; grep 'cpu ' /proc/stat))

    local cpu_cores=$(nproc)

    local cpu_freq=$(cat /proc/cpuinfo | grep "MHz" | head -n 1 | awk '{printf "%.1f GHz\n", $4/1000}')

    local mem_info=$(free -b | awk 'NR==2{printf "%.2f/%.2fM (%.2f%%)", $3/1024/1024, $2/1024/1024, $3*100/$2}')

    local disk_info=$(df -h | awk '$NF=="/"{printf "%s/%s (%s)", $3, $2, $5}')

    local ipinfo=$(curl -s ipinfo.io)
    local country=$(echo "$ipinfo" | grep 'country' | awk -F': ' '{print $2}' | tr -d '",')
    local city=$(echo "$ipinfo" | grep 'city' | awk -F': ' '{print $2}' | tr -d '",')
    local isp_info=$(echo "$ipinfo" | grep 'org' | awk -F': ' '{print $2}' | tr -d '",')

    local load=$(uptime | awk '{print $(NF-2), $(NF-1), $NF}')
    local dns_addresses=$(awk '/^nameserver/{printf "%s ", $2} END {print ""}' /etc/resolv.conf)

    local cpu_arch=$(uname -m)
    local hostname=$(uname -n)
    local kernel_version=$(uname -r)

    local congestion_algorithm=$(sysctl -n net.ipv4.tcp_congestion_control)
    local queue_algorithm=$(sysctl -n net.core.default_qdisc)

    local os_info=$(grep PRETTY_NAME /etc/os-release | cut -d '=' -f2 | tr -d '"')

    output_status

    local current_time=$(date "+%Y-%m-%d %I:%M %p")

    local swap_info=$(free -m | awk 'NR==3{used=$3; total=$2; if (total == 0) {percentage=0} else {percentage=used*100/total}; printf "%dM/%dM (%d%%)", used, total, percentage}')

    local runtime=$(cat /proc/uptime | awk -F. '{run_days=int($1 / 86400);run_hours=int(($1 % 86400) / 3600);run_minutes=int(($1 % 3600) / 60); if (run_days > 0) printf("%d天 ", run_days); if (run_hours > 0) printf("%d时 ", run_hours); printf("%d分\n", run_minutes)}')

    local timezone=$(current_timezone)

    echo ""
    echo -e "系统信息查询"
    echo -e "${gl_kjlan}-------------"
    echo -e "${gl_kjlan}主机名:       ${gl_bai}$hostname"
    echo -e "${gl_kjlan}系统版本:     ${gl_bai}$os_info"
    echo -e "${gl_kjlan}Linux版本:    ${gl_bai}$kernel_version"
    echo -e "${gl_kjlan}-------------"
    echo -e "${gl_kjlan}CPU架构:      ${gl_bai}$cpu_arch"
    echo -e "${gl_kjlan}CPU型号:      ${gl_bai}$cpu_info"
    echo -e "${gl_kjlan}CPU核心数:    ${gl_bai}$cpu_cores"
    echo -e "${gl_kjlan}CPU频率:      ${gl_bai}$cpu_freq"
    echo -e "${gl_kjlan}-------------"
    echo -e "${gl_kjlan}CPU占用:      ${gl_bai}$cpu_usage_percent%"
    echo -e "${gl_kjlan}系统负载:     ${gl_bai}$load"
    echo -e "${gl_kjlan}物理内存:     ${gl_bai}$mem_info"
    echo -e "${gl_kjlan}虚拟内存:     ${gl_bai}$swap_info"
    echo -e "${gl_kjlan}硬盘占用:     ${gl_bai}$disk_info"
    echo -e "${gl_kjlan}-------------"
    echo -e "${gl_kjlan}总接收:       ${gl_bai}$rx"
    echo -e "${gl_kjlan}总发送:       ${gl_bai}$tx"
    echo -e "${gl_kjlan}-------------"
    echo -e "${gl_kjlan}网络算法:     ${gl_bai}$congestion_algorithm $queue_algorithm"
    echo -e "${gl_kjlan}-------------"
    echo -e "${gl_kjlan}运营商:       ${gl_bai}$isp_info"
    if [ -n "$ipv4_address" ]; then
        echo -e "${gl_kjlan}IPv4地址:     ${gl_bai}$ipv4_address"
    fi

    if [ -n "$ipv6_address" ]; then
        echo -e "${gl_kjlan}IPv6地址:     ${gl_bai}$ipv6_address"
    fi
    echo -e "${gl_kjlan}DNS地址:      ${gl_bai}$dns_addresses"
    echo -e "${gl_kjlan}地理位置:     ${gl_bai}$country $city"
    echo -e "${gl_kjlan}系统时间:     ${gl_bai}$timezone $current_time"
    echo -e "${gl_kjlan}-------------"
    echo -e "${gl_kjlan}运行时长:     ${gl_bai}$runtime"
    echo

    break_end
}

#=============================================================================
# 内核参数优化 - 星辰大海ヾ优化模式（VLESS Reality 专用）
#=============================================================================

optimize_xinchendahai() {
    echo -e "${gl_lv}切换到星辰大海ヾ优化模式...${gl_bai}"
    echo -e "${gl_zi}针对 VLESS Reality 节点深度优化${gl_bai}"
    echo ""
    echo -e "${gl_hong}⚠️  重要提示 ⚠️${gl_bai}"
    echo -e "${gl_huang}本配置为临时生效（使用 sysctl -w 命令）${gl_bai}"
    echo -e "${gl_huang}重启后将恢复到永久配置文件的设置${gl_bai}"
    echo ""
    echo "如果你之前执行过："
    echo "  - CAKE调优 / Debian12调优 / BBR直连优化"
    echo "重启后会恢复到那些配置，本次优化会消失！"
    echo ""
    read -e -p "是否继续？(Y/N) [Y]: " confirm
    confirm=${confirm:-Y}
    if [[ "$confirm" =~ ^[Nn]$ ]]; then
        echo "已取消"
        return
    fi
    echo ""

    # 文件描述符优化
    echo -e "${gl_lv}优化文件描述符...${gl_bai}"
    ulimit -n 131072
    echo "  ✓ 文件描述符: 131072 (13万)"

    # 内存管理优化
    echo -e "${gl_lv}优化内存管理...${gl_bai}"
    sysctl -w vm.swappiness=5 2>/dev/null
    echo "  ✓ swappiness = 5 （安全值）"
    sysctl -w vm.dirty_ratio=15 2>/dev/null
    echo "  ✓ dirty_ratio = 15"
    sysctl -w vm.dirty_background_ratio=5 2>/dev/null
    echo "  ✓ dirty_background_ratio = 5"
    sysctl -w vm.overcommit_memory=1 2>/dev/null
    echo "  ✓ overcommit_memory = 1"

    # TCP拥塞控制（保持用户的队列算法，不覆盖CAKE）
    echo -e "${gl_lv}优化TCP拥塞控制...${gl_bai}"
    sysctl -w net.ipv4.tcp_congestion_control=bbr 2>/dev/null
    echo "  ✓ tcp_congestion_control = bbr"
    current_qdisc=$(sysctl -n net.core.default_qdisc 2>/dev/null)
    if [ "$current_qdisc" = "cake" ]; then
        echo "  ✓ default_qdisc = cake （保持用户设置）"
    else
        echo "  ℹ default_qdisc = $current_qdisc （保持不变）"
    fi

    # TCP连接优化（TLS握手加速）
    echo -e "${gl_lv}优化TCP连接（TLS握手加速）...${gl_bai}"
    sysctl -w net.ipv4.tcp_fastopen=3 2>/dev/null
    echo "  ✓ tcp_fastopen = 3"
    sysctl -w net.ipv4.tcp_slow_start_after_idle=0 2>/dev/null
    echo "  ✓ tcp_slow_start_after_idle = 0 （关键优化）"
    sysctl -w net.ipv4.tcp_tw_reuse=1 2>/dev/null
    echo "  ✓ tcp_tw_reuse = 1"
    sysctl -w net.ipv4.tcp_fin_timeout=30 2>/dev/null
    echo "  ✓ tcp_fin_timeout = 30"
    sysctl -w net.ipv4.tcp_max_syn_backlog=8192 2>/dev/null
    echo "  ✓ tcp_max_syn_backlog = 8192"

    # TCP保活设置
    echo -e "${gl_lv}优化TCP保活...${gl_bai}"
    sysctl -w net.ipv4.tcp_keepalive_time=600 2>/dev/null
    echo "  ✓ tcp_keepalive_time = 600s (10分钟)"
    sysctl -w net.ipv4.tcp_keepalive_intvl=30 2>/dev/null
    echo "  ✓ tcp_keepalive_intvl = 30s"
    sysctl -w net.ipv4.tcp_keepalive_probes=5 2>/dev/null
    echo "  ✓ tcp_keepalive_probes = 5"

    # TCP缓冲区优化（16MB）
    echo -e "${gl_lv}优化TCP缓冲区（16MB）...${gl_bai}"
    sysctl -w net.core.rmem_max=16777216 2>/dev/null
    echo "  ✓ rmem_max = 16MB"
    sysctl -w net.core.wmem_max=16777216 2>/dev/null
    echo "  ✓ wmem_max = 16MB"
    sysctl -w net.ipv4.tcp_rmem='4096 87380 16777216' 2>/dev/null
    echo "  ✓ tcp_rmem = 4K 85K 16MB"
    sysctl -w net.ipv4.tcp_wmem='4096 65536 16777216' 2>/dev/null
    echo "  ✓ tcp_wmem = 4K 64K 16MB"

    # UDP优化（QUIC支持）
    echo -e "${gl_lv}优化UDP（QUIC支持）...${gl_bai}"
    sysctl -w net.ipv4.udp_rmem_min=8192 2>/dev/null
    echo "  ✓ udp_rmem_min = 8192"
    sysctl -w net.ipv4.udp_wmem_min=8192 2>/dev/null
    echo "  ✓ udp_wmem_min = 8192"

    # 连接队列优化
    echo -e "${gl_lv}优化连接队列...${gl_bai}"
    sysctl -w net.core.somaxconn=4096 2>/dev/null
    echo "  ✓ somaxconn = 4096"
    sysctl -w net.core.netdev_max_backlog=5000 2>/dev/null
    echo "  ✓ netdev_max_backlog = 5000 （修正过高值）"
    sysctl -w net.ipv4.ip_local_port_range='1024 65535' 2>/dev/null
    echo "  ✓ ip_local_port_range = 1024-65535"

    echo ""
    echo -e "${gl_lv}星辰大海ヾ优化模式设置完成！${gl_bai}"
    echo -e "${gl_zi}配置特点: TLS握手加速 + QUIC支持 + 大并发优化 + CAKE兼容${gl_bai}"
    echo -e "${gl_huang}优化说明: 已修正过激参数，保持用户CAKE设置，适配≥2GB内存${gl_bai}"
}

#=============================================================================
# 内核参数优化 - Reality终极优化（方案E）
#=============================================================================

optimize_reality_ultimate() {
    echo -e "${gl_lv}切换到Reality终极优化模式...${gl_bai}"
    echo -e "${gl_zi}基于星辰大海深度改进，性能提升5-10%，资源消耗降低25%${gl_bai}"
    echo ""
    echo -e "${gl_hong}⚠️  重要提示 ⚠️${gl_bai}"
    echo -e "${gl_huang}本配置为临时生效（使用 sysctl -w 命令）${gl_bai}"
    echo -e "${gl_huang}重启后将恢复到永久配置文件的设置${gl_bai}"
    echo ""
    echo "如果你之前执行过："
    echo "  - CAKE调优 / Debian12调优 / BBR直连优化"
    echo "重启后会恢复到那些配置，本次优化会消失！"
    echo ""
    read -e -p "是否继续？(Y/N) [Y]: " confirm
    confirm=${confirm:-Y}
    if [[ "$confirm" =~ ^[Nn]$ ]]; then
        echo "已取消"
        return
    fi
    echo ""

    # 文件描述符优化
    echo -e "${gl_lv}优化文件描述符...${gl_bai}"
    ulimit -n 524288
    echo "  ✓ 文件描述符: 524288 (50万)"

    # TCP拥塞控制（核心）
    echo -e "${gl_lv}优化TCP拥塞控制...${gl_bai}"
    sysctl -w net.ipv4.tcp_congestion_control=bbr 2>/dev/null
    echo "  ✓ tcp_congestion_control = bbr"
    current_qdisc=$(sysctl -n net.core.default_qdisc 2>/dev/null)
    if [ "$current_qdisc" = "cake" ]; then
        echo "  ✓ default_qdisc = cake （保持用户设置）"
    else
        echo "  ℹ default_qdisc = $current_qdisc （保持不变）"
    fi

    # TCP连接优化（TLS握手加速）
    echo -e "${gl_lv}优化TCP连接（TLS握手加速）...${gl_bai}"
    sysctl -w net.ipv4.tcp_fastopen=3 2>/dev/null
    echo "  ✓ tcp_fastopen = 3"
    sysctl -w net.ipv4.tcp_slow_start_after_idle=0 2>/dev/null
    echo "  ✓ tcp_slow_start_after_idle = 0 （关键优化）"
    sysctl -w net.ipv4.tcp_tw_reuse=1 2>/dev/null
    echo "  ✓ tcp_tw_reuse = 1"
    sysctl -w net.ipv4.ip_local_port_range='1024 65535' 2>/dev/null
    echo "  ✓ ip_local_port_range = 1024-65535"

    # Reality特有优化（方案E核心亮点）
    echo -e "${gl_lv}Reality特有优化...${gl_bai}"
    sysctl -w net.ipv4.tcp_notsent_lowat=16384 2>/dev/null
    echo "  ✓ tcp_notsent_lowat = 16384 （减少延迟）"
    sysctl -w net.ipv4.tcp_fin_timeout=15 2>/dev/null
    echo "  ✓ tcp_fin_timeout = 15 （快速回收）"
    sysctl -w net.ipv4.tcp_max_tw_buckets=5000 2>/dev/null
    echo "  ✓ tcp_max_tw_buckets = 5000"

    # TCP缓冲区（12MB平衡配置）
    echo -e "${gl_lv}优化TCP缓冲区（12MB）...${gl_bai}"
    sysctl -w net.core.rmem_max=12582912 2>/dev/null
    echo "  ✓ rmem_max = 12MB"
    sysctl -w net.core.wmem_max=12582912 2>/dev/null
    echo "  ✓ wmem_max = 12MB"
    sysctl -w net.ipv4.tcp_rmem='4096 87380 12582912' 2>/dev/null
    echo "  ✓ tcp_rmem = 4K 85K 12MB"
    sysctl -w net.ipv4.tcp_wmem='4096 65536 12582912' 2>/dev/null
    echo "  ✓ tcp_wmem = 4K 64K 12MB"

    # 内存管理
    echo -e "${gl_lv}优化内存管理...${gl_bai}"
    sysctl -w vm.swappiness=5 2>/dev/null
    echo "  ✓ swappiness = 5"
    sysctl -w vm.dirty_ratio=15 2>/dev/null
    echo "  ✓ dirty_ratio = 15"
    sysctl -w vm.dirty_background_ratio=5 2>/dev/null
    echo "  ✓ dirty_background_ratio = 5"
    sysctl -w vm.overcommit_memory=1 2>/dev/null
    echo "  ✓ overcommit_memory = 1"
    sysctl -w vm.vfs_cache_pressure=50 2>/dev/null
    echo "  ✓ vfs_cache_pressure = 50"

    # 连接保活（更短的检测周期）
    echo -e "${gl_lv}优化连接保活...${gl_bai}"
    sysctl -w net.ipv4.tcp_keepalive_time=300 2>/dev/null
    echo "  ✓ tcp_keepalive_time = 300s (5分钟)"
    sysctl -w net.ipv4.tcp_keepalive_intvl=30 2>/dev/null
    echo "  ✓ tcp_keepalive_intvl = 30s"
    sysctl -w net.ipv4.tcp_keepalive_probes=5 2>/dev/null
    echo "  ✓ tcp_keepalive_probes = 5"

    # UDP/QUIC优化
    echo -e "${gl_lv}优化UDP（QUIC支持）...${gl_bai}"
    sysctl -w net.ipv4.udp_rmem_min=8192 2>/dev/null
    echo "  ✓ udp_rmem_min = 8192"
    sysctl -w net.ipv4.udp_wmem_min=8192 2>/dev/null
    echo "  ✓ udp_wmem_min = 8192"

    # 连接队列优化（科学配置）
    echo -e "${gl_lv}优化连接队列...${gl_bai}"
    sysctl -w net.core.somaxconn=4096 2>/dev/null
    echo "  ✓ somaxconn = 4096"
    sysctl -w net.ipv4.tcp_max_syn_backlog=8192 2>/dev/null
    echo "  ✓ tcp_max_syn_backlog = 8192"
    sysctl -w net.core.netdev_max_backlog=5000 2>/dev/null
    echo "  ✓ netdev_max_backlog = 5000 （科学值）"

    # TCP安全
    echo -e "${gl_lv}TCP安全增强...${gl_bai}"
    sysctl -w net.ipv4.tcp_syncookies=1 2>/dev/null
    echo "  ✓ tcp_syncookies = 1"
    sysctl -w net.ipv4.tcp_mtu_probing=1 2>/dev/null
    echo "  ✓ tcp_mtu_probing = 1"

    echo ""
    echo -e "${gl_lv}Reality终极优化完成！${gl_bai}"
    echo -e "${gl_zi}配置特点: 性能提升5-10% + 资源消耗降低25% + 更科学的参数配置${gl_bai}"
    echo -e "${gl_huang}预期效果: 比星辰大海更平衡，适配性更强（≥2GB内存即可）${gl_bai}"
}

#=============================================================================
# 内核参数优化 - 低配优化（1GB内存专用）
#=============================================================================

optimize_low_spec() {
    echo -e "${gl_lv}切换到低配优化模式...${gl_bai}"
    echo -e "${gl_zi}专为512MB-1GB内存VPS设计，安全稳定${gl_bai}"
    echo ""
    echo -e "${gl_hong}⚠️  重要提示 ⚠️${gl_bai}"
    echo -e "${gl_huang}本配置为临时生效（使用 sysctl -w 命令）${gl_bai}"
    echo -e "${gl_huang}重启后将恢复到永久配置文件的设置${gl_bai}"
    echo ""
    echo "如果你之前执行过："
    echo "  - CAKE调优 / Debian12调优 / BBR直连优化"
    echo "重启后会恢复到那些配置，本次优化会消失！"
    echo ""
    read -e -p "是否继续？(Y/N) [Y]: " confirm
    confirm=${confirm:-Y}
    if [[ "$confirm" =~ ^[Nn]$ ]]; then
        echo "已取消"
        return
    fi
    echo ""

    # 文件描述符优化（适度）
    echo -e "${gl_lv}优化文件描述符...${gl_bai}"
    ulimit -n 65535
    echo "  ✓ 文件描述符: 65535 (6.5万)"

    # TCP拥塞控制（核心）
    echo -e "${gl_lv}优化TCP拥塞控制...${gl_bai}"
    sysctl -w net.ipv4.tcp_congestion_control=bbr 2>/dev/null
    echo "  ✓ tcp_congestion_control = bbr"
    current_qdisc=$(sysctl -n net.core.default_qdisc 2>/dev/null)
    if [ "$current_qdisc" = "cake" ]; then
        echo "  ✓ default_qdisc = cake （保持用户设置）"
    else
        echo "  ℹ default_qdisc = $current_qdisc （保持不变）"
    fi

    # TCP连接优化（核心功能）
    echo -e "${gl_lv}优化TCP连接...${gl_bai}"
    sysctl -w net.ipv4.tcp_fastopen=3 2>/dev/null
    echo "  ✓ tcp_fastopen = 3"
    sysctl -w net.ipv4.tcp_slow_start_after_idle=0 2>/dev/null
    echo "  ✓ tcp_slow_start_after_idle = 0 （关键优化）"
    sysctl -w net.ipv4.tcp_tw_reuse=1 2>/dev/null
    echo "  ✓ tcp_tw_reuse = 1"
    sysctl -w net.ipv4.ip_local_port_range='1024 65535' 2>/dev/null
    echo "  ✓ ip_local_port_range = 1024-65535"

    # TCP缓冲区（8MB保守配置）
    echo -e "${gl_lv}优化TCP缓冲区（8MB保守配置）...${gl_bai}"
    sysctl -w net.core.rmem_max=8388608 2>/dev/null
    echo "  ✓ rmem_max = 8MB"
    sysctl -w net.core.wmem_max=8388608 2>/dev/null
    echo "  ✓ wmem_max = 8MB"
    sysctl -w net.ipv4.tcp_rmem='4096 87380 8388608' 2>/dev/null
    echo "  ✓ tcp_rmem = 4K 85K 8MB"
    sysctl -w net.ipv4.tcp_wmem='4096 65536 8388608' 2>/dev/null
    echo "  ✓ tcp_wmem = 4K 64K 8MB"

    # 内存管理（保守安全）
    echo -e "${gl_lv}优化内存管理...${gl_bai}"
    sysctl -w vm.swappiness=10 2>/dev/null
    echo "  ✓ swappiness = 10 （安全值）"
    sysctl -w vm.dirty_ratio=20 2>/dev/null
    echo "  ✓ dirty_ratio = 20"
    sysctl -w vm.dirty_background_ratio=10 2>/dev/null
    echo "  ✓ dirty_background_ratio = 10"

    # 连接队列（适度配置）
    echo -e "${gl_lv}优化连接队列...${gl_bai}"
    sysctl -w net.core.somaxconn=2048 2>/dev/null
    echo "  ✓ somaxconn = 2048"
    sysctl -w net.ipv4.tcp_max_syn_backlog=4096 2>/dev/null
    echo "  ✓ tcp_max_syn_backlog = 4096"
    sysctl -w net.core.netdev_max_backlog=2500 2>/dev/null
    echo "  ✓ netdev_max_backlog = 2500"

    # TCP安全
    echo -e "${gl_lv}TCP安全增强...${gl_bai}"
    sysctl -w net.ipv4.tcp_syncookies=1 2>/dev/null
    echo "  ✓ tcp_syncookies = 1"

    echo ""
    echo -e "${gl_lv}低配优化完成！${gl_bai}"
    echo -e "${gl_zi}配置特点: 核心优化保留 + 资源消耗最低 + 稳定性最高${gl_bai}"
    echo -e "${gl_huang}适用场景: 512MB-1GB内存VPS，性能提升15-25%${gl_bai}"
}

#=============================================================================
# 内核参数优化 - 星辰大海原始版（用于对比测试）
#=============================================================================

optimize_xinchendahai_original() {
    echo -e "${gl_lv}切换到星辰大海ヾ原始版模式...${gl_bai}"
    echo -e "${gl_zi}针对 VLESS Reality 节点深度优化（原始参数）${gl_bai}"
    echo ""
    echo -e "${gl_hong}⚠️  重要提示 ⚠️${gl_bai}"
    echo -e "${gl_huang}本配置为临时生效（使用 sysctl -w 命令）${gl_bai}"
    echo -e "${gl_huang}重启后将恢复到永久配置文件的设置${gl_bai}"
    echo ""
    echo "如果你之前执行过："
    echo "  - CAKE调优 / Debian12调优 / BBR直连优化"
    echo "重启后会恢复到那些配置，本次优化会消失！"
    echo ""
    read -e -p "是否继续？(Y/N) [Y]: " confirm
    confirm=${confirm:-Y}
    if [[ "$confirm" =~ ^[Nn]$ ]]; then
        echo "已取消"
        return
    fi
    echo ""

    echo -e "${gl_lv}优化文件描述符...${gl_bai}"
    ulimit -n 1048576
    echo "  ✓ 文件描述符: 1048576 (100万)"

    echo -e "${gl_lv}优化内存管理...${gl_bai}"
    sysctl -w vm.swappiness=1 2>/dev/null
    echo "  ✓ vm.swappiness = 1"
    sysctl -w vm.dirty_ratio=15 2>/dev/null
    echo "  ✓ vm.dirty_ratio = 15"
    sysctl -w vm.dirty_background_ratio=5 2>/dev/null
    echo "  ✓ vm.dirty_background_ratio = 5"
    sysctl -w vm.overcommit_memory=1 2>/dev/null
    echo "  ✓ vm.overcommit_memory = 1"
    sysctl -w vm.min_free_kbytes=65536 2>/dev/null
    echo "  ✓ vm.min_free_kbytes = 65536"
    sysctl -w vm.vfs_cache_pressure=50 2>/dev/null
    echo "  ✓ vm.vfs_cache_pressure = 50"

    echo -e "${gl_lv}优化TCP拥塞控制...${gl_bai}"
    sysctl -w net.ipv4.tcp_congestion_control=bbr 2>/dev/null
    echo "  ✓ net.ipv4.tcp_congestion_control = bbr"
    
    # 智能检测当前 qdisc，如果是 cake 则保持，否则设为 fq
    current_qdisc=$(sysctl -n net.core.default_qdisc 2>/dev/null || echo "fq")
    if [ "$current_qdisc" = "cake" ]; then
        echo "  ✓ net.core.default_qdisc = cake (保持当前设置)"
    else
        sysctl -w net.core.default_qdisc=fq 2>/dev/null
        echo "  ✓ net.core.default_qdisc = fq"
    fi

    echo -e "${gl_lv}优化TCP连接（TLS握手加速）...${gl_bai}"
    sysctl -w net.ipv4.tcp_fastopen=3 2>/dev/null
    echo "  ✓ net.ipv4.tcp_fastopen = 3"
    sysctl -w net.ipv4.tcp_fin_timeout=30 2>/dev/null
    echo "  ✓ net.ipv4.tcp_fin_timeout = 30"
    sysctl -w net.ipv4.tcp_max_syn_backlog=8192 2>/dev/null
    echo "  ✓ net.ipv4.tcp_max_syn_backlog = 8192"
    sysctl -w net.ipv4.tcp_tw_reuse=1 2>/dev/null
    echo "  ✓ net.ipv4.tcp_tw_reuse = 1"
    sysctl -w net.ipv4.tcp_slow_start_after_idle=0 2>/dev/null
    echo "  ✓ net.ipv4.tcp_slow_start_after_idle = 0"
    sysctl -w net.ipv4.tcp_mtu_probing=2 2>/dev/null
    echo "  ✓ net.ipv4.tcp_mtu_probing = 2"
    sysctl -w net.ipv4.tcp_window_scaling=1 2>/dev/null
    echo "  ✓ net.ipv4.tcp_window_scaling = 1"
    sysctl -w net.ipv4.tcp_timestamps=1 2>/dev/null
    echo "  ✓ net.ipv4.tcp_timestamps = 1"

    echo -e "${gl_lv}优化TCP安全/稳态...${gl_bai}"
    sysctl -w net.ipv4.tcp_syncookies=1 2>/dev/null
    echo "  ✓ net.ipv4.tcp_syncookies = 1"
    sysctl -w net.ipv4.tcp_keepalive_time=600 2>/dev/null
    echo "  ✓ net.ipv4.tcp_keepalive_time = 600"
    sysctl -w net.ipv4.tcp_keepalive_intvl=30 2>/dev/null
    echo "  ✓ net.ipv4.tcp_keepalive_intvl = 30"
    sysctl -w net.ipv4.tcp_keepalive_probes=5 2>/dev/null
    echo "  ✓ net.ipv4.tcp_keepalive_probes = 5"

    echo -e "${gl_lv}优化TCP缓冲区...${gl_bai}"
    sysctl -w net.core.rmem_max=16777216 2>/dev/null
    echo "  ✓ net.core.rmem_max = 16777216"
    sysctl -w net.core.wmem_max=16777216 2>/dev/null
    echo "  ✓ net.core.wmem_max = 16777216"
    sysctl -w net.core.rmem_default=262144 2>/dev/null
    echo "  ✓ net.core.rmem_default = 262144"
    sysctl -w net.core.wmem_default=262144 2>/dev/null
    echo "  ✓ net.core.wmem_default = 262144"
    sysctl -w net.ipv4.tcp_rmem='4096 87380 16777216' 2>/dev/null
    echo "  ✓ net.ipv4.tcp_rmem = 4096 87380 16777216"
    sysctl -w net.ipv4.tcp_wmem='4096 65536 16777216' 2>/dev/null
    echo "  ✓ net.ipv4.tcp_wmem = 4096 65536 16777216"

    echo -e "${gl_lv}优化UDP（QUIC支持）...${gl_bai}"
    sysctl -w net.ipv4.udp_rmem_min=8192 2>/dev/null
    echo "  ✓ net.ipv4.udp_rmem_min = 8192"
    sysctl -w net.ipv4.udp_wmem_min=8192 2>/dev/null
    echo "  ✓ net.ipv4.udp_wmem_min = 8192"

    echo -e "${gl_lv}优化连接队列...${gl_bai}"
    sysctl -w net.core.somaxconn=4096 2>/dev/null
    echo "  ✓ net.core.somaxconn = 4096"
    sysctl -w net.core.netdev_max_backlog=250000 2>/dev/null
    echo "  ✓ net.core.netdev_max_backlog = 250000"
    sysctl -w net.ipv4.ip_local_port_range='1024 65535' 2>/dev/null
    echo "  ✓ net.ipv4.ip_local_port_range = 1024 65535"

    echo -e "${gl_lv}优化CPU设置...${gl_bai}"
    sysctl -w kernel.sched_autogroup_enabled=0 2>/dev/null
    echo "  ✓ kernel.sched_autogroup_enabled = 0"
    sysctl -w kernel.numa_balancing=0 2>/dev/null
    echo "  ✓ kernel.numa_balancing = 0"

    echo -e "${gl_lv}其他优化...${gl_bai}"
    echo never > /sys/kernel/mm/transparent_hugepage/enabled 2>/dev/null
    echo "  ✓ transparent_hugepage = never"

    echo ""
    echo -e "${gl_lv}星辰大海ヾ原始版优化模式设置完成！${gl_bai}"
    echo -e "${gl_zi}配置特点: TLS握手加速 + QUIC支持 + 大并发优化${gl_bai}"
    echo -e "${gl_huang}注意: 这是原始参数版本，用于对比测试，建议≥4GB内存使用${gl_bai}"
}

#=============================================================================
# DNS净化与安全加固功能（NS论坛）- SSH安全增强版
#=============================================================================

# DNS净化 - 智能检测并修复 systemd-resolved
dns_purify_fix_systemd_resolved() {
    echo -e "${gl_kjlan}正在检测 systemd-resolved 服务状态...${gl_bai}"

    # 检查服务是否已启用且正在运行
    if systemctl is-enabled systemd-resolved &> /dev/null; then
        if systemctl is-active --quiet systemd-resolved; then
            echo -e "${gl_lv}✅ systemd-resolved 服务已启用且运行中${gl_bai}"
            return 0
        else
            # 已启用但未运行（可能 crash 或被手动停止）
            echo -e "${gl_huang}systemd-resolved 已启用但未运行，正在启动...${gl_bai}"
            systemctl start systemd-resolved 2>/dev/null || true
            sleep 2
            if systemctl is-active --quiet systemd-resolved; then
                echo -e "${gl_lv}✅ systemd-resolved 服务已成功启动${gl_bai}"
                return 0
            else
                echo -e "${gl_hong}启动失败，尝试重新启用...${gl_bai}"
                systemctl restart systemd-resolved 2>/dev/null || true
                sleep 2
                if systemctl is-active --quiet systemd-resolved; then
                    echo -e "${gl_lv}✅ systemd-resolved 服务已重启成功${gl_bai}"
                    return 0
                else
                    echo -e "${gl_hong}服务无法启动${gl_bai}"
                    systemctl status systemd-resolved --no-pager || true
                    return 1
                fi
            fi
        fi
    fi

    # 检查是否被 masked
    if systemctl status systemd-resolved 2>&1 | grep -q "masked"; then
        echo -e "${gl_huang}检测到 systemd-resolved 被屏蔽 (masked)，正在修复...${gl_bai}"

        # 解除屏蔽
        if systemctl unmask systemd-resolved 2>/dev/null; then
            echo -e "${gl_lv}✅ 已成功解除 systemd-resolved 的屏蔽状态${gl_bai}"
        else
            echo -e "${gl_hong}解除屏蔽失败，尝试手动修复...${gl_bai}"
            # 手动删除屏蔽链接
            rm -f /etc/systemd/system/systemd-resolved.service 2>/dev/null || true
            systemctl daemon-reload
            echo -e "${gl_lv}✅ 已手动移除屏蔽链接${gl_bai}"
        fi

        # 启用服务
        if systemctl enable systemd-resolved 2>/dev/null; then
            echo -e "${gl_lv}✅ 已启用 systemd-resolved 服务${gl_bai}"
        else
            echo -e "${gl_hong}启用服务失败${gl_bai}"
            return 1
        fi

        # 启动服务
        if systemctl start systemd-resolved 2>/dev/null; then
            echo -e "${gl_lv}✅ 已启动 systemd-resolved 服务${gl_bai}"
        else
            echo -e "${gl_hong}启动服务失败${gl_bai}"
            return 1
        fi

        # 等待服务完全启动
        sleep 2

        # 验证服务状态
        if systemctl is-active --quiet systemd-resolved; then
            echo -e "${gl_lv}✅ systemd-resolved 服务运行正常${gl_bai}"
            return 0
        else
            echo -e "${gl_hong}服务启动后状态异常${gl_bai}"
            systemctl status systemd-resolved --no-pager || true
            return 1
        fi
    else
        echo -e "${gl_huang}systemd-resolved 未启用，正在启用...${gl_bai}"
        systemctl enable systemd-resolved 2>/dev/null || true
        systemctl start systemd-resolved 2>/dev/null || true

        # 等待服务启动并验证
        sleep 2
        if systemctl is-active --quiet systemd-resolved; then
            echo -e "${gl_lv}✅ systemd-resolved 服务已启用并运行${gl_bai}"
            return 0
        else
            echo -e "${gl_hong}systemd-resolved 启动失败${gl_bai}"
            systemctl status systemd-resolved --no-pager || true
            return 1
        fi
    fi
}

# DNS净化 - 主执行函数（SSH安全版）
dns_purify_and_harden() {
    clear
    echo -e "${gl_kjlan}╔════════════════════════════════════════════════════════════╗${gl_bai}"
    echo -e "${gl_kjlan}║    DNS净化与安全加固脚本 - SSH安全增强版 v2.0             ║${gl_bai}"
    echo -e "${gl_kjlan}╚════════════════════════════════════════════════════════════╝${gl_bai}"
    echo ""

    # ==================== SSH安全检测 ====================
    local IS_SSH=false
    if [ -n "$SSH_CLIENT" ] || [ -n "$SSH_TTY" ]; then
        IS_SSH=true
        echo -e "${gl_hong}⚠️  检测到您正在通过SSH连接${gl_bai}"
        echo -e "${gl_lv}✅ SSH安全模式已启用：本脚本不会中断您的网络连接${gl_bai}"
        echo ""
    fi

    echo -e "${gl_kjlan}功能说明：${gl_bai}"
    echo "  ✓ 配置安全的DNS服务器（支持国外/国内模式）"
    echo "  ✓ 防止DHCP覆盖DNS配置"
    echo "  ✓ 清除厂商残留的DNS配置"
    echo "  ✓ 启用DNS安全功能（DNSSEC + DNS over TLS）"
    echo ""

    if [ "$IS_SSH" = true ]; then
        echo -e "${gl_lv}SSH安全保证：${gl_bai}"
        echo "  ✓ 不会停止或重启网络服务"
        echo "  ✓ 不会中断SSH连接"
        echo "  ✓ 所有配置立即生效，无需重启"
        echo "  ✓ 提供完整的回滚机制"
        echo ""
    fi

    # ==================== 已有配置检测 ====================
    local dns_has_config=false
    local dns_is_legacy=false
    local dns_all_healthy=true
    local current_mode_name=""
    local svc_file="/etc/systemd/system/dns-purify-persist.service"

    # 第一步：检测是否存在 DNS 净化配置（不管健不健康）
    if systemctl is-enabled --quiet dns-purify-persist.service 2>/dev/null \
       || [ -f "$svc_file" ] \
       || [ -x /usr/local/bin/dns-purify-apply.sh ]; then
        dns_has_config=true
    fi

    # 第二步：如果存在配置，立即检查是新版还是老版（独立于DNS健康状态）
    if [ "$dns_has_config" = true ]; then
        # 老版特征1: 服务文件用 Requires 而非 Wants
        if [ -f "$svc_file" ] && grep -q "Requires=systemd-resolved" "$svc_file" 2>/dev/null; then
            dns_is_legacy=true
        fi
        # 老版特征2: 持久化脚本缺少 resolvectl 可用性检查
        if [ -x /usr/local/bin/dns-purify-apply.sh ] && ! grep -q "command -v resolvectl" /usr/local/bin/dns-purify-apply.sh 2>/dev/null; then
            dns_is_legacy=true
        fi
    fi

    # 第三步：健康检查（仅在有配置时执行）
    if [ "$dns_has_config" = true ]; then
        # 持久化服务已启用？
        if ! systemctl is-enabled --quiet dns-purify-persist.service 2>/dev/null; then
            dns_all_healthy=false
        fi
        # 持久化脚本存在？
        if [ ! -x /usr/local/bin/dns-purify-apply.sh ]; then
            dns_all_healthy=false
        fi
        # resolved 运行中？
        if ! systemctl is-active --quiet systemd-resolved 2>/dev/null; then
            dns_all_healthy=false
        fi
        # resolv.conf 指向 stub？
        if [ ! -L /etc/resolv.conf ] || [[ "$(readlink /etc/resolv.conf 2>/dev/null)" != *"stub-resolv.conf"* ]]; then
            dns_all_healthy=false
        fi
        # DNS 解析正常？
        if [ "$dns_all_healthy" = true ]; then
            local dns_resolve_ok=false
            if command -v getent >/dev/null 2>&1; then
                if getent hosts google.com >/dev/null 2>&1 || getent hosts baidu.com >/dev/null 2>&1; then
                    dns_resolve_ok=true
                fi
            fi
            if [ "$dns_resolve_ok" = false ]; then
                dns_all_healthy=false
            fi
        fi
    fi

    # 检测当前模式
    if [ "$dns_has_config" = true ] && [ -f /etc/systemd/resolved.conf ]; then
        local cur_dot
        cur_dot=$(sed -nE 's/^DNSOverTLS=(.+)/\1/p' /etc/systemd/resolved.conf 2>/dev/null)
        case "$cur_dot" in
            yes)           current_mode_name="纯国外模式（强制DoT）" ;;
            no)            current_mode_name="纯国内模式" ;;
            opportunistic) current_mode_name="混合模式（机会性DoT）" ;;
        esac
    fi

    # ==================== 显示检测结果 ====================
    if [ "$dns_has_config" = true ] && [ "$dns_is_legacy" = true ]; then
        # 老版配置（不管DNS当前是否健康，都必须警告）
        echo -e "${gl_hong}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
        echo -e "${gl_hong}  ⚠️  检测到老版 DNS 净化配置，重启后可能导致 DNS 失效！${gl_bai}"
        echo -e "${gl_hong}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
        echo ""
        [ -n "$current_mode_name" ] && echo -e "  当前模式:    ${gl_huang}${current_mode_name}${gl_bai}"
        if systemctl is-active --quiet systemd-resolved 2>/dev/null; then
            echo -e "  resolved:    ${gl_lv}✅ 运行中${gl_bai}"
        else
            echo -e "  resolved:    ${gl_hong}❌ 未运行${gl_bai}"
        fi
        if [ "$dns_all_healthy" = true ]; then
            echo -e "  DNS 解析:    ${gl_lv}✅ 当前正常${gl_bai}"
        else
            echo -e "  DNS 解析:    ${gl_hong}❌ 当前异常${gl_bai}"
        fi
        echo -e "  开机持久化:  ${gl_hong}⚠️  老版（重启有风险）${gl_bai}"
        echo ""
        echo -e "${gl_huang}原因：老版持久化服务存在已知bug，重启后可能导致DNS断连${gl_bai}"
        echo -e "${gl_lv}建议：继续执行功能5，新版会自动替换为安全的持久化机制${gl_bai}"
        echo ""

    elif [ "$dns_has_config" = true ] && [ "$dns_all_healthy" = true ]; then
        # 新版配置 + 全部健康：完美状态
        echo -e "${gl_lv}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
        echo -e "${gl_lv}  ✅ DNS净化已完美配置，无需重复执行！${gl_bai}"
        echo -e "${gl_lv}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
        echo ""
        echo -e "  当前模式:    ${gl_lv}${current_mode_name}${gl_bai}"
        echo -e "  resolved:    ${gl_lv}✅ 运行中${gl_bai}"
        echo -e "  resolv.conf: ${gl_lv}✅ 指向 stub（resolved 托管）${gl_bai}"
        echo -e "  开机持久化:  ${gl_lv}✅ dns-purify-persist 已启用（新版）${gl_bai}"
        echo -e "  DNS 解析:    ${gl_lv}✅ 正常${gl_bai}"
        echo ""
        echo -e "${gl_huang}提示：重启后 DNS 会自动恢复，无需担心${gl_bai}"
        echo ""
        if [ "$AUTO_MODE" = "1" ]; then
            return
        fi
        read -e -p "$(echo -e "${gl_huang}如需重新配置请输入 y，返回主菜单按回车: ${gl_bai}")" dns_reconfig
        if [[ ! "$dns_reconfig" =~ ^[Yy]$ ]]; then
            return
        fi
        echo ""
    fi

    # ==================== DNS模式选择 ====================
    echo -e "${gl_kjlan}请选择 DNS 配置模式：${gl_bai}"
    echo ""
    echo "  1. 🌍 纯国外模式（抗污染推荐）"
    echo "     首选：Google DNS + Cloudflare DNS"
    echo "     备用：无"
    echo "     加密：强制 DNS over TLS"
    echo ""
    echo "  2. 🇨🇳 纯国内模式（低延迟推荐）"
    echo "     首选：阿里云 DNS + 腾讯 DNSPod"
    echo "     备用：无"
    echo "     加密：无（国内DNS不支持DoT/DNSSEC）"
    echo ""
    if [ "$AUTO_MODE" = "1" ]; then
        dns_mode_choice=1
    else
        read -e -p "$(echo -e "${gl_huang}请选择 (1/2，默认1): ${gl_bai}")" dns_mode_choice
        dns_mode_choice=${dns_mode_choice:-1}
    fi

    # 验证输入
    if [[ ! "$dns_mode_choice" =~ ^[1-2]$ ]]; then
        dns_mode_choice=1
    fi

    echo ""

    if [ "$AUTO_MODE" = "1" ]; then
        confirm=y
    else
        read -e -p "$(echo -e "${gl_huang}是否继续执行？(y/n): ${gl_bai}")" confirm
    fi

    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        echo -e "${gl_huang}已取消操作${gl_bai}"
        return
    fi

    # ==================== 终极安全检查 ====================
    echo ""
    echo -e "${gl_kjlan}[安全检查] 正在验证系统环境...${gl_bai}"
    echo ""
    
    local pre_check_failed=false
    
    # 检查1: 磁盘空间（至少需要100MB）
    echo -n "  → 检查磁盘空间... "
    local available_space=$(df -m /etc | awk 'NR==2 {print $4}')
    if [ "$available_space" -lt 100 ]; then
        echo -e "${gl_hong}失败 (可用: ${available_space}MB, 需要: 100MB)${gl_bai}"
        pre_check_failed=true
    else
        echo -e "${gl_lv}通过 (可用: ${available_space}MB)${gl_bai}"
    fi
    
    # 检查2: 内存（至少需要50MB可用）
    echo -n "  → 检查可用内存... "
    local available_mem=$(free -m | awk 'NR==2 {print $7}')
    if [ "$available_mem" -lt 50 ]; then
        echo -e "${gl_hong}失败 (可用: ${available_mem}MB, 需要: 50MB)${gl_bai}"
        pre_check_failed=true
    else
        echo -e "${gl_lv}通过 (可用: ${available_mem}MB)${gl_bai}"
    fi
    
    # 检查3: systemd 是否正常工作
    echo -n "  → 检查 systemd 状态... "
    if ! systemctl --version > /dev/null 2>&1; then
        echo -e "${gl_hong}失败 (systemctl 命令无法执行)${gl_bai}"
        pre_check_failed=true
    else
        echo -e "${gl_lv}通过${gl_bai}"
    fi
    
    # 检查4: 是否有其他包管理器在运行
    echo -n "  → 检查包管理器锁... "
    if lsof /var/lib/dpkg/lock-frontend > /dev/null 2>&1 || \
       lsof /var/lib/apt/lists/lock > /dev/null 2>&1 || \
       lsof /var/cache/apt/archives/lock > /dev/null 2>&1; then
        echo -e "${gl_hong}失败 (其他包管理器正在运行)${gl_bai}"
        pre_check_failed=true
    else
        echo -e "${gl_lv}通过${gl_bai}"
    fi
    
    # 检查5: /run 目录是否可写
    echo -n "  → 检查 /run 目录权限... "
    if ! touch /run/.dns_test 2>/dev/null; then
        echo -e "${gl_hong}失败 (/run 目录不可写)${gl_bai}"
        pre_check_failed=true
    else
        rm -f /run/.dns_test
        echo -e "${gl_lv}通过${gl_bai}"
    fi
    
    # 检查6: 网络连通性（能否访问DNS服务器）
    echo -n "  → 检查网络连通性... "
    if ! ping -c 1 -W 2 8.8.8.8 > /dev/null 2>&1 && \
       ! ping -c 1 -W 2 1.1.1.1 > /dev/null 2>&1; then
        echo -e "${gl_huang}警告 (无法ping通DNS服务器，但继续执行)${gl_bai}"
    else
        echo -e "${gl_lv}通过${gl_bai}"
    fi
    
    echo ""
    
    # 如果有检查失败，拒绝执行
    if [ "$pre_check_failed" = true ]; then
        echo -e "${gl_hong}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
        echo -e "${gl_hong}❌ 安全检查未通过！${gl_bai}"
        echo -e "${gl_hong}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
        echo ""
        echo -e "${gl_huang}系统环境不满足安全执行条件，拒绝执行以避免风险。${gl_bai}"
        echo ""
        echo "请先解决上述问题，然后重试。"
        echo ""
        break_end
        return 1
    fi
    
    echo -e "${gl_lv}✅ 所有安全检查通过，可以安全执行${gl_bai}"
    echo ""

    # ==================== 创建备份 ====================
    local BACKUP_DIR="/root/.dns_purify_backup/$(date +%Y%m%d_%H%M%S)"
    local PRE_STATE_DIR="$BACKUP_DIR/pre_state"
    mkdir -p "$BACKUP_DIR" "$PRE_STATE_DIR"
    echo ""
    echo -e "${gl_lv}✅ 创建备份目录：$BACKUP_DIR${gl_bai}"
    echo ""

    # 记录/恢复单个路径状态（文件、符号链接或不存在）
    backup_path_state() {
        local src="$1"
        local key="$2"
        if [[ -e "$src" || -L "$src" ]]; then
            cp -a "$src" "$PRE_STATE_DIR/$key" 2>/dev/null || true
        else
            : > "$PRE_STATE_DIR/$key.absent"
        fi
    }

    restore_path_state() {
        local dst="$1"
        local key="$2"
        rm -f "$dst" 2>/dev/null || true
        if [[ -e "$PRE_STATE_DIR/$key" || -L "$PRE_STATE_DIR/$key" ]]; then
            mkdir -p "$(dirname "$dst")"
            cp -a "$PRE_STATE_DIR/$key" "$dst" 2>/dev/null || true
        elif [[ -f "$PRE_STATE_DIR/$key.absent" ]]; then
            rm -f "$dst" 2>/dev/null || true
        fi
    }

    # 解析 DNS 地址中的 SNI 后缀（例如 1.1.1.1#cloudflare-dns.com -> 1.1.1.1）
    plain_dns_ip() {
        local dns_addr="$1"
        echo "${dns_addr%%#*}"
    }

    # 预先快照本次功能可能修改的关键文件
    backup_path_state "/etc/dhcp/dhclient.conf" "dhclient.conf"
    backup_path_state "/etc/network/interfaces" "interfaces"
    backup_path_state "/etc/systemd/resolved.conf" "resolved.conf"
    backup_path_state "/etc/resolv.conf" "resolv.conf"
    backup_path_state "/etc/systemd/system/dns-purify-persist.service" "dns-purify-persist.service"
    backup_path_state "/usr/local/bin/dns-purify-apply.sh" "dns-purify-apply.sh"
    backup_path_state "/etc/systemd/system/systemd-resolved.service.d/dbus-fix.conf" "dbus-fix.conf"
    backup_path_state "/etc/NetworkManager/conf.d/99-dns-purify.conf" "nm-99-dns-purify.conf"

    # 快照 if-up.d/resolved 执行权限状态
    local ifup_script="/etc/network/if-up.d/resolved"
    if [[ -e "$ifup_script" ]]; then
        if [[ -x "$ifup_script" ]]; then
            echo "executable" > "$PRE_STATE_DIR/ifup-resolved.exec"
        else
            echo "not_executable" > "$PRE_STATE_DIR/ifup-resolved.exec"
        fi
    else
        echo "absent" > "$PRE_STATE_DIR/ifup-resolved.exec"
    fi

    # 快照服务启用状态
    if systemctl is-enabled --quiet dns-purify-persist.service 2>/dev/null; then
        echo "true" > "$PRE_STATE_DIR/dns-persist.was-enabled"
    else
        echo "false" > "$PRE_STATE_DIR/dns-persist.was-enabled"
    fi

    # 用文本输出精确记录 enabled/static/disabled/masked 状态（is-enabled --quiet 对 static 也返回 0）
    local resolved_enable_state
    resolved_enable_state=$(systemctl is-enabled systemd-resolved 2>/dev/null || echo "unknown")
    echo "$resolved_enable_state" > "$PRE_STATE_DIR/resolved.enable-state"

    if [[ "$resolved_enable_state" == "masked" || "$resolved_enable_state" == "masked-runtime" ]]; then
        echo "true" > "$PRE_STATE_DIR/resolved.was-masked"
    else
        echo "false" > "$PRE_STATE_DIR/resolved.was-masked"
    fi

    if systemctl is-active --quiet systemd-resolved 2>/dev/null; then
        echo "true" > "$PRE_STATE_DIR/resolved.was-active"
    else
        echo "false" > "$PRE_STATE_DIR/resolved.was-active"
    fi

    # 快照 resolvconf 包状态（用于 Debian 11 回滚）
    if dpkg -s resolvconf >/dev/null 2>&1; then
        echo "true" > "$PRE_STATE_DIR/had-resolvconf.pkg"
    else
        echo "false" > "$PRE_STATE_DIR/had-resolvconf.pkg"
    fi

    local pre_dns_health="false"
    if command -v getent >/dev/null 2>&1; then
        if getent hosts google.com >/dev/null 2>&1 || getent hosts baidu.com >/dev/null 2>&1; then
            pre_dns_health="true"
        fi
    fi
    echo "$pre_dns_health" > "$PRE_STATE_DIR/pre-dns.health"

    # 快照现有 systemd-networkd DNS drop-in
    : > "$PRE_STATE_DIR/networkd-dropins.map"
    local existing_dropin
    for existing_dropin in /etc/systemd/network/*.network.d/dns-purify-override.conf; do
        [[ -f "$existing_dropin" ]] || continue
        local dropin_key="networkd-$(echo "$existing_dropin" | sed 's|/|__|g')"
        cp -a "$existing_dropin" "$PRE_STATE_DIR/$dropin_key" 2>/dev/null || true
        echo "$existing_dropin|$dropin_key" >> "$PRE_STATE_DIR/networkd-dropins.map"
    done

    # 退出函数时自动清理本函数内动态定义的 helper，避免影响其他功能
    trap 'unset -f backup_path_state restore_path_state plain_dns_ip auto_rollback_dns_purify dns_runtime_health_check can_connect_tcp >/dev/null 2>&1 || true' RETURN

    # 自动回滚函数（失败即恢复，避免遗留DNS隐患）
    auto_rollback_dns_purify() {
        # 恢复关键文件到执行前状态（注意：resolv.conf 延后恢复，避免悬空链接）
        restore_path_state "/etc/dhcp/dhclient.conf" "dhclient.conf"
        restore_path_state "/etc/network/interfaces" "interfaces"
        restore_path_state "/etc/systemd/resolved.conf" "resolved.conf"
        # resolv.conf 在服务状态恢复后再处理（见下方）
        restore_path_state "/etc/systemd/system/dns-purify-persist.service" "dns-purify-persist.service"
        restore_path_state "/usr/local/bin/dns-purify-apply.sh" "dns-purify-apply.sh"
        restore_path_state "/etc/systemd/system/systemd-resolved.service.d/dbus-fix.conf" "dbus-fix.conf"
        restore_path_state "/etc/NetworkManager/conf.d/99-dns-purify.conf" "nm-99-dns-purify.conf"

        # 恢复 if-up.d/resolved 执行权限
        if [[ -f "$PRE_STATE_DIR/ifup-resolved.exec" ]]; then
            case "$(cat "$PRE_STATE_DIR/ifup-resolved.exec" 2>/dev/null)" in
                executable)
                    [[ -e /etc/network/if-up.d/resolved ]] && chmod +x /etc/network/if-up.d/resolved 2>/dev/null || true
                    ;;
                not_executable)
                    [[ -e /etc/network/if-up.d/resolved ]] && chmod -x /etc/network/if-up.d/resolved 2>/dev/null || true
                    ;;
                absent)
                    rm -f /etc/network/if-up.d/resolved 2>/dev/null || true
                    ;;
            esac
        fi

        # 移除本次可能新增的 networkd drop-in（扩展搜索所有可能路径）
        local dropin_file search_dir
        for search_dir in /etc/systemd/network /run/systemd/network /usr/lib/systemd/network; do
            for dropin_file in "$search_dir"/*.network.d/dns-purify-override.conf; do
                [[ -f "$dropin_file" ]] || continue
                rm -f "$dropin_file"
                rmdir "$(dirname "$dropin_file")" 2>/dev/null || true
            done
        done

        # 恢复执行前已有的 networkd drop-in
        if [[ -f "$PRE_STATE_DIR/networkd-dropins.map" ]]; then
            local restore_path restore_key
            while IFS='|' read -r restore_path restore_key; do
                [[ -n "$restore_path" && -n "$restore_key" ]] || continue
                [[ -f "$PRE_STATE_DIR/$restore_key" ]] || continue
                mkdir -p "$(dirname "$restore_path")"
                cp -a "$PRE_STATE_DIR/$restore_key" "$restore_path" 2>/dev/null || true
            done < "$PRE_STATE_DIR/networkd-dropins.map"
        fi

        # 重载 systemd-networkd（使 drop-in 变更生效）
        if systemctl is-active --quiet systemd-networkd 2>/dev/null; then
            networkctl reload 2>/dev/null || systemctl reload systemd-networkd 2>/dev/null || true
        fi

        # 重载 NetworkManager（使配置文件变更生效）
        if systemctl is-active --quiet NetworkManager 2>/dev/null; then
            systemctl reload NetworkManager 2>/dev/null || true
        fi

        # 恢复 dns-purify 持久化服务启用状态
        local dns_persist_was_enabled="false"
        [[ -f "$PRE_STATE_DIR/dns-persist.was-enabled" ]] && dns_persist_was_enabled=$(cat "$PRE_STATE_DIR/dns-persist.was-enabled" 2>/dev/null || echo "false")

        systemctl daemon-reload 2>/dev/null || true
        if [[ -e "$PRE_STATE_DIR/dns-purify-persist.service" || -L "$PRE_STATE_DIR/dns-purify-persist.service" ]]; then
            if [[ "$dns_persist_was_enabled" == "true" ]]; then
                systemctl enable dns-purify-persist.service 2>/dev/null || true
            else
                systemctl disable dns-purify-persist.service 2>/dev/null || true
            fi
        else
            systemctl disable dns-purify-persist.service 2>/dev/null || true
        fi

        # 尝试恢复 resolvconf 包状态（Debian 11 场景）
        local had_resolvconf_pkg="false"
        [[ -f "$PRE_STATE_DIR/had-resolvconf.pkg" ]] && had_resolvconf_pkg=$(cat "$PRE_STATE_DIR/had-resolvconf.pkg" 2>/dev/null || echo "false")
        if [[ "$had_resolvconf_pkg" == "true" ]] && ! dpkg -s resolvconf >/dev/null 2>&1; then
            DEBIAN_FRONTEND=noninteractive apt-get install -y resolvconf >/dev/null 2>&1 || true
        fi

        # 恢复 systemd-resolved 启用/屏蔽/运行状态（在 resolv.conf 之前）
        local resolved_enable_state="unknown"
        local resolved_was_masked="false"
        local resolved_was_active="false"
        [[ -f "$PRE_STATE_DIR/resolved.enable-state" ]] && resolved_enable_state=$(cat "$PRE_STATE_DIR/resolved.enable-state" 2>/dev/null || echo "unknown")
        # 兼容旧版快照格式
        [[ "$resolved_enable_state" == "unknown" && -f "$PRE_STATE_DIR/resolved.was-enabled" ]] && {
            local old_enabled
            old_enabled=$(cat "$PRE_STATE_DIR/resolved.was-enabled" 2>/dev/null || echo "false")
            [[ "$old_enabled" == "true" ]] && resolved_enable_state="enabled" || resolved_enable_state="disabled"
        }
        [[ -f "$PRE_STATE_DIR/resolved.was-masked" ]] && resolved_was_masked=$(cat "$PRE_STATE_DIR/resolved.was-masked" 2>/dev/null || echo "false")
        [[ -f "$PRE_STATE_DIR/resolved.was-active" ]] && resolved_was_active=$(cat "$PRE_STATE_DIR/resolved.was-active" 2>/dev/null || echo "false")

        if [[ "$resolved_was_masked" == "true" ]]; then
            systemctl mask systemd-resolved 2>/dev/null || true
            systemctl stop systemd-resolved 2>/dev/null || true
        else
            systemctl unmask systemd-resolved 2>/dev/null || true
            case "$resolved_enable_state" in
                enabled|enabled-runtime)
                    systemctl enable systemd-resolved 2>/dev/null || true
                    ;;
                static|indirect|generated)
                    # static/indirect/generated 状态由包管理器控制，不改变
                    ;;
                *)
                    systemctl disable systemd-resolved 2>/dev/null || true
                    ;;
            esac

            if [[ "$resolved_was_active" == "true" ]]; then
                systemctl restart systemd-resolved 2>/dev/null || systemctl start systemd-resolved 2>/dev/null || true
                # 等待 resolved 完全启动，确保 stub 文件可用
                local wait_i
                for wait_i in $(seq 1 5); do
                    [[ -f /run/systemd/resolve/stub-resolv.conf ]] && break
                    sleep 1
                done
            else
                systemctl stop systemd-resolved 2>/dev/null || true
            fi
        fi

        # 最后恢复 resolv.conf（此时 resolved 已恢复运行状态，stub 文件可用）
        # 特殊处理：如果备份是指向 stub 的软链接但 resolved 未运行，则写静态文件
        if [[ -L "$PRE_STATE_DIR/resolv.conf" ]]; then
            local backup_link_target
            backup_link_target=$(readlink "$PRE_STATE_DIR/resolv.conf" 2>/dev/null || echo "")
            if [[ "$backup_link_target" == *"stub-resolv.conf"* ]] && [[ ! -f /run/systemd/resolve/stub-resolv.conf ]]; then
                # resolved 未运行，stub 不存在 — 写入静态 nameserver 避免悬空链接
                rm -f /etc/resolv.conf 2>/dev/null || true
                echo "nameserver 127.0.0.53" > /etc/resolv.conf 2>/dev/null || true
            else
                restore_path_state "/etc/resolv.conf" "resolv.conf"
            fi
        else
            restore_path_state "/etc/resolv.conf" "resolv.conf"
        fi

        # 回滚后验证 — 充分等待 resolved 初始化（最多15秒，每3秒重试）
        local rollback_ok=false
        local pre_dns_health="false"
        [[ -f "$PRE_STATE_DIR/pre-dns.health" ]] && pre_dns_health=$(cat "$PRE_STATE_DIR/pre-dns.health" 2>/dev/null || echo "false")

        local max_wait=5
        for i in $(seq 1 $max_wait); do
            if dns_runtime_health_check "global" || dns_runtime_health_check "cn"; then
                rollback_ok=true
                break
            fi
            sleep 3
        done

        if [ "$rollback_ok" = true ]; then
            echo -e "${gl_lv}  ✅ 回滚后DNS健康校验通过${gl_bai}"
        elif [ "$pre_dns_health" = "true" ]; then
            echo -e "${gl_huang}  ⚠️  回滚后DNS验证超时，但已恢复执行前配置，可能需要等待网络就绪${gl_bai}"
        else
            echo -e "${gl_huang}  ⚠️  执行前DNS即不可用，已恢复原始配置${gl_bai}"
        fi
    }

    # DNS运行时健康检查（多域名，多方法）
    dns_runtime_health_check() {
        local check_mode="${1:-global}"
        local domains=()
        if [[ "$check_mode" == "cn" ]]; then
            domains=("baidu.com" "qq.com" "aliyun.com")
        else
            domains=("google.com" "cloudflare.com" "github.com" "baidu.com")
        fi

        if command -v getent >/dev/null 2>&1; then
            local domain
            for domain in "${domains[@]}"; do
                if getent hosts "$domain" >/dev/null 2>&1; then
                    return 0
                fi
            done
        fi

        if command -v nslookup >/dev/null 2>&1; then
            local domain
            for domain in "${domains[@]}"; do
                if nslookup "$domain" >/dev/null 2>&1; then
                    return 0
                fi
            done
        fi

        local domain
        for domain in "${domains[@]}"; do
            if ping -c 1 -W 2 "$domain" >/dev/null 2>&1; then
                return 0
            fi
        done

        return 1
    }

    # TCP端口探测（用于DoT 853预检）
    can_connect_tcp() {
        local host="$1"
        local port="$2"
        if command -v timeout >/dev/null 2>&1; then
            timeout 3 bash -c "exec 3<>/dev/tcp/${host}/${port} && exec 3>&-" >/dev/null 2>&1
        else
            bash -c "exec 3<>/dev/tcp/${host}/${port} && exec 3>&-" >/dev/null 2>&1
        fi
    }

    # 目标DNS配置（根据用户选择的模式）
    local TARGET_DNS=""
    local FALLBACK_DNS=""
    local DNS_OVER_TLS=""
    local DNSSEC_MODE=""
    local MODE_NAME=""
    # 网卡级 DNS（用于 resolvectl）
    local INTERFACE_DNS_PRIMARY=""
    local INTERFACE_DNS_SECONDARY=""
    case "$dns_mode_choice" in
        1)
            # 纯国外模式
            TARGET_DNS="8.8.8.8#dns.google 1.1.1.1#cloudflare-dns.com"
            FALLBACK_DNS=""
            DNS_OVER_TLS="yes"
            DNSSEC_MODE="no"
            MODE_NAME="纯国外模式"
            # 网卡级使用纯IP，避免个别systemd/resolvectl版本对SNI参数兼容问题
            INTERFACE_DNS_PRIMARY="8.8.8.8"
            INTERFACE_DNS_SECONDARY="1.1.1.1"
            ;;
        2)
            # 纯国内模式（国内DNS和国内域名大多不支持DNSSEC，必须禁用）
            TARGET_DNS="223.5.5.5 119.29.29.29"
            FALLBACK_DNS=""
            DNS_OVER_TLS="no"
            DNSSEC_MODE="no"
            MODE_NAME="纯国内模式"
            INTERFACE_DNS_PRIMARY="223.5.5.5"
            INTERFACE_DNS_SECONDARY="119.29.29.29"
            ;;
    esac

    # strict DoT 预检：若目标机房到853不可达，直接中止（不自动降级）
    if [[ "$dns_mode_choice" == "1" ]]; then
        local dot_reachable_count=0
        can_connect_tcp "8.8.8.8" 853 && dot_reachable_count=$((dot_reachable_count + 1))
        can_connect_tcp "1.1.1.1" 853 && dot_reachable_count=$((dot_reachable_count + 1))

        if [[ "$dot_reachable_count" -eq 0 ]]; then
            echo -e "${gl_hong}❌ 预检失败：当前机房无法连通 DoT(853)，已终止执行（未做任何修改）${gl_bai}"
            echo -e "${gl_huang}建议：改用模式2，或放开到 8.8.8.8/1.1.1.1 的 853 出口后再执行模式1${gl_bai}"
            break_end
            return 1
        fi
    fi
    
    echo -e "${gl_lv}已选择：${MODE_NAME}${gl_bai}"
    echo ""
    
    # 构建配置（动态拼接，避免 FallbackDNS 为空时产生空行）
    local SECURE_RESOLVED_CONFIG="[Resolve]
DNS=${TARGET_DNS}"
    if [[ -n "$FALLBACK_DNS" ]]; then
        SECURE_RESOLVED_CONFIG="${SECURE_RESOLVED_CONFIG}
FallbackDNS=${FALLBACK_DNS}"
    fi
    SECURE_RESOLVED_CONFIG="${SECURE_RESOLVED_CONFIG}
LLMNR=no
MulticastDNS=no
DNSSEC=${DNSSEC_MODE}
DNSOverTLS=${DNS_OVER_TLS}
Cache=yes
DNSStubListener=yes
"

    echo "--- 开始执行DNS净化与安全加固流程 ---"
    echo ""

    local debian_version
    debian_version=$(grep "VERSION_ID" /etc/os-release | cut -d'=' -f2 | tr -d '"' || echo "unknown")

    # ==================== 阶段一：清除DNS冲突源 ====================
    echo -e "${gl_kjlan}[阶段 1/5] 清除DNS冲突源（安全操作）...${gl_bai}"
    echo ""

    # 1. 驯服 DHCP 客户端
    local dhclient_conf="/etc/dhcp/dhclient.conf"
    if [[ -f "$dhclient_conf" ]]; then
        # 备份
        cp "$dhclient_conf" "$BACKUP_DIR/dhclient.conf.bak" 2>/dev/null || true
        
        local dhclient_changed=false
        if ! grep -q "ignore domain-name-servers;" "$dhclient_conf"; then
            echo "" >> "$dhclient_conf"
            echo "# 由DNS净化脚本添加 - $(date)" >> "$dhclient_conf"
            echo "ignore domain-name-servers;" >> "$dhclient_conf"
            dhclient_changed=true
        fi
        if ! grep -q "ignore domain-search;" "$dhclient_conf"; then
            if [ "$dhclient_changed" = false ]; then
                echo "" >> "$dhclient_conf"
                echo "# 由DNS净化脚本添加 - $(date)" >> "$dhclient_conf"
            fi
            echo "ignore domain-search;" >> "$dhclient_conf"
            dhclient_changed=true
        fi
        if [ "$dhclient_changed" = true ]; then
            echo "  → 配置 dhclient 忽略DHCP提供的DNS..."
            echo -e "${gl_lv}  ✅ dhclient 配置完成${gl_bai}"
        else
            echo -e "${gl_lv}  ✅ dhclient 已配置（跳过）${gl_bai}"
        fi
    fi

    # 2. 禁用冲突的 if-up.d 脚本
    local ifup_script="/etc/network/if-up.d/resolved"
    if [[ -f "$ifup_script" ]] && [[ -x "$ifup_script" ]]; then
        echo "  → 禁用 if-up.d/resolved 脚本..."
        chmod -x "$ifup_script"
        echo -e "${gl_lv}  ✅ 已移除可执行权限${gl_bai}"
    fi

    # 3. 注释 /etc/network/interfaces 中的DNS配置
    local interfaces_file="/etc/network/interfaces"
    if [[ -f "$interfaces_file" ]]; then
        # 备份
        cp "$interfaces_file" "$BACKUP_DIR/interfaces.bak" 2>/dev/null || true
        
        if grep -qE '^[[:space:]]*dns-(nameservers|search|domain)' "$interfaces_file"; then
            echo "  → 清除 /etc/network/interfaces 中的DNS配置..."
            sed -i.bak -E 's/^([[:space:]]*dns-(nameservers|search|domain).*)/# \1 # 已被DNS净化脚本禁用/' "$interfaces_file"
            echo -e "${gl_lv}  ✅ 厂商DNS配置已注释${gl_bai}"
        else
            echo -e "${gl_lv}  ✅ /etc/network/interfaces 无DNS配置${gl_bai}"
        fi
    fi

    echo ""

    # ==================== 阶段二：配置 systemd-resolved ====================
    echo -e "${gl_kjlan}[阶段 2/5] 配置 systemd-resolved...${gl_bai}"
    echo ""

    # 检查是否已安装
    if ! command -v resolvectl &> /dev/null; then
        echo "  → 检测到未安装 systemd-resolved"
        echo "  → 安装 systemd-resolved..."
        apt-get update -y > /dev/null 2>&1
        DEBIAN_FRONTEND=noninteractive apt-get install -y systemd-resolved > /dev/null 2>&1
        echo -e "${gl_lv}  ✅ systemd-resolved 安装完成${gl_bai}"
    else
        echo -e "${gl_lv}  ✅ systemd-resolved 已安装${gl_bai}"
    fi

    # 处理 Debian 11 的 resolvconf 冲突
    if [[ "$debian_version" == "11" ]] && dpkg -s resolvconf &> /dev/null; then
        echo "  → 检测到 Debian 11 的 resolvconf 冲突"
        
        # 🛡️ 关键修复：在卸载前确保 systemd-resolved 完全就绪
        # 先启动 systemd-resolved
        echo "  → 启动 systemd-resolved（在卸载 resolvconf 之前）..."
        systemctl enable systemd-resolved 2>/dev/null || true
        systemctl start systemd-resolved 2>/dev/null || true
        
        # 等待服务启动
        sleep 2
        
        # 验证 systemd-resolved 正在运行
        if ! systemctl is-active --quiet systemd-resolved; then
            echo -e "${gl_hong}❌ 无法启动 systemd-resolved，中止操作${gl_bai}"
            auto_rollback_dns_purify
            break_end
            return 1
        fi
        
        # 验证 stub-resolv.conf 存在
        if [[ ! -f /run/systemd/resolve/stub-resolv.conf ]]; then
            echo -e "${gl_hong}❌ systemd-resolved stub 文件不存在，中止操作${gl_bai}"
            auto_rollback_dns_purify
            break_end
            return 1
        fi
        
        # 现在可以安全地卸载 resolvconf
        # 备份当前 resolv.conf
        [[ -f /etc/resolv.conf ]] && cp /etc/resolv.conf "$BACKUP_DIR/resolv.conf.pre_remove" 2>/dev/null || true
        
        # 创建临时DNS配置（避免卸载期间DNS中断）
        echo "nameserver $(plain_dns_ip "$INTERFACE_DNS_PRIMARY")" > /etc/resolv.conf.tmp
        echo "nameserver $(plain_dns_ip "$INTERFACE_DNS_SECONDARY")" >> /etc/resolv.conf.tmp
        
        # 使用临时DNS配置
        mv /etc/resolv.conf /etc/resolv.conf.old 2>/dev/null || true
        cp /etc/resolv.conf.tmp /etc/resolv.conf
        
        # 卸载 resolvconf
        echo "  → 卸载 resolvconf..."
        DEBIAN_FRONTEND=noninteractive apt-get remove -y resolvconf > /dev/null 2>&1
        
        # 清理临时文件
        rm -f /etc/resolv.conf.tmp /etc/resolv.conf.old
        
        echo -e "${gl_lv}  ✅ resolvconf 已安全卸载${gl_bai}"
    fi

    # 🔧 调用智能修复函数
    if ! dns_purify_fix_systemd_resolved; then
        echo -e "${gl_hong}❌ 无法修复 systemd-resolved 服务，脚本终止${gl_bai}"
        echo "检测到修复失败，正在自动回滚到执行前状态"
        auto_rollback_dns_purify
        break_end
        return 1
    fi

    # 备份并写入配置
    if [[ -f /etc/systemd/resolved.conf ]]; then
        cp /etc/systemd/resolved.conf "$BACKUP_DIR/resolved.conf.bak" 2>/dev/null || true
    fi

    echo "  → 配置 systemd-resolved..."
    echo -e "${SECURE_RESOLVED_CONFIG}" > /etc/systemd/resolved.conf
    
    echo ""

    # ==================== 阶段三：应用DNS配置（SSH安全方式）====================
    echo -e "${gl_kjlan}[阶段 3/5] 应用DNS配置（SSH安全模式）...${gl_bai}"
    echo ""

    # 先重新加载 systemd-resolved 配置
    echo "  → 重新加载 systemd-resolved 配置..."
    if ! systemctl reload-or-restart systemd-resolved; then
        echo -e "${gl_hong}❌ systemd-resolved 重启失败！${gl_bai}"
        echo "正在自动回滚配置..."
        auto_rollback_dns_purify
        break_end
        return 1
    fi
    
    # 等待服务完全启动
    echo "  → 等待 systemd-resolved 完全启动..."
    sleep 3
    
    # 验证服务状态
    if ! systemctl is-active --quiet systemd-resolved; then
        echo -e "${gl_hong}❌ systemd-resolved 未能正常运行！${gl_bai}"
        echo "正在自动回滚配置..."
        auto_rollback_dns_purify
        break_end
        return 1
    fi
    
    # 验证 stub-resolv.conf 文件存在
    if [[ ! -f /run/systemd/resolve/stub-resolv.conf ]]; then
        echo -e "${gl_hong}❌ systemd-resolved stub 文件不存在！${gl_bai}"
        echo "路径: /run/systemd/resolve/stub-resolv.conf"
        echo "正在自动回滚配置..."
        auto_rollback_dns_purify
        break_end
        return 1
    fi
    
    echo -e "${gl_lv}  ✅ systemd-resolved 配置已重新加载并验证${gl_bai}"

    # 🔧 确保服务开机自启动（修复 #11：某些 Debian 版本服务状态为 static 时不会自启）
    echo "  → 确保 systemd-resolved 开机自启动..."
    systemctl enable systemd-resolved >/dev/null 2>&1 || true
    echo -e "${gl_lv}  ✅ 已设置开机自启动${gl_bai}"

    # 🔒 检测 immutable 属性（云服务商保护机制）
    if [[ -e /etc/resolv.conf ]] && lsattr /etc/resolv.conf 2>/dev/null | grep -q 'i'; then
        echo ""
        echo -e "${gl_hong}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
        echo -e "${gl_hong}⚠️  检测到 /etc/resolv.conf 被锁定保护${gl_bai}"
        echo -e "${gl_hong}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
        echo ""
        echo "原因：您的服务器设置了不可变属性（通常是云服务商的保护机制）"
        echo ""
        echo "风险：强制修改可能导致机器失联或网络异常"
        echo ""
        echo "建议：如非必要，不建议继续修改"
        echo "      能正常执行的系统不会弹出此提示"
        echo ""
        echo -e "${gl_huang}状态：检测到锁定保护，正在恢复已修改的配置${gl_bai}"
        # 只回滚 resolved.conf（阶段二已修改），不做完整回滚
        # resolv.conf 尚未被修改（软链接替换在此检查之后），无需恢复
        restore_path_state "/etc/systemd/resolved.conf" "resolved.conf"
        systemctl reload-or-restart systemd-resolved 2>/dev/null || true
        echo ""
        break_end
        return 1
    fi
    
    # 🛡️ 关键修复：安全地创建 resolv.conf 链接
    # 备份并创建 resolv.conf 链接（只有在验证通过后才执行）
    if [[ -e /etc/resolv.conf ]] && [[ ! -L /etc/resolv.conf ]]; then
        # 如果是普通文件，备份它
        cp /etc/resolv.conf "$BACKUP_DIR/resolv.conf.bak" 2>/dev/null || true
    fi
    
    # 安全地创建链接
    rm -f /etc/resolv.conf
    ln -s /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf
    
    # 验证链接创建成功
    if [[ ! -L /etc/resolv.conf ]] || [[ ! -e /etc/resolv.conf ]]; then
        echo -e "${gl_hong}❌ resolv.conf 链接创建失败！${gl_bai}"
        echo "正在自动回滚原始配置..."
        auto_rollback_dns_purify
        break_end
        return 1
    fi
    
    echo -e "${gl_lv}  ✅ resolv.conf 链接已安全创建${gl_bai}"
    
    # 🚫 完全移除 networking.service 重启（即使非SSH模式也危险）
    # 注意：不管是SSH还是本地连接，都不重启 networking.service
    # 因为重启网络服务在生产环境中极其危险
    echo -e "${gl_lv}  ✅ 网络服务未受影响（安全模式）${gl_bai}"

    echo ""
    
    # ==================== Debian 13特殊修复：D-Bus接口注册问题 ====================
    echo -e "${gl_kjlan}[特殊修复] 检测并修复 D-Bus 接口注册（Debian 13兼容）...${gl_bai}"
    echo ""
    
    # 检测是否需要修复D-Bus接口
    local need_dbus_fix=false
    # debian_version 已在阶段二前定义，此处直接使用

    echo "  → 检测系统版本：Debian ${debian_version:-未知}"
    
    # 检查resolvectl是否能正常通信
    echo "  → 测试 resolvectl 命令响应..."
    if ! timeout 3 resolvectl status >/dev/null 2>&1; then
        echo -e "${gl_huang}  ⚠️  resolvectl 命令无响应，需要修复 D-Bus 接口${gl_bai}"
        need_dbus_fix=true
    else
        echo -e "${gl_lv}  ✅ resolvectl 响应正常${gl_bai}"
    fi
    
    # 如果需要修复D-Bus接口
    if [ "$need_dbus_fix" = true ]; then
        echo ""
        echo -e "${gl_huang}检测到 D-Bus 接口注册问题（Debian 13已知问题），正在自动修复...${gl_bai}"
        echo ""
        
        # 🛡️ 安全措施：在重启前创建临时DNS配置，确保DNS始终可用
        echo "  → 创建临时DNS配置（防止修复期间DNS中断）..."
        
        # 备份当前resolv.conf
        if [[ -e /etc/resolv.conf ]]; then
            cp /etc/resolv.conf "$BACKUP_DIR/resolv.conf.before_dbus_fix" 2>/dev/null || true
        fi
        
        # 创建临时DNS配置文件
        cat > /etc/resolv.conf.dbus_fix_temp << TEMP_DNS
# 临时DNS配置（D-Bus修复期间使用）
nameserver $INTERFACE_DNS_PRIMARY
nameserver $INTERFACE_DNS_SECONDARY
TEMP_DNS
        
        # 使用临时DNS配置
        rm -f /etc/resolv.conf
        cp /etc/resolv.conf.dbus_fix_temp /etc/resolv.conf
        chmod 644 /etc/resolv.conf
        
        echo -e "${gl_lv}  ✅ 临时DNS配置已创建（确保修复期间DNS可用）${gl_bai}"
        
        # 1. 完全重启systemd-resolved，让它重新注册D-Bus接口
        echo "  → 重启 systemd-resolved 以重新注册 D-Bus 接口..."
        systemctl stop systemd-resolved 2>/dev/null || true
        sleep 2
        systemctl start systemd-resolved 2>/dev/null || true
        sleep 3
        
        # 🛡️ 恢复到 stub-resolv.conf 链接
        echo "  → 恢复 resolv.conf 链接到 stub-resolv.conf..."
        
        # 验证 stub-resolv.conf 存在
        if [[ -f /run/systemd/resolve/stub-resolv.conf ]]; then
            rm -f /etc/resolv.conf
            ln -s /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf
            echo -e "${gl_lv}  ✅ resolv.conf 链接已恢复${gl_bai}"
        else
            echo -e "${gl_huang}  ⚠️  stub-resolv.conf 不存在，保持临时DNS配置${gl_bai}"
        fi
        
        # 清理临时文件
        rm -f /etc/resolv.conf.dbus_fix_temp
        
        # 2. 验证D-Bus接口是否注册成功
        if command -v busctl &>/dev/null; then
            local dbus_status=$(busctl list 2>/dev/null | grep "org.freedesktop.resolve1" | grep -v "activatable" || echo "")
            if [ -n "$dbus_status" ]; then
                echo -e "${gl_lv}  ✅ D-Bus 接口已成功注册${gl_bai}"
                
                # 3. 创建永久修复配置（确保重启后也能正常工作）
                echo "  → 创建永久修复配置..."
                mkdir -p /etc/systemd/system/systemd-resolved.service.d
                cat > /etc/systemd/system/systemd-resolved.service.d/dbus-fix.conf << 'DBUS_FIX'
# Debian 13 D-Bus接口注册修复
# 确保D-Bus完全启动后再启动systemd-resolved
[Unit]
After=dbus.service
Requires=dbus.service

[Service]
# 启动后等待1秒，确保D-Bus接口注册完成
ExecStartPost=/bin/sleep 1
DBUS_FIX
                
                systemctl daemon-reload 2>/dev/null || true
                echo -e "${gl_lv}  ✅ 永久修复配置已创建${gl_bai}"
                
                # 4. 再次测试resolvectl
                if timeout 3 resolvectl status >/dev/null 2>&1; then
                    echo -e "${gl_lv}  ✅ resolvectl 现在能正常工作了${gl_bai}"
                else
                    echo -e "${gl_huang}  ⚠️  resolvectl 仍无响应（但DNS配置已通过resolved.conf生效）${gl_bai}"
                fi
            else
                echo -e "${gl_huang}  ⚠️  D-Bus 接口注册可能失败${gl_bai}"
                echo -e "${gl_lv}  ✅ 但DNS配置已通过 /etc/systemd/resolved.conf 生效${gl_bai}"
            fi
        else
            echo -e "${gl_huang}  ⚠️  busctl 命令不可用，无法验证 D-Bus 状态${gl_bai}"
            echo -e "${gl_lv}  ✅ 但DNS配置已通过 /etc/systemd/resolved.conf 生效${gl_bai}"
        fi
        
        echo ""
    fi

    echo ""

    # ==================== 阶段四：配置网卡DNS ====================
    echo -e "${gl_kjlan}[阶段 4/5] 配置网卡DNS（立即生效）...${gl_bai}"
    echo ""
    
    # 🔥 强力保障：阶段4执行前二次验证resolvectl（确保100%成功）
    echo "  → 验证 resolvectl 命令状态..."
    local resolvectl_ready=true
    
    # 快速测试resolvectl是否响应（2秒超时）
    if ! timeout 2 resolvectl status >/dev/null 2>&1; then
        echo -e "${gl_huang}  ⚠️  resolvectl 仍无响应${gl_bai}"
        echo ""
        echo -e "${gl_huang}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
        echo -e "${gl_huang}检测到 resolvectl 命令无法正常工作${gl_bai}"
        echo -e "${gl_huang}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
        echo ""
        echo "这可能导致阶段4的网卡级DNS配置失败。"
        echo ""
        echo "你可以选择："
        echo "  1) 尝试强制修复（会重启systemd-resolved，有临时DNS保护）"
        echo "  2) 跳过网卡配置（安全，全局DNS已生效，推荐）"
        echo ""
        if [ "$AUTO_MODE" = "1" ]; then
            force_fix_choice=2
        else
            read -e -p "$(echo -e "${gl_huang}请选择 (1/2，默认2): ${gl_bai}")" force_fix_choice
            force_fix_choice=${force_fix_choice:-2}
        fi
        
        if [[ "$force_fix_choice" == "1" ]]; then
            echo ""
            echo -e "${gl_kjlan}正在执行强制修复...${gl_bai}"
            resolvectl_ready=false
            
            # 强制修复：重启systemd-resolved重新注册D-Bus
            echo "  → 创建临时DNS保护..."
            
            # 创建临时DNS保护
            cat > /etc/resolv.conf.stage4_temp << STAGE4_TEMP
nameserver $(plain_dns_ip "$INTERFACE_DNS_PRIMARY")
nameserver $(plain_dns_ip "$INTERFACE_DNS_SECONDARY")
STAGE4_TEMP
            cp /etc/resolv.conf /etc/resolv.conf.stage4_backup 2>/dev/null || true
            cp /etc/resolv.conf.stage4_temp /etc/resolv.conf
            
            echo "  → 强制重启 systemd-resolved..."
            # 完全重启服务
            systemctl stop systemd-resolved 2>/dev/null || true
            sleep 2
            systemctl start systemd-resolved 2>/dev/null || true
            sleep 3
            
            # 恢复链接
            echo "  → 恢复 resolv.conf 链接..."
            if [[ -f /run/systemd/resolve/stub-resolv.conf ]]; then
                rm -f /etc/resolv.conf
                ln -s /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf
            fi
            
            # 清理临时文件
            rm -f /etc/resolv.conf.stage4_temp /etc/resolv.conf.stage4_backup
            
            # 再次验证
            echo "  → 验证修复结果..."
            if timeout 2 resolvectl status >/dev/null 2>&1; then
                echo -e "${gl_lv}  ✅ resolvectl 已修复，可以继续${gl_bai}"
                resolvectl_ready=true
            else
                echo -e "${gl_huang}  ⚠️  resolvectl 仍无法正常工作${gl_bai}"
                echo -e "${gl_lv}  ✅ 将跳过网卡级DNS配置（全局DNS已生效）${gl_bai}"
                resolvectl_ready=false
            fi
            echo ""
        else
            echo ""
            echo -e "${gl_lv}已选择跳过强制修复（安全选择）${gl_bai}"
            echo -e "${gl_lv}将跳过网卡级DNS配置，全局DNS配置已生效${gl_bai}"
            resolvectl_ready=false
            echo ""
        fi
    else
        echo -e "${gl_lv}  ✅ resolvectl 响应正常${gl_bai}"
    fi
    
    echo ""

    # 检测主网卡
    local main_interface=$(ip route | grep '^default' | awk '{print $5}' | head -n1)

    if [[ -n "$main_interface" ]] && command -v resolvectl &> /dev/null && [ "$resolvectl_ready" = true ]; then
        echo "  → 检测到主网卡: ${main_interface}"
        
        # 🛡️ 关键修复：检查timeout命令是否可用
        if ! command -v timeout &> /dev/null; then
            echo -e "${gl_huang}  ⚠️  timeout命令不可用，跳过网卡级DNS配置${gl_bai}"
            echo -e "${gl_lv}  ✅ DNS配置已通过 /etc/systemd/resolved.conf 生效${gl_bai}"
        else
            echo "  → 配置网卡 DNS（立即生效，无需重启）..."
            echo ""
            
            # 🛡️ 修复：添加超时机制防止resolvectl命令hang住
            local resolvectl_timeout=5  # 5秒超时
            local dns_config_success=true
            
            echo "    正在应用DNS服务器配置..."
            if timeout "$resolvectl_timeout" resolvectl dns "$main_interface" "$INTERFACE_DNS_PRIMARY" "$INTERFACE_DNS_SECONDARY" 2>/dev/null; then
                echo -e "    ${gl_lv}✅ DNS服务器配置成功${gl_bai}"
            else
                echo -e "    ${gl_huang}⚠️  DNS服务器配置超时或失败（配置已通过resolved.conf生效）${gl_bai}"
                dns_config_success=false
            fi
            
            echo "    正在应用DNS域配置..."
            if timeout "$resolvectl_timeout" resolvectl domain "$main_interface" ~. 2>/dev/null; then
                echo -e "    ${gl_lv}✅ DNS域配置成功${gl_bai}"
            else
                echo -e "    ${gl_huang}⚠️  DNS域配置超时或失败（配置已通过resolved.conf生效）${gl_bai}"
                dns_config_success=false
            fi
            
            echo "    正在应用默认路由配置..."
            if timeout "$resolvectl_timeout" resolvectl default-route "$main_interface" yes 2>/dev/null; then
                echo -e "    ${gl_lv}✅ 默认路由配置成功${gl_bai}"
            else
                echo -e "    ${gl_huang}⚠️  默认路由配置超时或失败（配置已通过resolved.conf生效）${gl_bai}"
                dns_config_success=false
            fi
            
            echo ""
            if [ "$dns_config_success" = true ]; then
                echo -e "${gl_lv}  ✅ 网卡DNS配置已全部应用${gl_bai}"
            else
                echo -e "${gl_huang}  ⚠️  部分网卡DNS配置未能通过resolvectl应用${gl_bai}"
                echo -e "${gl_lv}  ✅ 但DNS配置已通过 /etc/systemd/resolved.conf 生效${gl_bai}"
            fi
        fi
        echo -e "${gl_lv}  ✅ DNS配置立即生效，无需重启${gl_bai}"
    else
        if [[ -z "$main_interface" ]]; then
            echo -e "${gl_huang}  ⚠️  未检测到默认网卡${gl_bai}"
        else
            echo -e "${gl_huang}  ⚠️  resolvectl 命令不可用${gl_bai}"
        fi
        echo -e "${gl_lv}  ✅ DNS配置已通过 /etc/systemd/resolved.conf 生效${gl_bai}"
    fi

    # ==================== 阶段4.5：持久化前健康检查 ====================
    echo ""
    echo -e "${gl_kjlan}[阶段 4.5/5] 持久化前DNS健康检查...${gl_bai}"
    echo ""
    local precheck_dns_ok=false
    if [[ "$dns_mode_choice" == "2" ]]; then
        if dns_runtime_health_check "cn"; then
            precheck_dns_ok=true
        fi
    else
        if dns_runtime_health_check "global"; then
            precheck_dns_ok=true
        fi
    fi

    # strict 模式下绝不自动降级：解析失败立即回滚并退出
    if [ "$precheck_dns_ok" = false ] && [ "$DNS_OVER_TLS" = "yes" ]; then
        echo -e "${gl_hong}❌ strict DoT 健康检查失败，按严格策略中止并回滚（不降级）${gl_bai}"
        auto_rollback_dns_purify
        break_end
        return 1
    fi

    if [ "$precheck_dns_ok" = false ]; then
        echo -e "${gl_hong}❌ 持久化前DNS健康检查失败，正在自动回滚本次配置${gl_bai}"
        auto_rollback_dns_purify
        echo -e "${gl_huang}已自动回滚，请检查机房网络对上游DNS/DoT(853)连通性后重试${gl_bai}"
        break_end
        return 1
    else
        echo -e "${gl_lv}✅ 持久化前DNS健康检查通过${gl_bai}"
    fi

    # ==================== 阶段五：配置重启持久化 ====================
    echo ""
    echo -e "${gl_kjlan}[阶段 5/5] 配置重启持久化（确保重启后DNS不失效）...${gl_bai}"
    echo ""

    # --- 5a: 创建开机自动恢复脚本 ---
    echo "  → 创建DNS持久化恢复脚本..."
    cat > /usr/local/bin/dns-purify-apply.sh << 'PERSIST_SCRIPT_HEAD'
#!/bin/bash
# DNS净化持久化脚本 - 开机自动恢复网卡级DNS配置
# 由 net-tcp-tune.sh DNS净化功能自动生成
# 安全说明：仅重新应用 resolvectl 运行时配置，不修改网络服务

PERSIST_SCRIPT_HEAD

    # 写入用户选择的DNS（动态替换变量）
    cat >> /usr/local/bin/dns-purify-apply.sh << PERSIST_SCRIPT_VARS
DNS_PRIMARY="${INTERFACE_DNS_PRIMARY}"
DNS_SECONDARY="${INTERFACE_DNS_SECONDARY}"
PERSIST_SCRIPT_VARS

    cat >> /usr/local/bin/dns-purify-apply.sh << 'PERSIST_SCRIPT_BODY'

# 前置检查：resolvectl 是否可用
if ! command -v resolvectl >/dev/null 2>&1; then
    echo "dns-purify: resolvectl 不可用，跳过" | systemd-cat -t dns-purify 2>/dev/null || true
    exit 0
fi

# 检测默认网卡（动态获取，适应网卡名变更）
IFACE=$(ip route | grep '^default' | awk '{print $5}' | head -n1)

if [ -z "$IFACE" ]; then
    echo "dns-purify: 未检测到默认网卡，跳过" | systemd-cat -t dns-purify 2>/dev/null || true
    exit 0
fi

# 等待 systemd-resolved 完全就绪（最多等30秒）
for i in $(seq 1 15); do
    if resolvectl status >/dev/null 2>&1; then
        break
    fi
    sleep 2
done

# 应用网卡级DNS配置
resolvectl dns "$IFACE" "$DNS_PRIMARY" "$DNS_SECONDARY" 2>/dev/null
resolvectl domain "$IFACE" "~." 2>/dev/null
resolvectl default-route "$IFACE" yes 2>/dev/null

# 验证DNS可用性
sleep 2
if getent hosts google.com >/dev/null 2>&1 || getent hosts baidu.com >/dev/null 2>&1; then
    echo "dns-purify: DNS配置恢复成功 (接口: $IFACE, DNS: $DNS_PRIMARY $DNS_SECONDARY)" | systemd-cat -t dns-purify 2>/dev/null || true
else
    echo "dns-purify: DNS验证未通过，但配置已应用 (接口: $IFACE)" | systemd-cat -t dns-purify 2>/dev/null || true
fi
PERSIST_SCRIPT_BODY

    chmod +x /usr/local/bin/dns-purify-apply.sh
    echo -e "${gl_lv}  ✅ 持久化脚本已创建: /usr/local/bin/dns-purify-apply.sh${gl_bai}"

    # --- 5b: 创建 systemd 开机服务 ---
    echo "  → 创建开机自启服务..."
    cat > /etc/systemd/system/dns-purify-persist.service << 'PERSIST_SERVICE'
[Unit]
Description=DNS Purify - Restore DNS Configuration on Boot
Documentation=https://github.com/Eric86777/vps-tcp-tune
After=systemd-resolved.service network-online.target
Wants=network-online.target
Wants=systemd-resolved.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/bin/dns-purify-apply.sh
TimeoutStartSec=60

[Install]
WantedBy=multi-user.target
PERSIST_SERVICE

    systemctl daemon-reload
    systemctl enable dns-purify-persist.service >/dev/null 2>&1
    echo -e "${gl_lv}  ✅ 开机自启服务已创建并启用: dns-purify-persist.service${gl_bai}"

    # --- 5c: 阻止 systemd-networkd DHCP 覆盖DNS（最常见的重启失效原因）---
    if systemctl is-active --quiet systemd-networkd 2>/dev/null; then
        echo "  → 检测到 systemd-networkd，配置 DHCP DNS 阻断..."

        # 查找当前网卡对应的 .network 配置文件
        local networkd_file=""
        if command -v networkctl &>/dev/null; then
            networkd_file=$(networkctl status "$main_interface" 2>/dev/null | sed -nE 's/.*Network File:[[:space:]]*(.*)/\1/p' | head -1)
        fi

        if [[ -n "$networkd_file" ]] && [[ -f "$networkd_file" ]]; then
            # 安全方式：创建 drop-in 覆盖，不修改原文件
            local dropin_dir="${networkd_file}.d"
            mkdir -p "$dropin_dir"
            cat > "$dropin_dir/dns-purify-override.conf" << 'NETWORKD_DROPIN'
# DNS净化脚本 - 阻止DHCP覆盖DNS配置
# 仅禁用DHCP下发的DNS，不影响IP地址等其他DHCP功能
[DHCP]
UseDNS=false
UseDomains=false
NETWORKD_DROPIN
            echo -e "${gl_lv}  ✅ systemd-networkd DHCP DNS 阻断已配置（drop-in: ${dropin_dir}/）${gl_bai}"
            echo -e "${gl_lv}     仅阻止DNS覆盖，不影响IP/网关等DHCP功能${gl_bai}"
        else
            # 没找到现有配置文件，创建通用的 drop-in 目录
            echo -e "${gl_huang}  ⚠️  未找到 ${main_interface} 的 .network 文件${gl_bai}"
            echo -e "${gl_lv}  ✅ 已通过开机服务保障重启后DNS恢复${gl_bai}"
        fi
    else
        echo -e "${gl_lv}  ✅ 未使用 systemd-networkd（无需额外配置）${gl_bai}"
    fi

    # --- 5d: 处理 NetworkManager（如果存在）---
    if systemctl is-active --quiet NetworkManager 2>/dev/null; then
        echo "  → 检测到 NetworkManager，配置DNS保护..."
        mkdir -p /etc/NetworkManager/conf.d
        cat > /etc/NetworkManager/conf.d/99-dns-purify.conf << 'NM_CONF'
# DNS净化脚本 - 让 NetworkManager 使用 systemd-resolved
# 不直接管理 /etc/resolv.conf，交给 systemd-resolved
[main]
dns=systemd-resolved
NM_CONF
        echo -e "${gl_lv}  ✅ NetworkManager 已配置为使用 systemd-resolved${gl_bai}"
    fi

    echo ""
    echo -e "${gl_lv}  ✅ 重启持久化配置完成，重启后DNS不会失效${gl_bai}"

    echo ""
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo -e "${gl_lv}✅ DNS净化完成！${gl_bai}"
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo ""

    # 显示当前DNS状态
    echo -e "${gl_huang}当前DNS配置：${gl_bai}"
    echo "────────────────────────────────────────────────────────"
    if command -v resolvectl &> /dev/null; then
        resolvectl status 2>/dev/null | head -30 || cat /etc/resolv.conf
    else
        cat /etc/resolv.conf
    fi
    echo "────────────────────────────────────────────────────────"
    
    # ==================== 统一验证输出（兼容所有systemd版本）====================
    echo ""
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo -e "${gl_kjlan}[智能验证] 网卡DNS配置状态检测：${gl_bai}"
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo ""
    
    if command -v resolvectl &> /dev/null && [[ -n "$main_interface" ]]; then
        local verify_output=$(resolvectl status "$main_interface" 2>/dev/null || echo "")
        local verify_success=true
        
        # 检测1: Default Route（兼容不同systemd版本）
        if echo "$verify_output" | grep -q "Default Route: yes" || \
           echo "$verify_output" | grep -q "Protocols:.*+DefaultRoute"; then
            echo -e "  ${gl_lv}✅ Default Route: 已启用${gl_bai}"
        else
            echo -e "  ${gl_huang}⚠️  Default Route: 未启用或不支持${gl_bai}"
            verify_success=false
        fi
        
        # 检测2: DNS Servers（根据用户选择的模式动态验证）
        local escaped_dns_primary=$(echo "$INTERFACE_DNS_PRIMARY" | sed 's/\./\\./g')
        local escaped_dns_secondary=$(echo "$INTERFACE_DNS_SECONDARY" | sed 's/\./\\./g')
        if echo "$verify_output" | grep -q "DNS Servers:.*${escaped_dns_primary}" && \
           echo "$verify_output" | grep -q "DNS Servers:.*${escaped_dns_secondary}"; then
            echo -e "  ${gl_lv}✅ DNS Servers: ${INTERFACE_DNS_PRIMARY}, ${INTERFACE_DNS_SECONDARY}${gl_bai}"
        else
            echo -e "  ${gl_huang}⚠️  DNS Servers: 配置可能未完全生效${gl_bai}"
            verify_success=false
        fi
        
        # 检测3: DNS Domain
        if echo "$verify_output" | grep -q "DNS Domain:.*~\."; then
            echo -e "  ${gl_lv}✅ DNS Domain: ~. (所有域名)${gl_bai}"
        else
            echo -e "  ${gl_huang}⚠️  DNS Domain: 未配置${gl_bai}"
            verify_success=false
        fi
        
        echo ""
        
        # 最终判断
        if [ "$verify_success" = true ]; then
            echo -e "${gl_lv}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
            echo -e "${gl_lv}💯 最终判断: 网卡DNS配置 100% 成功！${gl_bai}"
            echo -e "${gl_lv}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
        else
            echo -e "${gl_huang}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
            echo -e "${gl_huang}⚠️  网卡DNS配置部分未生效${gl_bai}"
            echo -e "${gl_lv}✅ 但全局DNS配置已生效，DNS解析正常工作${gl_bai}"
            echo -e "${gl_huang}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
        fi
    else
        echo -e "${gl_huang}  ⚠️  resolvectl 不可用或未检测到网卡${gl_bai}"
        echo -e "${gl_lv}  ✅ 全局DNS配置已生效${gl_bai}"
        echo ""
        echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    fi
    
    echo ""

    # 测试DNS解析（等待配置生效）
    echo -e "${gl_huang}测试DNS解析：${gl_bai}"
    echo "  → 等待DNS配置生效（3秒）..."
    sleep 3
    
    local dns_test_passed=false
    if [[ "$dns_mode_choice" == "2" ]]; then
        if dns_runtime_health_check "cn"; then
            echo -e "${gl_lv}  ✅ DNS解析正常（国内链路）${gl_bai}"
            dns_test_passed=true
        fi
    else
        if dns_runtime_health_check "global"; then
            echo -e "${gl_lv}  ✅ DNS解析正常（国际链路）${gl_bai}"
            dns_test_passed=true
        fi
    fi
    
    # 如果所有测试都失败
    if [ "$dns_test_passed" = false ]; then
        echo -e "${gl_hong}  ❌ DNS测试未通过，触发自动回滚以避免遗留隐患${gl_bai}"
        auto_rollback_dns_purify
        # 回滚后再次校验，确保脚本退出时机器仍可解析
        local post_rollback_ok=false
        if dns_runtime_health_check "global" || dns_runtime_health_check "cn"; then
            post_rollback_ok=true
        fi
        if [ "$post_rollback_ok" = true ]; then
            echo -e "${gl_lv}  ✅ 回滚后DNS健康校验通过${gl_bai}"
        else
            echo -e "${gl_huang}  ⚠️  回滚后DNS仍异常，请检查上游网络/防火墙策略${gl_bai}"
        fi
        echo -e "${gl_huang}  已自动恢复执行前配置，请检查网络环境后重试${gl_bai}"
        break_end
        return 1
    fi
    echo ""

    # ==================== 生成回滚脚本 ====================
    cat > "$BACKUP_DIR/rollback.sh" << 'ROLLBACK_SCRIPT'
#!/bin/bash
# DNS配置回滚脚本
# 使用方法: bash rollback.sh

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  DNS配置回滚脚本"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

BACKUP_DIR="$(dirname "$0")"
PRE_STATE_DIR="$BACKUP_DIR/pre_state"

# 优先使用增强回滚（精确恢复执行前状态）
if [[ -d "$PRE_STATE_DIR" ]]; then
    echo "检测到增强备份元数据，正在精确恢复执行前状态..."

    restore_path_state() {
        local dst="$1"
        local key="$2"
        rm -f "$dst" 2>/dev/null || true
        if [[ -e "$PRE_STATE_DIR/$key" || -L "$PRE_STATE_DIR/$key" ]]; then
            mkdir -p "$(dirname "$dst")"
            cp -a "$PRE_STATE_DIR/$key" "$dst" 2>/dev/null || true
        elif [[ -f "$PRE_STATE_DIR/$key.absent" ]]; then
            rm -f "$dst" 2>/dev/null || true
        fi
    }

    # 恢复配置文件（resolv.conf 延后，避免悬空链接）
    restore_path_state "/etc/dhcp/dhclient.conf" "dhclient.conf"
    restore_path_state "/etc/network/interfaces" "interfaces"
    restore_path_state "/etc/systemd/resolved.conf" "resolved.conf"
    restore_path_state "/etc/systemd/system/dns-purify-persist.service" "dns-purify-persist.service"
    restore_path_state "/usr/local/bin/dns-purify-apply.sh" "dns-purify-apply.sh"
    restore_path_state "/etc/systemd/system/systemd-resolved.service.d/dbus-fix.conf" "dbus-fix.conf"
    restore_path_state "/etc/NetworkManager/conf.d/99-dns-purify.conf" "nm-99-dns-purify.conf"

    if [[ -f "$PRE_STATE_DIR/ifup-resolved.exec" ]]; then
        case "$(cat "$PRE_STATE_DIR/ifup-resolved.exec" 2>/dev/null)" in
            executable)
                [[ -e /etc/network/if-up.d/resolved ]] && chmod +x /etc/network/if-up.d/resolved 2>/dev/null || true
                ;;
            not_executable)
                [[ -e /etc/network/if-up.d/resolved ]] && chmod -x /etc/network/if-up.d/resolved 2>/dev/null || true
                ;;
            absent)
                rm -f /etc/network/if-up.d/resolved 2>/dev/null || true
                ;;
        esac
    fi

    # 移除 networkd drop-in（扩展搜索所有可能路径）
    for search_dir in /etc/systemd/network /run/systemd/network /usr/lib/systemd/network; do
        for dropin_file in "$search_dir"/*.network.d/dns-purify-override.conf; do
            [[ -f "$dropin_file" ]] || continue
            rm -f "$dropin_file"
            rmdir "$(dirname "$dropin_file")" 2>/dev/null || true
        done
    done

    if [[ -f "$PRE_STATE_DIR/networkd-dropins.map" ]]; then
        while IFS='|' read -r restore_path restore_key; do
            [[ -n "$restore_path" && -n "$restore_key" ]] || continue
            [[ -f "$PRE_STATE_DIR/$restore_key" ]] || continue
            mkdir -p "$(dirname "$restore_path")"
            cp -a "$PRE_STATE_DIR/$restore_key" "$restore_path" 2>/dev/null || true
        done < "$PRE_STATE_DIR/networkd-dropins.map"
    fi

    # 重载 networkd/NM 使配置变更生效
    if systemctl is-active --quiet systemd-networkd 2>/dev/null; then
        networkctl reload 2>/dev/null || systemctl reload systemd-networkd 2>/dev/null || true
    fi
    if systemctl is-active --quiet NetworkManager 2>/dev/null; then
        systemctl reload NetworkManager 2>/dev/null || true
    fi

    systemctl daemon-reload 2>/dev/null || true

    dns_persist_was_enabled="false"
    [[ -f "$PRE_STATE_DIR/dns-persist.was-enabled" ]] && dns_persist_was_enabled=$(cat "$PRE_STATE_DIR/dns-persist.was-enabled" 2>/dev/null || echo "false")

    if [[ -e "$PRE_STATE_DIR/dns-purify-persist.service" || -L "$PRE_STATE_DIR/dns-purify-persist.service" ]]; then
        if [[ "$dns_persist_was_enabled" == "true" ]]; then
            systemctl enable dns-purify-persist.service 2>/dev/null || true
        else
            systemctl disable dns-purify-persist.service 2>/dev/null || true
        fi
    else
        systemctl disable dns-purify-persist.service 2>/dev/null || true
    fi

    had_resolvconf_pkg="false"
    [[ -f "$PRE_STATE_DIR/had-resolvconf.pkg" ]] && had_resolvconf_pkg=$(cat "$PRE_STATE_DIR/had-resolvconf.pkg" 2>/dev/null || echo "false")
    if [[ "$had_resolvconf_pkg" == "true" ]] && ! dpkg -s resolvconf >/dev/null 2>&1; then
        DEBIAN_FRONTEND=noninteractive apt-get install -y resolvconf >/dev/null 2>&1 || true
    fi

    # 先恢复 resolved 服务状态（在 resolv.conf 之前，避免悬空链接）
    resolved_enable_state="unknown"
    resolved_was_masked="false"
    resolved_was_active="false"
    [[ -f "$PRE_STATE_DIR/resolved.enable-state" ]] && resolved_enable_state=$(cat "$PRE_STATE_DIR/resolved.enable-state" 2>/dev/null || echo "unknown")
    # 兼容旧版快照
    if [[ "$resolved_enable_state" == "unknown" && -f "$PRE_STATE_DIR/resolved.was-enabled" ]]; then
        old_enabled=$(cat "$PRE_STATE_DIR/resolved.was-enabled" 2>/dev/null || echo "false")
        [[ "$old_enabled" == "true" ]] && resolved_enable_state="enabled" || resolved_enable_state="disabled"
    fi
    [[ -f "$PRE_STATE_DIR/resolved.was-masked" ]] && resolved_was_masked=$(cat "$PRE_STATE_DIR/resolved.was-masked" 2>/dev/null || echo "false")
    [[ -f "$PRE_STATE_DIR/resolved.was-active" ]] && resolved_was_active=$(cat "$PRE_STATE_DIR/resolved.was-active" 2>/dev/null || echo "false")

    if [[ "$resolved_was_masked" == "true" ]]; then
        systemctl mask systemd-resolved 2>/dev/null || true
        systemctl stop systemd-resolved 2>/dev/null || true
    else
        systemctl unmask systemd-resolved 2>/dev/null || true
        case "$resolved_enable_state" in
            enabled|enabled-runtime)
                systemctl enable systemd-resolved 2>/dev/null || true
                ;;
            static|indirect|generated)
                ;;
            *)
                systemctl disable systemd-resolved 2>/dev/null || true
                ;;
        esac

        if [[ "$resolved_was_active" == "true" ]]; then
            systemctl restart systemd-resolved 2>/dev/null || systemctl start systemd-resolved 2>/dev/null || true
            # 等待 stub 文件可用
            for wait_i in $(seq 1 5); do
                [[ -f /run/systemd/resolve/stub-resolv.conf ]] && break
                sleep 1
            done
        else
            systemctl stop systemd-resolved 2>/dev/null || true
        fi
    fi

    # 最后恢复 resolv.conf（此时 resolved 已恢复，stub 文件可用）
    if [[ -L "$PRE_STATE_DIR/resolv.conf" ]]; then
        backup_link=$(readlink "$PRE_STATE_DIR/resolv.conf" 2>/dev/null || echo "")
        if [[ "$backup_link" == *"stub-resolv.conf"* ]] && [[ ! -f /run/systemd/resolve/stub-resolv.conf ]]; then
            rm -f /etc/resolv.conf 2>/dev/null || true
            echo "nameserver 127.0.0.53" > /etc/resolv.conf 2>/dev/null || true
        else
            restore_path_state "/etc/resolv.conf" "resolv.conf"
        fi
    else
        restore_path_state "/etc/resolv.conf" "resolv.conf"
    fi

    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "✅ 回滚完成（增强模式）！"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    exit 0
fi

# ===== 旧版回滚（无 pre_state 目录时的兼容模式）=====

# 恢复 dhclient.conf
if [[ -f "$BACKUP_DIR/dhclient.conf.bak" ]]; then
    echo "恢复 dhclient.conf..."
    cp "$BACKUP_DIR/dhclient.conf.bak" /etc/dhcp/dhclient.conf
    echo "✅ 已恢复 dhclient.conf"
fi

# 恢复 interfaces
if [[ -f "$BACKUP_DIR/interfaces.bak" ]]; then
    echo "恢复 interfaces..."
    cp "$BACKUP_DIR/interfaces.bak" /etc/network/interfaces
    echo "✅ 已恢复 interfaces"
fi

# 恢复 resolved.conf
if [[ -f "$BACKUP_DIR/resolved.conf.bak" ]]; then
    echo "恢复 resolved.conf..."
    cp "$BACKUP_DIR/resolved.conf.bak" /etc/systemd/resolved.conf
    echo "✅ 已恢复 resolved.conf"
fi

# 移除DNS持久化服务
if [[ -f /etc/systemd/system/dns-purify-persist.service ]]; then
    echo "移除 DNS持久化服务..."
    systemctl disable dns-purify-persist.service 2>/dev/null || true
    rm -f /etc/systemd/system/dns-purify-persist.service
    echo "✅ 已移除 dns-purify-persist.service"
fi

# 移除DNS持久化脚本
if [[ -f /usr/local/bin/dns-purify-apply.sh ]]; then
    rm -f /usr/local/bin/dns-purify-apply.sh
    echo "✅ 已移除 dns-purify-apply.sh"
fi

# 移除 D-Bus 修复配置（仅删除本脚本创建的文件，不删整个目录）
if [[ -f /etc/systemd/system/systemd-resolved.service.d/dbus-fix.conf ]]; then
    rm -f /etc/systemd/system/systemd-resolved.service.d/dbus-fix.conf
    rmdir /etc/systemd/system/systemd-resolved.service.d 2>/dev/null || true
    echo "✅ 已移除 D-Bus 修复配置"
fi

# 移除 systemd-networkd DNS阻断 drop-in（扩展搜索路径）
for search_dir in /etc/systemd/network /run/systemd/network /usr/lib/systemd/network; do
    for dropin_dir in "$search_dir"/*.network.d; do
        if [[ -f "$dropin_dir/dns-purify-override.conf" ]]; then
            rm -f "$dropin_dir/dns-purify-override.conf"
            rmdir "$dropin_dir" 2>/dev/null || true
            echo "✅ 已移除 systemd-networkd DNS阻断配置"
        fi
    done
done

# 移除 NetworkManager DNS配置
if [[ -f /etc/NetworkManager/conf.d/99-dns-purify.conf ]]; then
    rm -f /etc/NetworkManager/conf.d/99-dns-purify.conf
    echo "✅ 已移除 NetworkManager DNS配置"
fi

# 恢复 if-up.d/resolved 可执行权限
if [[ -f /etc/network/if-up.d/resolved ]] && [[ ! -x /etc/network/if-up.d/resolved ]]; then
    echo "恢复 if-up.d/resolved 可执行权限..."
    chmod +x /etc/network/if-up.d/resolved
    echo "✅ 已恢复 if-up.d/resolved 可执行权限"
fi

# 重新加载 systemd
systemctl daemon-reload 2>/dev/null || true

# 重载 networkd/NM
if systemctl is-active --quiet systemd-networkd 2>/dev/null; then
    networkctl reload 2>/dev/null || systemctl reload systemd-networkd 2>/dev/null || true
fi
if systemctl is-active --quiet NetworkManager 2>/dev/null; then
    systemctl reload NetworkManager 2>/dev/null || true
fi

# 重新加载 systemd-resolved
echo "重新加载 systemd-resolved..."
systemctl reload-or-restart systemd-resolved 2>/dev/null || true
echo "✅ systemd-resolved 已重新加载"

# 恢复 resolv.conf（在 resolved 重启之后，保留软链接特性）
if [[ -f "$BACKUP_DIR/resolv.conf.bak" ]]; then
    echo "恢复 resolv.conf..."
    rm -f /etc/resolv.conf
    cp -a "$BACKUP_DIR/resolv.conf.bak" /etc/resolv.conf
    echo "✅ 已恢复 resolv.conf"
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "✅ 回滚完成！"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
ROLLBACK_SCRIPT

    chmod +x "$BACKUP_DIR/rollback.sh"

    # 显示备份信息
    echo -e "${gl_kjlan}备份与回滚信息：${gl_bai}"
    echo "  所有原始配置已备份到："
    echo "  $BACKUP_DIR"
    echo ""
    echo -e "${gl_huang}如需回滚，执行：${gl_bai}"
    echo "  bash $BACKUP_DIR/rollback.sh"
    echo ""

    echo -e "${gl_lv}DNS净化脚本执行完成${gl_bai}"
    echo "原作者：NSdesk"
    echo "安全增强：SSH防断连优化"
    echo "更多信息：https://www.nodeseek.com/space/23129#/general"
    echo "════════════════════════════════════════════════════════"
    echo ""

    break_end
}

#=============================================================================
# Realm 转发首连超时修复（专项优化）
#=============================================================================

realm_fix_timeout() {
    clear
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo -e "${gl_kjlan}   Realm 转发首连超时修复（针对跨境线路优化）${gl_bai}"
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo ""
    echo -e "${gl_huang}功能说明：${gl_bai}"
    echo "  • 连接跟踪模块加载 + 容量扩展（转发必需）"
    echo "  • 强制 IPv4 + nodelay + reuse_port（优化 Realm 配置）"
    echo "  • 提升 realm.service 文件句柄限制"
    echo ""
    echo -e "${gl_kjlan}已由其他功能覆盖（本功能不再重复设置）：${gl_bai}"
    echo "  • MSS 钳制 → 功能3/4已配置"
    echo "  • DNS 管理 → 功能5已配置"
    echo "  • tcp_fin_timeout / tcp_fastopen → 功能3已配置"
    echo ""
    if [ "$AUTO_MODE" = "1" ]; then
        confirm=y
    else
        read -e -p "是否继续执行修复？(y/n): " confirm
    fi

    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        echo -e "${gl_huang}已取消操作${gl_bai}"
        return
    fi

    # 检查 root 权限
    if [[ ${EUID:-0} -ne 0 ]]; then
        echo -e "${gl_hong}错误：请以 root 身份运行（sudo -i 或 sudo bash）${gl_bai}"
        return 1
    fi

    # 备份目录
    BACKUP_DIR="/root/.realm_fix_backup/$(date +%Y%m%d-%H%M%S)"
    mkdir -p "$BACKUP_DIR"
    echo -e "${gl_lv}[1/4] 创建备份目录：$BACKUP_DIR${gl_bai}"

    # 加载并持久化 nf_conntrack
    echo -e "${gl_lv}[2/4] 加载/持久化 nf_conntrack（连接跟踪）${gl_bai}"
    if command -v modprobe >/dev/null 2>&1; then
        modprobe nf_conntrack 2>/dev/null || true
    fi
    mkdir -p /etc/modules-load.d
    if ! grep -q '^nf_conntrack$' /etc/modules-load.d/conntrack.conf 2>/dev/null; then
        echo nf_conntrack >> /etc/modules-load.d/conntrack.conf
    fi

    # 写入 Realm 专属 sysctl 配置（仅 conntrack_max，其余由功能3管理）
    cat >/etc/sysctl.d/60-realm-tune.conf <<'SYSC'
# Realm 转发专属优化（仅设置功能3未覆盖的参数）
# tcp_fin_timeout / tcp_fastopen 由功能3的 99-net-tcp-tune.conf 统一管理

# 连接跟踪容量（转发必需）
net.netfilter.nf_conntrack_max = 262144
SYSC
    sysctl --system >/dev/null 2>&1
    echo -e "${gl_lv}  ✓ nf_conntrack_max = 262144 已生效${gl_bai}"

    # 修改 Realm 配置
    echo -e "${gl_lv}[3/4] 优化 Realm 配置（IPv4 + nodelay + reuse_port）${gl_bai}"
    realm_cfg="/etc/realm/config.json"
    if [[ -f "$realm_cfg" ]]; then
        cp -a "$realm_cfg" "$BACKUP_DIR/"

        if command -v jq >/dev/null 2>&1; then
            tmpfile=$(mktemp)
            jq '.resolve = "ipv4" | .nodelay = true | .reuse_port = true' \
                "$realm_cfg" >"$tmpfile" && mv "$tmpfile" "$realm_cfg"
        else
            echo -e "${gl_huang}  未安装 jq，使用文本方式修改（推荐安装 jq）${gl_bai}"
            if ! grep -q '"resolve"' "$realm_cfg"; then
                sed -i.bak '0,/{/s//{\n  "resolve": "ipv4",/' "$realm_cfg" || true
            fi
            if ! grep -q '"nodelay"' "$realm_cfg"; then
                sed -i.bak '0,/{/s//{\n  "nodelay": true,/' "$realm_cfg" || true
            fi
            if ! grep -q '"reuse_port"' "$realm_cfg"; then
                sed -i.bak '0,/{/s//{\n  "reuse_port": true,/' "$realm_cfg" || true
            fi
        fi

        # 统一用文本替换确保 IPv6 监听改为 IPv4
        sed -i.bak -E 's/"listen"\s*:\s*":::([0-9]+)"/"listen": "0.0.0.0:\1"/g' "$realm_cfg" 2>/dev/null || true
        sed -i.bak -E 's/"listen"\s*:\s*"\[::\]:([0-9]+)"/"listen": "0.0.0.0:\1"/g' "$realm_cfg" 2>/dev/null || true
        sed -i.bak 's/:::/0.0.0.0:/g' "$realm_cfg" 2>/dev/null || true
        echo -e "${gl_lv}  ✓ Realm 配置已优化${gl_bai}"
    else
        echo -e "${gl_huang}  未找到 $realm_cfg，跳过 Realm 配置修改${gl_bai}"
    fi

    # realm.service 文件句柄限制
    echo -e "${gl_lv}[4/4] 提升 realm.service 文件句柄限制${gl_bai}"
    if systemctl list-unit-files 2>/dev/null | grep -q '^realm\.service'; then
        mkdir -p /etc/systemd/system/realm.service.d
        cat >/etc/systemd/system/realm.service.d/override.conf <<'OVR'
[Service]
LimitNOFILE=1048576
OVR
        systemctl daemon-reload
        systemctl restart realm 2>/dev/null || echo -e "${gl_huang}  ⚠ realm 重启失败，请手动检查${gl_bai}"
        echo -e "${gl_lv}  ✓ LimitNOFILE=1048576 已生效${gl_bai}"
    else
        echo -e "${gl_huang}  未发现 realm.service，跳过${gl_bai}"
    fi

    echo ""
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo -e "${gl_lv}✅ Realm 优化完成！${gl_bai}"
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo ""
    echo -e "${gl_huang}📋 备份位置：${gl_bai}$BACKUP_DIR"
    echo ""
    echo -e "${gl_huang}🔍 快速验证：${gl_bai}"
    echo "  • Realm 监听：  ss -tlnp | grep realm"
    echo "  • conntrack：   sysctl net.netfilter.nf_conntrack_max"
    echo "  • Realm 配置：  cat /etc/realm/config.json | grep -E 'resolve|nodelay|reuse_port'"
    echo ""
    echo -e "${gl_lv}💯 重启服务器后所有配置依然生效，无需重复执行！${gl_bai}"
    echo ""
}

#=============================================================================
# 内核参数优化 - 主菜单
#=============================================================================

Kernel_optimize() {
    while true; do
        clear
        echo "Linux系统内核参数优化 - Reality专用调优"
        echo "------------------------------------------------"
        echo "针对 VLESS Reality 节点深度优化"
        echo -e "${gl_huang}提示: ${gl_bai}所有方案都是临时生效（重启后自动还原）"
        echo "--------------------"
        echo "1. 星辰大海ヾ优化：  13万文件描述符，16MB缓冲区，兼容CAKE"
        echo "                      适用：≥2GB内存，推荐使用"
        echo "                      评分：⭐⭐⭐⭐⭐ (24/25分) 🏆"
        echo ""
        echo "2. Reality终极优化：  50万文件描述符，12MB缓冲区"
        echo "                      适用：≥2GB内存，性能+5-10%（推荐）"
        echo "                      评分：⭐⭐⭐⭐⭐ (24/25分) 🏆"
        echo ""
        echo "3. 低配优化模式：     6.5万文件描述符，8MB缓冲区"
        echo "                      适用：512MB-1GB内存，稳定优先"
        echo "                      评分：⭐⭐⭐⭐ (20/25分) 💡 1GB内存推荐"
        echo ""
        echo "4. 星辰大海原始版：   100万文件描述符，16MB缓冲区，强制fq"
        echo "                      适用：≥4GB内存，对比测试用"
        echo "                      评分：⭐⭐⭐⭐⭐ (23/25分) 🧪 测试对比"
        echo "--------------------"
        echo "0. 返回主菜单"
        echo "--------------------"
        read -e -p "请输入你的选择: " sub_choice
        case $sub_choice in
            1)
                cd ~
                clear
                optimize_xinchendahai
                ;;
            2)
                cd ~
                clear
                optimize_reality_ultimate
                ;;
            3)
                cd ~
                clear
                optimize_low_spec
                ;;
            4)
                cd ~
                clear
                optimize_xinchendahai_original
                ;;
            0)
                break
                ;;
            *)
                echo "无效的输入!"
                sleep 1
                ;;
        esac
        break_end
    done
}

run_speedtest() {
    while true; do
        clear
        echo -e "${gl_kjlan}=== 服务器带宽测试 ===${gl_bai}"
        echo ""
        
        # 检测 CPU 架构
        local cpu_arch=$(uname -m)
        echo "检测到系统架构: ${gl_huang}${cpu_arch}${gl_bai}"
        echo ""
        
        # 检查并安装 speedtest
        if ! command -v speedtest &>/dev/null; then
            echo "Speedtest 未安装，正在下载安装..."
            echo "------------------------------------------------"
            echo ""
            
            local download_url
            local tarball_name
            
            case "$cpu_arch" in
                x86_64)
                    download_url="https://install.speedtest.net/app/cli/ookla-speedtest-1.2.0-linux-x86_64.tgz"
                    tarball_name="ookla-speedtest-1.2.0-linux-x86_64.tgz"
                    echo "使用 AMD64 架构版本..."
                    ;;
                aarch64)
                    download_url="https://install.speedtest.net/app/cli/ookla-speedtest-1.2.0-linux-aarch64.tgz"
                    tarball_name="speedtest.tgz"
                    echo "使用 ARM64 架构版本..."
                    ;;
                *)
                    echo -e "${gl_hong}错误: 不支持的架构 ${cpu_arch}${gl_bai}"
                    echo "目前仅支持 x86_64 和 aarch64 架构"
                    echo ""
                    break_end
                    return 1
                    ;;
            esac
            
            cd /tmp || {
                echo -e "${gl_hong}错误: 无法切换到 /tmp 目录${gl_bai}"
                break_end
                return 1
            }
            
            echo "正在下载..."
            if [ "$cpu_arch" = "aarch64" ]; then
                curl -Lo "$tarball_name" "$download_url"
            else
                wget -q "$download_url"
            fi
            
            if [ $? -ne 0 ]; then
                echo -e "${gl_hong}下载失败！${gl_bai}"
                break_end
                return 1
            fi
            
            echo "正在解压..."
            tar -xzf "$tarball_name"
            
            if [ $? -ne 0 ]; then
                echo -e "${gl_hong}解压失败！${gl_bai}"
                rm -f "$tarball_name"
                break_end
                return 1
            fi
            
            mv speedtest /usr/local/bin/
            rm -f "$tarball_name"
            
            echo -e "${gl_lv}✅ Speedtest 安装成功！${gl_bai}"
            echo ""
        else
            echo -e "${gl_lv}✅ Speedtest 已安装${gl_bai}"
        fi
        
        echo ""
        echo -e "${gl_kjlan}请选择测速模式：${gl_bai}"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "1. 自动测速"
        echo "2. 手动选择服务器 ⭐ 推荐"
        echo ""
        echo "0. 返回主菜单"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo ""
        
        read -e -p "请输入选择 [1]: " speed_choice
        speed_choice=${speed_choice:-1}
        
        case "$speed_choice" in
            1)
                # 自动测速（使用智能重试逻辑）
                echo ""
                echo -e "${gl_zi}正在搜索附近测速服务器...${gl_bai}"
                
                # 获取附近服务器列表
                local servers_list=$(speedtest --accept-license --servers 2>/dev/null | sed -nE 's/^[[:space:]]*([0-9]+).*/\1/p' | head -n 10)
                
                if [ -z "$servers_list" ]; then
                    echo -e "${gl_huang}无法获取服务器列表，使用自动选择...${gl_bai}"
                    servers_list="auto"
                else
                    local server_count=$(echo "$servers_list" | wc -l)
                    echo -e "${gl_lv}✅ 找到 ${server_count} 个附近服务器${gl_bai}"
                fi
                echo ""
                
                local speedtest_output=""
                local test_success=false
                local attempt=0
                local max_attempts=5
                
                for server_id in $servers_list; do
                    attempt=$((attempt + 1))
                    
                    if [ $attempt -gt $max_attempts ]; then
                        echo -e "${gl_huang}已尝试 ${max_attempts} 个服务器，停止尝试${gl_bai}"
                        break
                    fi
                    
                    if [ "$server_id" = "auto" ]; then
                        echo -e "${gl_zi}[尝试 ${attempt}] 自动选择最近服务器...${gl_bai}"
                        echo "------------------------------------------------"
                        speedtest --accept-license
                        test_success=true
                        break
                    else
                        echo -e "${gl_zi}[尝试 ${attempt}] 测试服务器 #${server_id}...${gl_bai}"
                        echo "------------------------------------------------"
                        speedtest_output=$(speedtest --accept-license --server-id="$server_id" 2>&1)
                        echo "$speedtest_output"
                        echo ""
                        
                        # 检查是否成功
                        if echo "$speedtest_output" | grep -q "Download:" && ! echo "$speedtest_output" | grep -qi "FAILED\|error"; then
                            echo -e "${gl_lv}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
                            echo -e "${gl_lv}✅ 测速成功！${gl_bai}"
                            echo -e "${gl_lv}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
                            test_success=true
                            break
                        else
                            echo -e "${gl_huang}⚠️ 此服务器测速失败，尝试下一个...${gl_bai}"
                            echo ""
                        fi
                    fi
                done
                
                if [ "$test_success" = false ]; then
                    echo ""
                    echo -e "${gl_hong}❌ 所有服务器测速均失败${gl_bai}"
                    echo -e "${gl_zi}建议使用「手动选择服务器」模式${gl_bai}"
                fi
                
                echo ""
                break_end
                ;;
            2)
                # 手动选择服务器
                echo ""
                echo -e "${gl_zi}正在获取附近服务器列表...${gl_bai}"
                echo ""
                
                local server_list_output=$(speedtest --accept-license --servers 2>/dev/null | head -n 15)
                
                if [ -z "$server_list_output" ]; then
                    echo -e "${gl_hong}❌ 无法获取服务器列表${gl_bai}"
                    echo ""
                    break_end
                    continue
                fi
                
                echo -e "${gl_kjlan}附近的测速服务器列表：${gl_bai}"
                echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                echo "$server_list_output"
                echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                echo ""
                echo -e "${gl_zi}💡 提示：ID 列的数字就是服务器ID${gl_bai}"
                echo ""
                
                local server_id=""
                while true; do
                    read -e -p "$(echo -e "${gl_huang}请输入服务器ID（纯数字，输入0返回）: ${gl_bai}")" server_id
                    
                    if [ "$server_id" = "0" ]; then
                        break
                    elif [[ "$server_id" =~ ^[0-9]+$ ]]; then
                        echo ""
                        echo -e "${gl_huang}正在使用服务器 #${server_id} 测速...${gl_bai}"
                        echo "------------------------------------------------"
                        echo ""
                        
                        speedtest --accept-license --server-id="$server_id"
                        
                        echo ""
                        echo "------------------------------------------------"
                        break_end
                        break
                    else
                        echo -e "${gl_hong}❌ 无效输入，请输入纯数字的服务器ID${gl_bai}"
                    fi
                done
                ;;
            0)
                return 0
                ;;
            *)
                echo -e "${gl_hong}无效选择${gl_bai}"
                sleep 1
                ;;
        esac
    done
}

run_backtrace() {
    clear
    echo -e "${gl_kjlan}=== 三网回程路由测试 ===${gl_bai}"
    echo ""
    echo "正在运行三网回程路由测试脚本..."
    echo "------------------------------------------------"
    echo ""

    # 执行三网回程路由测试脚本
    if ! run_remote_script "https://raw.githubusercontent.com/ludashi2020/backtrace/main/install.sh" sh; then
        echo -e "${gl_hong}❌ 脚本执行失败${gl_bai}"
        break_end
        return 1
    fi

    echo ""
    echo "------------------------------------------------"
    break_end
}

run_ns_detect() {
    clear
    echo -e "${gl_kjlan}=== NS一键检测脚本 ===${gl_bai}"
    echo ""
    echo "正在运行 NS 一键检测脚本..."
    echo "------------------------------------------------"
    echo ""

    # 执行 NS 一键检测脚本
    if ! run_remote_script "https://run.NodeQuality.com" bash; then
        echo -e "${gl_hong}❌ 脚本执行失败${gl_bai}"
        break_end
        return 1
    fi

    echo ""
    echo "------------------------------------------------"
    break_end
}

run_ip_quality_check() {
    clear
    echo -e "${gl_kjlan}=== IP质量检测 ===${gl_bai}"
    echo ""
    echo "正在运行 IP 质量检测脚本（IPv4 + IPv6）..."
    echo "------------------------------------------------"
    echo ""

    # 执行 IP 质量检测脚本
    if ! run_remote_script "https://IP.Check.Place" bash; then
        echo -e "${gl_hong}❌ 脚本执行失败${gl_bai}"
        break_end
        return 1
    fi

    echo ""
    echo "------------------------------------------------"
    break_end
}

run_ip_quality_check_ipv4() {
    clear
    echo -e "${gl_kjlan}=== IP质量检测 - 仅IPv4 ===${gl_bai}"
    echo ""
    echo "正在运行 IP 质量检测脚本（仅 IPv4）..."
    echo "------------------------------------------------"
    echo ""

    # 执行 IP 质量检测脚本 - 仅 IPv4
    if ! run_remote_script "https://IP.Check.Place" bash -4; then
        echo -e "${gl_hong}❌ 脚本执行失败${gl_bai}"
        break_end
        return 1
    fi

    echo ""
    echo "------------------------------------------------"
    break_end
}

run_network_latency_check() {
    clear
    echo -e "${gl_kjlan}=== 网络延迟质量检测 ===${gl_bai}"
    echo ""
    echo "正在运行网络延迟质量检测脚本..."
    echo "------------------------------------------------"
    echo ""

    # 执行网络延迟质量检测脚本
    if ! run_remote_script "https://Check.Place" bash -N; then
        echo -e "${gl_hong}❌ 脚本执行失败${gl_bai}"
        break_end
        return 1
    fi

    echo ""
    echo "------------------------------------------------"
    break_end
}

run_international_speed_test() {
    clear
    echo -e "${gl_kjlan}=== 国际互联速度测试 ===${gl_bai}"
    echo ""
    echo "正在下载并运行国际互联速度测试脚本..."
    echo "------------------------------------------------"
    echo ""

    # 切换到临时目录
    cd /tmp || {
        echo -e "${gl_hong}错误: 无法切换到 /tmp 目录${gl_bai}"
        break_end
        return 1
    }

    # 下载脚本
    echo "正在下载脚本..."
    wget https://raw.githubusercontent.com/Cd1s/network-latency-tester/main/latency.sh

    if [ $? -ne 0 ]; then
        echo -e "${gl_hong}下载失败！${gl_bai}"
        break_end
        return 1
    fi

    # 添加执行权限
    chmod +x latency.sh

    # 运行测试
    echo ""
    echo "开始测试..."
    echo "------------------------------------------------"
    echo ""
    ./latency.sh

    # 清理临时文件
    rm -f latency.sh

    echo ""
    echo "------------------------------------------------"
    break_end
}

#=============================================================================
# iperf3 单线程网络测试
#=============================================================================

iperf3_single_thread_test() {
    clear
    echo -e "${gl_zi}╔════════════════════════════════════════════╗${gl_bai}"
    echo -e "${gl_zi}║       iperf3 单线程网络性能测试            ║${gl_bai}"
    echo -e "${gl_zi}╚════════════════════════════════════════════╝${gl_bai}"
    echo ""
    
    # 检查 iperf3 是否安装
    if ! command -v iperf3 &>/dev/null; then
        echo -e "${gl_huang}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
        echo -e "${gl_huang}检测到 iperf3 未安装，正在自动安装...${gl_bai}"
        echo -e "${gl_huang}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
        echo ""
        
        if command -v apt-get &>/dev/null || command -v apt &>/dev/null; then
            echo "步骤 1/2: 更新软件包列表..."
            apt-get update

            echo ""
            echo "步骤 2/2: 安装 iperf3..."
            apt-get install -y iperf3
            
            if [ $? -ne 0 ]; then
                echo ""
                echo -e "${gl_hong}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
                echo -e "${gl_hong}iperf3 安装失败！${gl_bai}"
                echo -e "${gl_hong}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
                break_end
                return 1
            fi
        else
            echo -e "${gl_hong}错误: 不支持的包管理器（仅支持 apt）${gl_bai}"
            break_end
            return 1
        fi
        
        echo ""
        echo -e "${gl_lv}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
        echo -e "${gl_lv}✓ iperf3 安装成功！${gl_bai}"
        echo -e "${gl_lv}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
        echo ""
    fi
    
    # 输入目标服务器
    echo -e "${gl_kjlan}[步骤 1/3] 输入目标服务器${gl_bai}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    read -e -p "请输入目标服务器 IP 或域名: " target_host
    
    if [ -z "$target_host" ]; then
        echo -e "${gl_hong}错误: 目标服务器不能为空！${gl_bai}"
        break_end
        return 1
    fi
    
    echo ""
    
    # 选择测试方向
    echo -e "${gl_kjlan}[步骤 2/3] 选择测试方向${gl_bai}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "1. 上传测试（本机 → 远程服务器）"
    echo "2. 下载测试（远程服务器 → 本机）"
    echo ""
    read -e -p "请选择测试方向 [1-2]: " direction_choice
    
    case "$direction_choice" in
        1)
            direction_flag=""
            direction_text="上行（本机 → ${target_host}）"
            ;;
        2)
            direction_flag="-R"
            direction_text="下行（${target_host} → 本机）"
            ;;
        *)
            echo -e "${gl_hong}无效的选择，使用默认值: 上传测试${gl_bai}"
            direction_flag=""
            direction_text="上行（本机 → ${target_host}）"
            ;;
    esac
    
    echo ""
    
    # 输入测试时长
    echo -e "${gl_kjlan}[步骤 3/3] 设置测试时长${gl_bai}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "建议: 30-120 秒（默认 60 秒）"
    echo ""
    read -e -p "请输入测试时长（秒）[60]: " test_duration
    test_duration=${test_duration:-60}
    
    # 验证时长是否为数字
    if ! [[ "$test_duration" =~ ^[0-9]+$ ]]; then
        echo -e "${gl_huang}警告: 无效的时长，使用默认值 60 秒${gl_bai}"
        test_duration=60
    fi
    
    # 限制时长范围
    if [ "$test_duration" -lt 1 ]; then
        test_duration=1
    elif [ "$test_duration" -gt 3600 ]; then
        echo -e "${gl_huang}警告: 时长过长，限制为 3600 秒${gl_bai}"
        test_duration=3600
    fi
    
    echo ""
    echo -e "${gl_lv}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo -e "${gl_kjlan}测试配置确认：${gl_bai}"
    echo "  目标服务器: ${target_host}"
    echo "  测试方向: ${direction_text}"
    echo "  测试时长: ${test_duration} 秒"
    echo -e "${gl_lv}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo ""
    
    # 测试连通性
    echo -e "${gl_huang}正在测试连通性...${gl_bai}"
    if ! ping -c 2 -W 3 "$target_host" &>/dev/null; then
        echo -e "${gl_hong}警告: 无法 ping 通目标服务器，但仍尝试 iperf3 测试...${gl_bai}"
    else
        echo -e "${gl_lv}✓ 目标服务器可达${gl_bai}"
    fi
    
    echo ""
    echo -e "${gl_kjlan}正在执行 iperf3 测试，请稍候...${gl_bai}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    
    # 执行 iperf3 测试并保存输出
    local test_output=$(mktemp)
    iperf3 -c "$target_host" -P 1 $direction_flag -t "$test_duration" -f m 2>&1 | tee "$test_output"
    local exit_code=$?
    
    echo ""
    
    # 检查是否成功
    if [ $exit_code -ne 0 ]; then
        echo -e "${gl_hong}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
        echo -e "${gl_hong}测试失败！${gl_bai}"
        echo ""
        echo "可能的原因："
        echo "  1. 目标服务器未运行 iperf3 服务（需要执行: iperf3 -s）"
        echo "  2. 防火墙阻止了连接（默认端口 5201）"
        echo "  3. 网络连接问题"
        echo -e "${gl_hong}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
        rm -f "$test_output"
        break_end
        return 1
    fi
    
    # 解析测试结果
    echo -e "${gl_lv}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo -e "${gl_zi}╔════════════════════════════════════════════╗${gl_bai}"
    echo -e "${gl_zi}║           测 试 结 果 汇 总                ║${gl_bai}"
    echo -e "${gl_zi}╚════════════════════════════════════════════╝${gl_bai}"
    echo ""
    
    # 提取关键指标
    local bandwidth=$(grep "sender\|receiver" "$test_output" | tail -1 | awk '{print $7, $8}')
    local transfer=$(grep "sender\|receiver" "$test_output" | tail -1 | awk '{print $5, $6}')
    local retrans=$(grep "sender" "$test_output" | tail -1 | awk '{print $9}')
    
    echo -e "${gl_kjlan}[测试信息]${gl_bai}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "  目标服务器: ${target_host}"
    echo "  测试方向: ${direction_text}"
    echo "  测试时长: ${test_duration} 秒"
    echo "  测试线程: 1"
    echo ""
    
    echo -e "${gl_kjlan}[性能指标]${gl_bai}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
    if [ -n "$bandwidth" ]; then
        echo "  平均带宽: ${bandwidth}"
    else
        echo "  平均带宽: 无法获取"
    fi
    
    if [ -n "$transfer" ]; then
        echo "  总传输量: ${transfer}"
    else
        echo "  总传输量: 无法获取"
    fi
    
    if [ -n "$retrans" ] && [ "$retrans" != "" ]; then
        echo "  重传次数: ${retrans}"
        # 简单评价
        if [ "$retrans" -eq 0 ]; then
            echo -e "  连接质量: ${gl_lv}优秀（无重传）${gl_bai}"
        elif [ "$retrans" -lt 100 ]; then
            echo -e "  连接质量: ${gl_lv}良好${gl_bai}"
        elif [ "$retrans" -lt 1000 ]; then
            echo -e "  连接质量: ${gl_huang}一般（重传偏多）${gl_bai}"
        else
            echo -e "  连接质量: ${gl_hong}较差（重传过多）${gl_bai}"
        fi
    fi
    
    echo ""
    echo -e "${gl_lv}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo -e "${gl_lv}✓ 测试完成${gl_bai}"
    echo -e "${gl_lv}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    
    # 清理临时文件
    rm -f "$test_output"
    
    echo ""
    break_end
}

#=============================================================================
# AI 代理服务子菜单
#=============================================================================

ai_proxy_menu() {
    while true; do
        clear
        echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
        echo -e "${gl_kjlan}  AI 代理服务工具箱${gl_bai}"
        echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
        echo ""
        echo "1. Antigravity Claude Proxy 部署管理"
        echo "2. Open WebUI 部署管理"
        echo "3. CRS 部署管理 (多账户中转/拼车)"
        echo "4. Fuclaude 部署管理 (Claude网页版共享)"
        echo "5. Sub2API 部署管理"
        echo "6. Caddy 多域名反代"
        echo "7. OpenClaw 部署管理 (AI多渠道消息网关)"
        echo "8. OpenAI Responses API 转换代理"
        echo ""
        echo "0. 返回主菜单"
        echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"

        read -e -p "请选择操作 [0-8]: " choice

        case $choice in
            1)
                manage_ag_proxy
                ;;
            2)
                manage_open_webui
                ;;
            3)
                manage_crs
                ;;
            4)
                manage_fuclaude
                ;;
            5)
                manage_sub2api
                ;;
            6)
                manage_caddy
                ;;
            7)
                manage_openclaw
                ;;
            8)
                manage_resp_proxy
                ;;
            0)
                return
                ;;
            *)
                echo "无效选择"
                sleep 1
                ;;
        esac
    done
}

#=============================================================================
#=============================================================================
# 一键全自动优化
#=============================================================================

one_click_optimize() {
    clear
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo -e "${gl_kjlan}   ⭐ 一键全自动优化 (BBR v3 + 网络调优)${gl_bai}"
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo ""

    # 检测当前是否已运行 XanMod 内核
    local xanmod_running=0
    if uname -r | grep -qi 'xanmod'; then
        xanmod_running=1
    fi

    if [ $xanmod_running -eq 0 ]; then
        # ===== 阶段1：安装内核 =====
        echo -e "${gl_huang}▶ 阶段 1/2：安装 XanMod + BBR v3 内核${gl_bai}"
        echo ""
        echo "安装完成后需要重启服务器"
        echo "重启后再次执行 66 即可进入阶段2（全自动优化）"
        echo ""

        install_xanmod_kernel
        if [ $? -eq 0 ]; then
            echo ""
            echo -e "${gl_lv}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
            echo -e "${gl_lv}  ✅ 内核安装完成！${gl_bai}"
            echo -e "${gl_lv}  重启后执行 66 继续自动优化${gl_bai}"
            echo -e "${gl_lv}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
            echo ""
            server_reboot
        fi
    else
        # ===== 阶段2：全自动优化 =====
        echo -e "${gl_lv}✅ 检测到 XanMod 内核已运行：$(uname -r)${gl_bai}"
        echo ""
        echo -e "${gl_huang}▶ 阶段 2/2：全自动网络优化${gl_bai}"
        echo "将依次执行："
        echo "  [1/5] 功能3 - BBR 直连优化（自动检测带宽）"
        echo "  [2/5] 功能4 - MTU/MSS 优化（自动检测+保守方案）"
        echo "  [3/5] 功能5 - DNS 净化（纯国外模式）"
        echo "  [4/5] 功能6 - Realm 转发修复"
        echo "  [5/5] 功能8 - 永久禁用 IPv6"
        echo ""
        sleep 3

        AUTO_MODE=1

        echo -e "${gl_kjlan}━━━━━━ [1/5] BBR 直连优化 ━━━━━━${gl_bai}"
        bbr_configure_direct

        echo ""
        echo -e "${gl_kjlan}━━━━━━ [2/5] MTU/MSS 优化 ━━━━━━${gl_bai}"
        mtu_mss_optimization

        echo ""
        echo -e "${gl_kjlan}━━━━━━ [3/5] DNS 净化 ━━━━━━${gl_bai}"
        dns_purify_and_harden

        echo ""
        echo -e "${gl_kjlan}━━━━━━ [4/5] Realm 转发修复 ━━━━━━${gl_bai}"
        realm_fix_timeout

        AUTO_MODE=""

        echo ""
        echo -e "${gl_kjlan}━━━━━━ [5/5] 禁用 IPv6（可选） ━━━━━━${gl_bai}"
        read -e -p "$(echo -e "${gl_huang}是否永久禁用 IPv6？(Y/N) [Y]: ${gl_bai}")" ipv6_choice
        ipv6_choice=${ipv6_choice:-Y}
        if [[ "$ipv6_choice" =~ ^[Yy]$ ]]; then
            AUTO_MODE=1
            disable_ipv6_permanent
            AUTO_MODE=""
        else
            echo -e "${gl_huang}已跳过 IPv6 禁用${gl_bai}"
        fi

        echo ""
        echo -e "${gl_lv}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
        echo -e "${gl_lv}  ✅ 全部优化完成！${gl_bai}"
        echo -e "${gl_lv}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
        echo ""
        break_end
    fi
}

# 主菜单
#=============================================================================

show_main_menu() {
    clear
    check_bbr_status
    local is_installed=$?

    echo ""
    local box_width=50
    local inner=$((box_width - 2))
    echo -e "${gl_zi}╔$(printf '═%.0s' $(seq 1 $inner))╗${gl_bai}"
    echo -e "${gl_zi}║ $(format_fixed_width "BBR v3 终极优化脚本 - Ultimate Edition" $((inner - 2))) ║${gl_bai}"
    echo -e "${gl_zi}║ $(format_fixed_width "version ${SCRIPT_VERSION}" $((inner - 2))) ║${gl_bai}"
    if [ -n "$SCRIPT_LAST_UPDATE" ]; then
        echo -e "${gl_zi}║ ${gl_huang}$(format_fixed_width "更新: ${SCRIPT_LAST_UPDATE}" $((inner - 2)))${gl_zi} ║${gl_bai}"
    fi
    echo -e "${gl_zi}╚$(printf '═%.0s' $(seq 1 $inner))╝${gl_bai}"
    echo ""
    echo -e "${gl_kjlan}━━━━━━━━━━━━ 核心功能 ━━━━━━━━━━━━${gl_bai}"
    echo -e "${gl_kjlan}[内核管理]${gl_bai}"
    echo "1. 安装/更新 XanMod 内核 + BBR v3 ⭐ 推荐"
    echo "2. 卸载 XanMod 内核"
    echo ""
    echo -e "${gl_kjlan}[BBR/网络优化]${gl_bai}"
    echo "3. BBR 直连/落地优化（智能带宽检测）⭐ 推荐"
    echo "4. MTU检测与MSS优化（消除重传）⭐ 推荐"
    echo "5. NS论坛-DNS净化（抗污染/驯服DHCP）"
    echo "6. Realm转发timeout修复 ⭐ 推荐"
    echo ""
    echo -e "${gl_kjlan}━━━━━━━━━━━ 系统配置 ━━━━━━━━━━━${gl_bai}"
    echo "7. 设置IPv4/IPv6优先级"
    echo "8. IPv6管理（临时/永久禁用/取消）"
    echo "9. 设置临时SOCKS5代理"
    echo "10. 虚拟内存管理"
    echo "11. 查看系统详细状态"
    echo ""
    echo -e "${gl_kjlan}━━━━━━━━━━ 代理部署 ━━━━━━━━━━${gl_bai}"
    echo "12. 星辰大海Snell协议 ⭐ 推荐"
    echo "13. 星辰大海Xray一键多协议 ⭐ 推荐"
    echo "14. 禁止端口通过中国大陆直连"
    echo "15. 一键部署SOCKS5代理"
    echo "16. Sub-Store多实例管理"
    echo "17. 一键反代 ⭐ 推荐"
    echo ""
    echo -e "${gl_kjlan}━━━━━━━━━━━ 测试检测 ━━━━━━━━━━━${gl_bai}"
    echo -e "${gl_kjlan}[IP质量检测]${gl_bai}"
    echo "18. IP质量检测（IPv4+IPv6）"
    echo "19. IP质量检测（仅IPv4）⭐ 推荐"
    echo ""
    echo -e "${gl_kjlan}[网络测试]${gl_bai}"
    echo "20. 服务器带宽测试"
    echo "21. iperf3单线程测试"
    echo "22. 国际互联速度测试 ⭐ 推荐"
    echo "23. 网络延迟质量检测 ⭐ 推荐"
    echo "24. 三网回程路由测试 ⭐ 推荐"
    echo ""
    echo -e "${gl_kjlan}[流媒体/AI检测]${gl_bai}"
    echo "25. IP媒体/AI解锁检测 ⭐ 推荐"
    echo "26. NQ一键检测 ⭐ 推荐"
    echo ""
    echo -e "${gl_kjlan}━━━━━━━━━━ 第三方工具 ━━━━━━━━━━${gl_bai}"
    echo "27. zywe_realm转发脚本（查看原版仓库）"
    echo "28. F佬一键sing box脚本"
    echo "29. 科技lion脚本"
    echo "30. NS论坛CAKE调优"
    echo "31. 科技lion高性能模式"
    echo ""
    echo -e "${gl_kjlan}━━━━━━━━━ AI 代理服务 ━━━━━━━━━${gl_bai}"
    echo "32. AI代理工具箱 ▶ (Claude/WebUI/CRS/Fuclaude/Caddy) ⭐ 推荐"
    echo ""
    echo -e "${gl_kjlan}━━━━━━━━━ 一键优化 ━━━━━━━━━${gl_bai}"
    echo "66. ⭐ 一键全自动优化 (BBR v3 + 网络调优)"
    echo ""
    echo -e "${gl_hong}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo -e "${gl_hong}99. 完全卸载脚本（卸载所有内容）${gl_bai}"
    echo ""
    echo "0. 退出脚本"
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    read -e -p "请输入选择: " choice

    case $choice in
        1)
            if [ $is_installed -eq 0 ]; then
                update_xanmod_kernel
                # update 函数内部已有重启交互，无需再次调用 server_reboot
            else
                install_xanmod_kernel && server_reboot
            fi
            ;;
        2)
            if [ $is_installed -eq 0 ]; then
                uninstall_xanmod
            else
                echo -e "${gl_huang}当前未检测到 XanMod 内核，无需卸载${gl_bai}"
                break_end
            fi
            ;;
        3)
            bbr_configure_direct
            break_end
            ;;
        4)
            mtu_mss_optimization
            ;;
        5)
            dns_purify_and_harden
            ;;
        6)
            realm_fix_timeout
            break_end
            ;;
        7)
            manage_ip_priority
            ;;
        8)
            manage_ipv6
            ;;
        9)
            set_temp_socks5_proxy
            ;;
        10)
            manage_swap
            ;;
        11)
            show_detailed_status
            ;;
        12)
            snell_menu
            ;;
        13)
            run_xinchendahai_xray
            ;;
        14)
            manage_cn_ip_block
            ;;
        15)
            manage_socks5
            ;;
        16)
            manage_substore
            ;;
        17)
            manage_reverse_proxy
            ;;
        18)
            run_ip_quality_check
            ;;
        19)
            run_ip_quality_check_ipv4
            ;;
        20)
            run_speedtest
            ;;
        21)
            iperf3_single_thread_test
            ;;
        22)
            run_international_speed_test
            ;;
        23)
            run_network_latency_check
            ;;
        24)
            run_backtrace
            ;;
        25)
            run_unlock_check
            ;;
        26)
            run_ns_detect
            ;;
        27)
            run_pf_realm
            ;;
        28)
            run_fscarmen_singbox
            ;;
        29)
            run_kejilion_script
            ;;
        30)
            startbbrcake
            ;;
        31)
            Kernel_optimize
            ;;
        32)
            ai_proxy_menu
            ;;
        66)
            one_click_optimize
            ;;
        99)
            uninstall_all
            ;;
        0)
            echo "退出脚本"
            exit 0
            ;;
        *)
            echo "无效选择"
            sleep 2
            ;;
    esac
}

update_xanmod_kernel() {
    clear
    echo -e "${gl_kjlan}=== 更新 XanMod 内核 ===${gl_bai}"
    echo "------------------------------------------------"
    
    # 获取当前内核版本
    local current_kernel=$(uname -r)
    echo -e "当前内核版本: ${gl_huang}${current_kernel}${gl_bai}"
    echo ""
    
    # 检测 CPU 架构
    local cpu_arch=$(uname -m)
    
    # ARM 架构提示
    if [ "$cpu_arch" = "aarch64" ]; then
        echo -e "${gl_huang}ARM64 架构暂不支持自动更新${gl_bai}"
        echo "建议卸载后重新安装以获取最新版本"
        break_end
        return 1
    fi
    
    # x86_64 架构更新流程
    echo "正在检查可用更新..."
    
    local xanmod_repo_file="/etc/apt/sources.list.d/xanmod-release.list"

    # 添加 XanMod 仓库（如果不存在）
    if [ ! -f "$xanmod_repo_file" ]; then
        echo "正在添加 XanMod 仓库..."

        # 添加密钥（分步执行，避免管道 $? 问题）
        local gpg_key_file="/usr/share/keyrings/xanmod-archive-keyring.gpg"
        local key_tmp=$(mktemp)
        local gpg_ok=false

        if wget -qO "$key_tmp" "${gh_proxy}raw.githubusercontent.com/kejilion/sh/main/archive.key" 2>/dev/null && \
           [ -s "$key_tmp" ]; then
            if gpg --dearmor -o "$gpg_key_file" --yes < "$key_tmp" 2>/dev/null; then
                gpg_ok=true
            fi
        fi

        if [ "$gpg_ok" = false ]; then
            if wget -qO "$key_tmp" "https://dl.xanmod.org/archive.key" 2>/dev/null && \
               [ -s "$key_tmp" ]; then
                if gpg --dearmor -o "$gpg_key_file" --yes < "$key_tmp" 2>/dev/null; then
                    gpg_ok=true
                fi
            fi
        fi

        rm -f "$key_tmp"

        if [ "$gpg_ok" = false ]; then
            echo -e "${gl_hong}错误: GPG 密钥导入失败${gl_bai}"
            break_end
            return 1
        fi

        # 添加仓库（HTTPS）
        echo "deb [signed-by=${gpg_key_file}] https://deb.xanmod.org releases main" | \
            tee "$xanmod_repo_file" > /dev/null
    fi

    # 更新软件包列表
    echo "正在更新软件包列表..."
    if ! apt-get update > /dev/null 2>&1; then
        echo -e "${gl_huang}⚠️  apt-get update 部分失败，尝试继续...${gl_bai}"
    fi

    # 检查已安装的 XanMod 内核包（使用 ^ii 过滤，排除已卸载残留）
    local installed_packages=$(dpkg -l | grep -E '^ii\s+linux-.*xanmod' | awk '{print $2}')
    
    if [ -z "$installed_packages" ]; then
        echo -e "${gl_hong}错误: 未检测到已安装的 XanMod 内核${gl_bai}"
        break_end
        return 1
    fi
    
    echo -e "已安装的内核包:"
    echo "$installed_packages" | while read pkg; do
        echo "  - $pkg"
    done
    echo ""
    
    # 检查是否有可用更新
    local upgradable=$(apt list --upgradable 2>/dev/null | grep xanmod)
    
    if [ -z "$upgradable" ]; then
        local cpu_level
        cpu_level=$(echo "$installed_packages" | sed -nE 's/.*x64v([1-4]).*/\1/p' | head -1)
        [ -z "$cpu_level" ] && cpu_level="3"

        # 获取已安装的最新 XanMod 内核版本（从 linux-image 包名提取版本号并取最大值）
        local latest_installed
        latest_installed=$(echo "$installed_packages" \
            | sed -nE 's/^linux-image-([0-9]+\.[0-9]+\.[0-9]+-x64v[1-4]-xanmod[0-9]+)$/\1/p' \
            | sort -V | tail -1)

        local running_latest=0
        if [ -n "$latest_installed" ] && [ "$current_kernel" = "$latest_installed" ]; then
            running_latest=1
        fi

        if [ $running_latest -eq 1 ]; then
            echo -e "${gl_lv}✅ 当前运行内核已是最新版本！${gl_bai}"
        else
            echo -e "${gl_lv}✅ XanMod 内核包已是最新，但当前运行内核尚未切换！${gl_bai}"
            echo -e "  正在运行: ${gl_hong}${current_kernel}${gl_bai}"
            if [ -n "$latest_installed" ]; then
                echo -e "  最新已装: ${gl_lv}${latest_installed}${gl_bai}"
            else
                echo -e "  ${gl_huang}提示: 未能解析最新已装内核版本，请重启后再检查${gl_bai}"
            fi
            echo -e "  ${gl_huang}请重启系统 (reboot) 以切换到最新内核${gl_bai}"
        fi
        echo ""

        echo -e "${gl_kjlan}━━━━━━━━━━ CPU 架构信息 ━━━━━━━━━━${gl_bai}"
        echo -e "  CPU 架构等级: ${gl_lv}x86-64-v${cpu_level}${gl_bai}"
        echo -e "  当前运行内核: ${gl_lv}${current_kernel}${gl_bai}"
        if [ -n "$latest_installed" ] && [ $running_latest -ne 1 ]; then
            echo -e "  最新已装内核: ${gl_lv}${latest_installed}${gl_bai}"
        fi
        if [ $running_latest -eq 1 ]; then
            echo -e "  ${gl_huang}说明: 本机 CPU 最高支持 v${cpu_level}，当前已运行该等级最新内核${gl_bai}"
        else
            echo -e "  ${gl_huang}说明: 本机 CPU 最高支持 v${cpu_level}，最新内核已安装，重启后生效${gl_bai}"
        fi
        echo -e "  ${gl_huang}不同等级(v1-v4)的内核更新进度可能不同，以 XanMod 官方仓库为准${gl_bai}"
        echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"

        rm -f "$xanmod_repo_file"
        echo -e "${gl_lv}已自动清理 XanMod 软件源（如需更新可再次运行选项1）${gl_bai}"
        break_end
        return 0
    fi
    
    echo -e "${gl_huang}发现可用更新:${gl_bai}"
    echo "$upgradable"
    echo ""
    
    read -e -p "确定更新 XanMod 内核吗？(Y/N): " confirm
    
    case "$confirm" in
        [Yy])
            echo ""
            echo "正在更新内核..."
            apt install --only-upgrade -y $(echo "$installed_packages" | tr '\n' ' ')
            
            if [ $? -eq 0 ]; then
                echo ""
                echo -e "${gl_lv}✅ XanMod 内核更新成功！${gl_bai}"
                echo -e "${gl_huang}⚠️  请重启系统以加载新内核${gl_bai}"
                echo ""
                local cpu_level
                cpu_level=$(echo "$installed_packages" | sed -nE 's/.*x64v([1-4]).*/\1/p' | head -1)
                [ -z "$cpu_level" ] && cpu_level="3"
                local latest_installed
                latest_installed=$(dpkg -l 2>/dev/null | awk '/^ii\s+linux-image-[0-9].*xanmod/ {print $2}' | sed 's/^linux-image-//' | sort -V | tail -1)
                echo -e "${gl_kjlan}━━━━━━━━━━ CPU 架构信息 ━━━━━━━━━━${gl_bai}"
                echo -e "  CPU 架构等级: ${gl_lv}x86-64-v${cpu_level}${gl_bai}"
                if [ -n "$latest_installed" ]; then
                    echo -e "  最新已装内核: ${gl_lv}${latest_installed}${gl_bai}"
                else
                    echo -e "  已更新内核包: ${gl_lv}$(echo "$installed_packages" | head -1)${gl_bai}"
                fi
                echo -e "  ${gl_huang}说明: 本机 CPU 最高支持 v${cpu_level}，已更新至该等级的最新内核${gl_bai}"
                echo -e "  ${gl_huang}不同等级(v1-v4)的内核更新进度可能不同，以 XanMod 官方仓库为准${gl_bai}"
                echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
                echo ""
                echo -e "${gl_kjlan}后续更新: 再次运行选项1即可检查并安装最新内核${gl_bai}"

                rm -f "$xanmod_repo_file"
                echo -e "${gl_lv}已自动清理 XanMod 软件源（如需更新可再次运行选项1）${gl_bai}"
                return 0
            else
                echo ""
                echo -e "${gl_hong}❌ 内核更新失败${gl_bai}"
                break_end
                return 1
            fi
            ;;
        *)
            echo "已取消更新"
            break_end
            return 1
            ;;
    esac
}

uninstall_xanmod() {
    echo -e "${gl_huang}警告: 即将卸载 XanMod 内核${gl_bai}"
    echo ""

    # 安全检查：确认系统中有回退内核可用
    local non_xanmod_kernels=$(dpkg -l 2>/dev/null | grep '^ii' | grep 'linux-image-' | grep -v 'xanmod' | grep -v 'dbg' | wc -l)
    if [ "$non_xanmod_kernels" -eq 0 ]; then
        echo -e "${gl_hong}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
        echo -e "${gl_hong}❌ 安全检查未通过：未检测到非 XanMod 的回退内核！${gl_bai}"
        echo -e "${gl_hong}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
        echo ""
        echo "卸载 XanMod 内核后系统将没有可启动的内核，重启会导致 VPS 无法开机。"
        echo ""
        echo -e "${gl_lv}建议：先安装默认内核再卸载 XanMod${gl_bai}"
        echo "  apt install -y linux-image-amd64   # Debian"
        echo "  apt install -y linux-image-generic  # Ubuntu"
        echo ""
        break_end
        return 1
    fi
    echo -e "${gl_lv}✅ 检测到 ${non_xanmod_kernels} 个回退内核，可以安全卸载${gl_bai}"
    echo ""

    read -e -p "确定继续吗？(Y/N): " confirm

    case "$confirm" in
        [Yy])
            # 使用能匹配元包和内核包的模式
            echo "正在卸载 XanMod 相关包..."
            if apt purge -y 'linux-*xanmod*' 2>&1; then
                # 验证卸载结果
                if dpkg -l 2>/dev/null | grep -qE '^ii\s+linux-.*xanmod'; then
                    echo -e "${gl_hong}⚠️  部分 XanMod 包未能卸载，请手动检查：${gl_bai}"
                    dpkg -l | grep -E '^ii\s+linux-.*xanmod' | awk '{print "  - " $2}'
                else
                    echo -e "${gl_lv}✅ XanMod 内核包已全部卸载${gl_bai}"
                fi
                update-grub 2>/dev/null
            else
                echo -e "${gl_hong}❌ 卸载命令执行失败，请手动检查${gl_bai}"
                break_end
                return 1
            fi

            # 清理软件源和 GPG 密钥
            rm -f /etc/apt/sources.list.d/xanmod-release.list
            rm -f /usr/share/keyrings/xanmod-archive-keyring.gpg
            echo -e "${gl_lv}✅ XanMod 软件源已清理${gl_bai}"

            rm -f "$SYSCTL_CONF"
            echo -e "${gl_lv}XanMod 内核已卸载${gl_bai}"
            server_reboot
            ;;
        *)
            echo "已取消"
            ;;
    esac
}

# 完全卸载脚本所有内容
uninstall_all() {
    clear
    echo -e "${gl_hong}╔════════════════════════════════════════════╗${gl_bai}"
    echo -e "${gl_hong}║       完全卸载脚本 - 所有内容清理          ║${gl_bai}"
    echo -e "${gl_hong}╚════════════════════════════════════════════╝${gl_bai}"
    echo ""
    echo -e "${gl_huang}⚠️  警告：此操作将完全卸载脚本的所有内容，包括：${gl_bai}"
    echo ""
    echo "  • XanMod 内核（如果已安装）"
    echo "  • bbr 快捷别名"
    echo "  • 所有 BBR/网络优化配置"
    echo "  • 所有 sysctl 配置文件"
    echo "  • MTU优化和持久化服务"
    echo "  • DNS净化和持久化服务"
    echo "  • 其他相关配置文件和备份"
    echo ""
    echo -e "${gl_hong}此操作不可逆！${gl_bai}"
    echo ""
    
    read -e -p "确定要完全卸载吗？(输入 YES 确认): " confirm
    
    if [ "$confirm" != "YES" ]; then
        echo -e "${gl_huang}已取消卸载${gl_bai}"
        break_end
        return 1
    fi
    
    echo ""
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo -e "${gl_kjlan}开始完全卸载...${gl_bai}"
    echo ""
    
    local uninstall_count=0
    local xanmod_removed=0
    
    # 1. 卸载 XanMod 内核
    echo -e "${gl_huang}[1/8] 检查并卸载 XanMod 内核...${gl_bai}"
    if dpkg -l | grep -qE '^ii\s+linux-.*xanmod'; then
        # 安全检查：确认有回退内核
        local non_xanmod_kernels=$(dpkg -l 2>/dev/null | grep '^ii' | grep 'linux-image-' | grep -v 'xanmod' | grep -v 'dbg' | wc -l)
        if [ "$non_xanmod_kernels" -eq 0 ]; then
            echo -e "  ${gl_hong}❌ 未检测到回退内核，跳过卸载以防系统无法启动${gl_bai}"
            echo -e "  ${gl_huang}请先安装默认内核: apt install -y linux-image-amd64${gl_bai}"
        else
            echo "  正在卸载 XanMod 内核..."
            if apt purge -y 'linux-*xanmod*' > /dev/null 2>&1; then
                update-grub > /dev/null 2>&1
            else
                echo -e "  ${gl_hong}❌ XanMod 内核卸载命令执行失败，请手动检查${gl_bai}"
            fi
            if dpkg -l | grep -qE '^ii\s+linux-.*xanmod'; then
                echo -e "  ${gl_hong}❌ 仍检测到 XanMod 内核，请手动检查${gl_bai}"
            else
                echo -e "  ${gl_lv}✅ XanMod 内核已卸载${gl_bai}"
                uninstall_count=$((uninstall_count + 1))
                xanmod_removed=1
            fi
        fi
    else
        echo -e "  ${gl_huang}未检测到 XanMod 内核，跳过${gl_bai}"
    fi
    echo ""
    
    # 2. 卸载 bbr 快捷别名
    echo -e "${gl_huang}[2/8] 卸载 bbr 快捷别名...${gl_bai}"
    
    # 检查所有可能的配置文件
    local rc_files=("$HOME/.bashrc" "$HOME/.bash_profile" "$HOME/.zshrc" "$HOME/.profile")
    local alias_found=0
    local alias_removed=0
    
    for rc_file in "${rc_files[@]}"; do
        if [ ! -f "$rc_file" ]; then
            continue
        fi
        
        # 检查是否存在别名（多种匹配方式）
        if grep -q "net-tcp-tune 快捷别名\|alias bbr=" "$rc_file" 2>/dev/null; then
            alias_found=1
            
            # 创建临时文件
            local temp_file=$(mktemp)
            
            # 方法1：删除包含 "net-tcp-tune 快捷别名" 的整个块
            if grep -q "net-tcp-tune 快捷别名" "$rc_file" 2>/dev/null; then
                # 使用精确的标记删除，避免 sed 范围匹配到用户其他内容
                sed '/net-tcp-tune 快捷别名/,/^alias bbr=/d' "$rc_file" 2>/dev/null > "$temp_file"
                # 清理可能残留的分隔线（只删紧邻别名块的分隔线）
                sed -i '/^# ================.*net-tcp-tune/d' "$temp_file" 2>/dev/null
                sed -i '/^# ================$/{ N; /net-tcp-tune\|alias bbr/d; }' "$temp_file" 2>/dev/null
            else
                # 直接复制文件
                cp "$rc_file" "$temp_file"
            fi
            
            # 方法2：删除所有包含 alias bbr 且指向脚本的行（多种匹配方式）
            # 匹配各种可能的格式
            sed -i '/alias bbr.*net-tcp-tune/d' "$temp_file" 2>/dev/null
            sed -i '/alias bbr.*vps-tcp-tune/d' "$temp_file" 2>/dev/null
            sed -i '/alias bbr.*Eric86777/d' "$temp_file" 2>/dev/null
            sed -i '/alias bbr.*curl.*net-tcp-tune/d' "$temp_file" 2>/dev/null
            sed -i '/alias bbr.*wget.*net-tcp-tune/d' "$temp_file" 2>/dev/null
            sed -i '/alias bbr.*raw.githubusercontent.com.*vps-tcp-tune/d' "$temp_file" 2>/dev/null
            
            # 方法3：删除所有注释行（可能包含脚本相关信息）
            sed -i '/#.*net-tcp-tune/d' "$temp_file" 2>/dev/null
            sed -i '/#.*vps-tcp-tune/d' "$temp_file" 2>/dev/null
            
            # 检查是否有变更
            if ! diff -q "$rc_file" "$temp_file" > /dev/null 2>&1; then
                # 备份原文件
                cp "$rc_file" "${rc_file}.bak.uninstall.$(date +%Y%m%d_%H%M%S)" 2>/dev/null
                # 替换文件（保留原文件权限）
                cp "$temp_file" "$rc_file"
                rm -f "$temp_file"
                alias_removed=1
                echo -e "  ${gl_lv}✅ 已从 $(basename $rc_file) 中删除别名${gl_bai}"
            else
                rm -f "$temp_file"
            fi
        fi
    done
    
    # 如果没有找到别名，尝试直接删除 alias bbr 定义（更激进的清理）
    if [ $alias_found -eq 0 ]; then
        for rc_file in "${rc_files[@]}"; do
            if [ ! -f "$rc_file" ]; then
                continue
            fi
            
            # 检查是否有任何 bbr 别名定义
            if grep -q "^alias bbr=" "$rc_file" 2>/dev/null; then
                # 删除所有 alias bbr 定义
                sed -i '/^alias bbr=/d' "$rc_file" 2>/dev/null
                alias_removed=1
                echo -e "  ${gl_lv}✅ 已从 $(basename $rc_file) 中删除 bbr 别名${gl_bai}"
            fi
        done
    fi
    
    if [ $alias_removed -eq 1 ]; then
        # 立即尝试取消当前会话中的别名（对子 shell 有效）
        unalias bbr 2>/dev/null || true
        
        echo -e "  ${gl_lv}✅ bbr 快捷别名已卸载${gl_bai}"
        echo -e "  ${gl_huang}提示: 配置文件已清理。如当前终端仍可执行 bbr，请手动运行: ${gl_kjlan}unalias bbr${gl_huang}${gl_bai}"
        echo -e "  ${gl_huang}如需在新终端生效，请执行: ${gl_bai}source ~/.bashrc${gl_huang} 或 ${gl_bai}source ~/.zshrc${gl_bai}"
        uninstall_count=$((uninstall_count + 1))
    elif [ $alias_found -eq 1 ]; then
        # 即使删除失败，也尝试取消当前会话的别名
        unalias bbr 2>/dev/null || true
        echo -e "  ${gl_huang}警告: 检测到别名但删除失败，请手动检查配置文件${gl_bai}"
        echo -e "  ${gl_huang}已尝试取消当前会话的别名${gl_bai}"
    else
        # 以防万一，取消当前会话的别名
        unalias bbr 2>/dev/null || true
        echo -e "  ${gl_huang}未检测到 bbr 别名，跳过${gl_bai}"
    fi
    echo ""
    
    # 3. 清理 sysctl 配置文件
    echo -e "${gl_huang}[3/8] 清理 sysctl 配置文件...${gl_bai}"
    local sysctl_files=(
        "$SYSCTL_CONF"
        "/etc/sysctl.d/99-bbr-ultimate.conf"
        "/etc/sysctl.d/99-sysctl.conf"
        "/etc/sysctl.d/999-net-bbr-fq.conf"
    )
    
    local sysctl_cleaned=0
    for file in "${sysctl_files[@]}"; do
        if [ -f "$file" ]; then
            rm -f "$file"
            sysctl_cleaned=$((sysctl_cleaned + 1))
        fi
    done
    
    # 清理 IPv6 管理相关配置
    if [ -f "/etc/sysctl.d/99-disable-ipv6.conf" ]; then
        rm -f "/etc/sysctl.d/99-disable-ipv6.conf"
        sysctl_cleaned=$((sysctl_cleaned + 1))
    fi
    if [ -f "/etc/sysctl.d/.ipv6-state-backup.conf" ]; then
        rm -f "/etc/sysctl.d/.ipv6-state-backup.conf"
        sysctl_cleaned=$((sysctl_cleaned + 1))
    fi
    
    # 恢复 sysctl.conf 原始配置（如果有备份）
    if [ -f "/etc/sysctl.conf.bak.original" ]; then
        cp /etc/sysctl.conf /etc/sysctl.conf.bak.$(date +%Y%m%d_%H%M%S) 2>/dev/null
        cp /etc/sysctl.conf.bak.original /etc/sysctl.conf 2>/dev/null
        rm -f /etc/sysctl.conf.bak.original
        sysctl_cleaned=$((sysctl_cleaned + 1))
    fi
    
    if [ $sysctl_cleaned -gt 0 ]; then
        echo -e "  ${gl_lv}✅ 已清理 $sysctl_cleaned 个配置文件${gl_bai}"
        uninstall_count=$((uninstall_count + 1))
    else
        echo -e "  ${gl_huang}未找到需要清理的配置文件${gl_bai}"
    fi
    echo ""
    
    # 4. 清理 XanMod 软件源
    echo -e "${gl_huang}[4/8] 清理 XanMod 软件源...${gl_bai}"
    local repo_files=(
        "/etc/apt/sources.list.d/xanmod-release.list"
        "/usr/share/keyrings/xanmod-archive-keyring.gpg"
    )
    
    local repo_cleaned=0
    for file in "${repo_files[@]}"; do
        if [ -f "$file" ]; then
            rm -f "$file"
            repo_cleaned=$((repo_cleaned + 1))
        fi
    done
    
    if [ $repo_cleaned -gt 0 ]; then
        echo -e "  ${gl_lv}✅ 已清理 XanMod 软件源${gl_bai}"
        uninstall_count=$((uninstall_count + 1))
    else
        echo -e "  ${gl_huang}未找到 XanMod 软件源${gl_bai}"
    fi
    echo ""
    
    # 5. 清理持久化服务和优化配置（功能3/4/5）
    echo -e "${gl_huang}[5/8] 清理持久化服务和优化配置...${gl_bai}"
    local persist_cleaned=0

    # 功能4: MTU优化 — 恢复路由/链路MTU + 清理服务
    if [ -f /usr/local/etc/mtu-optimize.conf ]; then
        . /usr/local/etc/mtu-optimize.conf 2>/dev/null
        # 恢复默认路由 MTU
        local def_rt
        def_rt=$(ip -4 route show default 2>/dev/null | head -1)
        if [ -n "$def_rt" ]; then
            local cl_rt
            cl_rt=$(echo "$def_rt" | sed 's/ mtu lock [0-9]*//;s/ mtu [0-9]*//')
            ip route replace $cl_rt 2>/dev/null || true
        fi
        # 恢复链路 MTU
        if [ -n "${DEFAULT_IFACE:-}" ] && [ -n "${ORIGINAL_MTU:-}" ]; then
            ip link set dev "$DEFAULT_IFACE" mtu "$ORIGINAL_MTU" 2>/dev/null || true
        fi
        rm -f /usr/local/etc/mtu-optimize.conf
        persist_cleaned=$((persist_cleaned + 1))
        echo -e "  ${gl_lv}✓ MTU优化已恢复${gl_bai}"
    fi
    if [ -f /etc/systemd/system/mtu-optimize-persist.service ]; then
        systemctl disable mtu-optimize-persist.service 2>/dev/null || true
        rm -f /etc/systemd/system/mtu-optimize-persist.service
        rm -f /usr/local/bin/mtu-optimize-apply.sh
        persist_cleaned=$((persist_cleaned + 1))
    fi

    # 功能3: BBR优化持久化
    if [ -f /etc/systemd/system/bbr-optimize-persist.service ]; then
        systemctl disable bbr-optimize-persist.service 2>/dev/null || true
        rm -f /etc/systemd/system/bbr-optimize-persist.service
        rm -f /usr/local/bin/bbr-optimize-apply.sh
        persist_cleaned=$((persist_cleaned + 1))
        echo -e "  ${gl_lv}✓ BBR持久化服务已移除${gl_bai}"
    fi

    # 功能5: DNS净化持久化
    if [ -f /etc/systemd/system/dns-purify-persist.service ]; then
        systemctl disable dns-purify-persist.service 2>/dev/null || true
        rm -f /etc/systemd/system/dns-purify-persist.service
        rm -f /usr/local/bin/dns-purify-apply.sh
        persist_cleaned=$((persist_cleaned + 1))
        echo -e "  ${gl_lv}✓ DNS持久化服务已移除${gl_bai}"
    fi

    # 清理旧版 iptables set-mss 规则（功能4旧版兼容）
    if command -v iptables &>/dev/null; then
        local tag="net-tcp-tune-mss" del_v
        while read -r del_v; do
            [ -n "$del_v" ] || continue
            iptables -t mangle -D OUTPUT -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss "$del_v" -m comment --comment "$tag" 2>/dev/null || true
        done < <(iptables -t mangle -S OUTPUT 2>/dev/null | grep "$tag" | sed -n 's/.*--set-mss \([0-9]\+\).*/\1/p')
        while read -r del_v; do
            [ -n "$del_v" ] || continue
            iptables -t mangle -D POSTROUTING -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss "$del_v" -m comment --comment "$tag" 2>/dev/null || true
        done < <(iptables -t mangle -S POSTROUTING 2>/dev/null | grep "$tag" | sed -n 's/.*--set-mss \([0-9]\+\).*/\1/p')
    fi

    if [ $persist_cleaned -gt 0 ]; then
        systemctl daemon-reload 2>/dev/null || true
        echo -e "  ${gl_lv}✅ 已清理 $persist_cleaned 个持久化组件${gl_bai}"
        uninstall_count=$((uninstall_count + 1))
    else
        echo -e "  ${gl_huang}未找到持久化服务${gl_bai}"
    fi
    echo ""

    # 6. 清理其他临时文件和备份
    echo -e "${gl_huang}[6/8] 清理临时文件和备份...${gl_bai}"
    local temp_files=(
        "/tmp/socks5_proxy_*.sh"
        "/root/.realm_backup/"
    )
    
    local temp_cleaned=0
    for pattern in "${temp_files[@]}"; do
        if ls $pattern > /dev/null 2>&1; then
            rm -rf $pattern 2>/dev/null
            temp_cleaned=$((temp_cleaned + 1))
        fi
    done
    
    if [ $temp_cleaned -gt 0 ]; then
        echo -e "  ${gl_lv}✅ 已清理临时文件${gl_bai}"
    else
        echo -e "  ${gl_huang}未找到临时文件${gl_bai}"
    fi
    echo ""
    
    # 7. 应用 sysctl 更改
    echo -e "${gl_huang}[7/8] 应用系统配置更改...${gl_bai}"
    sysctl --system > /dev/null 2>&1
    echo -e "  ${gl_lv}✅ 系统配置已重置${gl_bai}"
    echo ""

    # 8. 清理功能5 DNS净化残留配置
    echo -e "${gl_huang}[8/8] 清理 DNS 净化残留配置...${gl_bai}"
    local dns_cleaned=0
    # NetworkManager DNS 委托配置
    if [ -f /etc/NetworkManager/conf.d/99-dns-purify.conf ]; then
        rm -f /etc/NetworkManager/conf.d/99-dns-purify.conf
        systemctl reload NetworkManager 2>/dev/null || true
        dns_cleaned=$((dns_cleaned + 1))
    fi
    # systemd-networkd drop-in
    local sd_dir
    for sd_dir in /etc/systemd/network /run/systemd/network /usr/lib/systemd/network; do
        local dropin_f
        for dropin_f in "$sd_dir"/*.network.d/dns-purify-override.conf; do
            [ -f "$dropin_f" ] || continue
            rm -f "$dropin_f"
            rmdir "$(dirname "$dropin_f")" 2>/dev/null || true
            dns_cleaned=$((dns_cleaned + 1))
        done
    done
    if [ $dns_cleaned -gt 0 ]; then
        echo -e "  ${gl_lv}✅ 已清理 DNS 净化残留配置${gl_bai}"
    else
        echo -e "  ${gl_huang}未找到 DNS 净化残留${gl_bai}"
    fi
    echo ""

    # 完成提示
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo -e "${gl_lv}✅ 完全卸载完成！${gl_bai}"
    echo ""
    echo -e "${gl_huang}卸载统计：${gl_bai}"
    echo "  • 已卸载 $uninstall_count 个主要组件"
    echo ""
    echo -e "${gl_huang}⚠️  重要提示：${gl_bai}"
    echo "  1. 如果卸载了内核，请重启系统以生效"
    echo "  2. 如果卸载了别名，请重新加载 Shell 配置："
    echo -e "     ${gl_kjlan}source ~/.bashrc${gl_bai} 或 ${gl_kjlan}source ~/.zshrc${gl_bai}"
    echo "  3. 如需重新安装，请重新运行脚本"
    echo ""
    
    # 询问是否重启
    if [ "$xanmod_removed" -eq 1 ]; then
        echo -e "${gl_huang}检测到已卸载内核，建议重启系统${gl_bai}"
        read -e -p "是否立即重启？(Y/n): " reboot_confirm
        case "${reboot_confirm:-Y}" in
            [Yy])
                echo ""
                echo -e "${gl_lv}✅ 完全卸载完成，正在重启系统...${gl_bai}"
                sleep 2
                server_reboot
                ;;
            *)
                echo ""
                echo -e "${gl_huang}请稍后手动重启系统${gl_bai}"
                echo -e "${gl_lv}✅ 完全卸载完成，脚本即将退出${gl_bai}"
                sleep 2
                exit 0
                ;;
        esac
    else
        if dpkg -l | grep -qE '^ii\s+linux-.*xanmod'; then
            echo ""
            echo -e "${gl_hong}❌ 检测到 XanMod 内核仍存在，请手动检查${gl_bai}"
            sleep 2
            exit 1
        else
            echo ""
            echo -e "${gl_lv}✅ 完全卸载完成，脚本即将退出${gl_bai}"
            sleep 2
            exit 0
        fi
    fi
}

run_unlock_check() {
    clear
    echo -e "${gl_kjlan}=== IP媒体/AI解锁检测 ===${gl_bai}"
    echo ""
    echo "正在运行流媒体解锁检测脚本..."
    echo "------------------------------------------------"
    echo ""

    # 执行解锁检测脚本
    if ! run_remote_script "https://github.com/1-stream/RegionRestrictionCheck/raw/main/check.sh" bash; then
        echo -e "${gl_hong}❌ 脚本执行失败${gl_bai}"
        break_end
        return 1
    fi

    echo ""
    echo "------------------------------------------------"
    break_end
}

run_pf_realm() {
    clear
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo -e "${gl_kjlan}  zywe_realm 转发脚本${gl_bai}"
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo ""
    echo "本人已将 zywe 大佬的脚本二次修改并使用，"
    echo "如需使用原版，请直接访问："
    echo ""
    echo -e "${gl_lv}👉 https://github.com/zywe03/realm-xwPF${gl_bai}"
    echo ""
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    break_end
}

run_kxy_script() {
    clear
    echo -e "${gl_kjlan}=== 酷雪云脚本 ===${gl_bai}"
    echo ""
    echo "正在运行酷雪云脚本..."
    echo "------------------------------------------------"
    echo ""

    # 执行酷雪云脚本
    if ! run_remote_script "https://cdn.kxy.ovh/kxy.sh" bash; then
        echo -e "${gl_hong}❌ 脚本执行失败${gl_bai}"
        break_end
        return 1
    fi

    echo ""
    echo "------------------------------------------------"
    break_end
}

#=============================================================================
# 星辰大海 Snell 协议管理
#=============================================================================

# Snell 颜色定义（使用主脚本的颜色变量）
SNELL_RED="${gl_hong}"
SNELL_GREEN="${gl_lv}"
SNELL_YELLOW="${gl_huang}"
SNELL_BLUE="${gl_kjlan}"
SNELL_PURPLE="${gl_zi}"
SNELL_CYAN="${gl_kjlan}"
SNELL_RESET="${gl_bai}"

# Snell 日志文件路径
SNELL_LOG_FILE="/var/log/snell_manager.log"

# Snell 服务名称
SNELL_SERVICE_NAME="snell.service"

# 检测系统类型（Snell）
get_system_type_snell() {
    if [ -f /etc/debian_version ]; then
        echo "debian"
    elif [ -f /etc/redhat-release ]; then
        echo "centos"
    else
        echo "unknown"
    fi
}

# 等待包管理器锁（Snell）
wait_for_package_manager_snell() {
    local system_type=$(get_system_type_snell)
    if [ "$system_type" = "debian" ]; then
        while fuser /var/lib/dpkg/lock >/dev/null 2>&1 || fuser /var/lib/apt/lists/lock >/dev/null 2>&1 || fuser /var/cache/apt/archives/lock >/dev/null 2>&1; do
            echo -e "${SNELL_YELLOW}等待其他 apt 进程完成${SNELL_RESET}"
            sleep 1
        done
    fi
}

# 安装必要的软件包（Snell）
install_required_packages_snell() {
    local system_type=$(get_system_type_snell)
    echo -e "${SNELL_GREEN}安装必要的软件包${SNELL_RESET}"

    if [ "$system_type" = "debian" ]; then
        apt update
        apt install -y wget unzip curl
    elif [ "$system_type" = "centos" ]; then
        yum -y update
        yum -y install wget unzip curl
    else
        echo -e "${SNELL_RED}不支持的系统类型${SNELL_RESET}"
        exit 1
    fi
}

# 检查是否以 root 权限运行（Snell）
check_root_snell() {
    if [ "$(id -u)" != "0" ]; then
        echo -e "${SNELL_RED}请以 root 权限运行此脚本.${SNELL_RESET}"
        exit 1
    fi
}

# 检查 Snell 是否已安装
check_snell_installed() {
    if command -v snell-server &> /dev/null; then
        return 0
    else
        return 1
    fi
}

# 检查 Snell 是否正在运行
check_snell_running() {
    systemctl is-active --quiet "$SNELL_SERVICE_NAME"
    return $?
}

# 启动 Snell 服务
start_snell() {
    systemctl start "$SNELL_SERVICE_NAME"
    if [ $? -eq 0 ]; then
        echo -e "${SNELL_GREEN}Snell 启动成功${SNELL_RESET}"
        echo "$(date '+%Y-%m-%d %H:%M:%S') - Snell 启动成功" >> "$SNELL_LOG_FILE"
    else
        echo -e "${SNELL_RED}Snell 启动失败${SNELL_RESET}"
        echo "$(date '+%Y-%m-%d %H:%M:%S') - Snell 启动失败" >> "$SNELL_LOG_FILE"
    fi
}

# 停止 Snell 服务
stop_snell() {
    systemctl stop "$SNELL_SERVICE_NAME"
    if [ $? -eq 0 ]; then
        echo -e "${SNELL_GREEN}Snell 停止成功${SNELL_RESET}"
        echo "$(date '+%Y-%m-%d %H:%M:%S') - Snell 停止成功" >> "$SNELL_LOG_FILE"
    else
        echo -e "${SNELL_RED}Snell 停止失败${SNELL_RESET}"
        echo "$(date '+%Y-%m-%d %H:%M:%S') - Snell 停止失败" >> "$SNELL_LOG_FILE"
    fi
}

# 安装 Snell
install_snell() {
    echo -e "${SNELL_GREEN}正在安装 Snell${SNELL_RESET}"

    # 等待包管理器
    wait_for_package_manager_snell

    # 安装必要的软件包
    if ! install_required_packages_snell; then
        echo -e "${SNELL_RED}安装必要软件包失败，请检查您的网络连接。${SNELL_RESET}"
        echo "$(date '+%Y-%m-%d %H:%M:%S') - 安装必要软件包失败" >> "$SNELL_LOG_FILE"
        exit 1
    fi

    # 下载 Snell 服务器文件
    ARCH=$(arch)
    VERSION="v5.0.1"
    SNELL_URL=""
    INSTALL_DIR="/usr/local/bin"
    SYSTEMD_SERVICE_FILE="/lib/systemd/system/snell.service"
    CONF_DIR="/etc/snell"
    CONF_FILE="${CONF_DIR}/snell-server.conf"

    if [[ ${ARCH} == "aarch64" ]]; then
        SNELL_URL="https://dl.nssurge.com/snell/snell-server-${VERSION}-linux-aarch64.zip"
    else
        SNELL_URL="https://dl.nssurge.com/snell/snell-server-${VERSION}-linux-amd64.zip"
    fi

    # 下载 Snell 服务器文件
    wget ${SNELL_URL} -O snell-server.zip
    if [ $? -ne 0 ]; then
        echo -e "${SNELL_RED}下载 Snell 失败。${SNELL_RESET}"
        echo "$(date '+%Y-%m-%d %H:%M:%S') - 下载 Snell 失败" >> "$SNELL_LOG_FILE"
        exit 1
    fi

    # 解压缩文件到指定目录
    unzip -o snell-server.zip -d ${INSTALL_DIR}
    if [ $? -ne 0 ]; then
        echo -e "${SNELL_RED}解压缩 Snell 失败。${SNELL_RESET}"
        echo "$(date '+%Y-%m-%d %H:%M:%S') - 解压缩 Snell 失败" >> "$SNELL_LOG_FILE"
        exit 1
    fi

    # 删除下载的 zip 文件
    rm snell-server.zip

    # 赋予执行权限
    chmod +x ${INSTALL_DIR}/snell-server

    # 生成随机端口和密码
    SNELL_PORT=$(shuf -i 30000-65000 -n 1)
    RANDOM_PSK=$(tr -dc A-Za-z0-9 </dev/urandom | head -c 20)

    # 检查 snell 用户是否已存在
    if ! id "snell" &>/dev/null; then
        # 创建 Snell 用户
        useradd -r -s /usr/sbin/nologin snell
    fi

    # 创建配置文件目录
    mkdir -p ${CONF_DIR}

    # 询问端口（直接输入或回车使用随机）
    echo -e "${SNELL_CYAN}请输入端口号 (1-65535)，直接回车使用随机端口 [默认: ${SNELL_PORT}]:${SNELL_RESET}"
    while true; do
        read -p "端口: " custom_port
        
        # 如果用户直接回车，使用随机端口
        if [ -z "$custom_port" ]; then
            echo -e "${SNELL_GREEN}使用随机端口: ${SNELL_PORT}${SNELL_RESET}"
            break
        fi
        
        # 如果用户输入了端口，验证端口号
        if [[ "$custom_port" =~ ^[0-9]+$ ]] && [ "$custom_port" -ge 1 ] && [ "$custom_port" -le 65535 ]; then
            SNELL_PORT=$custom_port
            echo -e "${SNELL_GREEN}已设置端口为: ${SNELL_PORT}${SNELL_RESET}"
            break
        else
            echo -e "${SNELL_RED}无效端口，请输入 1-65535 之间的数字，或直接回车使用随机端口${SNELL_RESET}"
        fi
    done
    
    # 询问节点名称
    echo -e "${SNELL_CYAN}请输入节点名称 (例如: 🇯🇵【Gen2】Fxtransit JP T1):${SNELL_RESET}"
    read -p "节点名称: " NODE_NAME
    if [ -z "$NODE_NAME" ]; then
        NODE_NAME="Snell-Node-${SNELL_PORT}"
        echo -e "${SNELL_YELLOW}未输入名称，使用默认名称: ${NODE_NAME}${SNELL_RESET}"
    fi

    # 定义特定端口的配置文件和服务文件
    CONF_FILE="${CONF_DIR}/snell-${SNELL_PORT}.conf"
    SYSTEMD_SERVICE_FILE="/etc/systemd/system/snell-${SNELL_PORT}.service"
    SNELL_SERVICE_NAME="snell-${SNELL_PORT}.service"

    # 检查端口是否被占用
    if ss -tulpn | grep -q ":${SNELL_PORT} "; then
        echo -e "${SNELL_RED}端口 ${SNELL_PORT} 已被占用，请选择其他端口。${SNELL_RESET}"
        echo "$(date '+%Y-%m-%d %H:%M:%S') - 端口 ${SNELL_PORT} 已被占用" >> "$SNELL_LOG_FILE"
        return 1
    fi

    # 询问用户选择监听模式
    echo -e "${SNELL_CYAN}请选择监听模式:${SNELL_RESET}"
    echo "1. 仅 IPv4 (0.0.0.0)"
    echo "2. 仅 IPv6 (::0)"
    echo "3. 双栈 (同时支持 IPv4 和 IPv6)"
    read -p "请输入选项 [1-3，默认为 1]: " listen_mode
    listen_mode=${listen_mode:-1}

    local IP_VERSION_STR=""
    case $listen_mode in
        1)
            LISTEN_ADDR="0.0.0.0:${SNELL_PORT}"
            IPV6_ENABLED="false"
            IP_VERSION_STR=", ip-version=v4-only"
            echo -e "${SNELL_GREEN}已选择：仅 IPv4 模式${SNELL_RESET}"
            ;;
        2)
            LISTEN_ADDR="::0:${SNELL_PORT}"
            IPV6_ENABLED="true"
            IP_VERSION_STR=", ip-version=v6-only"
            echo -e "${SNELL_GREEN}已选择：仅 IPv6 模式${SNELL_RESET}"
            ;;
        3)
            LISTEN_ADDR="::0:${SNELL_PORT}"
            IPV6_ENABLED="true"
            IP_VERSION_STR="" # 双栈模式不强制指定 ip-version，或者根据需求设为 prefer-v4
            echo -e "${SNELL_GREEN}已选择：双栈模式 (同时支持 IPv4 和 IPv6)${SNELL_RESET}"
            ;;
        *)
            LISTEN_ADDR="0.0.0.0:${SNELL_PORT}"
            IPV6_ENABLED="false"
            IP_VERSION_STR=", ip-version=v4-only"
            echo -e "${SNELL_YELLOW}无效选项，默认使用 IPv4 模式${SNELL_RESET}"
            ;;
    esac

    # 创建配置文件
    cat > ${CONF_FILE} << EOF
[snell-server]
listen = ${LISTEN_ADDR}
psk = ${RANDOM_PSK}
ipv6 = ${IPV6_ENABLED}
EOF

    # 创建 Systemd 服务文件
    cat > ${SYSTEMD_SERVICE_FILE} << EOF
[Unit]
Description=Snell Proxy Service (Port ${SNELL_PORT})
After=network.target

[Service]
Type=simple
User=snell
Group=snell
ExecStart=${INSTALL_DIR}/snell-server -c ${CONF_FILE}
AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_NET_ADMIN CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_NET_ADMIN CAP_NET_RAW
LimitNOFILE=32768
Restart=on-failure
StandardOutput=journal
StandardError=journal
SyslogIdentifier=snell-${SNELL_PORT}

[Install]
WantedBy=multi-user.target
EOF

    # 重载 Systemd 配置
    systemctl daemon-reload
    if [ $? -ne 0 ]; then
        echo -e "${SNELL_RED}重载 Systemd 配置失败。${SNELL_RESET}"
        echo "$(date '+%Y-%m-%d %H:%M:%S') - 重载 Systemd 配置失败" >> "$SNELL_LOG_FILE"
        exit 1
    fi

    # 开机自启动 Snell
    systemctl enable ${SNELL_SERVICE_NAME}
    if [ $? -ne 0 ]; then
        echo -e "${SNELL_RED}开机自启动 Snell 失败。${SNELL_RESET}"
        echo "$(date '+%Y-%m-%d %H:%M:%S') - 开机自启动 Snell 失败" >> "$SNELL_LOG_FILE"
        exit 1
    fi

    # 启动 Snell 服务
    systemctl start ${SNELL_SERVICE_NAME}
    if [ $? -ne 0 ]; then
        echo -e "${SNELL_RED}启动 Snell 服务失败。${SNELL_RESET}"
        echo "$(date '+%Y-%m-%d %H:%M:%S') - 启动 Snell 服务失败" >> "$SNELL_LOG_FILE"
        exit 1
    fi

    # 查看 Snell 日志
    echo -e "${SNELL_GREEN}Snell (端口 ${SNELL_PORT}) 安装成功${SNELL_RESET}"
    sleep 3
    journalctl -u ${SNELL_SERVICE_NAME} -n 8 --no-pager || echo -e "${SNELL_YELLOW}无法获取日志，但不影响服务运行${SNELL_RESET}"

    # 获取本机IP地址
    HOST_IP=$(curl -s --max-time 5 http://checkip.amazonaws.com)
    if [ -z "$HOST_IP" ]; then
        HOST_IP=$(curl -s --max-time 5 http://ifconfig.me)
    fi
    if [ -z "$HOST_IP" ]; then
        HOST_IP="127.0.0.1"
    fi

    # 构造最终配置字符串
    local FINAL_CONFIG="${NODE_NAME} = snell, ${HOST_IP}, ${SNELL_PORT}, psk=${RANDOM_PSK}, version=5, reuse=true${IP_VERSION_STR}"

    echo ""
    echo -e "${SNELL_GREEN}节点信息输出：${SNELL_RESET}"
    echo -e "${SNELL_CYAN}${FINAL_CONFIG}${SNELL_RESET}"
    
    cat << EOF > /etc/snell/config-${SNELL_PORT}.txt
${FINAL_CONFIG}
EOF
}

# 更新 Snell
update_snell() {
    # 检查 Snell 是否已安装
    INSTALL_DIR="/usr/local/bin"
    SNELL_BIN="${INSTALL_DIR}/snell-server"
    if [ ! -f "${SNELL_BIN}" ]; then
        echo -e "${SNELL_YELLOW}Snell 未安装，跳过更新${SNELL_RESET}"
        return
    fi

    echo -e "${SNELL_GREEN}Snell 正在更新${SNELL_RESET}"

    # 停止所有 Snell 实例
    echo -e "${SNELL_GREEN}正在停止所有 Snell 服务...${SNELL_RESET}"
    for service_file in /etc/systemd/system/snell-*.service; do
        if [ -f "$service_file" ]; then
            service_name=$(basename "$service_file")
            systemctl stop "$service_name" 2>/dev/null
        fi
    done
    # 兼容旧版单实例
    systemctl stop snell 2>/dev/null

    # 等待包管理器
    wait_for_package_manager_snell

    # 检查是否已安装 Snell 核心程序
    echo -e "${SNELL_GREEN}正在安装 Snell 核心程序...${SNELL_RESET}"
    
    # 安装必要的软件包
    if ! install_required_packages_snell; then
        echo -e "${SNELL_RED}安装必要软件包失败，请检查您的网络连接。${SNELL_RESET}"
        echo "$(date '+%Y-%m-%d %H:%M:%S') - 安装必要软件包失败" >> "$SNELL_LOG_FILE"
        exit 1
    fi

    # 下载 Snell 服务器文件
    ARCH=$(arch)
    VERSION="v5.0.1"
    SNELL_URL=""

    if [[ ${ARCH} == "aarch64" ]]; then
        SNELL_URL="https://dl.nssurge.com/snell/snell-server-${VERSION}-linux-aarch64.zip"
    else
        SNELL_URL="https://dl.nssurge.com/snell/snell-server-${VERSION}-linux-amd64.zip"
    fi

    # 下载 Snell 服务器文件
    if ! wget ${SNELL_URL} -O snell-server.zip; then
        echo -e "${SNELL_RED}下载 Snell 失败。${SNELL_RESET}"
        echo "$(date '+%Y-%m-%d %H:%M:%S') - 下载 Snell 失败" >> "$SNELL_LOG_FILE"
        exit 1
    fi

    # 解压缩文件到指定目录
    if ! unzip -o snell-server.zip -d ${INSTALL_DIR}; then
        echo -e "${SNELL_RED}解压缩 Snell 失败。${SNELL_RESET}"
        echo "$(date '+%Y-%m-%d %H:%M:%S') - 解压缩 Snell 失败" >> "$SNELL_LOG_FILE"
        exit 1
    fi

    # 删除下载的 zip 文件
    rm snell-server.zip

    # 赋予执行权限
    chmod +x ${INSTALL_DIR}/snell-server

    # 重启 Snell
    # 重启所有 Snell 实例
    echo -e "${SNELL_GREEN}正在重启所有 Snell 服务...${SNELL_RESET}"
    local restart_count=0
    for service_file in /etc/systemd/system/snell-*.service; do
        if [ -f "$service_file" ]; then
            service_name=$(basename "$service_file")
            if systemctl restart "$service_name"; then
                ((restart_count++))
            else
                echo -e "${SNELL_RED}重启 ${service_name} 失败${SNELL_RESET}"
            fi
        fi
    done
    
    # 兼容旧版单实例
    if [ -f "/etc/systemd/system/snell.service" ] || [ -f "/lib/systemd/system/snell.service" ]; then
        systemctl restart snell 2>/dev/null
    fi

    if [ $restart_count -eq 0 ] && ! systemctl is-active --quiet snell; then
        echo -e "${SNELL_YELLOW}未检测到活动的 Snell 服务实例${SNELL_RESET}"
    fi

    echo -e "${SNELL_GREEN}Snell 更新成功，非TF版本请改为version = 4${SNELL_RESET}"
    cat /etc/snell/config.txt
}

# 列出所有 Snell 实例
list_snell_instances() {
    echo -e "${SNELL_CYAN}当前已安装的 Snell 实例：${SNELL_RESET}"
    echo "================================================================"
    printf "%-30s %-12s %-12s %-10s\n" "节点名称" "端口" "状态" "版本"
    echo "================================================================"

    local count=0
    
    # 检查新版多实例服务
    for service_file in /etc/systemd/system/snell-*.service; do
        if [ -f "$service_file" ]; then
            local port=$(echo "$service_file" | sed -E 's/.*snell-([0-9]+)\.service/\1/')
            
            # 判断状态（纯文本，不带颜色）
            local status_text="已停止"
            if systemctl is-active --quiet "snell-${port}.service"; then
                status_text="运行中"
            fi
            
            # 从配置文件读取节点名称
            local node_name="未命名"
            if [ -f "/etc/snell/config-${port}.txt" ]; then
                node_name=$(head -n 1 "/etc/snell/config-${port}.txt" | awk -F' = ' '{print $1}')
            fi
            
            local version="v5"
            
            # 输出时根据状态添加颜色
            if [ "$status_text" = "运行中" ]; then
                printf "%-30s %-12s ${SNELL_GREEN}%-12s${SNELL_RESET} %-10s\n" "$node_name" "$port" "$status_text" "$version"
            else
                printf "%-30s %-12s ${SNELL_RED}%-12s${SNELL_RESET} %-10s\n" "$node_name" "$port" "$status_text" "$version"
            fi
            ((count++))
        fi
    done

    # 检查旧版单实例服务
    if [ -f "/lib/systemd/system/snell.service" ] || [ -f "/etc/systemd/system/snell.service" ]; then
        local status_text="已停止"
        if systemctl is-active --quiet "snell.service"; then
            status_text="运行中"
        fi
        
        # 尝试从配置文件读取端口
        local port="未知"
        if [ -f "/etc/snell/snell-server.conf" ]; then
            port=$(grep "listen" /etc/snell/snell-server.conf | awk -F':' '{print $NF}')
        fi
        
        # 尝试读取旧版节点名称
        local node_name="旧版实例"
        if [ -f "/etc/snell/config.txt" ]; then
            node_name=$(head -n 1 "/etc/snell/config.txt" | awk -F' = ' '{print $1}')
        fi
        
        if [ "$status_text" = "运行中" ]; then
            printf "%-30s %-12s ${SNELL_GREEN}%-12s${SNELL_RESET} %-10s\n" "$node_name" "$port" "$status_text" "v5"
        else
            printf "%-30s %-12s ${SNELL_RED}%-12s${SNELL_RESET} %-10s\n" "$node_name" "$port" "$status_text" "v5"
        fi
        ((count++))
    fi

    if [ "$count" -eq 0 ]; then
        echo "暂无安装任何 Snell 实例"
    fi
    echo "================================================================"
    echo ""
    return $count
}

# 卸载 Snell
uninstall_snell() {
    echo -e "${SNELL_GREEN}=== 卸载 Snell 服务 ===${SNELL_RESET}"
    
    list_snell_instances
    local instance_count=$?
    
    if [ "$instance_count" -eq 0 ]; then
        echo -e "${SNELL_YELLOW}未检测到任何 Snell 实例，无需卸载。${SNELL_RESET}"
        return
    fi

    echo "请选择卸载方式："
    echo "1. 卸载指定端口的实例"
    echo "2. 卸载所有实例"
    echo "0. 取消"
    read -p "请输入选项 [0-2]: " uninstall_choice

    case "$uninstall_choice" in
        1)
            read -p "请输入要卸载的端口号: " port_to_uninstall
            if [ -z "$port_to_uninstall" ]; then
                echo "端口号不能为空"
                return
            fi
            
            # 检查是否存在该端口的服务
            local service_name=""
            if [ -f "/etc/systemd/system/snell-${port_to_uninstall}.service" ]; then
                service_name="snell-${port_to_uninstall}.service"
            elif [ -f "/lib/systemd/system/snell.service" ] || [ -f "/etc/systemd/system/snell.service" ]; then
                # 检查旧版服务是否使用该端口
                if grep -q ":${port_to_uninstall}" /etc/snell/snell-server.conf 2>/dev/null; then
                    service_name="snell.service"
                fi
            fi
            
            if [ -z "$service_name" ]; then
                echo -e "${SNELL_RED}未找到端口为 ${port_to_uninstall} 的 Snell 实例${SNELL_RESET}"
                return
            fi
            
            echo "正在卸载服务: ${service_name} ..."
            systemctl stop "$service_name"
            systemctl disable "$service_name"
            rm "/etc/systemd/system/${service_name}" 2>/dev/null
            rm "/lib/systemd/system/${service_name}" 2>/dev/null
            
            if [ "$service_name" == "snell.service" ]; then
                rm /etc/snell/snell-server.conf 2>/dev/null
            else
                rm "/etc/snell/snell-${port_to_uninstall}.conf" 2>/dev/null
                rm "/etc/snell/config-${port_to_uninstall}.txt" 2>/dev/null
            fi
            
            systemctl daemon-reload
            echo -e "${SNELL_GREEN}实例 ${port_to_uninstall} 卸载成功${SNELL_RESET}"
            ;;
        2)
            echo "正在卸载所有 Snell 实例..."
            # 卸载新版多实例
            for service_file in /etc/systemd/system/snell-*.service; do
                if [ -f "$service_file" ]; then
                    local port=$(echo "$service_file" | sed -E 's/.*snell-([0-9]+)\.service/\1/')
                    echo "卸载端口 $port ..."
                    systemctl stop "snell-${port}.service"
                    systemctl disable "snell-${port}.service"
                    rm "$service_file"
                fi
            done
            
            # 卸载旧版实例
            if systemctl list-unit-files | grep -q "snell.service"; then
                echo "卸载旧版默认实例..."
                systemctl stop snell.service
                systemctl disable snell.service
                rm /lib/systemd/system/snell.service 2>/dev/null
                rm /etc/systemd/system/snell.service 2>/dev/null
            fi
            
            # 清理配置目录
            rm -rf /etc/snell
            # 清理二进制文件
            rm /usr/local/bin/snell-server
            
            systemctl daemon-reload
            echo -e "${SNELL_GREEN}所有 Snell 实例已卸载${SNELL_RESET}"
            ;;
        *)
            echo "已取消"
            ;;
    esac
}


# Snell 主函数
# Snell 管理菜单
snell_menu() {
    while true; do
        clear
        echo -e "${SNELL_CYAN}=== Snell 管理工具 ===${SNELL_RESET}"
        
        # 统计实例数量
        local instance_count=0
        local running_count=0
        
        # 统计新版实例
        for service_file in /etc/systemd/system/snell-*.service; do
            if [ -f "$service_file" ]; then
                ((instance_count++))
                local port=$(echo "$service_file" | sed -E 's/.*snell-([0-9]+)\.service/\1/')
                if systemctl is-active --quiet "snell-${port}.service"; then
                    ((running_count++))
                fi
            fi
        done
        
        # 统计旧版实例
        if [ -f "/lib/systemd/system/snell.service" ] || [ -f "/etc/systemd/system/snell.service" ]; then
            ((instance_count++))
            if systemctl is-active --quiet "snell.service"; then
                ((running_count++))
            fi
        fi
        
        echo -e "已安装实例: ${SNELL_GREEN}${instance_count}${SNELL_RESET} 个"
        echo -e "运行中实例: ${SNELL_GREEN}${running_count}${SNELL_RESET} 个"
        
        # 动态获取 Snell 版本
        local snell_version="未知"
        if [ -f "/usr/local/bin/snell-server" ]; then
            # 尝试获取版本号（Snell 没有 --version 参数，通过文件修改时间或固定版本号）
            # 这里使用配置中指定的版本号
            snell_version="v5.0.1"
        fi
        echo -e "运行版本: ${snell_version}"
        echo ""
        echo "1. 安装/添加 Snell 服务"
        echo "2. 卸载/删除 Snell 服务"
        echo "3. 查看所有 Snell 实例"
        echo "4. 更新 Snell 服务 (更新核心程序)"
        echo "5. 查看 Snell 配置"
        echo "0. 返回主菜单"
        echo "======================"
        read -p "请输入选项编号: " snell_choice

        case "$snell_choice" in
            1) 
                install_snell
                echo ""
                read -n 1 -s -r -p "按任意键继续..."
                ;;
            2) uninstall_snell ;;
            3) 
                list_snell_instances 
                echo ""
                read -n 1 -s -r -p "按任意键继续..."
                ;;
            4) update_snell ;;
            5) 
                echo ""
                list_snell_instances
                local count=$?
                if [ "$count" -gt 0 ]; then
                    echo ""
                    read -p "请输入要查看配置的端口号: " view_port
                    if [ -f "/etc/snell/config-${view_port}.txt" ]; then
                        echo ""
                        cat "/etc/snell/config-${view_port}.txt"
                    elif [ -f "/etc/snell/snell-server.conf" ] && grep -q ":${view_port}" /etc/snell/snell-server.conf; then
                         # 旧版配置查看 (这里只是简单处理，实际上旧版没有 config.txt 备份可能需要解析 conf 文件)
                         echo "旧版配置 (端口 ${view_port}):"
                         cat /etc/snell/snell-server.conf
                    else
                        echo -e "${SNELL_RED}未找到端口 ${view_port} 的配置文件${SNELL_RESET}"
                    fi
                    echo ""
                    read -n 1 -s -r -p "按任意键继续..."
                else
                    echo ""
                    read -n 1 -s -r -p "按任意键继续..."
                fi
                ;;
            0) return ;;
            *) echo -e "${SNELL_RED}无效选项${SNELL_RESET}"; sleep 1 ;;
        esac
    done
}

#=============================================================================
# 星辰大海 Xray 一键多协议
#=============================================================================

run_xinchendahai_xray() {
    clear
    echo -e "${gl_kjlan}=== 星辰大海Xray一键多协议（增强版） ===${gl_bai}"
    echo ""
    echo -e "${gl_lv}✨ 功能特性：${gl_bai}"
    echo "  • 支持多 VLESS 节点部署（不同端口）"
    echo "  • 随机 shortid 生成（更安全）"
    echo "  • SNI 域名快速选择（addons.mozilla.org / updates.cdn-apple.com）"
    echo "  • 节点自定义命名"
    echo "  • 灵活的节点管理（增加/删除/修改）"
    echo "------------------------------------------------"
    echo ""

    # 创建临时脚本
    local script_path="/tmp/xinchendahai_xray_$$.sh"

    echo "正在准备星辰大海Xray增强版脚本..."

    # 将完整脚本内容写入临时文件
    cat > "$script_path" << 'XRAY_ENHANCED_SCRIPT_EOF'
#!/bin/bash

# ==============================================================================
# Xray VLESS-Reality & Shadowsocks 2022 多功能管理脚本
# 版本: Final v2.9.1
# 更新日志 (v2.9.1):
# - [安全] 添加配置文件权限保护
# - [安全] 增强脚本下载验证
# - [安全] 敏感信息显示保护
# - [稳定] 网络操作重试机制
# - [稳定] 服务启动详细错误显示
# ==============================================================================

# --- Shell 严格模式 ---
set -euo pipefail

# --- 全局常量 ---
readonly XRAY_SCRIPT_VERSION="Final v2.9.1"
readonly xray_config_path="/usr/local/etc/xray/config.json"
readonly xray_binary_path="/usr/local/bin/xray"
readonly xray_install_script_url="https://github.com/XTLS/Xray-install/raw/main/install-release.sh"

# --- 颜色定义 ---
readonly red='\e[91m' green='\e[92m' yellow='\e[93m'
readonly magenta='\e[95m' cyan='\e[96m' none='\e[0m'

# --- 全局变量 ---
xray_status_info=""
is_quiet=false

# --- 辅助函数 ---
error() { 
    echo -e "\n$red[✖] $1$none\n" >&2
    
    # 根据错误内容提供简单建议
    case "$1" in
        *"网络"*|*"下载"*) 
            echo -e "$yellow提示: 检查网络连接或更换DNS$none" >&2 ;;
        *"权限"*|*"root"*) 
            echo -e "$yellow提示: 请使用 sudo 运行脚本$none" >&2 ;;
        *"端口"*) 
            echo -e "$yellow提示: 尝试使用其他端口号$none" >&2 ;;
    esac
}

info() { [[ "$is_quiet" = false ]] && echo -e "\n$yellow[!] $1$none\n"; }
success() { [[ "$is_quiet" = false ]] && echo -e "\n$green[✔] $1$none\n"; }
warning() { [[ "$is_quiet" = false ]] && echo -e "\n$yellow[⚠] $1$none\n"; }

spinner() {
    local pid="$1"
    local spinstr='|/-\'
    if [[ "$is_quiet" = true ]]; then
        wait "$pid"
        return
    fi
    while ps -p "$pid" > /dev/null; do
        local temp=${spinstr#?}
        printf " [%c]  " "$spinstr"
        local spinstr=$temp${spinstr%"$temp"}
        sleep 0.1
        printf "\r"
    done
    printf "    \r"
}

get_public_ip() {
    local ip
    local attempts=0
    local max_attempts=2
    
    while [[ $attempts -lt $max_attempts ]]; do
        for cmd in "curl -4s --max-time 5" "wget -4qO- --timeout=5"; do
            for url in "https://api.ipify.org" "https://ip.sb" "https://checkip.amazonaws.com"; do
                ip=$($cmd "$url" 2>/dev/null) && [[ -n "$ip" ]] && echo "$ip" && return
            done
        done
        ((attempts++))
        [[ $attempts -lt $max_attempts ]] && sleep 1
    done
    
    # IPv6 fallback
    for cmd in "curl -6s --max-time 5" "wget -6qO- --timeout=5"; do
        for url in "https://api64.ipify.org" "https://ip.sb"; do
            ip=$($cmd "$url" 2>/dev/null) && [[ -n "$ip" ]] && echo "$ip" && return
        done
    done
}

# --- 预检查与环境设置 ---
pre_check() {
    [[ "$(id -u)" != 0 ]] && error "错误: 您必须以root用户身份运行此脚本" && exit 1
    if [ ! -f /etc/debian_version ]; then error "错误: 此脚本仅支持 Debian/Ubuntu 及其衍生系统。" && exit 1; fi
    if ! command -v jq &>/dev/null || ! command -v curl &>/dev/null; then
        info "检测到缺失的依赖 (jq/curl)，正在尝试自动安装..."
        (DEBIAN_FRONTEND=noninteractive apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y jq curl) &> /dev/null &
        spinner $!
        if ! command -v jq &>/dev/null || ! command -v curl &>/dev/null; then
            error "依赖 (jq/curl) 自动安装失败。请手动运行 'apt update && apt install -y jq curl' 后重试。"
            exit 1
        fi
        success "依赖已成功安装。"
    fi
}

check_xray_status() {
    if [[ ! -f "$xray_binary_path" || ! -x "$xray_binary_path" ]]; then
        xray_status_info=" Xray 状态: ${red}未安装${none}"
        return
    fi
    local xray_version
    xray_version=$("$xray_binary_path" version 2>/dev/null | head -n 1 | awk '{print $2}' || echo "未知")
    local service_status
    if systemctl is-active --quiet xray 2>/dev/null; then
        service_status="${green}运行中${none}"
    else
        service_status="${yellow}未运行${none}"
    fi
    xray_status_info=" Xray 状态: ${green}已安装${none} | ${service_status} | 版本: ${cyan}${xray_version}${none}"
}

# 新增：快速状态检查
quick_status() {
    if [[ ! -f "$xray_binary_path" ]]; then
        echo -e " ${red}●${none} 未安装"
        return
    fi
    
    local status_icon
    if systemctl is-active --quiet xray 2>/dev/null; then
        status_icon="${green}●${none}"
    else
        status_icon="${red}●${none}"
    fi
    
    echo -e " $status_icon Xray $(systemctl is-active xray 2>/dev/null || echo "inactive")"
}

# --- 核心配置生成函数 ---
generate_ss_key() {
    openssl rand -base64 16
}

# 生成随机 shortid (8位十六进制)
generate_shortid() {
    openssl rand -hex 4
}

build_vless_inbound() {
    local port="$1" uuid="$2" domain="$3" private_key="$4" public_key="$5" node_name="$6"
    local shortid="${7:-$(generate_shortid)}"
    jq -n --argjson port "$port" --arg uuid "$uuid" --arg domain "$domain" --arg private_key "$private_key" --arg public_key "$public_key" --arg shortid "$shortid" --arg node_name "$node_name" \
    '{ "listen": "0.0.0.0", "port": $port, "protocol": "vless", "settings": {"clients": [{"id": $uuid, "flow": "xtls-rprx-vision"}], "decryption": "none"}, "streamSettings": {"network": "tcp", "security": "reality", "realitySettings": {"show": false, "dest": ($domain + ":443"), "xver": 0, "serverNames": [$domain], "privateKey": $private_key, "publicKey": $public_key, "shortIds": [$shortid]}}, "sniffing": {"enabled": true, "destOverride": ["http", "tls", "quic"]}, "tag": $node_name }'
}

build_ss_inbound() {
    local port="$1" password="$2" node_name="$3"
    jq -n --argjson port "$port" --arg password "$password" --arg node_name "$node_name" \
    '{ "listen": "0.0.0.0", "port": $port, "protocol": "shadowsocks", "settings": {"method": "2022-blake3-aes-128-gcm", "password": $password}, "tag": $node_name }'
}

write_config() {
    local inbounds_json="$1"
    local enable_routing="${2:-}"
    local config_content

    # 🔥 核心逻辑：如果调用者没指定 enable_routing，就自动检测现有配置
    if [[ -z "$enable_routing" ]]; then
        # 检测现有配置文件是否存在 routing 配置
        if [[ -f "$xray_config_path" ]]; then
            local has_routing
            has_routing=$(jq -r '.routing // empty' "$xray_config_path" 2>/dev/null)
            if [[ -n "$has_routing" ]]; then
                enable_routing="true"
            else
                enable_routing="false"
            fi
        else
            # 配置文件不存在，默认不启用路由
            enable_routing="false"
        fi
    fi

    # 🆕 保留现有的自定义 outbounds（SOCKS5等）
    local existing_custom_outbounds="[]"
    local existing_custom_routing_rules="[]"
    local should_preserve_config=false
    
    if [[ -f "$xray_config_path" ]]; then
        # 🛡️ 首先检测是否为 Xray 官方默认配置
        # 只有配置文件包含我们添加的节点（VLESS或Shadowsocks）时，才尝试保留现有配置
        if jq -e '.inbounds[]? | select(.protocol == "vless" or .protocol == "shadowsocks")' "$xray_config_path" &>/dev/null; then
            should_preserve_config=true
        fi
        
        # 只有当配置文件包含我们的节点时，才尝试保留现有配置
        if [[ "$should_preserve_config" == "true" ]]; then
            # 验证配置文件是否为有效的 JSON
            if jq empty "$xray_config_path" 2>/dev/null; then
                # 提取所有非默认的 outbounds（保留 SOCKS5 等自定义代理）
                local temp_outbounds
                temp_outbounds=$(jq -c '[.outbounds[]? | select(.protocol != "freedom" and .protocol != "blackhole")]' "$xray_config_path" 2>/dev/null)
                
                # 验证提取结果是否为有效的 JSON 数组
                if [[ -n "$temp_outbounds" ]] && echo "$temp_outbounds" | jq empty 2>/dev/null; then
                    existing_custom_outbounds="$temp_outbounds"
                fi
                
                # 提取所有自定义的 routing rules（排除默认的广告过滤规则）
                # 判断是否为自定义规则：包含 inboundTag 或 outboundTag 以 "socks5-" 开头
                local temp_rules
                temp_rules=$(jq -c '[.routing.rules[]? | select(.inboundTag != null or (.outboundTag? | startswith("socks5-")))]' "$xray_config_path" 2>/dev/null)
                
                # 验证提取结果是否为有效的 JSON 数组
                if [[ -n "$temp_rules" ]] && echo "$temp_rules" | jq empty 2>/dev/null; then
                    existing_custom_routing_rules="$temp_rules"
                fi
            else
                warning "现有配置文件格式异常，将忽略现有的自定义配置"
            fi
        fi
    fi
    
    # 🔧 确保所有 JSON 变量都是紧凑的单行格式
    inbounds_json=$(echo "$inbounds_json" | jq -c '.')
    existing_custom_outbounds=$(echo "$existing_custom_outbounds" | jq -c '.')
    existing_custom_routing_rules=$(echo "$existing_custom_routing_rules" | jq -c '.')
    
    # 🔧 在 shell 中预先构建完整的 outbounds 数组
    # 这样可以避免在 jq 表达式内部使用 + 操作符，解决兼容性问题
    local base_outbounds
    if [[ "$enable_routing" == "true" ]]; then
        base_outbounds='[{"protocol":"freedom","tag":"direct","settings":{"domainStrategy":"UseIPv4v6"}},{"protocol":"blackhole","tag":"block"}]'
    else
        base_outbounds='[{"protocol":"freedom","settings":{"domainStrategy":"UseIPv4v6"}}]'
    fi
    
    # 使用 jq 合并 outbounds 数组（在 shell 中完成，不是在 jq 表达式内部）
    local full_outbounds
    full_outbounds=$(echo "$base_outbounds" | jq -c --argjson custom "$existing_custom_outbounds" '. + $custom')
    
    # 构建完整的 routing rules
    local full_rules
    if [[ "$enable_routing" == "true" ]]; then
        local default_block_rule='[{"type":"field","domain":["geosite:category-ads-all","geosite:category-porn","regexp:.*missav.*","geosite:missav"],"outboundTag":"block"}]'
        full_rules=$(echo "$existing_custom_routing_rules" | jq -c --argjson default "$default_block_rule" '. + $default')
    else
        full_rules="$existing_custom_routing_rules"
    fi

    if [[ "$enable_routing" == "true" ]]; then
        # 带路由规则的配置
        config_content=$(jq -n \
            --argjson inbounds "$inbounds_json" \
            --argjson outbounds "$full_outbounds" \
            --argjson rules "$full_rules" \
        '{
          "log": {"loglevel": "warning"},
          "inbounds": $inbounds,
          "outbounds": $outbounds,
          "routing": {
            "domainStrategy": "IPOnDemand",
            "rules": $rules
          }
        }')
    else
        # 不带路由规则的配置
        local rules_length
        rules_length=$(echo "$full_rules" | jq 'length')
        
        if [[ "$rules_length" -gt 0 ]]; then
            # 有自定义 rules，需要添加 routing
            config_content=$(jq -n \
                --argjson inbounds "$inbounds_json" \
                --argjson outbounds "$full_outbounds" \
                --argjson rules "$full_rules" \
            '{
              "log": {"loglevel": "warning"},
              "inbounds": $inbounds,
              "outbounds": $outbounds,
              "routing": {
                "domainStrategy": "IPOnDemand",
                "rules": $rules
              }
            }')
        else
            # 没有 rules，不需要 routing
            config_content=$(jq -n \
                --argjson inbounds "$inbounds_json" \
                --argjson outbounds "$full_outbounds" \
            '{
              "log": {"loglevel": "warning"},
              "inbounds": $inbounds,
              "outbounds": $outbounds
            }')
        fi
    fi
    
    # 新增：验证生成的JSON是否有效
    if ! echo "$config_content" | jq . >/dev/null 2>&1; then
        error "生成的配置文件格式错误！"
        return 1
    fi
    
    echo "$config_content" > "$xray_config_path"

    # 安全：配置文件仅 nobody（xray运行用户）和 root 可读
    chmod 640 "$xray_config_path"
    chown nobody:root "$xray_config_path"
}

execute_official_script() {
    local args="$1"
    local script_content
    local temp_script="/tmp/xray_install_$$.sh"

    # 下载官方安装脚本
    if ! script_content=$(curl -fsSL --max-time 30 "$xray_install_script_url" 2>/dev/null); then
        error "下载 Xray 官方安装脚本失败！请检查网络连接。"
        return 1
    fi

    # 验证脚本内容
    if [[ -z "$script_content" || ! "$script_content" =~ "install-release" ]]; then
        error "Xray 官方安装脚本内容异常！"
        return 1
    fi

    # 写入临时文件并执行
    echo "$script_content" > "$temp_script"
    chmod +x "$temp_script"

    if [[ "$is_quiet" = false ]]; then
        bash "$temp_script" $args &
        spinner $!
        wait $! || { rm -f "$temp_script"; return 1; }
    else
        bash "$temp_script" $args &>/dev/null || { rm -f "$temp_script"; return 1; }
    fi

    rm -f "$temp_script"
    return 0
}

run_core_install() {
    info "正在下载并安装 Xray 核心..."
    if ! execute_official_script "install"; then
        error "Xray 核心安装失败！"
        return 1
    fi
    
    info "正在更新 GeoIP 和 GeoSite 数据文件..."
    if ! execute_official_script "install-geodata"; then
        error "Geo-data 更新失败！"
        info "这通常不影响核心功能，您可以稍后手动更新。"
    fi
    
    success "Xray 核心及数据文件已准备就绪。"
}

# --- 输入验证与交互函数 (优化) ---
is_valid_port() {
    local port="$1"
    [[ "$port" =~ ^[0-9]+$ ]] && [ "$port" -ge 1 ] && [ "$port" -le 65535 ]
}

# 显示系统端口使用情况
show_port_usage() {
    echo ""
    info "当前系统端口使用情况:"
    printf "%-15s %-9s\n" "程序名" "端口"
    echo "────────────────────────────────────────────────────────"

    # 解析ss输出，聚合同程序的端口
    declare -A program_ports
    while read line; do
        if [[ "$line" =~ LISTEN|UNCONN ]]; then
            local local_addr=$(echo "$line" | awk '{print $5}')
            local port=$(echo "$local_addr" | grep -o ':[0-9]*$' | cut -d':' -f2)
            local program=$(echo "$line" | awk '{print $7}' | cut -d'"' -f2 2>/dev/null || echo "")

            if [ -n "$port" ] && [ -n "$program" ] && [ "$program" != "-" ]; then
                if [ -z "${program_ports[$program]:-}" ]; then
                    program_ports[$program]="$port"
                else
                    # 避免重复端口
                    if [[ ! "${program_ports[$program]}" =~ (^|.*\|)$port(\||$) ]]; then
                        program_ports[$program]="${program_ports[$program]}|$port"
                    fi
                fi
            fi
        fi
    done < <(ss -tulnp 2>/dev/null || true)

    if [ ${#program_ports[@]} -gt 0 ]; then
        for program in $(printf '%s\n' "${!program_ports[@]}" | sort); do
            local ports="${program_ports[$program]}"
            printf "%-10s | %-9s\n" "$program" "$ports"
        done
    else
        echo "无活跃端口"
    fi

    echo "────────────────────────────────────────────────────────"
    echo ""
}

# 新增：端口可用性检测
is_port_available() {
    local port="$1"
    is_valid_port "$port" || return 1

    # 检查系统端口是否被占用
    if ss -tlpn 2>/dev/null | grep -q ":$port "; then
        error "端口 $port 已被系统占用"
        return 1
    fi

    # 检查配置文件中是否已存在该端口
    if [[ -f "$xray_config_path" ]]; then
        local existing_ports
        existing_ports=$(jq -r '.inbounds[]?.port // empty' "$xray_config_path" 2>/dev/null)
        if echo "$existing_ports" | grep -q "^${port}$"; then
            error "端口 $port 已在 Xray 配置中使用"
            return 1
        fi
    fi

    return 0
}

# 生成随机可用端口（排除所有已占用端口）
generate_random_port() {
    local max_attempts=100
    local attempt=0

    while [ $attempt -lt $max_attempts ]; do
        # 生成 10000-65535 范围的随机端口
        local random_port=$((RANDOM % 55536 + 10000))

        # 检查端口是否可用
        if is_port_available "$random_port" 2>/dev/null; then
            echo "$random_port"
            return 0
        fi

        attempt=$((attempt + 1))
    done

    # 如果 100 次都没找到可用端口，返回错误
    error "无法生成可用的随机端口，请手动指定"
    return 1
}

is_valid_domain() {
    local domain="$1"
    [[ "$domain" =~ ^[a-zA-Z0-9-]{1,63}(\.[a-zA-Z0-9-]{1,63})+$ ]] && [[ "$domain" != *--* ]]
}

prompt_for_vless_config() {
    local -n p_port="$1" p_uuid="$2" p_sni="$3" p_node_name="$4"
    local default_port="${5:-443}"

    # 显示端口使用情况
    show_port_usage

    while true; do
        read -p "$(echo -e " -> 请输入 VLESS 端口 (留空随机生成): ")" p_port || true
        if [[ -z "$p_port" ]]; then
            # 回车随机生成
            p_port=$(generate_random_port)
            if [ $? -eq 0 ]; then
                info "已为您随机生成端口: ${cyan}${p_port}${none}"
                break
            else
                continue
            fi
        else
            # 手动输入
            if is_port_available "$p_port"; then
                break
            fi
        fi
    done
    info "VLESS 端口将使用: ${cyan}${p_port}${none}"

    read -p "$(echo -e " -> 请输入UUID (留空将自动生成): ")" p_uuid || true
    if [[ -z "$p_uuid" ]]; then
        p_uuid=$(cat /proc/sys/kernel/random/uuid)
        info "已为您生成随机UUID: ${cyan}${p_uuid:0:8}...${p_uuid: -4}${none}"
    fi

    # SNI 域名选择
    echo ""
    echo -e "${cyan}请选择 SNI 域名:${none}"
    echo "  1. addons.mozilla.org"
    echo "  2. updates.cdn-apple.com"
    echo "  3. 自定义输入"
    read -p "$(echo -e "请输入选择 [${cyan}1${none}]: ")" sni_choice || true
    sni_choice=${sni_choice:-1}

    case "$sni_choice" in
        1)
            p_sni="addons.mozilla.org"
            ;;
        2)
            p_sni="updates.cdn-apple.com"
            ;;
        3)
            while true; do
                read -p "$(echo -e " -> 请输入自定义SNI域名: ")" p_sni || true
                if [[ -n "$p_sni" ]] && is_valid_domain "$p_sni"; then
                    break
                else
                    error "域名格式无效，请重新输入。"
                fi
            done
            ;;
        *)
            warning "无效选择，使用默认: addons.mozilla.org"
            p_sni="addons.mozilla.org"
            ;;
    esac
    info "SNI 域名将使用: ${cyan}${p_sni}${none}"

    # 节点名称
    read -p "$(echo -e " -> 请输入节点名称 (留空默认使用端口号): ")" p_node_name || true
    if [[ -z "$p_node_name" ]]; then
        p_node_name="VLESS-Reality-${p_port}"
        info "节点名称将使用: ${cyan}${p_node_name}${none}"
    fi
}

prompt_for_ss_config() {
    local -n p_port="$1" p_pass="$2" p_node_name="$3"
    local default_port="${4:-8388}"

    # 显示端口使用情况
    show_port_usage

    while true; do
        read -p "$(echo -e " -> 请输入 Shadowsocks 端口 (留空随机生成): ")" p_port || true
        if [[ -z "$p_port" ]]; then
            # 回车随机生成
            p_port=$(generate_random_port)
            if [ $? -eq 0 ]; then
                info "已为您随机生成端口: ${cyan}${p_port}${none}"
                break
            else
                continue
            fi
        else
            # 手动输入
            if is_port_available "$p_port"; then
                break
            fi
        fi
    done
    info "Shadowsocks 端口将使用: ${cyan}${p_port}${none}"

    read -p "$(echo -e " -> 请输入 Shadowsocks 密钥 (留空将自动生成): ")" p_pass || true
    if [[ -z "$p_pass" ]]; then
        p_pass=$(generate_ss_key)
        info "已为您生成随机密钥: ${cyan}${p_pass:0:4}...${p_pass: -4}${none}"
    fi

    # 节点名称
    read -p "$(echo -e " -> 请输入节点名称 (留空默认使用端口号): ")" p_node_name || true
    if [[ -z "$p_node_name" ]]; then
        p_node_name="Shadowsocks-2022-${p_port}"
        info "节点名称将使用: ${cyan}${p_node_name}${none}"
    fi
}

# --- 菜单功能函数 ---
draw_divider() {
    printf "%0.s─" {1..48}
    printf "\n"
}

draw_menu_header() {
    clear
    echo -e "${cyan} Xray VLESS-Reality & Shadowsocks-2022 管理脚本${none}"
    echo -e "${yellow} Version: ${XRAY_SCRIPT_VERSION}${none}"
    draw_divider
    check_xray_status
    echo -e "${xray_status_info}"
    quick_status  # 新增快速状态显示
    draw_divider
}

press_any_key_to_continue() {
    echo ""
    read -n 1 -s -r -p " 按任意键返回主菜单..." || true
}

install_menu() {
    local vless_exists="" ss_exists=""
    if [[ -f "$xray_config_path" ]]; then
        vless_exists=$(jq '.inbounds[] | select(.protocol == "vless")' "$xray_config_path" 2>/dev/null || true)
        ss_exists=$(jq '.inbounds[] | select(.protocol == "shadowsocks")' "$xray_config_path" 2>/dev/null || true)
    fi
    
    draw_menu_header
    if [[ -n "$vless_exists" && -n "$ss_exists" ]]; then
        success "您已安装 VLESS-Reality + Shadowsocks-2022 双协议。"
        info "如需修改，请使用主菜单的"修改配置"选项。\n 如需重装，请先"卸载"后，再重新"安装"。"
        return
    elif [[ -n "$vless_exists" && -z "$ss_exists" ]]; then
        info "检测到您已安装 VLESS-Reality"
        echo -e "${cyan} 请选择下一步操作${none}"
        draw_divider
        printf "  ${green}%-2s${none} %-35s\n" "1." "追加安装 Shadowsocks-2022 (组成双协议)"
        printf "  ${red}%-2s${none} %-35s\n" "2." "覆盖重装 VLESS-Reality"
        draw_divider
        printf "  ${yellow}%-2s${none} %-35s\n" "0." "返回主菜单"
        draw_divider
        read -p " 请输入选项 [0-2]: " choice || true
        case "$choice" in 1) add_ss_to_vless ;; 2) install_vless_only ;; 0) return ;; *) error "无效选项。" ;; esac
    elif [[ -z "$vless_exists" && -n "$ss_exists" ]]; then
        info "检测到您已安装 Shadowsocks-2022"
        echo -e "${cyan} 请选择下一步操作${none}"
        draw_divider
        printf "  ${green}%-2s${none} %-35s\n" "1." "追加安装 VLESS-Reality (组成双协议)"
        printf "  ${red}%-2s${none} %-35s\n" "2." "覆盖重装 Shadowsocks-2022"
        draw_divider
        printf "  ${yellow}%-2s${none} %-35s\n" "0." "返回主菜单"
        draw_divider
        read -p " 请输入选项 [0-2]: " choice || true
        case "$choice" in 1) add_vless_to_ss ;; 2) install_ss_only ;; 0) return ;; *) error "无效选项。" ;; esac
    else
        clean_install_menu
    fi
}

clean_install_menu() {
    draw_menu_header
    echo -e "${cyan} 请选择要安装的协议类型${none}"
    draw_divider
    printf "  ${green}%-2s${none} %-35s\n" "1." "仅 VLESS-Reality"
    printf "  ${cyan}%-2s${none} %-35s\n" "2." "仅 Shadowsocks-2022"
    printf "  ${yellow}%-2s${none} %-35s\n" "3." "VLESS-Reality + Shadowsocks-2022 (双协议)"
    draw_divider
    printf "  ${magenta}%-2s${none} %-35s\n" "0." "返回主菜单"
    draw_divider
    read -p " 请输入选项 [0-3]: " choice || true
    case "$choice" in 1) install_vless_only ;; 2) install_ss_only ;; 3) install_dual ;; 0) return ;; *) error "无效选项。" ;; esac
}

add_ss_to_vless() {
    info "开始追加安装 Shadowsocks-2022..."
    if [[ -z "$(get_public_ip)" ]]; then
        error "无法获取公网 IP 地址，操作中止。请检查您的网络连接。"
        return 1
    fi
    local vless_inbound vless_port default_ss_port ss_port ss_password ss_node_name ss_inbound
    vless_inbound=$(jq '.inbounds[] | select(.protocol == "vless")' "$xray_config_path")
    vless_port=$(echo "$vless_inbound" | jq -r '.port')
    default_ss_port=$([[ "$vless_port" == "443" ]] && echo "8388" || echo "$((vless_port + 1))")

    prompt_for_ss_config ss_port ss_password ss_node_name "$default_ss_port"

    ss_inbound=$(build_ss_inbound "$ss_port" "$ss_password" "$ss_node_name")
    write_config "[$vless_inbound, $ss_inbound]"

    if ! restart_xray; then return 1; fi

    success "追加安装成功！"
    view_all_info
}

add_vless_to_ss() {
    info "开始追加安装 VLESS-Reality..."
    if [[ -z "$(get_public_ip)" ]]; then
        error "无法获取公网 IP 地址，操作中止。请检查您的网络连接。"
        return 1
    fi
    local ss_inbound ss_port default_vless_port vless_port vless_uuid vless_domain vless_node_name key_pair private_key public_key vless_inbound
    ss_inbound=$(jq '.inbounds[] | select(.protocol == "shadowsocks")' "$xray_config_path")
    ss_port=$(echo "$ss_inbound" | jq -r '.port')
    default_vless_port=$([[ "$ss_port" == "8388" ]] && echo "443" || echo "$((ss_port - 1))")

    prompt_for_vless_config vless_port vless_uuid vless_domain vless_node_name "$default_vless_port"

    info "正在生成 Reality 密钥对..."
    key_pair=$("$xray_binary_path" x25519)
    private_key=$(echo "$key_pair" | awk '/PrivateKey:/ {print $2}')
    public_key=$(echo "$key_pair" | awk '/Password:/ {print $2}')

    if [[ -z "$private_key" || -z "$public_key" ]]; then
        error "生成 Reality 密钥对失败！请检查 Xray 核心是否正常，或尝试卸载后重装。"
        exit 1
    fi

    vless_inbound=$(build_vless_inbound "$vless_port" "$vless_uuid" "$vless_domain" "$private_key" "$public_key" "$vless_node_name")
    write_config "[$vless_inbound, $ss_inbound]"

    if ! restart_xray; then return 1; fi

    success "追加安装成功！"
    view_all_info
}

install_vless_only() {
    info "开始配置 VLESS-Reality..."
    local port uuid domain node_name
    prompt_for_vless_config port uuid domain node_name
    run_install_vless "$port" "$uuid" "$domain" "$node_name"
}

install_ss_only() {
    info "开始配置 Shadowsocks-2022..."
    local port password node_name
    prompt_for_ss_config port password node_name
    run_install_ss "$port" "$password" "$node_name"
}

install_dual() {
    info "开始配置双协议 (VLESS-Reality + Shadowsocks-2022)..."
    local vless_port vless_uuid vless_domain vless_node_name ss_port ss_password ss_node_name
    prompt_for_vless_config vless_port vless_uuid vless_domain vless_node_name

    local default_ss_port
    if [[ "$vless_port" == "443" ]]; then
        default_ss_port=8388
    else
        default_ss_port=$((vless_port + 1))
    fi

    prompt_for_ss_config ss_port ss_password ss_node_name "$default_ss_port"

    run_install_dual "$vless_port" "$vless_uuid" "$vless_domain" "$vless_node_name" "$ss_port" "$ss_password" "$ss_node_name"
}

update_xray() {
    if [[ ! -f "$xray_binary_path" ]]; then error "错误: Xray 未安装。" && return; fi
    info "正在检查最新版本..."
    local current_version latest_version
    current_version=$("$xray_binary_path" version 2>/dev/null | head -n 1 | awk '{print $2}')

    # 尝试多种方式获取最新版本
    latest_version=$(curl -s --max-time 10 https://api.github.com/repos/XTLS/Xray-core/releases/latest 2>/dev/null | jq -r '.tag_name' 2>/dev/null | sed 's/v//' || echo "")

    if [[ -z "$latest_version" ]]; then
        warning "无法通过 GitHub API 获取最新版本，尝试直接更新..."
        info "开始更新 Xray..."
        if ! run_core_install; then
            error "Xray 更新失败！"
            return 1
        fi
        if ! restart_xray; then return 1; fi
        success "Xray 更新完成！"
        return
    fi

    info "当前版本: ${cyan}${current_version}${none}，最新版本: ${cyan}${latest_version}${none}"

    if [[ "$current_version" == "$latest_version" ]]; then
        success "您的 Xray 已是最新版本。"
        return
    fi

    info "发现新版本，开始更新..."
    if ! run_core_install; then
        error "Xray 更新失败！"
        return 1
    fi
    if ! restart_xray; then return 1; fi
    success "Xray 更新成功！"
}

uninstall_xray() {
    if [[ ! -f "$xray_binary_path" ]]; then error "错误: Xray 未安装。" && return; fi
    read -p "$(echo -e "${yellow}您确定要卸载 Xray 吗？这将删除所有配置！[Y/n]: ${none}")" confirm || true
    if [[ "$confirm" =~ ^[nN]$ ]]; then
        info "操作已取消。"
        return
    fi
    info "正在卸载 Xray..."
    if ! execute_official_script "remove --purge"; then
        error "Xray 卸载失败！"
        return 1
    fi
    rm -f ~/xray_subscription_info.txt
    success "Xray 已成功卸载。"
}

# 增加 VLESS 协议
add_new_vless() {
    if [[ ! -f "$xray_binary_path" ]]; then
        error "错误: Xray 未安装，请先安装 Xray。"
        return
    fi

    info "开始添加新的 VLESS-Reality 节点..."
    if [[ -z "$(get_public_ip)" ]]; then
        error "无法获取公网 IP 地址，操作中止。请检查您的网络连接。"
        return 1
    fi

    local vless_port vless_uuid vless_domain vless_node_name
    prompt_for_vless_config vless_port vless_uuid vless_domain vless_node_name

    info "正在生成 Reality 密钥对..."
    local key_pair private_key public_key
    key_pair=$("$xray_binary_path" x25519)
    private_key=$(echo "$key_pair" | awk '/PrivateKey:/ {print $2}')
    public_key=$(echo "$key_pair" | awk '/Password:/ {print $2}')

    if [[ -z "$private_key" || -z "$public_key" ]]; then
        error "生成 Reality 密钥对失败！请检查 Xray 核心是否正常。"
        return 1
    fi

    local new_vless_inbound
    new_vless_inbound=$(build_vless_inbound "$vless_port" "$vless_uuid" "$vless_domain" "$private_key" "$public_key" "$vless_node_name")

    # 读取现有配置
    local existing_inbounds
    if [[ -f "$xray_config_path" ]]; then
        existing_inbounds=$(jq '.inbounds' "$xray_config_path")
        # 追加新的 VLESS inbound
        local new_inbounds
        new_inbounds=$(echo "$existing_inbounds" | jq ". += [$new_vless_inbound]")
        write_config "$new_inbounds"
    else
        write_config "[$new_vless_inbound]"
    fi

    if ! restart_xray; then return 1; fi

    success "新 VLESS 节点添加成功！"
    view_all_info
}

# 增加 Shadowsocks-2022 协议
add_new_ss() {
    if [[ ! -f "$xray_binary_path" ]]; then
        error "错误: Xray 未安装，请先安装 Xray。"
        return
    fi

    info "开始添加新的 Shadowsocks-2022 节点..."
    if [[ -z "$(get_public_ip)" ]]; then
        error "无法获取公网 IP 地址，操作中止。请检查您的网络连接。"
        return 1
    fi

    local ss_port ss_password ss_node_name
    prompt_for_ss_config ss_port ss_password ss_node_name

    local new_ss_inbound
    new_ss_inbound=$(build_ss_inbound "$ss_port" "$ss_password" "$ss_node_name")

    # 读取现有配置
    local existing_inbounds
    if [[ -f "$xray_config_path" ]]; then
        existing_inbounds=$(jq '.inbounds' "$xray_config_path")
        # 追加新的 SS inbound
        local new_inbounds
        new_inbounds=$(echo "$existing_inbounds" | jq ". += [$new_ss_inbound]")
        write_config "$new_inbounds"
    else
        write_config "[$new_ss_inbound]"
    fi

    if ! restart_xray; then return 1; fi

    success "新 Shadowsocks-2022 节点添加成功！"
    view_all_info
}

# 删除指定 VLESS 节点
delete_vless_node() {
    if [[ ! -f "$xray_config_path" ]]; then
        error "错误: Xray 配置文件不存在。"
        return
    fi

    # 获取所有 VLESS inbounds
    local vless_count
    vless_count=$(jq '[.inbounds[] | select(.protocol == "vless")] | length' "$xray_config_path")

    if [[ "$vless_count" -eq 0 ]]; then
        error "未找到任何 VLESS 节点。"
        return
    fi

    draw_menu_header
    echo -e "${cyan} 当前 VLESS 节点列表${none}"
    draw_divider

    # 列出所有 VLESS 节点
    local index=1
    jq -r '.inbounds[] | select(.protocol == "vless") | "\(.port)|\(.settings.clients[0].id)|\(.tag // "未命名")"' "$xray_config_path" | while IFS='|' read -r port uuid tag; do
        printf "  ${green}%-2s${none} 端口: ${cyan}%-6s${none} UUID: ${cyan}%s...%s${none} 名称: ${cyan}%s${none}\n" "$index." "$port" "${uuid:0:8}" "${uuid: -4}" "$tag"
        ((index++))
    done

    draw_divider
    printf "  ${yellow}%-2s${none} %-35s\n" "0." "返回主菜单"
    draw_divider

    read -p " 请选择要删除的节点编号 [0-$vless_count]: " choice || true

    if [[ "$choice" == "0" ]]; then
        return
    fi

    if ! [[ "$choice" =~ ^[0-9]+$ ]] || [[ "$choice" -lt 1 ]] || [[ "$choice" -gt "$vless_count" ]]; then
        error "无效选项。"
        return
    fi

    # 删除选中的节点
    local new_inbounds
    new_inbounds=$(jq --argjson idx "$((choice - 1))" '
        ([.inbounds[] | select(.protocol == "vless")] | del(.[$idx])) as $vless_filtered |
        [.inbounds[] | select(.protocol != "vless")] + $vless_filtered
    ' "$xray_config_path")

    write_config "$new_inbounds"

    if ! restart_xray; then return 1; fi

    success "VLESS 节点删除成功！"
    view_all_info
}

# 删除指定 Shadowsocks-2022 节点
delete_ss_node() {
    if [[ ! -f "$xray_config_path" ]]; then
        error "错误: Xray 配置文件不存在。"
        return
    fi

    # 获取所有 SS inbounds
    local ss_count
    ss_count=$(jq '[.inbounds[] | select(.protocol == "shadowsocks")] | length' "$xray_config_path")

    if [[ "$ss_count" -eq 0 ]]; then
        error "未找到任何 Shadowsocks-2022 节点。"
        return
    fi

    draw_menu_header
    echo -e "${cyan} 当前 Shadowsocks-2022 节点列表${none}"
    draw_divider

    # 列出所有 SS 节点
    local index=1
    jq -r '.inbounds[] | select(.protocol == "shadowsocks") | "\(.port)|\(.settings.password)|\(.tag // "未命名")"' "$xray_config_path" | while IFS='|' read -r port password tag; do
        printf "  ${green}%-2s${none} 端口: ${cyan}%-6s${none} 密码: ${cyan}%s...%s${none} 名称: ${cyan}%s${none}\n" "$index." "$port" "${password:0:4}" "${password: -4}" "$tag"
        ((index++))
    done

    draw_divider
    printf "  ${yellow}%-2s${none} %-35s\n" "0." "返回主菜单"
    draw_divider

    read -p " 请选择要删除的节点编号 [0-$ss_count]: " choice || true

    if [[ "$choice" == "0" ]]; then
        return
    fi

    if ! [[ "$choice" =~ ^[0-9]+$ ]] || [[ "$choice" -lt 1 ]] || [[ "$choice" -gt "$ss_count" ]]; then
        error "无效选项。"
        return
    fi

    # 删除选中的节点
    local new_inbounds
    new_inbounds=$(jq --argjson idx "$((choice - 1))" '
        ([.inbounds[] | select(.protocol == "shadowsocks")] | del(.[$idx])) as $ss_filtered |
        [.inbounds[] | select(.protocol != "shadowsocks")] + $ss_filtered
    ' "$xray_config_path")

    write_config "$new_inbounds"

    if ! restart_xray; then return 1; fi

    success "Shadowsocks-2022 节点删除成功！"
    view_all_info
}

modify_vless_config() {
    # 获取所有 VLESS inbounds
    local vless_count
    vless_count=$(jq '[.inbounds[] | select(.protocol == "vless")] | length' "$xray_config_path")

    if [[ "$vless_count" -eq 0 ]]; then
        error "未找到任何 VLESS 节点。"
        return
    fi

    local selected_index
    if [[ "$vless_count" -gt 1 ]]; then
        draw_menu_header
        echo -e "${cyan} 请选择要修改的 VLESS 节点${none}"
        draw_divider

        # 列出所有 VLESS 节点
        local index=1
        jq -r '.inbounds[] | select(.protocol == "vless") | "\(.port)|\(.settings.clients[0].id)|\(.tag // "未命名")"' "$xray_config_path" | while IFS='|' read -r port uuid tag; do
            printf "  ${green}%-2s${none} 端口: ${cyan}%-6s${none} UUID: ${cyan}%s...%s${none} 名称: ${cyan}%s${none}\n" "$index." "$port" "${uuid:0:8}" "${uuid: -4}" "$tag"
            ((index++))
        done

        draw_divider
        printf "  ${yellow}%-2s${none} %-35s\n" "0." "返回主菜单"
        draw_divider

        read -p " 请选择要修改的节点编号 [0-$vless_count]: " choice || true

        if [[ "$choice" == "0" ]]; then
            return
        fi

        if ! [[ "$choice" =~ ^[0-9]+$ ]] || [[ "$choice" -lt 1 ]] || [[ "$choice" -gt "$vless_count" ]]; then
            error "无效选项。"
            return
        fi

        selected_index=$((choice - 1))
    else
        selected_index=0
    fi

    info "开始修改 VLESS-Reality 配置..."

    # 获取选中的 VLESS inbound
    local vless_inbound current_port current_uuid current_domain current_node_name current_shortid private_key public_key
    vless_inbound=$(jq --argjson idx "$selected_index" '[.inbounds[] | select(.protocol == "vless")][$idx]' "$xray_config_path")
    current_port=$(echo "$vless_inbound" | jq -r '.port')
    current_uuid=$(echo "$vless_inbound" | jq -r '.settings.clients[0].id')
    current_domain=$(echo "$vless_inbound" | jq -r '.streamSettings.realitySettings.serverNames[0]')
    current_node_name=$(echo "$vless_inbound" | jq -r '.tag // "VLESS-" + (.port | tostring)')
    current_shortid=$(echo "$vless_inbound" | jq -r '.streamSettings.realitySettings.shortIds[0]')
    private_key=$(echo "$vless_inbound" | jq -r '.streamSettings.realitySettings.privateKey')
    public_key=$(echo "$vless_inbound" | jq -r '.streamSettings.realitySettings.publicKey')

    # 显示端口使用情况
    show_port_usage

    # 输入新配置
    local port uuid domain node_name
    while true; do
        read -p "$(echo -e " -> 新端口 (当前: ${cyan}${current_port}${none}, 留空不改): ")" port || true
        [[ -z "$port" ]] && port=$current_port
        if is_port_available "$port" || [[ "$port" == "$current_port" ]]; then break; fi
    done

    read -p "$(echo -e " -> 新UUID (当前: ${cyan}${current_uuid:0:8}...${current_uuid: -4}${none}, 留空不改): ")" uuid || true
    [[ -z "$uuid" ]] && uuid=$current_uuid

    while true; do
        read -p "$(echo -e " -> 新SNI域名 (当前: ${cyan}${current_domain}${none}, 留空不改): ")" domain || true
        [[ -z "$domain" ]] && domain=$current_domain
        if is_valid_domain "$domain"; then break; else error "域名格式无效，请重新输入。"; fi
    done

    read -p "$(echo -e " -> 新节点名称 (当前: ${cyan}${current_node_name}${none}, 留空不改): ")" node_name || true
    [[ -z "$node_name" ]] && node_name=$current_node_name

    # 构建新的 VLESS inbound (保持原有的 shortid 和密钥对)
    local new_vless_inbound
    new_vless_inbound=$(build_vless_inbound "$port" "$uuid" "$domain" "$private_key" "$public_key" "$node_name" "$current_shortid")

    # 更新配置
    local new_inbounds
    new_inbounds=$(jq --argjson idx "$selected_index" --argjson new_vless "$new_vless_inbound" '
        ([.inbounds[] | select(.protocol == "vless")] | .[$idx] = $new_vless) as $vless_updated |
        [.inbounds[] | select(.protocol != "vless")] + $vless_updated
    ' "$xray_config_path" | jq '.inbounds')

    write_config "$new_inbounds"
    if ! restart_xray; then return 1; fi

    success "配置修改成功！"
    view_all_info
}

modify_ss_config() {
    if [[ ! -f "$xray_config_path" ]]; then
        error "错误: Xray 配置文件不存在。"
        return
    fi

    # 获取所有 SS inbounds
    local ss_count
    ss_count=$(jq '[.inbounds[] | select(.protocol == "shadowsocks")] | length' "$xray_config_path")

    if [[ "$ss_count" -eq 0 ]]; then
        error "未找到任何 Shadowsocks-2022 节点。"
        return
    fi

    local selected_index=0

    # 如果有多个 SS 节点，让用户选择
    if [[ "$ss_count" -gt 1 ]]; then
        draw_menu_header
        echo -e "${cyan} 当前 Shadowsocks-2022 节点列表${none}"
        draw_divider

        # 列出所有 SS 节点
        local index=1
        jq -r '.inbounds[] | select(.protocol == "shadowsocks") | "\(.port)|\(.settings.password)|\(.tag // "未命名")"' "$xray_config_path" | while IFS='|' read -r port password tag; do
            printf "  ${green}%-2s${none} 端口: ${cyan}%-6s${none} 密码: ${cyan}%s...%s${none} 名称: ${cyan}%s${none}\n" "$index." "$port" "${password:0:4}" "${password: -4}" "$tag"
            ((index++))
        done

        draw_divider
        printf "  ${yellow}%-2s${none} %-35s\n" "0." "返回主菜单"
        draw_divider

        read -p " 请选择要修改的节点编号 [0-$ss_count]: " choice || true

        if [[ "$choice" == "0" ]]; then
            return
        fi

        if ! [[ "$choice" =~ ^[0-9]+$ ]] || [[ "$choice" -lt 1 ]] || [[ "$choice" -gt "$ss_count" ]]; then
            error "无效选项。"
            return
        fi

        selected_index=$((choice - 1))
    else
        selected_index=0
    fi

    info "开始修改 Shadowsocks-2022 配置..."

    # 获取选中的 SS inbound
    local ss_inbound current_port current_password current_node_name
    ss_inbound=$(jq --argjson idx "$selected_index" '[.inbounds[] | select(.protocol == "shadowsocks")][$idx]' "$xray_config_path")
    current_port=$(echo "$ss_inbound" | jq -r '.port')
    current_password=$(echo "$ss_inbound" | jq -r '.settings.password')
    current_node_name=$(echo "$ss_inbound" | jq -r '.tag // "Shadowsocks-2022-" + (.port | tostring)')

    # 显示端口使用情况
    show_port_usage

    # 输入新配置
    local port password node_name
    while true; do
        read -p "$(echo -e " -> 新端口 (当前: ${cyan}${current_port}${none}, 留空不改): ")" port || true
        [[ -z "$port" ]] && port=$current_port
        if is_port_available "$port" || [[ "$port" == "$current_port" ]]; then break; fi
    done

    read -p "$(echo -e " -> 新密钥 (当前: ${cyan}${current_password:0:4}...${current_password: -4}${none}, 留空不改): ")" password || true
    [[ -z "$password" ]] && password=$current_password

    read -p "$(echo -e " -> 新节点名称 (当前: ${cyan}${current_node_name}${none}, 留空不改): ")" node_name || true
    [[ -z "$node_name" ]] && node_name=$current_node_name

    # 构建新的 SS inbound
    local new_ss_inbound
    new_ss_inbound=$(build_ss_inbound "$port" "$password" "$node_name")

    # 更新配置
    local new_inbounds
    new_inbounds=$(jq --argjson idx "$selected_index" --argjson new_ss "$new_ss_inbound" '
        ([.inbounds[] | select(.protocol == "shadowsocks")] | .[$idx] = $new_ss) as $ss_updated |
        [.inbounds[] | select(.protocol != "shadowsocks")] + $ss_updated
    ' "$xray_config_path" | jq '.inbounds')

    write_config "$new_inbounds"
    if ! restart_xray; then return 1; fi

    success "配置修改成功！"
    view_all_info
}

restart_xray() {
    if [[ ! -f "$xray_binary_path" ]]; then error "错误: Xray 未安装。" && return 1; fi
    
    info "正在重启 Xray 服务..."
    if ! systemctl restart xray; then
        error "尝试重启 Xray 服务失败！"
        # 新增：显示详细错误信息
        echo -e "\n${yellow}错误详情:${none}"
        systemctl status xray --no-pager -l | tail -5
        return 1
    fi
    
    # 等待时间稍微延长，确保服务完全启动
    sleep 2
    if systemctl is-active --quiet xray; then
        success "Xray 服务已成功重启！"
    else
        error "服务启动失败，详细信息:"
        systemctl status xray --no-pager -l | tail -5
        return 1
    fi
}

view_xray_log() {
    if [[ ! -f "$xray_binary_path" ]]; then error "错误: Xray 未安装。" && return; fi
    info "正在显示 Xray 实时日志... 按 Ctrl+C 退出。"
    journalctl -u xray -f --no-pager
}

view_all_info() {
    if [ ! -f "$xray_config_path" ]; then
        [[ "$is_quiet" = true ]] && return
        error "错误: 配置文件不存在。"
        return
    fi
    
    [[ "$is_quiet" = false ]] && clear && echo -e "${cyan} Xray 配置及订阅信息${none}" && draw_divider

    local ip
    ip=$(get_public_ip)
    if [[ -z "$ip" ]]; then
        [[ "$is_quiet" = false ]] && error "无法获取公网 IP 地址。"
        return 1
    fi
    local host
    host=$(hostname)
    local links_array=()

    # 处理所有 VLESS inbounds
    local vless_count
    vless_count=$(jq '[.inbounds[] | select(.protocol == "vless")] | length' "$xray_config_path" 2>/dev/null || echo "0")

    if [[ "$vless_count" -gt 0 ]]; then
        local display_ip
        display_ip=$ip && [[ $ip =~ ":" ]] && display_ip="[$ip]"

        # 循环处理每个 VLESS 节点
        for ((i=0; i<vless_count; i++)); do
            local vless_inbound uuid port domain public_key shortid node_name link_name_raw link_name_encoded vless_url
            vless_inbound=$(jq --argjson idx "$i" '[.inbounds[] | select(.protocol == "vless")][$idx]' "$xray_config_path")
            uuid=$(echo "$vless_inbound" | jq -r '.settings.clients[0].id')
            port=$(echo "$vless_inbound" | jq -r '.port')
            domain=$(echo "$vless_inbound" | jq -r '.streamSettings.realitySettings.serverNames[0]')
            public_key=$(echo "$vless_inbound" | jq -r '.streamSettings.realitySettings.publicKey')
            shortid=$(echo "$vless_inbound" | jq -r '.streamSettings.realitySettings.shortIds[0]')
            node_name=$(echo "$vless_inbound" | jq -r '.tag // "VLESS-" + (.port | tostring)')

            if [[ -z "$public_key" ]]; then
                [[ "$is_quiet" = false ]] && error "VLESS配置不完整，可能已损坏。"
                continue
            fi

            link_name_raw="$node_name"
            link_name_encoded=$(echo "$link_name_raw" | sed 's/ /%20/g')
            vless_url="vless://${uuid}@${display_ip}:${port}?flow=xtls-rprx-vision&encryption=none&type=tcp&security=reality&sni=${domain}&fp=chrome&pbk=${public_key}&sid=${shortid}#${link_name_encoded}"
            links_array+=("$vless_url")

            if [[ "$is_quiet" = false ]]; then
                [[ $i -gt 0 ]] && echo ""
                echo -e "${green} [ VLESS-Reality 配置 - ${node_name} ]${none}"
                printf "    %s: ${cyan}%s${none}\n" "节点名称" "$link_name_raw"
                printf "    %s: ${cyan}%s${none}\n" "服务器地址" "$ip"
                printf "    %s: ${cyan}%s${none}\n" "端口" "$port"
                printf "    %s: ${cyan}%s${none}\n" "UUID" "${uuid:0:8}...${uuid: -4}"
                printf "    %s: ${cyan}%s${none}\n" "流控" "xtls-rprx-vision"
                printf "    %s: ${cyan}%s${none}\n" "传输协议" "tcp"
                printf "    %s: ${cyan}%s${none}\n" "安全类型" "reality"
                printf "    %s: ${cyan}%s${none}\n" "SNI" "$domain"
                printf "    %s: ${cyan}%s${none}\n" "指纹" "chrome"
                printf "    %s: ${cyan}%s${none}\n" "PublicKey" "${public_key:0:16}..."
                printf "    %s: ${cyan}%s${none}\n" "ShortId" "$shortid"
            fi
        done
    fi

    # 处理所有 Shadowsocks inbounds
    local ss_count
    ss_count=$(jq '[.inbounds[] | select(.protocol == "shadowsocks")] | length' "$xray_config_path" 2>/dev/null || echo "0")

    if [[ "$ss_count" -gt 0 ]]; then
        # 循环处理每个 SS 节点
        for ((i=0; i<ss_count; i++)); do
            local ss_inbound port method password node_name link_name_raw link_name_encoded user_info_base64 ss_url
            ss_inbound=$(jq --argjson idx "$i" '[.inbounds[] | select(.protocol == "shadowsocks")][$idx]' "$xray_config_path")
            port=$(echo "$ss_inbound" | jq -r '.port')
            method=$(echo "$ss_inbound" | jq -r '.settings.method')
            password=$(echo "$ss_inbound" | jq -r '.settings.password')
            node_name=$(echo "$ss_inbound" | jq -r '.tag // "Shadowsocks-2022-" + (.port | tostring)')

            link_name_raw="$node_name"
            link_name_encoded=$(echo "$link_name_raw" | sed 's/ /%20/g')
            user_info_base64=$(echo -n "${method}:${password}" | base64 -w 0)
            ss_url="ss://${user_info_base64}@${ip}:${port}#${link_name_encoded}"
            links_array+=("$ss_url")

            if [[ "$is_quiet" = false ]]; then
                echo ""
                echo -e "${green} [ Shadowsocks-2022 配置 - ${node_name} ]${none}"
                printf "    %s: ${cyan}%s${none}\n" "节点名称" "$link_name_raw"
                printf "    %s: ${cyan}%s${none}\n" "服务器地址" "$ip"
                printf "    %s: ${cyan}%s${none}\n" "端口" "$port"
                printf "    %s: ${cyan}%s${none}\n" "加密方式" "$method"
                printf "    %s: ${cyan}%s${none}\n" "密码" "${password:0:4}...${password: -4}"
            fi
        done
    fi

    if [ ${#links_array[@]} -gt 0 ]; then
        if [[ "$is_quiet" = true ]]; then
            printf "%s\n" "${links_array[@]}"
        else
            draw_divider
            printf "%s\n" "${links_array[@]}" > ~/xray_subscription_info.txt
            success "所有订阅链接已汇总保存到: ~/xray_subscription_info.txt"
            
            echo -e "\n${yellow} --- V2Ray / Clash 等客户端可直接导入以下链接 --- ${none}\n"
            for link in "${links_array[@]}"; do
                echo -e "${cyan}${link}${none}\n"
            done
            draw_divider
        fi
    elif [[ "$is_quiet" = false ]]; then
        info "当前未安装任何协议，无订阅信息可显示。"
    fi
}

# --- SOCKS5 链式代理管理 ---

# 新增 SOCKS5 链式代理
add_socks5_proxy() {
    if [[ ! -f "$xray_config_path" ]]; then
        error "错误: Xray 配置文件不存在。"
        return
    fi

    clear
    draw_menu_header
    echo -e "${cyan}╔════════════════════════════════════════════╗${none}"
    echo -e "${cyan}║      新增 SOCKS5 链式代理                   ║${none}"
    echo -e "${cyan}╚════════════════════════════════════════════╝${none}"
    echo ""
    
    # 获取所有inbounds (VLESS 和 SS)
    local inbound_count
    inbound_count=$(jq '[.inbounds[] | select(.protocol == "vless" or .protocol == "shadowsocks")] | length' "$xray_config_path")
    
    if [[ "$inbound_count" -eq 0 ]]; then
        error "未找到任何 VLESS 或 Shadowsocks 节点。"
        return
    fi
    
    echo -e "${cyan} 当前节点列表${none}"
    draw_divider
    
    # 列出所有节点（避免子shell问题）
    local index=1
    while IFS='|' read -r protocol port tag; do
        printf "  ${green}%-2s${none} [%-12s] 端口: ${cyan}%-6s${none} 名称: ${cyan}%s${none}\n" "$index." "$protocol" "$port" "$tag"
        ((index++))
    done < <(jq -r '.inbounds[] | select(.protocol == "vless" or .protocol == "shadowsocks") | "\(.protocol)|\(.port)|\(.tag // "未命名")"' "$xray_config_path")
    
    draw_divider
    printf "  ${yellow}%-2s${none} %-35s\n" "0." "返回主菜单"
    draw_divider
    
    read -p " 请选择要配置链式代理的节点编号 [0-$inbound_count]: " choice || true
    
    if [[ "$choice" == "0" ]]; then
        return
    fi
    
    if ! [[ "$choice" =~ ^[0-9]+$ ]] || [[ "$choice" -lt 1 ]] || [[ "$choice" -gt "$inbound_count" ]]; then
        error "无效选项。"
        return
    fi
    
    # 获取选中节点的信息
    local selected_info
    selected_info=$(jq -r --argjson idx "$((choice - 1))" '[.inbounds[] | select(.protocol == "vless" or .protocol == "shadowsocks")][$idx] | "\(.tag // "inbound-\(.port)")|\(.port)"' "$xray_config_path")
    
    if [[ -z "$selected_info" ]]; then
        error "无法获取节点信息"
        return
    fi
    
    local selected_tag=$(echo "$selected_info" | cut -d'|' -f1)
    local selected_port=$(echo "$selected_info" | cut -d'|' -f2)
    
    echo ""
    info "已选择节点: ${cyan}${selected_tag}${none} (端口: ${cyan}${selected_port}${none})"
    
    # 检查是否已配置链式代理
    local existing_rule
    existing_rule=$(jq -r --arg tag "$selected_tag" '.routing.rules[]? | select(.inboundTag[0] == $tag and (.outboundTag | startswith("socks5-"))) | .outboundTag' "$xray_config_path" 2>/dev/null)
    
    if [[ -n "$existing_rule" ]]; then
        echo ""
        warn "⚠️  该节点已配置链式代理: ${cyan}${existing_rule}${none}"
        read -p " 是否覆盖现有配置? [y/N]: " overwrite || true
        if [[ ! "$overwrite" =~ ^[Yy]$ ]]; then
            return
        fi
    fi
    
    echo ""
    
    # 输入SOCKS5信息
    draw_divider
    echo -e "${cyan}请输入 SOCKS5 代理信息${none}"
    draw_divider
    
    local socks5_addr socks5_port socks5_user socks5_pass need_auth
    
    read -p " SOCKS5 代理地址: " socks5_addr || true
    if [[ -z "$socks5_addr" ]]; then
        error "地址不能为空"
        return
    fi
    
    read -p " SOCKS5 代理端口: " socks5_port || true
    if ! [[ "$socks5_port" =~ ^[0-9]+$ ]] || [[ "$socks5_port" -lt 1 ]] || [[ "$socks5_port" -gt 65535 ]]; then
        error "无效端口"
        return
    fi
    
    read -p " 是否需要认证? [y/N]: " need_auth || true
    if [[ "$need_auth" =~ ^[Yy]$ ]]; then
        read -p " 用户名: " socks5_user || true
        read -p " 密码: " socks5_pass || true
    fi
    
    # 生成唯一的outbound tag
    local socks5_tag="socks5-${selected_tag}"
    
    # 读取现有配置
    local config
    config=$(cat "$xray_config_path")
    
    # 构建SOCKS5 outbound
    local socks5_outbound
    if [[ "$need_auth" =~ ^[Yy]$ ]]; then
        socks5_outbound=$(jq -n --arg addr "$socks5_addr" --arg port "$socks5_port" --arg user "$socks5_user" --arg pass "$socks5_pass" --arg tag "$socks5_tag" '{
            tag: $tag,
            protocol: "socks",
            settings: {
                servers: [{
                    address: $addr,
                    port: ($port | tonumber),
                    users: [{
                        user: $user,
                        pass: $pass
                    }]
                }]
            }
        }')
    else
        socks5_outbound=$(jq -n --arg addr "$socks5_addr" --arg port "$socks5_port" --arg tag "$socks5_tag" '{
            tag: $tag,
            protocol: "socks",
            settings: {
                servers: [{
                    address: $addr,
                    port: ($port | tonumber)
                }]
            }
        }')
    fi
    
    # 检查是否已存在相同的socks5 outbound
    local existing_outbound
    existing_outbound=$(echo "$config" | jq --arg tag "$socks5_tag" '.outbounds[]? | select(.tag == $tag)')
    
    if [[ -n "$existing_outbound" ]]; then
        # 更新现有的outbound
        config=$(echo "$config" | jq --argjson new_outbound "$socks5_outbound" --arg tag "$socks5_tag" '
            .outbounds |= map(if .tag == $tag then $new_outbound else . end)
        ')
    else
        # 添加新的outbound
        config=$(echo "$config" | jq --argjson new_outbound "$socks5_outbound" '
            .outbounds += [$new_outbound]
        ')
    fi
    
    # 添加或更新路由规则
    config=$(echo "$config" | jq --arg inbound_tag "$selected_tag" --arg outbound_tag "$socks5_tag" '
        if .routing.rules then
            # 删除当前节点的旧规则，并在前面添加新规则（一个原子操作）
            .routing.rules = [{
                type: "field",
                inboundTag: [$inbound_tag],
                outboundTag: $outbound_tag
            }] + (.routing.rules | map(select(.inboundTag[0] != $inbound_tag)))
        else
            # 如果没有routing，创建一个
            .routing = {
                rules: [{
                    type: "field",
                    inboundTag: [$inbound_tag],
                    outboundTag: $outbound_tag
                }]
            }
        end
    ')
    
    # 验证JSON有效性
    if ! echo "$config" | jq . > /dev/null 2>&1; then
        error "生成的配置文件格式错误！"
        return 1
    fi
    
    # 备份原配置
    cp "$xray_config_path" "${xray_config_path}.bak.$(date +%s)"
    
    # 保存配置（安全权限）
    echo "$config" > "$xray_config_path"
    chmod 640 "$xray_config_path"
    chown nobody:root "$xray_config_path"

    success "✅ 已为节点 ${cyan}${selected_tag}${none} 配置 SOCKS5 链式代理"
    info "SOCKS5: ${cyan}${socks5_addr}:${socks5_port}${none}"
    
    # 重启Xray
    echo ""
    read -p " 是否立即重启 Xray 使配置生效? [Y/n]: " restart_choice || true
    if [[ ! "$restart_choice" =~ ^[Nn]$ ]]; then
        systemctl restart xray
        sleep 1
        if systemctl is-active --quiet xray; then
            success "✅ Xray 已重启"
        else
            error "❌ Xray 重启失败，请检查日志: journalctl -u xray -n 20"
            warn "已创建备份: ${xray_config_path}.bak.*"
        fi
    fi
}

# 查看 SOCKS5 链式代理列表
list_socks5_proxies() {
    if [[ ! -f "$xray_config_path" ]]; then
        error "错误: Xray 配置文件不存在。"
        return
    fi

    clear
    draw_menu_header
    echo -e "${cyan}╔════════════════════════════════════════════╗${none}"
    echo -e "${cyan}║      SOCKS5 链式代理列表                    ║${none}"
    echo -e "${cyan}╚════════════════════════════════════════════╝${none}"
    echo ""
    
    # 获取所有routing rules中指向socks outbound的规则
    local socks5_rules
    socks5_rules=$(jq -r '
        .routing.rules[]? | 
        select(.outboundTag? | startswith("socks5-")) | 
        "\(.inboundTag[0])|\(.outboundTag)"
    ' "$xray_config_path" 2>/dev/null)
    
    if [[ -z "$socks5_rules" ]]; then
        info "当前没有配置任何 SOCKS5 链式代理"
        return
    fi
    
    echo -e "${cyan} 已配置链式代理的节点${none}"
    draw_divider
    printf "  ${cyan}%-20s${none} ${cyan}%-30s${none} ${cyan}%s${none}\n" "节点" "SOCKS5地址" "状态"
    draw_divider
    
    while IFS='|' read -r inbound_tag outbound_tag; do
        # 获取SOCKS5 outbound信息
        local socks5_info
        socks5_info=$(jq -r --arg tag "$outbound_tag" '
            .outbounds[]? | select(.tag == $tag) | 
            "\(.settings.servers[0].address):\(.settings.servers[0].port)"
        ' "$xray_config_path" 2>/dev/null)
        
        if [[ -n "$socks5_info" ]]; then
            printf "  ${green}%-20s${none} → ${yellow}%-30s${none} ${green}%s${none}\n" "$inbound_tag" "$socks5_info" "✓"
        else
            printf "  ${red}%-20s${none} → ${red}%-30s${none} ${red}%s${none}\n" "$inbound_tag" "配置丢失" "✗"
        fi
    done <<< "$socks5_rules"
    
    draw_divider
}

# 删除 SOCKS5 链式代理
delete_socks5_proxy() {
    if [[ ! -f "$xray_config_path" ]]; then
        error "错误: Xray 配置文件不存在。"
        return
    fi

    clear
    draw_menu_header
    echo -e "${cyan}╔════════════════════════════════════════════╗${none}"
    echo -e "${cyan}║      删除 SOCKS5 链式代理                   ║${none}"
    echo -e "${cyan}╚════════════════════════════════════════════╝${none}"
    echo ""
    
    # 获取所有配置了socks5的节点
    local socks5_rules
    socks5_rules=$(jq -r '
        .routing.rules[]? | 
        select(.outboundTag? | startswith("socks5-")) | 
        "\(.inboundTag[0])|\(.outboundTag)"
    ' "$xray_config_path" 2>/dev/null)
    
    if [[ -z "$socks5_rules" ]]; then
        info "当前没有配置任何 SOCKS5 链式代理"
        return
    fi
    
    echo -e "${cyan} 已配置链式代理的节点${none}"
    draw_divider
    
    # 使用数组存储，避免子shell问题
    local index=1
    local -a node_list
    while IFS='|' read -r inbound_tag outbound_tag; do
        local socks5_info
        socks5_info=$(jq -r --arg tag "$outbound_tag" '
            .outbounds[]? | select(.tag == $tag) | 
            "\(.settings.servers[0].address):\(.settings.servers[0].port)"
        ' "$xray_config_path" 2>/dev/null)
        
        printf "  ${green}%-2s${none} 节点: ${cyan}%-20s${none} SOCKS5: ${yellow}%s${none}\n" "$index." "$inbound_tag" "$socks5_info"
        node_list[$index]="$inbound_tag|$outbound_tag"
        ((index++))
    done <<< "$socks5_rules"
    
    local proxy_count=$((index - 1))
    
    draw_divider
    printf "  ${yellow}%-2s${none} %-35s\n" "0." "返回主菜单"
    draw_divider
    
    read -p " 请选择要删除的链式代理编号 [0-$proxy_count]: " choice || true
    
    if [[ "$choice" == "0" ]]; then
        return
    fi
    
    if ! [[ "$choice" =~ ^[0-9]+$ ]] || [[ "$choice" -lt 1 ]] || [[ "$choice" -gt "$proxy_count" ]]; then
        error "无效选项。"
        return
    fi
    
    # 获取选中的inbound和outbound tag
    local selected_info="${node_list[$choice]}"
    if [[ -z "$selected_info" ]]; then
        error "无法获取节点信息"
        return
    fi
    
    local inbound_tag=$(echo "$selected_info" | cut -d'|' -f1)
    local outbound_tag=$(echo "$selected_info" | cut -d'|' -f2)
    
    # 读取配置
    local config
    config=$(cat "$xray_config_path")
    
    # 删除routing rule（只删除匹配该inbound且指向socks5的规则）
    config=$(echo "$config" | jq --arg inbound_tag "$inbound_tag" --arg outbound_tag "$outbound_tag" '
        .routing.rules |= map(select(
            (.inboundTag[0] != $inbound_tag) or 
            (.outboundTag != $outbound_tag)
        ))
    ')
    
    # 删除socks5 outbound
    config=$(echo "$config" | jq --arg outbound_tag "$outbound_tag" '
        .outbounds |= map(select(.tag != $outbound_tag))
    ')
    
    # 验证JSON有效性
    if ! echo "$config" | jq . > /dev/null 2>&1; then
        error "生成的配置文件格式错误！"
        return 1
    fi
    
    # 备份原配置
    cp "$xray_config_path" "${xray_config_path}.bak.$(date +%s)"
    
    # 保存配置（安全权限）
    echo "$config" > "$xray_config_path"
    chmod 640 "$xray_config_path"
    chown nobody:root "$xray_config_path"

    success "✅ 已删除节点 ${cyan}${inbound_tag}${none} 的链式代理配置"
    
    # 重启Xray
    echo ""
    read -p " 是否立即重启 Xray 使配置生效? [Y/n]: " restart_choice || true
    if [[ ! "$restart_choice" =~ ^[Nn]$ ]]; then
        systemctl restart xray
        sleep 1
        if systemctl is-active --quiet xray; then
            success "✅ Xray 已重启"
        else
            error "❌ Xray 重启失败，请检查日志: journalctl -u xray -n 20"
            warn "已创建备份: ${xray_config_path}.bak.*"
        fi
    fi
}

# --- 路由过滤规则管理 ---
manage_routing_rules() {
    clear
    echo -e "${cyan}╔════════════════════════════════════════════╗${none}"
    echo -e "${cyan}║      路由过滤规则管理                      ║${none}"
    echo -e "${cyan}╚════════════════════════════════════════════╝${none}"
    echo ""
    
    if [[ ! -f "$xray_config_path" ]]; then
        error "Xray 配置文件不存在！请先安装 Xray。"
        return 1
    fi
    
    # 检查当前是否启用了路由规则
    local has_routing
    has_routing=$(jq -r '.routing // empty' "$xray_config_path" 2>/dev/null)
    
    if [[ -n "$has_routing" ]]; then
        echo -e "${green}✓ 当前状态: 路由过滤规则${green}已启用${none}"
        echo ""
        echo -e "${yellow}过滤内容:${none}"
        echo "  • geosite:category-ads-all  (所有广告)"
        echo "  • geosite:category-porn     (色情网站)"
        echo "  • regexp:.*missav.*         (missav相关域名)"
        echo "  • geosite:missav            (missav站点)"
        echo ""
        echo "────────────────────────────────────────────────"
        echo -e "${cyan}1.${none} 禁用路由过滤规则（恢复纯净代理）"
        echo -e "${red}0.${none} 返回上级菜单"
        echo "────────────────────────────────────────────────"
        read -p " 请选择 [0-1]: " choice || true
        
        if [[ "$choice" == "1" ]]; then
            info "正在禁用路由过滤规则..."
            
            # 读取现有的inbounds配置
            local inbounds_json
            inbounds_json=$(jq -c '.inbounds' "$xray_config_path")
            
            # 重新生成不带路由的配置
            write_config "$inbounds_json" "false"
            
            if restart_xray; then
                success "路由过滤规则已禁用！现在是纯净代理模式。"
            else
                error "Xray 重启失败！"
                return 1
            fi
        fi
    else
        echo -e "${yellow}✗ 当前状态: 路由过滤规则${red}未启用${none}"
        echo ""
        echo -e "${cyan}启用后将自动屏蔽以下内容:${none}"
        echo "  • 所有广告 (geosite:category-ads-all)"
        echo "  • 色情网站 (geosite:category-porn)"
        echo "  • missav相关域名"
        echo ""
        echo -e "${yellow}⚠ 注意: 需要GeoIP/GeoSite数据文件支持${none}"
        echo ""
        echo "────────────────────────────────────────────────"
        echo -e "${green}1.${none} 启用路由过滤规则"
        echo -e "${red}0.${none} 返回上级菜单"
        echo "────────────────────────────────────────────────"
        read -p " 请选择 [0-1]: " choice || true
        
        if [[ "$choice" == "1" ]]; then
            info "正在启用路由过滤规则..."
            
            # 检查GeoIP和GeoSite文件是否存在
            local geo_missing=false
            if [[ ! -f "/usr/local/share/xray/geosite.dat" ]]; then
                warning "GeoSite 数据文件不存在，正在下载..."
                execute_official_script "install-geodata" || geo_missing=true
            fi
            
            if [[ "$geo_missing" == "true" ]]; then
                error "GeoSite 数据文件下载失败，路由规则可能无法正常工作。"
                read -p " 是否继续启用？(y/N): " confirm || true
                if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
                    info "已取消操作"
                    return 0
                fi
            fi
            
            # 读取现有的inbounds配置
            local inbounds_json
            inbounds_json=$(jq -c '.inbounds' "$xray_config_path")
            
            # 重新生成带路由的配置
            write_config "$inbounds_json" "true"
            
            if restart_xray; then
                success "路由过滤规则已启用！"
                echo -e "${green}现在将自动屏蔽广告、色情网站和missav${none}"
            else
                error "Xray 重启失败！"
                return 1
            fi
        fi
    fi
}

# --- 核心安装逻辑函数 ---
run_install_vless() {
    local port="$1" uuid="$2" domain="$3" node_name="$4"
    if [[ -z "$(get_public_ip)" ]]; then
        error "无法获取公网 IP 地址，安装中止。请检查您的网络连接。"
        exit 1
    fi
    run_core_install || exit 1
    info "正在生成 Reality 密钥对..."
    local key_pair private_key public_key vless_inbound
    key_pair=$("$xray_binary_path" x25519)
    private_key=$(echo "$key_pair" | awk '/PrivateKey:/ {print $2}')
    public_key=$(echo "$key_pair" | awk '/Password:/ {print $2}')

    if [[ -z "$private_key" || -z "$public_key" ]]; then
        error "生成 Reality 密钥对失败！请检查 Xray 核心是否正常，或尝试卸载后重装。"
        exit 1
    fi

    vless_inbound=$(build_vless_inbound "$port" "$uuid" "$domain" "$private_key" "$public_key" "$node_name")
    write_config "[$vless_inbound]"

    if ! restart_xray; then exit 1; fi

    success "VLESS-Reality 安装成功！"
    view_all_info
}

run_install_ss() {
    local port="$1" password="$2" node_name="$3"
    if [[ -z "$(get_public_ip)" ]]; then
        error "无法获取公网 IP 地址，安装中止。请检查您的网络连接。"
        exit 1
    fi
    run_core_install || exit 1
    local ss_inbound
    ss_inbound=$(build_ss_inbound "$port" "$password" "$node_name")
    write_config "[$ss_inbound]"

    if ! restart_xray; then exit 1; fi

    success "Shadowsocks-2022 安装成功！"
    view_all_info
}

run_install_dual() {
    local vless_port="$1" vless_uuid="$2" vless_domain="$3" vless_node_name="$4" ss_port="$5" ss_password="$6" ss_node_name="$7"
    if [[ -z "$(get_public_ip)" ]]; then
        error "无法获取公网 IP 地址，安装中止。请检查您的网络连接。"
        exit 1
    fi
    run_core_install || exit 1
    info "正在生成 Reality 密钥对..."
    local key_pair private_key public_key vless_inbound ss_inbound
    key_pair=$("$xray_binary_path" x25519)
    private_key=$(echo "$key_pair" | awk '/PrivateKey:/ {print $2}')
    public_key=$(echo "$key_pair" | awk '/Password:/ {print $2}')

    if [[ -z "$private_key" || -z "$public_key" ]]; then
        error "生成 Reality 密钥对失败！请检查 Xray 核心是否正常，或尝试卸载后重装。"
        exit 1
    fi

    vless_inbound=$(build_vless_inbound "$vless_port" "$vless_uuid" "$vless_domain" "$private_key" "$public_key" "$vless_node_name")
    ss_inbound=$(build_ss_inbound "$ss_port" "$ss_password" "$ss_node_name")
    write_config "[$vless_inbound, $ss_inbound]"

    if ! restart_xray; then exit 1; fi

    success "双协议安装成功！"
    view_all_info
}

# --- 主菜单与脚本入口 ---
main_menu() {
    while true; do
        draw_menu_header
        printf "  ${green}%-2s${none} %-35s\n" "1." "安装 Xray (VLESS/Shadowsocks)"
        draw_divider
        echo -e "${cyan}[VLESS 协议管理]${none}"
        printf "  ${cyan}%-2s${none} %-35s\n" "2." "增加 VLESS 协议"
        printf "  ${magenta}%-2s${none} %-35s\n" "3." "删除指定 VLESS 节点"
        printf "  ${yellow}%-2s${none} %-35s\n" "4." "修改 VLESS 配置"
        draw_divider
        echo -e "${cyan}[Shadowsocks-2022 协议管理]${none}"
        printf "  ${cyan}%-2s${none} %-35s\n" "5." "增加 Shadowsocks-2022 协议"
        printf "  ${magenta}%-2s${none} %-35s\n" "6." "删除指定 Shadowsocks-2022 节点"
        printf "  ${yellow}%-2s${none} %-35s\n" "7." "修改 Shadowsocks-2022 配置"
        draw_divider
        echo -e "${cyan}[SOCKS5 链式代理管理]${none}"
        printf "  ${green}%-2s${none} %-35s\n" "8." "🔗 新增 SOCKS5 链式代理"
        printf "  ${cyan}%-2s${none} %-35s\n" "9." "📋 查看 SOCKS5 链式代理列表"
        printf "  ${magenta}%-2s${none} %-35s\n" "10." "❌ 删除 SOCKS5 链式代理"
        draw_divider
        echo -e "${cyan}[Xray 服务管理]${none}"
        printf "  ${green}%-2s${none} %-35s\n" "11." "更新 Xray"
        printf "  ${red}%-2s${none} %-35s\n" "12." "卸载 Xray"
        printf "  ${cyan}%-2s${none} %-35s\n" "13." "重启 Xray"
        printf "  ${magenta}%-2s${none} %-35s\n" "14." "查看 Xray 日志"
        printf "  ${yellow}%-2s${none} %-35s\n" "15." "查看订阅信息"
        draw_divider
        echo -e "${cyan}[高级功能]${none}"
        printf "  ${green}%-2s${none} %-35s ⭐\n" "16." "路由过滤规则管理"
        draw_divider
        echo -e "${cyan}[多协议代理一键部署脚本]${none}"
        printf "  ${green}%-2s${none} %-35s\n" "17." "vless-all-in-one"
        draw_divider
        printf "  ${red}%-2s${none} %-35s\n" "0." "退出脚本"
        draw_divider

        read -p " 请输入选项 [0-17]: " choice || true

        local needs_pause=true

        case "$choice" in
            1) install_menu ;;
            2) add_new_vless ;;
            3) delete_vless_node ;;
            4) modify_vless_config ;;
            5) add_new_ss ;;
            6) delete_ss_node ;;
            7) modify_ss_config ;;
            8) add_socks5_proxy ;;
            9) list_socks5_proxies ;;
            10) delete_socks5_proxy ;;
            11) update_xray ;;
            12) uninstall_xray ;;
            13) restart_xray ;;
            14) view_xray_log; needs_pause=false ;;
            15) view_all_info ;;
            16) manage_routing_rules ;;
            17) wget -O vless-server.sh https://raw.githubusercontent.com/Chil30/vless-all-in-one/main/vless-server.sh && chmod +x vless-server.sh && bash vless-server.sh; needs_pause=false ;;
            0) success "感谢使用！"; exit 0 ;;
            *) error "无效选项。请输入 0-17。" ;;
        esac

        if [ "$needs_pause" = true ]; then
            press_any_key_to_continue
        fi
    done
}

# --- 脚本主入口 ---
main() {
    pre_check
    main_menu
}

main "$@"
XRAY_ENHANCED_SCRIPT_EOF

    chmod +x "$script_path"
    echo -e "${gl_lv}✅ 脚本准备完成${gl_bai}"
    echo ""

    # 执行脚本
    if bash "$script_path"; then
        echo ""
        echo -e "${gl_lv}✅ 星辰大海Xray增强版脚本执行完成${gl_bai}"
    else
        echo ""
        echo -e "${gl_hong}❌ 脚本执行失败${gl_bai}"
    fi

    # 清理临时文件
    rm -f "$script_path"

    echo ""
    echo "------------------------------------------------"
    break_end
}

#=============================================================================
# 禁止端口通过中国大陆直连功能
#=============================================================================

# 配置文件路径
CN_BLOCK_CONFIG="/usr/local/etc/xray/cn-block-ports.conf"
CN_IPSET_NAME="china-ip-block"
CN_IP_LIST_FILE="/tmp/china-ip-list.txt"

# 检查依赖
check_cn_block_dependencies() {
    local missing_deps=()

    if ! command -v ipset &> /dev/null; then
        missing_deps+=("ipset")
    fi

    if ! command -v iptables &> /dev/null; then
        missing_deps+=("iptables")
    fi

    if [ ${#missing_deps[@]} -gt 0 ]; then
        echo -e "${gl_huang}检测到缺少依赖: ${missing_deps[*]}${gl_bai}"
        echo "正在安装..."

        if command -v apt-get &> /dev/null; then
            apt-get update -qq
            # 预设交互式问题答案
            echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections 2>/dev/null
            echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections 2>/dev/null
            apt-get install -y ipset iptables iptables-persistent
        elif command -v yum &> /dev/null; then
            yum install -y ipset iptables iptables-services
        else
            echo -e "${gl_hong}❌ 不支持的系统，请手动安装 ipset 和 iptables${gl_bai}"
            return 1
        fi

        echo -e "${gl_lv}✅ 依赖安装完成${gl_bai}"
    fi

    # 确保持久化服务开机自启
    if command -v netfilter-persistent &> /dev/null; then
        systemctl enable netfilter-persistent 2>/dev/null || true
    elif command -v systemctl &> /dev/null && [ -f /usr/lib/systemd/system/iptables.service ]; then
        systemctl enable iptables 2>/dev/null || true
    fi

    return 0
}

# ipset 持久化文件路径
CN_IPSET_SAVE_FILE="/etc/iptables/ipsets.china-block"

# 保存 ipset 数据
save_cn_ipset() {
    if ipset list "$CN_IPSET_NAME" &>/dev/null; then
        mkdir -p /etc/iptables
        ipset save "$CN_IPSET_NAME" > "$CN_IPSET_SAVE_FILE" 2>/dev/null
    fi
}

# 恢复 ipset 数据
restore_cn_ipset() {
    # 如果 ipset 已存在且有数据，跳过恢复
    if ipset list "$CN_IPSET_NAME" &>/dev/null; then
        local ip_count=$(ipset list "$CN_IPSET_NAME" 2>/dev/null | grep -c '^[0-9]' || echo "0")
        if [ "$ip_count" -gt 0 ]; then
            return 0
        fi
    fi

    # 尝试从保存文件恢复
    if [ -f "$CN_IPSET_SAVE_FILE" ]; then
        ipset restore < "$CN_IPSET_SAVE_FILE" 2>/dev/null && return 0
    fi

    # 尝试从系统默认位置恢复
    if [ -f /etc/iptables/ipsets ]; then
        grep -A 99999 "create $CN_IPSET_NAME" /etc/iptables/ipsets 2>/dev/null | \
            sed "/^create [^$CN_IPSET_NAME]/q" | head -n -1 | \
            ipset restore 2>/dev/null && return 0
    fi

    return 1
}

# 恢复 iptables 规则（针对已配置的端口）
restore_cn_iptables_rules() {
    # 检查 ipset 是否存在
    if ! ipset list "$CN_IPSET_NAME" &>/dev/null; then
        return 1
    fi

    # 检查配置文件
    if [ ! -f "$CN_BLOCK_CONFIG" ]; then
        return 0
    fi

    # 获取已配置的端口并重新应用规则
    local port
    while IFS='|' read -r port _ _; do
        [[ -z "$port" || "$port" =~ ^# ]] && continue

        # 检查规则是否已存在，不存在则添加
        if ! iptables -C INPUT -p tcp --dport "$port" -m set --match-set "$CN_IPSET_NAME" src -j DROP 2>/dev/null; then
            iptables -I INPUT -p tcp --dport "$port" -m set --match-set "$CN_IPSET_NAME" src -j DROP 2>/dev/null
        fi
        if ! iptables -C INPUT -p udp --dport "$port" -m set --match-set "$CN_IPSET_NAME" src -j DROP 2>/dev/null; then
            iptables -I INPUT -p udp --dport "$port" -m set --match-set "$CN_IPSET_NAME" src -j DROP 2>/dev/null
        fi
    done < "$CN_BLOCK_CONFIG"

    return 0
}

# 初始化配置文件
init_cn_block_config() {
    if [ ! -f "$CN_BLOCK_CONFIG" ]; then
        mkdir -p "$(dirname "$CN_BLOCK_CONFIG")"
        cat > "$CN_BLOCK_CONFIG" << 'EOF'
# 中国大陆 IP 封锁端口配置文件
# 格式: 端口|添加时间|备注
# 示例: 1234|2025-10-25 12:00:00|SS节点
EOF
    fi

    # 检查：如果 ipset 在内存中存在但保存文件不存在，自动保存一份（升级兼容）
    if ipset list "$CN_IPSET_NAME" &>/dev/null; then
        local ip_count=$(ipset list "$CN_IPSET_NAME" 2>/dev/null | grep -c '^[0-9]' || echo "0")
        if [ "$ip_count" -gt 0 ] && [ ! -f "$CN_IPSET_SAVE_FILE" ]; then
            echo -e "${gl_huang}检测到内存中有 IP 数据但未持久化，正在自动保存...${gl_bai}"
            save_cn_ipset
            echo -e "${gl_lv}✅ 已自动保存 $ip_count 条 IP 段，重启后将自动恢复${gl_bai}"
            sleep 1
        fi
    else
        # 重启后恢复 ipset 数据
        restore_cn_ipset
    fi

    # 重启后恢复 iptables 规则
    restore_cn_iptables_rules
}

# 下载中国 IP 段列表
download_china_ip_list() {
    echo -e "${gl_kjlan}正在下载中国 IP 段列表...${gl_bai}"

    local sources=(
        "https://raw.githubusercontent.com/metowolf/iplist/master/data/country/CN.txt"
        "https://ispip.clang.cn/all_cn.txt"
        "https://raw.githubusercontent.com/17mon/china_ip_list/master/china_ip_list.txt"
    )

    local downloaded=0

    for source in "${sources[@]}"; do
        echo "尝试从 $source 下载..."
        if curl -sSL --connect-timeout 10 --max-time 60 "$source" -o "$CN_IP_LIST_FILE" 2>/dev/null; then
            if [ -s "$CN_IP_LIST_FILE" ]; then
                local line_count=$(wc -l < "$CN_IP_LIST_FILE")
                if [ "$line_count" -gt 1000 ]; then
                    echo -e "${gl_lv}✅ 下载成功，共 $line_count 条 IP 段${gl_bai}"
                    downloaded=1
                    break
                fi
            fi
        fi
    done

    if [ $downloaded -eq 0 ]; then
        echo -e "${gl_hong}❌ 所有源下载失败${gl_bai}"
        return 1
    fi

    return 0
}

# 创建或更新 ipset
update_china_ipset() {
    echo -e "${gl_kjlan}正在更新 IP 地址库...${gl_bai}"

    # 使用文件锁防止并发执行
    local lock_file="/var/lock/china-ipset-update.lock"
    local lock_fd=200

    # 尝试获取锁（最多等待30秒）
    exec 200>"$lock_file"
    if ! flock -w 30 200; then
        echo -e "${gl_hong}❌ 无法获取锁，可能有其他实例正在运行${gl_bai}"
        return 1
    fi

    # 确保退出时释放锁和清理临时文件
    trap "flock -u 200; rm -f '$lock_file' '$CN_IP_LIST_FILE'" EXIT ERR

    # 下载 IP 列表
    if ! download_china_ip_list; then
        return 1
    fi

    # 创建临时 ipset
    local temp_set="${CN_IPSET_NAME}-temp"

    # 删除旧的临时集合（如果存在）
    ipset destroy "$temp_set" 2>/dev/null || true

    # 创建新的临时集合
    ipset create "$temp_set" hash:net maxelem 70000

    # 添加 IP 段到临时集合
    local count=0
    while IFS= read -r ip; do
        # 跳过空行和注释
        [[ -z "$ip" || "$ip" =~ ^# ]] && continue

        # 验证 IP 格式
        if [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]+)?$ ]]; then
            ipset add "$temp_set" "$ip" 2>/dev/null && ((count++))
        fi
    done < "$CN_IP_LIST_FILE"

    echo -e "${gl_lv}✅ 成功添加 $count 条 IP 段到集合${gl_bai}"

    # 交换集合（原子操作）
    if ipset list "$CN_IPSET_NAME" &>/dev/null; then
        ipset swap "$temp_set" "$CN_IPSET_NAME"
        ipset destroy "$temp_set"
    else
        ipset rename "$temp_set" "$CN_IPSET_NAME"
    fi

    # 清理临时文件
    rm -f "$CN_IP_LIST_FILE"

    # 保存 ipset 到专用文件（确保重启后恢复）
    save_cn_ipset

    # 同时尝试保存到系统持久化服务
    if command -v ipset-persistent &> /dev/null; then
        ipset-persistent save 2>/dev/null || true
    elif command -v netfilter-persistent &> /dev/null; then
        netfilter-persistent save 2>/dev/null || true
    fi

    # 清理 trap 和释放锁
    trap - EXIT ERR
    flock -u 200

    echo -e "${gl_lv}✅ IP 地址库更新完成${gl_bai}"
    return 0
}

# 添加端口封锁规则
add_port_block_rule() {
    local port="$1"
    local note="${2:-手动添加}"

    # 验证端口
    if ! [[ "$port" =~ ^[0-9]+$ ]] || [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
        echo -e "${gl_hong}❌ 无效的端口号: $port${gl_bai}"
        return 1
    fi

    # 检查是否已存在
    if grep -q "^${port}|" "$CN_BLOCK_CONFIG" 2>/dev/null; then
        echo -e "${gl_huang}⚠ 端口 $port 已在封锁列表中${gl_bai}"
        return 1
    fi

    # 确保 ipset 存在
    if ! ipset list "$CN_IPSET_NAME" &>/dev/null; then
        echo -e "${gl_huang}IP 地址库不存在，正在创建...${gl_bai}"
        if ! update_china_ipset; then
            return 1
        fi
    fi

    # 添加 iptables 规则
    iptables -C INPUT -p tcp --dport "$port" -m set --match-set "$CN_IPSET_NAME" src -j DROP 2>/dev/null || \
        iptables -I INPUT -p tcp --dport "$port" -m set --match-set "$CN_IPSET_NAME" src -j DROP

    iptables -C INPUT -p udp --dport "$port" -m set --match-set "$CN_IPSET_NAME" src -j DROP 2>/dev/null || \
        iptables -I INPUT -p udp --dport "$port" -m set --match-set "$CN_IPSET_NAME" src -j DROP

    # 保存到配置文件
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "${port}|${timestamp}|${note}" >> "$CN_BLOCK_CONFIG"

    # 保存 iptables 规则
    if command -v netfilter-persistent &> /dev/null; then
        netfilter-persistent save >/dev/null 2>&1
    elif command -v iptables-save &> /dev/null; then
        mkdir -p /etc/iptables
        iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
    fi

    echo -e "${gl_lv}✅ 端口 $port 封锁规则已添加${gl_bai}"
    return 0
}

# 删除端口封锁规则
remove_port_block_rule() {
    local port="$1"

    # 验证端口
    if ! [[ "$port" =~ ^[0-9]+$ ]]; then
        echo -e "${gl_hong}❌ 无效的端口号: $port${gl_bai}"
        return 1
    fi

    # 检查是否存在
    if ! grep -q "^${port}|" "$CN_BLOCK_CONFIG" 2>/dev/null; then
        echo -e "${gl_huang}⚠ 端口 $port 不在封锁列表中${gl_bai}"
        return 1
    fi

    # 删除 iptables 规则
    iptables -D INPUT -p tcp --dport "$port" -m set --match-set "$CN_IPSET_NAME" src -j DROP 2>/dev/null || true
    iptables -D INPUT -p udp --dport "$port" -m set --match-set "$CN_IPSET_NAME" src -j DROP 2>/dev/null || true

    # 从配置文件删除
    sed -i "/^${port}|/d" "$CN_BLOCK_CONFIG"

    # 保存 iptables 规则
    if command -v netfilter-persistent &> /dev/null; then
        netfilter-persistent save >/dev/null 2>&1
    elif command -v iptables-save &> /dev/null; then
        mkdir -p /etc/iptables
        iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
    fi

    echo -e "${gl_lv}✅ 端口 $port 封锁规则已删除${gl_bai}"
    return 0
}

# 获取已封锁端口列表
get_blocked_ports() {
    if [ ! -f "$CN_BLOCK_CONFIG" ]; then
        return 0
    fi

    grep -v '^#' "$CN_BLOCK_CONFIG" | grep -v '^$' | awk -F'|' '{print $1}'
}

# 获取 Xray 端口列表
get_xray_ports() {
    local xray_config="/usr/local/etc/xray/config.json"

    if [ ! -f "$xray_config" ]; then
        return 0
    fi

    if command -v jq &> /dev/null; then
        jq -r '.inbounds[]?.port // empty' "$xray_config" 2>/dev/null | sort -n
    fi
}

# 清空所有封锁规则
clear_all_block_rules() {
    echo -e "${gl_huang}正在清空所有封锁规则...${gl_bai}"

    # 读取所有已封锁端口
    local ports=($(get_blocked_ports))

    if [ ${#ports[@]} -eq 0 ]; then
        echo -e "${gl_huang}⚠ 没有需要清空的规则${gl_bai}"
        return 0
    fi

    # 删除所有 iptables 规则
    for port in "${ports[@]}"; do
        iptables -D INPUT -p tcp --dport "$port" -m set --match-set "$CN_IPSET_NAME" src -j DROP 2>/dev/null || true
        iptables -D INPUT -p udp --dport "$port" -m set --match-set "$CN_IPSET_NAME" src -j DROP 2>/dev/null || true
    done

    # 清空配置文件
    cat > "$CN_BLOCK_CONFIG" << 'EOF'
# 中国大陆 IP 封锁端口配置文件
# 格式: 端口|添加时间|备注
# 示例: 1234|2025-10-25 12:00:00|SS节点
EOF

    # 保存 iptables 规则
    if command -v netfilter-persistent &> /dev/null; then
        netfilter-persistent save >/dev/null 2>&1
    elif command -v iptables-save &> /dev/null; then
        mkdir -p /etc/iptables
        iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
    fi

    echo -e "${gl_lv}✅ 已清空 ${#ports[@]} 条封锁规则${gl_bai}"
    return 0
}

# 菜单：添加端口封锁
menu_add_port_block() {
    clear
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo -e "${gl_kjlan}      添加端口封锁规则${gl_bai}"
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo ""

    # 显示 Xray 端口
    local xray_ports=($(get_xray_ports))
    if [ ${#xray_ports[@]} -gt 0 ]; then
        echo -e "${gl_zi}检测到 Xray 端口:${gl_bai}"
        for i in "${!xray_ports[@]}"; do
            echo "  $((i+1)). ${xray_ports[$i]}"
        done
        echo ""
    fi

    echo "请选择添加方式:"
    echo "1. 手动输入端口号"
    if [ ${#xray_ports[@]} -gt 0 ]; then
        echo "2. 从 Xray 端口列表选择"
        echo "3. 封锁所有 Xray 端口"
    fi
    echo "0. 返回"
    echo ""

    read -p "请选择 [0-3]: " choice

    case "$choice" in
        1)
            echo ""
            read -p "请输入端口号（多个端口用逗号分隔）: " ports_input

            if [ -z "$ports_input" ]; then
                echo -e "${gl_hong}❌ 端口号不能为空${gl_bai}"
                sleep 2
                return
            fi

            IFS=',' read -ra ports <<< "$ports_input"
            local success=0
            local failed=0

            for port in "${ports[@]}"; do
                port=$(echo "$port" | xargs)  # 去除空格
                read -p "为端口 $port 添加备注（可选，回车跳过）: " note
                [ -z "$note" ] && note="手动添加"

                if add_port_block_rule "$port" "$note"; then
                    ((success++))
                else
                    ((failed++))
                fi
            done

            echo ""
            echo -e "${gl_lv}✅ 成功添加 $success 条规则${gl_bai}"
            [ $failed -gt 0 ] && echo -e "${gl_hong}❌ 失败 $failed 条${gl_bai}"
            ;;
        2)
            if [ ${#xray_ports[@]} -eq 0 ]; then
                echo -e "${gl_hong}❌ 无效选择${gl_bai}"
                sleep 2
                return
            fi

            echo ""
            read -p "请选择端口编号（多个用逗号分隔，0=全部）: " selection

            if [ "$selection" = "0" ]; then
                local success=0
                for port in "${xray_ports[@]}"; do
                    if add_port_block_rule "$port" "Xray端口"; then
                        ((success++))
                    fi
                done
                echo ""
                echo -e "${gl_lv}✅ 成功添加 $success 条规则${gl_bai}"
            else
                IFS=',' read -ra selections <<< "$selection"
                local success=0
                for sel in "${selections[@]}"; do
                    sel=$(echo "$sel" | xargs)
                    if [ "$sel" -ge 1 ] && [ "$sel" -le ${#xray_ports[@]} ]; then
                        local port="${xray_ports[$((sel-1))]}"
                        if add_port_block_rule "$port" "Xray端口"; then
                            ((success++))
                        fi
                    fi
                done
                echo ""
                echo -e "${gl_lv}✅ 成功添加 $success 条规则${gl_bai}"
            fi
            ;;
        3)
            if [ ${#xray_ports[@]} -eq 0 ]; then
                echo -e "${gl_hong}❌ 无效选择${gl_bai}"
                sleep 2
                return
            fi

            echo ""
            echo -e "${gl_huang}将封锁以下端口:${gl_bai}"
            printf '%s\n' "${xray_ports[@]}"
            echo ""
            read -p "确认执行？[y/N]: " confirm

            if [[ "$confirm" =~ ^[Yy]$ ]]; then
                local success=0
                for port in "${xray_ports[@]}"; do
                    if add_port_block_rule "$port" "Xray端口"; then
                        ((success++))
                    fi
                done
                echo ""
                echo -e "${gl_lv}✅ 成功添加 $success 条规则${gl_bai}"
            else
                echo "已取消"
            fi
            ;;
        0)
            return
            ;;
        *)
            echo -e "${gl_hong}❌ 无效选择${gl_bai}"
            sleep 2
            return
            ;;
    esac

    echo ""
    read -p "按任意键继续..." -n 1
}

# 菜单：删除端口封锁
menu_remove_port_block() {
    clear
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo -e "${gl_kjlan}      删除端口封锁规则${gl_bai}"
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo ""

    if [ ! -f "$CN_BLOCK_CONFIG" ]; then
        echo -e "${gl_huang}⚠ 没有已封锁的端口${gl_bai}"
        echo ""
        read -p "按任意键继续..." -n 1
        return
    fi

    # 读取已封锁端口
    local blocked_ports=()
    local port_info=()

    while IFS='|' read -r port timestamp note; do
        [[ "$port" =~ ^# ]] && continue
        [[ -z "$port" ]] && continue
        blocked_ports+=("$port")
        port_info+=("$port|$timestamp|$note")
    done < "$CN_BLOCK_CONFIG"

    if [ ${#blocked_ports[@]} -eq 0 ]; then
        echo -e "${gl_huang}⚠ 没有已封锁的端口${gl_bai}"
        echo ""
        read -p "按任意键继续..." -n 1
        return
    fi

    echo -e "${gl_zi}已封锁的端口:${gl_bai}"
    echo ""
    printf "%-4s %-8s %-20s %s\n" "编号" "端口" "添加时间" "备注"
    echo "────────────────────────────────────────────────"

    for i in "${!port_info[@]}"; do
        IFS='|' read -r port timestamp note <<< "${port_info[$i]}"
        printf "%-4s %-8s %-20s %s\n" "$((i+1))" "$port" "$timestamp" "$note"
    done

    echo ""
    read -p "请选择要删除的端口编号（多个用逗号分隔，0=全部）: " selection

    if [ -z "$selection" ]; then
        return
    fi

    if [ "$selection" = "0" ]; then
        echo ""
        read -p "确认删除所有封锁规则？[y/N]: " confirm
        if [[ "$confirm" =~ ^[Yy]$ ]]; then
            clear_all_block_rules
        else
            echo "已取消"
        fi
    else
        IFS=',' read -ra selections <<< "$selection"
        local success=0
        for sel in "${selections[@]}"; do
            sel=$(echo "$sel" | xargs)
            if [ "$sel" -ge 1 ] && [ "$sel" -le ${#blocked_ports[@]} ]; then
                local port="${blocked_ports[$((sel-1))]}"
                if remove_port_block_rule "$port"; then
                    ((success++))
                fi
            fi
        done
        echo ""
        echo -e "${gl_lv}✅ 成功删除 $success 条规则${gl_bai}"
    fi

    echo ""
    read -p "按任意键继续..." -n 1
}

# 菜单：查看已封锁端口列表
menu_list_blocked_ports() {
    clear
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo -e "${gl_kjlan}      已封锁端口列表${gl_bai}"
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo ""

    if [ ! -f "$CN_BLOCK_CONFIG" ]; then
        echo -e "${gl_huang}⚠ 没有已封锁的端口${gl_bai}"
        echo ""
        read -p "按任意键继续..." -n 1
        return
    fi

    local count=0
    echo -e "${gl_zi}端口列表:${gl_bai}"
    echo ""
    printf "%-8s %-20s %-30s\n" "端口" "添加时间" "备注"
    echo "────────────────────────────────────────────────────────────"

    while IFS='|' read -r port timestamp note; do
        [[ "$port" =~ ^# ]] && continue
        [[ -z "$port" ]] && continue
        printf "%-8s %-20s %-30s\n" "$port" "$timestamp" "$note"
        ((count++))
    done < "$CN_BLOCK_CONFIG"

    echo "────────────────────────────────────────────────────────────"
    echo -e "${gl_lv}共 $count 个端口被封锁${gl_bai}"

    # 显示 ipset 统计
    if ipset list "$CN_IPSET_NAME" &>/dev/null; then
        local ip_count=$(ipset list "$CN_IPSET_NAME" | grep -c '^[0-9]')
        echo -e "${gl_zi}IP 地址库: $ip_count 条中国 IP 段${gl_bai}"
    fi

    echo ""
    read -p "按任意键继续..." -n 1
}

# 菜单：更新 IP 地址库
menu_update_ip_database() {
    clear
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo -e "${gl_kjlan}      更新 IP 地址库${gl_bai}"
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo ""

    if ipset list "$CN_IPSET_NAME" &>/dev/null; then
        local ip_count=$(ipset list "$CN_IPSET_NAME" | grep -c '^[0-9]')
        echo -e "${gl_zi}当前 IP 地址库: $ip_count 条中国 IP 段${gl_bai}"
        echo ""
    fi

    read -p "确认更新 IP 地址库？[y/N]: " confirm

    if [[ "$confirm" =~ ^[Yy]$ ]]; then
        echo ""
        if update_china_ipset; then
            echo ""
            echo -e "${gl_lv}✅ IP 地址库更新成功${gl_bai}"

            # 重新应用所有规则
            local ports=($(get_blocked_ports))
            if [ ${#ports[@]} -gt 0 ]; then
                echo ""
                echo -e "${gl_kjlan}正在重新应用封锁规则...${gl_bai}"
                for port in "${ports[@]}"; do
                    # 删除旧规则
                    iptables -D INPUT -p tcp --dport "$port" -m set --match-set "$CN_IPSET_NAME" src -j DROP 2>/dev/null || true
                    iptables -D INPUT -p udp --dport "$port" -m set --match-set "$CN_IPSET_NAME" src -j DROP 2>/dev/null || true

                    # 添加新规则
                    iptables -I INPUT -p tcp --dport "$port" -m set --match-set "$CN_IPSET_NAME" src -j DROP
                    iptables -I INPUT -p udp --dport "$port" -m set --match-set "$CN_IPSET_NAME" src -j DROP
                done

                # 保存规则
                if command -v netfilter-persistent &> /dev/null; then
                    netfilter-persistent save >/dev/null 2>&1
                fi

                echo -e "${gl_lv}✅ 已重新应用 ${#ports[@]} 条封锁规则${gl_bai}"
            fi
        else
            echo ""
            echo -e "${gl_hong}❌ IP 地址库更新失败${gl_bai}"
        fi
    else
        echo "已取消"
    fi

    echo ""
    read -p "按任意键继续..." -n 1
}

# 菜单：查看拦截日志
menu_view_block_logs() {
    clear
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo -e "${gl_kjlan}      拦截日志（最近50条）${gl_bai}"
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo ""

    # 获取已封锁端口
    local ports=($(get_blocked_ports))

    if [ ${#ports[@]} -eq 0 ]; then
        echo -e "${gl_huang}⚠ 没有已封锁的端口${gl_bai}"
        echo ""
        read -p "按任意键继续..." -n 1
        return
    fi

    echo -e "${gl_zi}正在查询防火墙日志...${gl_bai}"
    echo ""

    # 构建端口过滤条件
    local port_filter=""
    for port in "${ports[@]}"; do
        port_filter="${port_filter}DPT=${port}|"
    done
    port_filter="${port_filter%|}"  # 删除最后一个 |

    # 查询内核日志
    if dmesg | grep -E "$port_filter" | tail -50 | grep -q .; then
        dmesg | grep -E "$port_filter" | tail -50
    elif journalctl -k --no-pager 2>/dev/null | grep -E "$port_filter" | tail -50 | grep -q .; then
        journalctl -k --no-pager | grep -E "$port_filter" | tail -50
    else
        echo -e "${gl_huang}⚠ 暂无拦截日志${gl_bai}"
        echo ""
        echo "提示: 如需记录拦截日志，请添加 iptables LOG 规则："
        echo "  iptables -I INPUT -p tcp --dport <端口> -m set --match-set $CN_IPSET_NAME src -j LOG --log-prefix 'CN-BLOCK: '"
    fi

    echo ""
    read -p "按任意键继续..." -n 1
}

# 主菜单
manage_cn_ip_block() {
    # 检查依赖
    if ! check_cn_block_dependencies; then
        echo ""
        read -p "按任意键继续..." -n 1
        return
    fi

    # 初始化配置
    init_cn_block_config

    while true; do
        clear
        echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
        echo -e "${gl_kjlan}    禁止端口通过中国大陆直连管理${gl_bai}"
        echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
        echo ""

        # 显示状态
        local blocked_count=$(get_blocked_ports | wc -l)
        local ipset_count=0
        if ipset list "$CN_IPSET_NAME" &>/dev/null; then
            ipset_count=$(ipset list "$CN_IPSET_NAME" | grep -c '^[0-9]')
        fi

        echo -e "${gl_zi}当前状态:${gl_bai}"
        echo "  • 已封锁端口: $blocked_count 个"
        echo "  • IP 地址库: $ipset_count 条中国 IP 段"
        echo ""

        echo "1. 添加端口封锁规则"
        echo "2. 删除端口封锁规则"
        echo "3. 查看已封锁端口列表"
        echo "4. 更新 IP 地址库"
        echo "5. 查看拦截日志"
        echo "6. 一键封锁所有 Xray 端口"
        echo "7. 清空所有封锁规则"
        echo "0. 返回主菜单"
        echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
        echo ""

        read -p "请选择 [0-7]: " choice

        case "$choice" in
            1)
                menu_add_port_block
                ;;
            2)
                menu_remove_port_block
                ;;
            3)
                menu_list_blocked_ports
                ;;
            4)
                menu_update_ip_database
                ;;
            5)
                menu_view_block_logs
                ;;
            6)
                clear
                echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
                echo -e "${gl_kjlan}    一键封锁所有 Xray 端口${gl_bai}"
                echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
                echo ""

                local xray_ports=($(get_xray_ports))
                if [ ${#xray_ports[@]} -eq 0 ]; then
                    echo -e "${gl_huang}⚠ 未检测到 Xray 端口${gl_bai}"
                else
                    echo -e "${gl_zi}检测到以下 Xray 端口:${gl_bai}"
                    printf '%s\n' "${xray_ports[@]}"
                    echo ""
                    read -p "确认封锁所有端口？[y/N]: " confirm

                    if [[ "$confirm" =~ ^[Yy]$ ]]; then
                        local success=0
                        for port in "${xray_ports[@]}"; do
                            if add_port_block_rule "$port" "Xray端口"; then
                                ((success++))
                            fi
                        done
                        echo ""
                        echo -e "${gl_lv}✅ 成功添加 $success 条规则${gl_bai}"
                    else
                        echo "已取消"
                    fi
                fi

                echo ""
                read -p "按任意键继续..." -n 1
                ;;
            7)
                clear
                echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
                echo -e "${gl_kjlan}      清空所有封锁规则${gl_bai}"
                echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
                echo ""

                local blocked_count=$(get_blocked_ports | wc -l)
                echo -e "${gl_huang}⚠ 将删除所有 $blocked_count 条封锁规则${gl_bai}"
                echo ""
                read -p "确认执行？[y/N]: " confirm

                if [[ "$confirm" =~ ^[Yy]$ ]]; then
                    clear_all_block_rules
                else
                    echo "已取消"
                fi

                echo ""
                read -p "按任意键继续..." -n 1
                ;;
            0)
                return
                ;;
            *)
                echo -e "${gl_hong}❌ 无效选择${gl_bai}"
                sleep 1
                ;;
        esac
    done
}

run_kejilion_script() {
    clear
    echo -e "${gl_kjlan}=== 科技lion脚本 ===${gl_bai}"
    echo ""
    echo "正在运行科技lion脚本..."
    echo "------------------------------------------------"
    echo ""

    # 执行科技lion脚本
    if ! run_remote_script "kejilion.sh" bash; then
        echo -e "${gl_hong}❌ 脚本执行失败${gl_bai}"
        break_end
        return 1
    fi

    echo ""
    echo "------------------------------------------------"
    break_end
}

run_fscarmen_singbox() {
    clear
    echo -e "${gl_kjlan}=== F佬一键sing box脚本 ===${gl_bai}"
    echo ""
    echo "正在运行 F佬一键sing box脚本..."
    echo "------------------------------------------------"
    echo ""

    # 执行 F佬一键sing box脚本
    if ! run_remote_script "https://raw.githubusercontent.com/fscarmen/sing-box/main/sing-box.sh" bash; then
        echo -e "${gl_hong}❌ 脚本执行失败${gl_bai}"
        break_end
        return 1
    fi

    echo ""
    echo "------------------------------------------------"
    break_end
}

#=============================================================================
# CAKE 加速功能（来自 cake.sh）
#=============================================================================

#卸载bbr+锐速
remove_bbr_lotserver() {
  sed -i '/net.ipv4.tcp_ecn/d' /etc/sysctl.d/99-sysctl.conf
  sed -i '/net.core.default_qdisc/d' /etc/sysctl.d/99-sysctl.conf
  sed -i '/net.ipv4.tcp_congestion_control/d' /etc/sysctl.d/99-sysctl.conf
  sed -i '/net.ipv4.tcp_ecn/d' /etc/sysctl.conf
  sed -i '/net.core.default_qdisc/d' /etc/sysctl.conf
  sed -i '/net.ipv4.tcp_congestion_control/d' /etc/sysctl.conf
  sysctl --system

  rm -rf bbrmod

  if [[ -e /appex/bin/lotServer.sh ]]; then
    if ! printf '\n' | run_remote_script "https://raw.githubusercontent.com/fei5seven/lotServer/master/lotServerInstall.sh" bash uninstall; then
      echo -e "${gl_huang}⚠️  lotServer 卸载脚本执行失败，已跳过${gl_bai}"
    fi
  fi
  clear
}

#启用BBR+cake
startbbrcake() {
  remove_bbr_lotserver
  echo "net.core.default_qdisc=cake" >>/etc/sysctl.d/99-sysctl.conf
  echo "net.ipv4.tcp_congestion_control=bbr" >>/etc/sysctl.d/99-sysctl.conf
  sysctl --system
  echo -e "${gl_lv}[信息]${gl_bai}BBR+cake修改成功，重启生效！"
  break_end
}

#=============================================================================
# SOCKS5 一键部署功能
#=============================================================================

# SOCKS5 配置目录
SOCKS5_CONFIG_DIR="/etc/sbox_socks5"
SOCKS5_CONFIG_FILE="${SOCKS5_CONFIG_DIR}/config.json"
SOCKS5_SERVICE_NAME="sbox-socks5"

# 检测 sing-box 二进制程序（公共函数）
# 成功时设置全局变量 DETECTED_SINGBOX_CMD 并返回 0
# 失败时返回 1
# 参数: $1 = "verbose" 时显示详细检测过程
detect_singbox_cmd() {
    local verbose="${1:-}"
    DETECTED_SINGBOX_CMD=""
    local detection_debug=""

    # 优先查找常见的二进制程序位置
    for path in /etc/sing-box/sing-box /usr/local/bin/sing-box /opt/sing-box/sing-box; do
        detection_debug+="正在检测: $path ... "

        if [ ! -e "$path" ]; then
            detection_debug+="不存在\n"
            continue
        fi

        if [ ! -x "$path" ]; then
            detection_debug+="存在但不可执行（尝试添加执行权限）\n"
            chmod +x "$path" 2>/dev/null
            if [ ! -x "$path" ]; then
                detection_debug+="  └─ 无法添加执行权限，跳过\n"
                continue
            fi
        fi

        # 如果是符号链接，解析实际路径
        if [ -L "$path" ]; then
            local real_path=$(readlink -f "$path")
            detection_debug+="是符号链接 → $real_path\n"
            path="$real_path"
        fi

        # 验证是 ELF 二进制文件（如果 file 命令可用）
        if command -v file >/dev/null 2>&1; then
            local file_type=$(file "$path" 2>/dev/null)
            if echo "$file_type" | grep -q "ELF"; then
                DETECTED_SINGBOX_CMD="$path"
                break
            else
                detection_debug+="  └─ 不是 ELF 二进制文件（类型: $file_type），跳过\n"
            fi
        else
            DETECTED_SINGBOX_CMD="$path"
            break
        fi
    done

    # 如果没找到，检查 PATH 中的命令
    if [ -z "$DETECTED_SINGBOX_CMD" ]; then
        for cmd in sing-box sb; do
            if command -v "$cmd" &>/dev/null; then
                local cmd_path=$(which "$cmd")
                detection_debug+="正在检测 PATH 命令: $cmd → $cmd_path ... "

                if [ -L "$cmd_path" ]; then
                    local real_path=$(readlink -f "$cmd_path")
                    detection_debug+="是符号链接 → $real_path\n"
                    cmd_path="$real_path"
                fi

                if command -v file >/dev/null 2>&1; then
                    local file_type=$(file "$cmd_path" 2>/dev/null)
                    if echo "$file_type" | grep -q "ELF"; then
                        DETECTED_SINGBOX_CMD="$cmd_path"
                        break
                    else
                        detection_debug+="  └─ 不是 ELF 二进制文件（类型: $file_type），跳过\n"
                    fi
                else
                    DETECTED_SINGBOX_CMD="$cmd_path"
                    break
                fi
            fi
        done
    fi

    if [ -n "$DETECTED_SINGBOX_CMD" ]; then
        [ "$verbose" = "verbose" ] && echo -e "${gl_lv}✅ 找到 sing-box 二进制程序: $DETECTED_SINGBOX_CMD${gl_bai}"
        return 0
    else
        [ "$verbose" = "verbose" ] && echo -e "${gl_hong}❌ 未找到 sing-box 二进制程序${gl_bai}"
        # 提供调试信息
        if [ "$verbose" = "verbose" ]; then
            read -e -p "$(echo -e "${gl_zi}是否查看详细检测过程？(y/N): ${gl_bai}")" show_debug
            if [[ "$show_debug" =~ ^[Yy]$ ]]; then
                echo ""
                echo "检测过程："
                echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                echo -e "$detection_debug"
                echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                echo ""
            fi
        fi
        return 1
    fi
}

# 获取服务器公网IP（带格式验证）
# 参数: $1 = "ipv4" | "ipv6" | "auto"（默认 auto，优先IPv4）
# 返回: 输出有效IP地址，失败输出 "IP获取失败"
get_server_ip() {
    local mode="${1:-auto}"
    local result=""

    # IP格式验证函数
    _is_valid_ip() {
        local ip="$1"
        # IPv4: 纯数字和点
        if [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            return 0
        fi
        # IPv6: 十六进制和冒号（含压缩格式）
        if [[ "$ip" =~ ^[0-9a-fA-F:]+$ ]] && [[ "$ip" == *:* ]]; then
            return 0
        fi
        return 1
    }

    # 尝试获取IP并验证
    _try_get_ip() {
        local url="$1"
        local curl_flag="$2"
        result=$(curl "$curl_flag" -s --max-time 5 "$url" 2>/dev/null | tr -d '[:space:]')
        if [ -n "$result" ] && _is_valid_ip "$result"; then
            echo "$result"
            return 0
        fi
        return 1
    }

    case "$mode" in
        ipv6)
            _try_get_ip "ifconfig.me" "-6" && return 0
            _try_get_ip "ip.sb" "-6" && return 0
            _try_get_ip "ipinfo.io/ip" "-6" && return 0
            ;;
        ipv4)
            _try_get_ip "ifconfig.me" "-4" && return 0
            _try_get_ip "ip.sb" "-4" && return 0
            _try_get_ip "ipinfo.io/ip" "-4" && return 0
            ;;
        *)
            # auto: 先IPv4后IPv6
            _try_get_ip "ifconfig.me" "-4" && return 0
            _try_get_ip "ip.sb" "-4" && return 0
            _try_get_ip "ipinfo.io/ip" "-4" && return 0
            _try_get_ip "ifconfig.me" "-6" && return 0
            _try_get_ip "ip.sb" "-6" && return 0
            ;;
    esac

    echo "IP获取失败"
    return 1
}

# 查看 SOCKS5 配置信息
view_socks5() {
    clear
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo -e "${gl_kjlan}      查看 SOCKS5 代理信息${gl_bai}"
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo ""
    
    # 检查配置文件是否存在
    if [ ! -f "$SOCKS5_CONFIG_FILE" ]; then
        echo -e "${gl_huang}⚠️  未检测到 SOCKS5 代理配置${gl_bai}"
        echo ""
        echo "您可以选择菜单 [1] 新增 SOCKS5 代理"
        echo ""
        break_end
        return 1
    fi
    
    # 解析配置文件
    local port=$(jq -r '.inbounds[0].listen_port // empty' "$SOCKS5_CONFIG_FILE" 2>/dev/null)
    local username=$(jq -r '.inbounds[0].users[0].username // empty' "$SOCKS5_CONFIG_FILE" 2>/dev/null)
    local password=$(jq -r '.inbounds[0].users[0].password // empty' "$SOCKS5_CONFIG_FILE" 2>/dev/null)
    
    if [ -z "$port" ] || [ -z "$username" ]; then
        echo -e "${gl_hong}❌ 配置文件格式错误或为空${gl_bai}"
        echo ""
        echo "配置文件路径: $SOCKS5_CONFIG_FILE"
        echo ""
        break_end
        return 1
    fi
    
    # 获取服务器IP（带格式验证）
    local listen_addr=$(jq -r '.inbounds[0].listen // "0.0.0.0"' "$SOCKS5_CONFIG_FILE" 2>/dev/null)
    local server_ip=""
    if [ "$listen_addr" = "::" ]; then
        server_ip=$(get_server_ip "ipv6")
    else
        server_ip=$(get_server_ip "auto")
    fi
    
    # 检查服务状态
    local service_status=""
    if systemctl is-active --quiet "$SOCKS5_SERVICE_NAME"; then
        service_status="${gl_lv}✅ 运行中${gl_bai}"
    else
        service_status="${gl_hong}❌ 未运行${gl_bai}"
    fi
    
    # 检查端口监听
    local port_status=""
    if ss -tulpn | grep -q ":${port} "; then
        port_status="${gl_lv}✅ 监听中${gl_bai}"
    else
        port_status="${gl_hong}❌ 未监听${gl_bai}"
    fi
    
    echo -e "${gl_lv}SOCKS5 连接信息：${gl_bai}"
    echo ""
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo -e "  服务器地址: ${gl_huang}${server_ip}${gl_bai}"
    echo -e "  端口:       ${gl_huang}${port}${gl_bai}"
    echo -e "  用户名:     ${gl_huang}${username}${gl_bai}"
    echo -e "  密码:       ${gl_huang}${password}${gl_bai}"
    echo -e "  协议:       ${gl_huang}SOCKS5${gl_bai}"
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo ""
    echo -e "  服务状态:   $service_status"
    echo -e "  端口状态:   $port_status"
    echo ""
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo ""
    echo -e "${gl_lv}快捷复制（代理URL）：${gl_bai}"
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo ""
    echo "socks5://${username}:${password}@${server_ip}:${port}"
    echo ""
    echo "socks5h://${username}:${password}@${server_ip}:${port}"
    echo ""
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo ""
    echo -e "${gl_zi}测试连接命令：${gl_bai}"
    echo "curl --socks5-hostname ${username}:${password}@${server_ip}:${port} http://httpbin.org/ip"
    echo ""
    echo -e "${gl_zi}管理命令：${gl_bai}"
    echo "  查看日志: journalctl -u ${SOCKS5_SERVICE_NAME} -f"
    echo "  重启服务: systemctl restart ${SOCKS5_SERVICE_NAME}"
    echo "  停止服务: systemctl stop ${SOCKS5_SERVICE_NAME}"
    echo ""

    break_end
}

# 修改 SOCKS5 配置
modify_socks5() {
    clear
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo -e "${gl_kjlan}      修改 SOCKS5 代理配置${gl_bai}"
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo ""
    
    # 检查配置文件是否存在
    if [ ! -f "$SOCKS5_CONFIG_FILE" ]; then
        echo -e "${gl_huang}⚠️  未检测到 SOCKS5 代理配置${gl_bai}"
        echo ""
        echo "您可以选择菜单 [1] 新增 SOCKS5 代理"
        echo ""
        break_end
        return 1
    fi
    
    # 读取当前配置
    local current_port=$(jq -r '.inbounds[0].listen_port // empty' "$SOCKS5_CONFIG_FILE" 2>/dev/null)
    local current_user=$(jq -r '.inbounds[0].users[0].username // empty' "$SOCKS5_CONFIG_FILE" 2>/dev/null)
    local current_pass=$(jq -r '.inbounds[0].users[0].password // empty' "$SOCKS5_CONFIG_FILE" 2>/dev/null)
    
    echo -e "${gl_zi}当前配置：${gl_bai}"
    echo "  端口: ${current_port}"
    echo "  用户名: ${current_user}"
    echo "  密码: ${current_pass}"
    echo ""
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo ""
    echo "请选择要修改的项目："
    echo ""
    echo "  1. 修改端口"
    echo "  2. 修改用户名"
    echo "  3. 修改密码"
    echo "  4. 修改所有配置"
    echo ""
    echo "  0. 返回上级菜单"
    echo ""
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    
    read -e -p "请输入选项 [0-4]: " modify_choice
    
    local new_port="$current_port"
    local new_user="$current_user"
    local new_pass="$current_pass"
    
    case "$modify_choice" in
        1)
            echo ""
            while true; do
                read -e -p "$(echo -e "${gl_huang}请输入新端口 [当前: ${current_port}]: ${gl_bai}")" new_port
                new_port=${new_port:-$current_port}
                
                if [[ "$new_port" =~ ^[0-9]+$ ]] && [ "$new_port" -ge 1024 ] && [ "$new_port" -le 65535 ]; then
                    if [ "$new_port" != "$current_port" ] && ss -tulpn | grep -q ":${new_port} "; then
                        echo -e "${gl_hong}❌ 端口 ${new_port} 已被占用${gl_bai}"
                    else
                        break
                    fi
                else
                    echo -e "${gl_hong}❌ 无效端口，请输入 1024-65535 之间的数字${gl_bai}"
                fi
            done
            ;;
        2)
            echo ""
            while true; do
                read -e -p "$(echo -e "${gl_huang}请输入新用户名 [当前: ${current_user}]: ${gl_bai}")" new_user
                new_user=${new_user:-$current_user}
                
                if [[ "$new_user" =~ ^[a-zA-Z0-9_-]+$ ]]; then
                    break
                else
                    echo -e "${gl_hong}❌ 用户名只能包含字母、数字、下划线和连字符${gl_bai}"
                fi
            done
            ;;
        3)
            echo ""
            while true; do
                read -e -p "$(echo -e "${gl_huang}请输入新密码: ${gl_bai}")" new_pass
                
                if [ -z "$new_pass" ]; then
                    new_pass="$current_pass"
                    break
                elif [ ${#new_pass} -lt 6 ]; then
                    echo -e "${gl_hong}❌ 密码长度至少6位${gl_bai}"
                elif [[ "$new_pass" == *\"* || "$new_pass" == *\\* ]]; then
                    echo -e "${gl_hong}❌ 密码不能包含 \" 或 \\ 字符${gl_bai}"
                else
                    break
                fi
            done
            ;;
        4)
            echo ""
            # 修改端口
            while true; do
                read -e -p "$(echo -e "${gl_huang}请输入新端口 [当前: ${current_port}, 回车保持不变]: ${gl_bai}")" new_port
                new_port=${new_port:-$current_port}
                
                if [[ "$new_port" =~ ^[0-9]+$ ]] && [ "$new_port" -ge 1024 ] && [ "$new_port" -le 65535 ]; then
                    if [ "$new_port" != "$current_port" ] && ss -tulpn | grep -q ":${new_port} "; then
                        echo -e "${gl_hong}❌ 端口 ${new_port} 已被占用${gl_bai}"
                    else
                        break
                    fi
                else
                    echo -e "${gl_hong}❌ 无效端口，请输入 1024-65535 之间的数字${gl_bai}"
                fi
            done
            echo ""
            
            # 修改用户名
            while true; do
                read -e -p "$(echo -e "${gl_huang}请输入新用户名 [当前: ${current_user}, 回车保持不变]: ${gl_bai}")" new_user
                new_user=${new_user:-$current_user}
                
                if [[ "$new_user" =~ ^[a-zA-Z0-9_-]+$ ]]; then
                    break
                else
                    echo -e "${gl_hong}❌ 用户名只能包含字母、数字、下划线和连字符${gl_bai}"
                fi
            done
            echo ""
            
            # 修改密码
            while true; do
                read -e -p "$(echo -e "${gl_huang}请输入新密码 [回车保持不变]: ${gl_bai}")" new_pass
                
                if [ -z "$new_pass" ]; then
                    new_pass="$current_pass"
                    break
                elif [ ${#new_pass} -lt 6 ]; then
                    echo -e "${gl_hong}❌ 密码长度至少6位${gl_bai}"
                elif [[ "$new_pass" == *\"* || "$new_pass" == *\\* ]]; then
                    echo -e "${gl_hong}❌ 密码不能包含 \" 或 \\ 字符${gl_bai}"
                else
                    break
                fi
            done
            ;;
        0)
            return 0
            ;;
        *)
            echo -e "${gl_hong}❌ 无效选项${gl_bai}"
            sleep 1
            return 1
            ;;
    esac
    
    # 确认修改
    echo ""
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo -e "${gl_lv}修改后的配置：${gl_bai}"
    echo "  端口: ${new_port}"
    echo "  用户名: ${new_user}"
    echo "  密码: ${new_pass}"
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo ""
    
    read -e -p "$(echo -e "${gl_huang}确认修改？(Y/N): ${gl_bai}")" confirm
    
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        echo "已取消修改"
        break_end
        return 0
    fi
    
    # 检测 sing-box 二进制程序（使用公共函数）
    if ! detect_singbox_cmd; then
        echo -e "${gl_hong}❌ 未找到 sing-box 程序${gl_bai}"
        break_end
        return 1
    fi
    local SINGBOX_CMD="$DETECTED_SINGBOX_CMD"

    # 读取现有的 listen 地址（保留用户之前的 IPv4/IPv6 选择）
    local current_listen=$(jq -r '.inbounds[0].listen // "0.0.0.0"' "$SOCKS5_CONFIG_FILE" 2>/dev/null)

    # 更新配置文件
    echo ""
    echo -e "${gl_zi}正在更新配置...${gl_bai}"

    cat > "$SOCKS5_CONFIG_FILE" << CONFIGEOF
{
  "log": {
    "level": "info",
    "output": "${SOCKS5_CONFIG_DIR}/socks5.log"
  },
  "inbounds": [
    {
      "type": "socks",
      "tag": "socks5-in",
      "listen": "${current_listen}",
      "listen_port": ${new_port},
      "users": [
        {
          "username": "${new_user}",
          "password": "${new_pass}"
        }
      ]
    }
  ],
  "outbounds": [
    {
      "type": "direct",
      "tag": "direct"
    }
  ]
}
CONFIGEOF
    
    chmod 600 "$SOCKS5_CONFIG_FILE"
    
    # 验证配置
    if ! $SINGBOX_CMD check -c "$SOCKS5_CONFIG_FILE" >/dev/null 2>&1; then
        echo -e "${gl_hong}❌ 配置文件语法错误${gl_bai}"
        $SINGBOX_CMD check -c "$SOCKS5_CONFIG_FILE"
        break_end
        return 1
    fi
    
    # 更新 systemd 服务文件（如果端口改变需要更新）
    cat > /etc/systemd/system/${SOCKS5_SERVICE_NAME}.service << SERVICEEOF
[Unit]
Description=Sing-box SOCKS5 Service
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${SINGBOX_CMD} run -c ${SOCKS5_CONFIG_FILE}
ExecReload=/bin/kill -HUP \$MAINPID
Restart=always
RestartSec=5
User=root
Group=root
StandardOutput=journal
StandardError=journal
SyslogIdentifier=${SOCKS5_SERVICE_NAME}
KillMode=mixed
KillSignal=SIGTERM
TimeoutStopSec=5s
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=${SOCKS5_CONFIG_DIR}
PrivateTmp=true

[Install]
WantedBy=multi-user.target
SERVICEEOF
    
    # 重新加载并重启服务
    systemctl daemon-reload
    systemctl restart "$SOCKS5_SERVICE_NAME"
    
    sleep 2
    
    # 验证服务状态
    if systemctl is-active --quiet "$SOCKS5_SERVICE_NAME"; then
        echo -e "${gl_lv}✅ 配置修改成功，服务已重启${gl_bai}"
    else
        echo -e "${gl_hong}❌ 服务重启失败，请检查日志${gl_bai}"
        echo "journalctl -u ${SOCKS5_SERVICE_NAME} -n 20 --no-pager"
    fi
    
    echo ""
    break_end
}

# 删除 SOCKS5 配置
delete_socks5() {
    clear
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo -e "${gl_kjlan}      删除 SOCKS5 代理${gl_bai}"
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo ""
    
    # 检查是否存在配置
    local has_config=false
    local has_service=false
    
    if [ -f "$SOCKS5_CONFIG_FILE" ] || [ -d "$SOCKS5_CONFIG_DIR" ]; then
        has_config=true
    fi
    
    if [ -f "/etc/systemd/system/${SOCKS5_SERVICE_NAME}.service" ]; then
        has_service=true
    fi
    
    if [ "$has_config" = false ] && [ "$has_service" = false ]; then
        echo -e "${gl_huang}⚠️  未检测到 SOCKS5 代理配置${gl_bai}"
        echo ""
        break_end
        return 0
    fi
    
    # 显示即将删除的内容
    echo -e "${gl_huang}即将删除以下内容：${gl_bai}"
    echo ""
    
    if [ "$has_service" = true ]; then
        echo "  • 系统服务: ${SOCKS5_SERVICE_NAME}"
        if systemctl is-active --quiet "$SOCKS5_SERVICE_NAME"; then
            echo "    状态: 运行中（将被停止）"
        else
            echo "    状态: 未运行"
        fi
    fi
    
    if [ "$has_config" = true ]; then
        echo "  • 配置目录: ${SOCKS5_CONFIG_DIR}"
        if [ -f "$SOCKS5_CONFIG_FILE" ]; then
            local port=$(jq -r '.inbounds[0].listen_port // "未知"' "$SOCKS5_CONFIG_FILE" 2>/dev/null)
            echo "    端口: ${port}"
        fi
    fi
    
    echo ""
    echo -e "${gl_hong}⚠️  此操作不可恢复！${gl_bai}"
    echo ""
    
    read -e -p "$(echo -e "${gl_huang}确认删除？请输入 'yes' 确认: ${gl_bai}")" confirm
    
    if [ "$confirm" != "yes" ]; then
        echo ""
        echo "已取消删除"
        break_end
        return 0
    fi
    
    echo ""
    echo -e "${gl_zi}正在删除...${gl_bai}"
    
    # 停止并禁用服务
    if [ "$has_service" = true ]; then
        systemctl stop "$SOCKS5_SERVICE_NAME" 2>/dev/null
        systemctl disable "$SOCKS5_SERVICE_NAME" 2>/dev/null
        rm -f "/etc/systemd/system/${SOCKS5_SERVICE_NAME}.service"
        systemctl daemon-reload
        echo -e "${gl_lv}✅ 服务已删除${gl_bai}"
    fi
    
    # 删除配置目录
    if [ "$has_config" = true ]; then
        rm -rf "$SOCKS5_CONFIG_DIR"
        echo -e "${gl_lv}✅ 配置目录已删除${gl_bai}"
    fi
    
    echo ""
    echo -e "${gl_lv}🎉 SOCKS5 代理已完全删除${gl_bai}"
    echo ""
    
    break_end
}

# SOCKS5 管理主菜单
manage_socks5() {
    while true; do
        clear
        echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
        echo -e "${gl_kjlan}      Sing-box SOCKS5 管理${gl_bai}"
        echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
        echo ""
        
        # 检查当前状态
        if [ -f "$SOCKS5_CONFIG_FILE" ]; then
            local port=$(jq -r '.inbounds[0].listen_port // "未知"' "$SOCKS5_CONFIG_FILE" 2>/dev/null)
            local user=$(jq -r '.inbounds[0].users[0].username // "未知"' "$SOCKS5_CONFIG_FILE" 2>/dev/null)
            
            if systemctl is-active --quiet "$SOCKS5_SERVICE_NAME"; then
                echo -e "  当前状态: ${gl_lv}✅ 运行中${gl_bai}"
            else
                echo -e "  当前状态: ${gl_hong}❌ 未运行${gl_bai}"
            fi
            echo -e "  端口: ${gl_huang}${port}${gl_bai}  用户名: ${gl_huang}${user}${gl_bai}"
        else
            echo -e "  当前状态: ${gl_zi}未部署${gl_bai}"
        fi
        
        echo ""
        echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
        echo ""
        echo "  1. 新增 SOCKS5 代理"
        echo "  2. 修改 SOCKS5 配置"
        echo "  3. 删除 SOCKS5 代理"
        echo "  4. 查看 SOCKS5 信息"
        echo ""
        echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
        echo "  0. 返回主菜单"
        echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
        echo ""
        
        read -e -p "请输入选项 [0-4]: " socks5_choice
        
        case "$socks5_choice" in
            1)
                # 检查是否已存在配置
                if [ -f "$SOCKS5_CONFIG_FILE" ]; then
                    echo ""
                    echo -e "${gl_huang}⚠️  检测到已存在 SOCKS5 配置${gl_bai}"
                    echo ""
                    read -e -p "$(echo -e "${gl_huang}是否覆盖现有配置？(Y/N): ${gl_bai}")" overwrite
                    if [[ ! "$overwrite" =~ ^[Yy]$ ]]; then
                        echo "已取消"
                        sleep 1
                        continue
                    fi
                fi
                deploy_socks5
                ;;
            2)
                modify_socks5
                ;;
            3)
                delete_socks5
                ;;
            4)
                view_socks5
                ;;
            0)
                return 0
                ;;
            *)
                echo -e "${gl_hong}❌ 无效选项${gl_bai}"
                sleep 1
                ;;
        esac
    done
}

install_singbox_binary() {
    clear
    echo -e "${gl_kjlan}=== 自动安装 Sing-box 核心程序 ===${gl_bai}"
    echo ""
    echo "检测到系统未安装 sing-box"
    echo ""
    echo -e "${gl_huang}安装说明：${gl_bai}"
    echo "  • 仅下载 sing-box 官方二进制程序"
    echo "  • 不安装任何协议配置（纯净安装）"
    echo "  • 安装后可用于 SOCKS5 代理部署"
    echo "  • 如需完整功能，可稍后通过菜单 36 安装"
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    
    read -e -p "$(echo -e "${gl_huang}是否继续安装？(Y/N): ${gl_bai}")" confirm
    
    case "$confirm" in
        [Yy])
            echo ""
            echo -e "${gl_lv}开始下载 Sing-box...${gl_bai}"
            echo ""
            
            # 步骤1：检测系统架构
            local arch=""
            case "$(uname -m)" in
                aarch64|arm64)
                    arch="arm64"
                    ;;
                x86_64|amd64)
                    arch="amd64"
                    ;;
                armv7l)
                    arch="armv7"
                    ;;
                *)
                    echo -e "${gl_hong}❌ 不支持的系统架构: $(uname -m)${gl_bai}"
                    echo ""
                    echo "支持的架构：amd64, arm64, armv7"
                    echo ""
                    break_end
                    return 1
                    ;;
            esac
            
            echo -e "${gl_zi}[1/5] 检测架构: ${arch}${gl_bai}"
            echo ""
            
            # 步骤2：获取最新版本
            echo -e "${gl_zi}[2/5] 获取最新版本...${gl_bai}"
            
            local version=""
            local gh_api_url="https://api.github.com/repos/SagerNet/sing-box/releases"
            
            # 尝试从 GitHub API 获取最新稳定版本（过滤掉 alpha/beta/rc）
            version=$(wget --timeout=10 --tries=2 -qO- "$gh_api_url" 2>/dev/null | \
                      grep '"tag_name"' | \
                      sed -E 's/.*"tag_name":[[:space:]]*"v([^"]+)".*/\1/' | \
                      grep -v -E '(alpha|beta|rc)' | \
                      sort -Vr | head -1)
            
            # 如果 API 失败，使用默认版本
            if [ -z "$version" ]; then
                version="1.10.0"
                echo -e "${gl_huang}  ⚠️  API 获取失败，使用默认版本: v${version}${gl_bai}"
            else
                echo -e "${gl_lv}  ✓ 最新版本: v${version}${gl_bai}"
            fi
            echo ""
            
            # 步骤3：下载并解压
            echo -e "${gl_zi}[3/5] 下载 sing-box v${version} (${arch})...${gl_bai}"
            
            local download_url="https://github.com/SagerNet/sing-box/releases/download/v${version}/sing-box-${version}-linux-${arch}.tar.gz"
            local temp_dir="/tmp/singbox-install-$$"
            
            mkdir -p "$temp_dir"
            
            if ! wget --timeout=30 --tries=3 -qO "${temp_dir}/sing-box.tar.gz" "$download_url" 2>/dev/null; then
                echo -e "${gl_hong}  ✗ 下载失败${gl_bai}"
                echo ""
                echo "可能的原因："
                echo "  1. 网络连接问题"
                echo "  2. GitHub 访问受限"
                echo "  3. 版本 v${version} 不存在"
                echo ""
                echo "建议："
                echo "  • 检查网络连接"
                echo "  • 配置代理后重试"
                echo "  • 手动执行菜单 36 使用 F 佬脚本安装"
                echo ""
                rm -rf "$temp_dir"
                break_end
                return 1
            fi
            
            echo -e "${gl_lv}  ✓ 下载完成${gl_bai}"
            echo ""
            
            # 步骤4：解压并安装
            echo -e "${gl_zi}[4/5] 解压并安装...${gl_bai}"
            
            if ! tar -xzf "${temp_dir}/sing-box.tar.gz" -C "$temp_dir" 2>/dev/null; then
                echo -e "${gl_hong}  ✗ 解压失败${gl_bai}"
                rm -rf "$temp_dir"
                break_end
                return 1
            fi
            
            # 创建安装目录
            mkdir -p /etc/sing-box
            
            # 查找并移动二进制文件（兼容不同版本的目录结构）
            # 注意：不使用 -executable 参数，因为解压后的文件可能还没有执行权限
            local binary_path=$(find "$temp_dir" -name "sing-box" -type f 2>/dev/null | head -1)
            
            if [ -n "$binary_path" ] && [ -f "$binary_path" ]; then
                mv "$binary_path" /etc/sing-box/sing-box
                chmod +x /etc/sing-box/sing-box
                echo -e "${gl_lv}  ✓ 安装完成${gl_bai}"
            else
                echo -e "${gl_hong}  ✗ 未找到 sing-box 二进制文件${gl_bai}"
                echo ""
                echo "调试信息："
                echo "临时目录内容："
                ls -R "$temp_dir" 2>/dev/null || echo "无法列出目录"
                echo ""
                rm -rf "$temp_dir"
                break_end
                return 1
            fi
            
            # 清理临时文件
            rm -rf "$temp_dir"
            echo ""
            
            # 步骤5：验证安装
            echo -e "${gl_zi}[5/5] 验证安装...${gl_bai}"
            
            if /etc/sing-box/sing-box version >/dev/null 2>&1; then
                local installed_version=$(/etc/sing-box/sing-box version 2>/dev/null | head -1)
                echo -e "${gl_lv}  ✓ ${installed_version}${gl_bai}"
                echo ""
                echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                echo -e "${gl_lv}✅ Sing-box 核心程序安装成功！${gl_bai}"
                echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                echo ""
                echo -e "${gl_zi}提示：${gl_bai}"
                echo "  • 二进制位置: /etc/sing-box/sing-box"
                echo "  • 这是纯净安装，未配置任何协议"
                echo "  • 可继续部署 SOCKS5 代理"
                echo "  • 如需完整功能，可执行菜单 36 安装协议配置"
                echo ""
                return 0
            else
                echo -e "${gl_hong}  ✗ 验证失败${gl_bai}"
                echo ""
                break_end
                return 1
            fi
            ;;
        *)
            echo ""
            echo "已取消安装"
            echo ""
            echo "您可以："
            echo "  • 稍后通过菜单 36 使用 F 佬脚本安装（含完整协议配置）"
            echo "  • 自行安装 sing-box 到 /etc/sing-box/sing-box"
            echo ""
            break_end
            return 1
            ;;
    esac
}

deploy_socks5() {
    clear
    echo -e "${gl_kjlan}=== Sing-box SOCKS5 一键部署 ===${gl_bai}"
    echo ""
    echo "此功能将部署一个独立的SOCKS5代理服务"
    echo "------------------------------------------------"
    echo ""

    # 步骤1：检测 sing-box 二进制程序（使用公共函数）
    echo -e "${gl_zi}[步骤 1/7] 检测 sing-box 安装...${gl_bai}"
    echo ""

    local SINGBOX_CMD=""

    if detect_singbox_cmd "verbose"; then
        SINGBOX_CMD="$DETECTED_SINGBOX_CMD"
    else
        # 调用纯净安装函数（仅二进制）
        if install_singbox_binary; then
            # 安装成功，重新检测
            echo ""
            echo -e "${gl_zi}重新检测 sing-box...${gl_bai}"
            echo ""

            if detect_singbox_cmd "verbose"; then
                SINGBOX_CMD="$DETECTED_SINGBOX_CMD"
            else
                echo -e "${gl_hong}❌ 安装后仍未找到 sing-box${gl_bai}"
                echo ""
                echo "请手动检查："
                echo "  ls -lh /etc/sing-box/sing-box"
                echo ""
                break_end
                return 1
            fi
        else
            # 用户取消或安装失败
            return 1
        fi
    fi

    # 显示版本信息
    echo ""
    $SINGBOX_CMD version 2>/dev/null | head -n 1
    echo ""

    # 步骤2：配置参数输入
    echo -e "${gl_zi}[步骤 2/7] 配置 SOCKS5 参数...${gl_bai}"
    echo ""

    # 选择监听模式（IPv4 / IPv6）
    local listen_addr=""
    echo -e "${gl_huang}请选择监听模式：${gl_bai}"
    echo "  1. IPv4 only (0.0.0.0)  — 适用于有 IPv4 地址的服务器（默认）"
    echo "  2. IPv6 only (::)       — 适用于纯 IPv6 服务器"
    echo ""
    read -e -p "$(echo -e "${gl_huang}请输入选项 [1/2，回车默认1]: ${gl_bai}")" listen_choice

    case "$listen_choice" in
        2)
            listen_addr="::"
            echo -e "${gl_lv}✅ 监听模式: IPv6 only (::)${gl_bai}"
            ;;
        *)
            listen_addr="0.0.0.0"
            echo -e "${gl_lv}✅ 监听模式: IPv4 only (0.0.0.0)${gl_bai}"
            ;;
    esac

    echo ""

    # 输入端口（支持回车使用随机端口）
    local socks5_port=""
    while true; do
        read -e -p "$(echo -e "${gl_huang}请输入 SOCKS5 端口 [回车随机生成]: ${gl_bai}")" socks5_port

        if [ -z "$socks5_port" ]; then
            # 生成随机端口（10000-65535）
            socks5_port=$(( ((RANDOM<<15) | RANDOM) % 55536 + 10000 ))
            echo -e "${gl_lv}✅ 已生成随机端口: ${socks5_port}${gl_bai}"
            break
        elif [[ "$socks5_port" =~ ^[0-9]+$ ]] && [ "$socks5_port" -ge 1024 ] && [ "$socks5_port" -le 65535 ]; then
            # 检查端口是否被占用
            if ss -tulpn | grep -q ":${socks5_port} "; then
                echo -e "${gl_hong}❌ 端口 ${socks5_port} 已被占用，请选择其他端口${gl_bai}"
            else
                echo -e "${gl_lv}✅ 使用端口: ${socks5_port}${gl_bai}"
                break
            fi
        else
            echo -e "${gl_hong}❌ 无效端口，请输入 1024-65535 之间的数字${gl_bai}"
        fi
    done

    echo ""

    # 输入用户名
    local socks5_user=""
    while true; do
        read -e -p "$(echo -e "${gl_huang}请输入用户名: ${gl_bai}")" socks5_user

        if [ -z "$socks5_user" ]; then
            echo -e "${gl_hong}❌ 用户名不能为空${gl_bai}"
        elif [[ "$socks5_user" =~ ^[a-zA-Z0-9_-]+$ ]]; then
            echo -e "${gl_lv}✅ 用户名: ${socks5_user}${gl_bai}"
            break
        else
            echo -e "${gl_hong}❌ 用户名只能包含字母、数字、下划线和连字符${gl_bai}"
        fi
    done

    echo ""

    # 输入密码
    local socks5_pass=""
    while true; do
        read -e -p "$(echo -e "${gl_huang}请输入密码: ${gl_bai}")" socks5_pass

        if [ -z "$socks5_pass" ]; then
            echo -e "${gl_hong}❌ 密码不能为空${gl_bai}"
        elif [ ${#socks5_pass} -lt 6 ]; then
            echo -e "${gl_hong}❌ 密码长度至少6位${gl_bai}"
        elif [[ "$socks5_pass" == *\"* || "$socks5_pass" == *\\* ]]; then
            echo -e "${gl_hong}❌ 密码不能包含 \" 或 \\ 字符${gl_bai}"
        else
            echo -e "${gl_lv}✅ 密码已设置${gl_bai}"
            break
        fi
    done

    echo ""
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo -e "${gl_lv}配置信息确认：${gl_bai}"
    echo -e "  监听地址: ${gl_huang}${listen_addr}${gl_bai}"
    echo -e "  端口: ${gl_huang}${socks5_port}${gl_bai}"
    echo -e "  用户名: ${gl_huang}${socks5_user}${gl_bai}"
    echo -e "  密码: ${gl_huang}${socks5_pass}${gl_bai}"
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo ""

    read -e -p "$(echo -e "${gl_huang}确认开始部署？(Y/N): ${gl_bai}")" confirm

    case "$confirm" in
        [Yy])
            ;;
        *)
            echo "已取消部署"
            break_end
            return 1
            ;;
    esac

    # 步骤3：创建目录
    echo ""
    echo -e "${gl_zi}[步骤 3/7] 创建配置目录...${gl_bai}"
    mkdir -p "$SOCKS5_CONFIG_DIR"
    echo -e "${gl_lv}✅ 目录创建成功${gl_bai}"

    # 步骤4：创建配置文件
    echo ""
    echo -e "${gl_zi}[步骤 4/7] 创建配置文件...${gl_bai}"

    cat > "$SOCKS5_CONFIG_FILE" << CONFIGEOF
{
  "log": {
    "level": "info",
    "output": "${SOCKS5_CONFIG_DIR}/socks5.log"
  },
  "inbounds": [
    {
      "type": "socks",
      "tag": "socks5-in",
      "listen": "${listen_addr}",
      "listen_port": ${socks5_port},
      "users": [
        {
          "username": "${socks5_user}",
          "password": "${socks5_pass}"
        }
      ]
    }
  ],
  "outbounds": [
    {
      "type": "direct",
      "tag": "direct"
    }
  ]
}
CONFIGEOF

    chmod 600 "$SOCKS5_CONFIG_FILE"
    echo -e "${gl_lv}✅ 配置文件创建成功${gl_bai}"

    # 步骤5：验证配置
    echo ""
    echo -e "${gl_zi}[步骤 5/7] 验证配置文件语法...${gl_bai}"

    if $SINGBOX_CMD check -c "$SOCKS5_CONFIG_FILE" >/dev/null 2>&1; then
        echo -e "${gl_lv}✅ 配置文件语法正确${gl_bai}"
    else
        echo -e "${gl_hong}❌ 配置文件语法错误${gl_bai}"
        $SINGBOX_CMD check -c "$SOCKS5_CONFIG_FILE"
        break_end
        return 1
    fi

    # 步骤6：创建服务文件
    echo ""
    echo -e "${gl_zi}[步骤 6/7] 创建 systemd 服务...${gl_bai}"

    cat > /etc/systemd/system/${SOCKS5_SERVICE_NAME}.service << SERVICEEOF
[Unit]
Description=Sing-box SOCKS5 Service
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${SINGBOX_CMD} run -c ${SOCKS5_CONFIG_FILE}
ExecReload=/bin/kill -HUP \$MAINPID
Restart=always
RestartSec=5
User=root
Group=root
StandardOutput=journal
StandardError=journal
SyslogIdentifier=${SOCKS5_SERVICE_NAME}
KillMode=mixed
KillSignal=SIGTERM
TimeoutStopSec=5s
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=${SOCKS5_CONFIG_DIR}
PrivateTmp=true

[Install]
WantedBy=multi-user.target
SERVICEEOF

    chmod 644 /etc/systemd/system/${SOCKS5_SERVICE_NAME}.service
    echo -e "${gl_lv}✅ 服务文件创建成功${gl_bai}"

    # 步骤7：启动服务
    echo ""
    echo -e "${gl_zi}[步骤 7/7] 启动服务...${gl_bai}"

    systemctl daemon-reload
    systemctl enable "$SOCKS5_SERVICE_NAME" >/dev/null 2>&1
    systemctl reset-failed "$SOCKS5_SERVICE_NAME" >/dev/null 2>&1

    local systemctl_action="start"
    if systemctl is-active --quiet "$SOCKS5_SERVICE_NAME"; then
        systemctl_action="restart"
    fi

    if ! systemctl "$systemctl_action" "$SOCKS5_SERVICE_NAME" >/dev/null 2>&1; then
        echo -e "${gl_hong}❌ 服务 ${systemctl_action} 命令执行失败，请查看日志${gl_bai}"
    fi

    # 等待服务启动
    sleep 3

    # 验证部署
    echo ""
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo -e "${gl_lv}验证部署结果：${gl_bai}"
    echo ""

    local deploy_success=true

    # 检查服务状态
    if systemctl is-active --quiet "$SOCKS5_SERVICE_NAME"; then
        echo -e "  服务状态: ${gl_lv}✅ Running${gl_bai}"
    else
        echo -e "  服务状态: ${gl_hong}❌ Failed${gl_bai}"
        deploy_success=false
    fi

    # 检查端口监听
    if ss -tulpn | grep -q ":${socks5_port} "; then
        echo -e "  端口监听: ${gl_lv}✅ ${socks5_port}${gl_bai}"
    else
        echo -e "  端口监听: ${gl_hong}❌ 未监听${gl_bai}"
        deploy_success=false
    fi

    echo ""
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"

    if [ "$deploy_success" = true ]; then
        # 根据监听模式获取服务器IP（带格式验证）
        local server_ip=""
        if [ "$listen_addr" = "::" ]; then
            server_ip=$(get_server_ip "ipv6")
        else
            server_ip=$(get_server_ip "auto")
        fi

        echo ""
        echo -e "${gl_lv}🎉 部署成功！${gl_bai}"
        echo ""
        echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
        echo -e "${gl_lv}SOCKS5 连接信息：${gl_bai}"
        echo ""
        echo -e "  服务器地址: ${gl_huang}${server_ip}${gl_bai}"
        echo -e "  端口:       ${gl_huang}${socks5_port}${gl_bai}"
        echo -e "  用户名:     ${gl_huang}${socks5_user}${gl_bai}"
        echo -e "  密码:       ${gl_huang}${socks5_pass}${gl_bai}"
        echo -e "  协议:       ${gl_huang}SOCKS5${gl_bai}"
        echo -e "  监听模式:   ${gl_huang}${listen_addr}${gl_bai}"
        echo ""
        echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
        echo ""
        echo -e "${gl_zi}测试连接命令：${gl_bai}"
        echo "curl --socks5-hostname ${socks5_user}:${socks5_pass}@${server_ip}:${socks5_port} http://httpbin.org/ip"
        echo ""
        echo -e "${gl_huang}⚠️  重要提醒：${gl_bai}"
        echo "  1. 确保云服务商安全组已开放 TCP ${socks5_port} 端口"
        echo "  2. 查看日志: journalctl -u ${SOCKS5_SERVICE_NAME} -f"
        echo "  3. 重启服务: systemctl restart ${SOCKS5_SERVICE_NAME}"
        echo "  4. 停止服务: systemctl stop ${SOCKS5_SERVICE_NAME}"
        echo "  5. 卸载服务: systemctl stop ${SOCKS5_SERVICE_NAME} && systemctl disable ${SOCKS5_SERVICE_NAME} && rm -rf ${SOCKS5_CONFIG_DIR} /etc/systemd/system/${SOCKS5_SERVICE_NAME}.service"
        echo ""
    else
        echo ""
        echo -e "${gl_hong}❌ 部署失败${gl_bai}"
        echo ""
        echo "查看详细错误信息："
        echo "  journalctl -u ${SOCKS5_SERVICE_NAME} -n 50 --no-pager"
        echo ""
        echo "常见问题排查："
        echo "  1. 检查 sing-box 程序是否正确: file ${SINGBOX_CMD}"
        echo "  2. 检查端口是否被占用: ss -tulpn | grep ${socks5_port}"
        echo "  3. 检查服务日志: systemctl status ${SOCKS5_SERVICE_NAME} --no-pager"
        echo ""
    fi

    break_end
}
#=============================================================================
# Sub-Store 多实例管理功能
#=============================================================================

# 检查端口是否被占用
check_substore_port() {
    local port=$1
    if netstat -tuln 2>/dev/null | grep -q ":$port "; then
        return 1
    elif ss -tuln 2>/dev/null | grep -q ":$port "; then
        return 1
    fi
    return 0
}

# 验证端口号
validate_substore_port() {
    local port=$1
    if ! [[ "$port" =~ ^[0-9]+$ ]] || [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
        return 1
    fi
    return 0
}

# 验证访问路径
validate_substore_path() {
    local path=$1
    # 只包含字母数字和少数符号
    if [[ ! "$path" =~ ^[a-zA-Z0-9/_-]+$ ]]; then
        return 1
    fi
    return 0
}

# 生成随机路径
generate_substore_random_path() {
    cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 20 | head -n 1
}

# 检查 Docker 是否安装
check_substore_docker() {
    if ! command -v docker &> /dev/null; then
        echo -e "${gl_hong}Docker 未安装${gl_bai}"
        echo ""
        read -e -p "$(echo -e "${gl_huang}是否现在安装 Docker？(Y/N): ${gl_bai}")" install_docker
        
        case "$install_docker" in
            [Yy])
                echo ""
                echo "请选择安装源："
                echo "1. 国内镜像（阿里云）"
                echo "2. 国外官方源"
                read -e -p "请选择 [1]: " mirror_choice
                mirror_choice=${mirror_choice:-1}
                
                case "$mirror_choice" in
                    1)
                        echo "正在使用阿里云镜像安装 Docker..."
                        run_remote_script "https://get.docker.com" bash -s docker --mirror Aliyun
                        ;;
                    2)
                        echo "正在使用官方源安装 Docker..."
                        run_remote_script "https://get.docker.com" bash
                        ;;
                    *)
                        echo "无效选择，使用阿里云镜像..."
                        run_remote_script "https://get.docker.com" bash -s docker --mirror Aliyun
                        ;;
                esac
                
                if [ $? -eq 0 ]; then
                    echo -e "${gl_lv}✅ Docker 安装成功${gl_bai}"
                    systemctl enable docker
                    systemctl start docker
                else
                    echo -e "${gl_hong}❌ Docker 安装失败${gl_bai}"
                    return 1
                fi
                ;;
            *)
                echo "已取消，请先安装 Docker"
                return 1
                ;;
        esac
    fi
    
    if ! command -v docker compose &> /dev/null && ! command -v docker-compose &> /dev/null; then
        echo -e "${gl_huang}Docker Compose 未安装，尝试安装...${gl_bai}"
        # Docker Compose v2 通常随 Docker 一起安装
        if docker compose version &>/dev/null; then
            echo -e "${gl_lv}✅ Docker Compose 已可用${gl_bai}"
        else
            echo -e "${gl_hong}❌ Docker Compose 不可用，请手动安装${gl_bai}"
            return 1
        fi
    fi
    
    return 0
}

# 获取已部署的实例列表
get_substore_instances() {
    local instances=()
    if [ -d "/root/sub-store-configs" ]; then
        for config in /root/sub-store-configs/store-*.yaml; do
            if [ -f "$config" ]; then
                local instance_name=$(basename "$config" .yaml)
                instances+=("$instance_name")
            fi
        done
    fi
    echo "${instances[@]}"
}

# 检查实例是否存在
check_substore_instance_exists() {
    local instance_num=$1
    if [ -f "/root/sub-store-configs/store-$instance_num.yaml" ]; then
        return 0
    fi
    return 1
}

# 安装新实例
install_substore_instance() {
    clear
    echo "=================================="
    echo "    Sub-Store 实例安装向导"
    echo "=================================="
    echo ""
    
    # 检查 Docker
    if ! check_substore_docker; then
        break_end
        return 1
    fi
    
    echo -e "${gl_lv}✅ Docker 环境检查通过${gl_bai}"
    echo ""
    
    # 获取建议的实例编号
    local instances=($(get_substore_instances))
    local suggested_num=1
    if [ ${#instances[@]} -gt 0 ]; then
        echo -e "${gl_huang}已存在 ${#instances[@]} 个实例${gl_bai}"
        suggested_num=$((${#instances[@]} + 1))
    fi
    
    # 输入实例编号
    local instance_num
    while true; do
        read -e -p "请输入实例编号（建议: $suggested_num）: " instance_num
        
        if [ -z "$instance_num" ]; then
            echo -e "${gl_hong}实例编号不能为空${gl_bai}"
            continue
        fi
        
        if ! [[ "$instance_num" =~ ^[0-9]+$ ]]; then
            echo -e "${gl_hong}实例编号必须是数字${gl_bai}"
            continue
        fi
        
        if check_substore_instance_exists "$instance_num"; then
            echo -e "${gl_hong}实例编号 $instance_num 已存在${gl_bai}"
            continue
        fi
        
        break
    done
    
    echo -e "${gl_lv}✅ 实例编号: $instance_num${gl_bai}"
    echo ""
    
    # 输入后端 API 端口
    local api_port
    local default_api_port=3001
    while true; do
        read -e -p "请输入后端 API 端口（回车使用默认 $default_api_port）: " api_port
        
        if [ -z "$api_port" ]; then
            api_port=$default_api_port
            echo -e "${gl_huang}使用默认端口: $api_port${gl_bai}"
        fi
        
        if ! validate_substore_port "$api_port"; then
            echo -e "${gl_hong}端口号无效${gl_bai}"
            continue
        fi
        
        if ! check_substore_port "$api_port"; then
            echo -e "${gl_hong}端口 $api_port 已被占用${gl_bai}"
            continue
        fi
        
        break
    done
    
    echo -e "${gl_lv}✅ 后端 API 端口: $api_port${gl_bai}"
    echo ""
    
    # 输入 HTTP-META 端口
    local http_port
    local default_http_port=9876
    while true; do
        read -e -p "请输入 HTTP-META 端口（回车使用默认 $default_http_port）: " http_port
        
        if [ -z "$http_port" ]; then
            http_port=$default_http_port
            echo -e "${gl_huang}使用默认端口: $http_port${gl_bai}"
        fi
        
        if ! validate_substore_port "$http_port"; then
            echo -e "${gl_hong}端口号无效${gl_bai}"
            continue
        fi
        
        if ! check_substore_port "$http_port"; then
            echo -e "${gl_hong}端口 $http_port 已被占用${gl_bai}"
            continue
        fi
        
        if [ "$http_port" == "$api_port" ]; then
            echo -e "${gl_hong}HTTP-META 端口不能与后端 API 端口相同${gl_bai}"
            continue
        fi
        
        break
    done
    
    echo -e "${gl_lv}✅ HTTP-META 端口: $http_port${gl_bai}"
    echo ""
    
    # 输入访问路径
    local access_path
    while true; do
        local random_path=$(generate_substore_random_path)
        echo -e "${gl_zi}访问路径说明：${gl_bai}"
        echo "  - 路径会自动添加开头的 /"
        echo "  - 建议使用随机路径（更安全）"
        echo "  - 也可使用自定义路径（易记）"
        echo ""
        echo -e "${gl_huang}随机生成的路径: ${random_path}${gl_bai}"
        echo ""
        
        read -e -p "请输入访问路径（直接输入如 my-subs，或回车使用随机）: " access_path
        
        if [ -z "$access_path" ]; then
            access_path="$random_path"
            echo -e "${gl_lv}✅ 使用随机路径: /$access_path${gl_bai}"
        else
            # 移除可能的开头斜杠
            access_path="${access_path#/}"
            
            if ! validate_substore_path "$access_path"; then
                echo -e "${gl_hong}路径格式无效（只能包含字母、数字、-、_、/）${gl_bai}"
                continue
            fi
            
            echo -e "${gl_lv}✅ 使用自定义路径: /$access_path${gl_bai}"
        fi
        
        break
    done
    
    echo ""
    
    # 输入数据存储目录
    local data_dir
    local default_data_dir="/root/data-sub-store-$instance_num"
    
    read -e -p "请输入数据存储目录（回车使用默认 $default_data_dir）: " data_dir
    
    if [ -z "$data_dir" ]; then
        data_dir="$default_data_dir"
        echo -e "${gl_huang}使用默认目录: $data_dir${gl_bai}"
    fi
    
    if [ -d "$data_dir" ]; then
        echo ""
        echo -e "${gl_huang}目录 $data_dir 已存在${gl_bai}"
        local use_existing
        read -e -p "是否使用现有目录？(y/n): " use_existing
        if [[ ! "$use_existing" =~ ^[Yy]$ ]]; then
            echo "请重新运行并选择其他目录"
            break_end
            return 1
        fi
    fi
    
    # 确认信息
    echo ""
    echo "=================================="
    echo "          配置确认"
    echo "=================================="
    echo "实例编号: $instance_num"
    echo "容器名称: sub-store-$instance_num"
    echo "后端 API 端口: $api_port"
    echo "HTTP-META 端口: $http_port"
    echo "访问路径: /$access_path"
    echo "数据目录: $data_dir"
    echo "=================================="
    echo ""
    
    local confirm
    read -e -p "确认开始安装？(y/n): " confirm
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        echo "已取消安装"
        break_end
        return 1
    fi
    
    # 创建配置目录
    mkdir -p /root/sub-store-configs
    
    # 创建数据目录
    echo ""
    echo "正在创建数据目录..."
    mkdir -p "$data_dir"
    
    # 生成配置文件
    local config_file="/root/sub-store-configs/store-$instance_num.yaml"
    echo "正在生成配置文件..."
    
    cat > "$config_file" << EOF
services:
  sub-store-$instance_num:
    image: xream/sub-store:http-meta
    container_name: sub-store-$instance_num
    restart: always
    network_mode: host
    environment:
      SUB_STORE_BACKEND_API_HOST: 127.0.0.1
      SUB_STORE_BACKEND_API_PORT: $api_port
      SUB_STORE_BACKEND_MERGE: true
      SUB_STORE_FRONTEND_BACKEND_PATH: /$access_path
      HOST: 127.0.0.1
    volumes:
      - $data_dir:/opt/app/data
EOF
    
    # 启动容器
    echo "正在启动 Sub-Store 实例..."
    if docker compose -f "$config_file" up -d; then
        echo ""
        echo -e "${gl_lv}=========================================="
        echo "  Sub-Store 实例安装成功！"
        echo "==========================================${gl_bai}"
        echo ""
        echo -e "${gl_zi}实例信息：${gl_bai}"
        echo "  - 实例编号: $instance_num"
        echo "  - 容器名称: sub-store-$instance_num"
        echo "  - 服务端口: $api_port（前后端共用，监听 127.0.0.1）"
        echo "  - 访问路径: /$access_path"
        echo "  - 数据目录: $data_dir"
        echo "  - 配置文件: $config_file"
        echo ""
        echo -e "${gl_huang}⚠️  重要提示：${gl_bai}"
        echo "  此实例仅监听本地 127.0.0.1，无法直接通过IP访问！"
        echo "  必须配置 Cloudflare Tunnel 后才能使用。"
        echo ""
        
        # 生成 Cloudflare Tunnel 配置
        local cf_tunnel_conf="/root/sub-store-cf-tunnel-$instance_num.yaml"
        cat > "$cf_tunnel_conf" << CFEOF
# Cloudflare Tunnel 配置
# 使用说明：
#   1. 安装 cloudflared: 
#      wget https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64
#      chmod +x cloudflared-linux-amd64 && mv cloudflared-linux-amd64 /usr/local/bin/cloudflared
#   2. 登录: cloudflared tunnel login
#   3. 创建隧道: cloudflared tunnel create sub-store-$instance_num
#   4. 修改下面的 tunnel 和 credentials-file
#   5. 配置路由: cloudflared tunnel route dns <TUNNEL_ID> sub.你的域名.com
#   6. 启动: cloudflared tunnel --config $cf_tunnel_conf run

tunnel: <TUNNEL_ID>  # 替换为你的 Tunnel ID
credentials-file: /root/.cloudflared/<TUNNEL_ID>.json  # 替换为你的凭证文件路径

ingress:
  # 后端 API 路由（必须在前面，更具体的规则）
  - hostname: sub.你的域名.com
    path: /$access_path
    service: http://127.0.0.1:$api_port
  
  # 前端页面路由（通配所有其他请求，与后端共用端口）
  - hostname: sub.你的域名.com
    service: http://127.0.0.1:$api_port
  
  # 默认规则（必须）
  - service: http_status:404
CFEOF
        
        echo -e "${gl_kjlan}【Cloudflare Tunnel 配置文件】${gl_bai}"
        echo ""
        echo "  配置模板已生成: $cf_tunnel_conf"
        echo ""
        echo "  接下来将引导你进行自动配置"
        echo ""
        
        echo -e "${gl_zi}常用命令：${gl_bai}"
        echo "  - 查看日志: docker logs sub-store-$instance_num"
        echo "  - 停止服务: docker compose -f $config_file down"
        echo "  - 重启服务: docker compose -f $config_file restart"
        echo ""
        
        # 交互式配置向导
        echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
        echo -e "${gl_huang}📌 接下来需要配置 Cloudflare Tunnel 才能使用${gl_bai}"
        echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
        echo ""
        echo "请选择："
        echo "1. 立即配置 Cloudflare Tunnel（推荐）"
        echo "2. 跳过配置（稍后手动配置）"
        echo ""
        
        local proxy_choice
        read -e -p "请选择 [1-2]: " proxy_choice
        
        case "$proxy_choice" in
            1)
                # Cloudflare Tunnel 配置向导
                configure_cf_tunnel "$instance_num" "$http_port" "$api_port" "$access_path" "$cf_tunnel_conf"
                ;;
            2)
                echo ""
                echo -e "${gl_huang}已跳过配置${gl_bai}"
                echo "稍后可手动配置，配置文件位于："
                echo "  - CF Tunnel: $cf_tunnel_conf"
                echo ""
                ;;
            *)
                echo ""
                echo -e "${gl_huang}无效选择，已跳过配置${gl_bai}"
                ;;
        esac
    else
        echo -e "${gl_hong}启动失败，请检查配置和日志${gl_bai}"
        break_end
        return 1
    fi
    
    break_end
}

# Cloudflare Tunnel 配置向导

# Cloudflare Tunnel 配置向导
configure_cf_tunnel() {
    local instance_num=$1
    local http_port=$2
    local api_port=$3
    local access_path=$4
    local cf_tunnel_conf=$5
    
    clear
    echo -e "${gl_kjlan}=================================="
    echo "  Cloudflare Tunnel 配置向导"
    echo "==================================${gl_bai}"
    echo ""
    
    # 检查 cloudflared 是否安装
    if ! command -v cloudflared &>/dev/null; then
        echo -e "${gl_huang}cloudflared 未安装${gl_bai}"
        echo ""
        read -e -p "是否现在安装 cloudflared？(Y/N): " install_cf
        
        case "$install_cf" in
            [Yy])
                echo ""
                echo "正在下载 cloudflared..."
                
                local cpu_arch=$(uname -m)
                local download_url
                
                case "$cpu_arch" in
                    x86_64)
                        download_url="https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64"
                        ;;
                    aarch64)
                        download_url="https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-arm64"
                        ;;
                    *)
                        echo -e "${gl_hong}不支持的架构: $cpu_arch${gl_bai}"
                        break_end
                        return 1
                        ;;
                esac
                
                wget -O /usr/local/bin/cloudflared "$download_url"
                chmod +x /usr/local/bin/cloudflared
                
                if [ $? -eq 0 ]; then
                    echo -e "${gl_lv}✅ cloudflared 安装成功${gl_bai}"
                else
                    echo -e "${gl_hong}❌ cloudflared 安装失败${gl_bai}"
                    break_end
                    return 1
                fi
                ;;
            *)
                echo "已取消，请手动安装 cloudflared 后配置"
                break_end
                return 1
                ;;
        esac
    else
        echo -e "${gl_lv}✅ cloudflared 已安装${gl_bai}"
    fi
    
    echo ""
    echo -e "${gl_zi}[步骤 1/5] Cloudflare 账户登录${gl_bai}"
    echo ""
    
    # 检查是否已有有效的证书（之前已登录过）
    if [ -f "/root/.cloudflared/cert.pem" ]; then
        echo -e "${gl_lv}✅ 检测到已有 Cloudflare 认证证书${gl_bai}"
        echo ""
        echo "请选择："
        echo "1. 复用现有账户认证（推荐，适用于同一 CF 账户下的不同域名）"
        echo "2. 使用新账户登录（需要使用其他 Cloudflare 账户）"
        echo ""
        
        local auth_choice
        read -e -p "请选择 [1-2]: " auth_choice
        
        case "$auth_choice" in
            2)
                echo ""
                echo -e "${gl_huang}正在清除旧的认证信息...${gl_bai}"
                rm -f /root/.cloudflared/cert.pem
                
                echo ""
                echo "即将打开浏览器进行 Cloudflare 登录..."
                echo -e "${gl_huang}请在浏览器中完成授权${gl_bai}"
                echo ""
                read -e -p "按回车继续..."
                
                cloudflared tunnel login
                
                if [ $? -ne 0 ]; then
                    echo -e "${gl_hong}❌ 登录失败${gl_bai}"
                    break_end
                    return 1
                fi
                
                echo -e "${gl_lv}✅ 新账户登录成功${gl_bai}"
                ;;
            *)
                echo ""
                echo -e "${gl_lv}✅ 将复用现有认证${gl_bai}"
                ;;
        esac
    else
        echo "即将打开浏览器进行 Cloudflare 登录..."
        echo -e "${gl_huang}请在浏览器中完成授权${gl_bai}"
        echo ""
        read -e -p "按回车继续..."
        
        cloudflared tunnel login
        
        if [ $? -ne 0 ]; then
            echo -e "${gl_hong}❌ 登录失败${gl_bai}"
            break_end
            return 1
        fi
        
        echo -e "${gl_lv}✅ 登录成功${gl_bai}"
    fi
    
    echo ""
    echo -e "${gl_zi}[步骤 2/5] 创建隧道${gl_bai}"
    echo ""
    
    local tunnel_name="sub-store-$instance_num"
    echo "隧道名称: $tunnel_name"
    
    # 检查隧道是否已存在
    local existing_tunnel_id=$(cloudflared tunnel list 2>/dev/null | grep "$tunnel_name" | awk '{print $1}')
    
    if [ -n "$existing_tunnel_id" ]; then
        echo ""
        echo -e "${gl_lv}✅ 检测到同名隧道已存在${gl_bai}"
        echo "Tunnel ID: $existing_tunnel_id"
        echo ""
        echo "请选择操作："
        echo "1. 复用现有隧道（推荐）"
        echo "2. 删除旧隧道并重新创建"
        echo "3. 取消配置"
        echo ""
        
        local tunnel_choice
        read -e -p "请选择 [1-3]: " tunnel_choice
        
        case "$tunnel_choice" in
            1)
                echo -e "${gl_lv}✅ 将复用现有隧道${gl_bai}"
                tunnel_id="$existing_tunnel_id"
                ;;
            2)
                echo ""
                # 先停止可能正在运行的 cloudflared 服务
                local service_name="cloudflared-sub-store-$instance_num"
                if systemctl is-active --quiet "$service_name" 2>/dev/null; then
                    echo "正在停止旧的 cloudflared 服务..."
                    systemctl stop "$service_name" 2>/dev/null
                    systemctl disable "$service_name" 2>/dev/null
                    rm -f "/etc/systemd/system/$service_name.service" 2>/dev/null
                    systemctl daemon-reload 2>/dev/null
                    sleep 2
                fi
                
                # 清理旧的凭证文件
                if [ -n "$existing_tunnel_id" ]; then
                    echo "正在清理旧的隧道凭证..."
                    rm -f "/root/.cloudflared/$existing_tunnel_id.json" 2>/dev/null
                fi
                
                echo "正在删除旧隧道..."
                cloudflared tunnel cleanup "$tunnel_name" 2>/dev/null
                cloudflared tunnel delete "$tunnel_name" 2>/dev/null
                
                # 如果删除失败，尝试强制删除
                if cloudflared tunnel list 2>/dev/null | grep -q "$tunnel_name"; then
                    echo -e "${gl_huang}尝试强制删除隧道...${gl_bai}"
                    cloudflared tunnel delete -f "$tunnel_name" 2>/dev/null
                fi
                
                echo "正在创建新隧道..."
                cloudflared tunnel create "$tunnel_name"
                
                if [ $? -ne 0 ]; then
                    echo -e "${gl_hong}❌ 创建隧道失败${gl_bai}"
                    echo -e "${gl_huang}提示：可能是隧道名称冲突，请尝试更换实例编号${gl_bai}"
                    break_end
                    return 1
                fi
                
                tunnel_id=$(cloudflared tunnel list | grep "$tunnel_name" | awk '{print $1}')
                echo -e "${gl_lv}✅ 新隧道创建成功${gl_bai}"
                echo "Tunnel ID: $tunnel_id"
                ;;
            *)
                echo "已取消配置"
                break_end
                return 1
                ;;
        esac
    else
        # 隧道不存在，创建新隧道
        local create_output
        create_output=$(cloudflared tunnel create "$tunnel_name" 2>&1)
        local create_result=$?
        
        if [ $create_result -ne 0 ]; then
            echo -e "${gl_hong}❌ 创建隧道失败${gl_bai}"
            echo ""
            echo -e "${gl_huang}错误信息：${gl_bai}"
            echo "$create_output"
            echo ""
            
            # 检查是否是隧道名称已存在的错误
            if echo "$create_output" | grep -qi "already exists"; then
                echo -e "${gl_huang}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
                echo -e "${gl_huang}可能的原因：${gl_bai}"
                echo "  1. 隧道名称已在 Cloudflare 账户中存在（可能是其他机器创建的）"
                echo "  2. 之前使用不同账户创建过同名隧道"
                echo ""
                echo -e "${gl_huang}解决方案：${gl_bai}"
                echo "  方案1: 登录 Cloudflare Dashboard -> Zero Trust -> Networks -> Tunnels"
                echo "         手动删除名为 '$tunnel_name' 的隧道，然后重试"
                echo ""
                echo "  方案2: 使用不同的实例编号（如改用 2, 3...）"
                echo "         这会创建 sub-store-2, sub-store-3 等不同名称的隧道"
                echo -e "${gl_huang}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
            fi
            
            break_end
            return 1
        fi
        
        echo "$create_output"
        
        # 获取 tunnel ID
        tunnel_id=$(cloudflared tunnel list | grep "$tunnel_name" | awk '{print $1}')
        
        if [ -z "$tunnel_id" ]; then
            echo -e "${gl_hong}❌ 无法获取 tunnel ID${gl_bai}"
            break_end
            return 1
        fi
        
        echo -e "${gl_lv}✅ 隧道创建成功${gl_bai}"
        echo "Tunnel ID: $tunnel_id"
    fi
    
    echo ""
    echo -e "${gl_zi}[步骤 3/5] 输入域名${gl_bai}"
    echo ""
    
    local domain
    read -e -p "请输入你的域名（如 sub.example.com）: " domain
    
    if [ -z "$domain" ]; then
        echo -e "${gl_hong}域名不能为空${gl_bai}"
        break_end
        return 1
    fi
    
    echo ""
    echo -e "${gl_zi}[步骤 4/5] 配置 DNS 路由${gl_bai}"
    echo ""
    
    cloudflared tunnel route dns "$tunnel_id" "$domain"
    
    if [ $? -ne 0 ]; then
        echo -e "${gl_hong}❌ DNS 配置失败${gl_bai}"
        break_end
        return 1
    fi
    
    echo -e "${gl_lv}✅ DNS 配置成功${gl_bai}"
    
    echo ""
    echo -e "${gl_zi}[步骤 5/5] 生成并启动配置${gl_bai}"
    echo ""
    
    # 生成最终配置文件
    local final_cf_conf="/root/sub-store-cf-tunnel-$instance_num.yaml"
    cat > "$final_cf_conf" << CFEOF
tunnel: $tunnel_id
credentials-file: /root/.cloudflared/$tunnel_id.json

ingress:
  # 后端 API 路由（必须在前面，更具体的规则）
  - hostname: $domain
    path: /$access_path
    service: http://127.0.0.1:$api_port
  
  # 前端页面路由（通配所有其他请求，与后端共用端口）
  - hostname: $domain
    service: http://127.0.0.1:$api_port
  
  # 默认规则（必须）
  - service: http_status:404
CFEOF
    
    echo -e "${gl_lv}✅ 配置文件已生成: $final_cf_conf${gl_bai}"
    
    echo ""
    echo "正在启动 Cloudflare Tunnel..."
    
    # 创建 systemd 服务
    cat > /etc/systemd/system/cloudflared-sub-store-$instance_num.service << SERVICEEOF
[Unit]
Description=Cloudflare Tunnel for Sub-Store Instance $instance_num
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/cloudflared tunnel --config $final_cf_conf run
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
SERVICEEOF
    
    systemctl daemon-reload
    systemctl enable cloudflared-sub-store-$instance_num
    systemctl start cloudflared-sub-store-$instance_num
    
    sleep 3
    
    if systemctl is-active --quiet cloudflared-sub-store-$instance_num; then
        echo -e "${gl_lv}✅ Cloudflare Tunnel 启动成功${gl_bai}"
        echo ""
        echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
        echo -e "${gl_lv}🎉 配置完成！${gl_bai}"
        echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
        echo ""
        echo -e "访问地址: ${gl_lv}https://$domain?api=https://$domain/$access_path${gl_bai}"
        echo ""
        echo "服务管理："
        echo "  - 查看状态: systemctl status cloudflared-sub-store-$instance_num"
        echo "  - 查看日志: journalctl -u cloudflared-sub-store-$instance_num -f"
        echo "  - 重启服务: systemctl restart cloudflared-sub-store-$instance_num"
        echo ""
    else
        echo -e "${gl_hong}❌ Cloudflare Tunnel 启动失败${gl_bai}"
        echo "查看日志: journalctl -u cloudflared-sub-store-$instance_num -n 50"
    fi
    
    break_end
}

# 更新实例
update_substore_instance() {
    clear
    echo "=================================="
    echo "    Sub-Store 实例更新"
    echo "=================================="
    echo ""
    
    local instances=($(get_substore_instances))
    
    if [ ${#instances[@]} -eq 0 ]; then
        echo -e "${gl_huang}没有已部署的实例${gl_bai}"
        break_end
        return 1
    fi
    
    echo -e "${gl_zi}已部署的实例：${gl_bai}"
    for i in "${!instances[@]}"; do
        local instance_name="${instances[$i]}"
        local instance_num=$(echo "$instance_name" | sed 's/store-//')
        local container_name="sub-store-$instance_num"
        
        if docker ps --format '{{.Names}}' | grep -q "^${container_name}$"; then
            echo -e "  $((i+1)). ${instance_name} ${gl_lv}[运行中]${gl_bai}"
        else
            echo -e "  $((i+1)). ${instance_name} ${gl_hong}[已停止]${gl_bai}"
        fi
    done
    echo "  $((${#instances[@]}+1)). 更新所有实例"
    echo ""
    
    local choice
    read -e -p "请选择要更新的实例编号（输入 0 取消）: " choice
    
    if [ "$choice" == "0" ]; then
        echo "已取消更新"
        break_end
        return 1
    fi
    
    # 更新所有实例
    if [ "$choice" == "$((${#instances[@]}+1))" ]; then
        echo ""
        echo "准备更新所有实例..."
        local confirm
        read -e -p "确认更新所有 ${#instances[@]} 个实例？(y/n): " confirm
        if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
            echo "已取消更新"
            break_end
            return 1
        fi
        
        echo "正在拉取最新镜像..."
        docker pull xream/sub-store:http-meta
        
        for instance in "${instances[@]}"; do
            local config_file="/root/sub-store-configs/${instance}.yaml"
            local instance_num=$(echo "$instance" | sed 's/store-//')
            
            echo ""
            echo "正在更新实例: $instance"
            docker compose -f "$config_file" down
            docker compose -f "$config_file" up -d
            echo -e "${gl_lv}✅ 实例 $instance 更新完成${gl_bai}"
        done
        
        echo ""
        echo -e "${gl_lv}所有实例更新完成！${gl_bai}"
        break_end
        return 0
    fi
    
    # 更新单个实例
    if ! [[ "$choice" =~ ^[0-9]+$ ]] || [ "$choice" -lt 1 ] || [ "$choice" -gt ${#instances[@]} ]; then
        echo -e "${gl_hong}无效的选择${gl_bai}"
        break_end
        return 1
    fi
    
    local instance_name="${instances[$((choice-1))]}"
    local config_file="/root/sub-store-configs/${instance_name}.yaml"
    local instance_num=$(echo "$instance_name" | sed 's/store-//')
    
    echo ""
    echo "准备更新实例: $instance_name"
    local confirm
    read -e -p "确认更新？(y/n): " confirm
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        echo "已取消更新"
        break_end
        return 1
    fi
    
    echo "正在拉取最新镜像..."
    docker pull xream/sub-store:http-meta
    
    echo "正在停止容器..."
    docker compose -f "$config_file" down
    
    echo "正在启动更新后的容器..."
    docker compose -f "$config_file" up -d
    
    echo -e "${gl_lv}✅ 实例 $instance_name 更新完成！${gl_bai}"
    
    break_end
}

# 卸载实例
uninstall_substore_instance() {
    clear
    echo "=================================="
    echo "    Sub-Store 实例卸载"
    echo "=================================="
    echo ""
    
    local instances=($(get_substore_instances))
    
    if [ ${#instances[@]} -eq 0 ]; then
        echo -e "${gl_huang}没有已部署的实例${gl_bai}"
        break_end
        return 1
    fi
    
    echo -e "${gl_zi}已部署的实例：${gl_bai}"
    for i in "${!instances[@]}"; do
        local instance_name="${instances[$i]}"
        local instance_num=$(echo "$instance_name" | sed 's/store-//')
        local container_name="sub-store-$instance_num"
        
        if docker ps --format '{{.Names}}' | grep -q "^${container_name}$"; then
            echo -e "  $((i+1)). ${instance_name} ${gl_lv}[运行中]${gl_bai}"
        else
            echo -e "  $((i+1)). ${instance_name} ${gl_hong}[已停止]${gl_bai}"
        fi
    done
    echo ""
    
    local choice
    read -e -p "请选择要卸载的实例编号（输入 0 取消）: " choice
    
    if [ "$choice" == "0" ]; then
        echo "已取消卸载"
        break_end
        return 1
    fi
    
    if ! [[ "$choice" =~ ^[0-9]+$ ]] || [ "$choice" -lt 1 ] || [ "$choice" -gt ${#instances[@]} ]; then
        echo -e "${gl_hong}无效的选择${gl_bai}"
        break_end
        return 1
    fi
    
    local instance_name="${instances[$((choice-1))]}"
    local config_file="/root/sub-store-configs/${instance_name}.yaml"
    local instance_num=$(echo "$instance_name" | sed 's/store-//')
    
    echo ""
    echo -e "${gl_huang}将要卸载实例: $instance_name${gl_bai}"
    
    local delete_data
    read -e -p "是否同时删除数据目录？(y/n): " delete_data
    echo ""
    
    local confirm
    read -e -p "确认卸载？(y/n): " confirm
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        echo "已取消卸载"
        break_end
        return 1
    fi
    
    echo "正在停止并删除容器..."
    docker compose -f "$config_file" down
    
    if [[ "$delete_data" =~ ^[Yy]$ ]]; then
        # 从配置文件中提取数据目录
        local data_dir=$(grep -A 1 "volumes:" "$config_file" | tail -n 1 | awk -F':' '{print $1}' | xargs)
        if [ -n "$data_dir" ] && [ -d "$data_dir" ]; then
            echo "正在删除数据目录: $data_dir"
            rm -rf "$data_dir"
        fi
    fi
    
    echo "正在删除配置文件..."
    rm -f "$config_file"
    
    # 删除相关配置模板
    rm -f "/root/sub-store-nginx-$instance_num.conf"
    rm -f "/root/sub-store-cf-tunnel-$instance_num.yaml"
    
    echo -e "${gl_lv}✅ 实例 $instance_name 已成功卸载${gl_bai}"
    
    break_end
}

# 列出所有实例
list_substore_instances() {
    clear
    echo "=================================="
    echo "    已部署的 Sub-Store 实例"
    echo "=================================="
    echo ""
    
    local instances=($(get_substore_instances))
    
    if [ ${#instances[@]} -eq 0 ]; then
        echo -e "${gl_huang}没有已部署的实例${gl_bai}"
        break_end
        return 1
    fi
    
    for instance in "${instances[@]}"; do
        local config_file="/root/sub-store-configs/${instance}.yaml"
        local instance_num=$(echo "$instance" | sed 's/store-//')
        local container_name="sub-store-$instance_num"
        
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "实例编号: $instance_num"
        
        # 检查容器状态
        if docker ps --format '{{.Names}}' | grep -q "^${container_name}$"; then
            echo -e "  状态: ${gl_lv}运行中${gl_bai}"
        else
            echo -e "  状态: ${gl_hong}已停止${gl_bai}"
        fi
        
        # 提取配置信息
        if [ -f "$config_file" ]; then
            local http_port=$(grep "PORT:" "$config_file" | awk '{print $2}')
            local api_port=$(grep "SUB_STORE_BACKEND_API_PORT:" "$config_file" | awk '{print $2}')
            local access_path=$(grep "SUB_STORE_FRONTEND_BACKEND_PATH:" "$config_file" | awk '{print $2}')
            local data_dir=$(grep -A 1 "volumes:" "$config_file" | tail -n 1 | awk -F':' '{print $1}' | xargs)
            
            echo "  容器名称: $container_name"
            echo "  前端端口: $http_port (127.0.0.1)"
            echo "  后端端口: $api_port (127.0.0.1)"
            echo "  访问路径: $access_path"
            echo "  数据目录: $data_dir"
            echo "  配置文件: $config_file"
        fi
        
        echo ""
    done
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
    break_end
}

# Sub-Store 主菜单
manage_substore() {
    while true; do
        clear
        echo "=================================="
        echo "   Sub-Store 多实例管理"
        echo "=================================="
        echo ""
        echo "1. 安装新实例"
        echo "2. 更新实例"
        echo "3. 卸载实例"
        echo "4. 查看已部署实例"
        echo "0. 返回主菜单"
        echo "=================================="
        read -e -p "请选择操作 [0-4]: " choice
        
        case $choice in
            1)
                install_substore_instance
                ;;
            2)
                update_substore_instance
                ;;
            3)
                uninstall_substore_instance
                ;;
            4)
                list_substore_instances
                ;;
            0)
                return
                ;;
            *)
                echo "无效的选择"
                sleep 2
                ;;
        esac
    done
}

#=============================================================================
# 一键反代功能 - 通用反向代理管理
#=============================================================================

# 配置文件路径
REVERSE_PROXY_CONFIG_DIR="/root/reverse-proxy-configs"
REVERSE_PROXY_CONFIG_FILE="$REVERSE_PROXY_CONFIG_DIR/config.json"

# 初始化配置目录
init_reverse_proxy_config() {
    if [ ! -d "$REVERSE_PROXY_CONFIG_DIR" ]; then
        mkdir -p "$REVERSE_PROXY_CONFIG_DIR"
        mkdir -p "$REVERSE_PROXY_CONFIG_DIR/caddy"
        mkdir -p "$REVERSE_PROXY_CONFIG_DIR/cf-tunnel"
    fi

    if [ ! -f "$REVERSE_PROXY_CONFIG_FILE" ]; then
        echo '{"proxies":[]}' > "$REVERSE_PROXY_CONFIG_FILE"
    fi
}

# 检查端口是否在监听
check_port_listening() {
    local port=$1
    if ss -tuln 2>/dev/null | grep -q ":$port " || netstat -tuln 2>/dev/null | grep -q ":$port "; then
        return 0
    fi
    return 1
}

# 安装 cloudflared
install_cloudflared() {
    if command -v cloudflared &>/dev/null; then
        echo -e "${gl_lv}✅ cloudflared 已安装${gl_bai}"
        return 0
    fi

    echo -e "${gl_huang}正在安装 cloudflared...${gl_bai}"

    local cpu_arch=$(uname -m)
    local download_url

    case "$cpu_arch" in
        x86_64)
            download_url="https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64"
            ;;
        aarch64)
            download_url="https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-arm64"
            ;;
        *)
            echo -e "${gl_hong}❌ 不支持的架构: $cpu_arch${gl_bai}"
            return 1
            ;;
    esac

    if wget -O /usr/local/bin/cloudflared "$download_url" && chmod +x /usr/local/bin/cloudflared; then
        echo -e "${gl_lv}✅ cloudflared 安装成功${gl_bai}"
        return 0
    else
        echo -e "${gl_hong}❌ cloudflared 安装失败${gl_bai}"
        return 1
    fi
}

# 安装 Caddy
install_caddy() {
    if command -v caddy &>/dev/null; then
        echo -e "${gl_lv}✅ Caddy 已安装${gl_bai}"
        return 0
    fi

    echo -e "${gl_huang}正在安装 Caddy...${gl_bai}"

    if apt install -y caddy; then
        echo -e "${gl_lv}✅ Caddy 安装成功${gl_bai}"
        return 0
    else
        echo -e "${gl_hong}❌ Caddy 安装失败${gl_bai}"
        return 1
    fi
}

# 快速部署 - Cloudflare Tunnel
quick_deploy_cf_tunnel() {
    clear
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo -e "${gl_kjlan}  一键反代 - Cloudflare Tunnel${gl_bai}"
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo ""

    # 初始化配置
    init_reverse_proxy_config

    # 检查并安装 cloudflared
    if ! install_cloudflared; then
        break_end
        return 1
    fi

    echo ""
    echo -e "${gl_zi}[步骤 1/4] 输入本地端口${gl_bai}"
    echo ""

    local port
    while true; do
        read -e -p "请输入要反代的本地端口（如 5555）: " port

        if [ -z "$port" ]; then
            echo -e "${gl_hong}端口不能为空${gl_bai}"
            continue
        fi

        if ! [[ "$port" =~ ^[0-9]+$ ]] || [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
            echo -e "${gl_hong}端口号无效（1-65535）${gl_bai}"
            continue
        fi

        # 检查端口是否在监听
        if ! check_port_listening "$port"; then
            echo -e "${gl_huang}⚠️  警告: 端口 $port 当前未在监听${gl_bai}"
            read -e -p "是否继续？(y/n): " continue_anyway
            if [[ ! "$continue_anyway" =~ ^[Yy]$ ]]; then
                continue
            fi
        else
            echo -e "${gl_lv}✅ 检测到端口 $port 正在监听${gl_bai}"
        fi

        break
    done

    echo ""
    echo -e "${gl_zi}[步骤 2/4] 输入域名${gl_bai}"
    echo ""

    local domain
    while true; do
        read -e -p "请输入你的域名（如 app.example.com）: " domain

        if [ -z "$domain" ]; then
            echo -e "${gl_hong}域名不能为空${gl_bai}"
            continue
        fi

        # 简单的域名格式验证
        if ! [[ "$domain" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$ ]]; then
            echo -e "${gl_hong}域名格式无效${gl_bai}"
            continue
        fi

        break
    done

    echo ""
    echo -e "${gl_zi}[步骤 3/4] 输入应用名称（可选）${gl_bai}"
    echo ""

    local app_name
    read -e -p "请输入应用名称（回车跳过，如 MyApp）: " app_name

    if [ -z "$app_name" ]; then
        app_name="port-$port"
    fi

    # 生成安全的隧道名称
    local tunnel_name=$(echo "$app_name" | tr '[:upper:]' '[:lower:]' | tr -cd 'a-z0-9-')
    tunnel_name="tunnel-$tunnel_name-$(date +%s)"

    echo ""
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo -e "${gl_huang}配置确认${gl_bai}"
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo "应用名称: $app_name"
    echo "本地端口: $port"
    echo "访问域名: https://$domain"
    echo "隧道名称: $tunnel_name"
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo ""

    read -e -p "确认开始部署？(y/n): " confirm
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        echo "已取消部署"
        break_end
        return 1
    fi

    echo ""
    echo -e "${gl_zi}[步骤 4/4] 配置 Cloudflare Tunnel${gl_bai}"
    echo ""

    # 检查是否已登录
    if [ ! -d "/root/.cloudflared" ] || [ -z "$(ls -A /root/.cloudflared/*.json 2>/dev/null)" ]; then
        echo "首次使用需要登录 Cloudflare..."
        echo -e "${gl_huang}即将打开浏览器，请在浏览器中完成授权${gl_bai}"
        echo ""
        read -e -p "按回车继续..."

        cloudflared tunnel login

        if [ $? -ne 0 ]; then
            echo -e "${gl_hong}❌ 登录失败${gl_bai}"
            break_end
            return 1
        fi

        echo -e "${gl_lv}✅ 登录成功${gl_bai}"
        echo ""
    else
        echo -e "${gl_lv}✅ 已登录 Cloudflare${gl_bai}"
        echo ""
    fi

    # 创建隧道
    echo "正在创建隧道: $tunnel_name"
    cloudflared tunnel create "$tunnel_name"

    if [ $? -ne 0 ]; then
        echo -e "${gl_hong}❌ 创建隧道失败${gl_bai}"
        break_end
        return 1
    fi

    # 获取 tunnel ID
    local tunnel_id=$(cloudflared tunnel list | grep "$tunnel_name" | awk '{print $1}')

    if [ -z "$tunnel_id" ]; then
        echo -e "${gl_hong}❌ 无法获取 tunnel ID${gl_bai}"
        break_end
        return 1
    fi

    echo -e "${gl_lv}✅ 隧道创建成功${gl_bai}"
    echo "Tunnel ID: $tunnel_id"
    echo ""

    # 配置 DNS 路由
    echo "正在配置 DNS 路由..."
    cloudflared tunnel route dns "$tunnel_id" "$domain"

    if [ $? -ne 0 ]; then
        echo -e "${gl_hong}❌ DNS 配置失败${gl_bai}"
        break_end
        return 1
    fi

    echo -e "${gl_lv}✅ DNS 配置成功${gl_bai}"
    echo ""

    # 生成配置文件
    local config_file="$REVERSE_PROXY_CONFIG_DIR/cf-tunnel/$tunnel_name.yaml"
    cat > "$config_file" << EOF
tunnel: $tunnel_id
credentials-file: /root/.cloudflared/$tunnel_id.json

ingress:
  - hostname: $domain
    service: http://127.0.0.1:$port
  - service: http_status:404
EOF

    echo "正在创建 systemd 服务..."

    # 创建 systemd 服务
    cat > /etc/systemd/system/cloudflared-$tunnel_name.service << EOF
[Unit]
Description=Cloudflare Tunnel - $app_name
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/cloudflared tunnel --config $config_file run
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable cloudflared-$tunnel_name
    systemctl start cloudflared-$tunnel_name

    sleep 3

    if systemctl is-active --quiet cloudflared-$tunnel_name; then
        echo -e "${gl_lv}✅ 服务启动成功${gl_bai}"
        echo ""
        echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
        echo -e "${gl_lv}🎉 部署完成！${gl_bai}"
        echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
        echo ""
        echo -e "访问地址: ${gl_lv}https://$domain${gl_bai}"
        echo ""
        echo "服务管理："
        echo "  - 查看状态: systemctl status cloudflared-$tunnel_name"
        echo "  - 查看日志: journalctl -u cloudflared-$tunnel_name -f"
        echo "  - 重启服务: systemctl restart cloudflared-$tunnel_name"
        echo "  - 停止服务: systemctl stop cloudflared-$tunnel_name"
        echo ""

        # 保存配置到 JSON
        local timestamp=$(date +%s)
        local temp_file=$(mktemp)

        if command -v jq &>/dev/null; then
            jq --arg name "$app_name" \
               --arg port "$port" \
               --arg domain "$domain" \
               --arg tunnel "$tunnel_name" \
               --arg tunnel_id "$tunnel_id" \
               --arg type "cf-tunnel" \
               --arg time "$timestamp" \
               '.proxies += [{
                   "name": $name,
                   "port": $port,
                   "domain": $domain,
                   "tunnel_name": $tunnel,
                   "tunnel_id": $tunnel_id,
                   "type": $type,
                   "created_at": $time,
                   "service": ("cloudflared-" + $tunnel),
                   "config_file": ($tunnel + ".yaml")
               }]' "$REVERSE_PROXY_CONFIG_FILE" > "$temp_file" && mv "$temp_file" "$REVERSE_PROXY_CONFIG_FILE"
        fi
    else
        echo -e "${gl_hong}❌ 服务启动失败${gl_bai}"
        echo "查看日志: journalctl -u cloudflared-$tunnel_name -n 50"
    fi

    break_end
}

# 查看所有反代配置
list_reverse_proxies() {
    clear
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo -e "${gl_kjlan}  已部署的反向代理${gl_bai}"
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo ""

    init_reverse_proxy_config

    # 列出所有 cloudflared 服务
    local services=$(systemctl list-units --type=service --all | grep "cloudflared-tunnel" | awk '{print $1}')

    if [ -z "$services" ]; then
        echo -e "${gl_huang}暂无已部署的反向代理${gl_bai}"
        echo ""
        break_end
        return 0
    fi

    local count=0
    for service in $services; do
        count=$((count + 1))
        local tunnel_name=$(echo "$service" | sed 's/cloudflared-//' | sed 's/.service//')

        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "[$count] $tunnel_name"

        # 检查服务状态
        if systemctl is-active --quiet "$service"; then
            echo -e "  状态: ${gl_lv}运行中${gl_bai}"
        else
            echo -e "  状态: ${gl_hong}已停止${gl_bai}"
        fi

        # 读取配置文件
        local config_file="$REVERSE_PROXY_CONFIG_DIR/cf-tunnel/$tunnel_name.yaml"
        if [ -f "$config_file" ]; then
            local domain=$(grep "hostname:" "$config_file" | head -1 | awk '{print $3}')
            local port=$(grep "service:" "$config_file" | head -1 | sed -nE 's/.*:([0-9]+).*/\1/p')

            echo "  域名: https://$domain"
            echo "  端口: $port"
            echo "  配置: $config_file"
        fi

        echo "  服务: $service"
        echo ""
    done

    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    echo "总计: $count 个反向代理"
    echo ""

    break_end
}

# 删除反代配置
delete_reverse_proxy() {
    clear
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo -e "${gl_kjlan}  删除反向代理${gl_bai}"
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo ""

    # 列出所有服务
    local services=$(systemctl list-units --type=service --all | grep "cloudflared-tunnel" | awk '{print $1}')

    if [ -z "$services" ]; then
        echo -e "${gl_huang}暂无已部署的反向代理${gl_bai}"
        break_end
        return 0
    fi

    local services_array=($services)
    local count=0

    for service in "${services_array[@]}"; do
        count=$((count + 1))
        local tunnel_name=$(echo "$service" | sed 's/cloudflared-//' | sed 's/.service//')

        if systemctl is-active --quiet "$service"; then
            echo -e "  $count. $tunnel_name ${gl_lv}[运行中]${gl_bai}"
        else
            echo -e "  $count. $tunnel_name ${gl_hong}[已停止]${gl_bai}"
        fi
    done

    echo ""
    read -e -p "请选择要删除的反代编号 (1-$count, 0取消): " choice

    if [ "$choice" = "0" ]; then
        return 0
    fi

    if ! [[ "$choice" =~ ^[0-9]+$ ]] || [ "$choice" -lt 1 ] || [ "$choice" -gt $count ]; then
        echo -e "${gl_hong}无效的选择${gl_bai}"
        break_end
        return 1
    fi

    local selected_service="${services_array[$((choice-1))]}"
    local tunnel_name=$(echo "$selected_service" | sed 's/cloudflared-//' | sed 's/.service//')

    echo ""
    echo -e "${gl_huang}将要删除: $tunnel_name${gl_bai}"
    echo ""
    read -e -p "确认删除？(y/n): " confirm

    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        echo "已取消"
        break_end
        return 0
    fi

    echo ""
    echo "正在停止服务..."
    systemctl stop "$selected_service"
    systemctl disable "$selected_service"

    echo "正在删除服务文件..."
    rm -f "/etc/systemd/system/$selected_service"
    systemctl daemon-reload

    echo "正在删除配置文件..."
    rm -f "$REVERSE_PROXY_CONFIG_DIR/cf-tunnel/$tunnel_name.yaml"

    # 删除隧道（可选）
    read -e -p "是否同时删除 Cloudflare Tunnel？(y/n): " delete_tunnel
    if [[ "$delete_tunnel" =~ ^[Yy]$ ]]; then
        echo "正在删除隧道..."
        cloudflared tunnel delete "$tunnel_name" 2>/dev/null || true
    fi

    echo ""
    echo -e "${gl_lv}✅ 删除完成${gl_bai}"

    break_end
}

# 一键反代主菜单
manage_reverse_proxy() {
    while true; do
        clear
        echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
        echo -e "${gl_kjlan}  一键反代 🎯${gl_bai}"
        echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
        echo ""
        echo "1. 快速部署（输入端口+域名）"
        echo "2. 查看已部署的反代"
        echo "3. 删除反代配置"
        echo "0. 返回主菜单"
        echo ""
        echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
        read -e -p "请选择操作 [0-3]: " choice

        case $choice in
            1)
                quick_deploy_cf_tunnel
                ;;
            2)
                list_reverse_proxies
                ;;
            3)
                delete_reverse_proxy
                ;;
            0)
                return
                ;;
            *)
                echo "无效的选择"
                sleep 2
                ;;
        esac
    done
}

#=============================================================================
# Antigravity Claude Proxy 部署管理
#=============================================================================

# 固定配置
AG_PROXY_SERVICE_NAME="ag-proxy"
AG_PROXY_INSTALL_DIR="/root/antigravity-claude-proxy"
AG_PROXY_PORT="8080"
AG_PROXY_REPO="https://github.com/badri-s2001/antigravity-claude-proxy.git"
AG_PROXY_SERVICE_FILE="/etc/systemd/system/ag-proxy.service"
AG_PROXY_PORT_FILE="/root/antigravity-claude-proxy/.ag-proxy-port"

# 获取当前配置的端口
ag_proxy_get_port() {
    if [ -f "$AG_PROXY_PORT_FILE" ]; then
        cat "$AG_PROXY_PORT_FILE"
    else
        echo "$AG_PROXY_PORT"
    fi
}

# 检查端口是否可用
ag_proxy_check_port() {
    local port=$1
    if ss -lntp 2>/dev/null | grep -q ":${port} "; then
        return 1
    fi
    return 0
}

# 检测 Antigravity Claude Proxy 状态
ag_proxy_check_status() {
    if [ ! -d "$AG_PROXY_INSTALL_DIR" ]; then
        echo "not_installed"
    elif ! systemctl is-enabled "$AG_PROXY_SERVICE_NAME" &>/dev/null; then
        echo "installed_no_service"
    elif systemctl is-active "$AG_PROXY_SERVICE_NAME" &>/dev/null; then
        echo "running"
    else
        echo "stopped"
    fi
}

# 检测并安装 Node.js
ag_proxy_install_nodejs() {
    echo -e "${gl_kjlan}[1/6] 检测 Node.js 环境...${gl_bai}"

    if command -v node &>/dev/null; then
        local node_version=$(node -v | sed 's/v//' | cut -d. -f1)
        if [ "$node_version" -ge 20 ]; then
            echo -e "${gl_lv}✅ Node.js $(node -v) 已安装${gl_bai}"
            return 0
        else
            echo -e "${gl_huang}⚠ Node.js 版本过低 ($(node -v))，需要 20+${gl_bai}"
        fi
    else
        echo -e "${gl_huang}⚠ Node.js 未安装${gl_bai}"
    fi

    echo "正在安装 Node.js 20..."

    # 检测系统类型
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        local os_id="${ID,,}"
    fi

    # 安全下载并执行设置脚本（避免 curl | bash 漏洞）
    local setup_script=$(mktemp)
    local script_url=""

    if [[ "$os_id" == "debian" || "$os_id" == "ubuntu" ]]; then
        script_url="https://deb.nodesource.com/setup_20.x"
    elif [[ "$os_id" == "centos" || "$os_id" == "rhel" || "$os_id" == "fedora" || "$os_id" == "rocky" || "$os_id" == "alma" ]]; then
        script_url="https://rpm.nodesource.com/setup_20.x"
    fi

    if [ -n "$script_url" ]; then
        # 下载脚本
        if ! curl -fsSL --connect-timeout 15 --max-time 60 "$script_url" -o "$setup_script" 2>/dev/null; then
            echo -e "${gl_hong}❌ 下载 Node.js 设置脚本失败${gl_bai}"
            rm -f "$setup_script"
            return 1
        fi

        # 验证脚本格式（必须是 shell 脚本）
        if ! head -1 "$setup_script" | grep -q "^#!"; then
            echo -e "${gl_hong}❌ 脚本格式验证失败${gl_bai}"
            rm -f "$setup_script"
            return 1
        fi

        # 执行脚本
        chmod +x "$setup_script"
        bash "$setup_script" >/dev/null 2>&1
        rm -f "$setup_script"
    fi

    if [[ "$os_id" == "debian" || "$os_id" == "ubuntu" ]]; then
        apt-get install -y nodejs >/dev/null 2>&1
    elif [[ "$os_id" == "centos" || "$os_id" == "rhel" || "$os_id" == "fedora" || "$os_id" == "rocky" || "$os_id" == "alma" ]]; then
        if command -v dnf &>/dev/null; then
            dnf install -y nodejs >/dev/null 2>&1
        else
            yum install -y nodejs >/dev/null 2>&1
        fi
    else
        echo -e "${gl_hong}❌ 不支持的系统，请手动安装 Node.js 20+${gl_bai}"
        return 1
    fi

    if command -v node &>/dev/null; then
        echo -e "${gl_lv}✅ Node.js $(node -v) 安装成功${gl_bai}"
        return 0
    else
        echo -e "${gl_hong}❌ Node.js 安装失败${gl_bai}"
        return 1
    fi
}

# 克隆项目
ag_proxy_clone_repo() {
    echo -e "${gl_kjlan}[2/6] 拉取项目代码...${gl_bai}"

    if [ -d "$AG_PROXY_INSTALL_DIR" ]; then
        echo -e "${gl_huang}⚠ 项目目录已存在，正在更新...${gl_bai}"
        cd "$AG_PROXY_INSTALL_DIR"
        git pull >/dev/null 2>&1
        if [ $? -eq 0 ]; then
            echo -e "${gl_lv}✅ 代码更新成功${gl_bai}"
            return 0
        else
            echo -e "${gl_hong}❌ 代码更新失败，尝试重新克隆...${gl_bai}"
            cd /root
            rm -rf "$AG_PROXY_INSTALL_DIR"
        fi
    fi

    # 安装 git（如果没有）
    if ! command -v git &>/dev/null; then
        echo "正在安装 git..."
        if command -v apt-get &>/dev/null; then
            apt-get update -qq && apt-get install -y git >/dev/null 2>&1
        elif command -v dnf &>/dev/null; then
            dnf install -y git >/dev/null 2>&1
        elif command -v yum &>/dev/null; then
            yum install -y git >/dev/null 2>&1
        fi
    fi

    git clone "$AG_PROXY_REPO" "$AG_PROXY_INSTALL_DIR" >/dev/null 2>&1
    if [ $? -eq 0 ]; then
        echo -e "${gl_lv}✅ 项目克隆成功${gl_bai}"
        return 0
    else
        echo -e "${gl_hong}❌ 项目克隆失败，请检查网络连接${gl_bai}"
        return 1
    fi
}

# 安装依赖
ag_proxy_install_deps() {
    echo -e "${gl_kjlan}[3/6] 安装项目依赖...${gl_bai}"

    cd "$AG_PROXY_INSTALL_DIR"

    # 先检查 package.json 是否存在
    if [ ! -f "package.json" ]; then
        echo -e "${gl_hong}❌ package.json 不存在，项目可能未正确克隆${gl_bai}"
        return 1
    fi

    # 检查并安装编译工具（better-sqlite3 需要）
    echo "检测编译工具..."
    local need_build_tools=false

    if ! command -v make &>/dev/null; then
        echo "  make: 未安装"
        need_build_tools=true
    else
        echo "  make: 已安装"
    fi

    if ! command -v g++ &>/dev/null; then
        echo "  g++: 未安装"
        need_build_tools=true
    else
        echo "  g++: 已安装"
    fi

    if [ "$need_build_tools" = true ]; then
        echo ""
        echo "正在安装编译工具（make, g++, python3）..."
        if command -v apt-get &>/dev/null; then
            apt-get update -qq
            apt-get install -y build-essential python3
        elif command -v dnf &>/dev/null; then
            dnf install -y make gcc-c++ python3
        elif command -v yum &>/dev/null; then
            yum install -y make gcc-c++ python3
        fi

        # 验证安装
        if command -v make &>/dev/null && command -v g++ &>/dev/null; then
            echo -e "${gl_lv}✅ 编译工具安装成功${gl_bai}"
        else
            echo -e "${gl_hong}❌ 编译工具安装失败，请手动安装: apt install build-essential${gl_bai}"
            return 1
        fi
    fi

    echo ""
    # 安装依赖，显示进度
    echo "正在执行 npm install（可能需要几分钟）..."
    npm install 2>&1 | tail -30

    if [ ${PIPESTATUS[0]} -eq 0 ]; then
        echo -e "${gl_lv}✅ 依赖安装成功${gl_bai}"
        return 0
    else
        echo -e "${gl_hong}❌ 依赖安装失败，请检查上方错误信息${gl_bai}"
        return 1
    fi
}

# 配置端口
ag_proxy_configure_port() {
    echo -e "${gl_kjlan}[4/6] 配置服务端口...${gl_bai}"

    local port="$AG_PROXY_PORT"
    read -e -p "请输入访问端口 [$AG_PROXY_PORT]: " input_port
    if [ -n "$input_port" ]; then
        port="$input_port"
    fi

    # 检查端口是否可用
    while ! ag_proxy_check_port "$port"; do
        echo -e "${gl_hong}⚠️ 端口 $port 已被占用，请换一个${gl_bai}"
        read -e -p "请输入访问端口: " port
        if [ -z "$port" ]; then
            port="$AG_PROXY_PORT"
        fi
    done
    echo -e "${gl_lv}✅ 端口 $port 可用${gl_bai}"

    # 保存端口配置
    mkdir -p "$(dirname "$AG_PROXY_PORT_FILE")"
    echo "$port" > "$AG_PROXY_PORT_FILE"
    return 0
}

# 创建 systemd 服务
ag_proxy_create_service() {
    local port=$(ag_proxy_get_port)
    echo -e "${gl_kjlan}[5/6] 创建 systemd 服务...${gl_bai}"

    cat > "$AG_PROXY_SERVICE_FILE" <<EOF
[Unit]
Description=Antigravity Claude Proxy
After=network.target

[Service]
Type=simple
WorkingDirectory=${AG_PROXY_INSTALL_DIR}
Environment=PORT=${port}
ExecStart=/usr/bin/npm start
Restart=always
RestartSec=3
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload

    if [ -f "$AG_PROXY_SERVICE_FILE" ]; then
        echo -e "${gl_lv}✅ 服务文件创建成功${gl_bai}"
        return 0
    else
        echo -e "${gl_hong}❌ 服务文件创建失败${gl_bai}"
        return 1
    fi
}

# 启动服务
ag_proxy_start_service() {
    echo -e "${gl_kjlan}[6/6] 启动服务...${gl_bai}"

    systemctl enable "$AG_PROXY_SERVICE_NAME" >/dev/null 2>&1
    systemctl start "$AG_PROXY_SERVICE_NAME"

    sleep 2

    if systemctl is-active "$AG_PROXY_SERVICE_NAME" &>/dev/null; then
        echo -e "${gl_lv}✅ 服务启动成功${gl_bai}"
        return 0
    else
        echo -e "${gl_hong}❌ 服务启动失败${gl_bai}"
        echo "查看日志: journalctl -u $AG_PROXY_SERVICE_NAME -n 20"
        return 1
    fi
}

# 一键部署
ag_proxy_deploy() {
    clear
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo -e "${gl_kjlan}  Antigravity Claude Proxy 一键部署${gl_bai}"
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo ""

    local status=$(ag_proxy_check_status)
    if [ "$status" = "running" ]; then
        echo -e "${gl_huang}⚠ 服务已在运行中${gl_bai}"
        echo ""
        read -e -p "是否重新部署？(Y/N): " confirm
        case "$confirm" in
            [Yy]) ;;
            *) return ;;
        esac
        echo ""
        systemctl stop "$AG_PROXY_SERVICE_NAME" 2>/dev/null
    fi

    # 执行部署步骤
    ag_proxy_install_nodejs || { break_end; return 1; }
    echo ""
    ag_proxy_clone_repo || { break_end; return 1; }
    echo ""
    ag_proxy_install_deps || { break_end; return 1; }
    echo ""
    ag_proxy_configure_port || { break_end; return 1; }
    echo ""
    ag_proxy_create_service || { break_end; return 1; }
    echo ""
    ag_proxy_start_service || { break_end; return 1; }

    # 获取服务器 IP
    local server_ip=$(curl -s4 ip.sb 2>/dev/null || curl -s6 ip.sb 2>/dev/null || echo "服务器IP")
    local port=$(ag_proxy_get_port)

    echo ""
    echo -e "${gl_lv}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo -e "${gl_lv}  ✅ 部署完成！${gl_bai}"
    echo -e "${gl_lv}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo ""
    echo -e "访问地址: ${gl_huang}http://${server_ip}:${port}${gl_bai}"
    echo ""
    echo -e "${gl_kjlan}【第一步】添加 Google 账号${gl_bai}"
    echo "  打开上面的地址 → Accounts → Add Account → 完成 Google 授权"
    echo ""
    echo -e "${gl_kjlan}【第二步】配置本地 Claude Code${gl_bai}"
    echo "  编辑文件: ~/.claude/settings.json"
    echo ""
    echo "  添加以下内容（推荐配置）："
    echo -e "${gl_huang}  {${gl_bai}"
    echo -e "${gl_huang}    \"env\": {${gl_bai}"
    echo -e "${gl_huang}      \"ANTHROPIC_AUTH_TOKEN\": \"test\",${gl_bai}"
    echo -e "${gl_huang}      \"ANTHROPIC_BASE_URL\": \"http://${server_ip}:${port}\",${gl_bai}"
    echo -e "${gl_huang}      \"ANTHROPIC_MODEL\": \"claude-opus-4-5-thinking\",${gl_bai}"
    echo -e "${gl_huang}      \"ANTHROPIC_DEFAULT_OPUS_MODEL\": \"claude-opus-4-5-thinking\",${gl_bai}"
    echo -e "${gl_huang}      \"ANTHROPIC_DEFAULT_SONNET_MODEL\": \"claude-sonnet-4-5-thinking\",${gl_bai}"
    echo -e "${gl_huang}      \"ANTHROPIC_DEFAULT_HAIKU_MODEL\": \"gemini-3-flash\",${gl_bai}"
    echo -e "${gl_huang}      \"CLAUDE_CODE_SUBAGENT_MODEL\": \"claude-sonnet-4-5-thinking\"${gl_bai}"
    echo -e "${gl_huang}    }${gl_bai}"
    echo -e "${gl_huang}  }${gl_bai}"
    echo ""
    echo -e "${gl_zi}说明: Opus=主力模型, Sonnet=子代理, Haiku用Gemini省额度${gl_bai}"
    echo ""
    echo -e "${gl_kjlan}【可选】通过环境变量配置（macOS/Linux）${gl_bai}"
    echo "  将以下命令添加到 shell 配置文件："
    echo ""
    echo -e "${gl_huang}  echo 'export ANTHROPIC_BASE_URL=\"http://${server_ip}:${port}\"' >> ~/.zshrc${gl_bai}"
    echo -e "${gl_huang}  echo 'export ANTHROPIC_AUTH_TOKEN=\"test\"' >> ~/.zshrc${gl_bai}"
    echo -e "${gl_huang}  source ~/.zshrc${gl_bai}"
    echo ""
    echo -e "${gl_zi}提示: Bash 用户请将 ~/.zshrc 替换为 ~/.bashrc${gl_bai}"
    echo ""
    echo -e "${gl_kjlan}【第三步】重启 Claude Code${gl_bai}"
    echo "  关闭并重新打开终端，然后运行 claude 即可"
    echo ""
    echo -e "${gl_zi}提示: 更多模型选项请访问 WebUI 的 Settings 页面${gl_bai}"
    echo ""
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo -e "${gl_kjlan}管理命令:${gl_bai}"
    echo "  状态: systemctl status $AG_PROXY_SERVICE_NAME"
    echo "  日志: journalctl -u $AG_PROXY_SERVICE_NAME -f"
    echo "  重启: systemctl restart $AG_PROXY_SERVICE_NAME"
    echo ""
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo -e "${gl_kjlan}命令行添加账号（无法访问 Web 时使用）:${gl_bai}"
    echo ""
    echo "  # 1. 停止服务"
    echo "  systemctl stop $AG_PROXY_SERVICE_NAME"
    echo ""
    echo "  # 2. 添加账号（按提示在浏览器中打开链接完成 Google 授权）"
    echo "  cd $AG_PROXY_INSTALL_DIR && npx antigravity-claude-proxy accounts add --no-browser"
    echo ""
    echo "  # 3. 重新启动服务"
    echo "  systemctl start $AG_PROXY_SERVICE_NAME"
    echo ""

    break_end
}

# 查看配置指引
ag_proxy_show_config() {
    clear

    if [ ! -d "$AG_PROXY_INSTALL_DIR" ]; then
        echo -e "${gl_hong}❌ 项目未安装，请先执行一键部署${gl_bai}"
        break_end
        return 1
    fi

    # 获取服务器 IP 和端口
    local server_ip=$(curl -s4 ip.sb 2>/dev/null || curl -s6 ip.sb 2>/dev/null || echo "服务器IP")
    local port=$(ag_proxy_get_port)

    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo -e "${gl_kjlan}  Claude Code 本地配置指引${gl_bai}"
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo ""
    echo -e "访问地址: ${gl_huang}http://${server_ip}:${port}${gl_bai}"
    echo ""
    echo -e "${gl_kjlan}【第一步】添加 Google 账号${gl_bai}"
    echo "  打开上面的地址 → Accounts → Add Account → 完成 Google 授权"
    echo ""
    echo -e "${gl_kjlan}【第二步】配置本地 Claude Code${gl_bai}"
    echo "  编辑文件: ~/.claude/settings.json"
    echo ""
    echo "  添加以下内容（推荐配置）："
    echo -e "${gl_huang}  {${gl_bai}"
    echo -e "${gl_huang}    \"env\": {${gl_bai}"
    echo -e "${gl_huang}      \"ANTHROPIC_AUTH_TOKEN\": \"test\",${gl_bai}"
    echo -e "${gl_huang}      \"ANTHROPIC_BASE_URL\": \"http://${server_ip}:${port}\",${gl_bai}"
    echo -e "${gl_huang}      \"ANTHROPIC_MODEL\": \"claude-opus-4-5-thinking\",${gl_bai}"
    echo -e "${gl_huang}      \"ANTHROPIC_DEFAULT_OPUS_MODEL\": \"claude-opus-4-5-thinking\",${gl_bai}"
    echo -e "${gl_huang}      \"ANTHROPIC_DEFAULT_SONNET_MODEL\": \"claude-sonnet-4-5-thinking\",${gl_bai}"
    echo -e "${gl_huang}      \"ANTHROPIC_DEFAULT_HAIKU_MODEL\": \"gemini-3-flash\",${gl_bai}"
    echo -e "${gl_huang}      \"CLAUDE_CODE_SUBAGENT_MODEL\": \"claude-sonnet-4-5-thinking\"${gl_bai}"
    echo -e "${gl_huang}    }${gl_bai}"
    echo -e "${gl_huang}  }${gl_bai}"
    echo ""
    echo -e "${gl_zi}说明: Opus=主力模型, Sonnet=子代理, Haiku用Gemini省额度${gl_bai}"
    echo ""
    echo -e "${gl_kjlan}【可选】通过环境变量配置（macOS/Linux）${gl_bai}"
    echo "  将以下命令添加到 shell 配置文件："
    echo ""
    echo -e "${gl_huang}  echo 'export ANTHROPIC_BASE_URL=\"http://${server_ip}:${port}\"' >> ~/.zshrc${gl_bai}"
    echo -e "${gl_huang}  echo 'export ANTHROPIC_AUTH_TOKEN=\"test\"' >> ~/.zshrc${gl_bai}"
    echo -e "${gl_huang}  source ~/.zshrc${gl_bai}"
    echo ""
    echo -e "${gl_zi}提示: Bash 用户请将 ~/.zshrc 替换为 ~/.bashrc${gl_bai}"
    echo ""
    echo -e "${gl_kjlan}【第三步】重启 Claude Code${gl_bai}"
    echo "  关闭并重新打开终端，然后运行 claude 即可"
    echo ""
    echo -e "${gl_zi}提示: 更多模型选项请访问 WebUI 的 Settings 页面${gl_bai}"
    echo ""
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo -e "${gl_kjlan}管理命令:${gl_bai}"
    echo "  状态: systemctl status $AG_PROXY_SERVICE_NAME"
    echo "  日志: journalctl -u $AG_PROXY_SERVICE_NAME -f"
    echo "  重启: systemctl restart $AG_PROXY_SERVICE_NAME"
    echo ""
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo -e "${gl_kjlan}命令行添加账号（无法访问 Web 时使用）:${gl_bai}"
    echo ""
    echo "  # 1. 停止服务"
    echo "  systemctl stop $AG_PROXY_SERVICE_NAME"
    echo ""
    echo "  # 2. 添加账号（按提示在浏览器中打开链接完成 Google 授权）"
    echo "  cd $AG_PROXY_INSTALL_DIR && npx antigravity-claude-proxy accounts add --no-browser"
    echo ""
    echo "  # 3. 重新启动服务"
    echo "  systemctl start $AG_PROXY_SERVICE_NAME"
    echo ""

    break_end
}

# 更新项目
ag_proxy_update() {
    clear
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo -e "${gl_kjlan}  更新 Antigravity Claude Proxy${gl_bai}"
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo ""

    if [ ! -d "$AG_PROXY_INSTALL_DIR" ]; then
        echo -e "${gl_hong}❌ 项目未安装，请先执行一键部署${gl_bai}"
        break_end
        return 1
    fi

    echo "正在拉取最新代码..."
    cd "$AG_PROXY_INSTALL_DIR"
    git pull

    if [ $? -eq 0 ]; then
        echo ""
        echo "正在更新依赖..."
        npm install --production >/dev/null 2>&1

        echo ""
        echo "正在重启服务..."
        systemctl restart "$AG_PROXY_SERVICE_NAME"

        sleep 2

        if systemctl is-active "$AG_PROXY_SERVICE_NAME" &>/dev/null; then
            echo ""
            echo -e "${gl_lv}✅ 更新完成，服务已重启${gl_bai}"

            # 显示版本信息
            if [ -f "$AG_PROXY_INSTALL_DIR/package.json" ]; then
                local version=$(sed -nE 's/.*"version"[[:space:]]*:[[:space:]]*"([0-9]+\.[0-9]+\.[0-9]+)".*/\1/p' "$AG_PROXY_INSTALL_DIR/package.json" | head -1)
                if [ -n "$version" ]; then
                    echo -e "当前版本: ${gl_huang}v${version}${gl_bai}"
                fi
            fi
        else
            echo -e "${gl_hong}❌ 服务重启失败${gl_bai}"
        fi
    else
        echo -e "${gl_hong}❌ 代码更新失败${gl_bai}"
    fi

    break_end
}

# 查看状态
ag_proxy_status() {
    clear
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo -e "${gl_kjlan}  Antigravity Claude Proxy 服务状态${gl_bai}"
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo ""

    systemctl status "$AG_PROXY_SERVICE_NAME" --no-pager

    echo ""
    break_end
}

# 查看日志
ag_proxy_logs() {
    clear
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo -e "${gl_kjlan}  Antigravity Claude Proxy 日志（按 Ctrl+C 退出）${gl_bai}"
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo ""

    journalctl -u "$AG_PROXY_SERVICE_NAME" -f
}

# 启动服务
ag_proxy_start() {
    echo "正在启动服务..."
    systemctl start "$AG_PROXY_SERVICE_NAME"
    sleep 2

    if systemctl is-active "$AG_PROXY_SERVICE_NAME" &>/dev/null; then
        echo -e "${gl_lv}✅ 服务已启动${gl_bai}"
    else
        echo -e "${gl_hong}❌ 服务启动失败${gl_bai}"
    fi

    break_end
}

# 停止服务
ag_proxy_stop() {
    echo "正在停止服务..."
    systemctl stop "$AG_PROXY_SERVICE_NAME"

    if ! systemctl is-active "$AG_PROXY_SERVICE_NAME" &>/dev/null; then
        echo -e "${gl_lv}✅ 服务已停止${gl_bai}"
    else
        echo -e "${gl_hong}❌ 服务停止失败${gl_bai}"
    fi

    break_end
}

# 重启服务
ag_proxy_restart() {
    echo "正在重启服务..."

    # 检测端口冲突
    local port=$(ag_proxy_get_port)
    local pid=$(ss -lntp 2>/dev/null | grep ":${port} " | sed -nE 's/.*pid=([0-9]+).*/\1/p' | head -1)
    local service_pid=$(systemctl show -p MainPID "$AG_PROXY_SERVICE_NAME" 2>/dev/null | cut -d= -f2)

    # 如果端口被其他进程占用（不是当前服务）
    if [ -n "$pid" ] && [ "$pid" != "$service_pid" ] && [ "$pid" != "0" ]; then
        echo -e "${gl_huang}⚠ 端口 ${port} 被 PID ${pid} 占用，正在释放...${gl_bai}"
        kill "$pid" 2>/dev/null
        sleep 1
        if ss -lntp 2>/dev/null | grep -q ":${port} "; then
            kill -9 "$pid" 2>/dev/null
            sleep 1
        fi
    fi

    systemctl restart "$AG_PROXY_SERVICE_NAME"
    sleep 2

    if systemctl is-active "$AG_PROXY_SERVICE_NAME" &>/dev/null; then
        echo -e "${gl_lv}✅ 服务已重启${gl_bai}"
    else
        echo -e "${gl_hong}❌ 服务重启失败${gl_bai}"
        echo "查看日志: journalctl -u $AG_PROXY_SERVICE_NAME -n 20"
    fi

    break_end
}

# 修改端口
ag_proxy_change_port() {
    clear
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo -e "${gl_kjlan}  修改 Antigravity Claude Proxy 端口${gl_bai}"
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo ""

    local current_port=$(ag_proxy_get_port)
    echo -e "当前端口: ${gl_huang}${current_port}${gl_bai}"
    echo ""

    read -e -p "请输入新端口 (1-65535): " new_port

    # 验证端口
    if ! [[ "$new_port" =~ ^[0-9]+$ ]] || [ "$new_port" -lt 1 ] || [ "$new_port" -gt 65535 ]; then
        echo -e "${gl_hong}❌ 无效的端口号${gl_bai}"
        break_end
        return 1
    fi

    if [ "$new_port" = "$current_port" ]; then
        echo -e "${gl_huang}⚠ 端口未改变${gl_bai}"
        break_end
        return 0
    fi

    # 检查新端口是否被占用
    if ss -lntp 2>/dev/null | grep -q ":${new_port} "; then
        echo -e "${gl_hong}❌ 端口 ${new_port} 已被占用${gl_bai}"
        break_end
        return 1
    fi

    echo ""
    echo "正在修改端口..."

    # 停止服务
    systemctl stop "$AG_PROXY_SERVICE_NAME" 2>/dev/null

    # 更新服务文件
    sed -i "s/Environment=PORT=.*/Environment=PORT=${new_port}/" "$AG_PROXY_SERVICE_FILE"

    # 保存端口配置
    echo "$new_port" > "$AG_PROXY_PORT_FILE"

    # 重新加载并启动
    systemctl daemon-reload
    systemctl start "$AG_PROXY_SERVICE_NAME"

    sleep 2

    if systemctl is-active "$AG_PROXY_SERVICE_NAME" &>/dev/null; then
        local server_ip=$(curl -s4 ip.sb 2>/dev/null || curl -s6 ip.sb 2>/dev/null || echo "服务器IP")
        echo ""
        echo -e "${gl_lv}✅ 端口已修改为 ${new_port}${gl_bai}"
        echo -e "新访问地址: ${gl_huang}http://${server_ip}:${new_port}${gl_bai}"
    else
        echo -e "${gl_hong}❌ 服务启动失败${gl_bai}"
    fi

    break_end
}

# 卸载
ag_proxy_uninstall() {
    clear
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo -e "${gl_hong}  卸载 Antigravity Claude Proxy${gl_bai}"
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo ""
    echo -e "${gl_huang}警告: 此操作将删除服务和所有项目文件！${gl_bai}"
    echo ""

    read -e -p "确认卸载？(输入 yes 确认): " confirm

    if [ "$confirm" != "yes" ]; then
        echo "已取消"
        break_end
        return 0
    fi

    echo ""
    echo "正在停止服务..."
    systemctl stop "$AG_PROXY_SERVICE_NAME" 2>/dev/null
    systemctl disable "$AG_PROXY_SERVICE_NAME" 2>/dev/null

    echo "正在删除服务文件..."
    rm -f "$AG_PROXY_SERVICE_FILE"
    systemctl daemon-reload

    echo "正在删除项目文件..."
    rm -rf "$AG_PROXY_INSTALL_DIR"

    echo ""
    echo -e "${gl_lv}✅ 卸载完成${gl_bai}"

    break_end
}

# Antigravity Claude Proxy 主菜单
manage_ag_proxy() {
    while true; do
        clear
        echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
        echo -e "${gl_kjlan}  Antigravity Claude Proxy 部署管理${gl_bai}"
        echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
        echo ""

        # 显示当前状态
        local status=$(ag_proxy_check_status)
        local port=$(ag_proxy_get_port)

        case "$status" in
            "not_installed")
                echo -e "当前状态: ${gl_huang}⚠️ 未安装${gl_bai}"
                ;;
            "installed_no_service")
                echo -e "当前状态: ${gl_huang}⚠️ 已安装但服务未配置${gl_bai}"
                ;;
            "running")
                echo -e "当前状态: ${gl_lv}✅ 运行中${gl_bai} (端口: ${port})"
                ;;
            "stopped")
                echo -e "当前状态: ${gl_hong}❌ 已停止${gl_bai}"
                ;;
        esac

        echo ""
        echo -e "${gl_kjlan}[部署与更新]${gl_bai}"
        echo "1. 一键部署（首次安装）"
        echo "2. 更新项目"
        echo ""
        echo -e "${gl_kjlan}[服务管理]${gl_bai}"
        echo "3. 查看状态"
        echo "4. 查看日志"
        echo "5. 启动服务"
        echo "6. 停止服务"
        echo "7. 重启服务"
        echo ""
        echo -e "${gl_kjlan}[配置与卸载]${gl_bai}"
        echo "8. 修改端口"
        echo -e "${gl_hong}9. 卸载（删除服务+代码）${gl_bai}"
        echo ""
        echo -e "${gl_kjlan}[帮助]${gl_bai}"
        echo "10. 查看 Claude Code 配置指引"
        echo ""
        echo "0. 返回主菜单"
        echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"

        read -e -p "请选择操作 [0-10]: " choice

        case $choice in
            1)
                ag_proxy_deploy
                ;;
            2)
                ag_proxy_update
                ;;
            3)
                ag_proxy_status
                ;;
            4)
                ag_proxy_logs
                ;;
            5)
                ag_proxy_start
                ;;
            6)
                ag_proxy_stop
                ;;
            7)
                ag_proxy_restart
                ;;
            8)
                ag_proxy_change_port
                ;;
            9)
                ag_proxy_uninstall
                ;;
            10)
                ag_proxy_show_config
                ;;
            0)
                return
                ;;
            *)
                echo "无效的选择"
                sleep 2
                ;;
        esac
    done
}

# =====================================================
# Open WebUI 部署管理 (菜单40)
# =====================================================

# 常量定义
OPEN_WEBUI_CONTAINER_NAME="open-webui"
OPEN_WEBUI_IMAGE="ghcr.io/open-webui/open-webui:main"
OPEN_WEBUI_DEFAULT_PORT="8888"
OPEN_WEBUI_PORT_FILE="/etc/open-webui-port"

# 获取当前配置的端口
open_webui_get_port() {
    if [ -f "$OPEN_WEBUI_PORT_FILE" ]; then
        cat "$OPEN_WEBUI_PORT_FILE"
    else
        echo "$OPEN_WEBUI_DEFAULT_PORT"
    fi
}

# 检查 Open WebUI 状态
open_webui_check_status() {
    if docker ps --format '{{.Names}}' 2>/dev/null | grep -q "^${OPEN_WEBUI_CONTAINER_NAME}$"; then
        echo "running"
    elif docker ps -a --format '{{.Names}}' 2>/dev/null | grep -q "^${OPEN_WEBUI_CONTAINER_NAME}$"; then
        echo "stopped"
    else
        echo "not_installed"
    fi
}

# 检查端口是否可用
open_webui_check_port() {
    local port=$1
    if ss -lntp 2>/dev/null | grep -q ":${port} "; then
        return 1
    fi
    return 0
}

# 安装 Docker
open_webui_install_docker() {
    if command -v docker &>/dev/null; then
        echo -e "${gl_lv}✅ Docker 已安装${gl_bai}"
        return 0
    fi

    echo "正在安装 Docker..."
    # 使用安全下载模式替代 curl | sh
    run_remote_script "https://get.docker.com" sh

    if [ $? -eq 0 ]; then
        systemctl enable docker
        systemctl start docker
        echo -e "${gl_lv}✅ Docker 安装成功${gl_bai}"
        return 0
    else
        echo -e "${gl_hong}❌ Docker 安装失败${gl_bai}"
        return 1
    fi
}

# 一键部署
open_webui_deploy() {
    clear
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo -e "${gl_kjlan}  一键部署 Open WebUI${gl_bai}"
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo ""

    # 检查是否已安装
    local status=$(open_webui_check_status)
    if [ "$status" != "not_installed" ]; then
        echo -e "${gl_huang}⚠️ Open WebUI 已安装${gl_bai}"
        read -e -p "是否重新部署？(y/n) [n]: " reinstall
        if [ "$reinstall" != "y" ] && [ "$reinstall" != "Y" ]; then
            break_end
            return 0
        fi
        # 删除现有容器
        docker stop "$OPEN_WEBUI_CONTAINER_NAME" 2>/dev/null
        docker rm "$OPEN_WEBUI_CONTAINER_NAME" 2>/dev/null
    fi

    # 安装 Docker
    echo ""
    open_webui_install_docker || { break_end; return 1; }

    # 配置端口
    echo ""
    local port="$OPEN_WEBUI_DEFAULT_PORT"
    read -e -p "请输入访问端口 [$OPEN_WEBUI_DEFAULT_PORT]: " input_port
    if [ -n "$input_port" ]; then
        port="$input_port"
    fi

    # 检查端口是否可用
    while ! open_webui_check_port "$port"; do
        echo -e "${gl_hong}⚠️ 端口 $port 已被占用，请换一个${gl_bai}"
        read -e -p "请输入访问端口: " port
    done
    echo -e "${gl_lv}✅ 端口 $port 可用${gl_bai}"

    # 询问是否配置 API
    echo ""
    local api_url=""
    local api_key=""
    read -e -p "是否现在配置 API？(y/n) [y]: " config_api
    if [ "$config_api" != "n" ] && [ "$config_api" != "N" ]; then
        echo ""
        echo "API 类型："
        echo "1. OpenAI 官方"
        echo "2. 自定义地址（反代/中转）"
        echo ""
        read -e -p "请选择 [1]: " api_type

        if [ "$api_type" = "2" ]; then
            read -e -p "请输入 API 地址: " api_url
            read -e -p "请输入 API 密钥: " api_key
        else
            api_url="https://api.openai.com/v1"
            read -e -p "请输入 OpenAI API 密钥: " api_key
        fi
    fi

    # 拉取镜像
    echo ""
    echo "正在拉取 Open WebUI 镜像..."
    docker pull "$OPEN_WEBUI_IMAGE"

    if [ $? -ne 0 ]; then
        echo -e "${gl_hong}❌ 镜像拉取失败${gl_bai}"
        break_end
        return 1
    fi

    # 启动容器
    echo ""
    echo "正在启动 Open WebUI..."

    # 停止并删除可能存在的旧容器
    docker stop "$OPEN_WEBUI_CONTAINER_NAME" 2>/dev/null
    docker rm "$OPEN_WEBUI_CONTAINER_NAME" 2>/dev/null

    # 根据是否有 API 配置选择不同的启动方式
    if [ -n "$api_url" ] && [ -n "$api_key" ]; then
        docker run -d -p ${port}:8080 \
            --add-host=host.docker.internal:host-gateway \
            -e OPENAI_API_BASE_URL="$api_url" \
            -e OPENAI_API_KEY="$api_key" \
            -v open-webui:/app/backend/data \
            --name "$OPEN_WEBUI_CONTAINER_NAME" \
            --restart always \
            "$OPEN_WEBUI_IMAGE"
    elif [ -n "$api_key" ]; then
        docker run -d -p ${port}:8080 \
            --add-host=host.docker.internal:host-gateway \
            -e OPENAI_API_KEY="$api_key" \
            -v open-webui:/app/backend/data \
            --name "$OPEN_WEBUI_CONTAINER_NAME" \
            --restart always \
            "$OPEN_WEBUI_IMAGE"
    else
        docker run -d -p ${port}:8080 \
            --add-host=host.docker.internal:host-gateway \
            -v open-webui:/app/backend/data \
            --name "$OPEN_WEBUI_CONTAINER_NAME" \
            --restart always \
            "$OPEN_WEBUI_IMAGE"
    fi

    if [ $? -ne 0 ]; then
        echo -e "${gl_hong}❌ 容器启动失败${gl_bai}"
        break_end
        return 1
    fi

    # 保存端口配置
    echo "$port" > "$OPEN_WEBUI_PORT_FILE"

    # 等待启动
    echo ""
    echo "等待服务启动..."
    sleep 5

    # 获取服务器 IP
    local server_ip=$(curl -s4 ip.sb 2>/dev/null || curl -s6 ip.sb 2>/dev/null || echo "服务器IP")

    echo ""
    echo -e "${gl_lv}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo -e "${gl_lv}  ✅ 部署完成！${gl_bai}"
    echo -e "${gl_lv}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo ""
    echo -e "访问地址: ${gl_huang}http://${server_ip}:${port}${gl_bai}"
    echo ""
    echo -e "${gl_zi}首次访问需要注册管理员账户${gl_bai}"
    echo ""
    if [ -z "$api_url" ]; then
        echo -e "${gl_huang}提示: API 未配置，请在网页 Admin Panel → Settings → Connections 中设置${gl_bai}"
        echo ""
    fi
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo -e "${gl_kjlan}管理命令:${gl_bai}"
    echo "  状态: docker ps | grep $OPEN_WEBUI_CONTAINER_NAME"
    echo "  日志: docker logs $OPEN_WEBUI_CONTAINER_NAME -f"
    echo "  重启: docker restart $OPEN_WEBUI_CONTAINER_NAME"
    echo ""

    break_end
}

# 更新镜像
open_webui_update() {
    clear
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo -e "${gl_kjlan}  更新 Open WebUI${gl_bai}"
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo ""

    local status=$(open_webui_check_status)
    if [ "$status" = "not_installed" ]; then
        echo -e "${gl_hong}❌ Open WebUI 未安装，请先执行一键部署${gl_bai}"
        break_end
        return 1
    fi

    echo "正在拉取最新镜像..."
    docker pull "$OPEN_WEBUI_IMAGE"

    if [ $? -eq 0 ]; then
        echo ""
        echo "正在重启容器..."
        docker stop "$OPEN_WEBUI_CONTAINER_NAME"
        docker rm "$OPEN_WEBUI_CONTAINER_NAME"

        # 获取保存的端口
        local port=$(open_webui_get_port)

        # 重新创建容器
        docker run -d -p ${port}:8080 \
            --add-host=host.docker.internal:host-gateway \
            -v open-webui:/app/backend/data \
            --name "$OPEN_WEBUI_CONTAINER_NAME" \
            --restart always \
            "$OPEN_WEBUI_IMAGE"

        if [ $? -eq 0 ]; then
            echo ""
            echo -e "${gl_lv}✅ 更新完成${gl_bai}"
        else
            echo -e "${gl_hong}❌ 重启失败${gl_bai}"
        fi
    else
        echo -e "${gl_hong}❌ 镜像拉取失败${gl_bai}"
    fi

    break_end
}

# 查看状态
open_webui_status() {
    clear
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo -e "${gl_kjlan}  Open WebUI 状态${gl_bai}"
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo ""

    local status=$(open_webui_check_status)
    local port=$(open_webui_get_port)
    local server_ip=$(curl -s4 ip.sb 2>/dev/null || curl -s6 ip.sb 2>/dev/null || echo "服务器IP")

    case "$status" in
        "running")
            echo -e "状态: ${gl_lv}✅ 运行中${gl_bai}"
            echo -e "端口: ${gl_huang}$port${gl_bai}"
            echo -e "访问地址: ${gl_huang}http://${server_ip}:${port}${gl_bai}"
            echo ""
            echo "容器详情:"
            docker ps --filter "name=$OPEN_WEBUI_CONTAINER_NAME" --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
            ;;
        "stopped")
            echo -e "状态: ${gl_hong}❌ 已停止${gl_bai}"
            echo ""
            echo "请使用「启动服务」选项启动"
            ;;
        "not_installed")
            echo -e "状态: ${gl_hui}未安装${gl_bai}"
            echo ""
            echo "请使用「一键部署」选项安装"
            ;;
    esac

    echo ""
    break_end
}

# 查看日志
open_webui_logs() {
    clear
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo -e "${gl_kjlan}  Open WebUI 日志${gl_bai}"
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo ""
    echo -e "${gl_zi}按 Ctrl+C 退出日志查看${gl_bai}"
    echo ""

    docker logs "$OPEN_WEBUI_CONTAINER_NAME" -f --tail 100
}

# 启动服务
open_webui_start() {
    echo ""
    echo "正在启动 Open WebUI..."
    docker start "$OPEN_WEBUI_CONTAINER_NAME"

    if [ $? -eq 0 ]; then
        echo -e "${gl_lv}✅ 启动成功${gl_bai}"
    else
        echo -e "${gl_hong}❌ 启动失败${gl_bai}"
    fi

    sleep 2
}

# 停止服务
open_webui_stop() {
    echo ""
    echo "正在停止 Open WebUI..."
    docker stop "$OPEN_WEBUI_CONTAINER_NAME"

    if [ $? -eq 0 ]; then
        echo -e "${gl_lv}✅ 已停止${gl_bai}"
    else
        echo -e "${gl_hong}❌ 停止失败${gl_bai}"
    fi

    sleep 2
}

# 重启服务
open_webui_restart() {
    echo ""
    echo "正在重启 Open WebUI..."
    docker restart "$OPEN_WEBUI_CONTAINER_NAME"

    if [ $? -eq 0 ]; then
        echo -e "${gl_lv}✅ 重启成功${gl_bai}"
    else
        echo -e "${gl_hong}❌ 重启失败${gl_bai}"
    fi

    sleep 2
}

# 修改端口
open_webui_change_port() {
    clear
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo -e "${gl_kjlan}  修改 Open WebUI 端口${gl_bai}"
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo ""

    local status=$(open_webui_check_status)
    if [ "$status" = "not_installed" ]; then
        echo -e "${gl_hong}❌ Open WebUI 未安装${gl_bai}"
        break_end
        return 1
    fi

    local current_port=$(open_webui_get_port)
    echo -e "当前端口: ${gl_huang}$current_port${gl_bai}"
    echo ""

    read -e -p "请输入新端口: " new_port

    if [ -z "$new_port" ]; then
        echo "未输入端口，取消修改"
        break_end
        return 0
    fi

    # 检查端口是否可用
    if ! open_webui_check_port "$new_port"; then
        echo -e "${gl_hong}❌ 端口 $new_port 已被占用${gl_bai}"
        break_end
        return 1
    fi

    echo ""
    echo "正在修改端口..."

    # 停止并删除旧容器
    docker stop "$OPEN_WEBUI_CONTAINER_NAME"
    docker rm "$OPEN_WEBUI_CONTAINER_NAME"

    # 用新端口创建容器
    docker run -d -p ${new_port}:8080 \
        --add-host=host.docker.internal:host-gateway \
        -v open-webui:/app/backend/data \
        --name "$OPEN_WEBUI_CONTAINER_NAME" \
        --restart always \
        "$OPEN_WEBUI_IMAGE"

    if [ $? -eq 0 ]; then
        echo "$new_port" > "$OPEN_WEBUI_PORT_FILE"
        local server_ip=$(curl -s4 ip.sb 2>/dev/null || curl -s6 ip.sb 2>/dev/null || echo "服务器IP")
        echo ""
        echo -e "${gl_lv}✅ 端口修改成功${gl_bai}"
        echo -e "新访问地址: ${gl_huang}http://${server_ip}:${new_port}${gl_bai}"
    else
        echo -e "${gl_hong}❌ 端口修改失败${gl_bai}"
    fi

    break_end
}

# 卸载
open_webui_uninstall() {
    clear
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo -e "${gl_kjlan}  卸载 Open WebUI${gl_bai}"
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo ""

    local status=$(open_webui_check_status)
    if [ "$status" = "not_installed" ]; then
        echo -e "${gl_hong}❌ Open WebUI 未安装${gl_bai}"
        break_end
        return 1
    fi

    echo -e "${gl_hong}⚠️ 此操作将删除 Open WebUI 容器${gl_bai}"
    echo ""
    read -e -p "是否同时删除数据卷？(y/n) [n]: " delete_volume
    echo ""
    read -e -p "确认卸载？(y/n) [n]: " confirm

    if [ "$confirm" != "y" ] && [ "$confirm" != "Y" ]; then
        echo "取消卸载"
        break_end
        return 0
    fi

    echo ""
    echo "正在卸载..."

    # 停止并删除容器
    docker stop "$OPEN_WEBUI_CONTAINER_NAME" 2>/dev/null
    docker rm "$OPEN_WEBUI_CONTAINER_NAME" 2>/dev/null

    # 删除数据卷
    if [ "$delete_volume" = "y" ] || [ "$delete_volume" = "Y" ]; then
        docker volume rm open-webui 2>/dev/null
        echo -e "${gl_lv}✅ 容器和数据已删除${gl_bai}"
    else
        echo -e "${gl_lv}✅ 容器已删除，数据保留${gl_bai}"
    fi

    # 删除端口配置文件
    rm -f "$OPEN_WEBUI_PORT_FILE"

    break_end
}

# Open WebUI 管理主菜单
manage_open_webui() {
    while true; do
        clear
        echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
        echo -e "${gl_kjlan}  Open WebUI 部署管理${gl_bai}"
        echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
        echo ""

        # 显示当前状态
        local status=$(open_webui_check_status)
        local port=$(open_webui_get_port)

        case "$status" in
            "running")
                echo -e "当前状态: ${gl_lv}✅ 运行中${gl_bai} (端口: $port)"
                ;;
            "stopped")
                echo -e "当前状态: ${gl_hong}❌ 已停止${gl_bai}"
                ;;
            "not_installed")
                echo -e "当前状态: ${gl_hui}未安装${gl_bai}"
                ;;
        esac

        echo ""
        echo -e "${gl_kjlan}[部署与更新]${gl_bai}"
        echo "1. 一键部署（首次安装）"
        echo "2. 更新镜像"
        echo ""
        echo -e "${gl_kjlan}[服务管理]${gl_bai}"
        echo "3. 查看状态"
        echo "4. 查看日志"
        echo "5. 启动服务"
        echo "6. 停止服务"
        echo "7. 重启服务"
        echo ""
        echo -e "${gl_kjlan}[配置与卸载]${gl_bai}"
        echo "8. 修改端口"
        echo -e "${gl_hong}9. 卸载（删除容器）${gl_bai}"
        echo ""
        echo "0. 返回主菜单"
        echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"

        read -e -p "请选择操作 [0-9]: " choice

        case $choice in
            1)
                open_webui_deploy
                ;;
            2)
                open_webui_update
                ;;
            3)
                open_webui_status
                ;;
            4)
                open_webui_logs
                ;;
            5)
                open_webui_start
                ;;
            6)
                open_webui_stop
                ;;
            7)
                open_webui_restart
                ;;
            8)
                open_webui_change_port
                ;;
            9)
                open_webui_uninstall
                ;;
            0)
                return
                ;;
            *)
                echo "无效的选择"
                sleep 2
                ;;
        esac
    done
}

# =====================================================
# Claude Relay Service (CRS) 部署管理 (菜单41)
# =====================================================

# 常量定义
CRS_DEFAULT_PORT="3000"
CRS_PORT_FILE="/etc/crs-port"
CRS_INSTALL_DIR_FILE="/etc/crs-install-dir"
CRS_DEFAULT_INSTALL_DIR="/root/claude-relay-service"
CRS_MANAGE_SCRIPT_URL="https://pincc.ai/manage.sh"

# 获取安装目录
crs_get_install_dir() {
    if [ -f "$CRS_INSTALL_DIR_FILE" ]; then
        cat "$CRS_INSTALL_DIR_FILE"
    else
        echo "$CRS_DEFAULT_INSTALL_DIR"
    fi
}

# 获取当前配置的端口
crs_get_port() {
    if [ -f "$CRS_PORT_FILE" ]; then
        cat "$CRS_PORT_FILE"
    else
        # 尝试从配置文件读取
        local install_dir=$(crs_get_install_dir)
        if [ -f "$install_dir/config/config.js" ]; then
            local port=$(sed -nE 's/.*port:[[:space:]]*([0-9]+).*/\1/p' "$install_dir/config/config.js" 2>/dev/null | head -1)
            if [ -n "$port" ]; then
                echo "$port"
                return
            fi
        fi
        echo "$CRS_DEFAULT_PORT"
    fi
}

# 检查 CRS 状态
crs_check_status() {
    # 检查 crs 命令是否存在
    if ! command -v crs &>/dev/null; then
        # 检查安装目录是否存在
        local install_dir=$(crs_get_install_dir)
        if [ -d "$install_dir" ]; then
            echo "installed_no_command"
        else
            echo "not_installed"
        fi
        return
    fi

    # 使用 crs status 检查
    local status_output=$(crs status 2>&1)
    if echo "$status_output" | grep -qi "running\|online\|started"; then
        echo "running"
    elif echo "$status_output" | grep -qi "stopped\|offline\|not running"; then
        echo "stopped"
    else
        # 通过端口检测
        local port=$(crs_get_port)
        if ss -lntp 2>/dev/null | grep -q ":${port} "; then
            echo "running"
        else
            echo "stopped"
        fi
    fi
}

# 检查端口是否可用
crs_check_port() {
    local port=$1
    if ss -lntp 2>/dev/null | grep -q ":${port} "; then
        return 1
    fi
    return 0
}

# 一键部署
crs_deploy() {
    clear
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo -e "${gl_kjlan}  一键部署 Claude Relay Service (CRS)${gl_bai}"
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo ""

    # 检查是否已安装
    local status=$(crs_check_status)
    if [ "$status" != "not_installed" ]; then
        echo -e "${gl_huang}⚠️ CRS 已安装${gl_bai}"
        read -e -p "是否重新部署？这将保留数据但重装服务 (y/n) [n]: " reinstall
        if [ "$reinstall" != "y" ] && [ "$reinstall" != "Y" ]; then
            break_end
            return 0
        fi
        echo ""
        echo "正在停止现有服务..."
        crs stop 2>/dev/null
    fi

    echo ""
    echo -e "${gl_kjlan}[1/4] 下载安装脚本...${gl_bai}"

    # 创建临时目录
    local temp_dir=$(mktemp -d)
    cd "$temp_dir" || { echo -e "${gl_hong}❌ 创建临时目录失败${gl_bai}"; break_end; return 1; }

    # 下载 manage.sh
    if ! curl -fsSL "$CRS_MANAGE_SCRIPT_URL" -o manage.sh; then
        echo -e "${gl_hong}❌ 下载安装脚本失败${gl_bai}"
        rm -rf "$temp_dir"
        break_end
        return 1
    fi
    chmod +x manage.sh
    echo -e "${gl_lv}✅ 下载完成${gl_bai}"

    echo ""
    echo -e "${gl_kjlan}[2/4] 配置安装参数...${gl_bai}"
    echo ""

    # 安装目录
    local install_dir="$CRS_DEFAULT_INSTALL_DIR"
    read -e -p "安装目录 [$CRS_DEFAULT_INSTALL_DIR]: " input_dir
    if [ -n "$input_dir" ]; then
        install_dir="$input_dir"
    fi

    # 端口配置
    local port="$CRS_DEFAULT_PORT"
    read -e -p "服务端口 [$CRS_DEFAULT_PORT]: " input_port
    if [ -n "$input_port" ]; then
        port="$input_port"
    fi

    # 检查端口是否可用
    while ! crs_check_port "$port"; do
        echo -e "${gl_hong}⚠️ 端口 $port 已被占用${gl_bai}"
        read -e -p "请输入其他端口: " port
        if [ -z "$port" ]; then
            port="$CRS_DEFAULT_PORT"
        fi
    done
    echo -e "${gl_lv}✅ 端口 $port 可用${gl_bai}"

    # Redis 配置
    echo ""
    local redis_host="localhost"
    local redis_port="6379"
    local redis_password=""

    read -e -p "Redis 地址 [localhost]: " input_redis_host
    if [ -n "$input_redis_host" ]; then
        redis_host="$input_redis_host"
    fi

    read -e -p "Redis 端口 [6379]: " input_redis_port
    if [ -n "$input_redis_port" ]; then
        redis_port="$input_redis_port"
    fi

    read -e -p "Redis 密码 (无密码直接回车): " redis_password

    echo ""
    echo -e "${gl_kjlan}[3/4] 执行安装...${gl_bai}"
    echo ""
    echo "安装目录: $install_dir"
    echo "服务端口: $port"
    echo "Redis: $redis_host:$redis_port"
    echo ""

    # 使用 expect 或直接执行安装（通过环境变量传递参数）
    # CRS 的 manage.sh 支持交互式安装，这里我们传递参数
    export CRS_INSTALL_DIR="$install_dir"
    export CRS_PORT="$port"
    export CRS_REDIS_HOST="$redis_host"
    export CRS_REDIS_PORT="$redis_port"
    export CRS_REDIS_PASSWORD="$redis_password"

    # 执行安装脚本
    echo ""
    echo -e "${gl_huang}正在安装，请按提示操作...${gl_bai}"
    echo -e "${gl_zi}（安装目录输入: $install_dir，端口输入: $port）${gl_bai}"
    echo ""

    ./manage.sh install

    local install_result=$?

    # 清理临时文件
    cd /
    rm -rf "$temp_dir"

    if [ $install_result -ne 0 ]; then
        echo ""
        echo -e "${gl_hong}❌ 安装过程出现错误${gl_bai}"
        break_end
        return 1
    fi

    # 保存配置
    echo "$port" > "$CRS_PORT_FILE"
    echo "$install_dir" > "$CRS_INSTALL_DIR_FILE"

    echo ""
    echo -e "${gl_kjlan}[4/4] 验证安装...${gl_bai}"

    sleep 3

    # 获取服务器 IP
    local server_ip=$(curl -s4 ip.sb 2>/dev/null || curl -s6 ip.sb 2>/dev/null || echo "服务器IP")

    # 检查服务状态
    if command -v crs &>/dev/null; then
        echo -e "${gl_lv}✅ crs 命令已安装${gl_bai}"
    fi

    echo ""
    echo -e "${gl_lv}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo -e "${gl_lv}  ✅ 部署完成！${gl_bai}"
    echo -e "${gl_lv}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo ""
    echo -e "Web 管理面板: ${gl_huang}http://${server_ip}:${port}/web${gl_bai}"
    echo ""
    echo -e "${gl_kjlan}【管理员账号】${gl_bai}"
    echo "  账号信息保存在: $install_dir/data/init.json"
    echo "  使用菜单「8. 查看管理员账号」可以直接查看"
    echo ""
    echo -e "${gl_kjlan}【下一步操作】${gl_bai}"
    echo "  1. 访问 Web 面板，使用管理员账号登录"
    echo "  2. 添加 Claude 账户（OAuth 授权）"
    echo "  3. 创建 API Key 分发给用户"
    echo "  4. 配置本地 Claude Code 环境变量"
    echo ""
    echo -e "${gl_kjlan}【Claude Code 配置】${gl_bai}"
    echo -e "  ${gl_huang}export ANTHROPIC_BASE_URL=\"http://${server_ip}:${port}/api/\"${gl_bai}"
    echo -e "  ${gl_huang}export ANTHROPIC_AUTH_TOKEN=\"后台创建的API密钥\"${gl_bai}"
    echo ""
    echo -e "${gl_zi}提示: 使用菜单「10. 查看配置指引」获取完整配置说明${gl_bai}"
    echo ""
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo -e "${gl_kjlan}管理命令:${gl_bai}"
    echo "  状态: crs status"
    echo "  启动: crs start"
    echo "  停止: crs stop"
    echo "  重启: crs restart"
    echo "  更新: crs update"
    echo ""

    break_end
}

# 更新服务
crs_update() {
    clear
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo -e "${gl_kjlan}  更新 Claude Relay Service${gl_bai}"
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo ""

    local status=$(crs_check_status)
    if [ "$status" = "not_installed" ]; then
        echo -e "${gl_hong}❌ CRS 未安装，请先执行一键部署${gl_bai}"
        break_end
        return 1
    fi

    echo "正在更新..."
    echo ""

    if command -v crs &>/dev/null; then
        crs update
        if [ $? -eq 0 ]; then
            echo ""
            echo -e "${gl_lv}✅ 更新完成${gl_bai}"
        else
            echo ""
            echo -e "${gl_hong}❌ 更新失败${gl_bai}"
        fi
    else
        echo -e "${gl_hong}❌ crs 命令不可用，请重新部署${gl_bai}"
    fi

    break_end
}

# 查看状态
crs_status() {
    clear
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo -e "${gl_kjlan}  Claude Relay Service 状态${gl_bai}"
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo ""

    local status=$(crs_check_status)
    local port=$(crs_get_port)
    local server_ip=$(curl -s4 ip.sb 2>/dev/null || curl -s6 ip.sb 2>/dev/null || echo "服务器IP")
    local install_dir=$(crs_get_install_dir)

    case "$status" in
        "running")
            echo -e "运行状态: ${gl_lv}✅ 运行中${gl_bai}"
            echo -e "服务端口: ${gl_huang}$port${gl_bai}"
            echo -e "Web 面板: ${gl_huang}http://${server_ip}:${port}/web${gl_bai}"
            echo -e "安装目录: ${gl_huang}$install_dir${gl_bai}"
            ;;
        "stopped")
            echo -e "运行状态: ${gl_hong}❌ 已停止${gl_bai}"
            echo -e "服务端口: ${gl_huang}$port${gl_bai}"
            echo -e "安装目录: ${gl_huang}$install_dir${gl_bai}"
            ;;
        "installed_no_command")
            echo -e "运行状态: ${gl_huang}⚠️ 已安装但 crs 命令不可用${gl_bai}"
            echo -e "安装目录: ${gl_huang}$install_dir${gl_bai}"
            echo ""
            echo "建议重新执行一键部署"
            ;;
        "not_installed")
            echo -e "运行状态: ${gl_hui}未安装${gl_bai}"
            echo ""
            echo "请使用「一键部署」选项安装"
            ;;
    esac

    echo ""

    # 如果 crs 命令可用，显示详细状态
    if command -v crs &>/dev/null && [ "$status" != "not_installed" ]; then
        echo -e "${gl_kjlan}详细状态:${gl_bai}"
        echo ""
        crs status
    fi

    echo ""
    break_end
}

# 查看日志
crs_logs() {
    clear
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo -e "${gl_kjlan}  Claude Relay Service 日志${gl_bai}"
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo ""
    echo -e "${gl_zi}按 Ctrl+C 退出日志查看${gl_bai}"
    echo ""

    local status=$(crs_check_status)
    if [ "$status" = "not_installed" ]; then
        echo -e "${gl_hong}❌ CRS 未安装${gl_bai}"
        break_end
        return 1
    fi

    if command -v crs &>/dev/null; then
        crs logs
    else
        # 尝试查看日志文件
        local install_dir=$(crs_get_install_dir)
        if [ -d "$install_dir/logs" ]; then
            tail -f "$install_dir/logs/"*.log 2>/dev/null || echo "无法读取日志文件"
        else
            echo "日志目录不存在"
        fi
    fi
}

# 启动服务
crs_start() {
    echo ""
    echo "正在启动 CRS..."

    local status=$(crs_check_status)
    if [ "$status" = "not_installed" ]; then
        echo -e "${gl_hong}❌ CRS 未安装${gl_bai}"
        break_end
        return 1
    fi

    if command -v crs &>/dev/null; then
        crs start
        sleep 2
        if [ "$(crs_check_status)" = "running" ]; then
            local port=$(crs_get_port)
            local server_ip=$(curl -s4 ip.sb 2>/dev/null || curl -s6 ip.sb 2>/dev/null || echo "服务器IP")
            echo ""
            echo -e "${gl_lv}✅ 服务已启动${gl_bai}"
            echo -e "访问地址: ${gl_huang}http://${server_ip}:${port}/web${gl_bai}"
        else
            echo -e "${gl_hong}❌ 启动失败${gl_bai}"
        fi
    else
        echo -e "${gl_hong}❌ crs 命令不可用${gl_bai}"
    fi

    break_end
}

# 停止服务
crs_stop() {
    echo ""
    echo "正在停止 CRS..."

    local status=$(crs_check_status)
    if [ "$status" = "not_installed" ]; then
        echo -e "${gl_hong}❌ CRS 未安装${gl_bai}"
        break_end
        return 1
    fi

    if command -v crs &>/dev/null; then
        crs stop
        sleep 2
        if [ "$(crs_check_status)" != "running" ]; then
            echo -e "${gl_lv}✅ 服务已停止${gl_bai}"
        else
            echo -e "${gl_hong}❌ 停止失败${gl_bai}"
        fi
    else
        echo -e "${gl_hong}❌ crs 命令不可用${gl_bai}"
    fi

    break_end
}

# 重启服务
crs_restart() {
    echo ""
    echo "正在重启 CRS..."

    local status=$(crs_check_status)
    if [ "$status" = "not_installed" ]; then
        echo -e "${gl_hong}❌ CRS 未安装${gl_bai}"
        break_end
        return 1
    fi

    if command -v crs &>/dev/null; then
        crs restart
        sleep 2
        if [ "$(crs_check_status)" = "running" ]; then
            local port=$(crs_get_port)
            local server_ip=$(curl -s4 ip.sb 2>/dev/null || curl -s6 ip.sb 2>/dev/null || echo "服务器IP")
            echo ""
            echo -e "${gl_lv}✅ 服务已重启${gl_bai}"
            echo -e "访问地址: ${gl_huang}http://${server_ip}:${port}/web${gl_bai}"
        else
            echo -e "${gl_hong}❌ 重启失败${gl_bai}"
        fi
    else
        echo -e "${gl_hong}❌ crs 命令不可用${gl_bai}"
    fi

    break_end
}

# 查看管理员账号
crs_show_admin() {
    clear
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo -e "${gl_kjlan}  CRS 管理员账号${gl_bai}"
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo ""

    local status=$(crs_check_status)
    if [ "$status" = "not_installed" ]; then
        echo -e "${gl_hong}❌ CRS 未安装${gl_bai}"
        break_end
        return 1
    fi

    local install_dir=$(crs_get_install_dir)
    local init_file="$install_dir/data/init.json"

    if [ -f "$init_file" ]; then
        echo -e "${gl_lv}管理员账号信息:${gl_bai}"
        echo ""

        # 解析 JSON 并显示
        local username=$(sed -nE 's/.*"username"[[:space:]]*:[[:space:]]*"([^"]+)".*/\1/p' "$init_file" 2>/dev/null | head -1)
        local password=$(sed -nE 's/.*"password"[[:space:]]*:[[:space:]]*"([^"]+)".*/\1/p' "$init_file" 2>/dev/null | head -1)

        if [ -n "$username" ] && [ -n "$password" ]; then
            local port=$(crs_get_port)
            local server_ip=$(curl -s4 ip.sb 2>/dev/null || curl -s6 ip.sb 2>/dev/null || echo "服务器IP")

            echo -e "  用户名: ${gl_huang}$username${gl_bai}"
            echo -e "  密  码: ${gl_huang}$password${gl_bai}"
            echo ""
            echo -e "  登录地址: ${gl_huang}http://${server_ip}:${port}/web${gl_bai}"
        else
            echo "无法解析账号信息，原始内容:"
            echo ""
            cat "$init_file"
        fi
    else
        echo -e "${gl_huang}⚠️ 未找到账号信息文件${gl_bai}"
        echo ""
        echo "文件路径: $init_file"
        echo ""
        echo "可能原因:"
        echo "  1. 服务尚未完成初始化"
        echo "  2. 使用了环境变量预设账号"
        echo ""
        echo "如果使用环境变量设置了账号，请查看安装时的配置"
    fi

    echo ""
    break_end
}

# 修改端口
crs_change_port() {
    clear
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo -e "${gl_kjlan}  修改 CRS 端口${gl_bai}"
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo ""

    local status=$(crs_check_status)
    if [ "$status" = "not_installed" ]; then
        echo -e "${gl_hong}❌ CRS 未安装${gl_bai}"
        break_end
        return 1
    fi

    local current_port=$(crs_get_port)
    local install_dir=$(crs_get_install_dir)
    echo -e "当前端口: ${gl_huang}$current_port${gl_bai}"
    echo ""

    read -e -p "请输入新端口 (1-65535): " new_port

    # 验证端口
    if ! [[ "$new_port" =~ ^[0-9]+$ ]] || [ "$new_port" -lt 1 ] || [ "$new_port" -gt 65535 ]; then
        echo -e "${gl_hong}❌ 无效的端口号${gl_bai}"
        break_end
        return 1
    fi

    if [ "$new_port" = "$current_port" ]; then
        echo -e "${gl_huang}⚠️ 端口未改变${gl_bai}"
        break_end
        return 0
    fi

    # 检查端口是否被占用
    if ! crs_check_port "$new_port"; then
        echo -e "${gl_hong}❌ 端口 $new_port 已被占用${gl_bai}"
        break_end
        return 1
    fi

    echo ""
    echo "正在修改端口..."

    # 停止服务
    if command -v crs &>/dev/null; then
        crs stop 2>/dev/null
    fi

    # 修改配置文件
    local config_file="$install_dir/config/config.js"
    if [ -f "$config_file" ]; then
        # 使用 sed 修改端口
        sed -i "s/port:\s*[0-9]\+/port: $new_port/" "$config_file"
        echo -e "${gl_lv}✅ 配置文件已更新${gl_bai}"
    else
        echo -e "${gl_huang}⚠️ 配置文件不存在，仅更新端口记录${gl_bai}"
    fi

    # 保存端口配置
    echo "$new_port" > "$CRS_PORT_FILE"

    # 重启服务
    if command -v crs &>/dev/null; then
        crs start
        sleep 2

        if [ "$(crs_check_status)" = "running" ]; then
            local server_ip=$(curl -s4 ip.sb 2>/dev/null || curl -s6 ip.sb 2>/dev/null || echo "服务器IP")
            echo ""
            echo -e "${gl_lv}✅ 端口已修改为 $new_port${gl_bai}"
            echo -e "新访问地址: ${gl_huang}http://${server_ip}:${new_port}/web${gl_bai}"
        else
            echo -e "${gl_hong}❌ 服务启动失败，请检查配置${gl_bai}"
        fi
    fi

    break_end
}

# 查看配置指引
crs_show_config() {
    clear

    local status=$(crs_check_status)
    if [ "$status" = "not_installed" ]; then
        echo -e "${gl_hong}❌ CRS 未安装，请先执行一键部署${gl_bai}"
        break_end
        return 1
    fi

    local port=$(crs_get_port)
    local server_ip=$(curl -s4 ip.sb 2>/dev/null || curl -s6 ip.sb 2>/dev/null || echo "服务器IP")

    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo -e "${gl_kjlan}  Claude Relay Service 配置指引${gl_bai}"
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo ""
    echo -e "Web 管理面板: ${gl_huang}http://${server_ip}:${port}/web${gl_bai}"
    echo ""
    echo -e "${gl_kjlan}【第一步】添加 Claude 账户${gl_bai}"
    echo "  1. 登录 Web 管理面板"
    echo "  2. 点击「Claude账户」标签"
    echo "  3. 点击「添加账户」→「生成授权链接」"
    echo "  4. 在新页面完成 Claude 登录授权"
    echo "  5. 复制 Authorization Code 粘贴回页面"
    echo ""
    echo -e "${gl_kjlan}【第二步】创建 API Key${gl_bai}"
    echo "  1. 点击「API Keys」标签"
    echo "  2. 点击「创建新Key」"
    echo "  3. 设置名称和限制（可选）"
    echo "  4. 保存并记录生成的 Key"
    echo ""
    echo -e "${gl_kjlan}【第三步】配置 Claude Code${gl_bai}"
    echo ""
    echo -e "${gl_huang}方式一：环境变量配置${gl_bai}"
    echo ""
    echo "  # 使用标准 Claude 账号池"
    echo -e "  ${gl_lv}export ANTHROPIC_BASE_URL=\"http://${server_ip}:${port}/api/\"${gl_bai}"
    echo -e "  ${gl_lv}export ANTHROPIC_AUTH_TOKEN=\"你的API密钥\"${gl_bai}"
    echo ""
    echo "  # 或使用 Antigravity 账号池"
    echo -e "  ${gl_lv}export ANTHROPIC_BASE_URL=\"http://${server_ip}:${port}/antigravity/api/\"${gl_bai}"
    echo -e "  ${gl_lv}export ANTHROPIC_AUTH_TOKEN=\"你的API密钥\"${gl_bai}"
    echo ""
    echo -e "${gl_huang}方式二：settings.json 配置${gl_bai}"
    echo ""
    echo "  编辑 ~/.claude/settings.json:"
    echo ""
    echo -e "  ${gl_lv}{"
    echo -e "    \"env\": {"
    echo -e "      \"ANTHROPIC_BASE_URL\": \"http://${server_ip}:${port}/api/\","
    echo -e "      \"ANTHROPIC_AUTH_TOKEN\": \"你的API密钥\""
    echo -e "    }"
    echo -e "  }${gl_bai}"
    echo ""
    echo -e "${gl_kjlan}【Gemini CLI 配置】${gl_bai}"
    echo ""
    echo -e "  ${gl_lv}export CODE_ASSIST_ENDPOINT=\"http://${server_ip}:${port}/gemini\"${gl_bai}"
    echo -e "  ${gl_lv}export GOOGLE_CLOUD_ACCESS_TOKEN=\"你的API密钥\"${gl_bai}"
    echo -e "  ${gl_lv}export GOOGLE_GENAI_USE_GCA=\"true\"${gl_bai}"
    echo -e "  ${gl_lv}export GEMINI_MODEL=\"gemini-2.5-pro\"${gl_bai}"
    echo ""
    echo -e "${gl_kjlan}【Codex CLI 配置】${gl_bai}"
    echo ""
    echo "  编辑 ~/.codex/config.toml 添加:"
    echo ""
    echo -e "  ${gl_lv}model_provider = \"crs\""
    echo -e "  [model_providers.crs]"
    echo -e "  name = \"crs\""
    echo -e "  base_url = \"http://${server_ip}:${port}/openai\""
    echo -e "  wire_api = \"responses\""
    echo -e "  requires_openai_auth = true"
    echo -e "  env_key = \"CRS_OAI_KEY\"${gl_bai}"
    echo ""
    echo "  然后设置环境变量:"
    echo -e "  ${gl_lv}export CRS_OAI_KEY=\"你的API密钥\"${gl_bai}"
    echo ""
    echo -e "${gl_zi}提示: 所有客户端使用相同的 API 密钥，系统根据路由自动选择账号类型${gl_bai}"
    echo ""

    break_end
}

# 卸载
crs_uninstall() {
    clear
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo -e "${gl_hong}  卸载 Claude Relay Service${gl_bai}"
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo ""

    local status=$(crs_check_status)
    if [ "$status" = "not_installed" ]; then
        echo -e "${gl_hong}❌ CRS 未安装${gl_bai}"
        break_end
        return 1
    fi

    local install_dir=$(crs_get_install_dir)

    echo -e "${gl_hong}⚠️ 警告: 此操作将删除 CRS 服务和所有数据！${gl_bai}"
    echo ""
    echo "安装目录: $install_dir"
    echo ""

    read -e -p "确认卸载？(输入 yes 确认): " confirm

    if [ "$confirm" != "yes" ]; then
        echo "已取消"
        break_end
        return 0
    fi

    echo ""
    echo "正在卸载..."

    # 使用 crs uninstall 命令
    if command -v crs &>/dev/null; then
        crs uninstall
    else
        # 手动卸载
        echo "正在停止服务..."
        # 尝试停止 pm2 进程
        pm2 stop crs 2>/dev/null
        pm2 delete crs 2>/dev/null

        echo "正在删除文件..."
        rm -rf "$install_dir"
    fi

    # 删除配置文件
    rm -f "$CRS_PORT_FILE"
    rm -f "$CRS_INSTALL_DIR_FILE"

    # 删除 crs 命令
    rm -f /usr/local/bin/crs 2>/dev/null

    echo ""
    echo -e "${gl_lv}✅ 卸载完成${gl_bai}"

    break_end
}

# CRS 主菜单
manage_crs() {
    while true; do
        clear
        echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
        echo -e "${gl_kjlan}  Claude Relay Service (CRS) 部署管理${gl_bai}"
        echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
        echo ""

        # 显示当前状态
        local status=$(crs_check_status)
        local port=$(crs_get_port)

        case "$status" in
            "running")
                echo -e "当前状态: ${gl_lv}✅ 运行中${gl_bai} (端口: $port)"
                ;;
            "stopped")
                echo -e "当前状态: ${gl_hong}❌ 已停止${gl_bai}"
                ;;
            "installed_no_command")
                echo -e "当前状态: ${gl_huang}⚠️ 已安装但命令不可用${gl_bai}"
                ;;
            "not_installed")
                echo -e "当前状态: ${gl_hui}未安装${gl_bai}"
                ;;
        esac

        echo ""
        echo -e "${gl_kjlan}[部署与更新]${gl_bai}"
        echo "1. 一键部署（首次安装）"
        echo "2. 更新服务"
        echo ""
        echo -e "${gl_kjlan}[服务管理]${gl_bai}"
        echo "3. 查看状态"
        echo "4. 查看日志"
        echo "5. 启动服务"
        echo "6. 停止服务"
        echo "7. 重启服务"
        echo ""
        echo -e "${gl_kjlan}[配置与信息]${gl_bai}"
        echo "8. 查看管理员账号"
        echo "9. 修改端口"
        echo "10. 查看配置指引"
        echo ""
        echo -e "${gl_kjlan}[卸载]${gl_bai}"
        echo -e "${gl_hong}99. 卸载（删除服务+数据）${gl_bai}"
        echo ""
        echo "0. 返回主菜单"
        echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"

        read -e -p "请选择操作 [0-10, 99]: " choice

        case $choice in
            1)
                crs_deploy
                ;;
            2)
                crs_update
                ;;
            3)
                crs_status
                ;;
            4)
                crs_logs
                ;;
            5)
                crs_start
                ;;
            6)
                crs_stop
                ;;
            7)
                crs_restart
                ;;
            8)
                crs_show_admin
                ;;
            9)
                crs_change_port
                ;;
            10)
                crs_show_config
                ;;
            99)
                crs_uninstall
                ;;
            0)
                return
                ;;
            *)
                echo "无效的选择"
                sleep 2
                ;;
        esac
    done
}

# =====================================================
# Fuclaude 部署管理 (菜单42) - Claude网页版共享
# =====================================================

# 常量定义
FUCLAUDE_CONTAINER_NAME="fuclaude"
FUCLAUDE_IMAGE="pengzhile/fuclaude"
FUCLAUDE_DEFAULT_PORT="8181"
FUCLAUDE_PORT_FILE="/etc/fuclaude-port"
FUCLAUDE_CONFIG_DIR="/etc/fuclaude"
FUCLAUDE_DATA_DIR="/var/lib/fuclaude"

# 获取当前配置的端口
fuclaude_get_port() {
    if [ -f "$FUCLAUDE_PORT_FILE" ]; then
        cat "$FUCLAUDE_PORT_FILE"
    else
        echo "$FUCLAUDE_DEFAULT_PORT"
    fi
}

# 检查 Fuclaude 状态
fuclaude_check_status() {
    if docker ps --format '{{.Names}}' 2>/dev/null | grep -q "^${FUCLAUDE_CONTAINER_NAME}$"; then
        echo "running"
    elif docker ps -a --format '{{.Names}}' 2>/dev/null | grep -q "^${FUCLAUDE_CONTAINER_NAME}$"; then
        echo "stopped"
    else
        echo "not_installed"
    fi
}

# 检查端口是否可用
fuclaude_check_port() {
    local port=$1
    if ss -lntp 2>/dev/null | grep -q ":${port} "; then
        return 1
    fi
    return 0
}

# 安装 Docker（复用通用函数）
fuclaude_install_docker() {
    if command -v docker &>/dev/null; then
        echo -e "${gl_lv}✅ Docker 已安装${gl_bai}"
        return 0
    fi

    echo "正在安装 Docker..."
    # 使用安全下载模式替代 curl | sh
    run_remote_script "https://get.docker.com" sh

    if [ $? -eq 0 ]; then
        systemctl enable docker
        systemctl start docker
        echo -e "${gl_lv}✅ Docker 安装成功${gl_bai}"
        return 0
    else
        echo -e "${gl_hong}❌ Docker 安装失败${gl_bai}"
        return 1
    fi
}

# 生成随机字符串
fuclaude_generate_secret() {
    cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1
}

# 一键部署
fuclaude_deploy() {
    clear
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo -e "${gl_kjlan}  一键部署 Fuclaude (Claude网页版共享)${gl_bai}"
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo ""

    # 检查是否已安装
    local status=$(fuclaude_check_status)
    if [ "$status" != "not_installed" ]; then
        echo -e "${gl_huang}⚠️ Fuclaude 已安装${gl_bai}"
        read -e -p "是否重新部署？(y/n) [n]: " reinstall
        if [ "$reinstall" != "y" ] && [ "$reinstall" != "Y" ]; then
            break_end
            return 0
        fi
        # 删除现有容器
        docker stop "$FUCLAUDE_CONTAINER_NAME" 2>/dev/null
        docker rm "$FUCLAUDE_CONTAINER_NAME" 2>/dev/null
    fi

    # 安装 Docker
    echo ""
    echo -e "${gl_kjlan}[1/4] 检查 Docker 环境...${gl_bai}"
    fuclaude_install_docker || { break_end; return 1; }

    # 配置端口
    echo ""
    echo -e "${gl_kjlan}[2/4] 配置服务参数...${gl_bai}"
    echo ""

    local port="$FUCLAUDE_DEFAULT_PORT"
    read -e -p "请输入访问端口 [$FUCLAUDE_DEFAULT_PORT]: " input_port
    if [ -n "$input_port" ]; then
        port="$input_port"
    fi

    # 检查端口是否可用
    while ! fuclaude_check_port "$port"; do
        echo -e "${gl_hong}⚠️ 端口 $port 已被占用，请换一个${gl_bai}"
        read -e -p "请输入访问端口: " port
        if [ -z "$port" ]; then
            port="$FUCLAUDE_DEFAULT_PORT"
        fi
    done
    echo -e "${gl_lv}✅ 端口 $port 可用${gl_bai}"

    # 配置站点密码
    echo ""
    local site_password=""
    read -e -p "设置站点访问密码 (直接回车跳过，不设密码): " site_password

    # 配置是否允许注册
    echo ""
    local signup_enabled="false"
    read -e -p "是否允许用户自行注册？(y/n) [n]: " allow_signup
    if [ "$allow_signup" = "y" ] || [ "$allow_signup" = "Y" ]; then
        signup_enabled="true"
    fi

    # 生成 Cookie 密钥
    local cookie_secret=$(fuclaude_generate_secret)

    # 拉取镜像
    echo ""
    echo -e "${gl_kjlan}[3/4] 拉取 Fuclaude 镜像...${gl_bai}"
    docker pull "$FUCLAUDE_IMAGE"

    if [ $? -ne 0 ]; then
        echo -e "${gl_hong}❌ 镜像拉取失败${gl_bai}"
        break_end
        return 1
    fi
    echo -e "${gl_lv}✅ 镜像拉取成功${gl_bai}"

    # 创建数据目录
    mkdir -p "$FUCLAUDE_DATA_DIR"

    # 启动容器
    echo ""
    echo -e "${gl_kjlan}[4/4] 启动 Fuclaude 服务...${gl_bai}"

    # 停止并删除可能存在的旧容器
    docker stop "$FUCLAUDE_CONTAINER_NAME" 2>/dev/null
    docker rm "$FUCLAUDE_CONTAINER_NAME" 2>/dev/null

    # 构建 docker run 命令的函数
    run_fuclaude_container() {
        docker run -d \
            --name "$FUCLAUDE_CONTAINER_NAME" \
            -p ${port}:8181 \
            -e TZ=Asia/Shanghai \
            -e FUCLAUDE_BIND=0.0.0.0:8181 \
            -e FUCLAUDE_TIMEOUT=600 \
            -e FUCLAUDE_PROXY_URL= \
            -e FUCLAUDE_REAL_LOGOUT=false \
            -e FUCLAUDE_SITE_PASSWORD="$site_password" \
            -e FUCLAUDE_COOKIE_SECRET="$cookie_secret" \
            -e FUCLAUDE_SIGNUP_ENABLED="$signup_enabled" \
            -e FUCLAUDE_SHOW_SESSION_KEY=false \
            -v ${FUCLAUDE_DATA_DIR}:/app/data \
            --restart unless-stopped \
            "$FUCLAUDE_IMAGE" 2>&1
    }

    # 第一次尝试启动
    local run_output=$(run_fuclaude_container)
    local run_result=$?

    # 检查是否是 iptables/网络错误
    if [ $run_result -ne 0 ]; then
        if echo "$run_output" | grep -qiE "iptables|chain|network|connectivity"; then
            echo -e "${gl_huang}⚠️ 检测到 Docker 网络问题，正在自动修复...${gl_bai}"
            echo ""

            # 清理失败的容器
            docker rm -f "$FUCLAUDE_CONTAINER_NAME" 2>/dev/null

            # 重启 Docker 服务
            echo "重启 Docker 服务..."
            systemctl restart docker
            sleep 3

            echo "重新启动容器..."
            run_output=$(run_fuclaude_container)
            run_result=$?
        fi
    fi

    if [ $run_result -ne 0 ]; then
        echo "$run_output"
        echo ""
        echo -e "${gl_hong}❌ 容器启动失败${gl_bai}"
        echo ""
        echo -e "${gl_huang}提示: 可尝试手动执行以下命令后重试:${gl_bai}"
        echo "  systemctl restart docker"
        break_end
        return 1
    fi

    # 保存端口配置
    echo "$port" > "$FUCLAUDE_PORT_FILE"

    # 等待启动
    echo ""
    echo "等待服务启动..."
    sleep 3

    # 获取服务器 IP
    local server_ip=$(curl -s4 ip.sb 2>/dev/null || curl -s6 ip.sb 2>/dev/null || echo "服务器IP")

    echo ""
    echo -e "${gl_lv}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo -e "${gl_lv}  ✅ 部署完成！${gl_bai}"
    echo -e "${gl_lv}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo ""
    echo -e "访问地址: ${gl_huang}http://${server_ip}:${port}${gl_bai}"
    echo ""
    if [ -n "$site_password" ]; then
        echo -e "站点密码: ${gl_huang}$site_password${gl_bai}"
    else
        echo -e "站点密码: ${gl_zi}未设置${gl_bai}"
    fi
    echo -e "允许注册: ${gl_huang}$signup_enabled${gl_bai}"
    echo ""
    echo -e "${gl_kjlan}【使用说明】${gl_bai}"
    echo "  1. 访问上面的地址"
    echo "  2. 使用 Claude Pro 账号的 Session Token 登录"
    echo "  3. 多个用户可以共享这个网页版 Claude"
    echo ""
    echo -e "${gl_kjlan}【如何获取 Session Token】${gl_bai}"
    echo "  1. 登录 claude.ai"
    echo "  2. 打开浏览器开发者工具 (F12)"
    echo "  3. 切换到 Application/Storage → Cookies"
    echo "  4. 找到 sessionKey 的值，复制使用"
    echo ""
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo -e "${gl_kjlan}管理命令:${gl_bai}"
    echo "  状态: docker ps | grep $FUCLAUDE_CONTAINER_NAME"
    echo "  日志: docker logs $FUCLAUDE_CONTAINER_NAME -f"
    echo "  重启: docker restart $FUCLAUDE_CONTAINER_NAME"
    echo ""

    break_end
}

# 更新镜像
fuclaude_update() {
    clear
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo -e "${gl_kjlan}  更新 Fuclaude${gl_bai}"
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo ""

    local status=$(fuclaude_check_status)
    if [ "$status" = "not_installed" ]; then
        echo -e "${gl_hong}❌ Fuclaude 未安装，请先执行一键部署${gl_bai}"
        break_end
        return 1
    fi

    echo "正在拉取最新镜像..."
    docker pull "$FUCLAUDE_IMAGE"

    if [ $? -eq 0 ]; then
        echo ""
        echo "正在重启容器..."

        # 获取当前容器的环境变量
        local old_env=$(docker inspect "$FUCLAUDE_CONTAINER_NAME" --format '{{range .Config.Env}}{{println .}}{{end}}' 2>/dev/null)

        # 获取保存的端口
        local port=$(fuclaude_get_port)

        # 停止并删除旧容器
        docker stop "$FUCLAUDE_CONTAINER_NAME"
        docker rm "$FUCLAUDE_CONTAINER_NAME"

        # 重新创建容器，使用保存的端口
        # 需要重新读取之前的配置，这里简化处理，使用默认值
        docker run -d \
            --name "$FUCLAUDE_CONTAINER_NAME" \
            -p ${port}:8181 \
            -e TZ=Asia/Shanghai \
            -e FUCLAUDE_BIND=0.0.0.0:8181 \
            -e FUCLAUDE_TIMEOUT=600 \
            -v ${FUCLAUDE_DATA_DIR}:/app/data \
            --restart unless-stopped \
            "$FUCLAUDE_IMAGE"

        if [ $? -eq 0 ]; then
            echo ""
            echo -e "${gl_lv}✅ 更新完成${gl_bai}"
            echo ""
            echo -e "${gl_huang}注意: 更新后环境变量已重置为默认值${gl_bai}"
            echo "如需修改配置，请使用「修改配置」功能"
        else
            echo -e "${gl_hong}❌ 重启失败${gl_bai}"
        fi
    else
        echo -e "${gl_hong}❌ 镜像拉取失败${gl_bai}"
    fi

    break_end
}

# 查看状态
fuclaude_status() {
    clear
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo -e "${gl_kjlan}  Fuclaude 状态${gl_bai}"
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo ""

    local status=$(fuclaude_check_status)
    local port=$(fuclaude_get_port)
    local server_ip=$(curl -s4 ip.sb 2>/dev/null || curl -s6 ip.sb 2>/dev/null || echo "服务器IP")

    case "$status" in
        "running")
            echo -e "状态: ${gl_lv}✅ 运行中${gl_bai}"
            echo -e "端口: ${gl_huang}$port${gl_bai}"
            echo -e "访问地址: ${gl_huang}http://${server_ip}:${port}${gl_bai}"
            echo ""
            echo "容器详情:"
            docker ps --filter "name=$FUCLAUDE_CONTAINER_NAME" --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
            echo ""
            echo "环境变量:"
            docker inspect "$FUCLAUDE_CONTAINER_NAME" --format '{{range .Config.Env}}  {{println .}}{{end}}' 2>/dev/null | grep FUCLAUDE
            ;;
        "stopped")
            echo -e "状态: ${gl_hong}❌ 已停止${gl_bai}"
            echo ""
            echo "请使用「启动服务」选项启动"
            ;;
        "not_installed")
            echo -e "状态: ${gl_hui}未安装${gl_bai}"
            echo ""
            echo "请使用「一键部署」选项安装"
            ;;
    esac

    echo ""
    break_end
}

# 查看日志
fuclaude_logs() {
    clear
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo -e "${gl_kjlan}  Fuclaude 日志${gl_bai}"
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo ""
    echo -e "${gl_zi}按 Ctrl+C 退出日志查看${gl_bai}"
    echo ""

    docker logs "$FUCLAUDE_CONTAINER_NAME" -f --tail 100
}

# 启动服务
fuclaude_start() {
    echo ""
    echo "正在启动 Fuclaude..."
    docker start "$FUCLAUDE_CONTAINER_NAME"

    if [ $? -eq 0 ]; then
        local port=$(fuclaude_get_port)
        local server_ip=$(curl -s4 ip.sb 2>/dev/null || curl -s6 ip.sb 2>/dev/null || echo "服务器IP")
        echo -e "${gl_lv}✅ 启动成功${gl_bai}"
        echo -e "访问地址: ${gl_huang}http://${server_ip}:${port}${gl_bai}"
    else
        echo -e "${gl_hong}❌ 启动失败${gl_bai}"
    fi

    sleep 2
    break_end
}

# 停止服务
fuclaude_stop() {
    echo ""
    echo "正在停止 Fuclaude..."
    docker stop "$FUCLAUDE_CONTAINER_NAME"

    if [ $? -eq 0 ]; then
        echo -e "${gl_lv}✅ 已停止${gl_bai}"
    else
        echo -e "${gl_hong}❌ 停止失败${gl_bai}"
    fi

    sleep 2
    break_end
}

# 重启服务
fuclaude_restart() {
    echo ""
    echo "正在重启 Fuclaude..."
    docker restart "$FUCLAUDE_CONTAINER_NAME"

    if [ $? -eq 0 ]; then
        local port=$(fuclaude_get_port)
        local server_ip=$(curl -s4 ip.sb 2>/dev/null || curl -s6 ip.sb 2>/dev/null || echo "服务器IP")
        echo -e "${gl_lv}✅ 重启成功${gl_bai}"
        echo -e "访问地址: ${gl_huang}http://${server_ip}:${port}${gl_bai}"
    else
        echo -e "${gl_hong}❌ 重启失败${gl_bai}"
    fi

    sleep 2
    break_end
}

# 修改配置
fuclaude_config() {
    clear
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo -e "${gl_kjlan}  修改 Fuclaude 配置${gl_bai}"
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo ""

    local status=$(fuclaude_check_status)
    if [ "$status" = "not_installed" ]; then
        echo -e "${gl_hong}❌ Fuclaude 未安装${gl_bai}"
        break_end
        return 1
    fi

    local current_port=$(fuclaude_get_port)

    echo "当前配置:"
    echo -e "  端口: ${gl_huang}$current_port${gl_bai}"
    echo ""
    echo "请选择要修改的配置:"
    echo "1. 修改端口"
    echo "2. 修改站点密码"
    echo "3. 修改注册设置"
    echo "0. 返回"
    echo ""

    read -e -p "请选择 [0-3]: " config_choice

    case $config_choice in
        1)
            fuclaude_change_port
            ;;
        2)
            fuclaude_change_password
            ;;
        3)
            fuclaude_change_signup
            ;;
        0)
            return
            ;;
        *)
            echo "无效的选择"
            sleep 2
            ;;
    esac
}

# 修改端口
fuclaude_change_port() {
    echo ""
    local current_port=$(fuclaude_get_port)
    echo -e "当前端口: ${gl_huang}$current_port${gl_bai}"
    echo ""

    read -e -p "请输入新端口: " new_port

    if [ -z "$new_port" ]; then
        echo "未输入端口，取消修改"
        break_end
        return 0
    fi

    # 验证端口
    if ! [[ "$new_port" =~ ^[0-9]+$ ]] || [ "$new_port" -lt 1 ] || [ "$new_port" -gt 65535 ]; then
        echo -e "${gl_hong}❌ 无效的端口号${gl_bai}"
        break_end
        return 1
    fi

    if [ "$new_port" = "$current_port" ]; then
        echo -e "${gl_huang}⚠️ 端口未改变${gl_bai}"
        break_end
        return 0
    fi

    # 检查端口是否可用
    if ! fuclaude_check_port "$new_port"; then
        echo -e "${gl_hong}❌ 端口 $new_port 已被占用${gl_bai}"
        break_end
        return 1
    fi

    echo ""
    echo "正在修改端口..."

    # 获取当前容器的环境变量
    local env_vars=$(docker inspect "$FUCLAUDE_CONTAINER_NAME" --format '{{range .Config.Env}}{{println .}}{{end}}' 2>/dev/null)

    # 停止并删除旧容器
    docker stop "$FUCLAUDE_CONTAINER_NAME"
    docker rm "$FUCLAUDE_CONTAINER_NAME"

    # 用新端口创建容器
    # 解析环境变量并重新创建
    local site_password=$(echo "$env_vars" | grep "FUCLAUDE_SITE_PASSWORD=" | cut -d= -f2-)
    local cookie_secret=$(echo "$env_vars" | grep "FUCLAUDE_COOKIE_SECRET=" | cut -d= -f2-)
    local signup_enabled=$(echo "$env_vars" | grep "FUCLAUDE_SIGNUP_ENABLED=" | cut -d= -f2-)

    # 设置默认值
    [ -z "$cookie_secret" ] && cookie_secret=$(fuclaude_generate_secret)
    [ -z "$signup_enabled" ] && signup_enabled="false"

    docker run -d \
        --name "$FUCLAUDE_CONTAINER_NAME" \
        -p ${new_port}:8181 \
        -e TZ=Asia/Shanghai \
        -e FUCLAUDE_BIND=0.0.0.0:8181 \
        -e FUCLAUDE_TIMEOUT=600 \
        -e FUCLAUDE_SITE_PASSWORD="$site_password" \
        -e FUCLAUDE_COOKIE_SECRET="$cookie_secret" \
        -e FUCLAUDE_SIGNUP_ENABLED="$signup_enabled" \
        -e FUCLAUDE_SHOW_SESSION_KEY=false \
        -v ${FUCLAUDE_DATA_DIR}:/app/data \
        --restart unless-stopped \
        "$FUCLAUDE_IMAGE"

    if [ $? -eq 0 ]; then
        echo "$new_port" > "$FUCLAUDE_PORT_FILE"
        local server_ip=$(curl -s4 ip.sb 2>/dev/null || curl -s6 ip.sb 2>/dev/null || echo "服务器IP")
        echo ""
        echo -e "${gl_lv}✅ 端口修改成功${gl_bai}"
        echo -e "新访问地址: ${gl_huang}http://${server_ip}:${new_port}${gl_bai}"
    else
        echo -e "${gl_hong}❌ 端口修改失败${gl_bai}"
    fi

    break_end
}

# 修改站点密码
fuclaude_change_password() {
    echo ""
    read -e -p "请输入新的站点密码 (留空取消密码保护): " new_password

    echo ""
    echo "正在修改密码..."

    # 获取当前容器的环境变量
    local env_vars=$(docker inspect "$FUCLAUDE_CONTAINER_NAME" --format '{{range .Config.Env}}{{println .}}{{end}}' 2>/dev/null)
    local port=$(fuclaude_get_port)
    local cookie_secret=$(echo "$env_vars" | grep "FUCLAUDE_COOKIE_SECRET=" | cut -d= -f2-)
    local signup_enabled=$(echo "$env_vars" | grep "FUCLAUDE_SIGNUP_ENABLED=" | cut -d= -f2-)

    [ -z "$cookie_secret" ] && cookie_secret=$(fuclaude_generate_secret)
    [ -z "$signup_enabled" ] && signup_enabled="false"

    # 停止并删除旧容器
    docker stop "$FUCLAUDE_CONTAINER_NAME"
    docker rm "$FUCLAUDE_CONTAINER_NAME"

    docker run -d \
        --name "$FUCLAUDE_CONTAINER_NAME" \
        -p ${port}:8181 \
        -e TZ=Asia/Shanghai \
        -e FUCLAUDE_BIND=0.0.0.0:8181 \
        -e FUCLAUDE_TIMEOUT=600 \
        -e FUCLAUDE_SITE_PASSWORD="$new_password" \
        -e FUCLAUDE_COOKIE_SECRET="$cookie_secret" \
        -e FUCLAUDE_SIGNUP_ENABLED="$signup_enabled" \
        -e FUCLAUDE_SHOW_SESSION_KEY=false \
        -v ${FUCLAUDE_DATA_DIR}:/app/data \
        --restart unless-stopped \
        "$FUCLAUDE_IMAGE"

    if [ $? -eq 0 ]; then
        echo ""
        if [ -n "$new_password" ]; then
            echo -e "${gl_lv}✅ 密码修改成功${gl_bai}"
            echo -e "新密码: ${gl_huang}$new_password${gl_bai}"
        else
            echo -e "${gl_lv}✅ 已取消密码保护${gl_bai}"
        fi
    else
        echo -e "${gl_hong}❌ 密码修改失败${gl_bai}"
    fi

    break_end
}

# 修改注册设置
fuclaude_change_signup() {
    echo ""
    local env_vars=$(docker inspect "$FUCLAUDE_CONTAINER_NAME" --format '{{range .Config.Env}}{{println .}}{{end}}' 2>/dev/null)
    local current_signup=$(echo "$env_vars" | grep "FUCLAUDE_SIGNUP_ENABLED=" | cut -d= -f2-)

    echo -e "当前注册设置: ${gl_huang}${current_signup:-false}${gl_bai}"
    echo ""

    local new_signup="false"
    read -e -p "是否允许用户自行注册？(y/n) [n]: " allow_signup
    if [ "$allow_signup" = "y" ] || [ "$allow_signup" = "Y" ]; then
        new_signup="true"
    fi

    echo ""
    echo "正在修改注册设置..."

    local port=$(fuclaude_get_port)
    local site_password=$(echo "$env_vars" | grep "FUCLAUDE_SITE_PASSWORD=" | cut -d= -f2-)
    local cookie_secret=$(echo "$env_vars" | grep "FUCLAUDE_COOKIE_SECRET=" | cut -d= -f2-)

    [ -z "$cookie_secret" ] && cookie_secret=$(fuclaude_generate_secret)

    # 停止并删除旧容器
    docker stop "$FUCLAUDE_CONTAINER_NAME"
    docker rm "$FUCLAUDE_CONTAINER_NAME"

    docker run -d \
        --name "$FUCLAUDE_CONTAINER_NAME" \
        -p ${port}:8181 \
        -e TZ=Asia/Shanghai \
        -e FUCLAUDE_BIND=0.0.0.0:8181 \
        -e FUCLAUDE_TIMEOUT=600 \
        -e FUCLAUDE_SITE_PASSWORD="$site_password" \
        -e FUCLAUDE_COOKIE_SECRET="$cookie_secret" \
        -e FUCLAUDE_SIGNUP_ENABLED="$new_signup" \
        -e FUCLAUDE_SHOW_SESSION_KEY=false \
        -v ${FUCLAUDE_DATA_DIR}:/app/data \
        --restart unless-stopped \
        "$FUCLAUDE_IMAGE"

    if [ $? -eq 0 ]; then
        echo ""
        echo -e "${gl_lv}✅ 注册设置修改成功${gl_bai}"
        echo -e "允许注册: ${gl_huang}$new_signup${gl_bai}"
    else
        echo -e "${gl_hong}❌ 设置修改失败${gl_bai}"
    fi

    break_end
}

# 卸载
fuclaude_uninstall() {
    clear
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo -e "${gl_hong}  卸载 Fuclaude${gl_bai}"
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo ""

    local status=$(fuclaude_check_status)
    if [ "$status" = "not_installed" ]; then
        echo -e "${gl_hong}❌ Fuclaude 未安装${gl_bai}"
        break_end
        return 1
    fi

    echo -e "${gl_hong}⚠️ 此操作将删除 Fuclaude 容器${gl_bai}"
    echo ""
    read -e -p "是否同时删除数据目录？(y/n) [n]: " delete_data
    echo ""
    read -e -p "确认卸载？(y/n) [n]: " confirm

    if [ "$confirm" != "y" ] && [ "$confirm" != "Y" ]; then
        echo "取消卸载"
        break_end
        return 0
    fi

    echo ""
    echo "正在卸载..."

    # 停止并删除容器
    docker stop "$FUCLAUDE_CONTAINER_NAME" 2>/dev/null
    docker rm "$FUCLAUDE_CONTAINER_NAME" 2>/dev/null

    # 删除数据目录
    if [ "$delete_data" = "y" ] || [ "$delete_data" = "Y" ]; then
        rm -rf "$FUCLAUDE_DATA_DIR"
        echo -e "${gl_lv}✅ 容器和数据已删除${gl_bai}"
    else
        echo -e "${gl_lv}✅ 容器已删除，数据保留在 $FUCLAUDE_DATA_DIR${gl_bai}"
    fi

    # 删除端口配置文件
    rm -f "$FUCLAUDE_PORT_FILE"

    break_end
}

# Fuclaude 管理主菜单
manage_fuclaude() {
    while true; do
        clear
        echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
        echo -e "${gl_kjlan}  Fuclaude 部署管理 (Claude网页版共享)${gl_bai}"
        echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
        echo ""

        # 显示当前状态
        local status=$(fuclaude_check_status)
        local port=$(fuclaude_get_port)

        case "$status" in
            "running")
                echo -e "当前状态: ${gl_lv}✅ 运行中${gl_bai} (端口: $port)"
                ;;
            "stopped")
                echo -e "当前状态: ${gl_hong}❌ 已停止${gl_bai}"
                ;;
            "not_installed")
                echo -e "当前状态: ${gl_hui}未安装${gl_bai}"
                ;;
        esac

        echo ""
        echo -e "${gl_kjlan}[部署与更新]${gl_bai}"
        echo "1. 一键部署（首次安装）"
        echo "2. 更新镜像"
        echo ""
        echo -e "${gl_kjlan}[服务管理]${gl_bai}"
        echo "3. 查看状态"
        echo "4. 查看日志"
        echo "5. 启动服务"
        echo "6. 停止服务"
        echo "7. 重启服务"
        echo ""
        echo -e "${gl_kjlan}[配置]${gl_bai}"
        echo "8. 修改配置（端口/密码/注册）"
        echo ""
        echo -e "${gl_kjlan}[卸载]${gl_bai}"
        echo -e "${gl_hong}9. 卸载（删除容器）${gl_bai}"
        echo ""
        echo "0. 返回主菜单"
        echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"

        read -e -p "请选择操作 [0-9]: " choice

        case $choice in
            1)
                fuclaude_deploy
                ;;
            2)
                fuclaude_update
                ;;
            3)
                fuclaude_status
                ;;
            4)
                fuclaude_logs
                ;;
            5)
                fuclaude_start
                ;;
            6)
                fuclaude_stop
                ;;
            7)
                fuclaude_restart
                ;;
            8)
                fuclaude_config
                ;;
            9)
                fuclaude_uninstall
                ;;
            0)
                return
                ;;
            *)
                echo "无效的选择"
                sleep 2
                ;;
        esac
    done
}

# =====================================================
# Sub2API 部署管理
# =====================================================

# 常量定义
SUB2API_SERVICE_NAME="sub2api"
SUB2API_INSTALL_DIR="/opt/sub2api"
SUB2API_CONFIG_DIR="/etc/sub2api"
SUB2API_DEFAULT_PORT="8282"
SUB2API_PORT_FILE="/etc/sub2api-port"
SUB2API_INSTALL_SCRIPT="https://raw.githubusercontent.com/Wei-Shaw/sub2api/main/deploy/install.sh"

# 获取当前配置的端口
sub2api_get_port() {
    if [ -f "$SUB2API_PORT_FILE" ]; then
        cat "$SUB2API_PORT_FILE"
    else
        echo "$SUB2API_DEFAULT_PORT"
    fi
}

# 检查端口是否可用
sub2api_check_port() {
    local port=$1
    if ss -lntp 2>/dev/null | grep -q ":${port} "; then
        return 1
    fi
    return 0
}

# 检测 Sub2API 状态
sub2api_check_status() {
    if [ ! -d "$SUB2API_INSTALL_DIR" ] && [ ! -f "/etc/systemd/system/sub2api.service" ]; then
        echo "not_installed"
    elif systemctl is-active "$SUB2API_SERVICE_NAME" &>/dev/null; then
        echo "running"
    else
        echo "stopped"
    fi
}

# 从 systemd 服务文件提取端口
sub2api_extract_port() {
    local service_file="/etc/systemd/system/sub2api.service"
    if [ -f "$service_file" ]; then
        # 尝试从 ExecStart 行提取端口
        local port=$(sed -nE 's/.*:([0-9]+).*/\1/p' "$service_file" 2>/dev/null | head -1)
        if [ -n "$port" ]; then
            echo "$port"
            return
        fi
    fi
    echo "$SUB2API_DEFAULT_PORT"
}

# 安装 PostgreSQL 并创建数据库
sub2api_setup_postgres() {
    echo -e "${gl_kjlan}[1/4] 安装 PostgreSQL 数据库...${gl_bai}"

    if command -v psql &>/dev/null; then
        echo -e "${gl_lv}✅ PostgreSQL 已安装${gl_bai}"
    else
        echo "正在安装 PostgreSQL..."
        apt-get update -qq 2>/dev/null
        apt-get install -y -qq postgresql postgresql-contrib > /dev/null 2>&1
        if [ $? -ne 0 ]; then
            echo -e "${gl_hong}❌ PostgreSQL 安装失败${gl_bai}"
            return 1
        fi
        echo -e "${gl_lv}✅ PostgreSQL 安装完成${gl_bai}"
    fi

    # 确保 PostgreSQL 运行
    systemctl start postgresql 2>/dev/null
    systemctl enable postgresql 2>/dev/null

    # 生成随机密码
    SUB2API_DB_PASSWORD=$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c 20)
    SUB2API_DB_USER="sub2api"
    SUB2API_DB_NAME="sub2api"

    # 创建用户和数据库（如果不存在）
    echo "正在配置数据库..."
    sudo -u postgres psql -tc "SELECT 1 FROM pg_roles WHERE rolname='$SUB2API_DB_USER'" | grep -q 1 || \
        sudo -u postgres psql -c "CREATE USER $SUB2API_DB_USER WITH PASSWORD '$SUB2API_DB_PASSWORD';" > /dev/null 2>&1

    # 如果用户已存在，更新密码
    sudo -u postgres psql -c "ALTER USER $SUB2API_DB_USER WITH PASSWORD '$SUB2API_DB_PASSWORD';" > /dev/null 2>&1

    sudo -u postgres psql -tc "SELECT 1 FROM pg_database WHERE datname='$SUB2API_DB_NAME'" | grep -q 1 || \
        sudo -u postgres psql -c "CREATE DATABASE $SUB2API_DB_NAME OWNER $SUB2API_DB_USER;" > /dev/null 2>&1

    # 验证连接
    if PGPASSWORD="$SUB2API_DB_PASSWORD" psql -h localhost -U "$SUB2API_DB_USER" -d "$SUB2API_DB_NAME" -c "SELECT 1" > /dev/null 2>&1; then
        echo -e "${gl_lv}✅ 数据库配置完成，连接正常${gl_bai}"
    else
        # 可能需要修改 pg_hba.conf 允许密码认证
        local pg_hba=$(find /etc/postgresql -name pg_hba.conf 2>/dev/null | head -1)
        if [ -n "$pg_hba" ]; then
            # 检查是否已有 sub2api 的规则
            if ! grep -q "sub2api" "$pg_hba"; then
                # 在文件开头添加密码认证规则
                sed -i "1i host    sub2api    sub2api    127.0.0.1/32    md5" "$pg_hba"
                sed -i "2i host    sub2api    sub2api    ::1/128         md5" "$pg_hba"
                systemctl restart postgresql
                echo -e "${gl_lv}✅ 数据库认证已配置${gl_bai}"
            fi
        fi

        # 再次验证
        if PGPASSWORD="$SUB2API_DB_PASSWORD" psql -h localhost -U "$SUB2API_DB_USER" -d "$SUB2API_DB_NAME" -c "SELECT 1" > /dev/null 2>&1; then
            echo -e "${gl_lv}✅ 数据库配置完成，连接正常${gl_bai}"
        else
            echo -e "${gl_huang}⚠️ 数据库已创建，但本地连接验证未通过（不影响使用）${gl_bai}"
        fi
    fi

    # 保存数据库信息到文件
    cat > "$SUB2API_CONFIG_DIR/db-info" << EOF
DB_HOST=localhost
DB_PORT=5432
DB_USER=$SUB2API_DB_USER
DB_PASSWORD=$SUB2API_DB_PASSWORD
DB_NAME=$SUB2API_DB_NAME
EOF
    chmod 600 "$SUB2API_CONFIG_DIR/db-info"
    return 0
}

# 安装 Redis
sub2api_setup_redis() {
    echo -e "${gl_kjlan}[2/4] 安装 Redis...${gl_bai}"

    if command -v redis-cli &>/dev/null; then
        echo -e "${gl_lv}✅ Redis 已安装${gl_bai}"
    else
        echo "正在安装 Redis..."
        apt-get install -y -qq redis-server > /dev/null 2>&1
        if [ $? -ne 0 ]; then
            echo -e "${gl_hong}❌ Redis 安装失败${gl_bai}"
            return 1
        fi
        echo -e "${gl_lv}✅ Redis 安装完成${gl_bai}"
    fi

    systemctl start redis-server 2>/dev/null
    systemctl enable redis-server 2>/dev/null

    # 验证 Redis
    if redis-cli ping 2>/dev/null | grep -q "PONG"; then
        echo -e "${gl_lv}✅ Redis 运行正常${gl_bai}"
    else
        echo -e "${gl_huang}⚠️ Redis 可能未正常运行，请检查${gl_bai}"
    fi
    return 0
}

# 一键部署
sub2api_deploy() {
    clear
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo -e "${gl_kjlan}  一键部署 Sub2API${gl_bai}"
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo ""

    # 检查是否已安装
    local status=$(sub2api_check_status)
    if [ "$status" != "not_installed" ]; then
        echo -e "${gl_huang}⚠️ Sub2API 已安装${gl_bai}"
        read -e -p "是否重新部署？(y/n) [n]: " reinstall
        if [ "$reinstall" != "y" ] && [ "$reinstall" != "Y" ]; then
            break_end
            return 0
        fi
        # 停止现有服务
        systemctl stop "$SUB2API_SERVICE_NAME" 2>/dev/null
    fi

    # 创建配置目录
    mkdir -p "$SUB2API_CONFIG_DIR"

    # 安装 PostgreSQL
    echo ""
    sub2api_setup_postgres || { break_end; return 1; }

    # 安装 Redis
    echo ""
    sub2api_setup_redis || { break_end; return 1; }

    # 执行官方安装脚本
    echo ""
    echo -e "${gl_kjlan}[3/4] 执行官方安装脚本...${gl_bai}"
    echo ""
    echo -e "${gl_huang}提示: 官方脚本会询问地址和端口${gl_bai}"
    echo -e "${gl_zi}  → 地址: 直接回车（默认 0.0.0.0）${gl_bai}"
    echo -e "${gl_zi}  → 端口: 建议输入 ${SUB2API_DEFAULT_PORT}（避免与其他服务冲突）${gl_bai}"
    echo ""
    read -e -p "按回车开始安装..." _
    echo ""

    bash <(curl -fsSL "$SUB2API_INSTALL_SCRIPT")
    local install_result=$?

    if [ $install_result -ne 0 ]; then
        echo -e "${gl_hong}❌ 安装失败${gl_bai}"
        break_end
        return 1
    fi

    # 从服务文件提取端口并保存
    echo ""
    echo -e "${gl_kjlan}[4/4] 验证安装...${gl_bai}"
    local port=$(sub2api_extract_port)
    echo "$port" > "$SUB2API_PORT_FILE"

    # 获取服务器 IP
    local server_ip=$(curl -s4 ip.sb 2>/dev/null || curl -s6 ip.sb 2>/dev/null || echo "服务器IP")

    echo ""
    echo -e "${gl_lv}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo -e "${gl_lv}  ✅ 部署完成！${gl_bai}"
    echo -e "${gl_lv}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo ""
    echo -e "Web 管理面板: ${gl_huang}http://${server_ip}:${port}/setup${gl_bai}"
    echo ""
    echo -e "${gl_kjlan}【网页初始化配置 - 请照抄以下信息】${gl_bai}"
    echo ""
    echo -e "${gl_kjlan}  第1步 - 数据库配置:${gl_bai}"
    echo -e "    主持人:     ${gl_huang}localhost${gl_bai}"
    echo -e "    端口:       ${gl_huang}5432${gl_bai}"
    echo -e "    用户名:     ${gl_huang}${SUB2API_DB_USER}${gl_bai}"
    echo -e "    密码:       ${gl_huang}${SUB2API_DB_PASSWORD}${gl_bai}"
    echo -e "    数据库名称: ${gl_huang}${SUB2API_DB_NAME}${gl_bai}"
    echo -e "    SSL 模式:   ${gl_huang}禁用${gl_bai}"
    echo ""
    echo -e "${gl_kjlan}  第2步 - Redis 配置:${gl_bai}"
    echo -e "    主持人:     ${gl_huang}localhost${gl_bai}"
    echo -e "    端口:       ${gl_huang}6379${gl_bai}"
    echo -e "    密码:       ${gl_huang}（留空，直接下一步）${gl_bai}"
    echo ""
    echo -e "${gl_kjlan}  第3步 - 管理员帐户:${gl_bai}"
    echo -e "    自己设置用户名和密码"
    echo ""
    echo -e "${gl_kjlan}  第4步 - 准备安装:${gl_bai}"
    echo -e "    点击安装即可"
    echo ""
    echo -e "${gl_zi}提示: 以上数据库信息已保存到 ${SUB2API_CONFIG_DIR}/db-info${gl_bai}"
    echo ""
    echo -e "${gl_kjlan}【完成初始化后 - Claude Code 配置】${gl_bai}"
    echo -e "  ${gl_huang}export ANTHROPIC_BASE_URL=\"http://${server_ip}:${port}/antigravity\"${gl_bai}"
    echo -e "  ${gl_huang}export ANTHROPIC_AUTH_TOKEN=\"后台创建的API密钥\"${gl_bai}"
    echo ""
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo -e "${gl_kjlan}管理命令:${gl_bai}"
    echo "  状态: systemctl status sub2api"
    echo "  启动: systemctl start sub2api"
    echo "  停止: systemctl stop sub2api"
    echo "  重启: systemctl restart sub2api"
    echo "  日志: journalctl -u sub2api -f"
    echo ""

    break_end
}

# 启动服务
sub2api_start() {
    echo "正在启动 Sub2API..."
    systemctl start "$SUB2API_SERVICE_NAME"
    sleep 1
    if systemctl is-active "$SUB2API_SERVICE_NAME" &>/dev/null; then
        echo -e "${gl_lv}✅ 启动成功${gl_bai}"
    else
        echo -e "${gl_hong}❌ 启动失败${gl_bai}"
    fi
    break_end
}

# 停止服务
sub2api_stop() {
    echo "正在停止 Sub2API..."
    systemctl stop "$SUB2API_SERVICE_NAME"
    sleep 1
    if ! systemctl is-active "$SUB2API_SERVICE_NAME" &>/dev/null; then
        echo -e "${gl_lv}✅ 已停止${gl_bai}"
    else
        echo -e "${gl_hong}❌ 停止失败${gl_bai}"
    fi
    break_end
}

# 重启服务
sub2api_restart() {
    echo "正在重启 Sub2API..."
    systemctl restart "$SUB2API_SERVICE_NAME"
    sleep 1
    if systemctl is-active "$SUB2API_SERVICE_NAME" &>/dev/null; then
        echo -e "${gl_lv}✅ 重启成功${gl_bai}"
    else
        echo -e "${gl_hong}❌ 重启失败${gl_bai}"
    fi
    break_end
}

# 查看状态
sub2api_view_status() {
    clear
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo -e "${gl_kjlan}  Sub2API 服务状态${gl_bai}"
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo ""

    local port=$(sub2api_get_port)
    local server_ip=$(curl -s4 --max-time 3 ip.sb 2>/dev/null || echo "获取中...")

    echo -e "服务状态: $(systemctl is-active $SUB2API_SERVICE_NAME 2>/dev/null || echo '未知')"
    echo -e "访问端口: ${gl_huang}${port}${gl_bai}"
    echo -e "访问地址: ${gl_huang}http://${server_ip}:${port}${gl_bai}"
    echo ""
    echo -e "${gl_kjlan}--- systemctl status ---${gl_bai}"
    systemctl status "$SUB2API_SERVICE_NAME" --no-pager 2>/dev/null || echo "服务未安装"
    echo ""

    break_end
}

# 修改端口
sub2api_change_port() {
    local current_port=$(sub2api_get_port)
    echo ""
    echo -e "当前端口: ${gl_huang}${current_port}${gl_bai}"
    echo ""
    read -e -p "请输入新端口: " new_port

    if [ -z "$new_port" ]; then
        echo "已取消"
        break_end
        return
    fi

    # 检查端口是否被占用
    if ! sub2api_check_port "$new_port"; then
        echo -e "${gl_hong}❌ 端口 $new_port 已被占用${gl_bai}"
        break_end
        return 1
    fi

    echo ""
    echo "正在修改端口..."

    # 修改 systemd 服务文件中的端口
    local service_file="/etc/systemd/system/sub2api.service"
    if [ -f "$service_file" ]; then
        sed -i "s/:${current_port}/:${new_port}/g" "$service_file"
        sed -i "s/=${current_port}/=${new_port}/g" "$service_file"
    fi

    # 保存新端口
    echo "$new_port" > "$SUB2API_PORT_FILE"

    # 重载并重启服务
    systemctl daemon-reload
    systemctl restart "$SUB2API_SERVICE_NAME"

    sleep 1
    if systemctl is-active "$SUB2API_SERVICE_NAME" &>/dev/null; then
        echo -e "${gl_lv}✅ 端口已修改为 ${new_port}${gl_bai}"
    else
        echo -e "${gl_hong}❌ 服务重启失败，请检查配置${gl_bai}"
    fi

    break_end
}

# 查看日志
sub2api_view_logs() {
    clear
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo -e "${gl_kjlan}  Sub2API 运行日志 (最近 50 行)${gl_bai}"
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo ""
    journalctl -u "$SUB2API_SERVICE_NAME" -n 50 --no-pager
    echo ""
    break_end
}

# 更新服务
sub2api_update() {
    local status=$(sub2api_check_status)
    if [ "$status" = "not_installed" ]; then
        echo -e "${gl_hong}❌ Sub2API 未安装，请先执行一键部署${gl_bai}"
        break_end
        return 1
    fi

    echo -e "${gl_kjlan}正在执行官方升级脚本...${gl_bai}"
    echo ""

    local tmp_script=$(mktemp)
    if ! curl -fsSL "$SUB2API_INSTALL_SCRIPT" -o "$tmp_script"; then
        echo -e "${gl_hong}❌ 下载升级脚本失败${gl_bai}"
        rm -f "$tmp_script"
        break_end
        return 1
    fi

    chmod +x "$tmp_script"
    bash "$tmp_script" upgrade
    local result=$?
    rm -f "$tmp_script"

    if [ $result -eq 0 ]; then
        echo -e "${gl_lv}✅ 升级完成${gl_bai}"
    else
        echo -e "${gl_hong}❌ 升级失败${gl_bai}"
    fi

    break_end
}

# 查看配置信息
sub2api_show_config() {
    clear

    local status=$(sub2api_check_status)
    if [ "$status" = "not_installed" ]; then
        echo -e "${gl_hong}❌ Sub2API 未安装，请先执行一键部署${gl_bai}"
        break_end
        return 1
    fi

    local port=$(sub2api_get_port)
    local server_ip=$(curl -s4 --max-time 3 ip.sb 2>/dev/null || curl -s6 --max-time 3 ip.sb 2>/dev/null || echo "服务器IP")

    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo -e "${gl_kjlan}  Sub2API 配置信息${gl_bai}"
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo ""
    echo -e "Web 管理面板: ${gl_huang}http://${server_ip}:${port}${gl_bai}"
    echo -e "设置向导:     ${gl_huang}http://${server_ip}:${port}/setup${gl_bai}"
    echo ""

    # 读取数据库信息
    local db_info_file="$SUB2API_CONFIG_DIR/db-info"
    if [ -f "$db_info_file" ]; then
        local db_user=$(grep "DB_USER=" "$db_info_file" | cut -d= -f2)
        local db_pass=$(grep "DB_PASSWORD=" "$db_info_file" | cut -d= -f2)
        local db_name=$(grep "DB_NAME=" "$db_info_file" | cut -d= -f2)

        echo -e "${gl_kjlan}【数据库配置】${gl_bai}"
        echo -e "  主持人:     ${gl_huang}localhost${gl_bai}"
        echo -e "  端口:       ${gl_huang}5432${gl_bai}"
        echo -e "  用户名:     ${gl_huang}${db_user}${gl_bai}"
        echo -e "  密码:       ${gl_huang}${db_pass}${gl_bai}"
        echo -e "  数据库名称: ${gl_huang}${db_name}${gl_bai}"
        echo -e "  SSL 模式:   ${gl_huang}禁用${gl_bai}"
        echo ""
        echo -e "${gl_kjlan}【Redis 配置】${gl_bai}"
        echo -e "  主持人:     ${gl_huang}localhost${gl_bai}"
        echo -e "  端口:       ${gl_huang}6379${gl_bai}"
        echo -e "  密码:       ${gl_huang}（留空）${gl_bai}"
        echo ""
    else
        echo -e "${gl_huang}⚠️ 未找到数据库配置文件（旧版本部署）${gl_bai}"
        echo -e "  文件路径: ${SUB2API_CONFIG_DIR}/db-info"
        echo ""
    fi

    echo -e "${gl_kjlan}【Claude Code 配置】${gl_bai}"
    echo -e "  ${gl_huang}export ANTHROPIC_BASE_URL=\"http://${server_ip}:${port}/antigravity\"${gl_bai}"
    echo -e "  ${gl_huang}export ANTHROPIC_AUTH_TOKEN=\"后台创建的API密钥\"${gl_bai}"
    echo ""
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo -e "${gl_kjlan}管理命令:${gl_bai}"
    echo "  状态: systemctl status sub2api"
    echo "  启动: systemctl start sub2api"
    echo "  停止: systemctl stop sub2api"
    echo "  重启: systemctl restart sub2api"
    echo "  日志: journalctl -u sub2api -f"
    echo ""

    break_end
}

# 卸载
sub2api_uninstall() {
    echo ""
    echo -e "${gl_hong}⚠️ 此操作将卸载 Sub2API 并删除所有配置数据${gl_bai}"
    read -e -p "确定要卸载吗？(y/n) [n]: " confirm
    if [ "$confirm" != "y" ] && [ "$confirm" != "Y" ]; then
        echo "已取消"
        break_end
        return
    fi

    echo ""
    echo "正在执行官方卸载脚本..."

    # 使用官方卸载命令
    local tmp_script=$(mktemp)
    if curl -fsSL "$SUB2API_INSTALL_SCRIPT" -o "$tmp_script" 2>/dev/null; then
        chmod +x "$tmp_script"
        bash "$tmp_script" uninstall -y --purge
        rm -f "$tmp_script"
    else
        # 官方脚本下载失败，手动卸载
        echo "官方脚本下载失败，执行手动卸载..."
        systemctl stop "$SUB2API_SERVICE_NAME" 2>/dev/null
        systemctl disable "$SUB2API_SERVICE_NAME" 2>/dev/null
        rm -f "/etc/systemd/system/sub2api.service"
        systemctl daemon-reload
        rm -rf "$SUB2API_INSTALL_DIR"
        userdel sub2api 2>/dev/null
    fi

    # 清理我们自己的配置文件
    rm -rf "$SUB2API_CONFIG_DIR"
    rm -f "$SUB2API_PORT_FILE"

    echo -e "${gl_lv}✅ 卸载完成${gl_bai}"
    break_end
}

# Sub2API 管理主菜单
manage_sub2api() {
    while true; do
        clear
        echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
        echo -e "${gl_kjlan}  Sub2API 部署管理${gl_bai}"
        echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
        echo ""

        # 显示当前状态
        local status=$(sub2api_check_status)
        local port=$(sub2api_get_port)

        case "$status" in
            "running")
                echo -e "当前状态: ${gl_lv}✅ 运行中${gl_bai} (端口: $port)"
                ;;
            "stopped")
                echo -e "当前状态: ${gl_hong}❌ 已停止${gl_bai}"
                ;;
            "not_installed")
                echo -e "当前状态: ${gl_hui}未安装${gl_bai}"
                ;;
        esac
        echo ""

        echo -e "${gl_kjlan}[部署与更新]${gl_bai}"
        echo "1. 一键部署（首次安装）"
        echo "2. 更新服务"
        echo ""
        echo -e "${gl_kjlan}[服务管理]${gl_bai}"
        echo "3. 查看状态"
        echo "4. 查看日志"
        echo "5. 启动服务"
        echo "6. 停止服务"
        echo "7. 重启服务"
        echo ""
        echo -e "${gl_kjlan}[配置与信息]${gl_bai}"
        echo "8. 查看配置信息"
        echo "9. 修改端口"
        echo ""
        echo -e "${gl_kjlan}[卸载]${gl_bai}"
        echo -e "${gl_hong}99. 卸载（删除服务+数据）${gl_bai}"
        echo ""
        echo "0. 返回上级菜单"
        echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"

        read -e -p "请选择操作 [0-9, 99]: " choice

        case $choice in
            1)
                sub2api_deploy
                ;;
            2)
                sub2api_update
                ;;
            3)
                sub2api_view_status
                ;;
            4)
                sub2api_view_logs
                ;;
            5)
                sub2api_start
                ;;
            6)
                sub2api_stop
                ;;
            7)
                sub2api_restart
                ;;
            8)
                sub2api_show_config
                ;;
            9)
                sub2api_change_port
                ;;
            99)
                sub2api_uninstall
                ;;
            0)
                return
                ;;
            *)
                echo "无效的选择"
                sleep 2
                ;;
        esac
    done
}

# =====================================================
# Caddy 多域名反代管理 (菜单43)
# =====================================================

# 常量定义
CADDY_SERVICE_NAME="caddy"
CADDY_CONFIG_FILE="/etc/caddy/Caddyfile"
CADDY_CONFIG_DIR="/etc/caddy"
CADDY_CONFIG_BACKUP_DIR="/etc/caddy/backups"
CADDY_DOMAIN_LIST_FILE="/etc/caddy/.domain-list"
CADDY_SITES_AVAILABLE="/etc/caddy/sites-available"
CADDY_SITES_ENABLED="/etc/caddy/sites-enabled"
CADDY_INSTALL_SCRIPT="https://caddyserver.com/api/download?os=linux&arch=amd64"

# 获取服务器 IP
caddy_get_server_ip() {
    local ip=$(curl -s4 --max-time 5 ip.sb 2>/dev/null)
    if [ -z "$ip" ]; then
        ip=$(curl -s6 --max-time 5 ip.sb 2>/dev/null)
    fi
    if [ -z "$ip" ]; then
        ip=$(hostname -I 2>/dev/null | awk '{print $1}')
    fi
    echo "$ip"
}

# 检查 Caddy 状态
caddy_check_status() {
    if ! command -v caddy &>/dev/null; then
        echo "not_installed"
        return
    fi

    if systemctl is-active "$CADDY_SERVICE_NAME" &>/dev/null; then
        echo "running"
    elif systemctl is-enabled "$CADDY_SERVICE_NAME" &>/dev/null; then
        echo "stopped"
    else
        echo "installed_no_service"
    fi
}

# 检查端口是否被占用
caddy_check_port() {
    local port=$1
    if ss -lntp 2>/dev/null | grep -q ":${port} "; then
        return 1  # 端口被占用
    fi
    return 0  # 端口可用
}

# 检查并处理端口占用
caddy_handle_port_conflict() {
    local port=$1
    local port_name=$2

    echo -e "${gl_kjlan}检测端口 ${port} (${port_name}) 占用情况...${gl_bai}"

    if caddy_check_port "$port"; then
        echo -e "${gl_lv}✅ 端口 ${port} 可用${gl_bai}"
        return 0
    fi

    # 端口被占用,查找占用进程
    local pid=$(ss -lntp 2>/dev/null | grep ":${port} " | sed -nE 's/.*pid=([0-9]+).*/\1/p' | head -1)

    if [ -z "$pid" ]; then
        echo -e "${gl_hong}❌ 端口 ${port} 被占用，但无法获取进程信息${gl_bai}"
        return 1
    fi

    local proc_comm=$(cat /proc/$pid/comm 2>/dev/null || echo "未知进程")
    local proc_cwd=$(readlink -f /proc/$pid/cwd 2>/dev/null || echo "未知路径")

    echo -e "${gl_hong}⚠️ 端口 ${port} 被占用${gl_bai}"
    echo ""
    echo -e "占用进程信息："
    echo -e "  PID: ${pid}"
    echo -e "  程序: ${proc_comm}"
    echo -e "  路径: ${proc_cwd}"
    echo ""

    # 检查是否是 Caddy 自己
    if [[ "$proc_comm" == "caddy" ]]; then
        echo -e "${gl_huang}⚠️ 端口被现有 Caddy 进程占用${gl_bai}"
        echo "部署过程会自动停止旧服务并重启"
        return 0
    fi

    echo -e "${gl_huang}请选择操作：${gl_bai}"
    echo "1. 停止占用进程并继续部署（需谨慎）"
    echo "2. 取消部署（推荐，请手动处理端口占用）"
    echo ""
    read -e -p "请选择 [1-2]: " conflict_choice

    case "$conflict_choice" in
        1)
            echo ""
            echo "正在停止进程 ${pid}..."
            kill "$pid" 2>/dev/null
            sleep 2

            if ss -lntp 2>/dev/null | grep -q ":${port} "; then
                echo "进程未响应，强制终止..."
                kill -9 "$pid" 2>/dev/null
                sleep 1
            fi

            if ss -lntp 2>/dev/null | grep -q ":${port} "; then
                echo -e "${gl_hong}❌ 无法释放端口 ${port}${gl_bai}"
                return 1
            fi

            echo -e "${gl_lv}✅ 端口 ${port} 已释放${gl_bai}"
            return 0
            ;;
        2|*)
            echo "取消部署"
            return 1
            ;;
    esac
}

# 检查防火墙并配置
caddy_check_firewall() {
    echo ""
    echo -e "${gl_kjlan}检查防火墙配置...${gl_bai}"

    local firewall_type="none"
    local need_config=false

    # 检测防火墙类型
    if command -v ufw &>/dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
        firewall_type="ufw"
    elif command -v firewall-cmd &>/dev/null && systemctl is-active firewalld &>/dev/null; then
        firewall_type="firewalld"
    elif command -v iptables &>/dev/null; then
        # 检查是否有 iptables 规则
        if iptables -L -n 2>/dev/null | grep -qE "Chain INPUT.*policy (DROP|REJECT)"; then
            firewall_type="iptables"
        fi
    fi

    if [ "$firewall_type" = "none" ]; then
        echo -e "${gl_lv}✅ 未检测到活动防火墙${gl_bai}"
        return 0
    fi

    echo -e "检测到防火墙: ${gl_huang}$firewall_type${gl_bai}"

    # 检查端口是否已开放
    case "$firewall_type" in
        ufw)
            if ! ufw status 2>/dev/null | grep -qE "80/tcp.*ALLOW|80.*ALLOW"; then
                need_config=true
            fi
            if ! ufw status 2>/dev/null | grep -qE "443/tcp.*ALLOW|443.*ALLOW"; then
                need_config=true
            fi
            ;;
        firewalld)
            if ! firewall-cmd --list-ports 2>/dev/null | grep -q "80/tcp"; then
                need_config=true
            fi
            if ! firewall-cmd --list-ports 2>/dev/null | grep -q "443/tcp"; then
                need_config=true
            fi
            ;;
        iptables)
            if ! iptables -L INPUT -n 2>/dev/null | grep -q "dpt:80"; then
                need_config=true
            fi
            if ! iptables -L INPUT -n 2>/dev/null | grep -q "dpt:443"; then
                need_config=true
            fi
            ;;
    esac

    if [ "$need_config" = false ]; then
        echo -e "${gl_lv}✅ 端口 80/443 已开放${gl_bai}"
        return 0
    fi

    echo ""
    echo -e "${gl_huang}⚠️ 需要开放端口 80 和 443${gl_bai}"
    echo "  端口 80: Let's Encrypt 证书验证"
    echo "  端口 443: HTTPS 服务"
    echo ""
    read -e -p "是否自动配置防火墙? (y/n) [y]: " auto_config

    if [ "$auto_config" = "n" ] || [ "$auto_config" = "N" ]; then
        echo -e "${gl_huang}⚠️ 请手动开放端口 80 和 443${gl_bai}"
        return 0
    fi

    echo ""
    echo "正在配置防火墙..."

    case "$firewall_type" in
        ufw)
            ufw allow 80/tcp >/dev/null 2>&1
            ufw allow 443/tcp >/dev/null 2>&1
            echo -e "${gl_lv}✅ UFW 防火墙配置完成${gl_bai}"
            ;;
        firewalld)
            firewall-cmd --permanent --add-port=80/tcp >/dev/null 2>&1
            firewall-cmd --permanent --add-port=443/tcp >/dev/null 2>&1
            firewall-cmd --reload >/dev/null 2>&1
            echo -e "${gl_lv}✅ Firewalld 防火墙配置完成${gl_bai}"
            ;;
        iptables)
            iptables -I INPUT -p tcp --dport 80 -j ACCEPT
            iptables -I INPUT -p tcp --dport 443 -j ACCEPT
            # 尝试保存规则
            if command -v iptables-save &>/dev/null; then
                iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
            fi
            echo -e "${gl_lv}✅ Iptables 防火墙配置完成${gl_bai}"
            ;;
    esac

    return 0
}

# 检查域名解析
caddy_check_dns() {
    local domain=$1
    local server_ip=$(caddy_get_server_ip)

    echo -e "${gl_kjlan}检查域名解析...${gl_bai}"
    echo "域名: $domain"
    echo "本机IP: $server_ip"
    echo ""

    # 使用多个方法检查域名解析（优先使用公共 DNS 避免本地缓存问题）
    local resolved_ip=""

    # 方法1: dig @1.1.1.1 (Cloudflare DNS)
    if command -v dig &>/dev/null; then
        resolved_ip=$(dig +short @1.1.1.1 "$domain" A 2>/dev/null | grep -E '^[0-9]+\.' | head -1)
    fi

    # 方法2: nslookup 1.1.1.1 (fallback)
    if [ -z "$resolved_ip" ] && command -v nslookup &>/dev/null; then
        resolved_ip=$(nslookup "$domain" 1.1.1.1 2>/dev/null | grep -A1 "Name:" | grep "Address:" | awk '{print $2}' | head -1)
    fi

    # 方法3: host (fallback，使用默认 DNS)
    if [ -z "$resolved_ip" ] && command -v host &>/dev/null; then
        resolved_ip=$(host "$domain" 1.1.1.1 2>/dev/null | grep "has address" | awk '{print $4}' | head -1)
    fi

    if [ -z "$resolved_ip" ]; then
        echo -e "${gl_hong}⚠️ 无法解析域名 $domain${gl_bai}"
        echo ""
        echo "可能原因:"
        echo "  1. 域名尚未添加 DNS 记录"
        echo "  2. DNS 记录还在传播中（通常需要几分钟）"
        echo "  3. DNS 查询工具未安装"
        echo ""
        echo -e "${gl_huang}建议：${gl_bai}"
        echo "  请确保在 DNS 服务商添加 A 记录："
        echo "  类型: A"
        echo "  名称: $domain"
        echo "  内容: $server_ip"
        echo ""
        read -e -p "是否继续部署? (y/n) [y]: " continue_anyway
        if [ "$continue_anyway" = "n" ] || [ "$continue_anyway" = "N" ]; then
            return 1
        fi
        return 0
    fi

    echo "解析结果: $resolved_ip"
    echo ""

    if [ "$resolved_ip" = "$server_ip" ]; then
        echo -e "${gl_lv}✅ 域名解析正确${gl_bai}"
        return 0
    else
        echo -e "${gl_hong}❌ 域名解析不匹配${gl_bai}"
        echo ""
        echo "期望: $server_ip"
        echo "实际: $resolved_ip"
        echo ""
        echo -e "${gl_huang}请检查 DNS 配置：${gl_bai}"
        echo "  1. 确认 A 记录指向: $server_ip"
        echo "  2. 等待 DNS 传播完成（可能需要几分钟到几小时）"
        echo "  3. 如果使用 Cloudflare，请关闭橙色云朵（仅 DNS 模式）"
        echo ""
        read -e -p "是否继续部署? (y/n) [n]: " continue_anyway
        if [ "$continue_anyway" = "y" ] || [ "$continue_anyway" = "Y" ]; then
            return 0
        fi
        return 1
    fi
}

# 迁移旧配置到新的 sites-available/sites-enabled 架构
caddy_migrate_old_config() {
    # 检查是否需要迁移（旧配置直接写在 Caddyfile 中）
    if [ ! -f "$CADDY_CONFIG_FILE" ]; then
        return 0
    fi

    # 检查是否已经是新架构（包含 import 语句）
    if grep -q "^import.*sites-enabled" "$CADDY_CONFIG_FILE" 2>/dev/null; then
        return 0
    fi

    # 检查是否有域名列表文件
    if [ ! -f "$CADDY_DOMAIN_LIST_FILE" ] || [ ! -s "$CADDY_DOMAIN_LIST_FILE" ]; then
        return 0
    fi

    echo ""
    echo -e "${gl_huang}检测到旧版配置，正在迁移到新架构...${gl_bai}"

    # 从旧配置中提取邮箱
    local ssl_email=$(awk '/^[[:space:]]*email[[:space:]]+/ {print $2; exit}' "$CADDY_CONFIG_FILE" 2>/dev/null)
    [ -z "$ssl_email" ] && ssl_email="admin@example.com"

    # 备份旧配置
    cp "$CADDY_CONFIG_FILE" "${CADDY_CONFIG_FILE}.bak.$(date +%Y%m%d%H%M%S)"

    # 创建目录
    mkdir -p "$CADDY_SITES_AVAILABLE"
    mkdir -p "$CADDY_SITES_ENABLED"
    chown -R caddy:caddy "$CADDY_SITES_AVAILABLE" "$CADDY_SITES_ENABLED"

    # 从域名列表读取并创建独立配置文件
    while IFS='|' read -r domain backend timestamp; do
        if [ -n "$domain" ] && [ -n "$backend" ]; then
            local conf_file="$CADDY_SITES_AVAILABLE/${domain}.conf"

            # 创建独立配置文件
            cat > "$conf_file" << EOF
# ${domain} - 迁移于 $(date '+%Y-%m-%d %H:%M:%S')
${domain} {
    reverse_proxy ${backend} {
        header_up Host {host}
        header_up X-Real-IP {remote_host}
    }
}
EOF
            chown caddy:caddy "$conf_file"

            # 创建软链接到 sites-enabled（默认启用）
            ln -sf "$conf_file" "$CADDY_SITES_ENABLED/${domain}.conf"

            echo "  迁移: $domain → ${domain}.conf"
        fi
    done < "$CADDY_DOMAIN_LIST_FILE"

    # 更新 Caddyfile 为新格式
    cat > "$CADDY_CONFIG_FILE" << EOF
# Caddy 多域名反代配置（新架构）
# 域名配置文件位于: ${CADDY_SITES_AVAILABLE}/
# 启用的域名软链接: ${CADDY_SITES_ENABLED}/

{
    admin localhost:2019
    email ${ssl_email}
}

import ${CADDY_SITES_ENABLED}/*.conf
EOF
    chown caddy:caddy "$CADDY_CONFIG_FILE"

    echo -e "${gl_lv}✅ 配置迁移完成${gl_bai}"

    # 如果 Caddy 在运行，重载配置
    if systemctl is-active caddy &>/dev/null; then
        echo "正在重载 Caddy..."
        if systemctl reload caddy; then
            echo -e "${gl_lv}✅ Caddy 重载成功${gl_bai}"
        else
            echo -e "${gl_huang}⚠️ 重载失败，请手动重启 Caddy${gl_bai}"
        fi
    fi

    sleep 2
}

# 检查域名是否启用
caddy_is_domain_enabled() {
    local domain=$1
    [ -L "$CADDY_SITES_ENABLED/${domain}.conf" ]
}

# 安装 Caddy
caddy_install() {
    clear
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo -e "${gl_kjlan}  一键部署 Caddy${gl_bai}"
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo ""

    # 检查是否已安装
    local status=$(caddy_check_status)
    if [ "$status" != "not_installed" ]; then
        echo -e "${gl_huang}⚠️ Caddy 已安装${gl_bai}"
        echo ""
        read -e -p "是否重新安装/更新? (y/n) [n]: " reinstall
        if [ "$reinstall" != "y" ] && [ "$reinstall" != "Y" ]; then
            break_end
            return 0
        fi

        echo ""
        echo "正在停止现有服务..."
        systemctl stop "$CADDY_SERVICE_NAME" 2>/dev/null
    fi

    echo ""
    echo -e "${gl_kjlan}[1/6] 检查端口占用...${gl_bai}"

    # 检查 443 端口
    if ! caddy_handle_port_conflict 443 "HTTPS"; then
        break_end
        return 1
    fi

    # 检查 80 端口
    if ! caddy_handle_port_conflict 80 "HTTP"; then
        break_end
        return 1
    fi

    # 检查防火墙
    echo ""
    echo -e "${gl_kjlan}[2/6] 检查防火墙配置...${gl_bai}"
    if ! caddy_check_firewall; then
        break_end
        return 1
    fi

    echo ""
    echo -e "${gl_kjlan}[3/6] 安装必要工具...${gl_bai}"

    # 安装 curl 和 dig (用于域名解析检查)
    if ! command -v curl &>/dev/null || ! command -v dig &>/dev/null; then
        echo "正在安装工具..."
        if command -v apt-get &>/dev/null; then
            apt-get update -qq 2>/dev/null
            apt-get install -y curl dnsutils >/dev/null 2>&1
        elif command -v dnf &>/dev/null; then
            dnf install -y curl bind-utils >/dev/null 2>&1
        elif command -v yum &>/dev/null; then
            yum install -y curl bind-utils >/dev/null 2>&1
        fi
    fi
    echo -e "${gl_lv}✅ 工具检查完成${gl_bai}"

    echo ""
    echo -e "${gl_kjlan}[4/6] 下载并安装 Caddy...${gl_bai}"

    # 使用全局定义的 Caddy 版本
    local CADDY_VERSION="${CADDY_DEFAULT_VERSION}"
    local download_success=false

    # 下载源列表(按优先级)
    declare -a download_urls=(
        "https://github.com/caddyserver/caddy/releases/download/v${CADDY_VERSION}/caddy_${CADDY_VERSION}_linux_amd64.tar.gz"
        "https://caddyserver.com/api/download?os=linux&arch=amd64"
        "https://ghproxy.com/https://github.com/caddyserver/caddy/releases/download/v${CADDY_VERSION}/caddy_${CADDY_VERSION}_linux_amd64.tar.gz"
    )

    # 尝试多个下载源
    for url in "${download_urls[@]}"; do
        echo "尝试下载: $url"

        if [[ "$url" == *.tar.gz ]]; then
            # 下载 tar.gz 格式
            if curl -fsSL --connect-timeout 10 --max-time 60 "$url" -o /tmp/caddy.tar.gz 2>/dev/null; then
                echo "解压 Caddy..."
                if tar -xzf /tmp/caddy.tar.gz -C /tmp/ caddy 2>/dev/null; then
                    mv /tmp/caddy /usr/bin/caddy
                    chmod +x /usr/bin/caddy
                    rm -f /tmp/caddy.tar.gz
                    download_success=true
                    break
                fi
            fi
        else
            # 直接下载二进制文件
            if curl -fsSL --connect-timeout 10 --max-time 60 "$url" -o /usr/bin/caddy 2>/dev/null; then
                # 验证文件是否有效(检查文件大小)
                if [ -f /usr/bin/caddy ] && [ -s /usr/bin/caddy ]; then
                    local file_size=$(stat -f%z /usr/bin/caddy 2>/dev/null || stat -c%s /usr/bin/caddy 2>/dev/null)
                    # Caddy 二进制文件应该大于 10MB
                    if [ "$file_size" -gt 10485760 ]; then
                        chmod +x /usr/bin/caddy
                        download_success=true
                        break
                    else
                        echo "文件大小异常,尝试下一个源..."
                        rm -f /usr/bin/caddy
                    fi
                fi
            fi
        fi
    done

    # 检查下载结果
    if [ "$download_success" = false ]; then
        echo -e "${gl_hong}❌ 所有下载源均失败${gl_bai}"
        echo ""
        echo "请手动安装 Caddy:"
        echo "  wget https://github.com/caddyserver/caddy/releases/download/v${CADDY_VERSION}/caddy_${CADDY_VERSION}_linux_amd64.tar.gz"
        echo "  tar -xzf caddy_${CADDY_VERSION}_linux_amd64.tar.gz"
        echo "  mv caddy /usr/bin/caddy"
        echo "  chmod +x /usr/bin/caddy"
        echo ""
        break_end
        return 1
    fi

    # 验证安装
    if ! /usr/bin/caddy version &>/dev/null; then
        echo -e "${gl_hong}❌ Caddy 安装验证失败${gl_bai}"
        break_end
        return 1
    fi

    echo -e "${gl_lv}✅ Caddy 下载完成${gl_bai}"
    echo "版本: $(/usr/bin/caddy version 2>/dev/null | head -1)"

    echo ""
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo -e "${gl_huang}📧 配置 SSL 证书联系邮箱${gl_bai}"
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo ""
    echo "用途: Let's Encrypt 会发送证书过期提醒到此邮箱"
    echo "说明: 邮箱不需要真实存在,但格式必须正确"
    echo "示例: admin@yourdomain.com"
    echo ""

    local ssl_email=""
    while true; do
        read -e -p "请输入联系邮箱 [回车使用 caddy@localhost]: " ssl_email

        # 如果为空,使用默认值
        if [ -z "$ssl_email" ]; then
            ssl_email="caddy@localhost"
            break
        fi

        # 验证邮箱格式
        if echo "$ssl_email" | grep -qE '^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'; then
            # 检查是否是被禁止的域名
            if echo "$ssl_email" | grep -qE '@example\.(com|org|net)$'; then
                echo -e "${gl_hong}❌ 不能使用 example.com 等示例域名${gl_bai}"
                continue
            fi
            break
        else
            echo -e "${gl_hong}❌ 邮箱格式不正确,请重新输入${gl_bai}"
        fi
    done

    echo -e "${gl_lv}✅ 邮箱: $ssl_email${gl_bai}"

    echo ""
    echo -e "${gl_kjlan}[5/6] 配置 Caddy...${gl_bai}"

    # 创建配置目录
    mkdir -p "$CADDY_CONFIG_DIR"
    mkdir -p "$CADDY_CONFIG_BACKUP_DIR"
    mkdir -p "$CADDY_SITES_AVAILABLE"
    mkdir -p "$CADDY_SITES_ENABLED"
    mkdir -p /var/log/caddy
    mkdir -p /var/lib/caddy/.local/share/caddy
    mkdir -p /var/lib/caddy/.config/caddy

    # 创建 Caddy 用户
    if ! id -u caddy &>/dev/null; then
        useradd -r -s /bin/false caddy 2>/dev/null || true
    fi

    # 设置权限
    chown -R caddy:caddy "$CADDY_CONFIG_DIR"
    chown -R caddy:caddy /var/log/caddy
    chown -R caddy:caddy /var/lib/caddy

    # 创建初始 Caddyfile（使用 import 导入启用的站点配置）
    cat > "$CADDY_CONFIG_FILE" << EOF
# Caddy 多域名反代配置
# 使用脚本菜单添加反代域名

{
    admin localhost:2019
    email ${ssl_email}
}

# 导入所有启用的站点配置
import ${CADDY_SITES_ENABLED}/*.conf
EOF
    chown caddy:caddy "$CADDY_CONFIG_FILE"

    # 迁移旧配置（如果存在旧格式的配置）
    caddy_migrate_old_config

    # 创建 systemd 服务
    cat > /etc/systemd/system/caddy.service << 'EOF'
[Unit]
Description=Caddy Web Server
Documentation=https://caddyserver.com/docs/
After=network.target network-online.target
Requires=network-online.target

[Service]
Type=notify
User=caddy
Group=caddy
Environment="HOME=/var/lib/caddy"
ExecStart=/usr/bin/caddy run --environ --config /etc/caddy/Caddyfile
ExecReload=/usr/bin/caddy reload --config /etc/caddy/Caddyfile --force
TimeoutStopSec=5s
LimitNOFILE=1048576
LimitNPROC=512
PrivateTmp=true
ProtectSystem=full
AmbientCapabilities=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
EOF

    echo -e "${gl_lv}✅ 配置完成${gl_bai}"

    echo ""
    echo -e "${gl_kjlan}[6/6] 启动 Caddy 服务...${gl_bai}"

    systemctl daemon-reload
    systemctl enable caddy >/dev/null 2>&1
    systemctl start caddy

    sleep 2

    if systemctl is-active caddy &>/dev/null; then
        echo -e "${gl_lv}✅ Caddy 启动成功${gl_bai}"

        local server_ip=$(caddy_get_server_ip)

        echo ""
        echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
        echo -e "${gl_lv}🎉 Caddy 部署成功!${gl_bai}"
        echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
        echo ""
        echo "服务器 IP: $server_ip"
        echo "配置文件: $CADDY_CONFIG_FILE"
        echo ""
        echo -e "${gl_huang}下一步:${gl_bai}"
        echo "  请使用菜单 [2. 添加反代域名] 来配置反向代理"
        echo ""
    else
        echo -e "${gl_hong}❌ Caddy 启动失败${gl_bai}"
        echo ""
        echo "查看错误日志:"
        echo "  journalctl -u caddy -n 50 --no-pager"
        echo ""
    fi

    break_end
}

# 添加反代域名
caddy_add_domain() {
    clear
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo -e "${gl_kjlan}  添加反代域名${gl_bai}"
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo ""

    # 检查 Caddy 是否已安装
    local status=$(caddy_check_status)
    if [ "$status" = "not_installed" ]; then
        echo -e "${gl_hong}❌ Caddy 未安装${gl_bai}"
        echo "请先使用 [1. 一键部署 Caddy]"
        break_end
        return 1
    fi

    if [ "$status" != "running" ]; then
        echo -e "${gl_huang}⚠️ Caddy 未运行${gl_bai}"
        read -e -p "是否启动 Caddy? (y/n) [y]: " start_caddy
        if [ "$start_caddy" != "n" ] && [ "$start_caddy" != "N" ]; then
            systemctl start caddy
            sleep 2
            if ! systemctl is-active caddy &>/dev/null; then
                echo -e "${gl_hong}❌ Caddy 启动失败${gl_bai}"
                break_end
                return 1
            fi
        else
            break_end
            return 1
        fi
    fi

    echo -e "${gl_huang}配置示例:${gl_bai}"
    echo "  域名: vox.moe"
    echo "  后端: 123.45.67.89:8181"
    echo ""

    # 输入域名
    read -e -p "请输入域名: " domain

    if [ -z "$domain" ]; then
        echo -e "${gl_hong}❌ 域名不能为空${gl_bai}"
        break_end
        return 1
    fi

    # 简单验证域名格式
    if ! echo "$domain" | grep -qE '^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$'; then
        echo -e "${gl_hong}❌ 域名格式不正确${gl_bai}"
        break_end
        return 1
    fi

    # 检查域名是否已存在
    if [ -f "$CADDY_DOMAIN_LIST_FILE" ] && grep -q "^${domain}|" "$CADDY_DOMAIN_LIST_FILE" 2>/dev/null; then
        echo -e "${gl_hong}❌ 域名 $domain 已存在${gl_bai}"
        break_end
        return 1
    fi

    echo ""

    # 检查域名解析
    if ! caddy_check_dns "$domain"; then
        break_end
        return 1
    fi

    echo ""

    # 输入后端地址
    read -e -p "请输入后端地址 (IP:端口): " backend

    if [ -z "$backend" ]; then
        echo -e "${gl_hong}❌ 后端地址不能为空${gl_bai}"
        break_end
        return 1
    fi

    # 验证后端地址格式
    if ! echo "$backend" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:[0-9]+$'; then
        echo -e "${gl_hong}❌ 后端地址格式不正确 (应为 IP:端口)${gl_bai}"
        break_end
        return 1
    fi

    echo ""
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo "域名: $domain"
    echo "后端: $backend"
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo ""
    read -e -p "确认添加? (y/n) [y]: " confirm

    if [ "$confirm" = "n" ] || [ "$confirm" = "N" ]; then
        echo "取消添加"
        break_end
        return 0
    fi

    echo ""
    echo -e "${gl_kjlan}[1/3] 创建配置文件...${gl_bai}"

    # 确保目录存在
    mkdir -p "$CADDY_SITES_AVAILABLE"
    mkdir -p "$CADDY_SITES_ENABLED"

    local conf_file="$CADDY_SITES_AVAILABLE/${domain}.conf"

    # 创建独立配置文件
    cat > "$conf_file" << EOF
# ${domain} - 添加于 $(date '+%Y-%m-%d %H:%M:%S')
${domain} {
    reverse_proxy ${backend} {
        header_up Host {host}
        header_up X-Real-IP {remote_host}
    }
}
EOF
    chown caddy:caddy "$conf_file"

    echo -e "${gl_lv}✅ 配置文件已创建: ${domain}.conf${gl_bai}"

    echo ""
    echo -e "${gl_kjlan}[2/3] 启用域名...${gl_bai}"

    # 创建软链接到 sites-enabled
    ln -sf "$conf_file" "$CADDY_SITES_ENABLED/${domain}.conf"

    echo -e "${gl_lv}✅ 域名已启用${gl_bai}"

    # 记录到域名列表
    echo "${domain}|${backend}|$(date +%s)" >> "$CADDY_DOMAIN_LIST_FILE"

    echo ""
    echo -e "${gl_kjlan}[3/3] 重载 Caddy...${gl_bai}"

    # 先测试配置
    if ! caddy validate --config "$CADDY_CONFIG_FILE" 2>/dev/null; then
        echo -e "${gl_hong}❌ 配置文件验证失败${gl_bai}"
        echo "正在清理..."

        # 删除配置文件和软链接
        rm -f "$CADDY_SITES_ENABLED/${domain}.conf"
        rm -f "$conf_file"

        # 从域名列表中删除
        if [ -f "$CADDY_DOMAIN_LIST_FILE" ]; then
            sed -i "/^${domain}|/d" "$CADDY_DOMAIN_LIST_FILE"
        fi

        break_end
        return 1
    fi

    # 检查 Caddy 是否在运行
    local caddy_running=false
    if systemctl is-active caddy &>/dev/null; then
        caddy_running=true
        # 重载 Caddy（零停机）
        if ! systemctl reload caddy; then
            echo -e "${gl_hong}❌ Caddy 重载失败${gl_bai}"
            echo "正在清理..."
            rm -f "$CADDY_SITES_ENABLED/${domain}.conf"
            rm -f "$conf_file"
            if [ -f "$CADDY_DOMAIN_LIST_FILE" ]; then
                sed -i "/^${domain}|/d" "$CADDY_DOMAIN_LIST_FILE"
            fi
            systemctl restart caddy
            break_end
            return 1
        fi
        echo -e "${gl_lv}✅ Caddy 重载成功${gl_bai}"
    fi

    echo ""
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo -e "${gl_lv}🎉 反代配置成功!${gl_bai}"
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo ""
    echo "访问地址: https://${domain}"
    echo "后端服务: ${backend}"
    echo ""
    if [ "$caddy_running" = true ]; then
        echo -e "${gl_huang}说明:${gl_bai}"
        echo "  ⏳ Caddy 正在自动申请 SSL 证书..."
        echo "  ⏳ 首次访问可能需要等待几秒钟"
        echo "  ✅ 证书申请成功后即可通过 HTTPS 访问"
    else
        echo -e "${gl_huang}⚠️ Caddy 未运行${gl_bai}"
        echo "  请使用菜单 [7. 启动 Caddy] 启动服务"
        echo "  启动后将自动申请 SSL 证书"
    fi
    echo ""
    echo -e "${gl_huang}提示:${gl_bai}"
    echo "  - 使用 [9. 查看 Caddy 日志] 可查看证书申请状态"
    echo "  - 证书由 Let's Encrypt 签发，自动续期"
    echo ""

    break_end
}

# 查看已配置域名
caddy_list_domains() {
    clear
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo -e "${gl_kjlan}  已配置域名列表${gl_bai}"
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo ""

    if [ ! -f "$CADDY_DOMAIN_LIST_FILE" ] || [ ! -s "$CADDY_DOMAIN_LIST_FILE" ]; then
        echo -e "${gl_huang}暂无配置的域名${gl_bai}"
        echo ""
        echo "请使用 [2. 添加反代域名] 来添加配置"
        break_end
        return 0
    fi

    local count=1
    local enabled_count=0
    local disabled_count=0

    echo -e "${gl_kjlan}序号  状态      域名                    后端地址               添加时间${gl_bai}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    while IFS='|' read -r domain backend timestamp; do
        if [ -n "$domain" ]; then
            local add_time=$(date -d "@$timestamp" '+%Y-%m-%d %H:%M' 2>/dev/null || date -r "$timestamp" '+%Y-%m-%d %H:%M' 2>/dev/null || echo "未知")
            local status_icon
            if caddy_is_domain_enabled "$domain"; then
                status_icon="${gl_lv}✅启用${gl_bai}"
                enabled_count=$((enabled_count + 1))
            else
                status_icon="${gl_hong}❌禁用${gl_bai}"
                disabled_count=$((disabled_count + 1))
            fi
            printf "%-6s%-10b%-24s%-23s%s\n" "$count" "$status_icon" "$domain" "$backend" "$add_time"
            count=$((count + 1))
        fi
    done < "$CADDY_DOMAIN_LIST_FILE"

    echo ""
    echo -e "总计: $((count - 1)) 个域名 (${gl_lv}启用: $enabled_count${gl_bai}, ${gl_hong}禁用: $disabled_count${gl_bai})"
    echo ""

    break_end
}

# 删除反代域名
caddy_delete_domain() {
    clear
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo -e "${gl_kjlan}  删除反代域名${gl_bai}"
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo ""

    if [ ! -f "$CADDY_DOMAIN_LIST_FILE" ] || [ ! -s "$CADDY_DOMAIN_LIST_FILE" ]; then
        echo -e "${gl_huang}暂无配置的域名${gl_bai}"
        break_end
        return 0
    fi

    # 显示域名列表
    local count=1
    declare -a domains
    declare -a backends

    echo -e "${gl_kjlan}序号  域名                    后端地址${gl_bai}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    while IFS='|' read -r domain backend timestamp; do
        if [ -n "$domain" ]; then
            printf "%-6s%-24s%s\n" "$count" "$domain" "$backend"
            domains[$count]="$domain"
            backends[$count]="$backend"
            count=$((count + 1))
        fi
    done < "$CADDY_DOMAIN_LIST_FILE"

    echo ""
    read -e -p "请输入要删除的序号 (0 取消): " choice

    if [ -z "$choice" ] || [ "$choice" = "0" ]; then
        echo "取消删除"
        break_end
        return 0
    fi

    if ! [[ "$choice" =~ ^[0-9]+$ ]] || [ "$choice" -lt 1 ] || [ "$choice" -ge "$count" ]; then
        echo -e "${gl_hong}❌ 无效的序号${gl_bai}"
        break_end
        return 1
    fi

    local domain_to_delete="${domains[$choice]}"
    local backend_to_delete="${backends[$choice]}"

    echo ""
    echo -e "${gl_hong}确认删除:${gl_bai}"
    echo "  域名: $domain_to_delete"
    echo "  后端: $backend_to_delete"
    echo ""
    read -e -p "确认删除? (y/n) [n]: " confirm

    if [ "$confirm" != "y" ] && [ "$confirm" != "Y" ]; then
        echo "取消删除"
        break_end
        return 0
    fi

    echo ""
    echo -e "${gl_kjlan}[1/2] 删除配置文件...${gl_bai}"

    # 删除软链接和配置文件
    rm -f "$CADDY_SITES_ENABLED/${domain_to_delete}.conf"
    rm -f "$CADDY_SITES_AVAILABLE/${domain_to_delete}.conf"

    echo -e "${gl_lv}✅ 配置文件已删除${gl_bai}"

    # 从域名列表中删除
    sed -i "/^${domain_to_delete}|/d" "$CADDY_DOMAIN_LIST_FILE"

    echo ""
    echo -e "${gl_lv}✅ 域名 $domain_to_delete 已删除${gl_bai}"

    # 检查 Caddy 是否在运行，在运行才重载
    if systemctl is-active caddy &>/dev/null; then
        echo ""
        echo -e "${gl_kjlan}[2/2] 重载 Caddy...${gl_bai}"

        # 验证配置
        if ! caddy validate --config "$CADDY_CONFIG_FILE" 2>/dev/null; then
            echo -e "${gl_hong}❌ 配置文件验证失败${gl_bai}"
            break_end
            return 1
        fi

        # 重载 Caddy（零停机）
        if systemctl reload caddy; then
            echo -e "${gl_lv}✅ Caddy 重载成功${gl_bai}"
        else
            echo -e "${gl_huang}⚠️ 重载失败，尝试重启...${gl_bai}"
            systemctl restart caddy
        fi
    else
        echo -e "${gl_huang}ℹ️ Caddy 未运行，配置将在下次启动时生效${gl_bai}"
    fi

    break_end
}

# 启用/禁用域名
caddy_toggle_domain() {
    while true; do
        clear
        echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
        echo -e "${gl_kjlan}  启用/禁用域名${gl_bai}"
        echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
        echo ""

        if [ ! -f "$CADDY_DOMAIN_LIST_FILE" ] || [ ! -s "$CADDY_DOMAIN_LIST_FILE" ]; then
            echo -e "${gl_huang}暂无配置的域名${gl_bai}"
            break_end
            return 0
        fi

        # 显示域名列表（带状态）
        local count=1
        declare -a domains
        declare -a backends
        declare -a statuses

        echo -e "${gl_kjlan}序号  状态      域名                    后端地址${gl_bai}"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

        while IFS='|' read -r domain backend timestamp; do
            if [ -n "$domain" ]; then
                local status_icon
                local status_text
                if caddy_is_domain_enabled "$domain"; then
                    status_icon="${gl_lv}✅启用${gl_bai}"
                    status_text="enabled"
                else
                    status_icon="${gl_hong}❌禁用${gl_bai}"
                    status_text="disabled"
                fi
                printf "%-6s%-10b%-24s%s\n" "$count" "$status_icon" "$domain" "$backend"
                domains[$count]="$domain"
                backends[$count]="$backend"
                statuses[$count]="$status_text"
                count=$((count + 1))
            fi
        done < "$CADDY_DOMAIN_LIST_FILE"

        echo ""
        echo "输入序号切换状态，0 返回"
        read -e -p "请选择: " choice

        if [ -z "$choice" ] || [ "$choice" = "0" ]; then
            return 0
        fi

        if ! [[ "$choice" =~ ^[0-9]+$ ]] || [ "$choice" -lt 1 ] || [ "$choice" -ge "$count" ]; then
            echo -e "${gl_hong}❌ 无效的序号${gl_bai}"
            sleep 1
            continue
        fi

        local domain_to_toggle="${domains[$choice]}"
        local current_status="${statuses[$choice]}"

        echo ""
        if [ "$current_status" = "enabled" ]; then
            # 禁用域名：删除软链接
            rm -f "$CADDY_SITES_ENABLED/${domain_to_toggle}.conf"
            echo -e "${gl_huang}正在禁用 $domain_to_toggle ...${gl_bai}"
        else
            # 启用域名：创建软链接
            ln -sf "$CADDY_SITES_AVAILABLE/${domain_to_toggle}.conf" "$CADDY_SITES_ENABLED/${domain_to_toggle}.conf"
            echo -e "${gl_lv}正在启用 $domain_to_toggle ...${gl_bai}"
        fi

        # 验证配置
        if ! caddy validate --config "$CADDY_CONFIG_FILE" 2>/dev/null; then
            echo -e "${gl_hong}❌ 配置验证失败，正在恢复...${gl_bai}"
            # 恢复原状态
            if [ "$current_status" = "enabled" ]; then
                ln -sf "$CADDY_SITES_AVAILABLE/${domain_to_toggle}.conf" "$CADDY_SITES_ENABLED/${domain_to_toggle}.conf"
            else
                rm -f "$CADDY_SITES_ENABLED/${domain_to_toggle}.conf"
            fi
            sleep 1
            continue
        fi

        # 检查 Caddy 是否在运行
        if systemctl is-active caddy &>/dev/null; then
            if systemctl reload caddy; then
                if [ "$current_status" = "enabled" ]; then
                    echo -e "${gl_lv}✅ $domain_to_toggle 已禁用${gl_bai}"
                else
                    echo -e "${gl_lv}✅ $domain_to_toggle 已启用${gl_bai}"
                fi
            else
                echo -e "${gl_huang}⚠️ 重载失败，尝试重启...${gl_bai}"
                systemctl restart caddy
            fi
        else
            if [ "$current_status" = "enabled" ]; then
                echo -e "${gl_lv}✅ $domain_to_toggle 已禁用${gl_bai}"
            else
                echo -e "${gl_lv}✅ $domain_to_toggle 已启用${gl_bai}"
            fi
            echo -e "${gl_huang}ℹ️ Caddy 未运行，配置将在下次启动时生效${gl_bai}"
        fi

        sleep 1
    done
}

# 重载 Caddy 配置
caddy_reload() {
    clear
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo -e "${gl_kjlan}  重载 Caddy 配置${gl_bai}"
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo ""

    local status=$(caddy_check_status)
    if [ "$status" = "not_installed" ]; then
        echo -e "${gl_hong}❌ Caddy 未安装${gl_bai}"
        break_end
        return 1
    fi

    echo "正在验证配置文件..."
    if ! caddy validate --config "$CADDY_CONFIG_FILE" 2>/dev/null; then
        echo -e "${gl_hong}❌ 配置文件验证失败${gl_bai}"
        echo ""
        echo "请检查配置文件: $CADDY_CONFIG_FILE"
        echo "查看详细错误: caddy validate --config $CADDY_CONFIG_FILE"
        break_end
        return 1
    fi

    echo -e "${gl_lv}✅ 配置文件验证通过${gl_bai}"
    echo ""

    # 检查 Caddy 是否在运行
    if ! systemctl is-active caddy &>/dev/null; then
        echo -e "${gl_huang}⚠️ Caddy 未运行${gl_bai}"
        echo ""
        echo "请先使用 [7. 启动 Caddy] 启动服务"
        break_end
        return 1
    fi

    echo "正在重载 Caddy..."
    if systemctl reload caddy; then
        echo -e "${gl_lv}✅ Caddy 重载成功${gl_bai}"
    else
        echo -e "${gl_hong}❌ Caddy 重载失败${gl_bai}"
        echo ""
        echo "查看错误日志: journalctl -u caddy -n 50"
    fi

    break_end
}

# 查看 Caddy 状态
caddy_show_status() {
    clear
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo -e "${gl_kjlan}  Caddy 状态${gl_bai}"
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo ""

    local status=$(caddy_check_status)

    case "$status" in
        "running")
            echo -e "服务状态: ${gl_lv}✅ 运行中${gl_bai}"
            ;;
        "stopped")
            echo -e "服务状态: ${gl_hong}❌ 已停止${gl_bai}"
            ;;
        "not_installed")
            echo -e "服务状态: ${gl_hui}未安装${gl_bai}"
            break_end
            return 0
            ;;
        *)
            echo -e "服务状态: ${gl_huang}⚠️ 未知${gl_bai}"
            ;;
    esac

    echo ""

    # 显示版本
    if command -v caddy &>/dev/null; then
        local version=$(caddy version 2>/dev/null | head -1)
        echo "Caddy 版本: $version"
    fi

    echo ""

    # 显示端口监听
    echo -e "${gl_kjlan}端口监听:${gl_bai}"
    if ss -lntp 2>/dev/null | grep -q ":443 "; then
        echo -e "  443/tcp: ${gl_lv}✅ 监听中${gl_bai}"
    else
        echo -e "  443/tcp: ${gl_hong}❌ 未监听${gl_bai}"
    fi

    if ss -lntp 2>/dev/null | grep -q ":80 "; then
        echo -e "  80/tcp: ${gl_lv}✅ 监听中${gl_bai}"
    else
        echo -e "  80/tcp: ${gl_hong}❌ 未监听${gl_bai}"
    fi

    echo ""

    # 显示配置的域名数量
    if [ -f "$CADDY_DOMAIN_LIST_FILE" ]; then
        local domain_count=$(wc -l < "$CADDY_DOMAIN_LIST_FILE" 2>/dev/null || echo 0)
        echo "配置域名: $domain_count 个"
    else
        echo "配置域名: 0 个"
    fi

    echo ""
    echo "配置文件: $CADDY_CONFIG_FILE"

    echo ""
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo ""

    read -e -p "是否查看详细服务状态? (y/n) [n]: " show_detail
    if [ "$show_detail" = "y" ] || [ "$show_detail" = "Y" ]; then
        echo ""
        systemctl status caddy --no-pager -l
    fi

    break_end
}

# 查看 Caddy 日志
caddy_show_logs() {
    clear
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo -e "${gl_kjlan}  Caddy 日志${gl_bai}"
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo ""

    local status=$(caddy_check_status)
    if [ "$status" = "not_installed" ]; then
        echo -e "${gl_hong}❌ Caddy 未安装${gl_bai}"
        break_end
        return 1
    fi

    echo "1. 查看最近 50 行日志"
    echo "2. 查看最近 100 行日志"
    echo "3. 实时查看日志（Ctrl+C 退出）"
    echo "4. 查看错误日志"
    echo "0. 返回"
    echo ""
    read -e -p "请选择 [0-4]: " log_choice

    echo ""

    case "$log_choice" in
        1)
            journalctl -u caddy -n 50 --no-pager
            ;;
        2)
            journalctl -u caddy -n 100 --no-pager
            ;;
        3)
            echo "按 Ctrl+C 退出..."
            echo ""
            journalctl -u caddy -f
            ;;
        4)
            journalctl -u caddy -p err -n 50 --no-pager
            ;;
        0|*)
            return 0
            ;;
    esac

    break_end
}

# 启动/停止 Caddy
caddy_toggle_service() {
    local status=$(caddy_check_status)

    if [ "$status" = "not_installed" ]; then
        echo -e "${gl_hong}❌ Caddy 未安装${gl_bai}"
        sleep 2
        return 1
    fi

    if [ "$status" = "running" ]; then
        # 当前运行中，执行停止
        echo -e "${gl_huang}正在停止 Caddy...${gl_bai}"
        systemctl stop caddy
        sleep 1
        if ! systemctl is-active caddy &>/dev/null; then
            echo -e "${gl_lv}✅ Caddy 已停止${gl_bai}"
        else
            echo -e "${gl_hong}❌ 停止失败${gl_bai}"
        fi
    else
        # 当前已停止，执行启动
        echo -e "${gl_huang}正在启动 Caddy...${gl_bai}"
        systemctl start caddy
        sleep 1
        if systemctl is-active caddy &>/dev/null; then
            echo -e "${gl_lv}✅ Caddy 已启动${gl_bai}"
        else
            echo -e "${gl_hong}❌ 启动失败${gl_bai}"
            echo "查看错误: journalctl -u caddy -n 20"
        fi
    fi
    sleep 2
}

# 卸载 Caddy
caddy_uninstall() {
    clear
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo -e "${gl_hong}  卸载 Caddy${gl_bai}"
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo ""

    local status=$(caddy_check_status)
    if [ "$status" = "not_installed" ]; then
        echo -e "${gl_hong}❌ Caddy 未安装${gl_bai}"
        break_end
        return 0
    fi

    echo -e "${gl_hong}⚠️ 此操作将删除 Caddy 及其配置${gl_bai}"
    echo ""
    echo "将要删除:"
    echo "  - Caddy 程序"
    echo "  - systemd 服务"
    echo "  - 配置文件"
    echo "  - SSL 证书"
    echo ""
    read -e -p "是否保留配置备份？(y/n) [y]: " keep_backup
    echo ""
    read -e -p "确认卸载? (y/n) [n]: " confirm

    if [ "$confirm" != "y" ] && [ "$confirm" != "Y" ]; then
        echo "取消卸载"
        break_end
        return 0
    fi

    echo ""
    echo "正在卸载..."
    echo ""

    # 停止并禁用服务
    echo "停止服务..."
    systemctl stop caddy 2>/dev/null
    systemctl disable caddy 2>/dev/null

    # 删除 systemd 服务文件
    echo "删除服务..."
    rm -f /etc/systemd/system/caddy.service
    systemctl daemon-reload

    # 删除 Caddy 程序
    echo "删除程序..."
    rm -f /usr/bin/caddy

    # 删除配置
    if [ "$keep_backup" = "n" ] || [ "$keep_backup" = "N" ]; then
        echo "删除配置..."
        rm -rf "$CADDY_CONFIG_DIR"
        rm -rf /var/lib/caddy
        rm -rf /var/log/caddy
    else
        echo "保留配置备份..."
        # 只删除主配置文件
        rm -f "$CADDY_CONFIG_FILE"
        rm -f "$CADDY_DOMAIN_LIST_FILE"
        echo "配置备份保留在: $CADDY_CONFIG_BACKUP_DIR"
    fi

    # 删除用户
    if id -u caddy &>/dev/null; then
        userdel caddy 2>/dev/null
    fi

    echo ""
    echo -e "${gl_lv}✅ Caddy 已卸载${gl_bai}"

    break_end
}

# Caddy 管理主菜单
manage_caddy() {
    # 首次进入时检测旧配置并迁移
    caddy_migrate_old_config

    while true; do
        clear
        echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
        echo -e "${gl_kjlan}  Caddy 多域名反代 🚀${gl_bai}"
        echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
        echo ""

        # 显示当前状态
        local status=$(caddy_check_status)
        local server_ip=$(caddy_get_server_ip)

        case "$status" in
            "running")
                echo -e "服务状态: ${gl_lv}✅ 运行中${gl_bai}"
                ;;
            "stopped")
                echo -e "服务状态: ${gl_hong}❌ 已停止${gl_bai}"
                ;;
            "not_installed")
                echo -e "服务状态: ${gl_hui}未安装${gl_bai}"
                ;;
            *)
                echo -e "服务状态: ${gl_huang}⚠️ 未知${gl_bai}"
                ;;
        esac

        echo -e "服务器IP: ${gl_huang}${server_ip}${gl_bai}"

        # 显示域名数量
        if [ -f "$CADDY_DOMAIN_LIST_FILE" ]; then
            local domain_count=$(wc -l < "$CADDY_DOMAIN_LIST_FILE" 2>/dev/null || echo 0)
            echo -e "配置域名: ${gl_huang}${domain_count}${gl_bai} 个"
        fi

        echo ""
        echo "1. 一键部署 Caddy"
        echo "2. 添加反代域名"
        echo "3. 查看已配置域名"
        echo "4. 删除反代域名"
        echo "5. 启用/禁用域名"
        echo "6. 重载 Caddy 配置"
        # 根据状态显示启动或停止
        if [ "$status" = "running" ]; then
            echo "7. 停止 Caddy ⏸️"
        else
            echo "7. 启动 Caddy ▶️"
        fi
        echo "8. 查看 Caddy 状态"
        echo "9. 查看 Caddy 日志"
        echo "10. 卸载 Caddy"
        echo "0. 返回主菜单"
        echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"

        read -e -p "请选择操作 [0-10]: " choice

        case $choice in
            1)
                caddy_install
                ;;
            2)
                caddy_add_domain
                ;;
            3)
                caddy_list_domains
                ;;
            4)
                caddy_delete_domain
                ;;
            5)
                caddy_toggle_domain
                ;;
            6)
                caddy_reload
                ;;
            7)
                caddy_toggle_service
                ;;
            8)
                caddy_show_status
                ;;
            9)
                caddy_show_logs
                ;;
            10)
                caddy_uninstall
                ;;
            0)
                return
                ;;
            *)
                echo "无效的选择"
                sleep 2
                ;;
        esac
    done
}

# =====================================================
# OpenClaw 部署管理 (AI多渠道消息网关)
# =====================================================

# 常量定义
OPENCLAW_SERVICE_NAME="openclaw-gateway"
OPENCLAW_HOME_DIR="${HOME}/.openclaw"
OPENCLAW_CONFIG_FILE="${HOME}/.openclaw/openclaw.json"
OPENCLAW_ENV_FILE="${HOME}/.openclaw/.env"
OPENCLAW_DEFAULT_PORT="18789"

# 检测 OpenClaw 状态
openclaw_check_status() {
    if ! command -v openclaw &>/dev/null; then
        echo "not_installed"
    elif systemctl is-active "$OPENCLAW_SERVICE_NAME" &>/dev/null; then
        echo "running"
    elif systemctl is-enabled "$OPENCLAW_SERVICE_NAME" &>/dev/null; then
        echo "stopped"
    else
        echo "installed_no_service"
    fi
}

# 获取当前端口
openclaw_get_port() {
    if [ -f "$OPENCLAW_CONFIG_FILE" ]; then
        # 兼容 JSON5 格式（key 无引号: port: 19966）和标准 JSON（"port": 19966）
        local port=$(sed -nE 's/.*"?port"?[[:space:]]*:[[:space:]]*([0-9]+).*/\1/p' "$OPENCLAW_CONFIG_FILE" 2>/dev/null | head -1)
        if [ -n "$port" ]; then
            echo "$port"
            return
        fi
    fi
    echo "$OPENCLAW_DEFAULT_PORT"
}

# 检查端口是否可用
openclaw_check_port() {
    local port=$1
    if ss -lntp 2>/dev/null | grep -q ":${port} "; then
        return 1
    fi
    return 0
}

# 检测并安装 Node.js 22+
openclaw_install_nodejs() {
    echo -e "${gl_kjlan}[1/4] 检测 Node.js 环境...${gl_bai}"

    if command -v node &>/dev/null; then
        local node_version=$(node -v | sed 's/v//' | cut -d. -f1)
        if [ "$node_version" -ge 22 ]; then
            echo -e "${gl_lv}✅ Node.js $(node -v) 已安装${gl_bai}"
            return 0
        else
            echo -e "${gl_huang}⚠ Node.js 版本过低 ($(node -v))，OpenClaw 需要 22+${gl_bai}"
        fi
    else
        echo -e "${gl_huang}⚠ Node.js 未安装${gl_bai}"
    fi

    echo "正在安装 Node.js 22..."

    if [ -f /etc/os-release ]; then
        . /etc/os-release
        local os_id="${ID,,}"
    fi

    local setup_script=$(mktemp)
    local script_url=""

    if [[ "$os_id" == "debian" || "$os_id" == "ubuntu" ]]; then
        script_url="https://deb.nodesource.com/setup_22.x"
    elif [[ "$os_id" == "centos" || "$os_id" == "rhel" || "$os_id" == "fedora" || "$os_id" == "rocky" || "$os_id" == "alma" ]]; then
        script_url="https://rpm.nodesource.com/setup_22.x"
    fi

    if [ -n "$script_url" ]; then
        if ! curl -fsSL --connect-timeout 15 --max-time 60 "$script_url" -o "$setup_script" 2>/dev/null; then
            echo -e "${gl_hong}❌ 下载 Node.js 设置脚本失败${gl_bai}"
            rm -f "$setup_script"
            return 1
        fi

        if ! head -1 "$setup_script" | grep -q "^#!"; then
            echo -e "${gl_hong}❌ 脚本格式验证失败${gl_bai}"
            rm -f "$setup_script"
            return 1
        fi

        chmod +x "$setup_script"
        bash "$setup_script" >/dev/null 2>&1
        rm -f "$setup_script"
    fi

    if [[ "$os_id" == "debian" || "$os_id" == "ubuntu" ]]; then
        apt-get install -y nodejs >/dev/null 2>&1
    elif [[ "$os_id" == "centos" || "$os_id" == "rhel" || "$os_id" == "fedora" || "$os_id" == "rocky" || "$os_id" == "alma" ]]; then
        if command -v dnf &>/dev/null; then
            dnf install -y nodejs >/dev/null 2>&1
        else
            yum install -y nodejs >/dev/null 2>&1
        fi
    else
        echo -e "${gl_hong}❌ 不支持的系统，请手动安装 Node.js 22+${gl_bai}"
        return 1
    fi

    if command -v node &>/dev/null; then
        local installed_ver=$(node -v | sed 's/v//' | cut -d. -f1)
        if [ "$installed_ver" -ge 22 ]; then
            echo -e "${gl_lv}✅ Node.js $(node -v) 安装成功${gl_bai}"
            return 0
        else
            echo -e "${gl_hong}❌ 安装的 Node.js 版本仍低于 22，请手动升级${gl_bai}"
            return 1
        fi
    else
        echo -e "${gl_hong}❌ Node.js 安装失败${gl_bai}"
        return 1
    fi
}

# 安装 OpenClaw
openclaw_install_pkg() {
    echo -e "${gl_kjlan}[2/4] 安装 OpenClaw...${gl_bai}"
    echo -e "${gl_hui}正在下载并安装，可能需要 1-3 分钟...${gl_bai}"
    echo ""

    npm install -g openclaw@latest --loglevel info

    if command -v openclaw &>/dev/null; then
        local ver=$(openclaw --version 2>/dev/null || echo "unknown")
        echo -e "${gl_lv}✅ OpenClaw ${ver} 安装成功${gl_bai}"
        return 0
    else
        echo -e "${gl_hong}❌ OpenClaw 安装失败${gl_bai}"
        return 1
    fi
}

# 交互式模型配置
openclaw_config_model() {
    clear
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo -e "${gl_kjlan}  OpenClaw 模型配置${gl_bai}"
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo ""

    # 步骤1: 选择 API 来源
    echo -e "${gl_kjlan}[步骤1] 选择你的 API 来源${gl_bai}"
    echo ""
    echo -e "${gl_lv}── 已验证可用的反代 ──${gl_bai}"
    echo "1. CRS 反代 (Claude)         — anthropic-messages 协议"
    echo "2. sub2api 反代 (Gemini)      — google-generative-ai 协议"
    echo "3. sub2api 反代 (GPT)         — openai-responses 协议"
    echo "4. sub2api Antigravity (Claude) — anthropic-messages 协议"
    echo ""
    echo -e "${gl_huang}── 通用配置 ──${gl_bai}"
    echo "5. Anthropic 直连反代（自建 Nginx/Caddy 反代）"
    echo "6. OpenAI 兼容中转（new-api / one-api / LiteLLM 等）"
    echo "7. OpenRouter"
    echo "8. Google Gemini 反代（其他 Gemini 代理）"
    echo ""
    echo -e "${gl_zi}── 官方直连 ──${gl_bai}"
    echo "9. Anthropic 官方 API Key"
    echo "10. Google Gemini 官方 API Key"
    echo "11. OpenAI 官方 API Key"
    echo ""
    read -e -p "请选择 [1-11]: " api_choice

    local api_type=""
    local base_url=""
    local provider_name="my-proxy"
    local need_base_url=true
    local need_api_key=true
    local preset_mode=""  # crs / sub2api-gemini / sub2api-gpt / sub2api-antigravity / 空=手动

    case "$api_choice" in
        1)
            # CRS 反代 (Claude) - 已验证
            preset_mode="crs"
            api_type="anthropic-messages"
            provider_name="crs-claude"
            echo ""
            echo -e "${gl_lv}已选择: CRS 反代 (Claude)${gl_bai}"
            echo -e "${gl_zi}协议: anthropic-messages | 只需输入 CRS 地址和 API Key${gl_bai}"
            echo ""
            echo -e "${gl_zi}地址格式示例: http://IP:端口/api${gl_bai}"
            echo -e "${gl_zi}Key 格式示例: cr_xxxx...${gl_bai}"
            ;;
        2)
            # sub2api 反代 (Gemini) - 已验证
            preset_mode="sub2api-gemini"
            api_type="google-generative-ai"
            provider_name="sub2api-gemini"
            echo ""
            echo -e "${gl_lv}已选择: sub2api 反代 (Gemini)${gl_bai}"
            echo -e "${gl_zi}协议: google-generative-ai | 只需输入 sub2api 地址和 API Key${gl_bai}"
            echo ""
            echo -e "${gl_zi}地址格式示例: https://你的sub2api域名${gl_bai}"
            echo -e "${gl_zi}Key 格式示例: sk-xxxx...（Gemini 专用 Key）${gl_bai}"
            echo -e "${gl_huang}注意: sub2api 的 Claude Key 因凭证限制无法用于 OpenClaw，只有 Gemini Key 可用${gl_bai}"
            ;;
        3)
            # sub2api 反代 (GPT) - 已验证
            preset_mode="sub2api-gpt"
            api_type="openai-responses"
            provider_name="sub2api-gpt"
            echo ""
            echo -e "${gl_lv}已选择: sub2api 反代 (GPT)${gl_bai}"
            echo -e "${gl_zi}协议: openai-responses | 只需输入 sub2api 地址和 API Key${gl_bai}"
            echo ""
            echo -e "${gl_zi}地址格式示例: https://你的sub2api域名${gl_bai}"
            echo -e "${gl_zi}Key 格式示例: sk-xxxx...（GPT 专用 Key）${gl_bai}"
            ;;
        4)
            # sub2api Antigravity (Claude) - 已验证
            preset_mode="sub2api-antigravity"
            api_type="anthropic-messages"
            provider_name="sub2api-antigravity"
            echo ""
            echo -e "${gl_lv}已选择: sub2api Antigravity (Claude)${gl_bai}"
            echo -e "${gl_zi}协议: anthropic-messages | 支持 tools，OpenClaw 完全兼容${gl_bai}"
            echo ""
            echo -e "${gl_zi}地址格式示例: https://你的sub2api域名/antigravity${gl_bai}"
            echo -e "${gl_zi}Key 格式示例: sk-xxxx...（Antigravity 专用 Key）${gl_bai}"
            echo -e "${gl_huang}注意: 高峰期偶尔返回 503，重试即可；账户池较小${gl_bai}"
            ;;
        5)
            api_type="anthropic-messages"
            echo ""
            echo -e "${gl_zi}提示: 反代地址一般不需要 /v1 后缀${gl_bai}"
            echo -e "${gl_huang}注意: 使用 Claude Code 凭证的反代（如 sub2api Claude）无法用于 OpenClaw${gl_bai}"
            ;;
        6)
            api_type="openai-completions"
            echo ""
            echo -e "${gl_zi}提示: 中转地址一般需要 /v1 后缀${gl_bai}"
            ;;
        7)
            api_type="openai-completions"
            base_url="https://openrouter.ai/api/v1"
            provider_name="openrouter"
            need_base_url=false
            echo ""
            echo -e "${gl_lv}已预填 OpenRouter 地址: ${base_url}${gl_bai}"
            ;;
        8)
            api_type="google-generative-ai"
            echo ""
            echo -e "${gl_zi}提示: Gemini 反代地址会自动添加 /v1beta 后缀${gl_bai}"
            ;;
        9)
            api_type="anthropic-messages"
            base_url="https://api.anthropic.com"
            provider_name="anthropic"
            need_base_url=false
            echo ""
            echo -e "${gl_lv}使用 Anthropic 官方 API${gl_bai}"
            ;;
        10)
            api_type="google-generative-ai"
            base_url="https://generativelanguage.googleapis.com/v1beta"
            provider_name="google"
            need_base_url=false
            echo ""
            echo -e "${gl_lv}使用 Google Gemini 官方 API${gl_bai}"
            ;;
        11)
            api_type="openai-responses"
            base_url="https://api.openai.com/v1"
            provider_name="openai"
            need_base_url=false
            echo ""
            echo -e "${gl_lv}使用 OpenAI 官方 API${gl_bai}"
            ;;
        *)
            echo -e "${gl_hong}无效选择${gl_bai}"
            break_end
            return 1
            ;;
    esac

    # 步骤2: 输入反代地址
    if [ "$need_base_url" = true ]; then
        echo ""
        echo -e "${gl_kjlan}[步骤2] 输入反代地址${gl_bai}"
        if [ "$preset_mode" = "crs" ]; then
            echo -e "${gl_zi}示例: http://IP:端口/api（CRS 默认格式）${gl_bai}"
        elif [ "$preset_mode" = "sub2api-gemini" ]; then
            echo -e "${gl_zi}示例: https://你的sub2api域名（/v1beta 会自动添加）${gl_bai}"
        elif [ "$preset_mode" = "sub2api-gpt" ]; then
            echo -e "${gl_zi}示例: https://你的sub2api域名（/v1 会自动添加）${gl_bai}"
        elif [ "$preset_mode" = "sub2api-antigravity" ]; then
            echo -e "${gl_zi}示例: https://你的sub2api域名/antigravity（路径需包含 /antigravity）${gl_bai}"
        elif [ "$api_type" = "google-generative-ai" ]; then
            echo -e "${gl_zi}示例: https://your-proxy.com（/v1beta 会自动添加）${gl_bai}"
        else
            echo -e "${gl_zi}示例: https://your-proxy.com 或 https://your-proxy.com/v1${gl_bai}"
        fi
        echo ""
        read -e -p "反代地址: " base_url
        if [ -z "$base_url" ]; then
            echo -e "${gl_hong}❌ 反代地址不能为空${gl_bai}"
            break_end
            return 1
        fi
        # 去除末尾的 /
        base_url="${base_url%/}"
        # 自动添加 API 路径后缀
        if [ "$api_type" = "google-generative-ai" ]; then
            if [[ ! "$base_url" =~ /v1beta$ ]] && [[ ! "$base_url" =~ /v1$ ]]; then
                base_url="${base_url}/v1beta"
                echo -e "${gl_lv}已自动添加后缀: ${base_url}${gl_bai}"
            fi
        elif [ "$preset_mode" = "sub2api-gpt" ]; then
            if [[ ! "$base_url" =~ /v1$ ]]; then
                base_url="${base_url}/v1"
                echo -e "${gl_lv}已自动添加后缀: ${base_url}${gl_bai}"
            fi
        fi
    fi

    # 步骤3: 输入 API Key
    echo ""
    echo -e "${gl_kjlan}[步骤3] 输入 API Key${gl_bai}"
    if [ "$preset_mode" = "crs" ]; then
        echo -e "${gl_zi}CRS Key 格式: cr_xxxx...${gl_bai}"
    elif [ "$preset_mode" = "sub2api-gemini" ]; then
        echo -e "${gl_zi}sub2api Gemini Key 格式: sk-xxxx...${gl_bai}"
    elif [ "$preset_mode" = "sub2api-gpt" ]; then
        echo -e "${gl_zi}sub2api GPT Key 格式: sk-xxxx...${gl_bai}"
    elif [ "$preset_mode" = "sub2api-antigravity" ]; then
        echo -e "${gl_zi}sub2api Antigravity Key 格式: sk-xxxx...${gl_bai}"
    fi
    echo ""
    read -e -p "API Key: " api_key
    if [ -z "$api_key" ]; then
        echo -e "${gl_hong}❌ API Key 不能为空${gl_bai}"
        break_end
        return 1
    fi

    # 步骤4: 选择模型
    echo ""
    echo -e "${gl_kjlan}[步骤4] 选择主力模型${gl_bai}"
    echo ""

    local model_id=""
    local model_name=""
    local model_reasoning="false"
    local model_input='["text"]'
    local model_cost_input="3"
    local model_cost_output="15"
    local model_cost_cache_read="0.3"
    local model_cost_cache_write="3.75"
    local model_context="200000"
    local model_max_tokens="16384"

    if [ "$preset_mode" = "sub2api-antigravity" ]; then
        echo "1. claude-sonnet-4-5 (推荐)"
        echo "2. claude-sonnet-4-5-thinking (扩展思考)"
        echo "3. claude-opus-4-5-thinking (最强思考)"
        echo "4. 自定义模型 ID"
        echo ""
        read -e -p "请选择 [1-4]: " model_choice
        case "$model_choice" in
            1) model_id="claude-sonnet-4-5"; model_name="Claude Sonnet 4.5" ;;
            2) model_id="claude-sonnet-4-5-thinking"; model_name="Claude Sonnet 4.5 Thinking"; model_reasoning="true"; model_input='["text", "image"]' ;;
            3) model_id="claude-opus-4-5-thinking"; model_name="Claude Opus 4.5 Thinking"; model_reasoning="true"; model_input='["text", "image"]'; model_cost_input="15"; model_cost_output="75"; model_cost_cache_read="1.5"; model_cost_cache_write="18.75"; model_max_tokens="32768" ;;
            4)
                read -e -p "输入模型 ID: " model_id
                read -e -p "输入模型显示名称: " model_name
                ;;
            *) model_id="claude-sonnet-4-5"; model_name="Claude Sonnet 4.5" ;;
        esac
    elif [ "$api_type" = "anthropic-messages" ]; then
        echo "1. claude-opus-4-6 (Opus 4.6 最强)"
        echo "2. claude-sonnet-4-5 (Sonnet 4.5 均衡)"
        echo "3. claude-haiku-4-5 (Haiku 4.5 快速)"
        echo "4. 自定义模型 ID"
        echo ""
        read -e -p "请选择 [1-4]: " model_choice
        case "$model_choice" in
            1) model_id="claude-opus-4-6"; model_name="Claude Opus 4.6"; model_reasoning="true"; model_input='["text", "image"]'; model_cost_input="15"; model_cost_output="75"; model_cost_cache_read="1.5"; model_cost_cache_write="18.75"; model_max_tokens="32768" ;;
            2) model_id="claude-sonnet-4-5"; model_name="Claude Sonnet 4.5" ;;
            3) model_id="claude-haiku-4-5"; model_name="Claude Haiku 4.5"; model_cost_input="0.8"; model_cost_output="4"; model_cost_cache_read="0.08"; model_cost_cache_write="1" ;;
            4)
                read -e -p "输入模型 ID: " model_id
                read -e -p "输入模型显示名称: " model_name
                ;;
            *) model_id="claude-sonnet-4-5"; model_name="Claude Sonnet 4.5" ;;
        esac
    elif [ "$api_type" = "google-generative-ai" ]; then
        echo "1. gemini-3-pro-preview (最新旗舰)"
        echo "2. gemini-3-flash-preview (最新快速)"
        echo "3. gemini-2.5-pro (推理增强)"
        echo "4. gemini-2.5-flash (快速均衡)"
        echo "5. 自定义模型 ID"
        echo ""
        read -e -p "请选择 [1-5]: " model_choice
        case "$model_choice" in
            1) model_id="gemini-3-pro-preview"; model_name="Gemini 3 Pro Preview"; model_reasoning="true"; model_input='["text", "image"]'; model_cost_input="2.5"; model_cost_output="15"; model_cost_cache_read="0.625"; model_cost_cache_write="7.5"; model_context="1000000"; model_max_tokens="65536" ;;
            2) model_id="gemini-3-flash-preview"; model_name="Gemini 3 Flash Preview"; model_reasoning="true"; model_input='["text", "image"]'; model_cost_input="0.15"; model_cost_output="0.6"; model_cost_cache_read="0.0375"; model_cost_cache_write="1"; model_context="1000000"; model_max_tokens="65536" ;;
            3) model_id="gemini-2.5-pro"; model_name="Gemini 2.5 Pro"; model_reasoning="true"; model_input='["text", "image"]'; model_cost_input="1.25"; model_cost_output="10"; model_cost_cache_read="0.315"; model_cost_cache_write="4.5"; model_context="1000000"; model_max_tokens="65536" ;;
            4) model_id="gemini-2.5-flash"; model_name="Gemini 2.5 Flash"; model_reasoning="true"; model_input='["text", "image"]'; model_cost_input="0.15"; model_cost_output="0.6"; model_cost_cache_read="0.0375"; model_cost_cache_write="1"; model_context="1000000"; model_max_tokens="65536" ;;
            5)
                read -e -p "输入模型 ID: " model_id
                read -e -p "输入模型显示名称: " model_name
                model_reasoning="true"; model_input='["text", "image"]'; model_context="1000000"; model_max_tokens="65536"
                ;;
            *) model_id="gemini-3-pro-preview"; model_name="Gemini 3 Pro Preview"; model_reasoning="true"; model_input='["text", "image"]'; model_cost_input="2.5"; model_cost_output="15"; model_cost_cache_read="0.625"; model_cost_cache_write="7.5"; model_context="1000000"; model_max_tokens="65536" ;;
        esac
    elif [ "$api_type" = "openai-responses" ]; then
        echo "1. gpt-5.3 (最新旗舰)"
        echo "2. gpt-5.3-codex (Codex 最强)"
        echo "3. gpt-5.2"
        echo "4. gpt-5.2-codex"
        echo "5. gpt-5.1"
        echo "6. gpt-5.1-codex"
        echo "7. gpt-5.1-codex-max"
        echo "8. 自定义模型 ID"
        echo ""
        read -e -p "请选择 [1-8]: " model_choice
        case "$model_choice" in
            1) model_id="gpt-5.3"; model_name="GPT 5.3"; model_reasoning="true"; model_input='["text", "image"]'; model_cost_input="2"; model_cost_output="8"; model_cost_cache_read="0.5"; model_cost_cache_write="2"; model_max_tokens="32768" ;;
            2) model_id="gpt-5.3-codex"; model_name="GPT 5.3 Codex"; model_reasoning="true"; model_input='["text", "image"]'; model_cost_input="2"; model_cost_output="8"; model_cost_cache_read="0.5"; model_cost_cache_write="2"; model_max_tokens="32768" ;;
            3) model_id="gpt-5.2"; model_name="GPT 5.2"; model_reasoning="true"; model_input='["text", "image"]'; model_cost_input="2"; model_cost_output="8"; model_cost_cache_read="0.5"; model_cost_cache_write="2"; model_max_tokens="32768" ;;
            4) model_id="gpt-5.2-codex"; model_name="GPT 5.2 Codex"; model_reasoning="true"; model_input='["text", "image"]'; model_cost_input="2"; model_cost_output="8"; model_cost_cache_read="0.5"; model_cost_cache_write="2"; model_max_tokens="32768" ;;
            5) model_id="gpt-5.1"; model_name="GPT 5.1"; model_reasoning="true"; model_input='["text", "image"]'; model_cost_input="2"; model_cost_output="8"; model_cost_cache_read="0.5"; model_cost_cache_write="2"; model_max_tokens="32768" ;;
            6) model_id="gpt-5.1-codex"; model_name="GPT 5.1 Codex"; model_reasoning="true"; model_input='["text", "image"]'; model_cost_input="2"; model_cost_output="8"; model_cost_cache_read="0.5"; model_cost_cache_write="2"; model_max_tokens="32768" ;;
            7) model_id="gpt-5.1-codex-max"; model_name="GPT 5.1 Codex Max"; model_reasoning="true"; model_input='["text", "image"]'; model_cost_input="2"; model_cost_output="8"; model_cost_cache_read="0.5"; model_cost_cache_write="2"; model_max_tokens="32768" ;;
            8)
                read -e -p "输入模型 ID: " model_id
                read -e -p "输入模型显示名称: " model_name
                model_reasoning="true"; model_input='["text", "image"]'; model_max_tokens="32768"
                ;;
            *) model_id="gpt-5.3"; model_name="GPT 5.3"; model_reasoning="true"; model_input='["text", "image"]'; model_cost_input="2"; model_cost_output="8"; model_cost_cache_read="0.5"; model_cost_cache_write="2"; model_max_tokens="32768" ;;
        esac
    elif [ "$api_type" = "openai-completions" ]; then
        echo "1. claude-opus-4-6 (通过中转)"
        echo "2. claude-sonnet-4-5 (通过中转)"
        echo "3. gpt-4o"
        echo "4. gpt-4o-mini"
        echo "5. 自定义模型 ID"
        echo ""
        read -e -p "请选择 [1-5]: " model_choice
        case "$model_choice" in
            1) model_id="claude-opus-4-6"; model_name="Claude Opus 4.6"; model_reasoning="true"; model_input='["text", "image"]'; model_cost_input="15"; model_cost_output="75"; model_cost_cache_read="1.5"; model_cost_cache_write="18.75"; model_max_tokens="32768" ;;
            2) model_id="claude-sonnet-4-5"; model_name="Claude Sonnet 4.5" ;;
            3) model_id="gpt-4o"; model_name="GPT-4o"; model_input='["text", "image"]'; model_cost_input="2.5"; model_cost_output="10"; model_cost_cache_read="1.25"; model_cost_cache_write="2.5"; model_context="128000"; model_max_tokens="16384" ;;
            4) model_id="gpt-4o-mini"; model_name="GPT-4o Mini"; model_input='["text", "image"]'; model_cost_input="0.15"; model_cost_output="0.6"; model_cost_cache_read="0.075"; model_cost_cache_write="0.15"; model_context="128000"; model_max_tokens="16384" ;;
            5)
                read -e -p "输入模型 ID: " model_id
                read -e -p "输入模型显示名称: " model_name
                ;;
            *) model_id="claude-sonnet-4-5"; model_name="Claude Sonnet 4.5" ;;
        esac
    fi

    if [ -z "$model_id" ]; then
        echo -e "${gl_hong}❌ 模型 ID 不能为空${gl_bai}"
        break_end
        return 1
    fi

    # 步骤5: 选择端口
    echo ""
    echo -e "${gl_kjlan}[步骤5] 设置网关端口${gl_bai}"
    local port="$OPENCLAW_DEFAULT_PORT"
    read -e -p "网关端口 [${OPENCLAW_DEFAULT_PORT}]: " input_port
    if [ -n "$input_port" ]; then
        port="$input_port"
    fi

    # 生成配置
    echo ""
    echo -e "${gl_kjlan}正在生成配置...${gl_bai}"

    mkdir -p "$OPENCLAW_HOME_DIR"

    # 生成网关 token
    local gateway_token=$(openssl rand -hex 16 2>/dev/null || head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')

    # 写入环境变量
    cat > "$OPENCLAW_ENV_FILE" <<EOF
# OpenClaw 环境变量 - 由部署脚本自动生成
OPENCLAW_API_KEY=${api_key}
OPENCLAW_GATEWAY_TOKEN=${gateway_token}
EOF
    chmod 600 "$OPENCLAW_ENV_FILE"

    # 生成 openclaw.json 配置（JSON5 格式）
    cat > "$OPENCLAW_CONFIG_FILE" <<EOF
// OpenClaw 配置 - 由部署脚本自动生成
// 文档: https://docs.openclaw.ai/gateway/configuration
{
  // 网关设置
  gateway: {
    port: ${port},
    mode: "local",
    auth: {
      token: "${gateway_token}"
    }
  },

  // 模型配置
  models: {
    mode: "merge",
    providers: {
      "${provider_name}": {
        baseUrl: "${base_url}",
        apiKey: "\${OPENCLAW_API_KEY}",
        api: "${api_type}",
        models: [
          { id: "${model_id}", name: "${model_name}", reasoning: ${model_reasoning}, input: ${model_input}, cost: { input: ${model_cost_input}, output: ${model_cost_output}, cacheRead: ${model_cost_cache_read}, cacheWrite: ${model_cost_cache_write} }, contextWindow: ${model_context}, maxTokens: ${model_max_tokens} }
        ]
      }
    }
  },

  // Agent 默认配置
  agents: {
    defaults: {
      model: {
        primary: "${provider_name}/${model_id}"
      }
    }
  }
}
EOF
    chmod 600 "$OPENCLAW_CONFIG_FILE"
    chmod 700 "$OPENCLAW_HOME_DIR"

    echo -e "${gl_lv}✅ 配置文件已生成${gl_bai}"
    echo ""
    echo -e "${gl_zi}配置文件: ${OPENCLAW_CONFIG_FILE}${gl_bai}"
    echo -e "${gl_zi}环境变量: ${OPENCLAW_ENV_FILE}${gl_bai}"
    echo ""

    # 显示配置摘要
    echo -e "${gl_kjlan}━━━ 配置摘要 ━━━${gl_bai}"
    if [ -n "$preset_mode" ]; then
        echo -e "配置预设:   ${gl_lv}${preset_mode}（已验证可用）${gl_bai}"
    fi
    echo -e "API 类型:   ${gl_huang}${api_type}${gl_bai}"
    echo -e "反代地址:   ${gl_huang}${base_url}${gl_bai}"
    echo -e "主力模型:   ${gl_huang}${provider_name}/${model_id}${gl_bai}"
    echo -e "模型名称:   ${gl_huang}${model_name}${gl_bai}"
    echo -e "网关端口:   ${gl_huang}${port}${gl_bai}"
    echo -e "网关Token:  ${gl_huang}${gateway_token}${gl_bai}"
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━${gl_bai}"

    return 0
}

# 执行 onboard 初始化
openclaw_onboard() {
    local port=$(openclaw_get_port)
    echo -e "${gl_kjlan}[4/4] 创建 systemd 服务并启动网关...${gl_bai}"
    echo ""

    # 创建必要的目录
    mkdir -p "${OPENCLAW_HOME_DIR}/agents/main/sessions"
    mkdir -p "${OPENCLAW_HOME_DIR}/credentials"
    mkdir -p "${OPENCLAW_HOME_DIR}/workspace"

    # 获取 openclaw 实际路径
    local openclaw_bin=$(which openclaw 2>/dev/null || echo "/usr/bin/openclaw")

    # 创建 systemd 服务
    cat > "/etc/systemd/system/${OPENCLAW_SERVICE_NAME}.service" <<EOF
[Unit]
Description=OpenClaw Gateway
After=network.target

[Service]
Type=simple
ExecStart=${openclaw_bin} gateway --port ${port} --verbose
Restart=always
RestartSec=5
EnvironmentFile=-${HOME}/.openclaw/.env
Environment=HOME=${HOME}
WorkingDirectory=${HOME}
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable "$OPENCLAW_SERVICE_NAME" >/dev/null 2>&1
    systemctl start "$OPENCLAW_SERVICE_NAME"

    sleep 5

    if systemctl is-active "$OPENCLAW_SERVICE_NAME" &>/dev/null; then
        echo -e "${gl_lv}✅ OpenClaw 网关已启动${gl_bai}"
        return 0
    else
        echo -e "${gl_hong}❌ 网关启动失败，查看日志:${gl_bai}"
        journalctl -u "$OPENCLAW_SERVICE_NAME" -n 10 --no-pager
        return 1
    fi
}

# 一键部署
openclaw_deploy() {
    clear
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo -e "${gl_kjlan}  OpenClaw 一键部署${gl_bai}"
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo ""

    local status=$(openclaw_check_status)
    if [ "$status" = "running" ]; then
        echo -e "${gl_huang}⚠ OpenClaw 已在运行中${gl_bai}"
        echo ""
        read -e -p "是否重新部署？(Y/N): " confirm
        case "$confirm" in
            [Yy]) ;;
            *) return ;;
        esac
        echo ""
        systemctl stop "$OPENCLAW_SERVICE_NAME" 2>/dev/null
    fi

    # 步骤1: Node.js
    openclaw_install_nodejs || { break_end; return 1; }
    echo ""

    # 步骤2: 安装 OpenClaw
    openclaw_install_pkg || { break_end; return 1; }
    echo ""

    # 步骤3: 交互式模型配置
    echo -e "${gl_kjlan}[3/4] 配置模型与 API...${gl_bai}"
    echo ""
    openclaw_config_model || { break_end; return 1; }
    echo ""

    # 步骤4: 初始化并启动
    openclaw_onboard || { break_end; return 1; }

    # 获取服务器 IP
    local server_ip=$(curl -s4 ip.sb 2>/dev/null || curl -s6 ip.sb 2>/dev/null || echo "服务器IP")
    local port=$(openclaw_get_port)

    echo ""
    echo -e "${gl_lv}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo -e "${gl_lv}  ✅ OpenClaw 部署完成！${gl_bai}"
    echo -e "${gl_lv}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo ""
    echo -e "控制面板: ${gl_huang}http://${server_ip}:${port}/${gl_bai}"
    echo ""

    # 显示 gateway token
    local gw_token=$(sed -nE 's/.*OPENCLAW_GATEWAY_TOKEN=(.*)/\1/p' "$OPENCLAW_ENV_FILE" 2>/dev/null)
    if [ -n "$gw_token" ]; then
        echo -e "网关 Token: ${gl_huang}${gw_token}${gl_bai}"
        echo -e "${gl_zi}（远程访问控制面板时需要此 Token）${gl_bai}"
        echo ""
    fi

    echo -e "${gl_kjlan}【下一步】连接消息频道${gl_bai}"
    echo "  运行: openclaw channels login"
    echo "  支持: WhatsApp / Telegram / Discord / Slack 等"
    echo ""
    echo -e "${gl_kjlan}【聊天命令】（在消息平台中使用）${gl_bai}"
    echo "  /status  — 查看会话状态"
    echo "  /new     — 清空上下文"
    echo "  /think   — 调整推理级别"
    echo ""
    echo -e "${gl_kjlan}【安全说明】${gl_bai}"
    echo "  网关默认绑定 loopback，外部访问需 SSH 隧道:"
    echo -e "  ${gl_huang}ssh -N -L ${port}:127.0.0.1:${port} root@${server_ip}${gl_bai}"
    echo "  检查安全: openclaw doctor"
    echo ""
    echo -e "${gl_kjlan}管理命令:${gl_bai}"
    echo "  状态: systemctl status $OPENCLAW_SERVICE_NAME"
    echo "  日志: journalctl -u $OPENCLAW_SERVICE_NAME -f"
    echo "  重启: systemctl restart $OPENCLAW_SERVICE_NAME"
    echo ""

    break_end
}

# 更新 OpenClaw
openclaw_update() {
    clear
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo -e "${gl_kjlan}  更新 OpenClaw${gl_bai}"
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo ""

    if ! command -v openclaw &>/dev/null; then
        echo -e "${gl_hong}❌ OpenClaw 未安装，请先执行一键部署${gl_bai}"
        break_end
        return 1
    fi

    local old_ver=$(openclaw --version 2>/dev/null || echo "unknown")
    echo -e "当前版本: ${gl_huang}${old_ver}${gl_bai}"
    echo ""

    echo "正在更新..."
    npm install -g openclaw@latest 2>&1 | tail -10

    local new_ver=$(openclaw --version 2>/dev/null || echo "unknown")
    echo ""

    if [ "$old_ver" = "$new_ver" ]; then
        echo -e "${gl_lv}✅ 已是最新版本 (${new_ver})${gl_bai}"
    else
        echo -e "${gl_lv}✅ 已更新: ${old_ver} → ${new_ver}${gl_bai}"
    fi

    echo ""
    echo "正在重启服务..."
    systemctl restart "$OPENCLAW_SERVICE_NAME" 2>/dev/null

    sleep 2
    if systemctl is-active "$OPENCLAW_SERVICE_NAME" &>/dev/null; then
        echo -e "${gl_lv}✅ 服务已重启${gl_bai}"
    else
        echo -e "${gl_huang}⚠ 服务未通过 systemctl 管理，请手动重启${gl_bai}"
    fi

    break_end
}

# 查看状态
openclaw_status() {
    clear
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo -e "${gl_kjlan}  OpenClaw 服务状态${gl_bai}"
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo ""

    if command -v openclaw &>/dev/null; then
        echo -e "版本: ${gl_huang}$(openclaw --version 2>/dev/null || echo 'unknown')${gl_bai}"
        echo ""
    fi

    systemctl status "$OPENCLAW_SERVICE_NAME" --no-pager 2>/dev/null || \
        echo -e "${gl_huang}⚠ systemd 服务不存在，可能需要重新执行 onboard${gl_bai}"

    echo ""
    break_end
}

# 查看日志
openclaw_logs() {
    clear
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo -e "${gl_kjlan}  OpenClaw 日志（按 Ctrl+C 退出）${gl_bai}"
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo ""

    journalctl -u "$OPENCLAW_SERVICE_NAME" -f 2>/dev/null || \
        echo -e "${gl_huang}⚠ 无法读取日志，服务可能未通过 systemd 管理${gl_bai}"
}

# 启动服务
openclaw_start() {
    echo "正在启动服务..."
    systemctl start "$OPENCLAW_SERVICE_NAME" 2>/dev/null
    sleep 2

    if systemctl is-active "$OPENCLAW_SERVICE_NAME" &>/dev/null; then
        echo -e "${gl_lv}✅ 服务已启动${gl_bai}"
    else
        echo -e "${gl_hong}❌ 服务启动失败，查看日志: journalctl -u $OPENCLAW_SERVICE_NAME -n 20${gl_bai}"
    fi

    break_end
}

# 停止服务
openclaw_stop() {
    echo "正在停止服务..."
    systemctl stop "$OPENCLAW_SERVICE_NAME" 2>/dev/null

    if ! systemctl is-active "$OPENCLAW_SERVICE_NAME" &>/dev/null; then
        echo -e "${gl_lv}✅ 服务已停止${gl_bai}"
    else
        echo -e "${gl_hong}❌ 服务停止失败${gl_bai}"
    fi

    break_end
}

# 重启服务
openclaw_restart() {
    echo "正在重启服务..."

    local port=$(openclaw_get_port)
    local pid=$(ss -lntp 2>/dev/null | grep ":${port} " | sed -nE 's/.*pid=([0-9]+).*/\1/p' | head -1)
    local service_pid=$(systemctl show -p MainPID "$OPENCLAW_SERVICE_NAME" 2>/dev/null | cut -d= -f2)

    if [ -n "$pid" ] && [ "$pid" != "$service_pid" ] && [ "$pid" != "0" ]; then
        echo -e "${gl_huang}⚠ 端口 ${port} 被 PID ${pid} 占用，正在释放...${gl_bai}"
        kill "$pid" 2>/dev/null
        sleep 1
        if ss -lntp 2>/dev/null | grep -q ":${port} "; then
            kill -9 "$pid" 2>/dev/null
            sleep 1
        fi
    fi

    systemctl restart "$OPENCLAW_SERVICE_NAME" 2>/dev/null
    sleep 2

    if systemctl is-active "$OPENCLAW_SERVICE_NAME" &>/dev/null; then
        echo -e "${gl_lv}✅ 服务已重启${gl_bai}"
    else
        echo -e "${gl_hong}❌ 服务重启失败${gl_bai}"
        echo "查看日志: journalctl -u $OPENCLAW_SERVICE_NAME -n 20"
    fi

    break_end
}

# 更新频道配置到 openclaw.json（通过 Node.js 合并 JSON5）
openclaw_update_channel() {
    local channel_name="$1"
    local channel_config_json="$2"

    if [ ! -f "$OPENCLAW_CONFIG_FILE" ]; then
        echo -e "${gl_hong}❌ 配置文件不存在，请先部署 OpenClaw${gl_bai}"
        return 1
    fi

    local tmp_channel=$(mktemp)
    local tmp_script=$(mktemp)
    echo "$channel_config_json" > "$tmp_channel"

    cat > "$tmp_script" << 'NODESCRIPT'
const fs = require('fs');
const configPath = process.argv[2];
const channelName = process.argv[3];
const channelFile = process.argv[4];
const newChannelConfig = JSON.parse(fs.readFileSync(channelFile, 'utf-8'));

const content = fs.readFileSync(configPath, 'utf-8');
let config;
try {
    config = new Function('return (' + content + ')')();
} catch(e) {
    console.error('无法解析配置文件: ' + e.message);
    process.exit(1);
}

if (!config.channels) config.channels = {};
config.channels[channelName] = newChannelConfig;

// 同时启用对应插件（防止 doctor --fix 禁用后无法自动恢复）
if (!config.plugins) config.plugins = {};
if (!config.plugins.entries) config.plugins.entries = {};
if (!config.plugins.entries[channelName]) config.plugins.entries[channelName] = {};
config.plugins.entries[channelName].enabled = true;

const output = '// OpenClaw 配置 - 由部署脚本自动生成\n// 文档: https://docs.openclaw.ai/gateway/configuration\n' + JSON.stringify(config, null, 2) + '\n';
fs.writeFileSync(configPath, output);
NODESCRIPT

    node "$tmp_script" "$OPENCLAW_CONFIG_FILE" "$channel_name" "$tmp_channel" 2>&1
    local result=$?
    rm -f "$tmp_channel" "$tmp_script"
    return $result
}

# 从 openclaw.json 移除频道配置
openclaw_remove_channel() {
    local channel_name="$1"

    if [ ! -f "$OPENCLAW_CONFIG_FILE" ]; then
        echo "配置文件不存在"
        return 1
    fi

    local tmp_script=$(mktemp)
    cat > "$tmp_script" << 'NODESCRIPT'
const fs = require('fs');
const configPath = process.argv[2];
const channelName = process.argv[3];

const content = fs.readFileSync(configPath, 'utf-8');
let config;
try {
    config = new Function('return (' + content + ')')();
} catch(e) {
    console.error('无法解析配置文件');
    process.exit(1);
}

if (config.channels && config.channels[channelName]) {
    delete config.channels[channelName];
    // 同时禁用对应插件
    if (config.plugins && config.plugins.entries && config.plugins.entries[channelName]) {
        config.plugins.entries[channelName].enabled = false;
    }
    const output = '// OpenClaw 配置 - 由部署脚本自动生成\n// 文档: https://docs.openclaw.ai/gateway/configuration\n' + JSON.stringify(config, null, 2) + '\n';
    fs.writeFileSync(configPath, output);
    console.log('已移除 ' + channelName + ' 频道配置');
} else {
    console.log('频道 ' + channelName + ' 未在配置中找到');
}
NODESCRIPT

    node "$tmp_script" "$OPENCLAW_CONFIG_FILE" "$channel_name" 2>&1
    local result=$?
    rm -f "$tmp_script"
    return $result
}

# 频道管理菜单
openclaw_channels() {
    if ! command -v openclaw &>/dev/null; then
        echo -e "${gl_hong}❌ OpenClaw 未安装，请先执行「一键部署」${gl_bai}"
        break_end
        return 1
    fi

    while true; do
        clear
        echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
        echo -e "${gl_kjlan}  OpenClaw 频道管理${gl_bai}"
        echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
        echo ""

        # 显示已配置的频道（从配置文件读取）
        echo -e "${gl_lv}── 已配置的频道 ──${gl_bai}"
        if [ -f "$OPENCLAW_CONFIG_FILE" ]; then
            node -e '
                const fs = require("fs");
                const content = fs.readFileSync(process.argv[1], "utf-8");
                try {
                    const config = new Function("return (" + content + ")")();
                    const ch = config.channels || {};
                    const names = Object.keys(ch);
                    if (names.length === 0) { console.log("  暂无已配置的频道"); }
                    else {
                        for (const n of names) {
                            const enabled = ch[n].enabled !== false ? "✅" : "❌";
                            console.log("  " + enabled + " " + n);
                        }
                    }
                } catch(e) { console.log("  暂无已配置的频道"); }
            ' "$OPENCLAW_CONFIG_FILE" 2>/dev/null || echo "  暂无已配置的频道"
        else
            echo "  暂无已配置的频道"
        fi
        echo ""

        echo -e "${gl_kjlan}[配置频道]${gl_bai}"
        echo "1. Telegram Bot      — 输入 Bot Token"
        echo "2. WhatsApp          — 终端扫码登录"
        echo "3. Discord Bot       — 输入 Bot Token"
        echo "4. Slack             — 输入 App Token + Bot Token"
        echo ""
        echo -e "${gl_kjlan}[频道管理]${gl_bai}"
        echo "5. 查看频道状态"
        echo "6. 查看频道日志"
        echo "7. 断开/删除频道"
        echo ""
        echo "0. 返回"
        echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"

        read -e -p "请选择 [0-7]: " ch_choice

        case $ch_choice in
            1)
                # Telegram
                clear
                echo -e "${gl_kjlan}━━━ 配置 Telegram Bot ━━━${gl_bai}"
                echo ""
                echo -e "${gl_zi}📋 获取 Bot Token 步骤:${gl_bai}"
                echo -e "  1. 打开 Telegram，搜索 ${gl_huang}@BotFather${gl_bai}"
                echo "  2. 发送 /newbot 创建新 Bot"
                echo "  3. 按提示设置 Bot 名称和用户名（用户名必须以 bot 结尾）"
                echo "  4. 复制 BotFather 给的 Token"
                echo ""
                echo -e "${gl_zi}Token 格式: 123456789:ABCdefGHIjklMNOpqrsTUVwxyz${gl_bai}"
                echo ""

                read -e -p "请输入 Telegram Bot Token: " tg_token
                if [ -z "$tg_token" ]; then
                    echo -e "${gl_hong}❌ Token 不能为空${gl_bai}"
                    break_end
                    continue
                fi

                echo ""
                echo "正在写入 Telegram 配置..."
                local tg_json="{\"botToken\":\"${tg_token}\",\"enabled\":true,\"dmPolicy\":\"pairing\",\"groupPolicy\":\"allowlist\",\"streamMode\":\"partial\",\"textChunkLimit\":4000,\"dmHistoryLimit\":50,\"historyLimit\":50}"
                openclaw_update_channel "telegram" "$tg_json"

                if [ $? -eq 0 ]; then
                    echo ""
                    echo -e "${gl_lv}✅ Telegram Bot 配置成功${gl_bai}"
                    echo ""
                    echo -e "${gl_zi}下一步:${gl_bai}"
                    echo "  1. 在 Telegram 中搜索你的 Bot 并发送一条消息"
                    echo "  2. Bot 会回复一个配对码（pairing code）"
                    echo -e "  3. 在服务器运行: ${gl_huang}openclaw pairing approve telegram <配对码>${gl_bai}"

                    if systemctl is-active "$OPENCLAW_SERVICE_NAME" &>/dev/null; then
                        systemctl restart "$OPENCLAW_SERVICE_NAME" 2>/dev/null
                        sleep 2
                        echo ""
                        echo -e "${gl_lv}✅ 服务已重启，配置已生效${gl_bai}"
                    fi
                else
                    echo ""
                    echo -e "${gl_hong}❌ 配置写入失败${gl_bai}"
                fi
                break_end
                ;;
            2)
                # WhatsApp
                clear
                echo -e "${gl_kjlan}━━━ 配置 WhatsApp ━━━${gl_bai}"
                echo ""
                echo -e "${gl_zi}📋 登录步骤:${gl_bai}"
                echo "  1. 先写入 WhatsApp 频道配置"
                echo "  2. 终端会显示 QR 二维码"
                echo "  3. 打开手机 WhatsApp → 设置 → 已关联设备 → 关联设备"
                echo "  4. 扫描终端中的 QR 码（60秒内有效，超时重新运行）"
                echo ""
                echo -e "${gl_huang}⚠ 注意事项:${gl_bai}"
                echo "  • 需要使用真实手机号，虚拟号码可能被封禁"
                echo "  • 一个 WhatsApp 号码只能绑定一个 OpenClaw 网关"
                echo ""

                read -e -p "准备好了吗？(Y/N): " confirm
                case "$confirm" in
                    [Yy])
                        echo ""
                        echo "正在写入 WhatsApp 配置..."
                        local wa_json='{"enabled":true,"dmPolicy":"pairing","groupPolicy":"allowlist","streamMode":"partial","historyLimit":50,"dmHistoryLimit":50}'
                        openclaw_update_channel "whatsapp" "$wa_json"

                        if [ $? -eq 0 ]; then
                            echo -e "${gl_lv}✅ WhatsApp 配置已写入${gl_bai}"
                            echo ""

                            if systemctl is-active "$OPENCLAW_SERVICE_NAME" &>/dev/null; then
                                systemctl restart "$OPENCLAW_SERVICE_NAME" 2>/dev/null
                                sleep 2
                            fi

                            echo "正在启动 WhatsApp 登录（显示 QR 码）..."
                            echo ""
                            openclaw channels login 2>&1
                        else
                            echo -e "${gl_hong}❌ 配置写入失败${gl_bai}"
                        fi
                        ;;
                    *)
                        echo "已取消"
                        ;;
                esac
                break_end
                ;;
            3)
                # Discord
                clear
                echo -e "${gl_kjlan}━━━ 配置 Discord Bot ━━━${gl_bai}"
                echo ""
                echo -e "${gl_zi}📋 获取 Bot Token 步骤:${gl_bai}"
                echo -e "  1. 打开 ${gl_huang}https://discord.com/developers/applications${gl_bai}"
                echo "  2. 点击 New Application → 输入名称 → 创建"
                echo "  3. 左侧 Bot 页面 → Reset Token → 复制 Token"
                echo -e "  4. 开启 ${gl_huang}Privileged Gateway Intents${gl_bai}:"
                echo "     • Message Content Intent（必须开启）"
                echo "     • Server Members Intent（推荐开启）"
                echo "  5. OAuth2 → URL Generator → 勾选 bot + applications.commands"
                echo "     权限: View Channels / Send Messages / Read Message History"
                echo "  6. 用生成的邀请链接把 Bot 添加到你的服务器"
                echo ""

                read -e -p "请输入 Discord Bot Token: " dc_token
                if [ -z "$dc_token" ]; then
                    echo -e "${gl_hong}❌ Token 不能为空${gl_bai}"
                    break_end
                    continue
                fi

                echo ""
                echo "正在写入 Discord 配置..."
                local dc_json="{\"token\":\"${dc_token}\",\"enabled\":true,\"dm\":{\"enabled\":true,\"policy\":\"pairing\"},\"groupPolicy\":\"allowlist\",\"textChunkLimit\":2000,\"historyLimit\":20}"
                openclaw_update_channel "discord" "$dc_json"

                if [ $? -eq 0 ]; then
                    echo ""
                    echo -e "${gl_lv}✅ Discord Bot 配置成功${gl_bai}"
                    echo ""
                    echo -e "${gl_zi}确保已用邀请链接将 Bot 添加到你的 Discord 服务器${gl_bai}"

                    if systemctl is-active "$OPENCLAW_SERVICE_NAME" &>/dev/null; then
                        systemctl restart "$OPENCLAW_SERVICE_NAME" 2>/dev/null
                        sleep 2
                        echo -e "${gl_lv}✅ 服务已重启，配置已生效${gl_bai}"
                    fi
                else
                    echo ""
                    echo -e "${gl_hong}❌ 配置写入失败${gl_bai}"
                fi
                break_end
                ;;
            4)
                # Slack
                clear
                echo -e "${gl_kjlan}━━━ 配置 Slack ━━━${gl_bai}"
                echo ""
                echo -e "${gl_zi}📋 获取 Token 步骤:${gl_bai}"
                echo -e "  1. 打开 ${gl_huang}https://api.slack.com/apps${gl_bai} → Create New App → From Scratch"
                echo -e "  2. 开启 ${gl_huang}Socket Mode${gl_bai}"
                echo "  3. Basic Information → App-Level Tokens → Generate Token"
                echo -e "     Scope: connections:write → 复制 App Token（${gl_huang}xapp-${gl_bai} 开头）"
                echo "  4. OAuth & Permissions → 添加 Bot Token Scopes:"
                echo "     chat:write / channels:history / groups:history"
                echo "     im:history / channels:read / users:read"
                echo -e "  5. Install to Workspace → 复制 Bot Token（${gl_huang}xoxb-${gl_bai} 开头）"
                echo "  6. Event Subscriptions → Enable → Subscribe to message.* events"
                echo ""
                echo -e "${gl_huang}Slack 需要两个 Token:${gl_bai}"
                echo ""

                read -e -p "App Token (xapp-开头): " slack_app_token
                if [ -z "$slack_app_token" ]; then
                    echo -e "${gl_hong}❌ App Token 不能为空${gl_bai}"
                    break_end
                    continue
                fi

                read -e -p "Bot Token (xoxb-开头): " slack_bot_token
                if [ -z "$slack_bot_token" ]; then
                    echo -e "${gl_hong}❌ Bot Token 不能为空${gl_bai}"
                    break_end
                    continue
                fi

                echo ""
                echo "正在写入 Slack 配置..."
                local slack_json="{\"appToken\":\"${slack_app_token}\",\"botToken\":\"${slack_bot_token}\",\"enabled\":true,\"dmPolicy\":\"pairing\",\"groupPolicy\":\"allowlist\",\"streamMode\":\"partial\",\"historyLimit\":50}"
                openclaw_update_channel "slack" "$slack_json"

                if [ $? -eq 0 ]; then
                    echo ""
                    echo -e "${gl_lv}✅ Slack 配置已保存${gl_bai}"

                    if systemctl is-active "$OPENCLAW_SERVICE_NAME" &>/dev/null; then
                        systemctl restart "$OPENCLAW_SERVICE_NAME" 2>/dev/null
                        sleep 2
                        echo -e "${gl_lv}✅ 服务已重启，配置已生效${gl_bai}"
                    fi
                else
                    echo ""
                    echo -e "${gl_hong}❌ 配置写入失败${gl_bai}"
                fi
                break_end
                ;;
            5)
                # 查看频道状态
                clear
                echo -e "${gl_kjlan}━━━ 频道状态 ━━━${gl_bai}"
                echo ""
                openclaw channels status --probe 2>&1 || \
                openclaw channels status 2>&1 || \
                openclaw gateway status 2>&1 || \
                echo "无法获取频道状态"
                echo ""
                break_end
                ;;
            6)
                # 查看频道日志
                clear
                echo -e "${gl_kjlan}━━━ 频道日志（最近 50 行）━━━${gl_bai}"
                echo ""
                journalctl -u "$OPENCLAW_SERVICE_NAME" --no-pager -n 50 2>/dev/null || \
                openclaw logs 2>&1 || \
                echo "无法获取频道日志"
                echo ""
                break_end
                ;;
            7)
                # 断开/删除频道
                clear
                echo -e "${gl_kjlan}━━━ 断开频道 ━━━${gl_bai}"
                echo ""
                echo "选择要断开的频道:"
                echo "1. Telegram"
                echo "2. WhatsApp"
                echo "3. Discord"
                echo "4. Slack"
                echo ""
                echo "0. 取消"
                echo ""

                read -e -p "请选择 [0-4]: " rm_choice
                local channel_name=""
                case $rm_choice in
                    1) channel_name="telegram" ;;
                    2) channel_name="whatsapp" ;;
                    3) channel_name="discord" ;;
                    4) channel_name="slack" ;;
                    0) continue ;;
                    *)
                        echo "无效选择"
                        break_end
                        continue
                        ;;
                esac

                echo ""
                read -e -p "确认断开 ${channel_name}？(Y/N): " confirm
                case "$confirm" in
                    [Yy])
                        echo ""
                        openclaw_remove_channel "$channel_name"
                        echo ""
                        echo -e "${gl_lv}✅ 已断开 ${channel_name}${gl_bai}"

                        if systemctl is-active "$OPENCLAW_SERVICE_NAME" &>/dev/null; then
                            systemctl restart "$OPENCLAW_SERVICE_NAME" 2>/dev/null
                            sleep 2
                            echo -e "${gl_lv}✅ 服务已重启${gl_bai}"
                        fi
                        ;;
                    *)
                        echo "已取消"
                        ;;
                esac
                break_end
                ;;
            0)
                return
                ;;
            *)
                echo "无效的选择"
                sleep 2
                ;;
        esac
    done
}

# 查看当前配置
openclaw_show_config() {
    clear
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo -e "${gl_kjlan}  OpenClaw 当前配置${gl_bai}"
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo ""

    if [ ! -f "$OPENCLAW_CONFIG_FILE" ]; then
        echo -e "${gl_huang}⚠ 配置文件不存在: ${OPENCLAW_CONFIG_FILE}${gl_bai}"
        echo ""
        break_end
        return
    fi

    # 格式化摘要
    local server_ip=$(curl -s4 ip.sb 2>/dev/null || curl -s6 ip.sb 2>/dev/null || echo "服务器IP")
    local port=$(openclaw_get_port)
    local gw_token=$(sed -nE 's/.*OPENCLAW_GATEWAY_TOKEN=(.*)/\1/p' "$OPENCLAW_ENV_FILE" 2>/dev/null)

    node -e "
        const fs = require('fs');
        const content = fs.readFileSync('${OPENCLAW_CONFIG_FILE}', 'utf-8');
        try {
            const config = new Function('return (' + content + ')')();
            const providers = config.models && config.models.providers || {};
            const keys = Object.keys(providers);
            const defaults = config.agents && config.agents.defaults && config.agents.defaults.model || {};
            for (const name of keys) {
                const p = providers[name];
                console.log('  Provider:  ' + name);
                console.log('  API 类型:  ' + (p.api || 'unknown'));
                console.log('  反代地址:  ' + (p.baseUrl || 'unknown'));
                const models = p.models || [];
                if (models.length > 0) {
                    console.log('  可用模型:  ' + models.map(m => m.id).join(', '));
                }
            }
            if (defaults.primary) console.log('  主力模型:  ' + defaults.primary);

            const ch = config.channels || {};
            const chNames = Object.keys(ch);
            if (chNames.length > 0) {
                console.log('');
                console.log('  已配置频道: ' + chNames.map(n => { const e = ch[n].enabled !== false; return (e ? '✅' : '❌') + ' ' + n; }).join('  |  '));
            }
        } catch(e) { console.log('  无法解析配置'); }
    " 2>/dev/null

    echo ""
    echo -e "${gl_kjlan}━━━ 部署信息 ━━━${gl_bai}"
    echo -e "网关端口:   ${gl_huang}${port}${gl_bai}"
    if [ -n "$gw_token" ]; then
        echo -e "网关 Token: ${gl_huang}${gw_token}${gl_bai}"
    fi
    echo -e "控制面板:   ${gl_huang}http://${server_ip}:${port}/${gl_bai}"
    echo ""
    echo -e "${gl_kjlan}━━━ 访问方式 ━━━${gl_bai}"
    echo -e "SSH 隧道:   ${gl_huang}ssh -N -L ${port}:127.0.0.1:${port} root@${server_ip}${gl_bai}"
    echo -e "然后访问:   ${gl_huang}http://localhost:${port}/${gl_bai}"
    echo ""

    echo -e "${gl_kjlan}━━━ 管理命令 ━━━${gl_bai}"
    echo "  状态: systemctl status $OPENCLAW_SERVICE_NAME"
    echo "  日志: journalctl -u $OPENCLAW_SERVICE_NAME -f"
    echo "  重启: systemctl restart $OPENCLAW_SERVICE_NAME"
    echo ""

    # 查看原始文件
    read -e -p "是否查看原始配置文件？(Y/N): " show_raw
    case "$show_raw" in
        [Yy])
            echo ""
            echo -e "${gl_zi}── ${OPENCLAW_CONFIG_FILE} ──${gl_bai}"
            cat "$OPENCLAW_CONFIG_FILE"
            echo ""
            if [ -f "$OPENCLAW_ENV_FILE" ]; then
                echo -e "${gl_zi}── ${OPENCLAW_ENV_FILE}（脱敏）──${gl_bai}"
                sed 's/\(=\).*/\1****（已隐藏）/' "$OPENCLAW_ENV_FILE"
            fi
            ;;
    esac

    echo ""
    break_end
}

# 编辑配置文件
openclaw_edit_config() {
    if [ ! -f "$OPENCLAW_CONFIG_FILE" ]; then
        echo -e "${gl_huang}⚠ 配置文件不存在，是否创建默认配置？${gl_bai}"
        read -e -p "(Y/N): " confirm
        case "$confirm" in
            [Yy])
                mkdir -p "$OPENCLAW_HOME_DIR"
                echo '{}' > "$OPENCLAW_CONFIG_FILE"
                ;;
            *)
                return
                ;;
        esac
    fi

    local editor="nano"
    if command -v vim &>/dev/null; then
        editor="vim"
    fi
    if command -v nano &>/dev/null; then
        editor="nano"
    fi

    $editor "$OPENCLAW_CONFIG_FILE"

    echo ""
    echo -e "${gl_zi}提示: 修改配置后需重启服务生效 (systemctl restart $OPENCLAW_SERVICE_NAME)${gl_bai}"

    read -e -p "是否现在重启服务？(Y/N): " confirm
    case "$confirm" in
        [Yy])
            systemctl restart "$OPENCLAW_SERVICE_NAME" 2>/dev/null
            sleep 2
            if systemctl is-active "$OPENCLAW_SERVICE_NAME" &>/dev/null; then
                echo -e "${gl_lv}✅ 服务已重启${gl_bai}"
            else
                echo -e "${gl_hong}❌ 服务重启失败，请检查配置是否正确${gl_bai}"
            fi
            ;;
    esac

    break_end
}

# 快速替换 API（保留现有设置）
openclaw_quick_api() {
    clear
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo -e "${gl_kjlan}  快速替换 API（保留端口/频道等现有设置）${gl_bai}"
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo ""

    if ! command -v openclaw &>/dev/null; then
        echo -e "${gl_hong}❌ OpenClaw 未安装${gl_bai}"
        break_end
        return 1
    fi

    if [ ! -f "$OPENCLAW_CONFIG_FILE" ]; then
        echo -e "${gl_hong}❌ 配置文件不存在，请先执行「一键部署」${gl_bai}"
        break_end
        return 1
    fi

    # 显示当前 API 配置
    echo -e "${gl_lv}── 当前 API 配置 ──${gl_bai}"
    node -e "
        const fs = require('fs');
        const content = fs.readFileSync('${OPENCLAW_CONFIG_FILE}', 'utf-8');
        try {
            const config = new Function('return (' + content + ')')();
            const providers = config.models && config.models.providers || {};
            const keys = Object.keys(providers);
            if (keys.length === 0) { console.log('  暂无 API 配置'); }
            for (const name of keys) {
                const p = providers[name];
                console.log('  Provider:  ' + name);
                console.log('  API 类型:  ' + (p.api || 'unknown'));
                console.log('  地址:      ' + (p.baseUrl || 'unknown'));
                const models = p.models || [];
                if (models.length > 0) {
                    console.log('  模型:      ' + models.map(m => m.id).join(', '));
                }
            }
        } catch(e) { console.log('  无法解析当前配置'); }
    " 2>/dev/null || echo "  无法读取当前配置"
    echo ""

    # 选择新的 API
    echo -e "${gl_huang}选择要配置的 API:${gl_bai}"
    echo ""
    echo -e "${gl_lv}── 已验证可用的反代 ──${gl_bai}"
    echo "1. CRS 反代 (Claude)         — anthropic-messages"
    echo "2. sub2api 反代 (Gemini)      — google-generative-ai"
    echo "3. sub2api 反代 (GPT)         — openai-responses"
    echo "4. sub2api Antigravity (Claude) — anthropic-messages"
    echo ""
    echo -e "${gl_huang}── 通用配置 ──${gl_bai}"
    echo "5. 自定义 Anthropic 反代"
    echo "6. 自定义 OpenAI 兼容"
    echo ""

    read -e -p "请选择 [1-6]: " api_choice

    local api_type="" provider_name="" preset_mode=""
    local base_url="" api_key="" model_id="" model_name=""
    local model_reasoning="false" model_input='["text"]' model_cost_input="3" model_cost_output="15"
    local model_cost_cache_read="0.3" model_cost_cache_write="3.75"
    local model_context="200000" model_max_tokens="16384"

    case $api_choice in
        1)
            preset_mode="crs"
            api_type="anthropic-messages"
            provider_name="crs-claude"
            echo ""
            echo -e "${gl_lv}已选择: CRS 反代 (Claude)${gl_bai}"
            echo -e "${gl_zi}地址格式: http://IP:端口/api${gl_bai}"
            ;;
        2)
            preset_mode="sub2api-gemini"
            api_type="google-generative-ai"
            provider_name="sub2api-gemini"
            echo ""
            echo -e "${gl_lv}已选择: sub2api 反代 (Gemini)${gl_bai}"
            echo -e "${gl_zi}地址格式: https://你的sub2api域名${gl_bai}"
            ;;
        3)
            preset_mode="sub2api-gpt"
            api_type="openai-responses"
            provider_name="sub2api-gpt"
            echo ""
            echo -e "${gl_lv}已选择: sub2api 反代 (GPT)${gl_bai}"
            echo -e "${gl_zi}地址格式: https://你的sub2api域名${gl_bai}"
            ;;
        4)
            preset_mode="sub2api-antigravity"
            api_type="anthropic-messages"
            provider_name="sub2api-antigravity"
            echo ""
            echo -e "${gl_lv}已选择: sub2api Antigravity (Claude)${gl_bai}"
            echo -e "${gl_zi}地址格式: https://你的sub2api域名/antigravity${gl_bai}"
            echo -e "${gl_huang}注意: 高峰期偶尔返回 503，重试即可${gl_bai}"
            ;;
        5)
            api_type="anthropic-messages"
            provider_name="custom-anthropic"
            echo ""
            echo -e "${gl_zi}地址格式: https://your-proxy.com${gl_bai}"
            ;;
        6)
            api_type="openai-completions"
            provider_name="custom-openai"
            echo ""
            echo -e "${gl_zi}地址格式: https://your-proxy.com/v1${gl_bai}"
            ;;
        *)
            echo "无效选择"
            break_end
            return
            ;;
    esac

    # 输入地址
    echo ""
    read -e -p "反代地址: " base_url
    if [ -z "$base_url" ]; then
        echo -e "${gl_hong}❌ 地址不能为空${gl_bai}"
        break_end
        return
    fi
    base_url="${base_url%/}"

    # 自动添加后缀
    if [ "$api_type" = "google-generative-ai" ]; then
        if [[ ! "$base_url" =~ /v1beta$ ]] && [[ ! "$base_url" =~ /v1$ ]]; then
            base_url="${base_url}/v1beta"
            echo -e "${gl_lv}已自动添加后缀: ${base_url}${gl_bai}"
        fi
    elif [ "$preset_mode" = "sub2api-gpt" ]; then
        if [[ ! "$base_url" =~ /v1$ ]]; then
            base_url="${base_url}/v1"
            echo -e "${gl_lv}已自动添加后缀: ${base_url}${gl_bai}"
        fi
    fi

    # 输入 Key
    echo ""
    read -e -p "API Key: " api_key
    if [ -z "$api_key" ]; then
        echo -e "${gl_hong}❌ Key 不能为空${gl_bai}"
        break_end
        return
    fi

    # 快速模型选择
    echo ""
    echo -e "${gl_kjlan}选择模型:${gl_bai}"
    if [ "$preset_mode" = "crs" ]; then
        echo "1. claude-opus-4-6 (推荐)"
        echo "2. claude-sonnet-4-5"
        echo "3. claude-haiku-4-5"
        echo "4. 自定义"
        read -e -p "请选择 [1-4]: " m_choice
        case $m_choice in
            1) model_id="claude-opus-4-6"; model_name="Claude Opus 4.6" ;;
            2) model_id="claude-sonnet-4-5"; model_name="Claude Sonnet 4.5" ;;
            3) model_id="claude-haiku-4-5"; model_name="Claude Haiku 4.5" ;;
            4) read -e -p "模型 ID: " model_id; model_name="$model_id" ;;
            *) model_id="claude-opus-4-6"; model_name="Claude Opus 4.6" ;;
        esac
    elif [ "$preset_mode" = "sub2api-antigravity" ]; then
        echo "1. claude-sonnet-4-5 (推荐)"
        echo "2. claude-sonnet-4-5-thinking (扩展思考)"
        echo "3. claude-opus-4-5-thinking (最强思考)"
        echo "4. 自定义"
        read -e -p "请选择 [1-4]: " m_choice
        case $m_choice in
            1) model_id="claude-sonnet-4-5"; model_name="Claude Sonnet 4.5" ;;
            2) model_id="claude-sonnet-4-5-thinking"; model_name="Claude Sonnet 4.5 Thinking" ;;
            3) model_id="claude-opus-4-5-thinking"; model_name="Claude Opus 4.5 Thinking" ;;
            4) read -e -p "模型 ID: " model_id; model_name="$model_id" ;;
            *) model_id="claude-sonnet-4-5"; model_name="Claude Sonnet 4.5" ;;
        esac
    elif [ "$preset_mode" = "sub2api-gemini" ]; then
        echo "1. gemini-3-pro-preview (推荐)"
        echo "2. gemini-3-flash-preview"
        echo "3. gemini-2.5-pro"
        echo "4. gemini-2.5-flash"
        echo "5. 自定义"
        read -e -p "请选择 [1-5]: " m_choice
        case $m_choice in
            1) model_id="gemini-3-pro-preview"; model_name="Gemini 3 Pro Preview" ;;
            2) model_id="gemini-3-flash-preview"; model_name="Gemini 3 Flash Preview" ;;
            3) model_id="gemini-2.5-pro"; model_name="Gemini 2.5 Pro" ;;
            4) model_id="gemini-2.5-flash"; model_name="Gemini 2.5 Flash" ;;
            5) read -e -p "模型 ID: " model_id; model_name="$model_id" ;;
            *) model_id="gemini-3-pro-preview"; model_name="Gemini 3 Pro Preview" ;;
        esac
    elif [ "$preset_mode" = "sub2api-gpt" ]; then
        echo "1. gpt-5.3 (推荐)"
        echo "2. gpt-5.3-codex"
        echo "3. gpt-5.2"
        echo "4. gpt-5.2-codex"
        echo "5. gpt-5.1"
        echo "6. gpt-5.1-codex"
        echo "7. gpt-5.1-codex-max"
        echo "8. 自定义"
        read -e -p "请选择 [1-8]: " m_choice
        case $m_choice in
            1) model_id="gpt-5.3"; model_name="GPT 5.3" ;;
            2) model_id="gpt-5.3-codex"; model_name="GPT 5.3 Codex" ;;
            3) model_id="gpt-5.2"; model_name="GPT 5.2" ;;
            4) model_id="gpt-5.2-codex"; model_name="GPT 5.2 Codex" ;;
            5) model_id="gpt-5.1"; model_name="GPT 5.1" ;;
            6) model_id="gpt-5.1-codex"; model_name="GPT 5.1 Codex" ;;
            7) model_id="gpt-5.1-codex-max"; model_name="GPT 5.1 Codex Max" ;;
            8) read -e -p "模型 ID: " model_id; model_name="$model_id" ;;
            *) model_id="gpt-5.3"; model_name="GPT 5.3" ;;
        esac
    else
        read -e -p "模型 ID: " model_id
        model_name="$model_id"
    fi

    if [ -z "$model_id" ]; then
        echo -e "${gl_hong}❌ 模型不能为空${gl_bai}"
        break_end
        return
    fi

    echo ""
    echo -e "${gl_kjlan}━━━ 确认配置 ━━━${gl_bai}"
    echo -e "API 类型:   ${gl_huang}${api_type}${gl_bai}"
    echo -e "反代地址:   ${gl_huang}${base_url}${gl_bai}"
    echo -e "模型:       ${gl_huang}${model_id}${gl_bai}"
    echo ""

    read -e -p "确认替换 API 配置？(Y/N): " confirm
    if [[ ! "$confirm" =~ [Yy] ]]; then
        echo "已取消"
        break_end
        return
    fi

    # 写入新 provider 数据到临时 JSON 文件
    local tmp_json=$(mktemp /tmp/openclaw_api_XXXXXX.json)
    cat > "$tmp_json" <<APIJSON
{
    "providers": {
        "${provider_name}": {
            "baseUrl": "${base_url}",
            "apiKey": "\${OPENCLAW_API_KEY}",
            "api": "${api_type}",
            "models": [
                {
                    "id": "${model_id}",
                    "name": "${model_name}",
                    "reasoning": ${model_reasoning},
                    "input": ${model_input},
                    "cost": { "input": ${model_cost_input}, "output": ${model_cost_output}, "cacheRead": ${model_cost_cache_read}, "cacheWrite": ${model_cost_cache_write} },
                    "contextWindow": ${model_context},
                    "maxTokens": ${model_max_tokens}
                }
            ]
        }
    },
    "primaryModel": "${provider_name}/${model_id}"
}
APIJSON

    # 用 Node.js 合并配置（只替换 models + agents.defaults.model，保留其他一切）
    echo ""
    echo "正在更新配置..."
    node -e "
        const fs = require('fs');
        const configPath = '${OPENCLAW_CONFIG_FILE}';
        const newDataPath = '${tmp_json}';

        // 读取现有配置（JSON5: 用 Function 解析，JS 引擎原生支持注释）
        const content = fs.readFileSync(configPath, 'utf-8');
        let config;
        try {
            config = new Function('return (' + content + ')')();
        } catch(e) {
            console.error('❌ 无法解析现有配置: ' + e.message);
            process.exit(1);
        }

        // 读取新 provider 数据
        const newData = JSON.parse(fs.readFileSync(newDataPath, 'utf-8'));

        // 只替换 models.providers 和 agents.defaults.model
        config.models = config.models || {};
        config.models.mode = 'merge';
        config.models.providers = newData.providers;

        config.agents = config.agents || {};
        config.agents.defaults = config.agents.defaults || {};
        config.agents.defaults.model = { primary: newData.primaryModel };

        // 写回（保留 gateway/channels 等所有其他配置）
        const header = '// OpenClaw 配置 - API 由脚本快速配置\n// 文档: https://docs.openclaw.ai/gateway/configuration\n';
        fs.writeFileSync(configPath, header + JSON.stringify(config, null, 2) + '\n');
        console.log('✅ 配置文件已更新');
    " 2>&1

    local node_exit=$?
    rm -f "$tmp_json"

    if [ $node_exit -ne 0 ]; then
        echo -e "${gl_hong}❌ 配置更新失败${gl_bai}"
        break_end
        return
    fi

    # 更新 .env 中的 API Key
    if [ -f "$OPENCLAW_ENV_FILE" ]; then
        sed -i "s|^OPENCLAW_API_KEY=.*|OPENCLAW_API_KEY=${api_key}|" "$OPENCLAW_ENV_FILE"
        echo "✅ API Key 已更新"
    else
        mkdir -p "$OPENCLAW_HOME_DIR"
        echo "OPENCLAW_API_KEY=${api_key}" > "$OPENCLAW_ENV_FILE"
        chmod 600 "$OPENCLAW_ENV_FILE"
        echo "✅ 环境变量文件已创建"
    fi

    # 重启服务
    if systemctl is-active "$OPENCLAW_SERVICE_NAME" &>/dev/null; then
        systemctl restart "$OPENCLAW_SERVICE_NAME" 2>/dev/null
        sleep 2
        if systemctl is-active "$OPENCLAW_SERVICE_NAME" &>/dev/null; then
            echo -e "${gl_lv}✅ 服务已重启，API 已生效${gl_bai}"
        else
            echo -e "${gl_hong}❌ 服务重启失败，查看日志: journalctl -u ${OPENCLAW_SERVICE_NAME} -n 20${gl_bai}"
        fi
    else
        echo -e "${gl_huang}⚠ 服务未运行，请手动启动: systemctl start ${OPENCLAW_SERVICE_NAME}${gl_bai}"
    fi

    echo ""
    echo -e "${gl_kjlan}━━━ 替换完成 ━━━${gl_bai}"
    echo -e "API 类型:   ${gl_huang}${api_type}${gl_bai}"
    echo -e "反代地址:   ${gl_huang}${base_url}${gl_bai}"
    echo -e "主力模型:   ${gl_huang}${provider_name}/${model_id}${gl_bai}"
    echo ""
    echo -e "${gl_zi}原有的端口、频道、网关 Token 等设置均已保留${gl_bai}"

    break_end
}

# 安全检查
openclaw_doctor() {
    clear
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo -e "${gl_kjlan}  OpenClaw 安全检查${gl_bai}"
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo ""

    if ! command -v openclaw &>/dev/null; then
        echo -e "${gl_hong}❌ OpenClaw 未安装${gl_bai}"
        break_end
        return 1
    fi

    openclaw doctor
    echo ""

    read -e -p "是否自动修复发现的问题？(Y/N): " confirm
    case "$confirm" in
        [Yy])
            echo ""
            openclaw doctor --fix
            ;;
    esac

    break_end
}

# 卸载 OpenClaw
openclaw_uninstall() {
    clear
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo -e "${gl_hong}  卸载 OpenClaw${gl_bai}"
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo ""
    echo -e "${gl_huang}警告: 此操作将删除 OpenClaw 及其所有配置！${gl_bai}"
    echo ""
    echo "将删除以下内容:"
    echo "  - OpenClaw 全局包"
    echo "  - systemd 服务"
    echo "  - 配置目录 ${OPENCLAW_HOME_DIR}"
    echo ""

    read -e -p "确认卸载？(输入 yes 确认): " confirm

    if [ "$confirm" != "yes" ]; then
        echo "已取消"
        break_end
        return 0
    fi

    echo ""
    echo "正在停止服务..."
    systemctl stop "$OPENCLAW_SERVICE_NAME" 2>/dev/null
    systemctl disable "$OPENCLAW_SERVICE_NAME" 2>/dev/null

    echo "正在删除 systemd 服务..."
    rm -f "/etc/systemd/system/${OPENCLAW_SERVICE_NAME}.service"
    systemctl daemon-reload 2>/dev/null

    echo "正在卸载 OpenClaw..."
    npm uninstall -g openclaw 2>/dev/null

    echo ""
    read -e -p "是否同时删除配置目录 ${OPENCLAW_HOME_DIR}？(Y/N): " del_config
    case "$del_config" in
        [Yy])
            rm -rf "$OPENCLAW_HOME_DIR"
            echo -e "${gl_lv}✅ 配置目录已删除${gl_bai}"
            ;;
        *)
            echo -e "${gl_zi}配置目录已保留，下次安装可复用${gl_bai}"
            ;;
    esac

    echo ""
    echo -e "${gl_lv}✅ OpenClaw 卸载完成${gl_bai}"

    break_end
}

# OpenClaw 主菜单
manage_openclaw() {
    while true; do
        clear
        echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
        echo -e "${gl_kjlan}  OpenClaw 部署管理 (AI多渠道消息网关)${gl_bai}"
        echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
        echo ""

        # 显示当前状态
        local status=$(openclaw_check_status)
        local port=$(openclaw_get_port)

        case "$status" in
            "not_installed")
                echo -e "当前状态: ${gl_huang}⚠ 未安装${gl_bai}"
                ;;
            "installed_no_service")
                echo -e "当前状态: ${gl_huang}⚠ 已安装但服务未配置${gl_bai}"
                ;;
            "running")
                echo -e "当前状态: ${gl_lv}✅ 运行中${gl_bai} (端口: ${port})"
                ;;
            "stopped")
                echo -e "当前状态: ${gl_hong}❌ 已停止${gl_bai}"
                ;;
        esac

        echo ""
        echo -e "${gl_kjlan}[部署与更新]${gl_bai}"
        echo "1. 一键部署（首次安装）"
        echo "2. 更新版本"
        echo ""
        echo -e "${gl_kjlan}[服务管理]${gl_bai}"
        echo "3. 查看状态"
        echo "4. 查看日志"
        echo "5. 启动服务"
        echo "6. 停止服务"
        echo "7. 重启服务"
        echo ""
        echo -e "${gl_kjlan}[配置管理]${gl_bai}"
        echo "8. 模型配置（完整配置/首次部署）"
        echo "9. 快速替换 API（保留现有设置）"
        echo "10. 频道管理（登录/配置）"
        echo "11. 查看当前配置"
        echo "12. 编辑配置文件"
        echo "13. 安全检查（doctor）"
        echo ""
        echo -e "${gl_hong}14. 卸载 OpenClaw${gl_bai}"
        echo ""
        echo "0. 返回主菜单"
        echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"

        read -e -p "请选择操作 [0-14]: " choice

        case $choice in
            1)
                openclaw_deploy
                ;;
            2)
                openclaw_update
                ;;
            3)
                openclaw_status
                ;;
            4)
                openclaw_logs
                ;;
            5)
                openclaw_start
                ;;
            6)
                openclaw_stop
                ;;
            7)
                openclaw_restart
                ;;
            8)
                openclaw_config_model
                echo ""
                # 检查服务是否存在再决定重启
                if systemctl list-unit-files "${OPENCLAW_SERVICE_NAME}.service" &>/dev/null && \
                   systemctl cat "$OPENCLAW_SERVICE_NAME" &>/dev/null 2>&1; then
                    read -e -p "是否重启服务使配置生效？(Y/N): " confirm
                    case "$confirm" in
                        [Yy])
                            systemctl restart "$OPENCLAW_SERVICE_NAME" 2>/dev/null
                            sleep 2
                            if systemctl is-active "$OPENCLAW_SERVICE_NAME" &>/dev/null; then
                                echo -e "${gl_lv}✅ 服务已重启${gl_bai}"
                            else
                                echo -e "${gl_hong}❌ 服务重启失败，查看日志: journalctl -u ${OPENCLAW_SERVICE_NAME} -n 20${gl_bai}"
                            fi
                            ;;
                    esac
                else
                    echo -e "${gl_huang}⚠ systemd 服务尚未创建，请先运行「1. 一键部署」完成完整部署${gl_bai}"
                fi
                break_end
                ;;
            9)
                openclaw_quick_api
                ;;
            10)
                openclaw_channels
                ;;
            11)
                openclaw_show_config
                ;;
            12)
                openclaw_edit_config
                ;;
            13)
                openclaw_doctor
                ;;
            14)
                openclaw_uninstall
                ;;
            0)
                return
                ;;
            *)
                echo "无效的选择"
                sleep 2
                ;;
        esac
    done
}

# ============================================================================
# OpenAI Responses API → Chat Completions 转换代理
# ============================================================================

RESP_PROXY_INSTALL_DIR="/opt/openai-resp-proxy"
RESP_PROXY_SCRIPT="${RESP_PROXY_INSTALL_DIR}/proxy.mjs"
RESP_PROXY_CONFIG="${RESP_PROXY_INSTALL_DIR}/config.json"
RESP_PROXY_SERVICE="openai-resp-proxy"
RESP_PROXY_DEFAULT_PORT="18790"

# 检测转换代理状态
resp_proxy_check_status() {
    if [ ! -f "$RESP_PROXY_SCRIPT" ]; then
        echo "not_installed"
    elif systemctl is-active "$RESP_PROXY_SERVICE" &>/dev/null; then
        echo "running"
    else
        echo "stopped"
    fi
}

# 获取转换代理端口
resp_proxy_get_port() {
    if [ -f "$RESP_PROXY_CONFIG" ]; then
        local port
        port=$(grep -o '"port"[[:space:]]*:[[:space:]]*[0-9]*' "$RESP_PROXY_CONFIG" | grep -o '[0-9]*$')
        echo "${port:-$RESP_PROXY_DEFAULT_PORT}"
    else
        echo "$RESP_PROXY_DEFAULT_PORT"
    fi
}

# 获取上游地址
resp_proxy_get_upstream() {
    if [ -f "$RESP_PROXY_CONFIG" ]; then
        grep -o '"upstream_url"[[:space:]]*:[[:space:]]*"[^"]*"' "$RESP_PROXY_CONFIG" | sed 's/.*"upstream_url"[[:space:]]*:[[:space:]]*"//' | sed 's/"$//'
    fi
}

# 部署转换代理
resp_proxy_deploy() {
    clear
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo -e "${gl_kjlan}  部署 OpenAI Responses API 转换代理${gl_bai}"
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo ""
    echo "此代理将 Responses API (/v1/responses) 转换为"
    echo "Chat Completions API (/v1/chat/completions)，使沉浸式翻译"
    echo "等只支持旧版协议的工具也能使用 Responses API 的服务。"
    echo ""

    # 检查 Node.js
    if ! command -v node &>/dev/null; then
        echo -e "${gl_huang}未检测到 Node.js，正在安装...${gl_bai}"
        if command -v apt &>/dev/null; then
            curl -fsSL https://deb.nodesource.com/setup_22.x | bash -
            apt install -y nodejs
        elif command -v yum &>/dev/null; then
            curl -fsSL https://rpm.nodesource.com/setup_22.x | bash -
            yum install -y nodejs
        else
            echo -e "${gl_hong}❌ 无法自动安装 Node.js，请手动安装后重试${gl_bai}"
            break_end
            return 1
        fi
    fi

    local node_ver
    node_ver=$(node -v 2>/dev/null | sed 's/^v//' | cut -d. -f1)
    if [ "$node_ver" -lt 18 ] 2>/dev/null; then
        echo -e "${gl_hong}❌ Node.js 版本过低 ($(node -v))，需要 v18+${gl_bai}"
        break_end
        return 1
    fi
    echo -e "${gl_lv}✓ Node.js $(node -v)${gl_bai}"

    # 配置上游地址
    echo ""
    echo -e "${gl_kjlan}配置上游 Responses API 服务${gl_bai}"
    echo ""
    echo "请输入提供 /v1/responses 端点的上游服务地址"
    echo -e "${gl_hui}例: https://api.openai.com  或  https://你的反代域名${gl_bai}"
    echo ""
    read -e -p "上游服务地址: " upstream_url

    if [ -z "$upstream_url" ]; then
        echo -e "${gl_hong}❌ 地址不能为空${gl_bai}"
        break_end
        return 1
    fi
    # 去除末尾斜杠
    upstream_url="${upstream_url%/}"

    echo ""
    read -e -p "API Key: " api_key
    if [ -z "$api_key" ]; then
        echo -e "${gl_hong}❌ API Key 不能为空${gl_bai}"
        break_end
        return 1
    fi

    echo ""
    read -e -p "代理监听端口 [${RESP_PROXY_DEFAULT_PORT}]: " proxy_port
    proxy_port="${proxy_port:-$RESP_PROXY_DEFAULT_PORT}"

    # 创建目录
    mkdir -p "$RESP_PROXY_INSTALL_DIR"

    # 写入配置文件
    cat > "$RESP_PROXY_CONFIG" << CONFIGEOF
{
    "upstream_url": "${upstream_url}",
    "api_key": "${api_key}",
    "port": ${proxy_port}
}
CONFIGEOF

    # 写入代理脚本
    cat > "$RESP_PROXY_SCRIPT" << 'PROXYEOF'
import http from 'node:http';
import https from 'node:https';
import fs from 'node:fs';
import { URL } from 'node:url';

const CONFIG_PATH = '/opt/openai-resp-proxy/config.json';
const config = JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf-8'));
const { upstream_url, api_key, port } = config;

function forwardRequest(upstreamUrl, reqData, authHeader) {
    return new Promise((resolve, reject) => {
        const parsedUrl = new URL(upstreamUrl);
        const httpModule = parsedUrl.protocol === 'https:' ? https : http;
        const proxyReq = httpModule.request(upstreamUrl, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': authHeader,
                'Content-Length': Buffer.byteLength(reqData)
            }
        }, (proxyRes) => {
            let body = '';
            proxyRes.on('data', chunk => body += chunk);
            proxyRes.on('end', () => resolve({ statusCode: proxyRes.statusCode, body }));
        });
        proxyReq.on('error', reject);
        proxyReq.write(reqData);
        proxyReq.end();
    });
}

const server = http.createServer(async (req, res) => {
    // CORS
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', '*');
    if (req.method === 'OPTIONS') { res.writeHead(204); res.end(); return; }

    // 模型列表（简易）
    if (req.url === '/v1/models' && req.method === 'GET') {
        res.writeHead(200, {'Content-Type': 'application/json'});
        res.end(JSON.stringify({
            object: 'list',
            data: [
                { id: 'gpt-5.3-codex', object: 'model' },
                { id: 'o3', object: 'model' },
                { id: 'gpt-4o', object: 'model' },
                { id: 'gpt-4o-mini', object: 'model' }
            ]
        }));
        return;
    }

    // 仅处理 /v1/chat/completions
    if (req.method !== 'POST' || !req.url.startsWith('/v1/chat/completions')) {
        res.writeHead(404, {'Content-Type': 'application/json'});
        res.end(JSON.stringify({ error: { message: 'Use POST /v1/chat/completions', type: 'not_found' } }));
        return;
    }

    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', async () => {
        try {
            const chatReq = JSON.parse(body);

            // 转换 Chat Completions → Responses API
            const respReq = {
                model: chatReq.model,
                input: (chatReq.messages || []).map(m => ({
                    role: m.role === 'system' ? 'developer' : m.role,
                    content: m.content
                })),
                stream: false
            };
            // 只转发 model/input/stream，不传 temperature/max_tokens 等额外参数
            // 部分上游（如 sub2api）不支持这些参数会导致 502

            const upstreamEndpoint = upstream_url.replace(/\/+$/, '') + '/v1/responses';
            const authHeader = `Bearer ${api_key}`;

            const result = await forwardRequest(upstreamEndpoint, JSON.stringify(respReq), authHeader);

            if (result.statusCode !== 200) {
                res.writeHead(result.statusCode, {'Content-Type': 'application/json'});
                res.end(result.body);
                return;
            }

            const respData = JSON.parse(result.body);

            // 提取文本
            let text = '';
            if (respData.output) {
                for (const item of respData.output) {
                    if (item.type === 'message' && item.content) {
                        for (const c of item.content) {
                            if (c.type === 'output_text') text += c.text;
                        }
                    }
                }
            }

            // 包装为 Chat Completions 响应
            const chatResp = {
                id: respData.id || 'chatcmpl-proxy',
                object: 'chat.completion',
                created: Math.floor(Date.now() / 1000),
                model: respData.model || chatReq.model,
                choices: [{
                    index: 0,
                    message: { role: 'assistant', content: text },
                    finish_reason: 'stop'
                }],
                usage: respData.usage || {}
            };

            res.writeHead(200, {'Content-Type': 'application/json'});
            res.end(JSON.stringify(chatResp));

        } catch (e) {
            res.writeHead(502, {'Content-Type': 'application/json'});
            res.end(JSON.stringify({ error: { message: e.message, type: 'proxy_error' } }));
        }
    });
});

server.listen(port, () => {
    console.log(`[Responses → Chat Completions] proxy on port ${port}`);
    console.log(`Upstream: ${upstream_url}/v1/responses`);
});
PROXYEOF

    echo ""
    echo "正在创建 systemd 服务..."

    cat > "/etc/systemd/system/${RESP_PROXY_SERVICE}.service" << SVCEOF
[Unit]
Description=OpenAI Responses to Chat Completions Proxy
After=network.target

[Service]
Type=simple
ExecStart=$(which node) ${RESP_PROXY_SCRIPT}
Restart=on-failure
RestartSec=5
WorkingDirectory=${RESP_PROXY_INSTALL_DIR}

[Install]
WantedBy=multi-user.target
SVCEOF

    systemctl daemon-reload
    systemctl enable "$RESP_PROXY_SERVICE" 2>/dev/null
    systemctl start "$RESP_PROXY_SERVICE"
    sleep 2

    if systemctl is-active "$RESP_PROXY_SERVICE" &>/dev/null; then
        local server_ip
        server_ip=$(curl -s4 --max-time 3 ifconfig.me 2>/dev/null || curl -s4 --max-time 3 ip.sb 2>/dev/null || echo "你的IP")
        echo ""
        echo -e "${gl_lv}✅ 转换代理部署成功！${gl_bai}"
        echo ""
        echo -e "代理地址: ${gl_huang}http://${server_ip}:${proxy_port}/v1/chat/completions${gl_bai}"
        echo ""
        echo "沉浸式翻译配置："
        echo -e "  翻译服务: ${gl_zi}OpenAI${gl_bai}"
        echo -e "  API URL:  ${gl_zi}http://${server_ip}:${proxy_port}/v1/chat/completions${gl_bai}"
        echo -e "  API Key:  ${gl_zi}${api_key}${gl_bai}"
        echo -e "  模型:     ${gl_zi}按上游支持的模型填写 (如 gpt-5.3-codex / o3)${gl_bai}"
    else
        echo -e "${gl_hong}❌ 服务启动失败，请检查日志：journalctl -u ${RESP_PROXY_SERVICE} -n 20${gl_bai}"
    fi

    break_end
}

# 修改转换代理配置
resp_proxy_config() {
    clear
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo -e "${gl_kjlan}  修改转换代理配置${gl_bai}"
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo ""

    # 显示当前配置
    if [ -f "$RESP_PROXY_CONFIG" ]; then
        local cur_upstream cur_port
        cur_upstream=$(resp_proxy_get_upstream)
        cur_port=$(resp_proxy_get_port)
        echo -e "当前上游地址: ${gl_zi}${cur_upstream}${gl_bai}"
        echo -e "当前监听端口: ${gl_zi}${cur_port}${gl_bai}"
        echo ""
    fi

    echo "请输入提供 /v1/responses 端点的上游服务地址"
    echo -e "${gl_hui}例: https://api.openai.com  或  https://你的反代域名${gl_bai}"
    echo -e "${gl_hui}直接回车保持不变${gl_bai}"
    echo ""
    read -e -p "上游服务地址: " new_upstream
    new_upstream="${new_upstream%/}"

    echo ""
    read -e -p "API Key: " new_key

    echo ""
    read -e -p "代理监听端口 [$(resp_proxy_get_port)]: " new_port

    # 读取现有值作为默认
    local final_upstream final_key final_port
    if [ -f "$RESP_PROXY_CONFIG" ]; then
        final_upstream="${new_upstream:-$(resp_proxy_get_upstream)}"
        final_key="${new_key:-$(grep -o '"api_key"[[:space:]]*:[[:space:]]*"[^"]*"' "$RESP_PROXY_CONFIG" | sed 's/.*"api_key"[[:space:]]*:[[:space:]]*"//' | sed 's/"$//')}"
        final_port="${new_port:-$(resp_proxy_get_port)}"
    else
        final_upstream="$new_upstream"
        final_key="$new_key"
        final_port="${new_port:-$RESP_PROXY_DEFAULT_PORT}"
    fi

    if [ -z "$final_upstream" ] || [ -z "$final_key" ]; then
        echo -e "${gl_hong}❌ 上游地址和 API Key 不能为空${gl_bai}"
        break_end
        return 1
    fi

    cat > "$RESP_PROXY_CONFIG" << CONFIGEOF
{
    "upstream_url": "${final_upstream}",
    "api_key": "${final_key}",
    "port": ${final_port}
}
CONFIGEOF

    echo ""
    echo -e "${gl_lv}✅ 配置已更新${gl_bai}"
    echo ""
    read -e -p "是否重启服务使配置生效？(Y/N): " confirm
    case "$confirm" in
        [Yy])
            systemctl restart "$RESP_PROXY_SERVICE" 2>/dev/null
            sleep 2
            if systemctl is-active "$RESP_PROXY_SERVICE" &>/dev/null; then
                echo -e "${gl_lv}✅ 服务已重启${gl_bai}"
            else
                echo -e "${gl_hong}❌ 服务重启失败${gl_bai}"
            fi
            ;;
    esac

    break_end
}

# 查看转换代理状态
resp_proxy_status() {
    clear
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo -e "${gl_kjlan}  转换代理状态${gl_bai}"
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo ""
    systemctl status "$RESP_PROXY_SERVICE" --no-pager 2>/dev/null || echo "服务未安装"
    echo ""
    if [ -f "$RESP_PROXY_CONFIG" ]; then
        local cur_port cur_upstream cur_key server_ip
        cur_port=$(resp_proxy_get_port)
        cur_upstream=$(resp_proxy_get_upstream)
        cur_key=$(grep -o '"api_key"[[:space:]]*:[[:space:]]*"[^"]*"' "$RESP_PROXY_CONFIG" | sed 's/.*"api_key"[[:space:]]*:[[:space:]]*"//' | sed 's/"$//')
        server_ip=$(curl -s4 --max-time 3 ifconfig.me 2>/dev/null || curl -s4 --max-time 3 ip.sb 2>/dev/null || echo "你的IP")

        echo -e "${gl_kjlan}当前配置:${gl_bai}"
        echo -e "  上游地址: ${gl_zi}${cur_upstream}${gl_bai}"
        echo -e "  监听端口: ${gl_zi}${cur_port}${gl_bai}"
        echo -e "  API Key:  ${gl_zi}${cur_key}${gl_bai}"
        echo ""
        echo -e "${gl_kjlan}代理地址:${gl_bai}"
        echo -e "  ${gl_huang}http://${server_ip}:${cur_port}${gl_bai}"
        echo ""
        echo -e "${gl_kjlan}沉浸式翻译配置:${gl_bai}"
        echo -e "  翻译服务: ${gl_zi}OpenAI${gl_bai}"
        echo -e "  API URL:  ${gl_zi}http://${server_ip}:${cur_port}/v1/chat/completions${gl_bai}"
        echo -e "  API Key:  ${gl_zi}${cur_key}${gl_bai}"
        echo -e "  模型:     ${gl_zi}按上游支持的模型填写 (如 gpt-5.3-codex / o3)${gl_bai}"
    fi
    break_end
}

# 查看转换代理日志
resp_proxy_logs() {
    clear
    echo -e "${gl_huang}按 Ctrl+C 退出日志${gl_bai}"
    echo ""
    journalctl -u "$RESP_PROXY_SERVICE" -f --no-pager
}

# 启动转换代理
resp_proxy_start() {
    systemctl start "$RESP_PROXY_SERVICE" 2>/dev/null
    sleep 1
    if systemctl is-active "$RESP_PROXY_SERVICE" &>/dev/null; then
        echo -e "${gl_lv}✅ 服务已启动${gl_bai}"
    else
        echo -e "${gl_hong}❌ 启动失败${gl_bai}"
    fi
    break_end
}

# 停止转换代理
resp_proxy_stop() {
    systemctl stop "$RESP_PROXY_SERVICE" 2>/dev/null
    echo -e "${gl_lv}✅ 服务已停止${gl_bai}"
    break_end
}

# 重启转换代理
resp_proxy_restart() {
    systemctl restart "$RESP_PROXY_SERVICE" 2>/dev/null
    sleep 1
    if systemctl is-active "$RESP_PROXY_SERVICE" &>/dev/null; then
        echo -e "${gl_lv}✅ 服务已重启${gl_bai}"
    else
        echo -e "${gl_hong}❌ 重启失败${gl_bai}"
    fi
    break_end
}

# 卸载转换代理
resp_proxy_uninstall() {
    clear
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo -e "${gl_hong}  卸载转换代理${gl_bai}"
    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
    echo ""
    echo -e "${gl_huang}警告: 此操作将删除转换代理及其所有配置！${gl_bai}"
    echo ""

    read -e -p "确认卸载？(输入 yes 确认): " confirm
    if [ "$confirm" != "yes" ]; then
        echo "已取消"
        break_end
        return 0
    fi

    echo ""
    echo "正在停止服务..."
    systemctl stop "$RESP_PROXY_SERVICE" 2>/dev/null
    systemctl disable "$RESP_PROXY_SERVICE" 2>/dev/null

    echo "正在删除 systemd 服务..."
    rm -f "/etc/systemd/system/${RESP_PROXY_SERVICE}.service"
    systemctl daemon-reload 2>/dev/null

    echo "正在删除代理文件..."
    rm -rf "$RESP_PROXY_INSTALL_DIR"

    echo ""
    echo -e "${gl_lv}✅ 转换代理卸载完成${gl_bai}"

    break_end
}

# 转换代理主菜单
manage_resp_proxy() {
    while true; do
        clear
        echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
        echo -e "${gl_kjlan}  OpenAI Responses API 转换代理${gl_bai}"
        echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
        echo ""
        echo -e "${gl_hui}将 Responses API → Chat Completions API"
        echo -e "让沉浸式翻译等工具使用仅支持 Responses API 的服务${gl_bai}"
        echo ""

        # 显示当前状态
        local status
        status=$(resp_proxy_check_status)

        case "$status" in
            "not_installed")
                echo -e "当前状态: ${gl_huang}⚠ 未安装${gl_bai}"
                ;;
            "running")
                local port upstream
                port=$(resp_proxy_get_port)
                upstream=$(resp_proxy_get_upstream)
                echo -e "当前状态: ${gl_lv}✅ 运行中${gl_bai} (端口: ${port})"
                echo -e "上游地址: ${gl_zi}${upstream}${gl_bai}"
                ;;
            "stopped")
                echo -e "当前状态: ${gl_hong}❌ 已停止${gl_bai}"
                ;;
        esac

        echo ""
        echo -e "${gl_kjlan}[部署]${gl_bai}"
        echo "1. 一键部署（首次安装）"
        echo ""
        echo -e "${gl_kjlan}[服务管理]${gl_bai}"
        echo "2. 查看状态"
        echo "3. 查看日志"
        echo "4. 启动服务"
        echo "5. 停止服务"
        echo "6. 重启服务"
        echo ""
        echo -e "${gl_kjlan}[配置]${gl_bai}"
        echo "7. 修改配置（上游地址/Key/端口）"
        echo "8. 查看当前配置文件"
        echo ""
        echo -e "${gl_hong}9. 卸载${gl_bai}"
        echo ""
        echo "0. 返回上级菜单"
        echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"

        read -e -p "请选择操作 [0-9]: " choice

        case $choice in
            1)
                resp_proxy_deploy
                ;;
            2)
                resp_proxy_status
                ;;
            3)
                resp_proxy_logs
                ;;
            4)
                resp_proxy_start
                ;;
            5)
                resp_proxy_stop
                ;;
            6)
                resp_proxy_restart
                ;;
            7)
                resp_proxy_config
                ;;
            8)
                clear
                if [ -f "$RESP_PROXY_CONFIG" ]; then
                    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
                    echo -e "${gl_kjlan}  原始反代 API 配置${gl_bai}"
                    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
                    echo ""
                    cat "$RESP_PROXY_CONFIG"
                    echo ""
                    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
                    echo -e "${gl_kjlan}  转换后的代理信息${gl_bai}"
                    echo -e "${gl_kjlan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${gl_bai}"
                    echo ""
                    local cfg_port cfg_key cfg_ip
                    cfg_port=$(resp_proxy_get_port)
                    cfg_key=$(grep -o '"api_key"[[:space:]]*:[[:space:]]*"[^"]*"' "$RESP_PROXY_CONFIG" | sed 's/.*"api_key"[[:space:]]*:[[:space:]]*"//' | sed 's/"$//')
                    cfg_ip=$(curl -s4 --max-time 3 ifconfig.me 2>/dev/null || curl -s4 --max-time 3 ip.sb 2>/dev/null || echo "你的IP")
                    echo -e "代理地址: ${gl_huang}http://${cfg_ip}:${cfg_port}/v1/chat/completions${gl_bai}"
                    echo ""
                    echo -e "${gl_kjlan}沉浸式翻译配置:${gl_bai}"
                    echo -e "  翻译服务: ${gl_zi}OpenAI${gl_bai}"
                    echo -e "  API URL:  ${gl_zi}http://${cfg_ip}:${cfg_port}/v1/chat/completions${gl_bai}"
                    echo -e "  API Key:  ${gl_zi}${cfg_key}${gl_bai}"
                    echo -e "  模型:     ${gl_zi}按上游支持的模型填写 (如 gpt-5.3-codex / o3)${gl_bai}"
                else
                    echo -e "${gl_huang}配置文件不存在${gl_bai}"
                fi
                break_end
                ;;
            9)
                resp_proxy_uninstall
                ;;
            0)
                return
                ;;
            *)
                echo "无效的选择"
                sleep 2
                ;;
        esac
    done
}

# 显示帮助信息
show_help() {
    cat << EOF
BBR v3 终极优化脚本 v${SCRIPT_VERSION}

用法: $0 [选项]

选项:
  -h, --help      显示此帮助信息
  -v, --version   显示版本号
  -i, --install   直接安装 XanMod 内核（非交互）
  --debug         启用调试模式（详细日志）
  -q, --quiet     静默模式（仅显示错误）

示例:
  $0              启动交互式菜单
  $0 -i           直接安装 BBR v3 内核
  $0 --debug      调试模式运行

日志文件: ${LOG_FILE}
配置文件: ~/.net-tcp-tune.conf 或 /etc/net-tcp-tune.conf
EOF
}

# 解析命令行参数
parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -h|--help)
                show_help
                exit 0
                ;;
            -v|--version)
                echo "net-tcp-tune.sh v${SCRIPT_VERSION}"
                exit 0
                ;;
            -i|--install)
                check_root
                install_xanmod_kernel
                if [ $? -eq 0 ]; then
                    echo ""
                    echo "安装完成后，请重启系统以加载新内核"
                fi
                exit 0
                ;;
            --debug)
                LOG_LEVEL="DEBUG"
                log_debug "调试模式已启用"
                shift
                ;;
            -q|--quiet)
                LOG_LEVEL="ERROR"
                shift
                ;;
            -*)
                echo "未知选项: $1"
                echo "使用 -h 或 --help 查看帮助"
                exit 1
                ;;
            *)
                # 无参数时继续
                break
                ;;
        esac
    done
}

main() {
    # 先解析参数
    parse_args "$@"

    # 检查 root 权限
    check_root

    # 加载用户配置（如果存在）
    [ -f "/etc/net-tcp-tune.conf" ] && source "/etc/net-tcp-tune.conf"
    [ -f "$HOME/.net-tcp-tune.conf" ] && source "$HOME/.net-tcp-tune.conf"

    # 交互式菜单
    while true; do
        show_main_menu
    done
}

# 执行主函数
main "$@"
