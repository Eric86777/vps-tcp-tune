#!/bin/bash
# ============================================================================
# 版本管理规则：每次更新版本时，只保留最新5条版本备注
# ============================================================================
# v1.9.10 更新: 修复邮件通知入/出流量显示与计费模式不一致 (by Eric86777)
# v1.9.9 更新: 修复恢复监控时重复追加规则 (by Eric86777)
# v1.9.8 更新: 修复定时任务北京时间换算为系统时区 (by Eric86777)
# v1.9.7 更新: 检测结果框再次微调对齐 (by Eric86777)
# v1.9.6 更新: 规则数量不足改为基于计数器/配额规则检查 (by Eric86777)
# 完整更新日志见: https://github.com/Eric86777/vps-tcp-tune

set -euo pipefail
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

readonly SCRIPT_VERSION="1.9.10"
readonly SCRIPT_NAME="端口流量狗"
# 修复：当通过 bash <(curl ...) 运行时，$0 会指向临时管道
# 此时 realpath "$0" 返回类似 /proc/xxx/fd/pipe:xxx 的无效路径
# 对于 cron 任务，我们需要使用固定的可执行路径
_raw_script_path="$(realpath "$0" 2>/dev/null || echo "")"
if [[ "$_raw_script_path" == /proc/* ]] || [[ "$_raw_script_path" == /dev/* ]] || [[ -z "$_raw_script_path" ]]; then
    # 通过管道运行，使用固定的 cron 脚本路径
    readonly SCRIPT_PATH="/usr/local/bin/port-traffic-dog.sh"
    readonly SCRIPT_RUN_MODE="online"
else
    readonly SCRIPT_PATH="$_raw_script_path"
    readonly SCRIPT_RUN_MODE="local"
fi
readonly CONFIG_DIR="/etc/port-traffic-dog"
readonly CONFIG_FILE="$CONFIG_DIR/config.json"
readonly LOG_FILE="$CONFIG_DIR/logs/traffic.log"
readonly TRAFFIC_DATA_FILE="$CONFIG_DIR/traffic_data.json"
readonly BACKUP_DIR="$CONFIG_DIR/backups"
readonly BACKUP_CONFIG_FILE="$CONFIG_DIR/backup_config.json"
readonly MAX_BACKUPS=7  # 保留最近7个备份

readonly RED='\033[0;31m'
readonly YELLOW='\033[0;33m'
readonly BLUE='\033[0;34m'
readonly GREEN='\033[0;32m'
readonly CYAN='\033[0;36m'
readonly NC='\033[0m'
readonly GRAY='\033[0;90m'

# 多源下载策略
readonly DOWNLOAD_SOURCES=(
    ""
    "https://ghfast.top/"
    "https://free.cn.eu.org/"
    "https://ghproxy.net/"
)

# 网络超时设置
readonly SHORT_CONNECT_TIMEOUT=5
readonly SHORT_MAX_TIMEOUT=7
readonly SCRIPT_URL="https://raw.githubusercontent.com/Eric86777/vps-tcp-tune/main/Eric_port-traffic-dog.sh"
readonly SHORTCUT_COMMAND="dog"

detect_system() {
    # Ubuntu优先检测：避免Debian系统误判
    if [ -f /etc/lsb-release ] && grep -q "Ubuntu" /etc/lsb-release 2>/dev/null; then
        echo "ubuntu"
        return
    fi

    if [ -f /etc/debian_version ]; then
        echo "debian"
        return
    fi

    echo "unknown"
}

install_missing_tools() {
    local missing_tools=("$@")
    local system_type=$(detect_system)

    echo -e "${YELLOW}检测到缺少工具: ${missing_tools[*]}${NC}"
    echo "正在自动安装..."

    case $system_type in
        "ubuntu")
            apt update -qq
            for tool in "${missing_tools[@]}"; do
                case $tool in
                    "nft") apt install -y nftables ;;
                    "tc") apt install -y iproute2 ;;
                    "ss") apt install -y iproute2 ;;
                    "jq") apt install -y jq ;;
                    "awk") apt install -y gawk ;;
                    "bc") apt install -y bc ;;
                    "cron")
                        apt install -y cron
                        systemctl enable cron 2>/dev/null || true
                        systemctl start cron 2>/dev/null || true
                        ;;
                    *) apt install -y "$tool" ;;
                esac
            done
            ;;
        "debian")
            apt-get update -qq
            for tool in "${missing_tools[@]}"; do
                case $tool in
                    "nft") apt-get install -y nftables ;;
                    "tc") apt-get install -y iproute2 ;;
                    "ss") apt-get install -y iproute2 ;;
                    "jq") apt-get install -y jq ;;
                    "awk") apt-get install -y gawk ;;
                    "bc") apt-get install -y bc ;;
                    "cron")
                        apt-get install -y cron
                        systemctl enable cron 2>/dev/null || true
                        systemctl start cron 2>/dev/null || true
                        ;;
                    *) apt-get install -y "$tool" ;;
                esac
            done
            ;;
        *)
            echo -e "${RED}不支持的系统类型: $system_type${NC}"
            echo "支持的系统: Ubuntu, Debian"
            echo "请手动安装: ${missing_tools[*]}"
            exit 1
            ;;
    esac

    echo -e "${GREEN}依赖工具安装完成${NC}"
}

check_dependencies() {
    local silent_mode=${1:-false}
    local missing_tools=()
    local required_tools=("nft" "tc" "ss" "jq" "awk" "bc" "unzip" "cron")

    for tool in "${required_tools[@]}"; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            missing_tools+=("$tool")
        fi
    done

    if [ ${#missing_tools[@]} -gt 0 ]; then
        install_missing_tools "${missing_tools[@]}"

        local still_missing=()
        for tool in "${missing_tools[@]}"; do
            if ! command -v "$tool" >/dev/null 2>&1; then
                still_missing+=("$tool")
            fi
        done

        if [ ${#still_missing[@]} -gt 0 ]; then
            echo -e "${RED}安装失败，仍缺少工具: ${still_missing[*]}${NC}"
            echo "请手动安装后重试"
            exit 1
        fi
    fi

    if [ "$silent_mode" != "true" ]; then
        echo -e "${GREEN}依赖检查通过${NC}"
    fi

    setup_script_permissions
    setup_cron_environment
    # 重启后恢复定时任务
    local active_ports=($(get_active_ports 2>/dev/null || true))
    for port in "${active_ports[@]}"; do
        setup_port_auto_reset_cron "$port" >/dev/null 2>&1 || true
    done
}

setup_script_permissions() {
    if [ -f "$SCRIPT_PATH" ]; then
        chmod +x "$SCRIPT_PATH" 2>/dev/null || true
    fi

    if [ -f "/usr/local/bin/port-traffic-dog.sh" ]; then
        chmod +x "/usr/local/bin/port-traffic-dog.sh" 2>/dev/null || true
    fi
}

setup_cron_environment() {
    # cron环境配置：设置PATH，所有任务按系统时区(UTC)执行
    local current_cron=$(crontab -l 2>/dev/null || true)
    local needs_update=false
    local temp_cron=$(mktemp)
    
    # 设置完整PATH
    echo "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" > "$temp_cron"
    if ! echo "$current_cron" | grep -q "^PATH=.*sbin"; then
        needs_update=true
    fi
    
    # 保留现有任务（排除旧的TZ和PATH设置）
    echo "$current_cron" | grep -v "^TZ=" | grep -v "^PATH=" >> "$temp_cron" || true
    
    # 如果需要更新，或者存在旧的TZ设置，就应用新配置
    if [ "$needs_update" = true ] || echo "$current_cron" | grep -q "^TZ="; then
        crontab "$temp_cron" 2>/dev/null || true
    fi
    
    rm -f "$temp_cron"
}

check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}错误：此脚本需要root权限运行${NC}"
        exit 1
    fi
}

verify_downloaded_dog_script() {
    local file=$1

    if [ ! -s "$file" ]; then
        return 1
    fi

    local first_line=""
    first_line=$(head -n 1 "$file" 2>/dev/null || true)
    if ! echo "$first_line" | grep -q "^#!"; then
        return 1
    fi

    if ! grep -q 'SCRIPT_VERSION=' "$file" 2>/dev/null; then
        return 1
    fi

    return 0
}

# 确保本地有脚本文件供 cron 任务使用
# 当通过 bash <(curl ...) 运行时，每次都更新本地脚本以保持最新
ensure_local_script_for_cron() {
    local local_script="/usr/local/bin/port-traffic-dog.sh"
    local script_url="https://raw.githubusercontent.com/Eric86777/vps-tcp-tune/main/Eric_port-traffic-dog.sh"
    
    # 每次在线运行时都更新本地脚本，确保 cron 任务使用最新版本
    local temp_file=""
    temp_file=$(mktemp) || true
    if [ -n "$temp_file" ] && download_with_sources "$script_url" "$temp_file"; then
        if verify_downloaded_dog_script "$temp_file"; then
            local backup_path=""
            if [ -f "$local_script" ]; then
                backup_path="${local_script}.bak.$(date +%Y%m%d_%H%M%S)"
                cp "$local_script" "$backup_path" 2>/dev/null || true
            fi

            if mv "$temp_file" "$local_script"; then
                chmod +x "$local_script" 2>/dev/null || true
            else
                echo -e "${YELLOW}更新脚本失败，保留旧版本${NC}"
                [ -n "$backup_path" ] && cp "$backup_path" "$local_script" 2>/dev/null || true
                rm -f "$temp_file" 2>/dev/null || true
            fi
        else
            echo -e "${YELLOW}脚本校验失败，已跳过更新${NC}"
            rm -f "$temp_file" 2>/dev/null || true
        fi
    else
        [ -n "$temp_file" ] && rm -f "$temp_file" 2>/dev/null || true
    fi
    
    # 自动修复 crontab 中的错误路径（/proc/xxx/fd/pipe:xxx → 正确路径）
    if crontab -l 2>/dev/null | grep -q '/proc/.*fd/pipe:'; then
        crontab -l 2>/dev/null | sed "s|/proc/[0-9]*/fd/pipe:\[[0-9]*\]|$local_script|g" | crontab -
    fi
}

init_config() {
    mkdir -p "$CONFIG_DIR" "$(dirname "$LOG_FILE")"

    # 静默下载通知模块，避免影响主流程
    download_notification_modules >/dev/null 2>&1 || true

    if [ ! -f "$CONFIG_FILE" ]; then
        cat > "$CONFIG_FILE" << 'EOF'
{
  "global": {
    "billing_mode": "double"
  },
  "ports": {},
  "nftables": {
    "table_name": "port_traffic_monitor",
    "family": "inet"
  },
  "notifications": {
    "telegram": {
      "enabled": false,
      "bot_token": "",
      "chat_id": "",
      "server_name": "",
      "status_notifications": {
        "enabled": false,
        "interval": "1h"
      }
    },
    "email": {
      "enabled": false,
      "resend_api_key": "",
      "email_from": "",
      "email_from_name": "",
      "email_to": "",
      "server_name": "",
      "status_notifications": {
        "enabled": false,
        "interval": "1h"
      }
    },
    "wecom": {
      "enabled": false,
      "webhook_url": "",
      "server_name": "",
      "status_notifications": {
        "enabled": false,
        "interval": "1h"
      }
    }
  }
}
EOF
    fi

    # 如果是在线运行模式，需要下载脚本到本地供 cron 任务使用
    if [ "$SCRIPT_RUN_MODE" = "online" ]; then
        ensure_local_script_for_cron
    fi

    init_nftables
    setup_exit_hooks
    restore_monitoring_if_needed
}

init_nftables() {
    local table_name=$(jq -r '.nftables.table_name' "$CONFIG_FILE")
    local family=$(jq -r '.nftables.family' "$CONFIG_FILE")
    # 使用inet family支持IPv4/IPv6双栈
    nft add table $family $table_name 2>/dev/null || true
    nft add chain $family $table_name input { type filter hook input priority 0\; } 2>/dev/null || true
    nft add chain $family $table_name output { type filter hook output priority 0\; } 2>/dev/null || true
    nft add chain $family $table_name forward { type filter hook forward priority 0\; } 2>/dev/null || true
    # 增加 prerouting 链以在 NAT 之前拦截 (Priority -150 在 Conntrack(-200)之后, DNAT(-100)之前)
    nft add chain $family $table_name prerouting { type filter hook prerouting priority -150\; } 2>/dev/null || true
}

get_network_interfaces() {
    local interfaces=()

    while IFS= read -r interface; do
        if [[ "$interface" != "lo" ]] && [[ "$interface" != "" ]]; then
            interfaces+=("$interface")
        fi
    done < <(ip link show | grep "state UP" | awk -F': ' '{print $2}' | cut -d'@' -f1)

    printf '%s\n' "${interfaces[@]}"
}

get_default_interface() {
    local default_interface=$(ip route | grep default | awk '{print $5}' | head -n1)

    if [ -n "$default_interface" ]; then
        echo "$default_interface"
        return
    fi

    local interfaces=($(get_network_interfaces))
    if [ ${#interfaces[@]} -gt 0 ]; then
        echo "${interfaces[0]}"
    else
        echo "eth0"
    fi
}

format_bytes() {
    local bytes=$1

    if ! [[ "$bytes" =~ ^[0-9]+$ ]]; then
        bytes=0
    fi

    if [ $bytes -ge 1073741824 ]; then
        local gb=$(echo "scale=2; $bytes / 1073741824" | bc)
        echo "${gb}GB"
    elif [ $bytes -ge 1048576 ]; then
        local mb=$(echo "scale=2; $bytes / 1048576" | bc)
        echo "${mb}MB"
    elif [ $bytes -ge 1024 ]; then
        local kb=$(echo "scale=2; $bytes / 1024" | bc)
        echo "${kb}KB"
    else
        echo "${bytes}B"
    fi
}

get_beijing_time() {
    TZ='Asia/Shanghai' date "$@"
}

# 将北京时间转换为系统本地时间（用于 cron 任务）
# 参数: $1=小时(0-23), $2=分钟(0-59), $3=星期(0-6,可选,0=周日)
# 返回: "本地小时 本地分钟 [本地星期]"
# 示例: convert_beijing_to_local_time 12 30      → "13 30" (东京)
#       convert_beijing_to_local_time 00 00 1    → "16 00 0" (UTC环境，北京周一00:00 = UTC周日16:00)
convert_beijing_to_local_time() {
    local beijing_hour=$1
    local beijing_minute=$2
    local beijing_weekday=${3:-}  # 可选参数，使用默认值避免unbound variable

    # 获取北京时间的基准日期
    local base_date
    base_date=$(TZ='Asia/Shanghai' date +%Y-%m-%d 2>/dev/null || date +%Y-%m-%d)

    # 如果传入了星期参数，找到北京当前日期中对应的下一次该星期
    local target_date="$base_date"
    if [ -n "$beijing_weekday" ]; then
        local current_weekday
        current_weekday=$(TZ='Asia/Shanghai' date +%w 2>/dev/null || date +%w)
        if [[ "$current_weekday" =~ ^[0-6]$ ]] && [[ "$beijing_weekday" =~ ^[0-6]$ ]]; then
            local diff=$((beijing_weekday - current_weekday))
            if [ $diff -lt 0 ]; then
                diff=$((diff + 7))
            fi
            target_date=$(TZ='Asia/Shanghai' date -d "$base_date +$diff day" +%Y-%m-%d 2>/dev/null || \
                date -d "$base_date +$diff day" +%Y-%m-%d 2>/dev/null || echo "$base_date")
        fi
    fi

    # 生成北京时间对应的时间戳，再转换为系统本地时间
    local epoch=""
    epoch=$(TZ='Asia/Shanghai' date -d "$target_date $beijing_hour:$beijing_minute:00" +%s 2>/dev/null || \
        date -d "$target_date $beijing_hour:$beijing_minute:00" +%s 2>/dev/null || echo "")

    local local_hour=""
    local local_minute=""
    local local_weekday=""
    if [ -n "$epoch" ]; then
        local_hour=$(date -d "@$epoch" +%H 2>/dev/null || date -r "$epoch" +%H 2>/dev/null || echo "")
        local_minute=$(date -d "@$epoch" +%M 2>/dev/null || date -r "$epoch" +%M 2>/dev/null || echo "")
        local_weekday=$(date -d "@$epoch" +%w 2>/dev/null || date -r "$epoch" +%w 2>/dev/null || echo "")
    fi

    # 兜底：若转换失败，则退回旧的UTC换算逻辑
    if ! [[ "$local_hour" =~ ^[0-9]{1,2}$ ]] || ! [[ "$local_minute" =~ ^[0-9]{1,2}$ ]]; then
        local utc_hour=$((beijing_hour - 8))
        local utc_minute=$beijing_minute
        local utc_weekday=$beijing_weekday

        if [ $utc_hour -lt 0 ]; then
            utc_hour=$((utc_hour + 24))
            if [ -n "$beijing_weekday" ]; then
                utc_weekday=$((beijing_weekday - 1))
                if [ $utc_weekday -lt 0 ]; then
                    utc_weekday=6
                fi
            fi
        fi

        local_hour=$(printf "%02d" $utc_hour)
        local_minute=$(printf "%02d" $utc_minute)
        local_weekday=$utc_weekday
    else
        local_hour=$(printf "%02d" "$local_hour")
        local_minute=$(printf "%02d" "$local_minute")
    fi

    if [ -n "$beijing_weekday" ]; then
        echo "$local_hour $local_minute $local_weekday"
    else
        echo "$local_hour $local_minute"
    fi
}

# 获取系统时区信息（用于显示）
get_system_timezone() {
    if command -v timedatectl &>/dev/null; then
        timedatectl | grep "Time zone" | awk '{print $3}' | sed 's/[()]//g'
    elif [ -f /etc/timezone ]; then
        cat /etc/timezone
    elif [ -n "$TZ" ]; then
        echo "$TZ"
    else
        date +%Z
    fi
}

update_config() {
    local jq_expression="$1"
    jq "$jq_expression" "$CONFIG_FILE" > "${CONFIG_FILE}.tmp"
    mv "${CONFIG_FILE}.tmp" "$CONFIG_FILE"
}

show_port_list() {
    local active_ports=($(get_active_ports))
    if [ ${#active_ports[@]} -eq 0 ]; then
        echo "暂无监控端口"
        return 1
    fi

    echo "当前监控的端口:"
    for i in "${!active_ports[@]}"; do
        local port=${active_ports[$i]}
        local status_label=$(get_port_status_label "$port")
        local remark=$(jq -r ".ports.\"$port\".remark // \"\"" "$CONFIG_FILE")
        
        # 端口类型判断和显示
        local port_display
        if is_port_group "$port"; then
            local display_str="$port"
            if [ ${#port} -gt 25 ]; then
                local count=$(echo "$port" | tr -cd ',' | wc -c)
                count=$((count + 1))
                display_str="${port:0:22}...(${count}个)"
            fi
            port_display="端口组[${display_str}]"
        elif is_port_range "$port"; then
            port_display="端口段[$port]"
        else
            port_display="端口 $port"
        fi
        
        echo "$((i+1)). $port_display $status_label"
    done
    return 0
}

parse_multi_choice_input() {
    local input="$1"
    local max_choice="$2"
    local -n result_array=$3

    IFS=',' read -ra CHOICES <<< "$input"
    result_array=()

    for choice in "${CHOICES[@]}"; do
        choice=$(echo "$choice" | tr -d ' ')
        if [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -ge 1 ] && [ "$choice" -le "$max_choice" ]; then
            result_array+=("$choice")
        else
            echo -e "${RED}无效选择: $choice${NC}"
        fi
    done
}

parse_comma_separated_input() {
    local input="$1"
    local -n result_array=$2

    IFS=',' read -ra result_array <<< "$input"

    for i in "${!result_array[@]}"; do
        result_array[$i]=$(echo "${result_array[$i]}" | tr -d ' ')
    done
}

parse_port_range_input() {
    local input="$1"
    local -n result_array=$2

    IFS=',' read -ra PARTS <<< "$input"
    result_array=()

    for part in "${PARTS[@]}"; do
        part=$(echo "$part" | tr -d ' ')

        if is_port_range "$part"; then
            # 端口段：100-200
            local start_port=$(echo "$part" | cut -d'-' -f1)
            local end_port=$(echo "$part" | cut -d'-' -f2)

            if [ "$start_port" -gt "$end_port" ]; then
                echo -e "${RED}错误：端口段 $part 起始端口大于结束端口${NC}"
                return 1
            fi

            if [ "$start_port" -lt 1 ] || [ "$start_port" -gt 65535 ] || [ "$end_port" -lt 1 ] || [ "$end_port" -gt 65535 ]; then
                echo -e "${RED}错误：端口段 $part 包含无效端口，必须在1-65535范围内${NC}"
                return 1
            fi

            result_array+=("$part")

        elif [[ "$part" =~ ^[0-9]+$ ]]; then
            if [ "$part" -ge 1 ] && [ "$part" -le 65535 ]; then
                result_array+=("$part")
            else
                echo -e "${RED}错误：端口号 $part 无效，必须是1-65535之间的数字${NC}"
                return 1
            fi
        else
            echo -e "${RED}错误：无效的端口格式 $part${NC}"
            return 1
        fi
    done

    return 0
}

expand_single_value_to_array() {
    local -n source_array=$1
    local target_size=$2

    if [ ${#source_array[@]} -eq 1 ]; then
        local single_value="${source_array[0]}"
        source_array=()
        for ((i=0; i<target_size; i++)); do
            source_array+=("$single_value")
        done
    fi
}


get_beijing_month_year() {
    local current_day=$(TZ='Asia/Shanghai' date +%d | sed 's/^0//')
    local current_month=$(TZ='Asia/Shanghai' date +%m | sed 's/^0//')
    local current_year=$(TZ='Asia/Shanghai' date +%Y)
    echo "$current_day $current_month $current_year"
}

get_nftables_counter_data() {
    local port=$1
    local table_name=$(jq -r '.nftables.table_name' "$CONFIG_FILE")
    local family=$(jq -r '.nftables.family' "$CONFIG_FILE")

    # 根据端口类型确定计数器名称
    local port_safe
    if is_port_group "$port"; then
        port_safe=$(generate_port_group_safe_name "$port")
    elif is_port_range "$port"; then
        port_safe=$(echo "$port" | tr '-' '_')
    else
        port_safe="$port"
    fi

    local input_bytes=$(nft list counter $family $table_name "port_${port_safe}_in" 2>/dev/null | \
        grep -o 'bytes [0-9]*' | awk '{print $2}')
    local output_bytes=$(nft list counter $family $table_name "port_${port_safe}_out" 2>/dev/null | \
        grep -o 'bytes [0-9]*' | awk '{print $2}')

    input_bytes=${input_bytes:-0}
    output_bytes=${output_bytes:-0}
    echo "$input_bytes $output_bytes"
}

get_port_traffic() {
    get_nftables_counter_data "$1"
}


save_traffic_data() {
    local temp_file=$(mktemp)
    local active_ports=($(get_active_ports 2>/dev/null || true))

    if [ ${#active_ports[@]} -eq 0 ]; then
        return 0
    fi

    echo '{}' > "$temp_file"

    for port in "${active_ports[@]}"; do
        local traffic_data=($(get_nftables_counter_data "$port"))
        local current_input=${traffic_data[0]}
        local current_output=${traffic_data[1]}

        # 只备份有意义的数据
        if [ $current_input -gt 0 ] || [ $current_output -gt 0 ]; then
            jq ".\"$port\" = {\"input\": $current_input, \"output\": $current_output, \"backup_time\": \"$(get_beijing_time -Iseconds)\"}" \
                "$temp_file" > "${temp_file}.tmp" && mv "${temp_file}.tmp" "$temp_file"
        fi
    done

    if [ -s "$temp_file" ] && [ "$(jq 'keys | length' "$temp_file" 2>/dev/null)" != "0" ]; then
        mv "$temp_file" "$TRAFFIC_DATA_FILE"
    else
        rm -f "$temp_file"
    fi
}

setup_exit_hooks() {
    # 进程退出时自动保存数据，避免重启丢失
    trap 'save_traffic_data_on_exit' EXIT
    trap 'save_traffic_data_on_exit; exit 1' INT TERM
}

save_traffic_data_on_exit() {
    save_traffic_data >/dev/null 2>&1
}

restore_monitoring_if_needed() {
    local active_ports=($(get_active_ports 2>/dev/null || true))

    if [ ${#active_ports[@]} -eq 0 ]; then
        return 0
    fi

    local table_name=$(jq -r '.nftables.table_name' "$CONFIG_FILE")
    local family=$(jq -r '.nftables.family' "$CONFIG_FILE")
    local all_rules
    all_rules=$(nft -a list table $family $table_name 2>/dev/null || true)
    local ports_to_restore=()

    for port in "${active_ports[@]}"; do
        local running_status
        running_status=$(get_port_running_status "$port")
        if [ "$running_status" = "blocked_expired" ]; then
            continue
        fi

        local port_safe
        if is_port_group "$port"; then
            port_safe=$(generate_port_group_safe_name "$port")
        elif is_port_range "$port"; then
            port_safe=$(echo "$port" | tr '-' '_')
        else
            port_safe="$port"
        fi

        local counter_missing=false
        if ! nft list counter $family $table_name "port_${port_safe}_in" >/dev/null 2>&1; then
            counter_missing=true
        fi
        if ! nft list counter $family $table_name "port_${port_safe}_out" >/dev/null 2>&1; then
            counter_missing=true
        fi

        local rules_insufficient=false
        if [ "$counter_missing" = false ]; then
            local counter_rules
            counter_rules=$(echo "$all_rules" | grep "counter name \"port_${port_safe}_" | wc -l)

            local expected_counter_rules=8
            if is_port_group "$port"; then
                local group_ports=($(get_group_ports "$port"))
                local port_count=${#group_ports[@]}
                expected_counter_rules=$((port_count * 8))
            fi

            if [ "$counter_rules" -lt "$expected_counter_rules" ]; then
                rules_insufficient=true
            fi
        fi

        if [ "$counter_missing" = true ] || [ "$rules_insufficient" = true ]; then
            ports_to_restore+=("$port")
        fi
    done

    if [ ${#ports_to_restore[@]} -eq 0 ]; then
        return 0
    fi

    # 仅修复缺失端口，避免重复追加规则
    for port in "${ports_to_restore[@]}"; do
        remove_nftables_rules "$port" >/dev/null 2>&1
    done

    restore_traffic_data_from_backup "${ports_to_restore[@]}"
    restore_all_monitoring_rules "${ports_to_restore[@]}" >/dev/null 2>&1
}

restore_traffic_data_from_backup() {
    local target_ports=("$@")
    if [ ! -f "$TRAFFIC_DATA_FILE" ]; then
        return 0
    fi

    local table_name=$(jq -r '.nftables.table_name' "$CONFIG_FILE")
    local family=$(jq -r '.nftables.family' "$CONFIG_FILE")
    local backup_ports=($(jq -r 'keys[]' "$TRAFFIC_DATA_FILE" 2>/dev/null || true))

    for port in "${backup_ports[@]}"; do
        if [ ${#target_ports[@]} -gt 0 ]; then
            local matched=false
            for target_port in "${target_ports[@]}"; do
                if [ "$port" = "$target_port" ]; then
                    matched=true
                    break
                fi
            done
            if [ "$matched" = false ]; then
                continue
            fi
        fi

        local backup_input=$(jq -r ".\"$port\".input // 0" "$TRAFFIC_DATA_FILE" 2>/dev/null || echo "0")
        local backup_output=$(jq -r ".\"$port\".output // 0" "$TRAFFIC_DATA_FILE" 2>/dev/null || echo "0")

        if [ $backup_input -gt 0 ] || [ $backup_output -gt 0 ]; then
            restore_counter_value "$port" "$backup_input" "$backup_output"
        fi
    done

    # 恢复完成后删除备份文件
    rm -f "$TRAFFIC_DATA_FILE"
}

restore_counter_value() {
    local port=$1
    local target_input=$2
    local target_output=$3
    local table_name=$(jq -r '.nftables.table_name' "$CONFIG_FILE")
    local family=$(jq -r '.nftables.family' "$CONFIG_FILE")

    # 根据端口类型确定计数器名称
    local port_safe
    if is_port_group "$port"; then
        port_safe=$(generate_port_group_safe_name "$port")
    elif is_port_range "$port"; then
        port_safe=$(echo "$port" | tr '-' '_')
    else
        port_safe="$port"
    fi

    # 先删除已存在的计数器（如果有），再创建带初始值的计数器
    nft delete counter $family $table_name "port_${port_safe}_in" 2>/dev/null || true
    nft delete counter $family $table_name "port_${port_safe}_out" 2>/dev/null || true
    
    nft add counter $family $table_name "port_${port_safe}_in" { packets 0 bytes $target_input } 2>/dev/null || true
    nft add counter $family $table_name "port_${port_safe}_out" { packets 0 bytes $target_output } 2>/dev/null || true
}

restore_all_monitoring_rules() {
    local active_ports=("$@")
    if [ ${#active_ports[@]} -eq 0 ]; then
        active_ports=($(get_active_ports))
    fi
    if [ ${#active_ports[@]} -eq 0 ]; then
        return 0
    fi

    local table_name=$(jq -r '.nftables.table_name' "$CONFIG_FILE")
    local family=$(jq -r '.nftables.family' "$CONFIG_FILE")
    local all_rules
    all_rules=$(nft -a list table $family $table_name 2>/dev/null || true)

    for port in "${active_ports[@]}"; do
        local port_safe
        if is_port_group "$port"; then
            port_safe=$(generate_port_group_safe_name "$port")
        elif is_port_range "$port"; then
            port_safe=$(echo "$port" | tr '-' '_')
        else
            port_safe="$port"
        fi

        local counter_in_exists=false
        local counter_out_exists=false
        if nft list counter $family $table_name "port_${port_safe}_in" >/dev/null 2>&1; then
            counter_in_exists=true
        fi
        if nft list counter $family $table_name "port_${port_safe}_out" >/dev/null 2>&1; then
            counter_out_exists=true
        fi

        local counter_rules
        counter_rules=$(echo "$all_rules" | grep "counter name \"port_${port_safe}_" | wc -l)
        local expected_counter_rules=8
        if is_port_group "$port"; then
            local group_ports=($(get_group_ports "$port"))
            local port_count=${#group_ports[@]}
            expected_counter_rules=$((port_count * 8))
        fi

        if [ "$counter_in_exists" = true ] && [ "$counter_out_exists" = true ] && [ "$counter_rules" -ge "$expected_counter_rules" ]; then
            continue
        fi

        add_nftables_rules "$port"

        # 恢复配额限制
        local quota_enabled=$(jq -r ".ports.\"$port\".quota.enabled // false" "$CONFIG_FILE")
        local monthly_limit=$(jq -r ".ports.\"$port\".quota.monthly_limit // \"unlimited\"" "$CONFIG_FILE")
        if [ "$quota_enabled" = "true" ] && [ "$monthly_limit" != "unlimited" ]; then
            apply_nftables_quota "$port" "$monthly_limit"
        fi

        # 恢复带宽限制
        local limit_enabled=$(jq -r ".ports.\"$port\".bandwidth_limit.enabled // false" "$CONFIG_FILE")
        local rate_limit=$(jq -r ".ports.\"$port\".bandwidth_limit.rate // \"unlimited\"" "$CONFIG_FILE")
        if [ "$limit_enabled" = "true" ] && [ "$rate_limit" != "unlimited" ]; then
            local limit_lower=$(echo "$rate_limit" | tr '[:upper:]' '[:lower:]')
            local tc_limit
            if [[ "$limit_lower" =~ kbps$ ]]; then
                tc_limit=$(echo "$limit_lower" | sed 's/kbps$/kbit/')
            elif [[ "$limit_lower" =~ mbps$ ]]; then
                tc_limit=$(echo "$limit_lower" | sed 's/mbps$/mbit/')
            elif [[ "$limit_lower" =~ gbps$ ]]; then
                tc_limit=$(echo "$limit_lower" | sed 's/gbps$/gbit/')
            fi
            if [ -n "$tc_limit" ]; then
                apply_tc_limit "$port" "$tc_limit"
            fi
        fi

        setup_port_auto_reset_cron "$port"
    done
}

# ============================================================================
# 流量计算核心函数 - 重要！必读！
# ============================================================================
#
# 【背景】为什么需要 ×2？
#
# 本脚本使用 nftables 按端口统计流量。假设用户节点监听 40001 端口，
# 通过 realm 转发到落地鸡 FX:443。
#
# 【流量流向示意】（用户看10G视频）
#
#   用户 ←→ CN:40001 ←→ CN:随机端口 ←→ FX:443 ←→ YouTube
#           ↑                ↑
#        监听端口         realm发起的新连接
#        (40001)          (源端口是随机的，不是40001)
#
# 【nftables 规则匹配】
#
#   规则1: tcp dport 40001 → counter _in   (统计目标端口=40001的入站流量)
#   规则2: tcp sport 40001 → counter _out  (统计源端口=40001的出站流量)
#
# 【实际匹配情况】
#
#   ┌─────────────────────────────────────────────────────────────────────┐
#   │ 流向                        │ 端口      │ 是否匹配40001 │ 流量    │
#   ├─────────────────────────────────────────────────────────────────────┤
#   │ 用户 → CN:40001 (请求)     │ dport=40001 │ ✅ 匹配 _in  │ ~1M     │
#   │ CN:40001 → 用户 (响应)     │ sport=40001 │ ✅ 匹配 _out │ ~10G    │
#   │ CN:随机端口 → FX:443       │ dport=443   │ ❌ 不匹配    │ ~1M     │
#   │ FX:443 → CN:随机端口       │ sport=443   │ ❌ 不匹配    │ ~10G    │
#   └─────────────────────────────────────────────────────────────────────┘
#
# 【结论】
#
#   nftables 只统计了 用户↔CN:40001 这一侧的流量（约10G）
#   没有统计 CN↔FX 这一侧的流量（也是约10G，因为源端口是随机的！）
#
#   但实际上，服务商（如绿云）计费的是 eth0 网卡的全部流量：
#   - 入站：用户请求(1M) + FX返回数据(10G) = ~10G
#   - 出站：转发给FX(1M) + 返回给用户(10G) = ~10G
#   - 总计：~20G
#
# 【×2 的作用】
#
#   nftables 统计结果 ≈ 10G（只有用户侧）
#   乘以 2 = 20G（补上FX侧）
#   这样就和服务商面板的计费对上了！
#
# 【公式】
#
#   双向统计: (入站 + 出站) × 2 = (1M + 10G) × 2 ≈ 20G ✓
#   仅出站统计: 出站 × 2 = 10G × 2 = 20G ✓
#   CN Premium 内网中转: (入站 + 出站) × 1 = (1M + 10G) × 1 ≈ 10G ✓
#     - 适用场景：CN → 软银(内网) → FX
#     - 因为 CN↔软银 走内网，绿云不计费，所以不需要 ×2
#
# ============================================================================
calculate_total_traffic() {
    local input_bytes=$1
    local output_bytes=$2
    local billing_mode=${3:-"double"}
    case $billing_mode in
        "double"|"relay")
            # 双向统计：(入站 + 出站) × 2
            # 适用场景：CN 直接转发到落地鸡 FX（全程走公网）
            echo $(( (input_bytes + output_bytes) * 2 ))
            ;;
        "premium")
            # CN Premium 内网中转：(入站 + 出站) × 1
            # 适用场景：CN 通过内网转发到软银，软银再转发到 FX
            # 因为 CN↔软银 走内网不计费，所以不需要 ×2
            echo $(( input_bytes + output_bytes ))
            ;;
        "single"|*)
            # 仅出站统计：出站 × 2
            # 适用场景：只关心出站流量的场景
            echo $(( output_bytes * 2 ))
            ;;
    esac
}

# 获取端口运行状态（准确检测 nftables/tc 规则）
# 返回: running / blocked_quota / blocked_expired / rate_limited
get_port_running_status() {
    local port=$1
    local table_name=$(jq -r '.nftables.table_name' "$CONFIG_FILE" 2>/dev/null || echo "port_traffic_monitor")
    local family=$(jq -r '.nftables.family' "$CONFIG_FILE" 2>/dev/null || echo "inet")
    local port_safe=$(echo "$port" | tr ',' '_' | tr '-' '_')
    
    # 1. 检查是否被租期过期封锁（存在 _block_quota 对象）
    if nft list quota $family $table_name "port_${port_safe}_block_quota" &>/dev/null; then
        echo "blocked_expired"
        return
    fi
    
    # 2. 检查是否配额超限封锁
    local quota_limit=$(jq -r ".ports.\"$port\".quota.monthly_limit // \"unlimited\"" "$CONFIG_FILE")
    if [ "$quota_limit" != "unlimited" ]; then
        local current_usage=$(get_port_monthly_usage "$port" 2>/dev/null || echo "0")
        local limit_bytes=$(parse_size_to_bytes "$quota_limit" 2>/dev/null || echo "0")
        if [ "$current_usage" -ge "$limit_bytes" ] && [ "$limit_bytes" -gt 0 ]; then
            echo "blocked_quota"
            return
        fi
    fi
    
    # 3. 检查是否有带宽限制
    local bandwidth_enabled=$(jq -r ".ports.\"$port\".bandwidth_limit.enabled // false" "$CONFIG_FILE")
    if [ "$bandwidth_enabled" = "true" ]; then
        local rate=$(jq -r ".ports.\"$port\".bandwidth_limit.rate // \"unlimited\"" "$CONFIG_FILE")
        if [ "$rate" != "unlimited" ]; then
            echo "rate_limited:$rate"
            return
        fi
    fi
    
    # 4. 正常运行中
    echo "running"
}

# 格式化端口运行状态为显示标签
format_running_status() {
    local status=$1
    case "$status" in
        "running")
            echo "🟢"
            ;;
        "blocked_expired")
            echo "🔴过期封锁"
            ;;
        "blocked_quota")
            echo "🔴超额封锁"
            ;;
        rate_limited:*)
            local rate="${status#rate_limited:}"
            echo "🟡限速${rate}"
            ;;
        *)
            echo "⚪"
            ;;
    esac
}

get_port_status_label() {
    local port=$1
    local port_config=$(jq -r ".ports.\"$port\"" "$CONFIG_FILE" 2>/dev/null)

    local remark=$(echo "$port_config" | jq -r '.remark // ""')
    local billing_mode=$(echo "$port_config" | jq -r '.billing_mode // "double"')
    local limit_enabled=$(echo "$port_config" | jq -r '.bandwidth_limit.enabled // false')
    local rate_limit=$(echo "$port_config" | jq -r '.bandwidth_limit.rate // "unlimited"')
    local quota_enabled=$(echo "$port_config" | jq -r '.quota.enabled // true')
    local monthly_limit=$(echo "$port_config" | jq -r '.quota.monthly_limit // "unlimited"')
    local reset_day_raw=$(echo "$port_config" | jq -r '.quota.reset_day')
    local reset_day="null"
    
    # 获取重置日期（null表示用户取消了自动重置或未设置）
    if [ "$reset_day_raw" != "null" ] && [ "$reset_day_raw" != "" ]; then
        reset_day="${reset_day_raw:-1}"
    fi

    local status_tags=()

    if [ -n "$remark" ] && [ "$remark" != "null" ] && [ "$remark" != "" ]; then
        status_tags+=("[备注:$remark]")
    fi

    if [ "$quota_enabled" = "true" ]; then
        if [ "$monthly_limit" != "unlimited" ]; then
            local current_usage=$(get_port_monthly_usage "$port")
            local limit_bytes=$(parse_size_to_bytes "$monthly_limit")
            local usage_percent=$((current_usage * 100 / limit_bytes))

            local quota_display="$monthly_limit"
            case "$billing_mode" in
                "double"|"relay")
                    status_tags+=("[双向×2 ${quota_display}]")
                    ;;
                "premium")
                    status_tags+=("[CN Premium ${quota_display}]")
                    ;;
                "single")
                    status_tags+=("[单向×2 ${quota_display}]")
                    ;;
            esac
            
            if [ $usage_percent -ge 100 ]; then
                status_tags+=("[已超限]")
            fi
        else
            case "$billing_mode" in
                "double"|"relay")
                    status_tags+=("[双向×2 无限制]")
                    ;;
                "premium")
                    status_tags+=("[CN Premium 无限制]")
                    ;;
                "single")
                    status_tags+=("[单向×2 无限制]")
                    ;;
            esac
        fi

        # 显示重置日期信息 (适用于有限制和无限制模式)
        if [ "$reset_day" != "null" ]; then
            local time_info=($(get_beijing_month_year))
            local current_day=${time_info[0]}
            local current_month=${time_info[1]}
            local next_month=$current_month

            if [ $current_day -ge $reset_day ]; then
                next_month=$((current_month + 1))
                if [ $next_month -gt 12 ]; then
                    next_month=1
                fi
            fi
            
            status_tags+=("[${next_month}月${reset_day}日重置]")
        fi
    fi

    if [ "$limit_enabled" = "true" ] && [ "$rate_limit" != "unlimited" ]; then
        status_tags+=("[限制带宽${rate_limit}]")
    fi

    if [ ${#status_tags[@]} -gt 0 ]; then
        printf '%s' "${status_tags[@]}"
        echo
    fi
}

get_port_monthly_usage() {
    local port=$1
    local traffic_data=($(get_port_traffic "$port"))
    local input_bytes=${traffic_data[0]}
    local output_bytes=${traffic_data[1]}
    local billing_mode=$(jq -r ".ports.\"$port\".billing_mode // \"double\"" "$CONFIG_FILE")

    calculate_total_traffic "$input_bytes" "$output_bytes" "$billing_mode"
}

validate_bandwidth() {
    local input="$1"
    local lower_input=$(echo "$input" | tr '[:upper:]' '[:lower:]')

    if [[ "$input" == "0" ]]; then
        return 0
    elif [[ "$lower_input" =~ ^[0-9]+kbps$ ]] || [[ "$lower_input" =~ ^[0-9]+mbps$ ]] || [[ "$lower_input" =~ ^[0-9]+gbps$ ]]; then
        return 0
    else
        return 1
    fi
}

validate_quota() {
    local input="$1"
    local lower_input=$(echo "$input" | tr '[:upper:]' '[:lower:]')

    if [[ "$input" == "0" ]]; then
        return 0
    elif [[ "$lower_input" =~ ^[0-9]+(mb|gb|tb|m|g|t)$ ]]; then
        return 0
    else
        return 1
    fi
}

parse_size_to_bytes() {
    local size_str=$1
    local number=$(echo "$size_str" | grep -o '^[0-9]\+')
    local unit=$(echo "$size_str" | grep -o '[A-Za-z]\+$' | tr '[:lower:]' '[:upper:]')

    [ -z "$number" ] && echo "0" && return 1

    case $unit in
        "MB"|"M") echo $((number * 1048576)) ;;
        "GB"|"G") echo $((number * 1073741824)) ;;
        "TB"|"T") echo $((number * 1099511627776)) ;;
        *) echo "0" ;;
    esac
}


get_active_ports() {
    jq -r '.ports | keys[]' "$CONFIG_FILE" 2>/dev/null | sort -n
}

is_port_range() {
    local port=$1
    [[ "$port" =~ ^[0-9]+-[0-9]+$ ]]
}

# 判断是否为端口组（多个端口用逗号分隔，共享配额）
# 端口组格式: "101,102,105" (包含逗号，且不是端口段)
is_port_group() {
    local port=$1
    # 包含逗号，且不是端口段格式
    [[ "$port" =~ , ]] && ! is_port_range "$port"
}

# 获取端口组中的所有端口列表
get_group_ports() {
    local port_key=$1
    if is_port_group "$port_key"; then
        # 端口组：按逗号分隔返回
        echo "$port_key" | tr ',' ' '
    elif is_port_range "$port_key"; then
        # 端口段：展开所有端口（用于TC规则）
        local start_port=$(echo "$port_key" | cut -d'-' -f1)
        local end_port=$(echo "$port_key" | cut -d'-' -f2)
        seq $start_port $end_port | tr '\n' ' '
    else
        # 单端口
        echo "$port_key"
    fi
}

# 为端口组生成安全的命名（用于nftables计数器/配额名称）
# 将逗号替换为下划线，连字符也替换为下划线
generate_port_group_safe_name() {
    local port_key=$1
    echo "$port_key" | tr ',-' '__'
}

# 为端口组生成TC标记（用于共享带宽限制）
generate_port_group_mark() {
    local port_key=$1
    local safe_name=$(generate_port_group_safe_name "$port_key")
    # 使用字符串哈希生成唯一标记
    local hash=$(echo -n "$safe_name" | cksum | cut -d' ' -f1)
    echo $(( hash % 65000 + 1000 ))  # 范围 1000-66000，避免与端口号冲突
}

# 生成端口的人类可读显示名称
format_port_display_name() {
    local port=$1
    local remark=$(jq -r ".ports.\"$port\".remark // \"\"" "$CONFIG_FILE" 2>/dev/null)
    
    if is_port_group "$port"; then
        local display_str="$port"
        if [ ${#port} -gt 25 ]; then
            local count=$(echo "$port" | tr -cd ',' | wc -c)
            count=$((count + 1))
            display_str="${port:0:22}...(${count}个)"
        fi
        echo "端口组[${display_str}]"
    elif is_port_range "$port"; then
        echo "端口段[$port]"
    else
        echo "端口 $port"
    fi
}

generate_port_range_mark() {
    local port_range=$1
    local start_port=$(echo "$port_range" | cut -d'-' -f1)
    local end_port=$(echo "$port_range" | cut -d'-' -f2)
    # 确定性算法：避免不同端口段产生相同标记
    echo $(( (start_port * 1000 + end_port) % 65536 ))
}

# burst速率突发计算
calculate_tc_burst() {
    local base_rate=$1
    local rate_bytes_per_sec=$((base_rate * 1000 / 8))
    local burst_by_formula=$((rate_bytes_per_sec / 20))  # 50ms缓冲
    local min_burst=$((2 * 1500))                        # 2个MTU最小值

    if [ $burst_by_formula -gt $min_burst ]; then
        echo $burst_by_formula
    else
        echo $min_burst
    fi
}

format_tc_burst() {
    local burst_bytes=$1
    if [ $burst_bytes -lt 1024 ]; then
        echo "${burst_bytes}"
    elif [ $burst_bytes -lt 1048576 ]; then
        echo "$((burst_bytes / 1024))k"
    else
        echo "$((burst_bytes / 1048576))m"
    fi
}

parse_tc_rate_to_kbps() {
    local total_limit=$1
    if [[ "$total_limit" =~ gbit$ ]]; then
        local rate=$(echo "$total_limit" | sed 's/gbit$//')
        echo $((rate * 1000000))
    elif [[ "$total_limit" =~ mbit$ ]]; then
        local rate=$(echo "$total_limit" | sed 's/mbit$//')
        echo $((rate * 1000))
    else
        echo $(echo "$total_limit" | sed 's/kbit$//')
    fi
}

generate_tc_class_id() {
    local port=$1
    if is_port_group "$port"; then
        # 端口组使用0x3000+标记避免冲突
        local mark_id=$(generate_port_group_mark "$port")
        echo "1:$(printf '%x' $((0x3000 + (mark_id % 4096))))"
    elif is_port_range "$port"; then
        # 端口段使用0x2000+标记避免与单端口冲突
        local mark_id=$(generate_port_range_mark "$port")
        echo "1:$(printf '%x' $((0x2000 + mark_id)))"
    else
        # 单端口使用0x1000+端口号
        echo "1:$(printf '%x' $((0x1000 + port)))"
    fi
}

get_daily_total_traffic() {
    local total_bytes=0
    local ports=($(get_active_ports))
    for port in "${ports[@]}"; do
        local traffic_data=($(get_port_traffic "$port"))
        local input_bytes=${traffic_data[0]}
        local output_bytes=${traffic_data[1]}
        local billing_mode=$(jq -r ".ports.\"$port\".billing_mode // \"double\"" "$CONFIG_FILE")
        local port_total=$(calculate_total_traffic "$input_bytes" "$output_bytes" "$billing_mode")
        total_bytes=$(( total_bytes + port_total ))
    done
    format_bytes $total_bytes
}

format_port_list() {
    local format_type="$1"
    local active_ports=($(get_active_ports))
    local result=""

    for port in "${active_ports[@]}"; do
        local traffic_data=($(get_port_traffic "$port"))
        local input_bytes=${traffic_data[0]}
        local output_bytes=${traffic_data[1]}
        local billing_mode=$(jq -r ".ports.\"$port\".billing_mode // \"double\"" "$CONFIG_FILE")
        local total_bytes=$(calculate_total_traffic "$input_bytes" "$output_bytes" "$billing_mode")
        local total_formatted=$(format_bytes $total_bytes)
        local output_formatted=$(format_bytes $output_bytes)
        local status_label=$(get_port_status_label "$port")
        local remark=$(jq -r ".ports.\"$port\".remark // \"\"" "$CONFIG_FILE")
        
        # 获取运行状态
        local running_status=$(get_port_running_status "$port")
        local running_label=$(format_running_status "$running_status")

        # 根据计费模式决定上行/下行显示是否×2
        # - double/relay/single: ×2 显示（反映真实网卡消耗，因为 CN↔FX 那侧也有等量流量）
        # - premium: 不×2（内网中转场景，CN↔软银走内网不计费，只统计用户侧）
        local input_formatted
        local output_formatted
        if [ "$billing_mode" = "premium" ]; then
            input_formatted=$(format_bytes $input_bytes)
            output_formatted=$(format_bytes $output_bytes)
        else
            input_formatted=$(format_bytes $((input_bytes * 2)))
            output_formatted=$(format_bytes $((output_bytes * 2)))
        fi

        # 端口显示逻辑优化
        local port_display="$port"
        local prefix="端口"
        
        if is_port_group "$port"; then
            prefix="端口组"
            if [ ${#port} -gt 25 ]; then
                local count=$(echo "$port" | tr -cd ',' | wc -c)
                count=$((count + 1))
                port_display="${port:0:22}...(${count}个)"
            fi
        elif is_port_range "$port"; then
            prefix="端口段"
        fi

        if [ "$format_type" = "display" ]; then
            echo -e "${running_label} ${prefix}:${GREEN}$port_display${NC} | 总流量:${GREEN}$total_formatted${NC} | 上行: ${GREEN}$input_formatted${NC} | 下行:${GREEN}$output_formatted${NC} | ${YELLOW}$status_label${NC}"
        elif [ "$format_type" = "markdown" ]; then
            result+="$running_label ${prefix}:**${port_display}** | 总流量:**${total_formatted}** | 上行:**${input_formatted}** | 下行:**${output_formatted}** | ${status_label}
"
        else
            result+="
$running_label ${prefix}:${port_display} | 总流量:${total_formatted} | 上行: ${input_formatted} | 下行:${output_formatted} | ${status_label}"
        fi
    done

    if [ "$format_type" = "message" ] || [ "$format_type" = "markdown" ]; then
        echo "$result"
    fi
}

# 显示主界面
show_main_menu() {
    while true; do
        clear

        local active_ports=($(get_active_ports))
        local port_count=${#active_ports[@]}
        local daily_total=$(get_daily_total_traffic)

        echo -e "${BLUE}=== 端口流量狗 v$SCRIPT_VERSION ===${NC}"
        echo -e "${GREEN}作者主页:${NC}https://zywe.de"
        echo -e "${GREEN}项目开源:${NC}https://github.com/zywe03/realm-xwPF"
        echo -e "${GREEN}一只轻巧的'守护犬'，时刻守护你的端口流量 | 快捷命令: dog${NC}"
        echo

        echo -e "${GREEN}状态: 监控中${NC} | ${BLUE}守护端口: ${port_count}个${NC} | ${YELLOW}端口总流量: $daily_total${NC}"
        echo "────────────────────────────────────────────────────────"

        if [ $port_count -gt 0 ]; then
            format_port_list "display"
        else
            echo -e "${YELLOW}暂无监控端口${NC}"
        fi

        echo "────────────────────────────────────────────────────────"

        echo -e "${BLUE}1.${NC} 添加/删除端口监控     ${BLUE}2.${NC} 端口限制设置管理"
        echo -e "${BLUE}3.${NC} 流量重置管理          ${BLUE}4.${NC} 一键导出/导入配置"
        echo -e "${BLUE}5.${NC} 通知管理              ${BLUE}6.${NC} 流量备份管理"
        echo -e "${BLUE}7.${NC} 当前流量狗配置检测    ${BLUE}8.${NC} 卸载脚本"
        echo -e "${BLUE}9.${NC} Private Network 配置"
        echo -e "${BLUE}0.${NC} 退出"
        echo
        read -p "请选择操作 [0-9]: " choice

        case $choice in
            1) manage_port_monitoring ;;
            2) manage_traffic_limits ;;
            3) manage_traffic_reset ;;
            4) manage_configuration ;;
            5) manage_notifications ;;
            6) manage_backup ;;
            7) diagnose_port_config ;;
            8) uninstall_script ;;
            9) manage_private_network ;;
            0) exit 0 ;;
            *) echo -e "${RED}无效选择，请输入0-9${NC}"; sleep 1 ;;
        esac
    done
}

manage_port_monitoring() {
    while true; do
        echo -e "${BLUE}=== 端口监控管理 ===${NC}"
        echo "1. 添加端口监控"
        echo "2. 删除端口监控"
        echo "3. 合并端口为组"
        echo "4. 快速开通端口"
        echo "0. 返回主菜单"
        echo
        read -p "请选择操作 [0-4]: " choice

        case $choice in
            1) add_port_monitoring ;;
            2) remove_port_monitoring ;;
            3) merge_ports_to_group ;;
            4) quick_setup_port ;;
            0) return ;;
            *) echo -e "${RED}无效选择${NC}"; sleep 1 ;;
        esac
    done
}

# 快速开通端口 - 完整逻辑（复制自 add_port_monitoring + set_reset_day + manage_port_expiration + email_configure_port_recipients）
quick_setup_port() {
    echo -e "${BLUE}=== 快速开通端口 ===${NC}"
    echo "此功能将依次引导您完成: 添加端口 → 设置重置日期 → 设置租期 → 设置邮箱"
    echo
    
    # ==================== 第一步：添加端口监控（完整复制自 add_port_monitoring）====================
    echo -e "${BLUE}=== 添加端口监控 ===${NC}"
    echo

    echo -e "${GREEN}当前系统端口使用情况:${NC}"
    printf "%-15s %-9s\n" "程序名" "端口"
    echo "────────────────────────────────────────────────────────"

    # 解析ss输出，聚合同程序的端口
    declare -A program_ports
    while read line; do
        if [[ "$line" =~ LISTEN|UNCONN ]]; then
            local_addr=$(echo "$line" | awk '{print $5}')
            port=$(echo "$local_addr" | grep -o ':[0-9]*$' | cut -d':' -f2)
            program=$(echo "$line" | awk '{print $7}' | cut -d'"' -f2 2>/dev/null || echo "")

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
            ports="${program_ports[$program]}"
            printf "%-10s | %-9s\n" "$program" "$ports"
        done
    else
        echo "无活跃端口"
    fi

    echo "────────────────────────────────────────────────────────"
    echo

    read -p "请输入要监控的端口号（多端口使用逗号,分隔,端口段使用-分隔）: " port_input

    # 检查是否包含多个端口（非端口段的情况）
    local single_port_count=0
    IFS=',' read -ra PORT_PARTS <<< "$port_input"
    for part in "${PORT_PARTS[@]}"; do
        part=$(echo "$part" | tr -d ' ')
        if [[ "$part" =~ ^[0-9]+$ ]]; then
            single_port_count=$((single_port_count + 1))
        fi
    done

    local valid_ports=()
    
    # 判断处理模式
    if [ $single_port_count -gt 1 ]; then
        # 多个端口：直接创建端口组（共享统计）
        local group_key=""
        for part in "${PORT_PARTS[@]}"; do
            part=$(echo "$part" | tr -d ' ')
            if [[ "$part" =~ ^[0-9]+$ ]] && [ "$part" -ge 1 ] && [ "$part" -le 65535 ]; then
                if [ -n "$group_key" ]; then
                    group_key="${group_key},${part}"
                else
                    group_key="$part"
                fi
            elif [[ "$part" =~ ^[0-9]+-[0-9]+$ ]]; then
                # 端口段也支持加入组，展开后添加
                local start_port=$(echo "$part" | cut -d'-' -f1)
                local end_port=$(echo "$part" | cut -d'-' -f2)
                for p in $(seq $start_port $end_port); do
                    if [ -n "$group_key" ]; then
                        group_key="${group_key},${p}"
                    else
                        group_key="$p"
                    fi
                done
            fi
        done
        
        if [ -n "$group_key" ]; then
            if jq -e ".ports.\"$group_key\"" "$CONFIG_FILE" >/dev/null 2>&1; then
                echo -e "${YELLOW}端口组 $group_key 已在监控列表中${NC}"
            else
                valid_ports+=("$group_key")
                echo -e "${GREEN}创建端口组: $group_key (所有端口共享统计)${NC}"
            fi
        fi
    else
        # 单个端口或端口段：使用原有逻辑（独立统计）
        local PORTS=()
        parse_port_range_input "$port_input" PORTS
        
        for port in "${PORTS[@]}"; do
            if jq -e ".ports.\"$port\"" "$CONFIG_FILE" >/dev/null 2>&1; then
                echo -e "${YELLOW}端口 $port 已在监控列表中，跳过${NC}"
                continue
            fi
            valid_ports+=("$port")
        done
    fi

    if [ ${#valid_ports[@]} -eq 0 ]; then
        echo -e "${RED}没有有效的端口可添加${NC}"
        sleep 2
        return
    fi

    echo
    echo -e "${GREEN}说明:${NC}"
    echo "1. 双向流量统计（推荐）："
    echo "   总流量 = (入站 + 出站) × 2"
    echo
    echo "2. 仅出站统计："
    echo "   总流量 = 出站 × 2"
    echo
    echo "3. CN Premium 内网中转："
    echo "   总流量 = (入站 + 出站) × 1"
    echo "   适用：CN 内网转发到软银的场景"
    echo
    echo "请选择统计模式:"
    echo "1. 双向流量统计（推荐）"
    echo "2. 仅出站统计"
    echo "3. CN Premium 内网中转"
    read -p "请选择(回车默认1) [1-3]: " billing_choice

    local billing_mode="double"
    case $billing_choice in
        1|"") billing_mode="double" ;;
        2) billing_mode="single" ;;
        3) billing_mode="premium" ;;
        *) billing_mode="double" ;;
    esac

    echo
    local port_list=$(IFS=','; echo "${valid_ports[*]}")
    while true; do
        echo "为端口 $port_list 设置流量配额（总量控制）:"
        echo "请输入配额值（0为无限制）（要带单位MB/GB/T）:"
        echo "(多端口分别配额使用逗号,分隔)(只输入一个值，应用到所有端口):"
        read -p "流量配额(回车默认0): " quota_input

        if [ -z "$quota_input" ]; then
            quota_input="0"
        fi

        local QUOTAS=()
        parse_comma_separated_input "$quota_input" QUOTAS

        local all_valid=true
        for quota in "${QUOTAS[@]}"; do
            if [ "$quota" != "0" ] && ! validate_quota "$quota"; then
                echo -e "${RED}配额格式错误: $quota，请使用如：100MB, 1GB, 2T${NC}"
                all_valid=false
                break
            fi
        done

        if [ "$all_valid" = false ]; then
            echo "请重新输入配额值"
            continue
        fi

        expand_single_value_to_array QUOTAS ${#valid_ports[@]}
        if [ ${#QUOTAS[@]} -ne ${#valid_ports[@]} ]; then
            echo -e "${RED}配额值数量与端口数量不匹配${NC}"
            continue
        fi

        break
    done

    echo
    echo -e "${BLUE}=== 规则备注配置 ===${NC}"
    echo "请输入当前规则备注(可选，直接回车跳过):"
    echo "(多端口排序分别备注使用逗号,分隔)(只输入一个值，应用到所有端口):"
    read -p "备注: " remark_input

    local REMARKS=()
    if [ -n "$remark_input" ]; then
        parse_comma_separated_input "$remark_input" REMARKS

        expand_single_value_to_array REMARKS ${#valid_ports[@]}
        if [ ${#REMARKS[@]} -ne ${#valid_ports[@]} ]; then
            echo -e "${RED}备注数量与端口数量不匹配${NC}"
            sleep 2
            return
        fi
    fi

    local added_count=0
    local added_ports=()
    for i in "${!valid_ports[@]}"; do
        local port="${valid_ports[$i]}"
        local quota=$(echo "${QUOTAS[$i]}" | tr -d ' ')
        local remark=""
        if [ ${#REMARKS[@]} -gt $i ]; then
            remark=$(echo "${REMARKS[$i]}" | tr -d ' ')
        fi

        local quota_enabled="true"
        local monthly_limit="unlimited"

        if [ "$quota" != "0" ] && [ -n "$quota" ]; then
            monthly_limit="$quota"
        fi

        # 只有设置了流量限额时才添加reset_day字段（默认为1）
        local quota_config
        if [ "$monthly_limit" != "unlimited" ]; then
            quota_config="{
                \"enabled\": $quota_enabled,
                \"monthly_limit\": \"$monthly_limit\",
                \"reset_day\": 1
            }"
        else
            quota_config="{
                \"enabled\": $quota_enabled,
                \"monthly_limit\": \"$monthly_limit\"
            }"
        fi

        local port_config="{
            \"name\": \"端口$port\",
            \"enabled\": true,
            \"billing_mode\": \"$billing_mode\",
            \"bandwidth_limit\": {
                \"enabled\": false,
                \"rate\": \"unlimited\"
            },
            \"quota\": $quota_config,
            \"remark\": \"$remark\",
            \"created_at\": \"$(get_beijing_time -Iseconds)\"
        }"

        update_config ".ports.\"$port\" = $port_config"
        add_nftables_rules "$port"

        if [ "$monthly_limit" != "unlimited" ]; then
            apply_nftables_quota "$port" "$quota"
        fi

        echo -e "${GREEN}端口 $port 监控添加成功${NC}"
        setup_port_auto_reset_cron "$port"
        added_count=$((added_count + 1))
        added_ports+=("$port")
    done

    echo
    echo -e "${GREEN}成功添加 $added_count 个端口监控${NC}"
    
    # ==================== 第二步：设置重置日期（简化：直接用刚添加的端口）====================
    echo
    echo -e "${CYAN}>>> 按回车进入【月重置日设置】...${NC}"
    read
    
    echo -e "${BLUE}=== 设置月重置日 ===${NC}"
    local port_list_display=$(IFS=','; echo "${added_ports[*]}")
    echo "为端口 $port_list_display 设置月重置日期:"
    echo "(0代表不重置，1-31 为每月重置日)"
    read -p "月重置日 [0-31]: " reset_day_input
    
    if [ -n "$reset_day_input" ]; then
        local RESET_DAYS=()
        parse_comma_separated_input "$reset_day_input" RESET_DAYS
        expand_single_value_to_array RESET_DAYS ${#added_ports[@]}
        
        for i in "${!added_ports[@]}"; do
            local port="${added_ports[$i]}"
            local reset_day=$(echo "${RESET_DAYS[$i]}" | tr -d ' ')
            
            if ! [[ "$reset_day" =~ ^[0-9]+$ ]] || [ "$reset_day" -lt 0 ] || [ "$reset_day" -gt 31 ]; then
                echo -e "${RED}端口 $port 重置日期无效: $reset_day${NC}"
                continue
            fi
            
            if [ "$reset_day" = "0" ]; then
                jq "del(.ports.\"$port\".quota.reset_day)" "$CONFIG_FILE" > "${CONFIG_FILE}.tmp" && mv "${CONFIG_FILE}.tmp" "$CONFIG_FILE"
                remove_port_auto_reset_cron "$port"
                echo -e "${GREEN}端口 $port 已取消自动重置${NC}"
            else
                update_config ".ports.\"$port\".quota.reset_day = $reset_day"
                setup_port_auto_reset_cron "$port"
                echo -e "${GREEN}端口 $port 月重置日设置成功: 每月${reset_day}日${NC}"
            fi
        done
    else
        echo -e "${YELLOW}跳过重置日期设置${NC}"
    fi
    
    # ==================== 第三步：设置租期（简化：直接用刚添加的端口）====================
    echo
    echo -e "${CYAN}>>> 按回车进入【租期设置】...${NC}"
    read
    
    # 确保后台检查任务已部署
    setup_daily_check_cron
    
    # 遍历每个刚添加的端口设置租期
    for port in "${added_ports[@]}"; do
        echo -e "${BLUE}=== 续费/设置租期: $port ===${NC}"
        
        # 获取当前信息
        local expire_date=$(jq -r ".ports.\"$port\".expiration_date // \"\"" "$CONFIG_FILE")
        local reset_day=$(jq -r ".ports.\"$port\".quota.reset_day // \"\"" "$CONFIG_FILE")
        
        if [ -z "$expire_date" ] || [ "$expire_date" = "null" ]; then
            expire_date="未设置 (永久)"
        fi
        if [ -z "$reset_day" ] || [ "$reset_day" = "null" ]; then
            reset_day=$(get_beijing_time +%-d)
        fi
        
        echo -e "当前到期日: ${GREEN}$expire_date${NC}"
        echo -e "重置日基准: 每月 ${GREEN}${reset_day}${NC} 日"
        echo "------------------------"
        echo "1. 增加 1 个月"
        echo "2. 增加 3 个月 (季付)"
        echo "3. 增加 6 个月 (半年)"
        echo "4. 增加 1 年"
        echo "5. 手动输入到期日期"
        echo "6. 清除租期 (设置为永久)"
        echo "0. 跳过"
        echo
        
        read -p "请选择续费时长 [0-6]: " duration_choice
        
        local new_date=""
        local base_date=""
        local months_to_add=0
        
        # 确定基准日期逻辑
        local current_expire=$(jq -r ".ports.\"$port\".expiration_date // \"\"" "$CONFIG_FILE")
        local today=$(get_beijing_time +%Y-%m-%d)
        local is_renewal=false
        
        if [ -n "$current_expire" ] && [ "$current_expire" != "null" ] && [[ "$current_expire" > "$today" ]]; then
            base_date="$current_expire"
            is_renewal=true
            echo -e "将在现有到期日 ($base_date) 基础上续费"
        else
            base_date="$today"
            is_renewal=false
            echo -e "端口已过期或首次设置，从今天 ($today) 开始计算租期"
        fi

        case $duration_choice in
            1) months_to_add=1 ;;
            2) months_to_add=3 ;;
            3) months_to_add=6 ;;
            4) months_to_add=12 ;;
            5) 
                read -p "请输入到期日期 (格式 YYYY-MM-DD): " manual_date
                if date -d "$manual_date" >/dev/null 2>&1; then
                    new_date="$manual_date"
                else
                    echo -e "${RED}日期格式错误${NC}"
                fi
                ;;
            6)
                update_config "del(.ports.\"$port\".expiration_date)"
                echo -e "${GREEN}已清除租期，端口恢复永久有效。${NC}"
                ;;
            0) echo -e "${YELLOW}跳过租期设置${NC}" ;;
            *) echo -e "${RED}无效选择${NC}" ;;
        esac
        
        # 如果不是手动输入，则计算日期
        if [ -z "$new_date" ] && [ "$duration_choice" -ge 1 ] 2>/dev/null && [ "$duration_choice" -le 4 ] 2>/dev/null; then
            if [ "$is_renewal" = "false" ]; then
                months_to_add=$(adjust_initial_expiration_months "$base_date" "$months_to_add" "$reset_day")
            fi
            new_date=$(calculate_next_expiration "$base_date" "$months_to_add" "$reset_day")
        fi
        
        if [ -n "$new_date" ]; then
            update_config ".ports.\"$port\".expiration_date = \"$new_date\""
            echo -e "${GREEN}续费成功！新到期日: $new_date${NC}"
        fi
        echo
    done
    
    # ==================== 第四步：设置用户邮箱（保持现状：可选）====================
    echo
    echo -e "${CYAN}>>> 按回车进入【邮箱设置】...${NC}"
    read
    
    read -p "是否设置用户邮箱？[y/n] (默认n，可后续补充): " choice
    if [[ "$choice" == "y" || "$choice" == "Y" ]]; then
        echo -e "${BLUE}=== 配置端口独立收件人 ===${NC}"
        echo
        
        local active_ports=($(get_active_ports))
        if [ ${#active_ports[@]} -eq 0 ]; then
             echo "暂无监控端口"
             sleep 2
        else
            echo "端口列表:"
            for i in "${!active_ports[@]}"; do
                local port=${active_ports[$i]}
                local remark=$(jq -r ".ports.\"$port\".remark // \"\"" "$CONFIG_FILE")
                local email=$(jq -r ".ports.\"$port\".email // \"未设置\"" "$CONFIG_FILE")
                
                # 显示名称处理
                local display_name=""
                if is_port_group "$port"; then
                    local display_str="$port"
                    if [ ${#port} -gt 20 ]; then
                        local count=$(echo "$port" | tr -cd ',' | wc -c)
                        count=$((count + 1))
                        display_str="${port:0:17}...(${count}个)"
                    fi
                    display_name="端口组[${display_str}]"
                elif is_port_range "$port"; then
                    display_name="端口段[$port]"
                else
                    display_name="端口 $port"
                fi
                
                if [ -n "$remark" ] && [ "$remark" != "null" ]; then
                    display_name+=" [$remark]"
                fi
                
                local email_display="${RED}未设置${NC}"
                if [ "$email" != "未设置" ] && [ "$email" != "null" ] && [ "$email" != "" ]; then
                    email_display="${GREEN}$email${NC}"
                fi
                
                echo -e "$((i+1)). $display_name -> $email_display"
            done
            echo
            echo "0. 跳过邮箱设置"
            echo
            
            read -p "请选择要配置的端口 [1-${#active_ports[@]}, 0跳过]: " choice
            
            if [ "$choice" != "0" ]; then
                if [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -ge 1 ] && [ "$choice" -le ${#active_ports[@]} ]; then
                    local port=${active_ports[$((choice-1))]}
                    
                    echo
                    local current_email=$(jq -r ".ports.\"$port\".email // \"\"" "$CONFIG_FILE")
                    if [ "$current_email" = "null" ]; then current_email=""; fi
                    
                    echo "正在配置端口: $port"
                    echo "当前邮箱: ${current_email:-未设置}"
                    echo "输入 'd' 或 'delete' 可删除邮箱配置"
                    read -p "请输入接收邮箱: " new_email
                    
                    if [ "$new_email" = "d" ] || [ "$new_email" = "delete" ]; then
                        update_config "del(.ports.\"$port\".email)"
                        echo -e "${YELLOW}已删除端口 $port 的邮箱配置${NC}"
                    elif [[ "$new_email" =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$ ]]; then
                        update_config ".ports.\"$port\".email = \"$new_email\""
                        echo -e "${GREEN}端口 $port 邮箱已设置为: $new_email${NC}"
                    else
                        echo -e "${RED}邮箱格式错误，未保存${NC}"
                    fi
                    sleep 1
                else
                    echo -e "${RED}无效选择${NC}"
                    sleep 1
                fi
            fi
        fi
    fi
    
    # ==================== 完成 ====================
    echo
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}       快速开通流程完成！${NC}"
    echo -e "${GREEN}========================================${NC}"
    sleep 2
}

add_port_monitoring() {
    echo -e "${BLUE}=== 添加端口监控 ===${NC}"
    echo

    echo -e "${GREEN}当前系统端口使用情况:${NC}"
    printf "%-15s %-9s\n" "程序名" "端口"
    echo "────────────────────────────────────────────────────────"

    # 解析ss输出，聚合同程序的端口
    declare -A program_ports
    while read line; do
        if [[ "$line" =~ LISTEN|UNCONN ]]; then
            local_addr=$(echo "$line" | awk '{print $5}')
            port=$(echo "$local_addr" | grep -o ':[0-9]*$' | cut -d':' -f2)
            program=$(echo "$line" | awk '{print $7}' | cut -d'"' -f2 2>/dev/null || echo "")

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
            ports="${program_ports[$program]}"
            printf "%-10s | %-9s\n" "$program" "$ports"
        done
    else
        echo "无活跃端口"
    fi

    echo "────────────────────────────────────────────────────────"
    echo

    read -p "请输入要监控的端口号（多端口使用逗号,分隔,端口段使用-分隔）: " port_input

    # 检查是否包含多个端口（非端口段的情况）
    local single_port_count=0
    IFS=',' read -ra PORT_PARTS <<< "$port_input"
    for part in "${PORT_PARTS[@]}"; do
        part=$(echo "$part" | tr -d ' ')
        if [[ "$part" =~ ^[0-9]+$ ]]; then
            single_port_count=$((single_port_count + 1))
        fi
    done

    local valid_ports=()
    
    # 判断处理模式
    if [ $single_port_count -gt 1 ]; then
        # 多个端口：直接创建端口组（共享统计）
        local group_key=""
        for part in "${PORT_PARTS[@]}"; do
            part=$(echo "$part" | tr -d ' ')
            if [[ "$part" =~ ^[0-9]+$ ]] && [ "$part" -ge 1 ] && [ "$part" -le 65535 ]; then
                if [ -n "$group_key" ]; then
                    group_key="${group_key},${part}"
                else
                    group_key="$part"
                fi
            elif [[ "$part" =~ ^[0-9]+-[0-9]+$ ]]; then
                # 端口段也支持加入组，展开后添加
                local start_port=$(echo "$part" | cut -d'-' -f1)
                local end_port=$(echo "$part" | cut -d'-' -f2)
                for p in $(seq $start_port $end_port); do
                    if [ -n "$group_key" ]; then
                        group_key="${group_key},${p}"
                    else
                        group_key="$p"
                    fi
                done
            fi
        done
        
        if [ -n "$group_key" ]; then
            if jq -e ".ports.\"$group_key\"" "$CONFIG_FILE" >/dev/null 2>&1; then
                echo -e "${YELLOW}端口组 $group_key 已在监控列表中${NC}"
            else
                valid_ports+=("$group_key")
                echo -e "${GREEN}创建端口组: $group_key (所有端口共享统计)${NC}"
            fi
        fi
    else
        # 单个端口或端口段：使用原有逻辑（独立统计）
        local PORTS=()
        parse_port_range_input "$port_input" PORTS
        
        for port in "${PORTS[@]}"; do
            if jq -e ".ports.\"$port\"" "$CONFIG_FILE" >/dev/null 2>&1; then
                echo -e "${YELLOW}端口 $port 已在监控列表中，跳过${NC}"
                continue
            fi
            valid_ports+=("$port")
        done
    fi

    if [ ${#valid_ports[@]} -eq 0 ]; then
        echo -e "${RED}没有有效的端口可添加${NC}"
        sleep 2
        manage_port_monitoring
        return
    fi

    echo
    echo -e "${GREEN}说明:${NC}"
    echo "1. 双向流量统计（推荐）："
    echo "   总流量 = (入站 + 出站) × 2"
    echo
    echo "2. 仅出站统计："
    echo "   总流量 = 出站 × 2"
    echo
    echo "3. CN Premium 内网中转："
    echo "   总流量 = (入站 + 出站) × 1"
    echo "   适用：CN 内网转发到软银的场景"
    echo
    echo "请选择统计模式:"
    echo "1. 双向流量统计（推荐）"
    echo "2. 仅出站统计"
    echo "3. CN Premium 内网中转"
    read -p "请选择(回车默认1) [1-3]: " billing_choice

    local billing_mode="double"
    case $billing_choice in
        1|"") billing_mode="double" ;;
        2) billing_mode="single" ;;
        3) billing_mode="premium" ;;
        *) billing_mode="double" ;;
    esac

    echo
    local port_list=$(IFS=','; echo "${valid_ports[*]}")
    while true; do
        echo "为端口 $port_list 设置流量配额（总量控制）:"
        echo "请输入配额值（0为无限制）（要带单位MB/GB/T）:"
        echo "(多端口分别配额使用逗号,分隔)(只输入一个值，应用到所有端口):"
        read -p "流量配额(回车默认0): " quota_input

        if [ -z "$quota_input" ]; then
            quota_input="0"
        fi

        local QUOTAS=()
        parse_comma_separated_input "$quota_input" QUOTAS

        local all_valid=true
        for quota in "${QUOTAS[@]}"; do
            if [ "$quota" != "0" ] && ! validate_quota "$quota"; then
                echo -e "${RED}配额格式错误: $quota，请使用如：100MB, 1GB, 2T${NC}"
                all_valid=false
                break
            fi
        done

        if [ "$all_valid" = false ]; then
            echo "请重新输入配额值"
            continue
        fi

        expand_single_value_to_array QUOTAS ${#valid_ports[@]}
        if [ ${#QUOTAS[@]} -ne ${#valid_ports[@]} ]; then
            echo -e "${RED}配额值数量与端口数量不匹配${NC}"
            continue
        fi

        break
    done

    echo
    echo -e "${BLUE}=== 规则备注配置 ===${NC}"
    echo "请输入当前规则备注(可选，直接回车跳过):"
    echo "(多端口排序分别备注使用逗号,分隔)(只输入一个值，应用到所有端口):"
    read -p "备注: " remark_input

    local REMARKS=()
    if [ -n "$remark_input" ]; then
        parse_comma_separated_input "$remark_input" REMARKS

        expand_single_value_to_array REMARKS ${#valid_ports[@]}
        if [ ${#REMARKS[@]} -ne ${#valid_ports[@]} ]; then
            echo -e "${RED}备注数量与端口数量不匹配${NC}"
            sleep 2
            add_port_monitoring
            return
        fi
    fi

    local added_count=0
    for i in "${!valid_ports[@]}"; do
        local port="${valid_ports[$i]}"
        local quota=$(echo "${QUOTAS[$i]}" | tr -d ' ')
        local remark=""
        if [ ${#REMARKS[@]} -gt $i ]; then
            remark=$(echo "${REMARKS[$i]}" | tr -d ' ')
        fi

        local quota_enabled="true"
        local monthly_limit="unlimited"

        if [ "$quota" != "0" ] && [ -n "$quota" ]; then
            monthly_limit="$quota"
        fi

        # 只有设置了流量限额时才添加reset_day字段（默认为1）
        local quota_config
        if [ "$monthly_limit" != "unlimited" ]; then
            quota_config="{
                \"enabled\": $quota_enabled,
                \"monthly_limit\": \"$monthly_limit\",
                \"reset_day\": 1
            }"
        else
            quota_config="{
                \"enabled\": $quota_enabled,
                \"monthly_limit\": \"$monthly_limit\"
            }"
        fi

        local port_config="{
            \"name\": \"端口$port\",
            \"enabled\": true,
            \"billing_mode\": \"$billing_mode\",
            \"bandwidth_limit\": {
                \"enabled\": false,
                \"rate\": \"unlimited\"
            },
            \"quota\": $quota_config,
            \"remark\": \"$remark\",
            \"created_at\": \"$(get_beijing_time -Iseconds)\"
        }"

        update_config ".ports.\"$port\" = $port_config"
        add_nftables_rules "$port"

        if [ "$monthly_limit" != "unlimited" ]; then
            apply_nftables_quota "$port" "$quota"
        fi

        echo -e "${GREEN}端口 $port 监控添加成功${NC}"
        setup_port_auto_reset_cron "$port"
        added_count=$((added_count + 1))
    done

    echo
    echo -e "${GREEN}成功添加 $added_count 个端口监控${NC}"

    sleep 2
    manage_port_monitoring
}

remove_port_monitoring() {
    echo -e "${BLUE}=== 删除端口监控 ===${NC}"
    echo

    local active_ports=($(get_active_ports))

    if ! show_port_list; then
        sleep 2
        manage_port_monitoring
        return
    fi
    echo

    read -p "请选择要删除的端口（多端口使用逗号,分隔）: " choice_input

    local valid_choices=()
    local ports_to_delete=()
    parse_multi_choice_input "$choice_input" "${#active_ports[@]}" valid_choices

    for choice in "${valid_choices[@]}"; do
        local port=${active_ports[$((choice-1))]}
        ports_to_delete+=("$port")
    done

    if [ ${#ports_to_delete[@]} -eq 0 ]; then
        echo -e "${RED}没有有效的端口可删除${NC}"
        sleep 2
        remove_port_monitoring
        return
    fi

    echo
    echo "将删除以下端口的监控:"
    for port in "${ports_to_delete[@]}"; do
        echo "  端口 $port"
    done
    echo

    read -p "确认删除这些端口的监控? [y/N]: " confirm
    if [[ "$confirm" =~ ^[Yy]$ ]]; then
        local deleted_count=0
        for port in "${ports_to_delete[@]}"; do
            remove_nftables_rules "$port"
            remove_nftables_quota "$port"
            remove_tc_limit "$port"
            update_config "del(.ports.\"$port\")"

            # 清理历史记录
            local history_file="$CONFIG_DIR/reset_history.log"
            if [ -f "$history_file" ]; then
                grep -v "|$port|" "$history_file" > "${history_file}.tmp" 2>/dev/null || true
                mv "${history_file}.tmp" "$history_file" 2>/dev/null || true
            fi

            local notification_log="$CONFIG_DIR/logs/notification.log"
            if [ -f "$notification_log" ]; then
                grep -v "端口 $port " "$notification_log" > "${notification_log}.tmp" 2>/dev/null || true
                mv "${notification_log}.tmp" "$notification_log" 2>/dev/null || true
            fi

            remove_port_auto_reset_cron "$port"

            echo -e "${GREEN}端口 $port 监控及相关数据删除成功${NC}"
            deleted_count=$((deleted_count + 1))
        done

        echo
        echo -e "${GREEN}成功删除 $deleted_count 个端口监控${NC}"

        # 清理连接跟踪：确保现有连接不受限制
        echo "正在清理网络状态..."
        for port in "${ports_to_delete[@]}"; do
            if is_port_group "$port"; then
                # 端口组：清理组内每个端口
                echo "清理端口组 $port 连接状态..."
                local group_ports=($(get_group_ports "$port"))
                for p in "${group_ports[@]}"; do
                    conntrack -D -p tcp --dport $p 2>/dev/null || true
                    conntrack -D -p udp --dport $p 2>/dev/null || true
                done
            elif is_port_range "$port"; then
                local start_port=$(echo "$port" | cut -d'-' -f1)
                local end_port=$(echo "$port" | cut -d'-' -f2)
                echo "清理端口段 $port 连接状态..."
                for ((p=start_port; p<=end_port; p++)); do
                    conntrack -D -p tcp --dport $p 2>/dev/null || true
                    conntrack -D -p udp --dport $p 2>/dev/null || true
                done
            else
                echo "清理端口 $port 连接状态..."
                conntrack -D -p tcp --dport $port 2>/dev/null || true
                conntrack -D -p udp --dport $port 2>/dev/null || true
            fi
        done

        echo -e "${GREEN}网络状态已清理，现有连接的限制应该已解除${NC}"
        echo -e "${YELLOW}提示：新建连接将不受任何限制${NC}"

        local remaining_ports=($(get_active_ports))
        if [ ${#remaining_ports[@]} -eq 0 ]; then
            echo -e "${YELLOW}所有端口已删除，自动重置功能已停用${NC}"
        fi
    else
        echo "取消删除"
    fi

    sleep 2
    manage_port_monitoring
}

# 合并多个单端口为端口组
merge_ports_to_group() {
    echo -e "${BLUE}=== 合并端口为组 ===${NC}"
    echo
    echo "此功能可将多个单独的端口合并为一个端口组，实现流量共享统计。"
    echo

    local active_ports=($(get_active_ports))
    
    # 过滤出可合并的单端口（排除已有的端口组和端口段）
    local single_ports=()
    for port in "${active_ports[@]}"; do
        if ! is_port_group "$port" && ! is_port_range "$port"; then
            single_ports+=("$port")
        fi
    done

    if [ ${#single_ports[@]} -lt 2 ]; then
        echo -e "${YELLOW}需要至少2个单独端口才能合并为组${NC}"
        echo "当前可合并的单端口数量: ${#single_ports[@]}"
        sleep 2
        manage_port_monitoring
        return
    fi

    echo "可合并的单端口:"
    for i in "${!single_ports[@]}"; do
        local port=${single_ports[$i]}
        local remark=$(jq -r ".ports.\"$port\".remark // \"\"" "$CONFIG_FILE")
        local traffic_data=($(get_port_traffic "$port"))
        local input_bytes=${traffic_data[0]}
        local output_bytes=${traffic_data[1]}
        local billing_mode=$(jq -r ".ports.\"$port\".billing_mode // \"double\"" "$CONFIG_FILE")
        local total_bytes=$(calculate_total_traffic "$input_bytes" "$output_bytes" "$billing_mode")
        local total_formatted=$(format_bytes $total_bytes)
        
        if [ -n "$remark" ] && [ "$remark" != "null" ]; then
            echo "$((i+1)). 端口 $port [$remark] - 流量: $total_formatted"
        else
            echo "$((i+1)). 端口 $port - 流量: $total_formatted"
        fi
    done
    echo
    
    read -p "请选择要合并的端口（用逗号分隔，如1,2,3）: " choice_input

    local valid_choices=()
    local ports_to_merge=()
    parse_multi_choice_input "$choice_input" "${#single_ports[@]}" valid_choices

    for choice in "${valid_choices[@]}"; do
        local port=${single_ports[$((choice-1))]}
        ports_to_merge+=("$port")
    done

    if [ ${#ports_to_merge[@]} -lt 2 ]; then
        echo -e "${RED}至少需要选择2个端口才能合并${NC}"
        sleep 2
        merge_ports_to_group
        return
    fi

    # 检查所有端口的计费模式是否一致
    local first_billing_mode=$(jq -r ".ports.\"${ports_to_merge[0]}\".billing_mode // \"double\"" "$CONFIG_FILE")
    local billing_mode_mismatch=false
    local mismatched_info=""
    for port in "${ports_to_merge[@]}"; do
        local port_billing_mode=$(jq -r ".ports.\"$port\".billing_mode // \"double\"" "$CONFIG_FILE")
        if [ "$port_billing_mode" != "$first_billing_mode" ]; then
            billing_mode_mismatch=true
            mismatched_info="$mismatched_info $port:$port_billing_mode"
        fi
    done
    
    if [ "$billing_mode_mismatch" = true ]; then
        echo
        echo -e "${RED}❌ 无法合并：端口计费模式不同${NC}"
        echo "第一个端口 ${ports_to_merge[0]} 的计费模式: $first_billing_mode"
        echo "计费模式不匹配的端口:$mismatched_info"
        echo
        echo "请确保所有端口使用相同的计费模式后再合并"
        read -p "按回车返回..." _
        manage_port_monitoring
        return
    fi

    # 生成新的端口组key
    local group_key=$(IFS=','; echo "${ports_to_merge[*]}")
    
    echo
    echo "将合并以下端口为组: $group_key"
    
    # 计算合并后的总流量
    local total_input=0
    local total_output=0
    for port in "${ports_to_merge[@]}"; do
        local traffic_data=($(get_port_traffic "$port"))
        total_input=$((total_input + ${traffic_data[0]}))
        total_output=$((total_output + ${traffic_data[1]}))
    done
    
    # 获取第一个端口的配置作为模板
    local first_port=${ports_to_merge[0]}
    local billing_mode=$(jq -r ".ports.\"$first_port\".billing_mode // \"double\"" "$CONFIG_FILE")
    local quota_config=$(jq -r ".ports.\"$first_port\".quota" "$CONFIG_FILE")
    local bandwidth_config=$(jq -r ".ports.\"$first_port\".bandwidth_limit" "$CONFIG_FILE")
    local remark=$(jq -r ".ports.\"$first_port\".remark // \"\"" "$CONFIG_FILE")
    
    local total_traffic=$(calculate_total_traffic "$total_input" "$total_output" "$billing_mode")
    echo "合并后总流量: $(format_bytes $total_traffic)"
    echo "将继承端口 $first_port 的配置（配额、带宽限制、计费模式）"
    echo
    
    read -p "确认合并? [y/N]: " confirm
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        echo "取消合并"
        sleep 2
        manage_port_monitoring
        return
    fi

    echo "正在合并端口..."
    
    # 1. 删除原有端口的规则
    for port in "${ports_to_merge[@]}"; do
        remove_nftables_rules "$port" >/dev/null 2>&1
        remove_nftables_quota "$port" >/dev/null 2>&1
        remove_tc_limit "$port" >/dev/null 2>&1
        remove_port_auto_reset_cron "$port" >/dev/null 2>&1
        update_config "del(.ports.\"$port\")"
    done

    # 2. 创建新的端口组配置
    local port_config="{
        \"name\": \"端口组${group_key}\",
        \"enabled\": true,
        \"billing_mode\": \"$billing_mode\",
        \"bandwidth_limit\": $bandwidth_config,
        \"quota\": $quota_config,
        \"remark\": \"$remark\",
        \"created_at\": \"$(get_beijing_time -Iseconds)\"
    }"
    
    jq ".ports.\"$group_key\" = $port_config" "$CONFIG_FILE" > "${CONFIG_FILE}.tmp" && mv "${CONFIG_FILE}.tmp" "$CONFIG_FILE"
    
    # 3. 先恢复流量计数器值（创建带初始值的计数器）
    restore_counter_value "$group_key" "$total_input" "$total_output"
    
    # 4. 添加新的端口组规则（计数器已存在不会重新创建）
    add_nftables_rules "$group_key"
    
    # 5. 应用配额限制
    local monthly_limit=$(echo "$quota_config" | jq -r '.monthly_limit // "unlimited"')
    if [ "$monthly_limit" != "unlimited" ]; then
        apply_nftables_quota "$group_key" "$monthly_limit"
    fi
    
    # 6. 应用带宽限制
    local rate_limit=$(echo "$bandwidth_config" | jq -r '.rate // "unlimited"')
    local limit_enabled=$(echo "$bandwidth_config" | jq -r '.enabled // false')
    if [ "$limit_enabled" = "true" ] && [ "$rate_limit" != "unlimited" ]; then
        local limit_lower=$(echo "$rate_limit" | tr '[:upper:]' '[:lower:]')
        local tc_limit
        if [[ "$limit_lower" =~ kbps$ ]]; then
            tc_limit=$(echo "$limit_lower" | sed 's/kbps$/kbit/')
        elif [[ "$limit_lower" =~ mbps$ ]]; then
            tc_limit=$(echo "$limit_lower" | sed 's/mbps$/mbit/')
        elif [[ "$limit_lower" =~ gbps$ ]]; then
            tc_limit=$(echo "$limit_lower" | sed 's/gbps$/gbit/')
        fi
        if [ -n "$tc_limit" ]; then
            apply_tc_limit "$group_key" "$tc_limit"
        fi
    fi
    
    # 7. 设置自动重置任务
    setup_port_auto_reset_cron "$group_key"

    echo
    echo -e "${GREEN}端口合并成功！${NC}"
    echo "新端口组: $group_key"
    echo "合并流量: $(format_bytes $total_traffic)"
    
    sleep 3
    manage_port_monitoring
}

add_nftables_rules() {
    local port=$1
    local table_name=$(jq -r '.nftables.table_name' "$CONFIG_FILE")
    local family=$(jq -r '.nftables.family' "$CONFIG_FILE")

    if is_port_group "$port"; then
        # 端口组：多个端口共享同一个计数器
        local port_safe=$(generate_port_group_safe_name "$port")
        local mark_id=$(generate_port_group_mark "$port")

        # 创建共享计数器
        nft list counter $family $table_name "port_${port_safe}_in" >/dev/null 2>&1 || \
            nft add counter $family $table_name "port_${port_safe}_in" 2>/dev/null || true
        nft list counter $family $table_name "port_${port_safe}_out" >/dev/null 2>&1 || \
            nft add counter $family $table_name "port_${port_safe}_out" 2>/dev/null || true

        # 为组内每个端口添加规则，指向同一个计数器
        local group_ports=($(get_group_ports "$port"))
        for single_port in "${group_ports[@]}"; do
            # 入站规则
            nft add rule $family $table_name input tcp dport $single_port meta mark set $mark_id counter name "port_${port_safe}_in"
            nft add rule $family $table_name input udp dport $single_port meta mark set $mark_id counter name "port_${port_safe}_in"
            nft add rule $family $table_name forward tcp dport $single_port meta mark set $mark_id counter name "port_${port_safe}_in"
            nft add rule $family $table_name forward udp dport $single_port meta mark set $mark_id counter name "port_${port_safe}_in"

            # 出站规则
            nft add rule $family $table_name output tcp sport $single_port meta mark set $mark_id counter name "port_${port_safe}_out"
            nft add rule $family $table_name output udp sport $single_port meta mark set $mark_id counter name "port_${port_safe}_out"
            nft add rule $family $table_name forward tcp sport $single_port meta mark set $mark_id counter name "port_${port_safe}_out"
            nft add rule $family $table_name forward udp sport $single_port meta mark set $mark_id counter name "port_${port_safe}_out"
        done

    elif is_port_range "$port"; then
        # 端口段：使用下划线替换连字符，添加标记用于TC分类
        local port_safe=$(echo "$port" | tr '-' '_')
        local mark_id=$(generate_port_range_mark "$port")

        nft list counter $family $table_name "port_${port_safe}_in" >/dev/null 2>&1 || \
            nft add counter $family $table_name "port_${port_safe}_in" 2>/dev/null || true
        nft list counter $family $table_name "port_${port_safe}_out" >/dev/null 2>&1 || \
            nft add counter $family $table_name "port_${port_safe}_out" 2>/dev/null || true

        # nftables原生端口段语法，同时设置标记
        nft add rule $family $table_name input tcp dport $port meta mark set $mark_id counter name "port_${port_safe}_in"
        nft add rule $family $table_name input udp dport $port meta mark set $mark_id counter name "port_${port_safe}_in"
        nft add rule $family $table_name forward tcp dport $port meta mark set $mark_id counter name "port_${port_safe}_in"
        nft add rule $family $table_name forward udp dport $port meta mark set $mark_id counter name "port_${port_safe}_in"

        nft add rule $family $table_name output tcp sport $port meta mark set $mark_id counter name "port_${port_safe}_out"
        nft add rule $family $table_name output udp sport $port meta mark set $mark_id counter name "port_${port_safe}_out"
        nft add rule $family $table_name forward tcp sport $port meta mark set $mark_id counter name "port_${port_safe}_out"
        nft add rule $family $table_name forward udp sport $port meta mark set $mark_id counter name "port_${port_safe}_out"
    else
        nft list counter $family $table_name "port_${port}_in" >/dev/null 2>&1 || \
            nft add counter $family $table_name "port_${port}_in" 2>/dev/null || true
        nft list counter $family $table_name "port_${port}_out" >/dev/null 2>&1 || \
            nft add counter $family $table_name "port_${port}_out" 2>/dev/null || true

        nft add rule $family $table_name input tcp dport $port counter name "port_${port}_in"
        nft add rule $family $table_name input udp dport $port counter name "port_${port}_in"
        nft add rule $family $table_name forward tcp dport $port counter name "port_${port}_in"
        nft add rule $family $table_name forward udp dport $port counter name "port_${port}_in"

        nft add rule $family $table_name output tcp sport $port counter name "port_${port}_out"
        nft add rule $family $table_name output udp sport $port counter name "port_${port}_out"
        nft add rule $family $table_name forward tcp sport $port counter name "port_${port}_out"
        nft add rule $family $table_name forward udp sport $port counter name "port_${port}_out"
    fi
}

remove_nftables_rules() {
    local port=$1
    local table_name=$(jq -r '.nftables.table_name' "$CONFIG_FILE")
    local family=$(jq -r '.nftables.family' "$CONFIG_FILE")

    echo "删除端口 $port 的所有规则..."

    # 根据端口类型确定搜索模式
    local port_safe
    if is_port_group "$port"; then
        port_safe=$(generate_port_group_safe_name "$port")
    elif is_port_range "$port"; then
        port_safe=$(echo "$port" | tr '-' '_')
    else
        port_safe="$port"
    fi
    local search_pattern="port_${port_safe}_"

    # 使用handle删除法：逐个删除匹配的规则
    local deleted_count=0
    while true; do
        local handle=$(nft -a list table $family $table_name 2>/dev/null | \
            grep -E "(tcp|udp).*(dport|sport).*$search_pattern" | \
            head -n1 | \
            sed -n 's/.*# handle \([0-9]\+\)$/\1/p')

        if [ -z "$handle" ]; then
            echo "没有更多匹配的规则，共删除 $deleted_count 条规则"
            break
        fi

        local deleted=false
        for chain in input output forward prerouting; do
            if nft delete rule $family $table_name $chain handle $handle 2>/dev/null; then
                echo "已删除规则 handle $handle (链: $chain)"
                deleted_count=$((deleted_count + 1))
                deleted=true
                break
            fi
        done

        if [ "$deleted" = false ]; then
            echo "删除规则 handle $handle 失败，跳过"
            break  # 跳出循环避免死循环
        fi

        if [ $deleted_count -ge 200 ]; then
            echo "已删除200条规则，停止删除以防无限循环"
            break
        fi
    done

    # 删除计数器
    nft delete counter $family $table_name "port_${port_safe}_in" 2>/dev/null || true
    nft delete counter $family $table_name "port_${port_safe}_out" 2>/dev/null || true

    echo "端口 $port 的规则删除完成"
}

set_port_bandwidth_limit() {
    echo -e "${BLUE}设置端口带宽限制${NC}"
    echo

    local active_ports=($(get_active_ports))

    if ! show_port_list; then
        sleep 2
        return
    fi
    echo

    read -p "请选择要限制的端口（多端口使用逗号,分隔） [1-${#active_ports[@]}]: " choice_input

    local valid_choices=()
    local ports_to_limit=()
    parse_multi_choice_input "$choice_input" "${#active_ports[@]}" valid_choices

    for choice in "${valid_choices[@]}"; do
        local port=${active_ports[$((choice-1))]}
        ports_to_limit+=("$port")
    done

    if [ ${#ports_to_limit[@]} -eq 0 ]; then
        echo -e "${RED}没有有效的端口可设置限制${NC}"
        sleep 2
        return
    fi

    echo
    local port_list=$(IFS=','; echo "${ports_to_limit[*]}")
    echo "为端口 $port_list 设置带宽限制（速率控制）:"
    echo "请输入限制值（0为无限制）（要带单位Kbps/Mbps/Gbps）:"
    echo "(多端口排序分别限制使用逗号,分隔)(只输入一个值，应用到所有端口):"
    read -p "带宽限制: " limit_input

    local LIMITS=()
    parse_comma_separated_input "$limit_input" LIMITS

    expand_single_value_to_array LIMITS ${#ports_to_limit[@]}
    if [ ${#LIMITS[@]} -ne ${#ports_to_limit[@]} ]; then
        echo -e "${RED}限制值数量与端口数量不匹配${NC}"
        sleep 2
        return
    fi

    local success_count=0
    for i in "${!ports_to_limit[@]}"; do
        local port="${ports_to_limit[$i]}"
        local limit=$(echo "${LIMITS[$i]}" | tr -d ' ')

        if [ "$limit" = "0" ] || [ -z "$limit" ]; then
            remove_tc_limit "$port"
            update_config ".ports.\"$port\".bandwidth_limit.enabled = false |
                .ports.\"$port\".bandwidth_limit.rate = \"unlimited\""
            echo -e "${GREEN}端口 $port 带宽限制已移除${NC}"
            success_count=$((success_count + 1))
            continue
        fi

        remove_tc_limit "$port"

        if ! validate_bandwidth "$limit"; then
            echo -e "${RED}端口 $port 格式错误，请使用如：500Kbps, 100Mbps, 1Gbps${NC}"
            continue
        fi

        # 转换为TC格式
        local tc_limit
        local limit_lower=$(echo "$limit" | tr '[:upper:]' '[:lower:]')
        if [[ "$limit_lower" =~ kbps$ ]]; then
            tc_limit=$(echo "$limit_lower" | sed 's/kbps$/kbit/')
        elif [[ "$limit_lower" =~ mbps$ ]]; then
            tc_limit=$(echo "$limit_lower" | sed 's/mbps$/mbit/')
        elif [[ "$limit_lower" =~ gbps$ ]]; then
            tc_limit=$(echo "$limit_lower" | sed 's/gbps$/gbit/')
        fi

        if ! apply_tc_limit "$port" "$tc_limit"; then
            echo -e "${RED}端口 $port 带宽限制设置失败${NC}"
            continue
        fi

        update_config ".ports.\"$port\".bandwidth_limit.enabled = true |
            .ports.\"$port\".bandwidth_limit.rate = \"$limit\""

        echo -e "${GREEN}端口 $port 带宽限制设置成功: $limit${NC}"
        success_count=$((success_count + 1))
    done

    echo
    echo -e "${GREEN}成功设置 $success_count 个端口的带宽限制${NC}"
}

set_port_quota_limit() {
    echo -e "${BLUE}=== 设置端口流量配额 ===${NC}"
    echo

    local active_ports=($(get_active_ports))
    if ! show_port_list; then
        sleep 2
        return
    fi
    echo

    read -p "请选择要设置配额的端口（多端口使用逗号,分隔） [1-${#active_ports[@]}]: " choice_input

    local valid_choices=()
    local ports_to_quota=()
    parse_multi_choice_input "$choice_input" "${#active_ports[@]}" valid_choices

    for choice in "${valid_choices[@]}"; do
        local port=${active_ports[$((choice-1))]}
        ports_to_quota+=("$port")
    done

    if [ ${#ports_to_quota[@]} -eq 0 ]; then
        echo -e "${RED}没有有效的端口可设置配额${NC}"
        sleep 2
        return
    fi

    echo
    local port_list=$(IFS=','; echo "${ports_to_quota[*]}")
    while true; do
        echo "为端口 $port_list 设置流量配额（总量控制）:"
        echo "请输入配额值（0为无限制）（要带单位MB/GB/T）:"
        echo "(多端口分别配额使用逗号,分隔)(只输入一个值，应用到所有端口):"
        read -p "流量配额(回车默认0): " quota_input

        if [ -z "$quota_input" ]; then
            quota_input="0"
        fi

        local QUOTAS=()
        parse_comma_separated_input "$quota_input" QUOTAS

        local all_valid=true
        for quota in "${QUOTAS[@]}"; do
            if [ "$quota" != "0" ] && ! validate_quota "$quota"; then
                echo -e "${RED}配额格式错误: $quota，请使用如：100MB, 1GB, 2T${NC}"
                all_valid=false
                break
            fi
        done

        if [ "$all_valid" = false ]; then
            echo "请重新输入配额值"
            continue
        fi

        expand_single_value_to_array QUOTAS ${#ports_to_quota[@]}
        if [ ${#QUOTAS[@]} -ne ${#ports_to_quota[@]} ]; then
            echo -e "${RED}配额值数量与端口数量不匹配${NC}"
            continue
        fi

        break
    done

    local success_count=0
    for i in "${!ports_to_quota[@]}"; do
        local port="${ports_to_quota[$i]}"
        local quota=$(echo "${QUOTAS[$i]}" | tr -d ' ')

        if [ "$quota" = "0" ] || [ -z "$quota" ]; then
            remove_nftables_quota "$port"
            # 设为无限额时删除reset_day字段并清除定时任务
            jq ".ports.\"$port\".quota.enabled = true | 
                .ports.\"$port\".quota.monthly_limit = \"unlimited\" | 
                del(.ports.\"$port\".quota.reset_day)" "$CONFIG_FILE" > "${CONFIG_FILE}.tmp" && mv "${CONFIG_FILE}.tmp" "$CONFIG_FILE"
            remove_port_auto_reset_cron "$port"
            echo -e "${GREEN}端口 $port 流量配额设置为无限制${NC}"
            success_count=$((success_count + 1))
            continue
        fi

        remove_nftables_quota "$port"
        apply_nftables_quota "$port" "$quota"

        # 获取当前配额限制状态
        local current_monthly_limit=$(jq -r ".ports.\"$port\".quota.monthly_limit // \"unlimited\"" "$CONFIG_FILE")
        
        # 从无限额改为有限额时默认添加reset_day=1
        if [ "$current_monthly_limit" = "unlimited" ]; then
            # 原来是无限额，现在设置为有限额，添加默认reset_day=1
            update_config ".ports.\"$port\".quota.enabled = true |
                .ports.\"$port\".quota.monthly_limit = \"$quota\" |
                .ports.\"$port\".quota.reset_day = 1"
        else
            # 原来就是有限额，只修改配额值，保持reset_day不变
            update_config ".ports.\"$port\".quota.enabled = true |
                .ports.\"$port\".quota.monthly_limit = \"$quota\""
        fi
        
        setup_port_auto_reset_cron "$port"
        echo -e "${GREEN}端口 $port 流量配额设置成功: $quota${NC}"
        success_count=$((success_count + 1))
    done

    echo
    echo -e "${GREEN}成功设置 $success_count 个端口的流量配额${NC}"
}

manage_traffic_limits() {
    while true; do
        echo -e "${BLUE}=== 端口限制设置管理 ===${NC}"
        echo "1. 设置端口带宽限制（速率控制）"
        echo "2. 设置端口流量配额（总量控制）"
        echo "3. 管理端口租期 (自动到期停机)"
        echo "0. 返回主菜单"
        echo
        read -p "请选择操作 [0-3]: " choice

        case $choice in
            1) set_port_bandwidth_limit ;;
            2) set_port_quota_limit ;;
            3) manage_port_expiration ;;
            0) return ;;
            *) echo -e "${RED}无效选择${NC}"; sleep 1 ;;
        esac
    done
}

# 管理端口租期
manage_port_expiration() {
    # 确保后台检查任务已部署
    setup_daily_check_cron

    while true; do
        clear
        echo -e "${BLUE}=== 管理端口租期 (到期自动停机) ===${NC}"
        echo
        
        local active_ports=($(get_active_ports))
        if [ ${#active_ports[@]} -eq 0 ]; then
             echo "暂无监控端口"
             sleep 2
             return
        fi

        echo "端口列表:"
        for i in "${!active_ports[@]}"; do
            local port=${active_ports[$i]}
            
            # 显示基本信息
            local display_name=""
            local remark=$(jq -r ".ports.\"$port\".remark // \"\"" "$CONFIG_FILE")
            if is_port_group "$port"; then
                local display_str="$port"
                if [ ${#port} -gt 20 ]; then
                    local count=$(echo "$port" | tr -cd ',' | wc -c)
                    count=$((count + 1))
                    display_str="${port:0:17}...(${count}个)"
                fi
                display_name="端口组[${display_str}]"
            elif is_port_range "$port"; then
                display_name="端口段[$port]"
            else
                display_name="端口 $port"
            fi
            if [ -n "$remark" ] && [ "$remark" != "null" ]; then
                display_name+=" [$remark]"
            fi

            # 读取到期信息
            local expire_date=$(jq -r ".ports.\"$port\".expiration_date // \"\"" "$CONFIG_FILE")
            local expire_status="${GREEN}永久有效${NC}"
            
            if [ -n "$expire_date" ] && [ "$expire_date" != "null" ]; then
                local today=$(get_beijing_time +%Y-%m-%d)
                if [[ "$today" > "$expire_date" ]]; then
                    expire_status="${RED}已过期 ($expire_date)${NC}"
                elif [[ "$today" == "$expire_date" ]]; then
                    expire_status="${YELLOW}今天到期 ($expire_date)${NC}"
                else
                    expire_status="${BLUE}$expire_date 到期${NC}"
                fi
            fi
            
            echo -e "$((i+1)). $display_name -> $expire_status"
        done
        echo
        echo "0. 返回上级菜单"
        echo
        
        read -p "请选择要管理的端口 [1-${#active_ports[@]}, 0返回]: " choice
        
        if [ "$choice" = "0" ]; then
            return
        fi

        if [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -ge 1 ] && [ "$choice" -le ${#active_ports[@]} ]; then
            local port=${active_ports[$((choice-1))]}
            set_port_update_expiration "$port"
        else
            echo -e "${RED}无效选择${NC}"
            sleep 1
        fi
    done
}

# 设置/更新端口到期时间
set_port_update_expiration() {
    local port=$1
    
    while true; do
        clear
        echo -e "${BLUE}=== 续费/设置租期: $port ===${NC}"
        
        # 获取当前信息
        local expire_date=$(jq -r ".ports.\"$port\".expiration_date // \"\"" "$CONFIG_FILE")
        local reset_day=$(jq -r ".ports.\"$port\".quota.reset_day // \"\"" "$CONFIG_FILE")
        
        if [ -z "$expire_date" ] || [ "$expire_date" = "null" ]; then
            expire_date="未设置 (永久)"
        fi
        if [ -z "$reset_day" ] || [ "$reset_day" = "null" ]; then
            reset_day=$(get_beijing_time +%-d) # 默认为今天
            echo -e "${YELLOW}提示: 该端口未设置流量重置日，将默认以每月 ${reset_day} 日为基准。${NC}"
        fi
        
        echo -e "当前到期日: ${GREEN}$expire_date${NC}"
        echo -e "重置日基准: 每月 ${GREEN}${reset_day}${NC} 日"
        echo "------------------------"
        echo "1. 增加 1 个月"
        echo "2. 增加 3 个月 (季付)"
        echo "3. 增加 6 个月 (半年)"
        echo "4. 增加 1 年"
        echo "5. 手动输入到期日期"
        echo "6. 清除租期 (设置为永久)"
        echo "0. 返回"
        echo
        
        read -p "请选择续费时长 [0-6]: " duration_choice
        
        local new_date=""
        local base_date=""
        local months_to_add=0
        
        # 确定基准日期逻辑
        local current_expire=$(jq -r ".ports.\"$port\".expiration_date // \"\"" "$CONFIG_FILE")
        local today=$(get_beijing_time +%Y-%m-%d)
        local is_renewal=false
        
        if [ -n "$current_expire" ] && [ "$current_expire" != "null" ] && [[ "$current_expire" > "$today" ]]; then
            # 续费模式：端口未过期，在现有到期日基础上叠加
            base_date="$current_expire"
            is_renewal=true
            echo -e "将在现有到期日 ($base_date) 基础上续费"
        else
            # 初始化/过期续费模式：从今天开始计算
            base_date="$today"
            is_renewal=false
            echo -e "端口已过期或首次设置，从今天 ($today) 开始计算租期"
        fi

        case $duration_choice in
            1) months_to_add=1 ;;
            2) months_to_add=3 ;;
            3) months_to_add=6 ;;
            4) months_to_add=12 ;;
            5) 
                read -p "请输入到期日期 (格式 YYYY-MM-DD): " manual_date
                if date -d "$manual_date" >/dev/null 2>&1; then
                    new_date="$manual_date"
                else
                    echo -e "${RED}日期格式错误${NC}"
                    sleep 2
                    continue
                fi
                ;;
            6)
                update_config "del(.ports.\"$port\".expiration_date)"
                echo -e "${GREEN}已清除租期，端口恢复永久有效。${NC}"
                
                # 【修复BUG】清除租期后必须解封端口，但要保留历史流量数据
                echo -e "${YELLOW}正在恢复端口服务...${NC}"
                
                # 1. 先保存当前流量数据
                local traffic_data=($(get_port_traffic "$port"))
                local saved_input=${traffic_data[0]}
                local saved_output=${traffic_data[1]}
                echo "保存当前流量: 上行=$(format_bytes $saved_input) 下行=$(format_bytes $saved_output)"
                
                # 2. 删除旧规则（包括可能的封锁规则）
                remove_nftables_rules "$port"
                
                # 3. 恢复流量计数器（创建带历史数据的计数器）
                restore_counter_value "$port" "$saved_input" "$saved_output"
                
                # 4. 重新添加监控规则（计数器已存在，不会重新创建）
                add_nftables_rules "$port"
                
                # 5. 恢复配额规则
                local quota_enabled=$(jq -r ".ports.\"$port\".quota.enabled // false" "$CONFIG_FILE")
                if [ "$quota_enabled" = "true" ]; then
                    local quota_limit=$(jq -r ".ports.\"$port\".quota.monthly_limit // \"unlimited\"" "$CONFIG_FILE")
                    if [ "$quota_limit" != "unlimited" ]; then
                        apply_nftables_quota "$port" "$quota_limit"
                    fi
                fi
                
                # 6. 恢复带宽限制
                local bw_enabled=$(jq -r ".ports.\"$port\".bandwidth_limit.enabled // false" "$CONFIG_FILE")
                if [ "$bw_enabled" = "true" ]; then
                    local bw_rate=$(jq -r ".ports.\"$port\".bandwidth_limit.rate" "$CONFIG_FILE")
                    if [ -n "$bw_rate" ] && [ "$bw_rate" != "null" ] && [ "$bw_rate" != "unlimited" ]; then
                        # 转换为TC格式
                        local limit_lower=$(echo "$bw_rate" | tr '[:upper:]' '[:lower:]')
                        local tc_limit=""
                        if [[ "$limit_lower" =~ kbps$ ]]; then
                            tc_limit=$(echo "$limit_lower" | sed 's/kbps$/kbit/')
                        elif [[ "$limit_lower" =~ mbps$ ]]; then
                            tc_limit=$(echo "$limit_lower" | sed 's/mbps$/mbit/')
                        elif [[ "$limit_lower" =~ gbps$ ]]; then
                            tc_limit=$(echo "$limit_lower" | sed 's/gbps$/gbit/')
                        fi
                        if [ -n "$tc_limit" ]; then
                            apply_tc_limit "$port" "$tc_limit"
                        fi
                    fi
                fi

                echo -e "${GREEN}端口服务已恢复，历史流量数据已保留${NC}"
                sleep 2
                return
                ;;
            0) return ;;
            *) echo -e "${RED}无效选择${NC}"; sleep 1; continue ;;
        esac
        
        # 如果不是手动输入，则计算日期
        if [ -z "$new_date" ] && [ $duration_choice -le 4 ]; then
            if [ "$is_renewal" = "false" ]; then
                months_to_add=$(adjust_initial_expiration_months "$base_date" "$months_to_add" "$reset_day")
            fi
            new_date=$(calculate_next_expiration "$base_date" "$months_to_add" "$reset_day")
        fi
        
        if [ -n "$new_date" ]; then
            update_config ".ports.\"$port\".expiration_date = \"$new_date\""
            echo -e "${GREEN}续费成功！新到期日: $new_date${NC}"
            
            # 【修复BUG】自动复活逻辑：必须先保存流量数据，避免续费时清空历史流量！
            echo -e "${YELLOW}正在恢复端口服务...${NC}"
            
            # 1. 先保存当前流量数据
            local traffic_data=($(get_port_traffic "$port"))
            local saved_input=${traffic_data[0]}
            local saved_output=${traffic_data[1]}
            echo "保存当前流量: 上行=$(format_bytes $saved_input) 下行=$(format_bytes $saved_output)"
            
            # 2. 删除旧规则（包括可能的封锁规则）
            remove_nftables_rules "$port"
            
            # 3. 恢复流量计数器（创建带历史数据的计数器）
            restore_counter_value "$port" "$saved_input" "$saved_output"
            
            # 4. 重新添加监控规则（计数器已存在，不会重新创建）
            add_nftables_rules "$port"
            
            # 5. 恢复配额限制
            local quota_enabled=$(jq -r ".ports.\"$port\".quota.enabled // false" "$CONFIG_FILE")
            if [ "$quota_enabled" = "true" ]; then
                local quota_limit=$(jq -r ".ports.\"$port\".quota.monthly_limit // \"unlimited\"" "$CONFIG_FILE")
                if [ "$quota_limit" != "unlimited" ]; then
                    apply_nftables_quota "$port" "$quota_limit"
                fi
            fi
            
            # 6. 恢复带宽限制 (TC)
            local bw_enabled=$(jq -r ".ports.\"$port\".bandwidth_limit.enabled // false" "$CONFIG_FILE")
            if [ "$bw_enabled" = "true" ]; then
                local bw_rate=$(jq -r ".ports.\"$port\".bandwidth_limit.rate" "$CONFIG_FILE")
                if [ -n "$bw_rate" ] && [ "$bw_rate" != "null" ] && [ "$bw_rate" != "unlimited" ]; then
                    # 转换为TC格式
                    local limit_lower=$(echo "$bw_rate" | tr '[:upper:]' '[:lower:]')
                    local tc_limit=""
                    if [[ "$limit_lower" =~ kbps$ ]]; then
                        tc_limit=$(echo "$limit_lower" | sed 's/kbps$/kbit/')
                    elif [[ "$limit_lower" =~ mbps$ ]]; then
                        tc_limit=$(echo "$limit_lower" | sed 's/mbps$/mbit/')
                    elif [[ "$limit_lower" =~ gbps$ ]]; then
                        tc_limit=$(echo "$limit_lower" | sed 's/gbps$/gbit/')
                    fi
                    if [ -n "$tc_limit" ]; then
                        apply_tc_limit "$port" "$tc_limit"
                    fi
                fi
            fi
            
            echo -e "${GREEN}端口服务已恢复，历史流量数据已保留${NC}"
            sleep 2
            return
        fi
    done
}

# 首次/过期续费时，根据重置日调整月数：重置日仍在本月则把本月计为第1个月
# 参数: $1=基准日期, $2=增加月数, $3=目标重置日(Day)
adjust_initial_expiration_months() {
    local base_date="$1"
    local months="$2"
    local reset_day="$3"

    if ! [[ "$months" =~ ^[0-9]+$ ]] || [ "$months" -le 0 ]; then
        echo "$months"
        return
    fi

    if ! [[ "$reset_day" =~ ^[0-9]+$ ]]; then
        echo "$months"
        return
    fi

    local today_day=$(get_beijing_time -d "$base_date" +%-d 2>/dev/null || date -d "$base_date" +%-d)
    local month_prefix="${base_date:0:8}"
    local last_day=$(get_beijing_time -d "${month_prefix}01 + 1 month - 1 day" +%-d 2>/dev/null || date -d "${month_prefix}01 + 1 month - 1 day" +%-d)

    local today_day_num=$((10#$today_day))
    local reset_day_num=$((10#$reset_day))
    local last_day_num=$((10#$last_day))

    if [ "$reset_day_num" -gt "$last_day_num" ]; then
        reset_day_num=$last_day_num
    fi

    if [ "$reset_day_num" -gt "$today_day_num" ]; then
        months=$((months - 1))
        if [ "$months" -lt 0 ]; then
            months=0
        fi
    fi

    echo "$months"
}

# 计算下一个到期日
# 参数: $1=基准日期, $2=增加月数, $3=目标重置日(Day)
calculate_next_expiration() {
    local base_date="$1"
    local months="$2"
    local target_day="$3"
    
    # 获取基准日期的年和月
    local base_year=$(get_beijing_time -d "$base_date" +%Y 2>/dev/null || date -d "$base_date" +%Y)
    local base_month=$(get_beijing_time -d "$base_date" +%m 2>/dev/null || date -d "$base_date" +%m)
    
    # 纯数学计算新的年份和月份，避免 date 命令在处理月底时的日期溢出问题
    # 1. 移除前导零 (10进制)
    base_month=$((10#$base_month))
    
    # 2. 计算总月数
    local total_months=$((base_month + months))
    
    # 3. 计算新年份增量 (减1是为了处理12月的倍数)
    local year_add=$(( (total_months - 1) / 12 ))
    local next_month=$(( (total_months - 1) % 12 + 1 ))
    local next_year=$((base_year + year_add))
    
    # 4. 补齐两位数月份
    printf -v next_month "%02d" $next_month
    
    # 构建目标日期字符串
    local candidate_date="${next_year}-${next_month}-${target_day}"
    
    # 验证日期合法性 (例如处理 2月30日)
    if get_beijing_time -d "$candidate_date" >/dev/null 2>&1 || date -d "$candidate_date" >/dev/null 2>&1; then
        echo "$candidate_date"
    else
        # 如果日期非法（比如本月没有31号），则使用本月最后一天
        echo $(get_beijing_time -d "${next_year}-${next_month}-01 + 1 month - 1 day" +%Y-%m-%d 2>/dev/null || date -d "${next_year}-${next_month}-01 + 1 month - 1 day" +%Y-%m-%d)
    fi
}

apply_nftables_quota() {
    local port=$1
    local quota_limit=$2
    local table_name=$(jq -r '.nftables.table_name' "$CONFIG_FILE")
    local family=$(jq -r '.nftables.family' "$CONFIG_FILE")
    local billing_mode=$(jq -r ".ports.\"$port\".billing_mode // \"double\"" "$CONFIG_FILE")

    local quota_bytes=$(parse_size_to_bytes "$quota_limit")

    # 使用当前流量作为配额初始值，避免重置后立即触发限制
    local current_traffic=($(get_port_traffic "$port"))
    local current_input=${current_traffic[0]}
    local current_output=${current_traffic[1]}
    local current_total=$(calculate_total_traffic "$current_input" "$current_output" "$billing_mode")

    # 根据端口类型确定配额名称
    local port_safe
    if is_port_group "$port"; then
        port_safe=$(generate_port_group_safe_name "$port")
    elif is_port_range "$port"; then
        port_safe=$(echo "$port" | tr '-' '_')
    else
        port_safe="$port"
    fi
    local quota_name="port_${port_safe}_quota"

    # 确保清理旧的 quota 规则和对象
    local last_handle=""
    while true; do
        local old_handle=$(nft -a list table $family $table_name 2>/dev/null | \
            grep "quota name \"$quota_name\"" | head -n1 | sed -n 's/.*# handle \([0-9]\+\)$/\1/p')
        [ -z "$old_handle" ] && break
        if [ "$old_handle" = "$last_handle" ]; then
            echo -e "${RED}清理旧规则失败，句柄重复: $old_handle${NC}" >&2
            break
        fi
        last_handle="$old_handle"

        local deleted=false
        for chain in input output forward; do
            if nft delete rule $family $table_name $chain handle $old_handle 2>/dev/null; then
                deleted=true
                break
            fi
        done
        [ "$deleted" = false ] && break
    done
    nft delete quota $family $table_name $quota_name 2>/dev/null || true

    # 创建新配额
    nft add quota $family $table_name $quota_name { over $quota_bytes bytes used $current_total bytes } 2>/dev/null || true

    # 根据端口类型添加规则
    if is_port_group "$port"; then
        # 端口组：为每个端口添加规则，共享同一个配额
        local group_ports=($(get_group_ports "$port"))
        for single_port in "${group_ports[@]}"; do
            _apply_quota_rules_for_single_port "$single_port" "$quota_name" "$billing_mode" "$family" "$table_name"
        done
    elif is_port_range "$port"; then
        # 端口段：nftables原生语法支持
        _apply_quota_rules_for_single_port "$port" "$quota_name" "$billing_mode" "$family" "$table_name"
    else
        # 单端口
        _apply_quota_rules_for_single_port "$port" "$quota_name" "$billing_mode" "$family" "$table_name"
    fi
}

# 辅助函数：为单个端口添加配额规则
_apply_quota_rules_for_single_port() {
    local single_port=$1
    local quota_name=$2
    local billing_mode=$3
    local family=$4
    local table_name=$5

    if [ "$billing_mode" = "single" ]; then
        # 仅出站统计：Out × 2
        # 出站规则×2（8条）
        nft insert rule $family $table_name output tcp sport $single_port quota name "$quota_name" drop 2>/dev/null || true
        nft insert rule $family $table_name output tcp sport $single_port quota name "$quota_name" drop 2>/dev/null || true
        nft insert rule $family $table_name output udp sport $single_port quota name "$quota_name" drop 2>/dev/null || true
        nft insert rule $family $table_name output udp sport $single_port quota name "$quota_name" drop 2>/dev/null || true
        nft insert rule $family $table_name forward tcp sport $single_port quota name "$quota_name" drop 2>/dev/null || true
        nft insert rule $family $table_name forward tcp sport $single_port quota name "$quota_name" drop 2>/dev/null || true
        nft insert rule $family $table_name forward udp sport $single_port quota name "$quota_name" drop 2>/dev/null || true
        nft insert rule $family $table_name forward udp sport $single_port quota name "$quota_name" drop 2>/dev/null || true
    elif [ "$billing_mode" = "premium" ]; then
        # CN Premium 内网中转：(入+出)×1
        # 入站规则×1（4条）
        nft insert rule $family $table_name input tcp dport $single_port quota name "$quota_name" drop 2>/dev/null || true
        nft insert rule $family $table_name input udp dport $single_port quota name "$quota_name" drop 2>/dev/null || true
        nft insert rule $family $table_name forward tcp dport $single_port quota name "$quota_name" drop 2>/dev/null || true
        nft insert rule $family $table_name forward udp dport $single_port quota name "$quota_name" drop 2>/dev/null || true
        # 出站规则×1（4条）
        nft insert rule $family $table_name output tcp sport $single_port quota name "$quota_name" drop 2>/dev/null || true
        nft insert rule $family $table_name output udp sport $single_port quota name "$quota_name" drop 2>/dev/null || true
        nft insert rule $family $table_name forward tcp sport $single_port quota name "$quota_name" drop 2>/dev/null || true
        nft insert rule $family $table_name forward udp sport $single_port quota name "$quota_name" drop 2>/dev/null || true
    else
        # double/relay: (入+出)×2
        # 入站规则×2（8条）
        nft insert rule $family $table_name input tcp dport $single_port quota name "$quota_name" drop 2>/dev/null || true
        nft insert rule $family $table_name input tcp dport $single_port quota name "$quota_name" drop 2>/dev/null || true
        nft insert rule $family $table_name input udp dport $single_port quota name "$quota_name" drop 2>/dev/null || true
        nft insert rule $family $table_name input udp dport $single_port quota name "$quota_name" drop 2>/dev/null || true
        nft insert rule $family $table_name forward tcp dport $single_port quota name "$quota_name" drop 2>/dev/null || true
        nft insert rule $family $table_name forward tcp dport $single_port quota name "$quota_name" drop 2>/dev/null || true
        nft insert rule $family $table_name forward udp dport $single_port quota name "$quota_name" drop 2>/dev/null || true
        nft insert rule $family $table_name forward udp dport $single_port quota name "$quota_name" drop 2>/dev/null || true
        # 出站规则×2（8条）
        nft insert rule $family $table_name output tcp sport $single_port quota name "$quota_name" drop 2>/dev/null || true
        nft insert rule $family $table_name output tcp sport $single_port quota name "$quota_name" drop 2>/dev/null || true
        nft insert rule $family $table_name output udp sport $single_port quota name "$quota_name" drop 2>/dev/null || true
        nft insert rule $family $table_name output udp sport $single_port quota name "$quota_name" drop 2>/dev/null || true
        nft insert rule $family $table_name forward tcp sport $single_port quota name "$quota_name" drop 2>/dev/null || true
        nft insert rule $family $table_name forward tcp sport $single_port quota name "$quota_name" drop 2>/dev/null || true
        nft insert rule $family $table_name forward udp sport $single_port quota name "$quota_name" drop 2>/dev/null || true
        nft insert rule $family $table_name forward udp sport $single_port quota name "$quota_name" drop 2>/dev/null || true
    fi
}

# 删除nftables配额限制 - 使用handle删除法
remove_nftables_quota() {
    local port=$1
    local table_name=$(jq -r '.nftables.table_name' "$CONFIG_FILE")
    local family=$(jq -r '.nftables.family' "$CONFIG_FILE")

    echo "删除端口 $port 的配额规则..."

    # 根据端口类型确定配额名称
    local port_safe
    if is_port_group "$port"; then
        port_safe=$(generate_port_group_safe_name "$port")
    elif is_port_range "$port"; then
        port_safe=$(echo "$port" | tr '-' '_')
    else
        port_safe="$port"
    fi
    local quota_name="port_${port_safe}_quota"

    # 循环删除所有包含配额名称的规则 - 每次只获取一个handle
    local deleted_count=0
    while true; do
        # 每次只获取第一个匹配的配额规则handle
        local handle=$(nft -a list table $family $table_name 2>/dev/null | \
            grep "quota name \"$quota_name\"" | \
            head -n1 | \
            sed -n 's/.*# handle \([0-9]\+\)$/\1/p')

        if [ -z "$handle" ]; then
            if [ $deleted_count -eq 0 ]; then
                echo "该端口未设置配额限制，无需删除配额规则"
            else
                echo "没有更多匹配的配额规则，共删除 $deleted_count 条规则"
            fi
            break
        fi

        # 删除找到的handle - 需要指定链名
        local deleted=false
        for chain in input output forward; do
            if nft delete rule $family $table_name $chain handle $handle 2>/dev/null; then
                echo "已删除配额规则 handle $handle (链: $chain)"
                deleted_count=$((deleted_count + 1))
                deleted=true
                break
            fi
        done

        if [ "$deleted" = false ]; then
            echo "删除配额规则 handle $handle 失败，跳过"
        fi

        if [ $deleted_count -ge 100 ]; then
            echo "已删除100条配额规则，停止删除以防无限循环"
            break
        fi
    done

    nft delete quota $family $table_name "$quota_name" 2>/dev/null || true

    echo "端口 $port 的配额限制删除完成"
}

# ==============================================================================
# 备用方案（v1.6.3逻辑）：高级带宽限制实现
# 功能特性：
# 1. 自动检测并强制将网卡根队列切换为 HTB（解决 Debian12/13 下 BBR+FQ 导致的带宽限制失效问题）
# 2. 创建默认直通分类（Class 1:30），确保未限速端口继续跑满带宽，不丢失性能
# 3. 提供详细的错误捕捉和报告
#
# 如果未来需要启用此逻辑，请替换下方的 apply_tc_limit 函数
#
# apply_tc_limit_advanced() {
#     local port=$1
#     local total_limit=$2
#     local interface=$(get_default_interface)
#
#     # 尝试加载sch_htb模块
#     modprobe sch_htb 2>/dev/null || true
#
#     # 检查并初始化根队列为HTB
#     if ! tc qdisc show dev $interface | grep -q "qdisc htb 1: root"; then
#         # 如果根队列不是HTB，尝试替换为HTB
#         # 注意：这会移除原有的根队列（如fq），但为了带宽限制是必须的
#         if ! tc qdisc replace dev $interface root handle 1: htb default 30 2>/dev/null; then
#              # 如果替换失败，尝试显示详细错误
#              echo -e "${RED}设置根队列失败，尝试强制替换...${NC}"
#              local err_out
#              if ! err_out=$(tc qdisc replace dev $interface root handle 1: htb default 30 2>&1); then
#                  echo -e "${RED}无法初始化HTB队列: $err_out${NC}" >&2
#                  return 1
#              fi
#         fi
#         # 初始化总带宽类 (1:1)
#         tc class add dev $interface parent 1: classid 1:1 htb rate 1000mbit 2>/dev/null || true
#         # 初始化默认全速类 (1:30) - 承载所有未被限制的流量
#         tc class add dev $interface parent 1:1 classid 1:30 htb rate 1000mbit ceil 1000mbit prio 0 2>/dev/null || true
#         tc qdisc add dev $interface parent 1:30 handle 30: sfq perturb 10 2>/dev/null || true
#     else
#         # 已经是HTB，确保基础类存在
#         tc class add dev $interface parent 1: classid 1:1 htb rate 1000mbit 2>/dev/null || true
#         tc class add dev $interface parent 1:1 classid 1:30 htb rate 1000mbit ceil 1000mbit prio 0 2>/dev/null || true
#         tc qdisc add dev $interface parent 1:30 handle 30: sfq perturb 10 2>/dev/null || true
#     fi
#
#     local class_id=$(generate_tc_class_id "$port")
#     tc class del dev $interface classid $class_id 2>/dev/null || true
#
#     # 计算burst参数以优化性能
#     local base_rate=$(parse_tc_rate_to_kbps "$total_limit")
#     local burst_bytes=$(calculate_tc_burst "$base_rate")
#     local burst_size=$(format_tc_burst "$burst_bytes")
#
#     local out
#     if ! out=$(tc class add dev $interface parent 1:1 classid $class_id htb rate $total_limit ceil $total_limit burst $burst_size 2>&1); then
#         echo -e "${RED}设置带宽限制失败: $out${NC}" >&2
#         return 1
#     fi
#     # 为限制类添加sfq公平队列
#     tc qdisc add dev $interface parent $class_id handle $class_id: sfq perturb 10 2>/dev/null || true
#
#     if is_port_group "$port"; then
#         # 端口组：使用fw分类器根据共享标记分类
#         local mark_id=$(generate_port_group_mark "$port")
#         tc filter add dev $interface protocol ip parent 1:0 prio 1 handle $mark_id fw flowid $class_id 2>/dev/null || true
#
#     elif is_port_range "$port"; then
#         # 端口段：使用fw分类器根据标记分类
#         local mark_id=$(generate_port_range_mark "$port")
#         tc filter add dev $interface protocol ip parent 1:0 prio 1 handle $mark_id fw flowid $class_id 2>/dev/null || true
#
#     else
#         # 单端口：使用u32精确匹配，避免优先级冲突
#         local filter_prio=$((port % 1000 + 1))
#
#         # TCP协议过滤器
#         tc filter add dev $interface protocol ip parent 1:0 prio $filter_prio u32 \
#             match ip protocol 6 0xff match ip sport $port 0xffff flowid $class_id 2>/dev/null || true
#         tc filter add dev $interface protocol ip parent 1:0 prio $filter_prio u32 \
#             match ip protocol 6 0xff match ip dport $port 0xffff flowid $class_id 2>/dev/null || true
#
#         # UDP协议过滤器
#         tc filter add dev $interface protocol ip parent 1:0 prio $((filter_prio + 1000)) u32 \
#             match ip protocol 17 0xff match ip sport $port 0xffff flowid $class_id 2>/dev/null || true
#         tc filter add dev $interface protocol ip parent 1:0 prio $((filter_prio + 1000)) u32 \
#             match ip protocol 17 0xff match ip dport $port 0xffff flowid $class_id 2>/dev/null || true
#     fi
# }
# ==============================================================================

apply_tc_limit() {
    local port=$1
    local total_limit=$2
    local interface=$(get_default_interface)

    tc qdisc add dev $interface root handle 1: htb default 30 2>/dev/null || true
    tc class add dev $interface parent 1: classid 1:1 htb rate 1000mbit 2>/dev/null || true

    local class_id=$(generate_tc_class_id "$port")
    tc class del dev $interface classid $class_id 2>/dev/null || true

    # 计算burst参数以优化性能
    local base_rate=$(parse_tc_rate_to_kbps "$total_limit")
    local burst_bytes=$(calculate_tc_burst "$base_rate")
    local burst_size=$(format_tc_burst "$burst_bytes")

    if ! tc class add dev $interface parent 1:1 classid $class_id htb rate $total_limit ceil $total_limit burst $burst_size 2>/dev/null; then
        echo -e "${RED}设置带宽限制失败，请检查网络设备${NC}" >&2
        return 1
    fi

    if is_port_group "$port"; then
        # 端口组：使用fw分类器根据共享标记分类
        local mark_id=$(generate_port_group_mark "$port")
        tc filter add dev $interface protocol ip parent 1:0 prio 1 handle $mark_id fw flowid $class_id 2>/dev/null || true

    elif is_port_range "$port"; then
        # 端口段：使用fw分类器根据标记分类
        local mark_id=$(generate_port_range_mark "$port")
        tc filter add dev $interface protocol ip parent 1:0 prio 1 handle $mark_id fw flowid $class_id 2>/dev/null || true

    else
        # 单端口：使用u32精确匹配，避免优先级冲突
        local filter_prio=$((port % 1000 + 1))

        # TCP协议过滤器
        tc filter add dev $interface protocol ip parent 1:0 prio $filter_prio u32 \
            match ip protocol 6 0xff match ip sport $port 0xffff flowid $class_id 2>/dev/null || true
        tc filter add dev $interface protocol ip parent 1:0 prio $filter_prio u32 \
            match ip protocol 6 0xff match ip dport $port 0xffff flowid $class_id 2>/dev/null || true

        # UDP协议过滤器
        tc filter add dev $interface protocol ip parent 1:0 prio $((filter_prio + 1000)) u32 \
            match ip protocol 17 0xff match ip sport $port 0xffff flowid $class_id 2>/dev/null || true
        tc filter add dev $interface protocol ip parent 1:0 prio $((filter_prio + 1000)) u32 \
            match ip protocol 17 0xff match ip dport $port 0xffff flowid $class_id 2>/dev/null || true
    fi
}

# 删除TC带宽限制
remove_tc_limit() {
    local port=$1
    local interface=$(get_default_interface)

    local class_id=$(generate_tc_class_id "$port")

    if is_port_group "$port"; then
        # 端口组：删除基于标记的过滤器
        local mark_id=$(generate_port_group_mark "$port")
        local mark_hex=$(printf '0x%x' "$mark_id")
        
        tc filter del dev $interface protocol ip parent 1:0 prio 1 handle $mark_hex fw 2>/dev/null || true
        tc filter del dev $interface protocol ip parent 1:0 prio 1 handle $mark_id fw 2>/dev/null || true

    elif is_port_range "$port"; then
        # 端口段：删除基于标记的过滤器
        local mark_id=$(generate_port_range_mark "$port")
        local mark_hex=$(printf '0x%x' "$mark_id")
        
        tc filter del dev $interface protocol ip parent 1:0 prio 1 handle $mark_hex fw 2>/dev/null || true
        tc filter del dev $interface protocol ip parent 1:0 prio 1 handle $mark_id fw 2>/dev/null || true
    else
        # 单端口：删除u32精确匹配过滤器
        local filter_prio=$((port % 1000 + 1))

        tc filter del dev $interface protocol ip parent 1:0 prio $filter_prio u32 \
            match ip protocol 6 0xff match ip sport $port 0xffff 2>/dev/null || true
        tc filter del dev $interface protocol ip parent 1:0 prio $filter_prio u32 \
            match ip protocol 6 0xff match ip dport $port 0xffff 2>/dev/null || true

        tc filter del dev $interface protocol ip parent 1:0 prio $((filter_prio + 1000)) u32 \
            match ip protocol 17 0xff match ip sport $port 0xffff 2>/dev/null || true
        tc filter del dev $interface protocol ip parent 1:0 prio $((filter_prio + 1000)) u32 \
            match ip protocol 17 0xff match ip dport $port 0xffff 2>/dev/null || true
    fi

    tc class del dev $interface classid $class_id 2>/dev/null || true
}



manage_traffic_reset() {
    while true; do
        echo -e "${BLUE}流量重置管理${NC}"
        echo "1. 重置流量月重置日设置"
        echo "2. 立即重置"
        echo "0. 返回主菜单"
        echo
        read -p "请选择操作 [0-2]: " choice

        case $choice in
            1) set_reset_day ;;
            2) immediate_reset ;;
            0) return ;;
            *) echo -e "${RED}无效选择，请输入0-2${NC}"; sleep 1 ;;
        esac
    done
}

set_reset_day() {
    echo -e "${BLUE}=== 重置流量月重置日设置 ===${NC}"
    echo

    local active_ports=($(get_active_ports))

    if ! show_port_list; then
        sleep 2
        manage_traffic_reset
        return
    fi
    echo

    read -p "请选择要设置重置日期的端口（多端口使用逗号,分隔） [1-${#active_ports[@]}]: " choice_input

    local valid_choices=()
    local ports_to_set=()
    parse_multi_choice_input "$choice_input" "${#active_ports[@]}" valid_choices

    for choice in "${valid_choices[@]}"; do
        local port=${active_ports[$((choice-1))]}
        ports_to_set+=("$port")
    done

    if [ ${#ports_to_set[@]} -eq 0 ]; then
        echo -e "${RED}没有有效的端口可设置${NC}"
        sleep 2
        set_reset_day
        return
    fi

    echo
    local port_list=$(IFS=','; echo "${ports_to_set[*]}")
    echo "为端口 $port_list 设置月重置日期:"
    echo "请输入月重置日（多端口使用逗号,分隔）(0代表不重置):"
    echo "(只输入一个值，应用到所有端口):"
    read -p "月重置日 [0-31]: " reset_day_input

    local RESET_DAYS=()
    parse_comma_separated_input "$reset_day_input" RESET_DAYS

    expand_single_value_to_array RESET_DAYS ${#ports_to_set[@]}
    if [ ${#RESET_DAYS[@]} -ne ${#ports_to_set[@]} ]; then
        echo -e "${RED}重置日期数量与端口数量不匹配${NC}"
        sleep 2
        set_reset_day
        return
    fi

    local success_count=0
    for i in "${!ports_to_set[@]}"; do
        local port="${ports_to_set[$i]}"
        local reset_day=$(echo "${RESET_DAYS[$i]}" | tr -d ' ')

        if ! [[ "$reset_day" =~ ^[0-9]+$ ]] || [ "$reset_day" -lt 0 ] || [ "$reset_day" -gt 31 ]; then
            echo -e "${RED}端口 $port 重置日期无效: $reset_day，必须是0-31之间的数字${NC}"
            continue
        fi

        if [ "$reset_day" = "0" ]; then
            # 删除reset_day字段并移除定时任务
            jq "del(.ports.\"$port\".quota.reset_day)" "$CONFIG_FILE" > "${CONFIG_FILE}.tmp" && mv "${CONFIG_FILE}.tmp" "$CONFIG_FILE"
            remove_port_auto_reset_cron "$port"
            echo -e "${GREEN}端口 $port 已取消自动重置${NC}"
        else
            update_config ".ports.\"$port\".quota.reset_day = $reset_day"
            setup_port_auto_reset_cron "$port"
            echo -e "${GREEN}端口 $port 月重置日设置成功: 每月${reset_day}日${NC}"
        fi
        
        success_count=$((success_count + 1))
    done

    echo
    echo -e "${GREEN}成功设置 $success_count 个端口的月重置日期${NC}"

    sleep 2
    manage_traffic_reset
}

immediate_reset() {
    echo -e "${BLUE}=== 立即重置 ===${NC}"
    echo

    local active_ports=($(get_active_ports))

    if ! show_port_list; then
        sleep 2
        manage_traffic_reset
        return
    fi
    echo

    read -p "请选择要立即重置的端口（多端口使用逗号,分隔） [1-${#active_ports[@]}]: " choice_input

    # 处理多选择输入
    local valid_choices=()
    local ports_to_reset=()
    parse_multi_choice_input "$choice_input" "${#active_ports[@]}" valid_choices

    for choice in "${valid_choices[@]}"; do
        local port=${active_ports[$((choice-1))]}
        ports_to_reset+=("$port")
    done

    if [ ${#ports_to_reset[@]} -eq 0 ]; then
        echo -e "${RED}没有有效的端口可重置${NC}"
        sleep 2
        immediate_reset
        return
    fi

    # 显示要重置的端口及其当前流量
    echo
    echo "将重置以下端口的流量统计:"
    local total_all_traffic=0
    for port in "${ports_to_reset[@]}"; do
        local traffic_data=($(get_port_traffic "$port"))
        local input_bytes=${traffic_data[0]}
        local output_bytes=${traffic_data[1]}
        local billing_mode=$(jq -r ".ports.\"$port\".billing_mode // \"double\"" "$CONFIG_FILE")
        local total_bytes=$(calculate_total_traffic "$input_bytes" "$output_bytes" "$billing_mode")
        local total_formatted=$(format_bytes $total_bytes)

        echo "  端口 $port: $total_formatted"
        total_all_traffic=$((total_all_traffic + total_bytes))
    done

    echo
    echo "总计流量: $(format_bytes $total_all_traffic)"
    echo -e "${YELLOW}警告：重置后流量统计将清零，此操作不可撤销！${NC}"
    read -p "确认重置选定端口的流量统计? [y/N]: " confirm

    if [[ "$confirm" =~ ^[Yy]$ ]]; then
        local reset_count=0
        for port in "${ports_to_reset[@]}"; do
            # 获取当前流量用于记录
            local traffic_data=($(get_port_traffic "$port"))
            local input_bytes=${traffic_data[0]}
            local output_bytes=${traffic_data[1]}
            local billing_mode=$(jq -r ".ports.\"$port\".billing_mode // \"double\"" "$CONFIG_FILE")
            local total_bytes=$(calculate_total_traffic "$input_bytes" "$output_bytes" "$billing_mode")

            reset_port_nftables_counters "$port"
            record_reset_history "$port" "$total_bytes"

            echo -e "${GREEN}端口 $port 流量统计重置成功${NC}"
            reset_count=$((reset_count + 1))
        done

        echo
        echo -e "${GREEN}成功重置 $reset_count 个端口的流量统计${NC}"
        echo "重置前总流量: $(format_bytes $total_all_traffic)"
    else
        echo "取消重置"
    fi

    sleep 3
    manage_traffic_reset
}

# 自动重置指定端口的流量
auto_reset_port() {
    local port="$1"

    local traffic_data=($(get_port_traffic "$port"))
    local input_bytes=${traffic_data[0]}
    local output_bytes=${traffic_data[1]}
    local billing_mode=$(jq -r ".ports.\"$port\".billing_mode // \"double\"" "$CONFIG_FILE")
    local total_bytes=$(calculate_total_traffic "$input_bytes" "$output_bytes" "$billing_mode")

    reset_port_nftables_counters "$port"
    record_reset_history "$port" "$total_bytes"

    log_notification "端口 $port 自动重置完成，重置前流量: $(format_bytes $total_bytes)"

    echo "端口 $port 自动重置完成"
}

# 重置端口nftables计数器和配额
reset_port_nftables_counters() {
    local port=$1
    local table_name=$(jq -r '.nftables.table_name' "$CONFIG_FILE")
    local family=$(jq -r '.nftables.family' "$CONFIG_FILE")

    # 根据端口类型确定名称
    local port_safe
    if is_port_group "$port"; then
        port_safe=$(generate_port_group_safe_name "$port")
    elif is_port_range "$port"; then
        port_safe=$(echo "$port" | tr '-' '_')
    else
        port_safe="$port"
    fi

    # 重置计数器
    nft reset counter $family $table_name "port_${port_safe}_in" >/dev/null 2>&1 || true
    nft reset counter $family $table_name "port_${port_safe}_out" >/dev/null 2>&1 || true
    # 重置配额使用量，保持限制不变
    nft reset quota $family $table_name "port_${port_safe}_quota" >/dev/null 2>&1 || true
}

record_reset_history() {
    local port=$1
    local traffic_bytes=$2
    local timestamp=$(get_beijing_time +%s)
    local history_file="$CONFIG_DIR/reset_history.log"

    mkdir -p "$(dirname "$history_file")"

    echo "$timestamp|$port|$traffic_bytes" >> "$history_file"

    # 限制历史记录条数，避免文件过大
    if [ $(wc -l < "$history_file" 2>/dev/null || echo 0) -gt 100 ]; then
        tail -n 100 "$history_file" > "${history_file}.tmp"
        mv "${history_file}.tmp" "$history_file"
    fi
}


manage_configuration() {
    while true; do
        echo -e "${BLUE}=== 配置文件管理 ===${NC}"
        echo
        echo "请选择操作:"
        echo "1. 导出配置包"
        echo "2. 导入配置包"
        echo "0. 返回上级菜单"
        echo
        read -p "请输入选择 [0-2]: " choice

        case $choice in
            1) export_config ;;
            2) import_config ;;
            0) return ;;
            *) echo -e "${RED}无效选择，请输入0-2${NC}"; sleep 1 ;;
        esac
    done
}

export_config() {
    echo -e "${BLUE}=== 导出配置包 ===${NC}"
    echo

    # 检查配置目录是否存在
    if [ ! -d "$CONFIG_DIR" ]; then
        echo -e "${RED}错误：配置目录不存在${NC}"
        sleep 2
        manage_configuration
        return
    fi

    # 生成时间戳文件名
    local timestamp=$(get_beijing_time +%Y%m%d-%H%M%S)
    local backup_name="port-traffic-dog-config-${timestamp}.tar.gz"
    local backup_path="/root/${backup_name}"

    echo "正在导出配置包..."
    echo "包含内容："
    echo "  - 主配置文件 (config.json)"
    echo "  - 端口监控数据"
    echo "  - 通知配置"
    echo "  - 日志文件"
    echo

    # 创建临时目录用于打包
    local temp_dir=$(mktemp -d)
    local package_dir="$temp_dir/port-traffic-dog-config"

    # 复制配置目录到临时位置
    cp -r "$CONFIG_DIR" "$package_dir"

    # 生成配置包信息文件
    cat > "$package_dir/package_info.txt" << EOF
端口流量狗配置包信息
===================
导出时间: $(get_beijing_time '+%Y-%m-%d %H:%M:%S')
脚本版本: $SCRIPT_VERSION
配置目录: $CONFIG_DIR
导出主机: $(hostname)
包含端口: $(jq -r '.ports | keys | join(", ")' "$CONFIG_FILE" 2>/dev/null || echo "无")
EOF

    # 打包配置
    cd "$temp_dir"
    tar -czf "$backup_path" port-traffic-dog-config/ 2>/dev/null

    # 清理临时目录
    rm -rf "$temp_dir"

    if [ -f "$backup_path" ]; then
        local file_size=$(du -h "$backup_path" | cut -f1)
        echo -e "${GREEN}✅ 配置包导出成功${NC}"
        echo
        echo "📦 文件信息："
        echo "  文件名: $backup_name"
        echo "  路径: $backup_path"
        echo "  大小: $file_size"
    else
        echo -e "${RED}❌ 配置包导出失败${NC}"
    fi

    echo
    read -p "按回车键返回..."
    manage_configuration
}

# 导入配置包
import_config() {
    echo -e "${BLUE}=== 导入配置包 ===${NC}"
    echo

    echo "请输入配置包路径 (支持绝对路径或相对路径):"
    echo "例如: /root/port-traffic-dog-config-20241227-143022.tar.gz"
    echo
    read -p "配置包路径: " package_path

    # 检查输入是否为空
    if [ -z "$package_path" ]; then
        echo -e "${RED}错误：路径不能为空${NC}"
        sleep 2
        import_config
        return
    fi

    # 检查文件是否存在
    if [ ! -f "$package_path" ]; then
        echo -e "${RED}错误：配置包文件不存在${NC}"
        echo "路径: $package_path"
        sleep 2
        import_config
        return
    fi

    # 检查文件格式
    if [[ ! "$package_path" =~ \.tar\.gz$ ]]; then
        echo -e "${RED}错误：配置包必须是 .tar.gz 格式${NC}"
        sleep 2
        import_config
        return
    fi

    echo
    echo "正在验证配置包..."

    # 创建临时目录用于解压验证
    local temp_dir=$(mktemp -d)

    # 解压到临时目录进行验证
    cd "$temp_dir"
    if ! tar -tzf "$package_path" >/dev/null 2>&1; then
        echo -e "${RED}错误：配置包文件损坏或格式错误${NC}"
        rm -rf "$temp_dir"
        sleep 2
        import_config
        return
    fi

    # 解压配置包
    tar -xzf "$package_path" 2>/dev/null

    # 验证配置包结构
    local config_dir_name=$(ls | head -n1)
    if [ ! -d "$config_dir_name" ]; then
        echo -e "${RED}错误：配置包结构异常${NC}"
        rm -rf "$temp_dir"
        sleep 2
        import_config
        return
    fi

    local extracted_config="$temp_dir/$config_dir_name"

    # 检查必要文件
    if [ ! -f "$extracted_config/config.json" ]; then
        echo -e "${RED}错误：配置包中缺少 config.json 文件${NC}"
        rm -rf "$temp_dir"
        sleep 2
        import_config
        return
    fi

    # 显示配置包信息
    echo -e "${GREEN}✅ 配置包验证通过${NC}"
    echo

    if [ -f "$extracted_config/package_info.txt" ]; then
        echo "📋 配置包信息："
        cat "$extracted_config/package_info.txt"
        echo
    fi

    # 显示将要导入的端口
    local import_ports=$(jq -r '.ports | keys | join(", ")' "$extracted_config/config.json" 2>/dev/null || echo "无")
    echo "📊 包含端口: $import_ports"
    echo

    # 确认导入
    echo -e "${YELLOW}⚠️  警告：导入配置将会：${NC}"
    echo "  1. 停止当前所有端口监控"
    echo "  2. 替换为新的配置"
    echo "  3. 重新应用监控规则"
    echo
    read -p "确认导入配置包? [y/N]: " confirm

    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        echo "取消导入"
        rm -rf "$temp_dir"
        sleep 1
        manage_configuration
        return
    fi

    echo
    echo "开始导入配置..."

    # 1. 停止当前监控
    echo "正在停止当前端口监控..."
    local current_ports=($(get_active_ports 2>/dev/null || true))
    for port in "${current_ports[@]}"; do
        remove_nftables_quota "$port" 2>/dev/null || true
        remove_nftables_rules "$port" 2>/dev/null || true
        remove_tc_limit "$port" 2>/dev/null || true
    done

    # 2. 替换配置
    echo "正在导入新配置..."
    rm -rf "$CONFIG_DIR" 2>/dev/null || true
    mkdir -p "$(dirname "$CONFIG_DIR")"
    cp -r "$extracted_config" "$CONFIG_DIR"

    # 3. 重新应用规则
    echo "正在重新应用监控规则..."

    # 重新初始化nftables
    init_nftables

    # 为每个端口重新应用规则
    local new_ports=($(get_active_ports))
    
    # 先将所有 relay 模式转换为 double
    for port in "${new_ports[@]}"; do
        local billing_mode=$(jq -r ".ports.\"$port\".billing_mode // \"double\"" "$CONFIG_FILE")
        if [ "$billing_mode" = "relay" ]; then
            jq ".ports.\"$port\".billing_mode = \"double\"" "$CONFIG_FILE" > "${CONFIG_FILE}.tmp" && mv "${CONFIG_FILE}.tmp" "$CONFIG_FILE"
            echo "  端口 $port: relay → double"
        fi
    done
    
    for port in "${new_ports[@]}"; do
        # 添加基础监控规则
        add_nftables_rules "$port"

        # 应用配额限制（如果有）
        local quota_enabled=$(jq -r ".ports.\"$port\".quota.enabled // false" "$CONFIG_FILE")
        local monthly_limit=$(jq -r ".ports.\"$port\".quota.monthly_limit // \"unlimited\"" "$CONFIG_FILE")
        if [ "$quota_enabled" = "true" ] && [ "$monthly_limit" != "unlimited" ]; then
            apply_nftables_quota "$port" "$monthly_limit"
        fi

        # 应用带宽限制（如果有）
        local limit_enabled=$(jq -r ".ports.\"$port\".bandwidth_limit.enabled // false" "$CONFIG_FILE")
        local rate_limit=$(jq -r ".ports.\"$port\".bandwidth_limit.rate // \"unlimited\"" "$CONFIG_FILE")
        if [ "$limit_enabled" = "true" ] && [ "$rate_limit" != "unlimited" ]; then
            local limit_lower=$(echo "$rate_limit" | tr '[:upper:]' '[:lower:]')
            local tc_limit
            if [[ "$limit_lower" =~ kbps$ ]]; then
                tc_limit=$(echo "$limit_lower" | sed 's/kbps$/kbit/')
            elif [[ "$limit_lower" =~ mbps$ ]]; then
                tc_limit=$(echo "$limit_lower" | sed 's/mbps$/mbit/')
            elif [[ "$limit_lower" =~ gbps$ ]]; then
                tc_limit=$(echo "$limit_lower" | sed 's/gbps$/gbit/')
            fi
            if [ -n "$tc_limit" ]; then
                apply_tc_limit "$port" "$tc_limit"
            fi
        fi
    done

    echo "正在更新通知模块..."
    download_notification_modules >/dev/null 2>&1 || true

    rm -rf "$temp_dir"

    echo
    echo -e "${GREEN}配置导入完成${NC}"
    echo
    echo "导入结果："
    echo "  导入端口数: ${#new_ports[@]} 个"
    if [ ${#new_ports[@]} -gt 0 ]; then
        echo "  端口列表: $(IFS=','; echo "${new_ports[*]}")"
    fi
    echo
    echo -e "${YELLOW}提示：${NC}"
    echo "  - 所有端口监控规则已重新应用"
    echo "  - 通知配置已恢复"
    echo "  - 历史数据已恢复"

    echo
    read -p "按回车键返回..."
    manage_configuration
}

# 统一下载函数
download_with_sources() {
    local url=$1
    local output_file=$2

    for source in "${DOWNLOAD_SOURCES[@]}"; do
        local full_url="${source}${url}"

        if [ -z "$source" ]; then
            echo -e "${YELLOW}尝试官方源下载...${NC}"
            full_url="$url"
        else
            echo -e "${YELLOW}尝试加速源: ${source}${NC}"
        fi

        if curl -sL --connect-timeout $SHORT_CONNECT_TIMEOUT --max-time $SHORT_MAX_TIMEOUT "$full_url" -o "$output_file" 2>/dev/null; then
            if [ -s "$output_file" ]; then
                echo -e "${GREEN}下载成功${NC}"
                return 0
            fi
        fi
        echo -e "${YELLOW}下载失败，尝试下一个源...${NC}"
    done

    echo -e "${RED}所有下载源均失败${NC}"
    return 1
}

# 下载通知模块
download_notification_modules() {
    local notifications_dir="$CONFIG_DIR/notifications"
    local temp_dir=$(mktemp -d)
    local repo_url="https://github.com/zywe03/realm-xwPF/archive/refs/heads/main.zip"
    local new_dir="$temp_dir/realm-xwPF-main/notifications"
    local backup_dir=""

    # 下载解压复制清理：每次都覆盖更新确保版本一致
    if download_with_sources "$repo_url" "$temp_dir/repo.zip" &&
       (cd "$temp_dir" && unzip -q repo.zip) &&
       [ -d "$new_dir" ] &&
       ls "$new_dir"/*.sh >/dev/null 2>&1; then
        if [ -d "$notifications_dir" ]; then
            backup_dir="${notifications_dir}.bak.$(date +%Y%m%d_%H%M%S)"
            mv "$notifications_dir" "$backup_dir" 2>/dev/null || true
        fi

        if mv "$new_dir" "$notifications_dir"; then
            chmod +x "$notifications_dir"/*.sh 2>/dev/null || true
            rm -rf "$temp_dir"
            return 0
        fi

        echo -e "${YELLOW}通知模块更新失败，尝试恢复旧版本${NC}"
        if [ -n "$backup_dir" ] && [ -d "$backup_dir" ]; then
            mv "$backup_dir" "$notifications_dir" 2>/dev/null || true
        fi
    fi

    rm -rf "$temp_dir"
    return 1
}

# 安装(更新)脚本
install_update_script() {
    echo -e "${BLUE}安装依赖(更新)脚本${NC}"
    echo "────────────────────────────────────────────────────────"

    echo -e "${YELLOW}正在检查系统依赖...${NC}"
    check_dependencies true

    echo -e "${YELLOW}正在下载最新版本...${NC}"

    local temp_file=$(mktemp)

    if download_with_sources "$SCRIPT_URL" "$temp_file"; then
        if [ -s "$temp_file" ] && grep -q "端口流量狗" "$temp_file" 2>/dev/null; then
            mv "$temp_file" "$SCRIPT_PATH"
            chmod +x "$SCRIPT_PATH"

            create_shortcut_command

            echo -e "${YELLOW}正在更新通知模块...${NC}"
            download_notification_modules >/dev/null 2>&1 || true

            echo -e "${GREEN}✅ 依赖检查完成${NC}"
            echo -e "${GREEN}✅ 脚本更新完成${NC}"
            echo -e "${GREEN}✅ 通知模块已更新${NC}"
        else
            echo -e "${RED}❌ 下载文件验证失败${NC}"
            rm -f "$temp_file"
        fi
    else
        echo -e "${RED}❌ 下载失败，请检查网络连接${NC}"
        rm -f "$temp_file"
    fi

    echo "────────────────────────────────────────────────────────"
    read -p "按回车键返回..."
    show_main_menu
}

create_shortcut_command() {
    if [ ! -f "/usr/local/bin/$SHORTCUT_COMMAND" ]; then
        cat > "/usr/local/bin/$SHORTCUT_COMMAND" << EOF
#!/bin/bash
exec bash "$SCRIPT_PATH" "\$@"
EOF
        chmod +x "/usr/local/bin/$SHORTCUT_COMMAND" 2>/dev/null || true
        echo -e "${GREEN}快捷命令 '$SHORTCUT_COMMAND' 创建成功${NC}"
    fi
}

# 检查端口规则是否存在 (通过Counter判断)
is_port_rules_exist() {
    local port=$1
    local table_name=$(jq -r '.nftables.table_name' "$CONFIG_FILE" 2>/dev/null || echo "port_traffic_monitor")
    local family=$(jq -r '.nftables.family' "$CONFIG_FILE" 2>/dev/null || echo "inet")
    local port_safe
    
    # 依赖 generate_port_group_safe_name 等函数，确保它们在此之前已定义 (它们在文件前面，通常没问题)
    if is_port_group "$port"; then
         port_safe=$(generate_port_group_safe_name "$port")
    elif is_port_range "$port"; then
         port_safe=$(echo "$port" | tr '-' '_')
    else
         port_safe="$port"
    fi
    
    nft list counter $family $table_name "port_${port_safe}_in" >/dev/null 2>&1
}

# 封锁端口流量 (用于过期停机)
# 原理：创建一个限制为0的配额对象，利用 quota over 机制实现阻断
# 优势：与 "超量限制" 逻辑保持一致，复用现有架构，兼容性更好
block_port_traffic() {
    local port=$1
    
    # 确保基础链存在
    init_nftables
    local table_name=$(jq -r '.nftables.table_name' "$CONFIG_FILE" 2>/dev/null || echo "port_traffic_monitor")
    local family=$(jq -r '.nftables.family' "$CONFIG_FILE" 2>/dev/null || echo "inet")
    local port_safe
    
    if is_port_group "$port"; then
         port_safe=$(generate_port_group_safe_name "$port")
    elif is_port_range "$port"; then
         port_safe=$(echo "$port" | tr '-' '_')
    else
         port_safe="$port"
    fi
    
    # 1. 先清理旧规则 (包括旧的 quota 规则)
    remove_nftables_rules "$port"
    
    echo "正在封锁端口 $port 流量..."
    
    # 2. 创建一个名为 "_block_quota" 的特殊配额
    # 设定限制为 0 byte -> 立即触发 over
    local quota_name="port_${port_safe}_block_quota"
    
    # 确保清理旧对象
    nft delete quota $family $table_name $quota_name 2>/dev/null || true
    
    # 创建"立即超量"的配额对象
    # 注意：不能在 add 时指定 used 值，否则会报 Invalid argument。
    # 使用 over 0 bytes，第一个包就会触发限制，达到封锁效果。
    if ! nft add quota $family $table_name $quota_name { over 0 bytes\; } 2>/dev/null; then
         # 兼容不带分号的格式
         nft add quota $family $table_name $quota_name { over 0 bytes } 2>/dev/null || true
    fi
    
    # 3. 插入规则：引用该配额对象，动作为 drop
    # 因为复用了 quota 机制，所以不需要 comment 也能被 remove_nftables_rules 的 grep 识别 (只要名字里含 port_safe)
    # 也不需要担心语法兼容性，因为这是标准 quota 用法
    
    # 针对不同链插入规则 (Input/Forward/Prerouting)
    # 需要处理端口组、端口段、单端口三种情况
    if is_port_group "$port"; then
        # 端口组：需要为每个端口单独添加规则（nftables不支持 tcp dport 101,102,105 这种逗号语法）
        local group_ports=($(get_group_ports "$port"))
        for single_port in "${group_ports[@]}"; do
            for chain in input forward prerouting; do
                nft insert rule $family $table_name $chain tcp dport $single_port quota name "$quota_name" drop 2>/dev/null || true
                nft insert rule $family $table_name $chain udp dport $single_port quota name "$quota_name" drop 2>/dev/null || true
            done
            for chain in output forward; do
                nft insert rule $family $table_name $chain tcp sport $single_port quota name "$quota_name" drop 2>/dev/null || true
                nft insert rule $family $table_name $chain udp sport $single_port quota name "$quota_name" drop 2>/dev/null || true
            done
        done
    else
        # 端口段和单端口：可以直接使用（nftables原生支持端口段语法如 100-200）
        for chain in input forward prerouting; do
            nft insert rule $family $table_name $chain tcp dport $port quota name "$quota_name" drop 2>/dev/null || true
            nft insert rule $family $table_name $chain udp dport $port quota name "$quota_name" drop 2>/dev/null || true
        done
        
        for chain in output forward; do
            nft insert rule $family $table_name $chain tcp sport $port quota name "$quota_name" drop 2>/dev/null || true
            nft insert rule $family $table_name $chain udp sport $port quota name "$quota_name" drop 2>/dev/null || true
        done
    fi
    
    # 再次尝试在 ip raw 表封锁 (针对 Docker 端口映射的强力补丁)
    # 许多 Docker 流量不走 inet filter INPUT，必须在 raw PREROUTING 拦截
    local raw_table="raw"
    local raw_chain="PREROUTING"
    
    # 检查 ip raw 表是否存在，不存在则不强求
    if nft list table ip $raw_table >/dev/null 2>&1; then
        # 在 raw 表也加一条规则 (这里不能用 quota 对象，因为 quota 在 inet 表里)
        # 没办法引用 inet 表的 quota，只能用纯规则。为了兼容性，不加 comment，纯写 drop
        # 这条规则可能不好删，所以作为“尽力而为”的补充，或者我们只依赖 inet 的 prerouting
        
        # 鉴于之前 raw 表测试里有 drop，说明 raw 表是好使的。
        # 我们尝试在 inet 表的 prerouting 链里拦截 (它 priority -150，比 docker nat -100 早，应该能拦住)
        :
    fi
}

# 检查所有端口是否过期 (用于每日Cron)
check_all_ports_expiration() {
    local active_ports=($(get_active_ports))
    local today=$(get_beijing_time +%Y-%m-%d)
    
    for port in "${active_ports[@]}"; do
        local expire_date=$(jq -r ".ports.\"$port\".expiration_date // \"\"" "$CONFIG_FILE")
        
        # 只有设置了到期日才检查
        if [ -n "$expire_date" ] && [ "$expire_date" != "null" ]; then
            local user_email=$(jq -r ".ports.\"$port\".email // \"\"" "$CONFIG_FILE")
            
            # 1. 到期提醒：到期前3天窗口内仅发送一次（若当天未配置邮箱，允许后续补发）
            local warning_start=$(get_beijing_time -d "$expire_date - 3 days" +%Y-%m-%d 2>/dev/null || date -d "$expire_date - 3 days" +%Y-%m-%d 2>/dev/null || echo "")
            if [ -n "$warning_start" ] && [[ "$today" > "$warning_start" || "$today" == "$warning_start" ]] && [[ "$today" < "$expire_date" ]]; then
                local last_warning_target=$(jq -r ".ports.\"$port\".last_warning_target_date // \"\"" "$CONFIG_FILE")
                if [ "$last_warning_target" != "$expire_date" ]; then
                    # 发送邮件预警
                    if [ -n "$user_email" ] && [ "$user_email" != "null" ]; then
                        log_notification "[租期预警] 端口 $port 将在近期 ($expire_date) 到期，发送提醒。"
                        local title="【租期提醒】端口 $port 服务即将到期"
                        local body="<h1>⚠️ 续费提醒</h1>
                                    <p>您好，</p>
                                    <p>您租用的端口 <strong>$port</strong> 即将到期 (<strong>$expire_date</strong>)。</p>
                                    <p>请及时联系管理员进行续费，以免影响使用。</p>"
                        if send_email_notification "$title" "$body" "$user_email" >/dev/null 2>&1; then
                             # 发送成功后，记录本次到期周期已发送
                             update_config ".ports.\"$port\".last_warning_target_date = \"$expire_date\" |
                                 .ports.\"$port\".last_warning_date = \"$today\""
                        fi
                    fi
                fi
            fi

            # 2. 检查是否过期 (停机)
            if [[ "$today" > "$expire_date" ]]; then
                echo "端口 $port 已过期 ($expire_date)，执行停机..."
                # 只有当规则还存在时才记录日志，避免每天重复刷屏
                if is_port_rules_exist "$port"; then
                    log_notification "[租期管理] 端口 $port 租期 (${expire_date}) 已截止，执行到期停机"
                    
                    # 发送邮件通知 (停机通知)
                    if [ -n "$user_email" ] && [ "$user_email" != "null" ]; then
                        local title="【服务暂停】端口 $port 已到期停机"
                        local body="<h1>⛔ 服务已暂停</h1>
                                    <p>您好，</p>
                                    <p>您租用的端口 <strong>$port</strong> 服务租期 ($expire_date) 已结束。</p>
                                    <p>该端口目前已被暂停服务。如需恢复使用，请联系管理员续费。</p>"
                        send_email_notification "$title" "$body" "$user_email" >/dev/null 2>&1
                    fi
                fi
                
                # 改为执行强制封锁 (先删后封)
                block_port_traffic "$port"
                remove_tc_limit "$port"
            fi
        fi
    done
}

# 当前流量狗配置检测 (完整详细版)
diagnose_port_config() {
    clear
    echo -e "${BLUE}==================== 开始完整检测 ====================${NC}"
    echo
    
    local table_name=$(jq -r '.nftables.table_name' "$CONFIG_FILE")
    local family=$(jq -r '.nftables.family' "$CONFIG_FILE")
    local active_ports=($(get_active_ports))
    
    echo -e "表名: ${GREEN}$table_name${NC} | 协议族: ${GREEN}$family${NC}"
    echo
    
    if [ ${#active_ports[@]} -eq 0 ]; then
        echo -e "${YELLOW}暂无监控端口${NC}"
        echo
        read -p "按回车键返回..." 
        return
    fi
    
    local problem_ports=()
    local ok_count=0
    
    # 问题端口分类统计
    local ports_no_email=()
    local ports_no_lease=()
    local ports_no_d3=()
    local ports_expired=()
    local ports_blocked=()
    local ports_rules_insufficient=()
    
    # 性能优化: 预先获取一次所有规则
    local all_rules=$(nft -a list table $family $table_name 2>/dev/null)
    
    for port in "${active_ports[@]}"; do
        echo -e "${BLUE}==========================================${NC}"
        echo -e "${BLUE}检测端口/端口组: ${GREEN}$port${NC}"
        echo -e "${BLUE}==========================================${NC}"
        
        # 1. 基本信息
        local port_safe=$(echo "$port" | tr ',' '_' | tr '-' '_')
        local remark=$(jq -r ".ports.\"$port\".remark // \"无备注\"" "$CONFIG_FILE")
        local quota_limit=$(jq -r ".ports.\"$port\".quota.monthly_limit // \"unlimited\"" "$CONFIG_FILE")
        local bandwidth_enabled=$(jq -r ".ports.\"$port\".bandwidth_limit.enabled // false" "$CONFIG_FILE")
        local billing_mode_raw=$(jq -r ".ports.\"$port\".billing_mode // \"double\"" "$CONFIG_FILE")
        
        # 计费模式友好显示
        local billing_mode_display
        case "$billing_mode_raw" in
            "double"|"relay") billing_mode_display="双向统计 (入+出)×2" ;;
            "single") billing_mode_display="仅出站 出站×2" ;;
            "premium") billing_mode_display="CN Premium (入+出)×1" ;;
            *) billing_mode_display="$billing_mode_raw" ;;
        esac
        
        echo "备注: $remark"
        echo "计费模式: $billing_mode_display"
        echo "配额限制: $quota_limit"
        echo "带宽限制: $bandwidth_enabled"
        echo
        
        # === 新增检测项 ===
        
        local expire_date=$(jq -r ".ports.\"$port\".expiration_date // \"\"" "$CONFIG_FILE")

        # 通知配置检查
        echo -e "${YELLOW}[通知配置检查]${NC}"
        local user_email=$(jq -r ".ports.\"$port\".email // \"\"" "$CONFIG_FILE")
        if [ -n "$user_email" ] && [ "$user_email" != "null" ]; then
            echo -e "  用户邮箱: ${GREEN}$user_email ✅${NC}"
        else
            echo -e "  用户邮箱: ${YELLOW}⚠️ 未配置${NC} (到期/超限通知无法发送给用户)"
            ports_no_email+=("$port")
        fi
        local d3_configured=false
        if [ -n "$user_email" ] && [ "$user_email" != "null" ] && [ -n "$expire_date" ] && [ "$expire_date" != "null" ]; then
            d3_configured=true
        fi
        if [ "$d3_configured" = "true" ]; then
            echo -e "  D-3提醒: ${GREEN}✅ 已配置${NC}"
        else
            echo -e "  D-3提醒: ${YELLOW}⚠️ 未配置${NC}"
            ports_no_d3+=("$port")
        fi
        echo
        
        # 租期状态检查
        echo -e "${YELLOW}[租期状态检查]${NC}"
        if [ -n "$expire_date" ] && [ "$expire_date" != "null" ]; then
            local today=$(get_beijing_time +%Y-%m-%d)
            # 计算剩余天数
            local expire_epoch=$(date -d "$expire_date" +%s 2>/dev/null || echo "0")
            local today_epoch=$(date -d "$today" +%s 2>/dev/null || echo "0")
            if [ "$expire_epoch" -gt 0 ] && [ "$today_epoch" -gt 0 ]; then
                local diff_days=$(( (expire_epoch - today_epoch) / 86400 ))
                
                if [ $diff_days -gt 3 ]; then
                    echo -e "  到期日: ${GREEN}$expire_date (剩余${diff_days}天) ✅${NC}"
                elif [ $diff_days -gt 0 ]; then
                    echo -e "  到期日: ${YELLOW}$expire_date (剩余${diff_days}天) ⚠️${NC}"
                elif [ $diff_days -eq 0 ]; then
                    echo -e "  到期日: ${YELLOW}$expire_date (今天到期!) ⚠️${NC}"
                else
                    local overdue_days=$((-diff_days))
                    echo -e "  到期日: ${RED}$expire_date (已过期${overdue_days}天!) 🔴${NC}"
                    ports_expired+=("$port")
                fi
            else
                echo -e "  到期日: ${YELLOW}$expire_date (日期格式异常) ⚠️${NC}"
            fi
        else
            echo -e "  到期日: ${YELLOW}⚠️ 未设置租期${NC}"
            ports_no_lease+=("$port")
        fi
        echo
        
        # 封锁状态检查
        echo -e "${YELLOW}[封锁状态检查]${NC}"
        local running_status=$(get_port_running_status "$port")
        case "$running_status" in
            "running")
                echo -e "  运行状态: ${GREEN}🟢 正常运行${NC}"
                ;;
            "blocked_expired")
                echo -e "  运行状态: ${RED}🔴 已封锁(租期过期)${NC}"
                ports_blocked+=("$port")
                ;;
            "blocked_quota")
                echo -e "  运行状态: ${RED}🔴 已封锁(配额超限)${NC}"
                ports_blocked+=("$port")
                ;;
            "rate_limited:"*)
                local rate=$(echo "$running_status" | cut -d':' -f2)
                echo -e "  运行状态: ${YELLOW}🟡 限速中 ($rate)${NC}"
                ;;
            *)
                echo -e "  运行状态: ${CYAN}$running_status${NC}"
                ;;
        esac
        echo
        
        # 2. 检查计数器
        echo -e "${YELLOW}[计数器检查]${NC}"
        local counter_ok=true
        local rules_insufficient=false
        if nft list counter $family $table_name "port_${port_safe}_in" &>/dev/null; then
            local counter_in=$(nft list counter $family $table_name "port_${port_safe}_in" 2>/dev/null | grep bytes | awk '{print $4}')
            echo -e "  ${GREEN}✅ 入站计数器存在: $counter_in bytes${NC}"
        else
            echo -e "  ${RED}❌ 入站计数器缺失!${NC}"
            counter_ok=false
        fi
        
        if nft list counter $family $table_name "port_${port_safe}_out" &>/dev/null; then
            local counter_out=$(nft list counter $family $table_name "port_${port_safe}_out" 2>/dev/null | grep bytes | awk '{print $4}')
            echo -e "  ${GREEN}✅ 出站计数器存在: $counter_out bytes${NC}"
        else
            echo -e "  ${RED}❌ 出站计数器缺失!${NC}"
            counter_ok=false
        fi
        echo
        
        # 3. 检查流量统计规则（counter规则）
        echo -e "${YELLOW}[流量统计规则检查]${NC}"
        local counter_rules=$(echo "$all_rules" | grep "counter name \"port_${port_safe}_" | wc -l)
        echo "  counter规则总数: $counter_rules"
        
        # 判断端口类型并计算预期规则数
        local expected_counter_rules=0
        if is_port_group "$port"; then
            local port_type="端口组"
            local group_ports=($(get_group_ports "$port"))
            local port_count=${#group_ports[@]}
            expected_counter_rules=$((port_count * 8))  # 每个端口8条counter规则
            echo "  端口类型: $port_type (包含 $port_count 个端口)"
        elif is_port_range "$port"; then
            local port_type="端口段"
            expected_counter_rules=8
            echo "  端口类型: $port_type"
        else
            local port_type="单端口"
            expected_counter_rules=8
            echo "  端口类型: $port_type"
        fi
        echo "  预期counter规则: $expected_counter_rules 条"
        
        if [ $counter_rules -eq $expected_counter_rules ]; then
            echo -e "  ${GREEN}✅ counter规则完整${NC}"
        else
            echo -e "  ${YELLOW}⚠️  counter规则数量异常 (实际: $counter_rules, 预期: $expected_counter_rules)${NC}"
            rules_insufficient=true
        fi
        echo
        
        # 4. 检查配额规则
        echo -e "${YELLOW}[配额限制规则检查]${NC}"
        local quota_ok=true
        if [ "$quota_limit" != "unlimited" ]; then
            if nft list quota $family $table_name "port_${port_safe}_quota" &>/dev/null; then
                # 解析 quota 输出，格式类似: quota port_xxx_quota { over 100 gbytes used 9254064685 bytes }
                local quota_output=$(nft list quota $family $table_name "port_${port_safe}_quota" 2>/dev/null)
                local quota_used=$(echo "$quota_output" | sed -n 's/.*used \([0-9]*\) bytes.*/\1/p' | head -1)
                [ -z "$quota_used" ] && quota_used="0"
                echo -e "  ${GREEN}✅ 配额对象存在 (已使用: $quota_used bytes)${NC}"
            else
                echo -e "  ${RED}❌ 配额对象缺失!${NC}"
                quota_ok=false
            fi
            
            local quota_drop_rules=$(echo "$all_rules" | grep "quota name \"port_${port_safe}_quota\" drop" | wc -l)
            
            # 获取计费模式以计算正确的预期规则数
            local billing_mode=$(jq -r ".ports.\"$port\".billing_mode // \"double\"" "$CONFIG_FILE")
            
            # 根据计费模式计算单个端口的预期 quota 规则数
            # double/relay: (入+出)×2 = 16条规则
            # premium: (入+出)×1 = 8条规则
            # single: 出站×2 = 8条规则
            local rules_per_port=16
            if [ "$billing_mode" = "single" ] || [ "$billing_mode" = "premium" ]; then
                rules_per_port=8
            fi
            
            local expected_quota_rules=0
            if is_port_group "$port"; then
                expected_quota_rules=$((port_count * rules_per_port))
            else
                expected_quota_rules=$rules_per_port
            fi
            
            echo "  quota drop规则数量: $quota_drop_rules (预期: $expected_quota_rules)"
            
            if [ $quota_drop_rules -eq $expected_quota_rules ]; then
                echo -e "  ${GREEN}✅ quota规则完整${NC}"
            else
                echo -e "  ${YELLOW}⚠️  quota规则数量异常${NC}"
                quota_ok=false
                rules_insufficient=true
            fi
            
            # 5. 规则类型验证（入站/出站规则是否符合计费模式）
            echo
            echo -e "${YELLOW}[规则类型验证]${NC}"
            local inbound_quota_rules=$(echo "$all_rules" | grep "quota name \"port_${port_safe}_quota\" drop" | grep -c "dport" 2>/dev/null || echo "0")
            inbound_quota_rules=$(echo "$inbound_quota_rules" | tr -d '\n\r ')
            local outbound_quota_rules=$(echo "$all_rules" | grep "quota name \"port_${port_safe}_quota\" drop" | grep -c "sport" 2>/dev/null || echo "0")
            outbound_quota_rules=$(echo "$outbound_quota_rules" | tr -d '\n\r ')
            echo "  入站quota规则: $inbound_quota_rules 条"
            echo "  出站quota规则: $outbound_quota_rules 条"
            
            # 计算预期规则数（端口组需要乘以端口数量）
            local multiplier=1
            if is_port_group "$port"; then
                multiplier=$port_count
            fi
            
            local type_ok=true
            case "$billing_mode" in
                "double"|"relay")
                    # 每个端口应该有入站8条和出站8条
                    local expected_in=$((8 * multiplier))
                    local expected_out=$((8 * multiplier))
                    if [ "$inbound_quota_rules" -eq "$expected_in" ] && [ "$outbound_quota_rules" -eq "$expected_out" ]; then
                        echo -e "  ${GREEN}✅ 规则类型正确 (入站${expected_in}+出站${expected_out})${NC}"
                    else
                        echo -e "  ${YELLOW}⚠️  规则类型异常 (预期: 入站${expected_in}+出站${expected_out})${NC}"
                        type_ok=false
                    fi
                    ;;
                "premium")
                    # 每个端口应该有入站4条和出站4条
                    local expected_in=$((4 * multiplier))
                    local expected_out=$((4 * multiplier))
                    if [ "$inbound_quota_rules" -eq "$expected_in" ] && [ "$outbound_quota_rules" -eq "$expected_out" ]; then
                        echo -e "  ${GREEN}✅ 规则类型正确 (入站${expected_in}+出站${expected_out})${NC}"
                    else
                        echo -e "  ${YELLOW}⚠️  规则类型异常 (预期: 入站${expected_in}+出站${expected_out})${NC}"
                        type_ok=false
                    fi
                    ;;
                "single")
                    # 每个端口应该只有出站8条
                    local expected_out=$((8 * multiplier))
                    if [ "$inbound_quota_rules" -eq 0 ] && [ "$outbound_quota_rules" -eq "$expected_out" ]; then
                        echo -e "  ${GREEN}✅ 规则类型正确 (仅出站${expected_out})${NC}"
                    else
                        echo -e "  ${YELLOW}⚠️  规则类型异常 (预期: 仅出站${expected_out})${NC}"
                        type_ok=false
                    fi
                    ;;
            esac
            
            if [ "$type_ok" = false ]; then
                quota_ok=false
            fi
            
            # 6. 流量一致性验证（counter计算值 vs quota used值）
            echo
            echo -e "${YELLOW}[流量一致性验证]${NC}"
            if [ -n "$counter_in" ] && [ -n "$counter_out" ]; then
                local calculated_total=$(calculate_total_traffic "$counter_in" "$counter_out" "$billing_mode")
                local calculated_formatted=$(format_bytes $calculated_total)
                local quota_used_formatted=$(format_bytes $quota_used)
                echo "  counter计算总流量: $calculated_formatted"
                echo "  quota已使用流量: $quota_used_formatted"
                
                # 允许一定误差（流量在不断增加，可能有微小差异）
                local diff=$((calculated_total - quota_used))
                [ $diff -lt 0 ] && diff=$((-diff))
                local tolerance=$((calculated_total / 100))  # 1%误差容忍
                [ $tolerance -lt 1048576 ] && tolerance=1048576  # 最小1MB误差容忍
                
                if [ $diff -le $tolerance ]; then
                    echo -e "  ${GREEN}✅ 流量数据一致${NC}"
                else
                    local diff_formatted=$(format_bytes $diff)
                    echo -e "  ${YELLOW}⚠️  流量数据差异: $diff_formatted (可能需要重新设置配额以同步)${NC}"
                fi
            fi
            
            # 7. 配额限制值验证
            echo
            echo -e "${YELLOW}[配额限制值验证]${NC}"
            local quota_limit_from_nft=$(echo "$quota_output" | sed -n 's/.*over \([0-9]*\) \([a-z]*\)bytes.*/\1 \2/p' | head -1)
            local config_limit_bytes=$(parse_size_to_bytes "$quota_limit")
            echo "  配置限制: $quota_limit ($config_limit_bytes bytes)"
            if [ -n "$quota_limit_from_nft" ]; then
                local nft_number=$(echo "$quota_limit_from_nft" | awk '{print $1}')
                local nft_unit=$(echo "$quota_limit_from_nft" | awk '{print $2}')
                local nft_bytes=0
                case "$nft_unit" in
                    "") nft_bytes=$nft_number ;;
                    "k") nft_bytes=$((nft_number * 1024)) ;;
                    "m") nft_bytes=$((nft_number * 1048576)) ;;
                    "g") nft_bytes=$((nft_number * 1073741824)) ;;
                    "t") nft_bytes=$((nft_number * 1099511627776)) ;;
                esac
                echo "  nftables限制: ${nft_number}${nft_unit}bytes ($nft_bytes bytes)"
                
                if [ "$nft_bytes" -eq "$config_limit_bytes" ]; then
                    echo -e "  ${GREEN}✅ 配额限制值一致${NC}"
                else
                    echo -e "  ${YELLOW}⚠️  配额限制值不一致 (需要重新设置配额)${NC}"
                fi
            fi
        else
            echo -e "  ${CYAN}⏭️  无配额限制，跳过检查${NC}"
        fi
        echo

        if [ "$rules_insufficient" = "true" ]; then
            ports_rules_insufficient+=("$port")
        fi

        # 判断整体状态
        if [ "$counter_ok" = false ] || [ "$quota_ok" = false ]; then
            problem_ports+=("$port")
        else
            ok_count=$((ok_count + 1))
        fi
        
        echo
    done
    
    # 显示汇总结果
    echo -e "${BLUE}==================== 检测汇总 ====================${NC}"
    echo
    echo "检测端口数: ${#active_ports[@]}"
    echo -e "正常端口数: ${GREEN}$ok_count${NC}"
    
    if [ ${#problem_ports[@]} -gt 0 ]; then
        echo -e "异常端口数: ${RED}${#problem_ports[@]}${NC}"
        echo -e "异常端口: ${RED}${problem_ports[*]}${NC}"
        echo
        echo -e "${BLUE}修复建议:${NC}"
        echo "1. 对于配额规则缺失: 进入\"端口限制设置管理\" -> \"设置端口流量配额\" -> 重新设置配额"
        echo "2. 对于计数器缺失: 需要删除端口后重新添加"
    fi
    
    echo
    
    # ========== 全局配置检查 ==========
    echo -e "${BLUE}==================== 全局配置检查 ====================${NC}"
    echo
    
    # 每日检查任务
    if crontab -l 2>/dev/null | grep -q "端口流量狗每日检查"; then
        echo -e "  每日租期检查任务: ${GREEN}✅ 已配置${NC}"
    else
        echo -e "  每日租期检查任务: ${RED}❌ 未配置${NC} (租期到期自动停机功能可能无法工作)"
    fi
    
    # 自动备份
    local backup_enabled=$(jq -r '.auto_backup_enabled // false' "$BACKUP_CONFIG_FILE" 2>/dev/null || echo "false")
    if [ "$backup_enabled" = "true" ]; then
        local last_backup=$(jq -r '.last_backup_time // ""' "$BACKUP_CONFIG_FILE" 2>/dev/null)
        echo -e "  自动备份: ${GREEN}✅ 已开启${NC}"
    else
        echo -e "  自动备份: ${YELLOW}⚠️ 未开启${NC}"
    fi
    
    # 邮件通知
    local email_enabled=$(jq -r '.notifications.email.enabled // false' "$CONFIG_FILE")
    local api_key=$(jq -r '.notifications.email.resend_api_key // ""' "$CONFIG_FILE")
    if [ "$email_enabled" = "true" ] && [ -n "$api_key" ] && [ "$api_key" != "null" ]; then
        echo -e "  邮件通知: ${GREEN}✅ 已配置${NC}"
    else
        echo -e "  邮件通知: ${YELLOW}⚠️ 未配置${NC}"
    fi
    
    echo
    
    # ========== 问题端口汇总 ==========
    echo -e "${BLUE}==================== 问题端口汇总 ====================${NC}"
    echo
    
    local has_issues=false
    
    if [ ${#ports_no_email[@]} -gt 0 ]; then
        echo -e "  未配置邮箱的端口: ${YELLOW}${#ports_no_email[@]}个${NC} - ${ports_no_email[*]}"
        has_issues=true
    else
        echo -e "  未配置邮箱的端口: ${GREEN}0个${NC}"
    fi
    if [ ${#ports_no_lease[@]} -gt 0 ]; then
        echo -e "  未设置租期的端口: ${YELLOW}${#ports_no_lease[@]}个${NC} - ${ports_no_lease[*]}"
        has_issues=true
    else
        echo -e "  未设置租期的端口: ${GREEN}0个${NC}"
    fi
    if [ ${#ports_no_d3[@]} -gt 0 ]; then
        echo -e "  D-3提醒未配置端口: ${YELLOW}${#ports_no_d3[@]}个${NC} - ${ports_no_d3[*]}"
        has_issues=true
    else
        echo -e "  D-3提醒未配置端口: ${GREEN}0个${NC}"
    fi
    if [ ${#problem_ports[@]} -gt 0 ]; then
        echo -e "  规则异常端口 [重新设置配额 ✅]: ${RED}${#problem_ports[@]}个${NC} - ${problem_ports[*]}"
        has_issues=true
    else
        echo -e "  规则异常端口 [重新设置配额 ✅]: ${GREEN}0个${NC}"
    fi
    if [ ${#ports_rules_insufficient[@]} -gt 0 ]; then
        echo -e "  规则数量可能不足端口 [重建监控规则 ✅]: ${YELLOW}${#ports_rules_insufficient[@]}个${NC} - ${ports_rules_insufficient[*]}"
        has_issues=true
    else
        echo -e "  规则数量可能不足端口 [重建监控规则 ✅]: ${GREEN}0个${NC}"
    fi
    if [ ${#ports_expired[@]} -gt 0 ]; then
        echo -e "  已过期的端口: ${RED}${#ports_expired[@]}个${NC} - ${ports_expired[*]}"
        has_issues=true
    else
        echo -e "  已过期的端口: ${GREEN}0个${NC}"
    fi
    if [ ${#ports_blocked[@]} -gt 0 ]; then
        echo -e "  已封锁的端口: ${RED}${#ports_blocked[@]}个${NC} - ${ports_blocked[*]}"
        has_issues=true
    else
        echo -e "  已封锁的端口: ${GREEN}0个${NC}"
    fi
    
    if [ "$has_issues" = false ]; then
        echo -e "  ${GREEN}✅ 所有端口配置完整${NC}"
    fi
    
    echo
    echo -e "${BLUE}==================== 检测完成 ====================${NC}"
    echo
    echo
    
    # ========== 最终结论 ==========
    if [ ${#problem_ports[@]} -eq 0 ] && [ "$has_issues" = false ]; then
        echo -e "╔═══════════════════════════════════════════════════════════╗"
        echo -e "║                                                           ║"
        echo -e "║   ${GREEN}★★★ 检测结果: 配置完全正常! ★★★${NC}                    ║"
        echo -e "║                                                           ║"
        echo -e "║   所有端口的计数器、流量统计规则、配额规则均已就绪        ║"
        echo -e "║   流量狗正在正常工作中 ✅                                 ║"
        echo -e "║                                                           ║"
        echo -e "╚═══════════════════════════════════════════════════════════╝"
    elif [ ${#problem_ports[@]} -gt 0 ]; then
        echo -e "╔═══════════════════════════════════════════════════════════╗"
        echo -e "║                                                           ║"
        echo -e "║   ${RED}⚠️⚠️⚠️ 检测结果: 配置存在问题! ⚠️⚠️⚠️${NC}                   ║"
        echo -e "║                                                           ║"
        echo -e "║   发现 ${RED}${#problem_ports[@]}${NC} 个端口配置异常，请按上方建议修复            ║"
        echo -e "║   异常端口可能无法正常统计流量或限制配额                  ║"
        echo -e "║                                                           ║"
        echo -e "╚═══════════════════════════════════════════════════════════╝"
    else
        echo -e "╔═══════════════════════════════════════════════════════════╗"
        echo -e "║                                                           ║"
        echo -e "║   ${YELLOW}⚠️ 检测结果: 规则正常，但部分端口配置不完整 ⚠️${NC}          ║"
        echo -e "║                                                           ║"
        echo -e "║   流量统计和配额规则正常，但建议补充上述缺失的配置        ║"
        echo -e "║   （邮箱/租期等）以确保通知功能正常工作                   ║"
        echo -e "║                                                           ║"
        echo -e "╚═══════════════════════════════════════════════════════════╝"
    fi
    
    echo
    read -p "按回车键返回..." 
    show_main_menu
}

# 卸载脚本
uninstall_script() {
    echo -e "${BLUE}卸载脚本${NC}"
    echo "────────────────────────────────────────────────────────"

    echo -e "${YELLOW}将要删除以下内容:${NC}"
    echo "  - 脚本文件: $SCRIPT_PATH"
    echo "  - 快捷命令: /usr/local/bin/$SHORTCUT_COMMAND"
    echo "  - 配置目录: $CONFIG_DIR"
    echo "  - 所有nftables规则"
    echo "  - 所有TC限制规则"
    echo "  - 通知定时任务"
    echo
    echo -e "${RED}警告：此操作将完全删除端口流量狗及其所有数据！${NC}"
    read -p "确认卸载? [y/N]: " confirm

    if [[ "$confirm" =~ ^[Yy]$ ]]; then
        echo -e "${YELLOW}正在卸载...${NC}"

        local active_ports=($(get_active_ports 2>/dev/null || true))
        for port in "${active_ports[@]}"; do
            remove_nftables_rules "$port" 2>/dev/null || true
            remove_tc_limit "$port" 2>/dev/null || true
        done

        local table_name=$(jq -r '.nftables.table_name' "$CONFIG_FILE" 2>/dev/null || echo "port_traffic_monitor")
        local family=$(jq -r '.nftables.family' "$CONFIG_FILE" 2>/dev/null || echo "inet")
        nft delete table $family $table_name >/dev/null 2>&1 || true

        remove_telegram_notification_cron 2>/dev/null || true
        remove_wecom_notification_cron 2>/dev/null || true
        remove_email_notification_cron 2>/dev/null || true

        rm -rf "$CONFIG_DIR" 2>/dev/null || true
        rm -f "/usr/local/bin/$SHORTCUT_COMMAND" 2>/dev/null || true
        rm -f "$SCRIPT_PATH" 2>/dev/null || true

        echo -e "${GREEN}卸载完成！${NC}"
        echo -e "${YELLOW}感谢使用端口流量狗！${NC}"
        exit 0
    else
        echo "取消卸载"
        sleep 1
        show_main_menu
    fi
}

manage_notifications() {
    while true; do
        echo -e "${BLUE}=== 通知管理 ===${NC}"
        echo "1. Telegram机器人通知"
        echo "2. 邮件通知 (Resend)"
        echo "3. 企业wx 机器人通知"
        echo "0. 返回主菜单"
        echo
        read -p "请选择操作 [0-3]: " choice

        case $choice in
            1) manage_telegram_notifications ;;
            2) manage_email_notifications ;;
            3) manage_wecom_notifications ;;
            0) return ;;
            *) echo -e "${RED}无效选择${NC}"; sleep 1 ;;
        esac
    done
}

manage_telegram_notifications() {
    local telegram_script="$CONFIG_DIR/notifications/telegram.sh"

    if [ -f "$telegram_script" ]; then
        # 导出通知管理函数供模块使用
        export_notification_functions
        source "$telegram_script"
        telegram_configure
        manage_notifications
    else
        echo -e "${RED}Telegram 通知模块不存在${NC}"
        echo "请检查文件: $telegram_script"
        sleep 2
        manage_notifications
    fi
}

manage_email_notifications() {
    email_configure
    manage_notifications
}

manage_wecom_notifications() {
    local wecom_script="$CONFIG_DIR/notifications/wecom.sh"

    if [ -f "$wecom_script" ]; then
        # 导出通知管理函数供模块使用
        export_notification_functions
        source "$wecom_script"
        wecom_configure
        manage_notifications
    else
        echo -e "${RED}企业wx 通知模块不存在${NC}"
        echo "请检查文件: $wecom_script"
        sleep 2
        manage_notifications
    fi
}

setup_telegram_notification_cron() {
    local script_path="$SCRIPT_PATH"
    local temp_cron=$(mktemp)

    crontab -l 2>/dev/null | grep -v "# 端口流量狗Telegram通知" > "$temp_cron" || true

    # 检查telegram通知是否启用
    local telegram_enabled=$(jq -r '.notifications.telegram.status_notifications.enabled // false' "$CONFIG_FILE")
    if [ "$telegram_enabled" = "true" ]; then
        local status_interval=$(jq -r '.notifications.telegram.status_notifications.interval' "$CONFIG_FILE")
        
        # 对于需要指定时间的间隔，转换北京时间 00:00 为UTC时间
        local local_hour local_minute local_weekday
        
        # 7天间隔需要特殊处理：转换北京周一00:00 → UTC时间+星期
        if [ "$status_interval" == "7d" ]; then
            local result=($(convert_beijing_to_local_time "00" "00" "1"))  # 北京周一
            local_hour=${result[0]:-0}
            local_minute=${result[1]:-0}
            local_weekday=${result[2]:-1}  # UTC星期
        else
            # 其他间隔：仅转换时间
            local result=($(convert_beijing_to_local_time "00" "00"))
            local_hour=${result[0]:-0}
            local_minute=${result[1]:-0}
        fi
        
        # 验证转换结果
        if ! [[ "$local_hour" =~ ^[0-9]+$ ]] || ! [[ "$local_minute" =~ ^[0-9]+$ ]]; then
            local_hour=0
            local_minute=0
        fi
        
        case "$status_interval" in
            "1m")  echo "* * * * * $script_path --send-telegram-status >/dev/null 2>&1  # 端口流量狗Telegram通知" >> "$temp_cron" ;;
            "15m") echo "*/15 * * * * $script_path --send-telegram-status >/dev/null 2>&1  # 端口流量狗Telegram通知" >> "$temp_cron" ;;
            "30m") echo "*/30 * * * * $script_path --send-telegram-status >/dev/null 2>&1  # 端口流量狗Telegram通知" >> "$temp_cron" ;;
            "1h")  echo "0 * * * * $script_path --send-telegram-status >/dev/null 2>&1  # 端口流量狗Telegram通知" >> "$temp_cron" ;;
            "2h")  echo "0 */2 * * * $script_path --send-telegram-status >/dev/null 2>&1  # 端口流量狗Telegram通知" >> "$temp_cron" ;;
            "6h")  echo "0 */6 * * * $script_path --send-telegram-status >/dev/null 2>&1  # 端口流量狗Telegram通知" >> "$temp_cron" ;;
            "12h") echo "0 */12 * * * $script_path --send-telegram-status >/dev/null 2>&1  # 端口流量狗Telegram通知" >> "$temp_cron" ;;
            "24h"|"1d") echo "$local_minute $local_hour * * * $script_path --send-telegram-status >/dev/null 2>&1  # 端口流量狗Telegram通知" >> "$temp_cron" ;;
            "3d")  echo "$local_minute $local_hour */3 * * $script_path --send-telegram-status >/dev/null 2>&1  # 端口流量狗Telegram通知" >> "$temp_cron" ;;
            "7d")  echo "$local_minute $local_hour * * $local_weekday $script_path --send-telegram-status >/dev/null 2>&1  # 端口流量狗Telegram通知" >> "$temp_cron" ;;
            "15d") echo "$local_minute $local_hour 1,15 * * $script_path --send-telegram-status >/dev/null 2>&1  # 端口流量狗Telegram通知" >> "$temp_cron" ;;
        esac
    fi

    crontab "$temp_cron"
    rm -f "$temp_cron"
}

setup_wecom_notification_cron() {
    local script_path="$SCRIPT_PATH"
    local temp_cron=$(mktemp)
    crontab -l 2>/dev/null | grep -v "# 端口流量狗企业wx 通知" > "$temp_cron" || true

    # 检查企业wx 通知是否启用
    local wecom_enabled=$(jq -r '.notifications.wecom.status_notifications.enabled // false' "$CONFIG_FILE")
    if [ "$wecom_enabled" = "true" ]; then
        local wecom_interval=$(jq -r '.notifications.wecom.status_notifications.interval' "$CONFIG_FILE")
        
        # 对于需要指定时间的间隔，转换北京时间 00:00 为UTC时间
        local local_hour local_minute local_weekday
        
        # 7天间隔需要特殊处理：转换北京周一00:00 → UTC时间+星期
        if [ "$wecom_interval" == "7d" ]; then
            local result=($(convert_beijing_to_local_time "00" "00" "1"))  # 北京周一
            local_hour=${result[0]:-0}
            local_minute=${result[1]:-0}
            local_weekday=${result[2]:-1}  # UTC星期
        else
            # 其他间隔：仅转换时间
            local result=($(convert_beijing_to_local_time "00" "00"))
            local_hour=${result[0]:-0}
            local_minute=${result[1]:-0}
        fi
        
        # 验证转换结果
        if ! [[ "$local_hour" =~ ^[0-9]+$ ]] || ! [[ "$local_minute" =~ ^[0-9]+$ ]]; then
            local_hour=0
            local_minute=0
        fi
        
        case "$wecom_interval" in
            "1m")  echo "* * * * * $script_path --send-wecom-status >/dev/null 2>&1  # 端口流量狗企业wx 通知" >> "$temp_cron" ;;
            "15m") echo "*/15 * * * * $script_path --send-wecom-status >/dev/null 2>&1  # 端口流量狗企业wx 通知" >> "$temp_cron" ;;
            "30m") echo "*/30 * * * * $script_path --send-wecom-status >/dev/null 2>&1  # 端口流量狗企业wx 通知" >> "$temp_cron" ;;
            "1h")  echo "0 * * * * $script_path --send-wecom-status >/dev/null 2>&1  # 端口流量狗企业wx 通知" >> "$temp_cron" ;;
            "2h")  echo "0 */2 * * * $script_path --send-wecom-status >/dev/null 2>&1  # 端口流量狗企业wx 通知" >> "$temp_cron" ;;
            "6h")  echo "0 */6 * * * $script_path --send-wecom-status >/dev/null 2>&1  # 端口流量狗企业wx 通知" >> "$temp_cron" ;;
            "12h") echo "0 */12 * * * $script_path --send-wecom-status >/dev/null 2>&1  # 端口流量狗企业wx 通知" >> "$temp_cron" ;;
            "24h"|"1d") echo "$local_minute $local_hour * * * $script_path --send-wecom-status >/dev/null 2>&1  # 端口流量狗企业wx 通知" >> "$temp_cron" ;;
            "3d")  echo "$local_minute $local_hour */3 * * $script_path --send-wecom-status >/dev/null 2>&1  # 端口流量狗企业wx 通知" >> "$temp_cron" ;;
            "7d")  echo "$local_minute $local_hour * * $local_weekday $script_path --send-wecom-status >/dev/null 2>&1  # 端口流量狗企业wx 通知" >> "$temp_cron" ;;
            "15d") echo "$local_minute $local_hour 1,15 * * $script_path --send-wecom-status >/dev/null 2>&1  # 端口流量狗企业wx 通知" >> "$temp_cron" ;;
        esac
    fi

    crontab "$temp_cron"
    rm -f "$temp_cron"
}

# 部署每日后台检查任务 (主要用于租期管理)
setup_daily_check_cron() {
    local script_path="$SCRIPT_PATH"
    local temp_cron=$(mktemp)
    
    # 过滤掉旧的检查任务
    crontab -l 2>/dev/null | grep -v "# 端口流量狗每日检查" > "$temp_cron" || true
    
    # 将北京时间 00:30 转换为系统本地时间
    local local_time=($(convert_beijing_to_local_time "00" "30"))
    local local_hour=${local_time[0]:-0}
    local local_minute=${local_time[1]:-30}
    
    # 验证转换结果
    if ! [[ "$local_hour" =~ ^[0-9]+$ ]] || ! [[ "$local_minute" =~ ^[0-9]+$ ]]; then
        local_hour=0
        local_minute=30
    fi
    
    # 添加新任务: 每天北京时间 00:30 运行
    echo "$local_minute $local_hour * * * $script_path --daily-check >/dev/null 2>&1  # 端口流量狗每日检查" >> "$temp_cron"
    
    crontab "$temp_cron"
    rm -f "$temp_cron"
}

setup_email_notification_cron() {
    local script_path="$SCRIPT_PATH"
    local temp_cron=$(mktemp)
    crontab -l 2>/dev/null | grep -v "# 端口流量狗邮件通知" > "$temp_cron" || true

    # 检查邮件通知是否启用
    local email_enabled=$(jq -r '.notifications.email.status_notifications.enabled // false' "$CONFIG_FILE")
    if [ "$email_enabled" = "true" ]; then
        local email_interval=$(jq -r '.notifications.email.status_notifications.interval' "$CONFIG_FILE")
        
        # 对于需要指定时间的间隔，转换北京时间 00:00 为UTC时间
        local local_hour local_minute local_weekday
        
        # 7天间隔需要特殊处理：转换北京周一00:00 → UTC时间+星期
        if [ "$email_interval" == "7d" ]; then
            local result=($(convert_beijing_to_local_time "00" "00" "1"))  # 北京周一
            local_hour=${result[0]:-0}
            local_minute=${result[1]:-0}
            local_weekday=${result[2]:-1}  # UTC星期
        else
            # 其他间隔：仅转换时间
            local result=($(convert_beijing_to_local_time "00" "00"))
            local_hour=${result[0]:-0}
            local_minute=${result[1]:-0}
        fi
        
        # 验证转换结果
        if ! [[ "$local_hour" =~ ^[0-9]+$ ]] || ! [[ "$local_minute" =~ ^[0-9]+$ ]]; then
            local_hour=0
            local_minute=0
        fi
        
        case "$email_interval" in
            "1m")  echo "* * * * * $script_path --send-email-status >/dev/null 2>&1  # 端口流量狗邮件通知" >> "$temp_cron" ;;
            "15m") echo "*/15 * * * * $script_path --send-email-status >/dev/null 2>&1  # 端口流量狗邮件通知" >> "$temp_cron" ;;
            "30m") echo "*/30 * * * * $script_path --send-email-status >/dev/null 2>&1  # 端口流量狗邮件通知" >> "$temp_cron" ;;
            "1h")  echo "0 * * * * $script_path --send-email-status >/dev/null 2>&1  # 端口流量狗邮件通知" >> "$temp_cron" ;;
            "2h")  echo "0 */2 * * * $script_path --send-email-status >/dev/null 2>&1  # 端口流量狗邮件通知" >> "$temp_cron" ;;
            "6h")  echo "0 */6 * * * $script_path --send-email-status >/dev/null 2>&1  # 端口流量狗邮件通知" >> "$temp_cron" ;;
            "12h") echo "0 */12 * * * $script_path --send-email-status >/dev/null 2>&1  # 端口流量狗邮件通知" >> "$temp_cron" ;;
            "24h"|"1d") echo "$local_minute $local_hour * * * $script_path --send-email-status >/dev/null 2>&1  # 端口流量狗邮件通知" >> "$temp_cron" ;;
            "3d")  echo "$local_minute $local_hour */3 * * $script_path --send-email-status >/dev/null 2>&1  # 端口流量狗邮件通知" >> "$temp_cron" ;;
            "7d")  echo "$local_minute $local_hour * * $local_weekday $script_path --send-email-status >/dev/null 2>&1  # 端口流量狗邮件通知" >> "$temp_cron" ;;
            "15d") echo "$local_minute $local_hour 1,15 * * $script_path --send-email-status >/dev/null 2>&1  # 端口流量狗邮件通知" >> "$temp_cron" ;;
        esac
    fi

    crontab "$temp_cron"
    rm -f "$temp_cron"
}

# 通用间隔选择函数
select_notification_interval() {
    # 显示选择菜单到stderr，避免被变量捕获
    echo "请选择状态通知发送间隔:" >&2
    echo "1. 1小时" >&2
    echo "2. 6小时" >&2
    echo "3. 1天 (24小时)" >&2
    echo "4. 3天" >&2
    echo "5. 一周 (7天)" >&2
    echo "6. 半个月 (15天)" >&2
    read -p "请选择(回车默认1小时) [1-6]: " interval_choice >&2

    # 默认1小时
    local interval="1h"
    case $interval_choice in
        1|"") interval="1h" ;;
        2) interval="6h" ;;
        3) interval="1d" ;;
        4) interval="3d" ;;
        5) interval="7d" ;;
        6) interval="15d" ;;
        *) interval="1h" ;;
    esac
    echo "$interval"
}

remove_telegram_notification_cron() {
    local temp_cron=$(mktemp)
    crontab -l 2>/dev/null | grep -v "# 端口流量狗Telegram通知" > "$temp_cron" || true
    crontab "$temp_cron"
    rm -f "$temp_cron"
}

remove_wecom_notification_cron() {
    local temp_cron=$(mktemp)
    crontab -l 2>/dev/null | grep -v "# 端口流量狗企业wx 通知" > "$temp_cron" || true
    crontab "$temp_cron"
    rm -f "$temp_cron"
}

remove_email_notification_cron() {
    local temp_cron=$(mktemp)
    crontab -l 2>/dev/null | grep -v "# 端口流量狗邮件通知" > "$temp_cron" || true
    crontab "$temp_cron"
    rm -f "$temp_cron"
}

export_notification_functions() {
    export -f setup_telegram_notification_cron
    export -f setup_wecom_notification_cron
    export -f setup_email_notification_cron
    export -f select_notification_interval
}

# 判断今天是否应该执行每月任务
# 参数: $1=目标日期(1-31)
# 返回: 0=应该执行, 1=不应该执行
should_run_monthly_task() {
    local target_day=$1
    
    # 获取北京时间的今天日期（去掉前导零）
    local beijing_today=$(TZ='Asia/Shanghai' date +%-d)
    
    # 判断是否匹配
    if [ "$beijing_today" == "$target_day" ]; then
        return 0  # 应该执行
    else
        return 1  # 跳过
    fi
}

setup_port_auto_reset_cron() {
    local port="$1"
    local script_path="$SCRIPT_PATH"
    local temp_cron=$(mktemp)
    
    # 为端口生成唯一标识符（端口组用安全名称）
    local port_id
    if is_port_group "$port"; then
        port_id=$(generate_port_group_safe_name "$port")
    else
        port_id="$port"
    fi

    # 保留现有任务，移除该端口的旧任务
    crontab -l 2>/dev/null | grep -v "端口流量狗自动重置ID_$port_id" > "$temp_cron" || true

    local quota_enabled=$(jq -r ".ports.\"$port\".quota.enabled // true" "$CONFIG_FILE")
    local monthly_limit=$(jq -r ".ports.\"$port\".quota.monthly_limit // \"unlimited\"" "$CONFIG_FILE")
    local reset_day_raw=$(jq -r ".ports.\"$port\".quota.reset_day" "$CONFIG_FILE")
    
    # 只有quota启用、monthly_limit不是unlimited、且reset_day存在时才添加cron任务
    if [ "$quota_enabled" = "true" ] && [ "$monthly_limit" != "unlimited" ] && [ "$reset_day_raw" != "null" ]; then
        local reset_day="${reset_day_raw:-1}"
        
        # 将北京时间 00:05 转换为系统本地时间
        local local_time=($(convert_beijing_to_local_time "00" "05"))
        local local_hour=${local_time[0]:-0}
        local local_minute=${local_time[1]:-5}
        
        # 验证转换结果
        if ! [[ "$local_hour" =~ ^[0-9]+$ ]] || ! [[ "$local_minute" =~ ^[0-9]+$ ]]; then
            local_hour=0
            local_minute=5
        fi
        
        # 改为每天执行，脚本内部判断日期
        echo "$local_minute $local_hour * * * $script_path --reset-port-if-match '$port' '$reset_day' >/dev/null 2>&1  # 端口流量狗自动重置ID_$port_id" >> "$temp_cron"
    fi

    crontab "$temp_cron"
    rm -f "$temp_cron"
}

remove_port_auto_reset_cron() {
    local port="$1"
    local temp_cron=$(mktemp)
    
    # 为端口生成唯一标识符
    local port_id
    if is_port_group "$port"; then
        port_id=$(generate_port_group_safe_name "$port")
    else
        port_id="$port"
    fi

    crontab -l 2>/dev/null | grep -v "端口流量狗自动重置ID_$port_id" > "$temp_cron" || true

    crontab "$temp_cron"
    rm -f "$temp_cron"
}

# 格式化状态消息（HTML格式）
format_status_message() {
    local server_name="${1:-$(hostname)}"  # 接受服务器名称参数
    local timestamp=$(get_beijing_time '+%Y-%m-%d %H:%M:%S')
    local notification_icon="🔔"
    local active_ports=($(get_active_ports))
    local port_count=${#active_ports[@]}
    local daily_total=$(get_daily_total_traffic)

    local message="<b>${notification_icon} 端口流量狗 v${SCRIPT_VERSION}</b> | ⏰ ${timestamp}
作者主页:<code>https://zywe.de</code> | 项目开源:<code>https://github.com/zywe03/realm-xwPF</code>
一只轻巧的'守护犬'，时刻守护你的端口流量 | 快捷命令: dog
---
状态: 监控中 | 守护端口: ${port_count}个 | 端口总流量: ${daily_total}
────────────────────────────────────────
<pre>$(format_port_list "message")</pre>
────────────────────────────────────────
🔗 服务器: <i>${server_name}</i>"

    echo "$message"
}

# 格式化状态消息（纯文本text格式）
format_text_status_message() {
    local server_name="${1:-$(hostname)}"
    local timestamp=$(get_beijing_time '+%Y-%m-%d %H:%M:%S')
    local notification_icon="🔔"
    local active_ports=($(get_active_ports))
    local port_count=${#active_ports[@]}
    local daily_total=$(get_daily_total_traffic)

    local message="${notification_icon} 端口流量狗 v${SCRIPT_VERSION} | ⏰ ${timestamp}
作者主页: https://zywe.de | 项目开源: https://github.com/zywe03/realm-xwPF
一只轻巧的'守护犬'，时刻守护你的端口流量 | 快捷命令: dog
---
状态: 监控中 | 守护端口: ${port_count}个 | 端口总流量: ${daily_total}
────────────────────────────────────────
$(format_port_list "message")
────────────────────────────────────────
🔗 服务器: ${server_name}"

    echo "$message"
}

# 格式化状态消息（Markdown格式）
format_markdown_status_message() {
    local server_name="${1:-$(hostname)}"
    local timestamp=$(get_beijing_time '+%Y-%m-%d %H:%M:%S')
    local notification_icon="🔔"
    local active_ports=($(get_active_ports))
    local port_count=${#active_ports[@]}
    local daily_total=$(get_daily_total_traffic)

    local message="**${notification_icon} 端口流量狗 v${SCRIPT_VERSION}** | ⏰ ${timestamp}
作者主页: \`https://zywe.de\` | 项目开源: \`https://github.com/zywe03/realm-xwPF\`
一只轻巧的'守护犬'，时刻守护你的端口流量 | 快捷命令: dog
---
**状态**: 监控中 | **守护端口**: ${port_count}个 | **端口总流量**: ${daily_total}
────────────────────────────────────────
$(format_port_list "markdown")
────────────────────────────────────────
🔗 **服务器**: ${server_name}"

    echo "$message"
}

# 记录通知日志
log_notification() {
    local message="$1"
    local timestamp=$(get_beijing_time '+%Y-%m-%d %H:%M:%S')
    local log_file="$CONFIG_DIR/logs/notification.log"

    mkdir -p "$(dirname "$log_file")"

    echo "[$timestamp] $message" >> "$log_file"

    # 日志轮转：防止日志文件过大
    if [ -f "$log_file" ] && [ $(wc -l < "$log_file") -gt 1000 ]; then
        tail -n 500 "$log_file" > "${log_file}.tmp"
        mv "${log_file}.tmp" "$log_file"
    fi
}

#=============================================================================
# 邮件通知模块 (内嵌) - 使用 Resend API
#=============================================================================

# 邮件通知网络参数
EMAIL_MAX_RETRIES=2
EMAIL_CONNECT_TIMEOUT=10
EMAIL_MAX_TIMEOUT=30

# 检查邮件通知是否启用
email_is_enabled() {
    local enabled=$(jq -r '.notifications.email.enabled // false' "$CONFIG_FILE")
    [ "$enabled" = "true" ]
}

# 生成单个端口的 HTML 卡片
generate_port_html_card() {
    local port=$1
    local hide_remark=$2
    local port_config=$(jq -r ".ports.\"$port\"" "$CONFIG_FILE" 2>/dev/null)
    
    local remark=$(echo "$port_config" | jq -r '.remark // ""')
    # 如果要求隐藏备注，则强制清空
    if [ "$hide_remark" = "true" ]; then
        remark=""
    fi
    local billing_mode=$(echo "$port_config" | jq -r '.billing_mode // "double"')
    local traffic_data=($(get_port_traffic "$port"))
    local input_bytes=${traffic_data[0]}
    local output_bytes=${traffic_data[1]}
    
    local total_traffic_bytes=$(calculate_total_traffic "$input_bytes" "$output_bytes" "$billing_mode")
    local total_traffic_str=$(format_bytes "$total_traffic_bytes")
    # 根据计费模式决定入站/出站显示是否×2（与终端显示逻辑一致）
    # - double/relay/single: ×2 显示（反映真实网卡消耗）
    # - premium: 不×2（内网中转场景，只统计用户侧）
    local input_str
    local output_str
    if [ "$billing_mode" = "premium" ]; then
        input_str=$(format_bytes "$input_bytes")
        output_str=$(format_bytes "$output_bytes")
    else
        input_str=$(format_bytes $((input_bytes * 2)))
        output_str=$(format_bytes $((output_bytes * 2)))
    fi
    
    local quota_info_html=""
    local quota_enabled=$(echo "$port_config" | jq -r '.quota.enabled // true')
    local monthly_limit=$(echo "$port_config" | jq -r '.quota.monthly_limit // "unlimited"')
    
    # 端口显示名称处理
    local port_display="端口 ${port}"
    if is_port_group "$port"; then
        local display_str="$port"
        if [ ${#port} -gt 25 ]; then
            local count=$(echo "$port" | tr -cd ',' | wc -c)
            count=$((count + 1))
            display_str="${port:0:22}...(${count}个)"
        fi
        port_display="端口组 [${display_str}]"
    elif is_port_range "$port"; then
        port_display="端口段 [${port}]"
    fi
    
    # 备注处理
    local remark_html=""
    if [ -n "$remark" ] && [ "$remark" != "null" ] && [ "$remark" != "" ]; then
        remark_html="<span class=\"remark-badge\">${remark}</span>"
    fi

    # 计费模式显示
    local mode_display
    case "$billing_mode" in
        "double"|"relay") mode_display="双向计费 (入+出)×2" ;;
        "premium") mode_display="CN Premium (入+出)×1" ;;
        "single") mode_display="单向计费 (出站×2)" ;;
        *) mode_display="双向计费" ;;
    esac

    echo "<div class=\"card\">
            <div class=\"card-header\">
                <span class=\"port-badge\">${port_display}</span>
                ${remark_html}
            </div>
            <div class=\"info-row\">
                <span>总流量: <span class=\"traffic-highlight\">${total_traffic_str}</span></span>
                <span>${mode_display}</span>
            </div>
            <div class=\"info-row\">
                <span>📥 入站: ${input_str}</span>
                <span>📤 出站: ${output_str}</span>
            </div>"

    # 配额进度条逻辑
    if [ "$quota_enabled" = "true" ] && [ "$monthly_limit" != "unlimited" ]; then
        local limit_bytes=$(parse_size_to_bytes "$monthly_limit")
        local usage_percent=0
        if [ $limit_bytes -gt 0 ]; then
            usage_percent=$((total_traffic_bytes * 100 / limit_bytes))
        fi
        
        # 进度条颜色：超过80%变黄，超过95%变红
        local bar_color="#3b82f6" # 蓝
        if [ $usage_percent -ge 95 ]; then
            bar_color="#ef4444" # 红
        elif [ $usage_percent -ge 80 ]; then
            bar_color="#f59e0b" # 黄
        fi

        # 限制进度条显示最大100%
        local display_percent=$usage_percent
        if [ $display_percent -gt 100 ]; then display_percent=100; fi

        local reset_day_raw=$(echo "$port_config" | jq -r '.quota.reset_day')
        local reset_msg=""
        if [ "$reset_day_raw" != "null" ]; then
             reset_msg="| 每月${reset_day_raw}日重置"
        fi

        echo "<div style=\"margin-top: 8px; font-size: 12px; color: #6b7280; display: flex; justify-content: space-between;\">
                <span>📊 配额使用: ${usage_percent}%</span>
                <span>${monthly_limit} ${reset_msg}</span>
              </div>
              <div class=\"progress-container\">
                <div class=\"progress-bar\" style=\"width: ${display_percent}%; background-color: ${bar_color};\"></div>
              </div>"
    fi

    echo "</div>"
}

# 生成精美的 HTML 邮件内容
generate_html_email_body() {
    local title="$1"
    local server_name="$2"
    local send_time=$(get_beijing_time '+%Y-%m-%d %H:%M:%S')
    
    # 获取汇总数据
    local active_ports=($(get_active_ports))
    local port_count=${#active_ports[@]}
    local daily_total=$(get_daily_total_traffic)
    
    # CSS 样式定义
    local css_styles="
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #f3f4f6; margin: 0; padding: 0; color: #1f2937; }
        .container { max-width: 600px; margin: 0 auto; background-color: #ffffff; border-radius: 8px; overflow: hidden; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1); }
        .header { background: linear-gradient(135deg, #3b82f6 0%, #2563eb 100%); padding: 24px; color: white; text-align: center; }
        .header h1 { margin: 0; font-size: 20px; font-weight: 600; }
        .header-stats { background-color: #eff6ff; padding: 16px; display: flex; justify-content: space-around; border-bottom: 1px solid #e5e7eb; font-size: 14px; color: #3b82f6; font-weight: 500; text-align: center; }
        .stat-item { flex: 1; }
        .content { padding: 20px; }
        .card { background-color: white; border: 1px solid #e5e7eb; border-radius: 8px; margin-bottom: 16px; padding: 16px; box-shadow: 0 1px 2px 0 rgba(0, 0, 0, 0.05); }
        .card-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; padding-bottom: 8px; border-bottom: 1px dashed #e5e7eb; }
        .port-badge { background-color: #dbeafe; color: #1e40af; padding: 4px 8px; border-radius: 4px; font-size: 13px; font-weight: 600; }
        .traffic-highlight { color: #059669; font-weight: 600; font-size: 15px; }
        .info-row { display: flex; justify-content: space-between; margin-bottom: 6px; font-size: 13px; color: #4b5563; }
        .remark-badge { background-color: #f3f4f6; color: #4b5563; padding: 2px 6px; border-radius: 4px; font-size: 12px; }
        .progress-container { height: 8px; background-color: #e5e7eb; border-radius: 4px; margin-top: 8px; overflow: hidden; }
        .progress-bar { height: 100%; background-color: #3b82f6; border-radius: 4px; }
        .footer { background-color: #f9fafb; padding: 16px; text-align: center; font-size: 12px; color: #6b7280; border-top: 1px solid #e5e7eb; }
    "

    echo "<!DOCTYPE html><html><head><meta charset=\"UTF-8\">
    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">
    <title>${title}</title>
    <style>${css_styles}</style></head><body>
    <div class=\"container\">
        <div class=\"header\">
            <h1>📊 ${title}</h1>
        </div>
        <div class=\"header-stats\">
            <div class=\"stat-item\">🟢 监控中</div>
            <div class=\"stat-item\">🛡️ 端口: ${port_count}个</div>
            <div class=\"stat-item\">📈 总流量: ${daily_total}</div>
        </div>
        <div class=\"content\">"

    # 遍历生成端口卡片
    for port in "${active_ports[@]}"; do
        generate_port_html_card "$port"
    done

    echo "</div>
        <div class=\"footer\">
            <p>🔗 服务器: ${server_name}</p>
            <p>端口流量狗 v${SCRIPT_VERSION} | 发送时间: ${send_time}</p>
        </div>
    </div></body></html>"
}

# 核心发送函数：调用 Resend API 发送邮件
send_email_notification() {
    local title="$1"
    local html_content="$2"
    local target_email="$3"

    local api_key=$(jq -r '.notifications.email.resend_api_key // ""' "$CONFIG_FILE" 2>/dev/null || echo "")
    local email_from=$(jq -r '.notifications.email.email_from // ""' "$CONFIG_FILE" 2>/dev/null || echo "")
    local email_from_name=$(jq -r '.notifications.email.email_from_name // ""' "$CONFIG_FILE" 2>/dev/null || echo "")
    
    # 如果没有指定收件人，尝试获取全局配置（兼容旧逻辑，虽然现在主要走分发）
    local email_to="${target_email}"
    if [ -z "$email_to" ]; then
        email_to=$(jq -r '.notifications.email.email_to // ""' "$CONFIG_FILE" 2>/dev/null || echo "")
    fi

    if [ -z "$api_key" ] || [ -z "$email_from" ] || [ -z "$email_to" ]; then
        if [ -z "$target_email" ]; then
            log_notification "[邮件通知] 未指定收件人，且无全局配置"
        else
            log_notification "[邮件通知] 配置不完整，缺少必要参数"
        fi
        return 1
    fi

    local from_address="$email_from"
    if [ -n "$email_from_name" ] && [ "$email_from_name" != "null" ]; then
        from_address="${email_from_name} <${email_from}>"
    fi

    # 纯文本备用内容
    local text_content="请使用支持HTML的邮箱客户端查看此邮件。"

    # 构建JSON请求体
    local json_body=$(jq -n \
        --arg from "$from_address" \
        --arg to "$email_to" \
        --arg subject "$title" \
        --arg html "$html_content" \
        --arg text "$text_content" \
        '{from: $from, to: $to, subject: $subject, html: $html, text: $text}')

    local retry_count=0

    # 重试机制
    while [ $retry_count -le $EMAIL_MAX_RETRIES ]; do
        local response=$(curl -s --connect-timeout $EMAIL_CONNECT_TIMEOUT --max-time $EMAIL_MAX_TIMEOUT \
            -X POST "https://api.resend.com/emails" \
            -H "Authorization: Bearer ${api_key}" \
            -H "Content-Type: application/json" \
            -d "$json_body" 2>/dev/null)

        # Resend API 成功响应包含 id 字段
        if echo "$response" | grep -q '"id"'; then
            if [ $retry_count -gt 0 ]; then
                log_notification "[邮件通知] 发送成功 (重试第${retry_count}次后成功)"
            else
                log_notification "[邮件通知] 发送成功"
            fi
            return 0
        fi

        retry_count=$((retry_count + 1))
        if [ $retry_count -le $EMAIL_MAX_RETRIES ]; then
            sleep 2
        fi
    done

    log_notification "[邮件通知] 发送失败 (已重试${EMAIL_MAX_RETRIES}次)"
    return 1
}

# 标准通知接口：发送邮件状态通知
email_send_status_notification() {
    local status_enabled=$(jq -r '.notifications.email.status_notifications.enabled // false' "$CONFIG_FILE")
    if [ "$status_enabled" != "true" ]; then
        log_notification "[邮件通知] 状态通知未启用"
        return 1
    fi

    local server_name=$(jq -r '.notifications.email.server_name // ""' "$CONFIG_FILE" 2>/dev/null || echo "$(hostname)")
    if [ -z "$server_name" ] || [ "$server_name" = "null" ]; then
        server_name=$(hostname)
    fi

    local active_ports=($(get_active_ports))
    local port_sent_count=0
    local port_success_count=0

    # 遍历所有端口进行分发
    for port in "${active_ports[@]}"; do
        local user_email=$(jq -r ".ports.\"$port\".email // \"\"" "$CONFIG_FILE")
        
        # 只有配置了邮箱的端口才发送
        if [ -n "$user_email" ] && [ "$user_email" != "null" ] && [ "$user_email" != "" ]; then
            port_sent_count=$((port_sent_count + 1))
            
            # 生成标题
            local port_display="$port"
            if is_port_group "$port"; then
                port_display="端口组"
            fi
            local title="流量使用报告 - ${port_display} - ${server_name}"
            
            # 生成专属HTML
            local html_content=$(generate_single_port_email_body "$title" "$server_name" "$port")
            
            # 发送邮件 (传递专属收件人)
            if send_email_notification "$title" "$html_content" "$user_email"; then
                port_success_count=$((port_success_count + 1))
                log_notification "[邮件通知] 端口 $port (${user_email}) 发送成功"
            else
                log_notification "[邮件通知] 端口 $port (${user_email}) 发送失败"
            fi
        fi
    done
    
    if [ $port_sent_count -eq 0 ]; then
        log_notification "[邮件通知] 未配置任何端口接收人，跳过发送"
        # 返回成功以免被上层判为失败(其实是正常的)
        return 0
    else
        echo "已向 ${port_success_count}/${port_sent_count} 个端口接收人发送邮件"
        if [ $port_success_count -gt 0 ]; then
            return 0
        else
            return 1
        fi
    fi
}

# 生成单端口专属 HTML 邮件内容
generate_single_port_email_body() {
    local title="$1"
    local server_name="$2"
    local port="$3"
    local send_time=$(get_beijing_time '+%Y-%m-%d %H:%M:%S')
    
    # CSS 样式 (复用)
    local css_styles="
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #f3f4f6; margin: 0; padding: 0; color: #1f2937; }
        .container { max-width: 600px; margin: 0 auto; background-color: #ffffff; border-radius: 8px; overflow: hidden; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1); }
        .header { background: linear-gradient(135deg, #3b82f6 0%, #2563eb 100%); padding: 24px; color: white; text-align: center; }
        .header h1 { margin: 0; font-size: 20px; font-weight: 600; }
        .content { padding: 20px; }
        .card { background-color: white; border: 1px solid #e5e7eb; border-radius: 8px; margin-bottom: 16px; padding: 16px; box-shadow: 0 1px 2px 0 rgba(0, 0, 0, 0.05); }
        .card-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; padding-bottom: 8px; border-bottom: 1px dashed #e5e7eb; }
        .port-badge { background-color: #dbeafe; color: #1e40af; padding: 4px 8px; border-radius: 4px; font-size: 13px; font-weight: 600; }
        .traffic-highlight { color: #059669; font-weight: 600; font-size: 15px; }
        .info-row { display: flex; justify-content: space-between; margin-bottom: 6px; font-size: 13px; color: #4b5563; }
        .remark-badge { background-color: #f3f4f6; color: #4b5563; padding: 2px 6px; border-radius: 4px; font-size: 12px; }
        .progress-container { height: 8px; background-color: #e5e7eb; border-radius: 4px; margin-top: 8px; overflow: hidden; }
        .progress-bar { height: 100%; background-color: #3b82f6; border-radius: 4px; }
        .footer { background-color: #f9fafb; padding: 16px; text-align: center; font-size: 12px; color: #6b7280; border-top: 1px solid #e5e7eb; }
    "

    echo "<!DOCTYPE html><html><head><meta charset=\"UTF-8\">
    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">
    <title>${title}</title>
    <style>${css_styles}</style></head><body>
    <div class=\"container\">
        <div class=\"header\">
            <h1>📊 您的流量使用报告</h1>
        </div>
        <div class=\"content\">"
    
    # 仅生成该端口的卡片
    generate_port_html_card "$port" "true"

    echo "</div>
        <div class=\"footer\">
            <p>🔗 服务器: ${server_name}</p>
            <p>发送时间: ${send_time}</p>
        </div>
    </div></body></html>"
}

# 测试邮件发送
email_test() {
    echo -e "${BLUE}=== 发送测试邮件 ===${NC}"
    echo

    if ! email_is_enabled; then
        echo -e "${RED}请先配置邮件通知信息${NC}"
        sleep 2
        return 1
    fi

    echo "1. 发送测试邮件到指定邮箱 (验证API连通性)"
    echo "2. 立即触发全员状态通知分发 (测试已配置的端口收件人)"
    echo "0. 返回"
    echo
    read -p "请选择测试类型 [0-2]: " test_choice

    if [ "$test_choice" = "1" ]; then
        local email_to
        read -p "请输入接收测试邮件的邮箱: " email_to
        
        if [ -z "$email_to" ]; then
            echo -e "${RED}邮箱不能为空${NC}"
            return 1
        fi
        
        echo "正在发送测试邮件到: $email_to"
        
        local title="端口流量狗 - 邮件测试"
        local html_content="<h1>✅ 邮件通知配置成功</h1><p>这是一封测试邮件，证明您的 Resend API 配置正确。</p>"

        if send_email_notification "$title" "$html_content" "$email_to"; then
            echo -e "${GREEN}✅ 邮件发送成功！${NC}"
        else
            echo -e "${RED}❌ 邮件发送失败${NC}"
        fi
    elif [ "$test_choice" = "2" ]; then
        echo "正在执行状态通知分发..."
        email_send_status_notification
    else
        return 0
    fi

    sleep 3
}

# 邮件通知配置主菜单
email_configure() {
    while true; do
        local status_notifications_enabled=$(jq -r '.notifications.email.status_notifications.enabled // false' "$CONFIG_FILE")
        local api_key=$(jq -r '.notifications.email.resend_api_key // ""' "$CONFIG_FILE")

        # 判断配置状态
        local config_status="[未配置]"
        if [ -n "$api_key" ] && [ "$api_key" != "" ] && [ "$api_key" != "null" ]; then
            config_status="[已配置]"
        fi

        # 判断开关状态
        local enable_status="[关闭]"
        if [ "$status_notifications_enabled" = "true" ]; then
            enable_status="[开启]"
        fi

        local status_interval=$(jq -r '.notifications.email.status_notifications.interval' "$CONFIG_FILE")

        echo -e "${BLUE}=== 邮件通知配置 (Resend) ===${NC}"
        local interval_display="未设置"
        if [ -n "$status_interval" ] && [ "$status_interval" != "null" ]; then
            interval_display="每${status_interval}"
        fi
        echo -e "当前状态: ${enable_status} | ${config_status} | 状态通知: ${interval_display}"
        echo
        echo "1. 配置基础信息 (API Key + 发件人)"
        echo "2. 配置端口收件人 (分端口独立发送)"
        echo "3. 通知设置管理"
        echo "4. 发送测试邮件"
        echo "5. 查看通知日志"
        echo "0. 返回上级菜单"
        echo
        read -p "请选择操作 [0-5]: " choice

        case $choice in
            1) email_configure_info ;;
            2) email_configure_port_recipients ;;
            3) email_manage_settings ;;
            4) email_test ;;
            5) email_view_logs ;;
            0) return 0 ;;
            *) echo -e "${RED}无效选择${NC}"; sleep 1 ;;
        esac
    done
}

# 配置邮件信息
email_configure_info() {
    echo -e "${BLUE}=== 配置邮件通知 (Resend API) ===${NC}"
    echo
    echo -e "${GREEN}配置步骤说明:${NC}"
    echo "1. 访问 https://resend.com 注册账号"
    echo "2. 在 Resend 控制台验证发件域名"
    echo "3. 获取 API Key"
    echo

    local current_api_key=$(jq -r '.notifications.email.resend_api_key' "$CONFIG_FILE")
    local current_email_from=$(jq -r '.notifications.email.email_from' "$CONFIG_FILE")
    local current_email_from_name=$(jq -r '.notifications.email.email_from_name' "$CONFIG_FILE")
    
    # 显示当前配置
    if [ "$current_api_key" != "" ] && [ "$current_api_key" != "null" ]; then
        local masked_key="${current_api_key:0:10}...${current_api_key: -5}"
        echo -e "${GREEN}当前API Key: $masked_key${NC}"
    fi
    if [ "$current_email_from" != "" ] && [ "$current_email_from" != "null" ]; then
        echo -e "${GREEN}当前发件人邮箱: $current_email_from${NC}"
    fi
    if [ "$current_email_from_name" != "" ] && [ "$current_email_from_name" != "null" ]; then
        echo -e "${GREEN}当前发件人名称: $current_email_from_name${NC}"
    fi
    echo

    # 输入 API Key
    read -p "请输入 Resend API Key: " api_key
    if [ -z "$api_key" ]; then
        echo -e "${RED}API Key 不能为空${NC}"
        sleep 2
        return
    fi

    if ! [[ "$api_key" =~ ^re_ ]]; then
        echo -e "${RED}API Key 格式错误，应以 re_ 开头${NC}"
        sleep 2
        return
    fi

    # 输入发件人邮箱
    read -p "请输入发件人邮箱 (需在Resend验证的域名): " email_from
    if [ -z "$email_from" ]; then
        echo -e "${RED}发件人邮箱不能为空${NC}"
        sleep 2
        return
    fi

    if ! [[ "$email_from" =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$ ]]; then
        echo -e "${RED}邮箱格式错误${NC}"
        sleep 2
        return
    fi

    # 从邮箱提取默认名称 (截取 @ 前面的部分)
    local default_name="${email_from%%@*}"

    # 输入发件人名称
    read -p "请输入发件人名称 (回车默认: ${default_name}): " email_from_name
    if [ -z "$email_from_name" ]; then
        email_from_name="$default_name"
    fi

    # 输入服务器名称
    read -p "请输入服务器名称 (回车默认: ${default_name}): " server_name
    if [ -z "$server_name" ]; then
        server_name="$default_name"
    fi

    # 保存配置 (移除 email_to)
    update_config "del(.notifications.email.email_to) | 
        .notifications.email.resend_api_key = \"$api_key\" |
        .notifications.email.email_from = \"$email_from\" |
        .notifications.email.email_from_name = \"$email_from_name\" |
        .notifications.email.server_name = \"$server_name\" |
        .notifications.email.enabled = true |
        .notifications.email.status_notifications.enabled = true"

    echo -e "${GREEN}✅ 基础配置保存成功！请继续配置端口收件人。${NC}"
    echo
    sleep 2
}

# 配置端口独立收件人
email_configure_port_recipients() {
    while true; do
        clear
        echo -e "${BLUE}=== 配置端口独立收件人 ===${NC}"
        echo
        
        local active_ports=($(get_active_ports))
        if [ ${#active_ports[@]} -eq 0 ]; then
             echo "暂无监控端口"
             sleep 2
             return
        fi

        echo "端口列表:"
        for i in "${!active_ports[@]}"; do
            local port=${active_ports[$i]}
            local remark=$(jq -r ".ports.\"$port\".remark // \"\"" "$CONFIG_FILE")
            local email=$(jq -r ".ports.\"$port\".email // \"未设置\"" "$CONFIG_FILE")
            
            # 显示名称处理
            # 显示名称处理
            local display_name=""
            if is_port_group "$port"; then
                local display_str="$port"
                if [ ${#port} -gt 20 ]; then
                    local count=$(echo "$port" | tr -cd ',' | wc -c)
                    count=$((count + 1))
                    display_str="${port:0:17}...(${count}个)"
                fi
                display_name="端口组[${display_str}]"
            elif is_port_range "$port"; then
                display_name="端口段[$port]"
            else
                display_name="端口 $port"
            fi
            
            if [ -n "$remark" ] && [ "$remark" != "null" ]; then
                display_name+=" [$remark]"
            fi
            
            local email_display="${RED}未设置${NC}"
            if [ "$email" != "未设置" ] && [ "$email" != "null" ] && [ "$email" != "" ]; then
                email_display="${GREEN}$email${NC}"
            fi
            
            echo -e "$((i+1)). $display_name -> $email_display"
        done
        echo
        echo "0. 返回上级菜单"
        echo
        
        read -p "请选择要配置的端口 [1-${#active_ports[@]}, 0返回]: " choice
        
        if [ "$choice" = "0" ]; then
            return
        fi

        if [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -ge 1 ] && [ "$choice" -le ${#active_ports[@]} ]; then
            local port=${active_ports[$((choice-1))]}
            
            echo
            local current_email=$(jq -r ".ports.\"$port\".email // \"\"" "$CONFIG_FILE")
            if [ "$current_email" = "null" ]; then current_email=""; fi
            
            echo "正在配置端口: $port"
            echo "当前邮箱: ${current_email:-未设置}"
            echo "输入 'd' 或 'delete' 可删除邮箱配置"
            read -p "请输入接收邮箱: " new_email
            
            if [ "$new_email" = "d" ] || [ "$new_email" = "delete" ]; then
                update_config "del(.ports.\"$port\".email)"
                echo -e "${YELLOW}已删除端口 $port 的邮箱配置${NC}"
            elif [[ "$new_email" =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$ ]]; then
                update_config ".ports.\"$port\".email = \"$new_email\""
                echo -e "${GREEN}端口 $port 邮箱已设置为: $new_email${NC}"
            else
                echo -e "${RED}邮箱格式错误，未保存${NC}"
            fi
            sleep 1
        else
            echo -e "${RED}无效选择${NC}"
            sleep 1
        fi
    done
}

# 邮件通知设置管理
email_manage_settings() {
    while true; do
        echo -e "${BLUE}=== 通知设置管理 ===${NC}"
        echo "1. 状态通知间隔"
        echo "2. 开启/关闭切换"
        echo "0. 返回上级菜单"
        echo
        read -p "请选择操作 [0-2]: " choice

        case $choice in
            1) email_configure_interval ;;
            2) email_toggle_status_notifications ;;
            0) return 0 ;;
            *) echo -e "${RED}无效选择${NC}"; sleep 1 ;;
        esac
    done
}

# 配置邮件通知间隔
email_configure_interval() {
    local current_interval=$(jq -r '.notifications.email.status_notifications.interval' "$CONFIG_FILE")

    echo -e "${BLUE}=== 状态通知间隔设置 ===${NC}"
    local interval_display="未设置"
    if [ -n "$current_interval" ] && [ "$current_interval" != "null" ]; then
        interval_display="$current_interval"
    fi
    echo -e "当前间隔: $interval_display"
    echo
    local interval=$(select_notification_interval)

    update_config ".notifications.email.status_notifications.interval = \"$interval\""
    echo -e "${GREEN}状态通知间隔已设置为: $interval${NC}"

    setup_email_notification_cron

    sleep 2
}

# 切换邮件状态通知开关
email_toggle_status_notifications() {
    local current_status=$(jq -r '.notifications.email.status_notifications.enabled // false' "$CONFIG_FILE")

    if [ "$current_status" = "true" ]; then
        update_config ".notifications.email.status_notifications.enabled = false"
        echo -e "${GREEN}状态通知已关闭${NC}"
    else
        update_config ".notifications.email.status_notifications.enabled = true"
        echo -e "${GREEN}状态通知已开启${NC}"
    fi

    setup_email_notification_cron
    sleep 2
}

# 查看邮件通知日志
email_view_logs() {
    echo -e "${BLUE}=== 邮件通知日志 ===${NC}"
    echo

    local log_file="$CONFIG_DIR/logs/notification.log"
    if [ ! -f "$log_file" ]; then
        echo -e "${YELLOW}暂无通知日志${NC}"
        sleep 2
        return
    fi

    echo "最近20条邮件相关日志:"
    echo "────────────────────────────────────────────────────────"
    grep "邮件通知" "$log_file" | tail -n 20 || echo "暂无邮件相关日志"
    echo "────────────────────────────────────────────────────────"
    echo
    read -p "按回车键返回..."
}

# 通用状态通知发送函数
send_status_notification() {
    local success_count=0
    local total_count=0

    # 发送Telegram通知
    local telegram_script="$CONFIG_DIR/notifications/telegram.sh"
    if [ -f "$telegram_script" ]; then
        source "$telegram_script"
        total_count=$((total_count + 1))
        if telegram_send_status_notification; then
            success_count=$((success_count + 1))
        fi
    fi

    # 发送企业wx 通知
    local wecom_script="$CONFIG_DIR/notifications/wecom.sh"
    if [ -f "$wecom_script" ]; then
        source "$wecom_script"
        total_count=$((total_count + 1))
        if wecom_send_status_notification; then
            success_count=$((success_count + 1))
        fi
    fi

    # 发送邮件通知
    if email_is_enabled; then
        total_count=$((total_count + 1))
        if email_send_status_notification; then
            success_count=$((success_count + 1))
        fi
    fi

    if [ $total_count -eq 0 ]; then
        log_notification "通知模块不存在"
        echo -e "${RED}通知模块不存在${NC}"
        return 1
    elif [ $success_count -gt 0 ]; then
        echo -e "${GREEN}状态通知发送成功 ($success_count/$total_count)${NC}"
        return 0
    else
        echo -e "${RED}状态通知发送失败${NC}"
        return 1
    fi
}

# ============================================================================
# 流量备份管理模块
# ============================================================================

# 初始化备份配置
init_backup_config() {
    mkdir -p "$BACKUP_DIR"
    
    if [ ! -f "$BACKUP_CONFIG_FILE" ]; then
        cat > "$BACKUP_CONFIG_FILE" << 'EOF'
{
  "auto_backup_enabled": false,
  "backup_time": "00:10",
  "last_backup_time": ""
}
EOF
    fi
}

# 执行流量备份
perform_backup() {
    local backup_time=$(get_beijing_time -Iseconds)
    local backup_date=$(get_beijing_time +%Y%m%d_%H%M%S)
    local backup_file="$BACKUP_DIR/traffic_backup_${backup_date}.json"
    
    echo -e "${BLUE}正在备份流量数据...${NC}"
    
    local active_ports=($(get_active_ports))
    if [ ${#active_ports[@]} -eq 0 ]; then
        echo -e "${YELLOW}暂无监控端口，无需备份${NC}"
        return 1
    fi
    
    # 创建备份JSON
    local backup_data="{"
    backup_data+="\"backup_time\":\"$backup_time\","
    backup_data+="\"ports\":{"
    
    local first=true
    for port in "${active_ports[@]}"; do
        local traffic_data=($(get_nftables_counter_data "$port"))
        local input_bytes=${traffic_data[0]}
        local output_bytes=${traffic_data[1]}
        local remark=$(jq -r ".ports.\"$port\".remark // \"\"" "$CONFIG_FILE")
        local billing_mode=$(jq -r ".ports.\"$port\".billing_mode // \"double\"" "$CONFIG_FILE")
        
        if [ "$first" = true ]; then
            first=false
        else
            backup_data+=","
        fi
        
        # 转义备注中的特殊字符
        local escaped_remark=$(echo "$remark" | sed 's/\\/\\\\/g; s/"/\\"/g')
        
        backup_data+="\"$port\":{"
        backup_data+="\"input\":$input_bytes,"
        backup_data+="\"output\":$output_bytes,"
        backup_data+="\"remark\":\"$escaped_remark\","
        backup_data+="\"billing_mode\":\"$billing_mode\""
        backup_data+="}"
    done
    
    backup_data+="}}"
    
    # 保存备份文件
    echo "$backup_data" | jq '.' > "$backup_file"
    
    # 更新最后备份时间
    jq ".last_backup_time = \"$backup_time\"" "$BACKUP_CONFIG_FILE" > "${BACKUP_CONFIG_FILE}.tmp" && \
        mv "${BACKUP_CONFIG_FILE}.tmp" "$BACKUP_CONFIG_FILE"
    
    # 清理旧备份，只保留最新的MAX_BACKUPS个
    cleanup_old_backups
    
    local file_size=$(du -h "$backup_file" | awk '{print $1}')
    echo -e "${GREEN}✓ 备份成功！${NC}"
    echo "  备份文件: $backup_file"
    echo "  文件大小: $file_size"
    echo "  备份时间: $backup_time"
    
    return 0
}

# 清理旧备份
cleanup_old_backups() {
    local backup_files=($(ls -t "$BACKUP_DIR"/traffic_backup_*.json 2>/dev/null))
    local count=${#backup_files[@]}
    
    if [ $count -gt $MAX_BACKUPS ]; then
        echo -e "${YELLOW}清理旧备份...${NC}"
        for ((i=$MAX_BACKUPS; i<$count; i++)); do
            rm -f "${backup_files[$i]}"
            echo "  已删除: $(basename "${backup_files[$i]}")"
        done
    fi
}

# 查看最新备份
view_latest_backup() {
    local latest_backup=$(ls -t "$BACKUP_DIR"/traffic_backup_*.json 2>/dev/null | head -n1)
    
    if [ -z "$latest_backup" ]; then
        echo -e "${YELLOW}暂无备份记录${NC}"
        return 1
    fi
    
    echo -e "${BLUE}=== 最新备份详情 ===${NC}"
    echo
    
    local backup_time=$(jq -r '.backup_time' "$latest_backup")
    echo -e "${GREEN}备份时间:${NC} $backup_time"
    echo -e "${GREEN}备份文件:${NC} $(basename "$latest_backup")"
    echo
    echo "────────────────────────────────────────────────────────"
    
    # 读取备份的端口数据
    local ports=($(jq -r '.ports | keys[]' "$latest_backup"))
    
    for port in "${ports[@]}"; do
        local backup_input=$(jq -r ".ports.\"$port\".input" "$latest_backup")
        local backup_output=$(jq -r ".ports.\"$port\".output" "$latest_backup")
        
        # 优先从备份文件读取备注和计费模式，如果没有再从当前配置读取
        local backup_remark=$(jq -r ".ports.\"$port\".remark // \"\"" "$latest_backup")
        local backup_billing_mode=$(jq -r ".ports.\"$port\".billing_mode // \"\"" "$latest_backup")
        
        local remark="$backup_remark"
        local billing_mode="$backup_billing_mode"
        
        # 如果备份中没有，尝试从当前配置读取
        if [ -z "$remark" ]; then
            remark=$(jq -r ".ports.\"$port\".remark // \"\"" "$CONFIG_FILE" 2>/dev/null)
        fi
        if [ -z "$billing_mode" ]; then
            billing_mode=$(jq -r ".ports.\"$port\".billing_mode // \"double\"" "$CONFIG_FILE" 2>/dev/null)
        fi
        [ -z "$billing_mode" ] && billing_mode="double"
        
        # 获取当前值
        local current_data=($(get_nftables_counter_data "$port" 2>/dev/null || echo "0 0"))
        local current_input=${current_data[0]}
        local current_output=${current_data[1]}
        
        # 计算当前总流量和备份总流量
        local backup_total=$(calculate_total_traffic "$backup_input" "$backup_output" "$billing_mode")
        local current_total=$(calculate_total_traffic "$current_input" "$current_output" "$billing_mode")
        local diff=$((current_total - backup_total))
        
        local display_name="端口 $port"
        if [ -n "$remark" ]; then
            display_name+=" [$remark]"
        fi
        
        echo -e "${BLUE}$display_name${NC}"
        echo "  备份总流量: $(format_bytes $backup_total)"
        echo "  当前总流量: $(format_bytes $current_total)"
        if [ $diff -gt 0 ]; then
            echo -e "  新增流量: ${GREEN}+$(format_bytes $diff)${NC}"
        else
            echo "  新增流量: 0B"
        fi
        echo
    done
    
    echo "────────────────────────────────────────────────────────"
}

# 查看所有备份历史
view_backup_history() {
    local backup_files=($(ls -t "$BACKUP_DIR"/traffic_backup_*.json 2>/dev/null))
    
    if [ ${#backup_files[@]} -eq 0 ]; then
        echo -e "${YELLOW}暂无备份记录${NC}"
        return 1
    fi
    
    echo -e "${BLUE}=== 备份历史记录 (共${#backup_files[@]}个) ===${NC}"
    echo
    echo "────────────────────────────────────────────────────────"
    
    for i in "${!backup_files[@]}"; do
        local file="${backup_files[$i]}"
        local backup_time=$(jq -r '.backup_time' "$file")
        local file_size=$(du -h "$file" | awk '{print $1}')
        local filename=$(basename "$file")
        
        # 计算备份中的总流量
        local total_bytes=0
        local ports=($(jq -r '.ports | keys[]' "$file"))
        for port in "${ports[@]}"; do
            local input=$(jq -r ".ports.\"$port\".input" "$file")
            local output=$(jq -r ".ports.\"$port\".output" "$file")
            local billing_mode=$(jq -r ".ports.\"$port\".billing_mode // \"double\"" "$CONFIG_FILE")
            local port_total=$(calculate_total_traffic "$input" "$output" "$billing_mode")
            total_bytes=$((total_bytes + port_total))
        done
        
        echo -e "${GREEN}$((i+1)). $filename${NC}"
        echo "   时间: $backup_time"
        echo "   大小: $file_size"
        echo "   端口总流量: $(format_bytes $total_bytes)"
        echo
    done
    
    echo "────────────────────────────────────────────────────────"
}

# 从备份恢复流量数据
restore_from_backup() {
    local backup_files=($(ls -t "$BACKUP_DIR"/traffic_backup_*.json 2>/dev/null))
    
    if [ ${#backup_files[@]} -eq 0 ]; then
        echo -e "${YELLOW}暂无可用备份${NC}"
        return 1
    fi
    
    echo -e "${RED}警告: 此操作将覆盖当前所有流量数据！${NC}"
    echo
    echo "可用备份列表:"
    echo
    
    for i in "${!backup_files[@]}"; do
        local file="${backup_files[$i]}"
        local backup_time=$(jq -r '.backup_time' "$file")
        local filename=$(basename "$file")
        echo "$((i+1)). $filename ($backup_time)"
    done
    echo
    echo "0. 取消"
    echo
    
    read -p "请选择要恢复的备份 [0-${#backup_files[@]}]: " choice
    
    if [ "$choice" = "0" ]; then
        echo "已取消"
        return 0
    fi
    
    if ! [[ "$choice" =~ ^[0-9]+$ ]] || [ "$choice" -lt 1 ] || [ "$choice" -gt ${#backup_files[@]} ]; then
        echo -e "${RED}无效选择${NC}"
        return 1
    fi
    
    local selected_backup="${backup_files[$((choice-1))]}"
    local backup_time=$(jq -r '.backup_time' "$selected_backup")
    
    echo
    echo -e "${YELLOW}将从以下备份恢复:${NC}"
    echo "  文件: $(basename "$selected_backup")"
    echo "  时间: $backup_time"
    echo
    read -p "确认恢复? [y/N]: " confirm
    
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        echo "已取消"
        return 0
    fi
    
    echo
    echo -e "${BLUE}开始恢复流量数据...${NC}"
    
    local ports=($(jq -r '.ports | keys[]' "$selected_backup"))
    local table_name=$(jq -r '.nftables.table_name' "$CONFIG_FILE")
    local family=$(jq -r '.nftables.family' "$CONFIG_FILE")
    
    for port in "${ports[@]}"; do
        local backup_input=$(jq -r ".ports.\"$port\".input" "$selected_backup")
        local backup_output=$(jq -r ".ports.\"$port\".output" "$selected_backup")
        
        echo "恢复端口 $port..."
        
        # 确定端口安全名称
        local port_safe
        if is_port_group "$port"; then
            port_safe=$(generate_port_group_safe_name "$port")
        elif is_port_range "$port"; then
            port_safe=$(echo "$port" | tr '-' '_')
        else
            port_safe="$port"
        fi
        
        # 删除所有规则
        while true; do
            handle=$(nft -a list table $family $table_name 2>/dev/null | \
                grep -E "(tcp|udp).*(dport|sport).*port_${port_safe}_" | \
                head -n1 | sed -n 's/.*# handle \([0-9]\+\)$/\1/p')
            [ -z "$handle" ] && break
            for chain in input output forward prerouting; do
                nft delete rule $family $table_name $chain handle $handle 2>/dev/null && break
            done
        done
        
        # 删除并重建计数器
        nft delete counter $family $table_name "port_${port_safe}_in" 2>/dev/null
        nft delete counter $family $table_name "port_${port_safe}_out" 2>/dev/null
        nft add counter $family $table_name "port_${port_safe}_in" { packets 0 bytes $backup_input }
        nft add counter $family $table_name "port_${port_safe}_out" { packets 0 bytes $backup_output }
        
        # 重新添加规则
        add_nftables_rules "$port"
        
        echo "  ✓ 已恢复"
    done
    
    echo
    echo -e "${GREEN}✓ 所有流量数据已从备份恢复！${NC}"
    sleep 2
}

# 设置自动备份
toggle_auto_backup() {
    local enabled=$(jq -r '.auto_backup_enabled' "$BACKUP_CONFIG_FILE")
    local backup_time="00:10"  # 固定为北京时间凌晨00:10（与流量重置00:05错开）
    
    # 获取系统时区信息
    local system_tz=$(get_system_timezone)
    local local_time=($(convert_beijing_to_local_time "00" "10"))
    local local_hour=${local_time[0]}
    local local_minute=${local_time[1]}
    
    echo -e "${BLUE}=== 自动备份设置 ===${NC}"
    echo
    echo -e "${GRAY}系统时区: $system_tz${NC}"
    echo -e "${GRAY}北京时间 00:10 对应系统本地时间 ${local_hour}:${local_minute}${NC}"
    echo
    
    if [ "$enabled" = "true" ]; then
        echo -e "当前状态: ${GREEN}已开启${NC}"
        echo "备份时间: 每天北京时间 $backup_time"
        echo
        read -p "是否关闭自动备份? [y/N]: " confirm
        
        if [[ "$confirm" =~ ^[Yy]$ ]]; then
            jq '.auto_backup_enabled = false' "$BACKUP_CONFIG_FILE" > "${BACKUP_CONFIG_FILE}.tmp" && \
                mv "${BACKUP_CONFIG_FILE}.tmp" "$BACKUP_CONFIG_FILE"
            remove_backup_cron
            echo -e "${GREEN}✓ 已关闭自动备份${NC}"
        fi
    else
        echo -e "当前状态: ${YELLOW}已关闭${NC}"
        echo
        echo -e "开启后将在每天北京时间 ${GREEN}$backup_time${NC} 自动备份流量数据"
        echo "自动保留最近7天的备份（循环覆盖）"
        echo
        read -p "是否开启自动备份? [y/N]: " confirm
        
        if [[ "$confirm" =~ ^[Yy]$ ]]; then
            jq ".auto_backup_enabled = true | .backup_time = \"$backup_time\"" "$BACKUP_CONFIG_FILE" > "${BACKUP_CONFIG_FILE}.tmp" && \
                mv "${BACKUP_CONFIG_FILE}.tmp" "$BACKUP_CONFIG_FILE"
            setup_backup_cron "$backup_time"
            echo -e "${GREEN}✓ 已开启自动备份，每天北京时间 $backup_time 执行${NC}"
            echo -e "${GRAY}  (系统本地时间: ${local_hour}:${local_minute})${NC}"
        fi
    fi
    
    sleep 2
}

# 设置备份定时任务
setup_backup_cron() {
    local time=$1
    local hour=$(echo "$time" | cut -d':' -f1)
    local minute=$(echo "$time" | cut -d':' -f2)
    
    # 将北京时间转换为系统本地时间
    local local_time=($(convert_beijing_to_local_time "$hour" "$minute"))
    local local_hour=${local_time[0]:-$hour}
    local local_minute=${local_time[1]:-$minute}
    
    # 验证转换结果
    if ! [[ "$local_hour" =~ ^[0-9]+$ ]] || ! [[ "$local_minute" =~ ^[0-9]+$ ]]; then
        echo -e "${RED}错误：时区转换失败，使用原始时间${NC}" >&2
        local_hour=$hour
        local_minute=$minute
    fi
    
    # 删除旧的定时任务
    remove_backup_cron

    # 添加新的定时任务（使用转换后的本地时间）
    local temp_cron=$(mktemp)
    crontab -l 2>/dev/null > "$temp_cron" || true
    grep -v -- "--auto-backup" "$temp_cron" > "${temp_cron}.clean" || true
    mv "${temp_cron}.clean" "$temp_cron"
    echo "$local_minute $local_hour * * * $SCRIPT_PATH --auto-backup >> $LOG_FILE 2>&1" >> "$temp_cron"
    if ! crontab "$temp_cron" 2>/dev/null; then
        rm -f "$temp_cron"
        echo -e "${RED}写入备份定时任务失败${NC}" >&2
        return 1
    fi
    rm -f "$temp_cron"
}

# 删除备份定时任务
remove_backup_cron() {
    crontab -l 2>/dev/null | grep -v "$SCRIPT_PATH.*--auto-backup\|/dog.*--auto-backup" | crontab - 2>/dev/null || true
}

# 备份管理主菜单
manage_backup() {
    init_backup_config
    
    while true; do
        clear
        echo -e "${BLUE}=== 流量数据备份管理 ===${NC}"
        echo
        
        local enabled=$(jq -r '.auto_backup_enabled' "$BACKUP_CONFIG_FILE")
        local backup_time=$(jq -r '.backup_time' "$BACKUP_CONFIG_FILE")
        local last_backup=$(jq -r '.last_backup_time' "$BACKUP_CONFIG_FILE")
        
        if [ "$enabled" = "true" ]; then
            echo -e "自动备份状态: ${GREEN}已开启${NC} (每天 $backup_time)"
        else
            echo -e "自动备份状态: ${YELLOW}已关闭${NC}"
        fi
        
        if [ -n "$last_backup" ] && [ "$last_backup" != "null" ] && [ "$last_backup" != "" ]; then
            echo -e "最后备份时间: ${GREEN}$last_backup${NC}"
        else
            echo "最后备份时间: 从未备份"
        fi
        
        local backup_count=$(ls "$BACKUP_DIR"/traffic_backup_*.json 2>/dev/null | wc -l)
        echo -e "备份数量: ${BLUE}$backup_count/$MAX_BACKUPS${NC}"
        
        echo
        echo "────────────────────────────────────────────────────────"
        echo -e "${BLUE}1.${NC} 开启/关闭自动备份"
        echo -e "${BLUE}2.${NC} 立即执行备份"
        echo -e "${BLUE}3.${NC} 查看最新备份详情"
        echo -e "${BLUE}4.${NC} 查看所有备份历史"
        echo -e "${BLUE}5.${NC} 从备份恢复流量数据"
        echo -e "${BLUE}0.${NC} 返回主菜单"
        echo
        read -p "请选择操作 [0-5]: " choice
        
        case $choice in
            1) toggle_auto_backup ;;
            2) perform_backup; sleep 3 ;;
            3) view_latest_backup; read -p "按回车继续..." ;;
            4) view_backup_history; read -p "按回车继续..." ;;
            5) restore_from_backup ;;
            0) return ;;
            *) echo -e "${RED}无效选择${NC}"; sleep 1 ;;
        esac
    done
}

# ============================================================================
# Private Network 配置模块 (绿云内网互通)
# ============================================================================

# 常量定义
readonly PRIVATE_NET_INTERFACE="eth1"
readonly PRIVATE_NET_CONFIG_FILE="/etc/network/interfaces.d/eth1.cfg"
readonly PRIVATE_NET_DEFAULT_NETMASK="255.255.0.0"
readonly PRIVATE_NET_DEFAULT_PREFIX="16"

# 检查是否支持当前系统
check_private_net_support() {
    # 只支持 Debian 12/13
    if [ -f /etc/os-release ]; then
        local os_id=$(grep "^ID=" /etc/os-release | cut -d'=' -f2 | tr -d '"')
        local os_version=$(grep "^VERSION_ID=" /etc/os-release | cut -d'=' -f2 | tr -d '"')
        
        if [ "$os_id" = "debian" ]; then
            if [[ "$os_version" =~ ^(12|13) ]]; then
                return 0
            fi
        fi
    fi
    return 1
}

# 检查 eth1 接口是否存在
check_eth1_exists() {
    ip link show "$PRIVATE_NET_INTERFACE" &>/dev/null
}

# 获取 eth1 当前 IP
get_eth1_ip() {
    ip addr show "$PRIVATE_NET_INTERFACE" 2>/dev/null | grep -oP 'inet \K[0-9.]+' | head -n1
}

# 获取 eth1 状态
get_eth1_status() {
    local state=$(ip link show "$PRIVATE_NET_INTERFACE" 2>/dev/null | grep -oP 'state \K\w+')
    echo "${state:-UNKNOWN}"
}

# 验证 IP 地址格式
validate_ip_address() {
    local ip=$1
    if [[ $ip =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        local IFS='.'
        read -ra octets <<< "$ip"
        for octet in "${octets[@]}"; do
            if [ "$octet" -gt 255 ]; then
                return 1
            fi
        done
        return 0
    fi
    return 1
}

# 显示 Private Network 状态
show_private_net_status() {
    echo -e "${BLUE}=== Private Network 状态 ===${NC}"
    echo
    
    # 检查系统支持
    if ! check_private_net_support; then
        echo -e "${YELLOW}⚠️  当前系统不是 Debian 12/13，功能可能不完全兼容${NC}"
        echo
    fi
    
    # 检查 eth1 是否存在
    if ! check_eth1_exists; then
        echo -e "${RED}❌ eth1 接口不存在${NC}"
        echo
        echo "说明: 绿云 VPS 需要先开通内网功能才会有 eth1 接口"
        echo "请联系绿云客服开通 Private Network 功能"
        return 1
    fi
    
    echo -e "${GREEN}✅ eth1 接口存在${NC}"
    echo
    
    # 获取当前状态
    local current_ip=$(get_eth1_ip)
    local current_status=$(get_eth1_status)
    
    echo "────────────────────────────────────────────────────────"
    echo -e "接口状态: $([ "$current_status" = "UP" ] && echo -e "${GREEN}$current_status${NC}" || echo -e "${YELLOW}$current_status${NC}")"
    
    if [ -n "$current_ip" ]; then
        echo -e "内网 IP:  ${GREEN}$current_ip${NC}"
    else
        echo -e "内网 IP:  ${YELLOW}未配置${NC}"
    fi
    
    # 显示配置文件状态
    if [ -f "$PRIVATE_NET_CONFIG_FILE" ]; then
        echo -e "配置文件: ${GREEN}已存在${NC}"
        echo
        echo "配置内容:"
        echo "────────────────────────────────────────────────────────"
        cat "$PRIVATE_NET_CONFIG_FILE" | sed 's/^/  /'
        echo "────────────────────────────────────────────────────────"
    else
        echo -e "配置文件: ${YELLOW}未创建${NC}"
    fi
    echo
    
    return 0
}

# 配置内网 IP
configure_private_net_ip() {
    echo -e "${BLUE}=== 配置内网 IP ===${NC}"
    echo
    
    # 检查系统支持
    if ! check_private_net_support; then
        echo -e "${RED}❌ 仅支持 Debian 12/13 系统${NC}"
        echo "其他系统请参考绿云官方文档手动配置"
        sleep 2
        return 1
    fi
    
    # 检查 eth1 是否存在
    if ! check_eth1_exists; then
        echo -e "${RED}❌ eth1 接口不存在${NC}"
        echo
        echo "说明: 绿云 VPS 需要先开通内网功能才会有 eth1 接口"
        echo "请联系绿云客服开通 Private Network 功能"
        sleep 2
        return 1
    fi
    
    # 检查是否已配置
    local current_ip=$(get_eth1_ip)
    if [ -n "$current_ip" ]; then
        echo -e "${YELLOW}⚠️  eth1 已配置 IP: $current_ip${NC}"
        echo
        read -p "是否覆盖现有配置? [y/N]: " confirm
        if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
            echo "已取消"
            sleep 1
            return 0
        fi
        echo
    fi
    
    # 提示输入 IP
    echo "请在 VirtFusion 面板 → Network 页面查看分配的 Private IP"
    echo
    read -p "请输入本机的内网 IP (如 10.0.1.5): " input_ip
    
    # 验证 IP 格式
    if [ -z "$input_ip" ]; then
        echo -e "${RED}错误: IP 不能为空${NC}"
        sleep 2
        return 1
    fi
    
    if ! validate_ip_address "$input_ip"; then
        echo -e "${RED}错误: IP 格式无效${NC}"
        sleep 2
        return 1
    fi
    
    # 显示配置预览
    echo
    echo -e "${BLUE}配置预览:${NC}"
    echo "────────────────────────────────────────────────────────"
    echo "  文件: $PRIVATE_NET_CONFIG_FILE"
    echo "  ┌────────────────────────────────────┐"
    echo "  │ auto $PRIVATE_NET_INTERFACE"
    echo "  │ iface $PRIVATE_NET_INTERFACE inet static"
    echo "  │     address $input_ip"
    echo "  │     netmask $PRIVATE_NET_DEFAULT_NETMASK"
    echo "  └────────────────────────────────────┘"
    echo "────────────────────────────────────────────────────────"
    echo
    
    read -p "确认配置并立即生效? [Y/n]: " confirm
    if [[ "$confirm" =~ ^[Nn]$ ]]; then
        echo "已取消"
        sleep 1
        return 0
    fi
    
    # 如果已有配置，先关闭接口
    if [ -f "$PRIVATE_NET_CONFIG_FILE" ]; then
        echo "正在关闭现有配置..."
        ifdown "$PRIVATE_NET_INTERFACE" 2>/dev/null || true
    fi
    
    # 写入配置文件
    echo "正在写入配置..."
    cat > "$PRIVATE_NET_CONFIG_FILE" << EOF
auto $PRIVATE_NET_INTERFACE
iface $PRIVATE_NET_INTERFACE inet static
    address $input_ip
    netmask $PRIVATE_NET_DEFAULT_NETMASK
EOF
    
    if [ $? -ne 0 ]; then
        echo -e "${RED}❌ 写入配置文件失败${NC}"
        sleep 2
        return 1
    fi
    
    # 激活接口
    echo "正在激活 eth1..."
    if ifup "$PRIVATE_NET_INTERFACE" 2>/dev/null; then
        echo
        echo -e "${GREEN}✅ 配置成功！${NC}"
        echo
        echo "当前状态:"
        ip addr show "$PRIVATE_NET_INTERFACE" | grep -E "state|inet " | sed 's/^/  /'
        echo
        echo -e "${YELLOW}💡 提示: 请在另一台 VPS 上也配置内网 IP 后测试连通性${NC}"
    else
        # ifup 失败，尝试使用 ip 命令
        echo -e "${YELLOW}ifup 命令执行异常，尝试使用 ip 命令...${NC}"
        ip addr add "$input_ip/$PRIVATE_NET_DEFAULT_PREFIX" dev "$PRIVATE_NET_INTERFACE" 2>/dev/null || true
        ip link set "$PRIVATE_NET_INTERFACE" up 2>/dev/null || true
        
        local new_ip=$(get_eth1_ip)
        if [ -n "$new_ip" ]; then
            echo
            echo -e "${GREEN}✅ 配置成功！${NC}"
            echo
            echo "当前状态:"
            ip addr show "$PRIVATE_NET_INTERFACE" | grep -E "state|inet " | sed 's/^/  /'
        else
            echo -e "${RED}❌ 激活接口失败${NC}"
            sleep 2
            return 1
        fi
    fi
    
    sleep 2
    return 0
}

# 删除内网配置
remove_private_net_config() {
    echo -e "${BLUE}=== 删除内网配置 ===${NC}"
    echo
    
    local current_ip=$(get_eth1_ip)
    
    if [ -z "$current_ip" ] && [ ! -f "$PRIVATE_NET_CONFIG_FILE" ]; then
        echo -e "${YELLOW}暂无内网配置${NC}"
        sleep 2
        return 0
    fi
    
    echo "当前配置:"
    [ -n "$current_ip" ] && echo "  内网 IP: $current_ip"
    [ -f "$PRIVATE_NET_CONFIG_FILE" ] && echo "  配置文件: $PRIVATE_NET_CONFIG_FILE"
    echo
    
    echo -e "${RED}警告: 删除后内网将无法通信，需要重新配置${NC}"
    read -p "确认删除? [y/N]: " confirm
    
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        echo "已取消"
        sleep 1
        return 0
    fi
    
    echo
    echo "正在删除配置..."
    
    # 关闭接口
    ifdown "$PRIVATE_NET_INTERFACE" 2>/dev/null || true
    
    # 清除 IP
    if [ -n "$current_ip" ]; then
        ip addr del "$current_ip/$PRIVATE_NET_DEFAULT_PREFIX" dev "$PRIVATE_NET_INTERFACE" 2>/dev/null || true
    fi
    
    # 关闭接口
    ip link set "$PRIVATE_NET_INTERFACE" down 2>/dev/null || true
    
    # 删除配置文件
    if [ -f "$PRIVATE_NET_CONFIG_FILE" ]; then
        rm -f "$PRIVATE_NET_CONFIG_FILE"
    fi
    
    echo -e "${GREEN}✅ 内网配置已删除${NC}"
    sleep 2
    return 0
}

# 测试内网连通性
test_private_net_connectivity() {
    echo -e "${BLUE}=== 测试内网连通性 ===${NC}"
    echo
    
    local current_ip=$(get_eth1_ip)
    
    if [ -z "$current_ip" ]; then
        echo -e "${YELLOW}本机内网未配置，请先配置内网 IP${NC}"
        sleep 2
        return 1
    fi
    
    echo "本机内网 IP: $current_ip"
    echo
    read -p "请输入对端 VPS 的内网 IP: " target_ip
    
    if [ -z "$target_ip" ]; then
        echo -e "${RED}错误: IP 不能为空${NC}"
        sleep 2
        return 1
    fi
    
    if ! validate_ip_address "$target_ip"; then
        echo -e "${RED}错误: IP 格式无效${NC}"
        sleep 2
        return 1
    fi
    
    echo
    echo "正在测试到 $target_ip 的连通性..."
    echo "────────────────────────────────────────────────────────"
    
    if ping -c 4 -W 3 "$target_ip"; then
        echo "────────────────────────────────────────────────────────"
        echo
        echo -e "${GREEN}✅ 连通性测试成功！内网互通正常${NC}"
    else
        echo "────────────────────────────────────────────────────────"
        echo
        echo -e "${RED}❌ 连通性测试失败${NC}"
        echo
        echo "可能原因:"
        echo "  1. 对端 VPS 未配置内网 IP"
        echo "  2. 两台 VPS 不在同一机房/内网 VLAN"
        echo "  3. 需要联系绿云客服确认内网配置"
    fi
    
    echo
    read -p "按回车键返回..." _
    return 0
}

# Private Network 管理主菜单
manage_private_network() {
    while true; do
        clear
        echo -e "${BLUE}=== Private Network 配置 ===${NC}"
        echo -e "${GRAY}绿云 VPS 内网互通配置${NC}"
        echo
        
        # 显示当前状态
        local eth1_exists="否"
        local current_ip="未配置"
        local current_status="--"
        
        if check_eth1_exists; then
            eth1_exists="是"
            local ip=$(get_eth1_ip)
            [ -n "$ip" ] && current_ip="$ip"
            current_status=$(get_eth1_status)
        fi
        
        echo "当前状态:"
        echo "  eth1 接口: $eth1_exists"
        if [ "$eth1_exists" = "是" ]; then
            echo -e "  内网 IP:  $([ "$current_ip" = "未配置" ] && echo -e "${YELLOW}$current_ip${NC}" || echo -e "${GREEN}$current_ip${NC}")"
            echo -e "  接口状态: $([ "$current_status" = "UP" ] && echo -e "${GREEN}$current_status${NC}" || echo -e "${YELLOW}$current_status${NC}")"
        fi
        
        echo
        echo "────────────────────────────────────────────────────────"
        echo -e "${BLUE}1.${NC} 配置内网 IP"
        echo -e "${BLUE}2.${NC} 查看详细状态"
        echo -e "${BLUE}3.${NC} 删除内网配置"
        echo -e "${BLUE}4.${NC} 测试内网连通性"
        echo -e "${BLUE}0.${NC} 返回主菜单"
        echo
        read -p "请选择操作 [0-4]: " choice
        
        case $choice in
            1) configure_private_net_ip ;;
            2) show_private_net_status; read -p "按回车继续..." _ ;;
            3) remove_private_net_config ;;
            4) test_private_net_connectivity ;;
            0) return ;;
            *) echo -e "${RED}无效选择${NC}"; sleep 1 ;;
        esac
    done
}

# ============================================================================
# 主函数
# ============================================================================

main() {
    check_root
    check_dependencies
    init_config

    create_shortcut_command

    if [ $# -gt 0 ]; then
        case $1 in
            --check-deps)
                echo -e "${GREEN}依赖检查通过${NC}"
                exit 0
                ;;
            --version)
                echo -e "${BLUE}$SCRIPT_NAME v$SCRIPT_VERSION${NC}"
                echo -e "${GREEN}作者主页:${NC} https://zywe.de"
                echo -e "${GREEN}项目开源:${NC} https://github.com/zywe03/realm-xwPF"
                exit 0
                ;;
            --install)
                install_update_script
                exit 0
                ;;
            --uninstall)
                uninstall_script
                exit 0
                ;;
            --auto-backup)
                init_backup_config
                perform_backup
                exit 0
                ;;
            --send-status)
                send_status_notification
                exit 0
                ;;
            --send-telegram-status)
                local telegram_script="$CONFIG_DIR/notifications/telegram.sh"
                if [ -f "$telegram_script" ]; then
                    source "$telegram_script"
                    telegram_send_status_notification
                fi
                exit 0
                ;;
            --send-wecom-status)
                local wecom_script="$CONFIG_DIR/notifications/wecom.sh"
                if [ -f "$wecom_script" ]; then
                    source "$wecom_script"
                    wecom_send_status_notification
                fi
                exit 0
                ;;
            --send-email-status)
                email_send_status_notification
                exit 0
                ;;
            --daily-check)
                check_all_ports_expiration
                exit 0
                ;;
            --reset-port)
                if [ $# -lt 2 ]; then
                    echo -e "${RED}错误：--reset-port 需要指定端口号${NC}"
                    exit 1
                fi
                auto_reset_port "$2"
                exit 0
                ;;
            --reset-port-if-match)
                if [ $# -lt 3 ]; then
                    echo -e "${RED}错误：--reset-port-if-match 需要指定端口号和日期${NC}"
                    exit 1
                fi
                local port_to_reset="$2"
                local target_day="$3"
                
                # 判断今天是否是目标日期
                if should_run_monthly_task "$target_day"; then
                    # 是目标日期，执行重置
                    auto_reset_port "$port_to_reset"
                    log_action "端口 $port_to_reset 流量已重置（北京时间${target_day}号）"
                else
                    # 不是目标日期，跳过
                    local beijing_today=$(TZ='Asia/Shanghai' date +%-d)
                    log_action "今天是北京时间${beijing_today}号，跳过端口 $port_to_reset 的重置（目标日期:${target_day}号）"
                fi
                exit 0
                ;;
            *)
                echo -e "${YELLOW}用法: $0 [选项]${NC}"
                echo "选项:"
                echo "  --check-deps              检查依赖工具"
                echo "  --version                 显示版本信息"
                echo "  --install                 安装/更新脚本"
                echo "  --uninstall               卸载脚本"
                echo "  --send-status             发送所有启用的状态通知"
                echo "  --send-telegram-status    发送Telegram状态通知"
                echo "  --send-wecom-status       发送企业wx 状态通知"
                echo "  --send-email-status       发送邮件状态通知"
                echo "  --reset-port PORT         重置指定端口流量"
                echo
                echo -e "${GREEN}快捷命令: $SHORTCUT_COMMAND${NC}"
                exit 1
                ;;
        esac
    fi

    show_main_menu
}

main "$@"
