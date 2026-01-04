#!/bin/bash
#═══════════════════════════════════════════════════════════════════════════════
#  多协议代理一键部署脚本 v3.1.3 [服务端]
#  
#  架构升级:
#    • Xray 核心: 处理 TCP/TLS 协议 (VLESS/VMess/Trojan/SOCKS/SS2022)
#    • Sing-box 核心: 处理 UDP/QUIC 协议 (Hysteria2/TUIC) - 低内存高效率
#  
#  支持协议: VLESS+Reality / VLESS+Reality+XHTTP / VLESS+WS / VMess+WS / 
#           VLESS-XTLS-Vision / SOCKS5 / SS2022 / HY2 / Trojan / 
#           Snell v4 / Snell v5 / AnyTLS / TUIC / NaïveProxy (共14种)
#  插件支持: Snell v4/v5 和 SS2022 可选启用 ShadowTLS
#  适配: Alpine/Debian/Ubuntu/CentOS
#  
#  作者: Chil30
#  项目地址: https://github.com/Chil30/vless-all-in-one
#═══════════════════════════════════════════════════════════════════════════════

readonly VERSION="3.1.3"
readonly AUTHOR="Chil30"
readonly REPO_URL="https://github.com/Chil30/vless-all-in-one"
readonly CFG="/etc/vless-reality"

# curl 超时常量
readonly CURL_TIMEOUT_FAST=5
readonly CURL_TIMEOUT_NORMAL=10
readonly CURL_TIMEOUT_DOWNLOAD=60

# IP 缓存变量
_CACHED_IPV4=""
_CACHED_IPV6=""

# Alpine busybox pgrep 不支持 -x，使用兼容方式检测进程
_pgrep() {
    local proc="$1"
    if [[ "$DISTRO" == "alpine" ]]; then
        # Alpine busybox pgrep: 先尝试精确匹配，再尝试命令行匹配
        pgrep "$proc" >/dev/null 2>&1 || pgrep -f "$proc" >/dev/null 2>&1
    else
        pgrep -x "$proc" >/dev/null 2>&1
    fi
}

#═══════════════════════════════════════════════════════════════════════════════
#  全局状态数据库 (JSON)
#═══════════════════════════════════════════════════════════════════════════════
readonly DB_FILE="$CFG/db.json"

# 初始化数据库
init_db() {
    mkdir -p "$CFG" || return 1
    [[ -f "$DB_FILE" ]] && return 0
    local now tmp
    # Alpine busybox date 不支持 -Iseconds，使用兼容格式
    now=$(date '+%Y-%m-%dT%H:%M:%S%z' 2>/dev/null || date '+%Y-%m-%dT%H:%M:%S')
    tmp=$(mktemp) || return 1
    if jq -n --arg v "4.0.0" --arg t "$now" \
      '{version:$v,xray:{},singbox:{},meta:{created:$t,updated:$t}}' >"$tmp" 2>/dev/null; then
        mv "$tmp" "$DB_FILE"
        return 0
    fi
    # jq 失败时使用简单方式创建
    echo '{"version":"4.0.0","xray":{},"singbox":{},"meta":{}}' > "$DB_FILE"
    rm -f "$tmp"
    return 0
}

# 更新数据库时间戳
_db_touch() {
    [[ -f "$DB_FILE" ]] || init_db || return 1
    local now tmp
    now=$(date -Iseconds 2>/dev/null || date '+%Y-%m-%dT%H:%M:%S')
    tmp=$(mktemp) || return 1
    if jq --arg t "$now" '.meta.updated=$t' "$DB_FILE" >"$tmp"; then
        mv "$tmp" "$DB_FILE"
    else
        rm -f "$tmp"
        return 1
    fi
}

_db_apply() { # _db_apply [jq args...] 'filter'
    [[ -f "$DB_FILE" ]] || init_db || return 1
    local tmp; tmp=$(mktemp) || return 1
    if jq "$@" "$DB_FILE" >"$tmp" 2>/dev/null; then
        mv "$tmp" "$DB_FILE"
        _db_touch
        return 0
    fi
    rm -f "$tmp"
    return 1
}


# 添加协议到数据库
# 用法: db_add "xray" "vless" '{"uuid":"xxx","port":443,...}'
db_add() { # db_add core proto json
    local core="$1" proto="$2" json="$3"
    
    # 验证 JSON 格式
    if ! echo "$json" | jq empty 2>/dev/null; then
        _err "db_add: 无效的 JSON 格式 - $proto"
        return 1
    fi
    
    _db_apply --arg p "$proto" --argjson c "$json" ".${core}[\$p]=\$c"
}


# 从数据库获取协议配置
db_get() {
    [[ ! -f "$DB_FILE" ]] && return 1
    jq -r --arg p "$2" ".${1}[\$p] // empty" "$DB_FILE" 2>/dev/null
}

# 从数据库获取协议的某个字段
db_get_field() {
    [[ ! -f "$DB_FILE" ]] && return 1
    jq -r --arg p "$2" --arg f "$3" ".${1}[\$p][\$f] // empty" "$DB_FILE" 2>/dev/null
}

# 删除协议
db_del() { # db_del core proto
    _db_apply --arg p "$2" "del(.${1}[\$p])"
}


# 检查协议是否存在
db_exists() {
    [[ ! -f "$DB_FILE" ]] && return 1
    local val=$(jq -r --arg p "$2" ".${1}[\$p] // empty" "$DB_FILE" 2>/dev/null)
    [[ -n "$val" && "$val" != "null" ]]
}

# 获取某个核心下所有协议名
db_list_protocols() {
    [[ ! -f "$DB_FILE" ]] && return 1
    jq -r ".${1} | keys[]" "$DB_FILE" 2>/dev/null
}

# 获取所有已安装协议
db_get_all_protocols() {
    [[ ! -f "$DB_FILE" ]] && return 1
    { jq -r '.xray | keys[]' "$DB_FILE" 2>/dev/null; jq -r '.singbox | keys[]' "$DB_FILE" 2>/dev/null; } | sort -u
}

#═══════════════════════════════════════════════════════════════════════════════
#  通用配置保存函数
#═══════════════════════════════════════════════════════════════════════════════

# 简化版：直接用关联数组构建 JSON
# 用法: build_config "uuid" "$uuid" "port" "$port" "sni" "$sni"
build_config() {
    local args=()
    local keys=()
    
    while [[ $# -ge 2 ]]; do
        local key="$1" val="$2"
        shift 2
        keys+=("$key")
        # 数字检测
        if [[ "$val" =~ ^[0-9]+$ ]]; then
            args+=(--argjson "$key" "$val")
        else
            args+=(--arg "$key" "$val")
        fi
    done
    
    # 自动添加 IP
    local ipv4=$(get_ipv4) ipv6=$(get_ipv6)
    args+=(--arg "ipv4" "$ipv4" --arg "ipv6" "$ipv6")
    keys+=("ipv4" "ipv6")
    
    # 构建 jq 表达式
    local expr="{"
    local first=true
    for k in "${keys[@]}"; do
        [[ "$first" == "true" ]] && first=false || expr+=","
        expr+="\"$k\":\$$k"
    done
    expr+="}"
    
    jq -n "${args[@]}" "$expr"
}

# 保存 JOIN 信息到文件
# 用法: _save_join_info "协议名" "数据格式" "链接生成命令" [额外行...]
# 数据格式中 %s 会被替换为 IP，%b 会被替换为 [IP] (IPv6 带括号)
# 示例: _save_join_info "vless" "REALITY|%s|$port|$uuid" "gen_vless_link %s $port $uuid"
_save_join_info() {
    local protocol="$1" data_fmt="$2" link_cmd="$3"; shift 3
    local join_file="$CFG/${protocol}.join"
    local link_prefix; link_prefix=$(tr '[:lower:]-' '[:upper:]_' <<<"$protocol")
    : >"$join_file"

    local label ip ipfmt data code cmd link
    for label in V4 V6; do
        ip=$([[ "$label" == V4 ]] && get_ipv4 || get_ipv6)
        [[ -z "$ip" ]] && continue
        ipfmt=$ip; [[ "$label" == V6 ]] && ipfmt="[$ip]"

        data=${data_fmt//%s/$ipfmt}; data=${data//%b/$ipfmt}
        code=$(printf '%s' "$data" | base64 -w 0 2>/dev/null || printf '%s' "$data" | base64)
        cmd=${link_cmd//%s/$ipfmt}; cmd=${cmd//%b/$ipfmt}
        link=$(eval "$cmd")

        printf '# IPv%s\nJOIN_%s=%s\n%s_%s=%s\n' "${label#V}" "$label" "$code" "$link_prefix" "$label" "$link" >>"$join_file"
    done

    local line
    for line in "$@"; do
        printf '%s\n' "$line" >>"$join_file"
    done
}


# 检测主协议并返回外部端口
# 用法: outer_port=$(_get_master_port "$default_port")
_get_master_port() {
    local default_port="$1"
    if db_exists "xray" "vless-vision"; then
        db_get_field "xray" "vless-vision" "port"
    elif db_exists "xray" "trojan"; then
        db_get_field "xray" "trojan" "port"
    else
        echo "$default_port"
    fi
}

# 检测是否有主协议
_has_master_protocol() {
    db_exists "xray" "vless-vision" || db_exists "xray" "trojan"
}

# 检查证书是否为 CA 签发的真实证书
_is_real_cert() {
    [[ ! -f "$CFG/certs/server.crt" ]] && return 1
    local issuer=$(openssl x509 -in "$CFG/certs/server.crt" -noout -issuer 2>/dev/null)
    [[ "$issuer" == *"Let's Encrypt"* ]] || [[ "$issuer" == *"R3"* ]] || \
    [[ "$issuer" == *"R10"* ]] || [[ "$issuer" == *"R11"* ]] || \
    [[ "$issuer" == *"E1"* ]] || [[ "$issuer" == *"ZeroSSL"* ]] || [[ "$issuer" == *"Buypass"* ]]
}

# 处理独立协议的证书 (WS 类协议独立安装时使用)
# 用法: _handle_standalone_cert "$sni" "$force_new_cert"
_handle_standalone_cert() {
    local sni="$1" force_new="${2:-false}"
    
    if [[ "$force_new" == "true" ]]; then
        if _is_real_cert; then
            _warn "检测到 CA 签发的真实证书，不会覆盖"
            return 1
        fi
        rm -f "$CFG/certs/server.crt" "$CFG/certs/server.key" "$CFG/cert_domain"
        gen_self_cert "$sni"
        echo "$sni" > "$CFG/cert_domain"
    elif [[ ! -f "$CFG/certs/server.crt" ]]; then
        gen_self_cert "$sni"
        echo "$sni" > "$CFG/cert_domain"
    fi
    return 0
}


#═══════════════════════════════════════════════════════════════════════════════
#  用户配置区 - 可根据需要修改以下设置
#═══════════════════════════════════════════════════════════════════════════════
# JOIN 码显示开关 (on=显示, off=隐藏)
SHOW_JOIN_CODE="off"
#═══════════════════════════════════════════════════════════════════════════════

# 颜色
R='\e[31m'; G='\e[32m'; Y='\e[33m'; C='\e[36m'; W='\e[97m'; D='\e[2m'; NC='\e[0m'
set -o pipefail

# 日志文件
LOG_FILE="/var/log/vless-server.log"

# 统一日志函数 - 同时输出到终端和日志文件
_log() {
    local level="$1"
    shift
    local msg="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    # 写入日志文件（无颜色）
    echo "[$timestamp] [$level] $msg" >> "$LOG_FILE" 2>/dev/null
}

# 初始化日志文件
init_log() {
    mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null
    # 日志轮转：超过 5MB 时截断保留最后 1000 行
    if [[ -f "$LOG_FILE" ]]; then
        local size=$(stat -f%z "$LOG_FILE" 2>/dev/null || stat -c%s "$LOG_FILE" 2>/dev/null || echo 0)
        if [[ $size -gt 5242880 ]]; then
            tail -n 1000 "$LOG_FILE" > "$LOG_FILE.tmp" 2>/dev/null && mv "$LOG_FILE.tmp" "$LOG_FILE" 2>/dev/null
        fi
    fi
    _log "INFO" "========== 脚本启动 v${VERSION} =========="
}

# timeout 兼容函数（某些精简系统可能没有 timeout 命令）
if ! command -v timeout &>/dev/null; then
    timeout() {
        local duration="$1"
        shift
        # 使用后台进程实现简单的超时
        "$@" &
        local pid=$!
        ( sleep "$duration" 2>/dev/null; kill -9 $pid 2>/dev/null ) &
        local killer=$!
        wait $pid 2>/dev/null
        local ret=$?
        kill $killer 2>/dev/null
        wait $killer 2>/dev/null
        return $ret
    }
fi

# 系统检测
if [[ -f /etc/alpine-release ]]; then
    DISTRO="alpine"
elif [[ -f /etc/redhat-release ]]; then
    DISTRO="centos"
elif [[ -f /etc/lsb-release ]] && grep -q "Ubuntu" /etc/lsb-release; then
    DISTRO="ubuntu"
elif [[ -f /etc/os-release ]] && grep -q "Ubuntu" /etc/os-release; then
    DISTRO="ubuntu"
else
    DISTRO="debian"
fi

#═══════════════════════════════════════════════════════════════════════════════
# 多协议管理系统
#═══════════════════════════════════════════════════════════════════════════════

# 协议分类定义 (重构: Sing-box 接管独立协议)
XRAY_PROTOCOLS="vless vless-xhttp vless-ws vmess-ws vless-vision trojan socks ss2022 ss-legacy"
# Sing-box 管理的协议 (原独立协议，现统一由 Sing-box 处理)
SINGBOX_PROTOCOLS="hy2 tuic"
# 仍需独立进程的协议 (Snell 等闭源协议)
STANDALONE_PROTOCOLS="snell snell-v5 snell-shadowtls snell-v5-shadowtls ss2022-shadowtls anytls naive"

#═══════════════════════════════════════════════════════════════════════════════
#  表驱动元数据 (协议/服务/进程/启动命令)
#  说明：将 “协议差异” 集中到这里，主体流程尽量通用化
#═══════════════════════════════════════════════════════════════════════════════
declare -A PROTO_SVC PROTO_EXEC PROTO_BIN PROTO_KIND
declare -A BACKEND_NAME BACKEND_DESC BACKEND_EXEC

# Xray 统一服务：所有 XRAY_PROTOCOLS 共用一个主服务 vless-reality
for _p in $XRAY_PROTOCOLS; do
    PROTO_SVC[$_p]="vless-reality"
    PROTO_EXEC[$_p]="/usr/local/bin/xray run -c $CFG/config.json"
    PROTO_BIN[$_p]="xray"
    PROTO_KIND[$_p]="xray"
done

# Sing-box 统一服务：hy2/tuic 由 vless-singbox 统一管理
PROTO_SVC[hy2]="vless-singbox";  PROTO_BIN[hy2]="sing-box"; PROTO_KIND[hy2]="singbox"
PROTO_SVC[tuic]="vless-singbox"; PROTO_BIN[tuic]="sing-box"; PROTO_KIND[tuic]="singbox"

# 独立协议 (Snell 等闭源协议仍需独立进程)
PROTO_SVC[snell]="vless-snell";     PROTO_EXEC[snell]="/usr/local/bin/snell-server -c $CFG/snell.conf";        PROTO_BIN[snell]="snell-server"; PROTO_KIND[snell]="snell"
PROTO_SVC[snell-v5]="vless-snell-v5"; PROTO_EXEC[snell-v5]="/usr/local/bin/snell-server-v5 -c $CFG/snell-v5.conf"; PROTO_BIN[snell-v5]="snell-server-v5"; PROTO_KIND[snell-v5]="snell"

# 动态命令：运行时从数据库取参数
PROTO_SVC[anytls]="vless-anytls"; PROTO_KIND[anytls]="anytls"
PROTO_SVC[naive]="vless-naive"; PROTO_KIND[naive]="naive"

# ShadowTLS：主服务 shadow-tls + 额外 backend 服务
for _p in snell-shadowtls snell-v5-shadowtls ss2022-shadowtls; do
    PROTO_SVC[$_p]="vless-${_p}"
    PROTO_KIND[$_p]="shadowtls"
    PROTO_BIN[$_p]="shadow-tls"
done

BACKEND_NAME[snell-shadowtls]="vless-snell-shadowtls-backend"
BACKEND_DESC[snell-shadowtls]="Snell Backend for ShadowTLS"
BACKEND_EXEC[snell-shadowtls]="/usr/local/bin/snell-server -c $CFG/snell-shadowtls.conf"

BACKEND_NAME[snell-v5-shadowtls]="vless-snell-v5-shadowtls-backend"
BACKEND_DESC[snell-v5-shadowtls]="Snell v5 Backend for ShadowTLS"
BACKEND_EXEC[snell-v5-shadowtls]="/usr/local/bin/snell-server-v5 -c $CFG/snell-v5-shadowtls.conf"

BACKEND_NAME[ss2022-shadowtls]="vless-ss2022-shadowtls-backend"
BACKEND_DESC[ss2022-shadowtls]="SS2022 Backend for ShadowTLS"
BACKEND_EXEC[ss2022-shadowtls]="/usr/local/bin/xray run -c $CFG/ss2022-shadowtls-backend.json"

# OpenRC status 回退：服务名 -> 进程名
declare -A SVC_PROC=(
    [vless-reality]="xray"
    [vless-singbox]="sing-box"
    [vless-snell]="snell-server"
    [vless-snell-v5]="snell-server-v5"
    [vless-anytls]="anytls-server"
    [vless-naive]="caddy"
    [vless-snell-shadowtls]="shadow-tls"
    [vless-snell-v5-shadowtls]="shadow-tls"
    [vless-ss2022-shadowtls]="shadow-tls"
    [nginx]="nginx"
)

# 协议注册和状态管理 (重构版 - 只使用数据库)
register_protocol() {
    local protocol=$1
    local config_json="${2:-}"  # JSON 配置 (必需)
    
    mkdir -p "$CFG"
    
    # 写入数据库
    if [[ -n "$config_json" ]]; then
        local core="xray"
        # 判断协议归属的核心 (使用空格包裹进行精确匹配，修复 grep -w 将连字符视为边界的问题)
        if [[ " $SINGBOX_PROTOCOLS " == *" $protocol "* ]]; then
            core="singbox"
        elif [[ " $STANDALONE_PROTOCOLS " == *" $protocol "* ]]; then
            core="singbox"  # 独立协议也记录到 singbox 分类
        fi
        
        if ! db_add "$core" "$protocol" "$config_json"; then
            _err "register_protocol: 写入数据库失败 - $protocol ($core)"
            return 1
        fi
    fi
}

unregister_protocol() {
    local protocol=$1
    
    # 从数据库删除
    db_del "xray" "$protocol" 2>/dev/null
    db_del "singbox" "$protocol" 2>/dev/null
}

get_installed_protocols() {
    # 从数据库获取
    if [[ -f "$DB_FILE" ]]; then
        db_get_all_protocols
    fi
}

is_protocol_installed() {
    local protocol=$1
    # 检查数据库
    db_exists "xray" "$protocol" && return 0
    db_exists "singbox" "$protocol" && return 0
    return 1
}

filter_installed() { # filter_installed "proto1 proto2 ..."
    local installed; installed=$(get_installed_protocols) || return 0
    local p
    for p in $1; do
        grep -qx "$p" <<<"$installed" && echo "$p"
    done
}

get_xray_protocols()       { filter_installed "$XRAY_PROTOCOLS"; }
get_singbox_protocols()    { filter_installed "$SINGBOX_PROTOCOLS"; }
get_standalone_protocols() { filter_installed "$STANDALONE_PROTOCOLS"; }

# 生成 Xray 多 inbounds 配置
generate_xray_config() {
    local xray_protocols=$(get_xray_protocols)
    [[ -z "$xray_protocols" ]] && return 1
    
    mkdir -p "$CFG"
    
    # 收集所有需要的出口
    local outbounds='[{"protocol": "freedom", "tag": "direct"}]'
    local routing_rules=""
    local has_routing=false
    
    # 获取分流规则
    local rules=$(db_get_routing_rules)
    
    if [[ -n "$rules" && "$rules" != "[]" ]]; then
        # 收集所有用到的出口 (支持多出口)
        local added_warp=false
        declare -A added_chains  # 记录已添加的链式代理节点
        
        while IFS= read -r outbound; do
            [[ -z "$outbound" ]] && continue
            
            if [[ "$outbound" == "warp" && "$added_warp" == "false" ]]; then
                local warp_out=$(gen_xray_warp_outbound)
                [[ -n "$warp_out" ]] && {
                    outbounds=$(echo "$outbounds" | jq --argjson out "$warp_out" '. + [$out]')
                    added_warp=true
                }
            elif [[ "$outbound" == chain:* ]]; then
                local node_name="${outbound#chain:}"
                # 检查是否已添加该节点
                if [[ -z "${added_chains[$node_name]}" ]]; then
                    local tag="chain-${node_name}"
                    local chain_out=$(gen_xray_chain_outbound "$node_name" "$tag")
                    [[ -n "$chain_out" ]] && {
                        outbounds=$(echo "$outbounds" | jq --argjson out "$chain_out" '. + [$out]')
                        added_chains[$node_name]=1
                    }
                fi
            fi
        done < <(echo "$rules" | jq -r '.[].outbound')
        
        routing_rules=$(gen_xray_routing_rules)
        [[ -n "$routing_rules" && "$routing_rules" != "[]" ]] && has_routing=true
    fi
    
    # 构建基础配置
    if [[ "$has_routing" == "true" ]]; then
        jq -n --argjson outbounds "$outbounds" '{
            log: {loglevel: "warning"},
            inbounds: [],
            outbounds: $outbounds,
            routing: {domainStrategy: "IPIfNonMatch", rules: []}
        }' > "$CFG/config.json"
        
        # 添加路由规则
        if [[ -n "$routing_rules" && "$routing_rules" != "[]" ]]; then
            local tmp=$(mktemp)
            jq --argjson rules "$routing_rules" '.routing.rules = $rules' "$CFG/config.json" > "$tmp" && mv "$tmp" "$CFG/config.json"
        fi
    else
        jq -n '{
            log: {loglevel: "warning"},
            inbounds: [],
            outbounds: [{protocol: "freedom", tag: "direct"}]
        }' > "$CFG/config.json"
    fi
    
    # 为每个 Xray 协议添加 inbound，并统计成功数量
    local success_count=0
    local failed_protocols=""
    local p
    for p in $xray_protocols; do
        if add_xray_inbound_v2 "$p"; then
            ((success_count++))
        else
            _warn "协议 $p 配置生成失败，跳过"
            failed_protocols+="$p "
        fi
    done
    
    # 检查是否至少有一个 inbound 成功添加
    if [[ $success_count -eq 0 ]]; then
        _err "没有任何协议配置成功生成"
        return 1
    fi
    
    # 验证最终配置文件的 JSON 格式
    if ! jq empty "$CFG/config.json" 2>/dev/null; then
        _err "生成的 Xray 配置文件 JSON 格式错误"
        return 1
    fi
    
    # 检查 inbounds 数组是否为空
    local inbound_count=$(jq '.inbounds | length' "$CFG/config.json" 2>/dev/null)
    if [[ "$inbound_count" == "0" || -z "$inbound_count" ]]; then
        _err "Xray 配置中没有有效的 inbound"
        return 1
    fi
    
    if [[ -n "$failed_protocols" ]]; then
        _warn "以下协议配置失败: $failed_protocols"
    fi
    
    _ok "Xray 配置生成成功 ($success_count 个协议)"
    return 0
}

# 使用 jq 动态构建 inbound (重构版 - 只从数据库读取)
add_xray_inbound_v2() {
    local protocol=$1
    
    # 从数据库读取配置
    local cfg=""
    if db_exists "xray" "$protocol"; then
        cfg=$(db_get "xray" "$protocol")
    else
        _err "协议 $protocol 在数据库中不存在 (xray 分类)"
        return 1
    fi
    
    [[ -z "$cfg" ]] && { _err "协议 $protocol 配置为空"; return 1; }
    
    # 从配置中提取字段
    local port=$(echo "$cfg" | jq -r '.port // empty')
    local uuid=$(echo "$cfg" | jq -r '.uuid // empty')
    local sni=$(echo "$cfg" | jq -r '.sni // empty')
    local short_id=$(echo "$cfg" | jq -r '.short_id // empty')
    local private_key=$(echo "$cfg" | jq -r '.private_key // empty')
    local path=$(echo "$cfg" | jq -r '.path // empty')
    local password=$(echo "$cfg" | jq -r '.password // empty')
    local username=$(echo "$cfg" | jq -r '.username // empty')
    local method=$(echo "$cfg" | jq -r '.method // empty')
    
    [[ -z "$port" ]] && return 1
    
    # 检测主协议和回落配置
    local has_master=false
    db_exists "xray" "vless-vision" && has_master=true
    db_exists "xray" "vless" && has_master=true
    db_exists "xray" "trojan" && has_master=true
    
    # 构建回落数组
    local fallbacks='[{"dest":"127.0.0.1:80","xver":0}]'
    local ws_port="" ws_path="" vmess_port="" vmess_path=""
    
    # 检查 vless-ws 回落
    if db_exists "xray" "vless-ws"; then
        ws_port=$(db_get_field "xray" "vless-ws" "port")
        ws_path=$(db_get_field "xray" "vless-ws" "path")
    fi
    
    # 检查 vmess-ws 回落
    if db_exists "xray" "vmess-ws"; then
        vmess_port=$(db_get_field "xray" "vmess-ws" "port")
        vmess_path=$(db_get_field "xray" "vmess-ws" "path")
    fi
    
    # 使用 jq 构建回落数组
    if [[ -n "$ws_port" && -n "$ws_path" ]]; then
        fallbacks=$(echo "$fallbacks" | jq --arg p "$ws_path" --argjson d "$ws_port" '. += [{"path":$p,"dest":$d,"xver":0}]')
    fi
    if [[ -n "$vmess_port" && -n "$vmess_path" ]]; then
        fallbacks=$(echo "$fallbacks" | jq --arg p "$vmess_path" --argjson d "$vmess_port" '. += [{"path":$p,"dest":$d,"xver":0}]')
    fi
    
    local inbound_json=""
    local tmp_inbound=$(mktemp)
    
    case "$protocol" in
        vless)
            # VLESS+Reality - 使用 jq 安全构建
            jq -n \
                --argjson port "$port" \
                --arg uuid "$uuid" \
                --arg sni "$sni" \
                --arg private_key "$private_key" \
                --arg short_id "$short_id" \
            '{
                port: $port,
                listen: "::",
                protocol: "vless",
                settings: {
                    clients: [{id: $uuid, flow: "xtls-rprx-vision"}],
                    decryption: "none"
                },
                streamSettings: {
                    network: "tcp",
                    security: "reality",
                    realitySettings: {
                        show: false,
                        dest: "\($sni):443",
                        xver: 0,
                        serverNames: [$sni],
                        privateKey: $private_key,
                        shortIds: [$short_id]
                    }
                },
                sniffing: {enabled: true, destOverride: ["http","tls"]},
                tag: "vless-reality"
            }' > "$tmp_inbound"
            ;;
        vless-vision)
            # VLESS-Vision - 使用 jq 安全构建
            jq -n \
                --argjson port "$port" \
                --arg uuid "$uuid" \
                --arg cert "$CFG/certs/server.crt" \
                --arg key "$CFG/certs/server.key" \
                --argjson fallbacks "$fallbacks" \
            '{
                port: $port,
                listen: "::",
                protocol: "vless",
                settings: {
                    clients: [{id: $uuid, flow: "xtls-rprx-vision"}],
                    decryption: "none",
                    fallbacks: $fallbacks
                },
                streamSettings: {
                    network: "tcp",
                    security: "tls",
                    tlsSettings: {
                        rejectUnknownSni: false,
                        minVersion: "1.2",
                        alpn: ["h2","http/1.1"],
                        certificates: [{certificateFile: $cert, keyFile: $key}]
                    }
                },
                tag: "vless-vision"
            }' > "$tmp_inbound"
            ;;
        vless-ws)
            if [[ "$has_master" == "true" ]]; then
                # 回落模式：监听本地
                jq -n \
                    --argjson port "$port" \
                    --arg uuid "$uuid" \
                    --arg path "$path" \
                    --arg sni "$sni" \
                '{
                    port: $port,
                    listen: "127.0.0.1",
                    protocol: "vless",
                    settings: {clients: [{id: $uuid}], decryption: "none"},
                    streamSettings: {
                        network: "ws",
                        security: "none",
                        wsSettings: {path: $path, headers: {Host: $sni}}
                    },
                    sniffing: {enabled: true, destOverride: ["http","tls"]},
                    tag: "vless-ws"
                }' > "$tmp_inbound"
            else
                # 独立模式：监听公网
                jq -n \
                    --argjson port "$port" \
                    --arg uuid "$uuid" \
                    --arg path "$path" \
                    --arg sni "$sni" \
                    --arg cert "$CFG/certs/server.crt" \
                    --arg key "$CFG/certs/server.key" \
                '{
                    port: $port,
                    listen: "::",
                    protocol: "vless",
                    settings: {
                        clients: [{id: $uuid}],
                        decryption: "none",
                        fallbacks: [{"dest":"127.0.0.1:80","xver":0}]
                    },
                    streamSettings: {
                        network: "ws",
                        security: "tls",
                        tlsSettings: {certificates: [{certificateFile: $cert, keyFile: $key}]},
                        wsSettings: {path: $path, headers: {Host: $sni}}
                    },
                    sniffing: {enabled: true, destOverride: ["http","tls"]},
                    tag: "vless-ws"
                }' > "$tmp_inbound"
            fi
            ;;
        vless-xhttp)
            jq -n \
                --argjson port "$port" \
                --arg uuid "$uuid" \
                --arg path "$path" \
                --arg sni "$sni" \
                --arg private_key "$private_key" \
                --arg short_id "$short_id" \
            '{
                port: $port,
                listen: "::",
                protocol: "vless",
                settings: {clients: [{id: $uuid}], decryption: "none"},
                streamSettings: {
                    network: "xhttp",
                    xhttpSettings: {path: $path, mode: "auto", host: $sni},
                    security: "reality",
                    realitySettings: {
                        show: false,
                        dest: "\($sni):443",
                        xver: 0,
                        serverNames: [$sni],
                        privateKey: $private_key,
                        shortIds: [$short_id]
                    }
                },
                sniffing: {enabled: true, destOverride: ["http","tls"]},
                tag: "vless-xhttp"
            }' > "$tmp_inbound"
            ;;
        vmess-ws)
            if [[ "$has_master" == "true" ]]; then
                jq -n \
                    --argjson port "$port" \
                    --arg uuid "$uuid" \
                    --arg path "$path" \
                    --arg sni "$sni" \
                '{
                    port: $port,
                    listen: "127.0.0.1",
                    protocol: "vmess",
                    settings: {clients: [{id: $uuid, alterId: 0, security: "auto"}]},
                    streamSettings: {
                        network: "ws",
                        security: "none",
                        wsSettings: {path: $path, headers: {Host: $sni}}
                    },
                    tag: "vmess-ws"
                }' > "$tmp_inbound"
            else
                jq -n \
                    --argjson port "$port" \
                    --arg uuid "$uuid" \
                    --arg path "$path" \
                    --arg sni "$sni" \
                    --arg cert "$CFG/certs/server.crt" \
                    --arg key "$CFG/certs/server.key" \
                '{
                    port: $port,
                    listen: "::",
                    protocol: "vmess",
                    settings: {clients: [{id: $uuid, alterId: 0, security: "auto"}]},
                    streamSettings: {
                        network: "ws",
                        security: "tls",
                        tlsSettings: {
                            certificates: [{certificateFile: $cert, keyFile: $key}],
                            alpn: ["http/1.1"]
                        },
                        wsSettings: {path: $path, headers: {Host: $sni}}
                    },
                    tag: "vmess-ws"
                }' > "$tmp_inbound"
            fi
            ;;
        trojan)
            jq -n \
                --argjson port "$port" \
                --arg password "$password" \
                --arg cert "$CFG/certs/server.crt" \
                --arg key "$CFG/certs/server.key" \
                --argjson fallbacks "$fallbacks" \
            '{
                port: $port,
                listen: "::",
                protocol: "trojan",
                settings: {
                    clients: [{password: $password}],
                    fallbacks: $fallbacks
                },
                streamSettings: {
                    network: "tcp",
                    security: "tls",
                    tlsSettings: {certificates: [{certificateFile: $cert, keyFile: $key}]}
                },
                tag: "trojan"
            }' > "$tmp_inbound"
            ;;
        socks)
            jq -n \
                --argjson port "$port" \
                --arg username "$username" \
                --arg password "$password" \
            '{
                port: $port,
                listen: "::",
                protocol: "socks",
                settings: {
                    auth: "password",
                    accounts: [{user: $username, pass: $password}],
                    udp: true,
                    ip: "::"
                },
                tag: "socks5"
            }' > "$tmp_inbound"
            ;;
        ss2022|ss-legacy)
            jq -n \
                --argjson port "$port" \
                --arg method "$method" \
                --arg password "$password" \
                --arg tag "$protocol" \
            '{
                port: $port,
                listen: "::",
                protocol: "shadowsocks",
                settings: {
                    method: $method,
                    password: $password,
                    network: "tcp,udp"
                },
                tag: $tag
            }' > "$tmp_inbound"
            ;;
        *)
            rm -f "$tmp_inbound"
            return 1
            ;;
    esac
    
    # 验证生成的 inbound JSON
    if ! jq empty "$tmp_inbound" 2>/dev/null; then
        _err "生成的 $protocol inbound JSON 格式错误"
        rm -f "$tmp_inbound"
        return 1
    fi
    
    # 合并到主配置
    local tmp_config=$(mktemp)
    if jq '.inbounds += [input]' "$CFG/config.json" "$tmp_inbound" > "$tmp_config" 2>/dev/null; then
        mv "$tmp_config" "$CFG/config.json"
        rm -f "$tmp_inbound"
        return 0
    else
        _err "合并 $protocol 配置失败"
        rm -f "$tmp_inbound" "$tmp_config"
        return 1
    fi
}

#═══════════════════════════════════════════════════════════════════════════════
# 基础工具函数
#═══════════════════════════════════════════════════════════════════════════════
_line()  { echo -e "${D}─────────────────────────────────────────────${NC}"; }
_dline() { echo -e "${C}═════════════════════════════════════════════${NC}"; }
_info()  { echo -e "  ${C}▸${NC} $1"; }
_ok()    { echo -e "  ${G}✓${NC} $1"; _log "OK" "$1"; }
_err()   { echo -e "  ${R}✗${NC} $1"; _log "ERROR" "$1"; }
_warn()  { echo -e "  ${Y}!${NC} $1"; _log "WARN" "$1"; }
_item()  { echo -e "  ${G}$1${NC}) $2"; }
_pause() { echo ""; read -rp "  按回车继续..."; }

# URL 解码函数 (处理 %XX 编码的中文等字符)
urldecode() {
    local encoded="$1"
    # 使用 printf 解码 %XX 格式
    printf '%b' "${encoded//%/\\x}"
}

_header() {
    clear; echo ""
    _dline
    echo -e "      ${W}多协议代理${NC} ${D}一键部署${NC} ${C}v${VERSION}${NC} ${Y}[服务端]${NC}"
    echo -e "      ${D}作者: ${AUTHOR}  快捷命令: vless${NC}"
    echo -e "      ${D}${REPO_URL}${NC}"
    _dline
}

get_protocol() {
    # 多协议模式下返回主协议或第一个协议
    local installed=$(get_installed_protocols)
    if [[ -n "$installed" ]]; then
        # 优先返回 Xray 主协议
        for proto in vless vless-vision vless-ws vless-xhttp trojan socks ss2022; do
            if echo "$installed" | grep -q "^$proto$"; then
                echo "$proto"
                return
            fi
        done
        # 返回第一个已安装的协议
        echo "$installed" | head -1
    elif [[ -f "$CFG/protocol" ]]; then
        cat "$CFG/protocol"
    else
        echo "vless"
    fi
}

get_protocol_name() {
    case "$1" in
        vless) echo "VLESS+Reality" ;;
        vless-xhttp) echo "VLESS+Reality+XHTTP" ;;
        vless-vision) echo "VLESS-XTLS-Vision" ;;
        vless-ws) echo "VLESS+WS+TLS" ;;
        vmess-ws) echo "VMess+WS" ;;
        ss2022) echo "Shadowsocks 2022" ;;
        ss-legacy) echo "Shadowsocks 传统版" ;;
        naive) echo "NaïveProxy" ;;
        hy2) echo "Hysteria2" ;;
        trojan) echo "Trojan" ;;
        snell) echo "Snell v4" ;;
        snell-v5) echo "Snell v5" ;;
        snell-shadowtls) echo "Snell v4+ShadowTLS" ;;
        snell-v5-shadowtls) echo "Snell v5+ShadowTLS" ;;
        ss2022-shadowtls) echo "SS2022+ShadowTLS" ;;
        tuic) echo "TUIC v5" ;;
        socks) echo "SOCKS5" ;;
        anytls) echo "AnyTLS" ;;
        *) echo "未知" ;;
    esac
}

check_root()      { [[ $EUID -ne 0 ]] && { _err "请使用 root 权限运行"; exit 1; }; }
check_cmd()       { command -v "$1" &>/dev/null; }
check_installed() { [[ -d "$CFG" && ( -f "$CFG/config.json" || -f "$CFG/db.json" ) ]]; }
get_role()        { [[ -f "$CFG/role" ]] && cat "$CFG/role" || echo ""; }
is_paused()       { [[ -f "$CFG/paused" ]]; }

# 配置 DNS64 (纯 IPv6 环境)
configure_dns64() {
    # 检测 IPv4 网络是否可用
    if ping -c 1 -W 2 8.8.8.8 &>/dev/null; then
        return 0  # IPv4 正常，无需配置
    fi
    
    _warn "检测到纯 IPv6 环境，正在配置 DNS64..."
    
    # 备份原有配置
    if [[ -f /etc/resolv.conf ]] && [[ ! -f /etc/resolv.conf.bak ]]; then
        cp /etc/resolv.conf /etc/resolv.conf.bak
    fi
    
    # 写入 DNS64 服务器
    cat > /etc/resolv.conf << 'EOF'
nameserver 2a00:1098:2b::1
nameserver 2001:4860:4860::6464
nameserver 2a00:1098:2c::1
EOF
    
    _ok "DNS64 配置完成 (Kasper Sky + Google DNS64 + Trex)"
}

# 检测并安装基础依赖
check_dependencies() {
    # 先配置 DNS64 (如果是纯 IPv6 环境)
    configure_dns64
    
    local missing_deps=()
    local need_install=false
    
    # 必需的基础命令
    local required_cmds="curl jq openssl"
    
    for cmd in $required_cmds; do
        if ! command -v "$cmd" &>/dev/null; then
            missing_deps+=("$cmd")
            need_install=true
        fi
    done
    
    if [[ "$need_install" == "true" ]]; then
        _info "安装缺失的依赖: ${missing_deps[*]}..."
        
        case "$DISTRO" in
            alpine)
                apk update >/dev/null 2>&1
                apk add --no-cache curl jq openssl coreutils >/dev/null 2>&1
                ;;
            centos)
                yum install -y curl jq openssl >/dev/null 2>&1
                ;;
            debian|ubuntu)
                apt-get update >/dev/null 2>&1
                DEBIAN_FRONTEND=noninteractive apt-get install -y curl jq openssl >/dev/null 2>&1
                ;;
        esac
        
        # 再次检查
        for cmd in $required_cmds; do
            if ! command -v "$cmd" &>/dev/null; then
                _err "依赖安装失败: $cmd"
                _warn "请手动安装: $cmd"
                return 1
            fi
        done
        _ok "依赖安装完成"
    fi
    return 0
}

#═══════════════════════════════════════════════════════════════════════════════
# 核心功能：强力清理 & 时间同步
#═══════════════════════════════════════════════════════════════════════════════
force_cleanup() {
    # 停止所有 vless 相关服务
    local services="watchdog reality hy2 tuic snell snell-v5 anytls singbox"
    services+=" snell-shadowtls snell-v5-shadowtls ss2022-shadowtls"
    services+=" snell-shadowtls-backend snell-v5-shadowtls-backend ss2022-shadowtls-backend"
    for s in $services; do svc stop "vless-$s" 2>/dev/null; done
    
    killall xray sing-box snell-server snell-server-v5 anytls-server shadow-tls 2>/dev/null
    
    # 清理 iptables NAT 规则
    cleanup_hy2_nat_rules
}

# 清理 Hysteria2/TUIC 端口跳跃 NAT 规则
cleanup_hy2_nat_rules() {
    # 清理 Hysteria2 端口跳跃规则
    if db_exists "singbox" "hy2"; then
        local port=$(db_get_field "singbox" "hy2" "port")
        local hs=$(db_get_field "singbox" "hy2" "hop_start"); hs="${hs:-20000}"
        local he=$(db_get_field "singbox" "hy2" "hop_end"); he="${he:-50000}"
        [[ -n "$port" ]] && {
            iptables -t nat -D PREROUTING -p udp --dport ${hs}:${he} -j REDIRECT --to-ports ${port} 2>/dev/null
            iptables -t nat -D OUTPUT -p udp --dport ${hs}:${he} -j REDIRECT --to-ports ${port} 2>/dev/null
        }
    fi
    # 清理 TUIC 端口跳跃规则
    if db_exists "singbox" "tuic"; then
        local port=$(db_get_field "singbox" "tuic" "port")
        local hs=$(db_get_field "singbox" "tuic" "hop_start"); hs="${hs:-20000}"
        local he=$(db_get_field "singbox" "tuic" "hop_end"); he="${he:-50000}"
        [[ -n "$port" ]] && {
            iptables -t nat -D PREROUTING -p udp --dport ${hs}:${he} -j REDIRECT --to-ports ${port} 2>/dev/null
            iptables -t nat -D OUTPUT -p udp --dport ${hs}:${he} -j REDIRECT --to-ports ${port} 2>/dev/null
        }
    fi
    # 兜底清理
    for chain in PREROUTING OUTPUT; do
        iptables -t nat -S $chain 2>/dev/null | grep -E "REDIRECT.*--to-ports" | while read -r rule; do
            eval "iptables -t nat $(echo "$rule" | sed 's/^-A/-D/')" 2>/dev/null
        done
    done
}

sync_time() {
    _info "同步系统时间..."
    
    # 方法1: 使用HTTP获取时间 (最快最可靠)
    local http_time=$(timeout 5 curl -sI --connect-timeout 3 --max-time 5 http://www.baidu.com 2>/dev/null | grep -i "^date:" | cut -d' ' -f2-)
    if [[ -n "$http_time" ]]; then
        if date -s "$http_time" &>/dev/null; then
            _ok "时间同步完成 (HTTP)"
            return 0
        fi
    fi
    
    # 方法2: 使用ntpdate (如果可用)
    if command -v ntpdate &>/dev/null; then
        if timeout 5 ntpdate -s pool.ntp.org &>/dev/null; then
            _ok "时间同步完成 (NTP)"
            return 0
        fi
    fi
    
    # 方法3: 使用timedatectl (systemd系统)
    if command -v timedatectl &>/dev/null; then
        if timeout 5 timedatectl set-ntp true &>/dev/null; then
            _ok "时间同步完成 (systemd)"
            return 0
        fi
    fi
    
    # 如果所有方法都失败，跳过时间同步
    _warn "时间同步失败，继续安装..."
    return 0
}

#═══════════════════════════════════════════════════════════════════════════════
# 网络工具
#═══════════════════════════════════════════════════════════════════════════════
get_ipv4() {
    [[ -n "$_CACHED_IPV4" ]] && { echo "$_CACHED_IPV4"; return; }
    local result=$(curl -4 -sf --connect-timeout 5 ip.sb 2>/dev/null || curl -4 -sf --connect-timeout 5 ifconfig.me 2>/dev/null)
    [[ -n "$result" ]] && _CACHED_IPV4="$result"
    echo "$result"
}
get_ipv6() {
    [[ -n "$_CACHED_IPV6" ]] && { echo "$_CACHED_IPV6"; return; }
    local result=$(curl -6 -sf --connect-timeout 5 ip.sb 2>/dev/null || curl -6 -sf --connect-timeout 5 ifconfig.me 2>/dev/null)
    [[ -n "$result" ]] && _CACHED_IPV6="$result"
    echo "$result"
}

# 获取 IP 地理位置代码 (如 HK, JP, US, SG)
get_ip_country() {
    local ip="${1:-}"
    local country=""
    
    # 方法1: ip-api.com (免费，无需 key)
    if [[ -n "$ip" ]]; then
        country=$(curl -sf --connect-timeout 3 "http://ip-api.com/line/${ip}?fields=countryCode" 2>/dev/null)
    else
        country=$(curl -sf --connect-timeout 3 "http://ip-api.com/line/?fields=countryCode" 2>/dev/null)
    fi
    
    # 方法2: 回退到 ipinfo.io
    if [[ -z "$country" || "$country" == "fail" ]]; then
        if [[ -n "$ip" ]]; then
            country=$(curl -sf --connect-timeout 3 "https://ipinfo.io/${ip}/country" 2>/dev/null)
        else
            country=$(curl -sf --connect-timeout 3 "https://ipinfo.io/country" 2>/dev/null)
        fi
    fi
    
    # 清理结果（去除空白字符）
    country=$(echo "$country" | tr -d '[:space:]')
    
    # 默认返回 XX
    echo "${country:-XX}"
}

# 通过DNS检查域名的IP解析 (兼容性增强)
check_domain_dns() {
    local domain=$1
    local dns_ip=""
    local ip_type=4
    local public_ip=""
    
    # 优先使用 dig
    if command -v dig &>/dev/null; then
        dns_ip=$(dig @1.1.1.1 +time=2 +short "$domain" 2>/dev/null | grep -E "^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$" | head -1)
        
        # 如果Cloudflare DNS失败，尝试Google DNS
        if [[ -z "$dns_ip" ]]; then
            dns_ip=$(dig @8.8.8.8 +time=2 +short "$domain" 2>/dev/null | grep -E "^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$" | head -1)
        fi
    fi
    
    # 回退到 nslookup
    if [[ -z "$dns_ip" ]] && command -v nslookup &>/dev/null; then
        dns_ip=$(nslookup "$domain" 1.1.1.1 2>/dev/null | awk '/^Address: / { print $2 }' | grep -v "1.1.1.1" | grep -E "^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$" | head -1)
    fi
    
    # 回退到 getent
    if [[ -z "$dns_ip" ]] && command -v getent &>/dev/null; then
        dns_ip=$(getent ahostsv4 "$domain" 2>/dev/null | awk '{print $1}' | head -1)
    fi
    
    # 如果IPv4解析失败，尝试IPv6
    if [[ -z "$dns_ip" ]] || echo "$dns_ip" | grep -q "timed out"; then
        _warn "无法通过DNS获取域名 IPv4 地址"
        _info "尝试检查域名 IPv6 地址..."
        
        if command -v dig &>/dev/null; then
            dns_ip=$(dig @2606:4700:4700::1111 +time=2 aaaa +short "$domain" 2>/dev/null | head -1)
        elif command -v getent &>/dev/null; then
            dns_ip=$(getent ahostsv6 "$domain" 2>/dev/null | awk '{print $1}' | head -1)
        fi
        ip_type=6
        
        if [[ -z "$dns_ip" ]] || echo "$dns_ip" | grep -q "network unreachable"; then
            _err "无法通过DNS获取域名IPv6地址"
            return 1
        fi
    fi
    
    # 获取服务器公网IP
    if [[ $ip_type -eq 4 ]]; then
        public_ip=$(get_ipv4)
    else
        public_ip=$(get_ipv6)
    fi
    
    # 比较DNS解析IP与服务器IP
    if [[ "$public_ip" != "$dns_ip" ]]; then
        _err "域名解析IP与当前服务器IP不一致"
        _warn "请检查域名解析是否生效以及正确"
        echo -e "  ${G}当前VPS IP：${NC}$public_ip"
        echo -e "  ${G}DNS解析 IP：${NC}$dns_ip"
        return 1
    else
        _ok "域名IP校验通过"
        return 0
    fi
}

#═══════════════════════════════════════════════════════════════════════════════
# 端口管理
#═══════════════════════════════════════════════════════════════════════════════

# 检查脚本内部记录的端口占用 (从数据库读取)
# 返回 0 表示被占用，1 表示未被占用
is_internal_port_occupied() {
    local check_port="$1"
    
    # 遍历 Xray 协议
    local xray_protos=$(db_list_protocols "xray")
    for proto in $xray_protos; do
        local used_port=$(db_get_field "xray" "$proto" "port")
        if [[ "$used_port" == "$check_port" ]]; then
            echo "$proto"
            return 0
        fi
    done
    
    # 遍历 Singbox 协议
    local singbox_protos=$(db_list_protocols "singbox")
    for proto in $singbox_protos; do
        local used_port=$(db_get_field "singbox" "$proto" "port")
        if [[ "$used_port" == "$check_port" ]]; then
            echo "$proto"
            return 0
        fi
    done
    
    return 1
}

# 优化后的端口生成函数 - 增加端口冲突检测和最大尝试次数
gen_port() {
    local port
    local max_attempts=100  # 最大尝试次数，防止无限循环
    local attempt=0
    
    while [[ $attempt -lt $max_attempts ]]; do
        port=$(shuf -i 10000-60000 -n 1 2>/dev/null || echo $((RANDOM % 50000 + 10000)))
        # 检查端口是否被占用 (TCP 和 UDP)
        if ! ss -tuln 2>/dev/null | grep -q ":$port " && ! netstat -tuln 2>/dev/null | grep -q ":$port "; then
            echo "$port"
            return 0
        fi
        ((attempt++))
    done
    
    # 达到最大尝试次数，返回一个随机端口并警告
    _warn "无法找到空闲端口（尝试 $max_attempts 次），使用随机端口" >&2
    echo "$port"
    return 1
}

# 智能端口推荐
# 参数: $1=协议类型
recommend_port() {
    local protocol="$1"
    
    # 检查是否已安装主协议（Vision/Trojan/Reality），用于判断 WS 协议是否为回落子协议
    local has_master=false
    if db_exists "xray" "vless-vision" || db_exists "xray" "vless" || db_exists "xray" "trojan"; then
        has_master=true
    fi
    
    case "$protocol" in
        vless-ws|vmess-ws)
            # 如果已有主协议，这些是回落子协议，监听本地，随机端口即可
            if [[ "$has_master" == "true" ]]; then
                gen_port
            else
                # 独立运行时才需要 HTTPS 端口
                if ! ss -tuln 2>/dev/null | grep -q ":443 " && ! is_internal_port_occupied "443" >/dev/null; then
                    echo "443"
                elif ! ss -tuln 2>/dev/null | grep -q ":8443 " && ! is_internal_port_occupied "8443" >/dev/null; then
                    echo "8443"
                else
                    gen_port
                fi
            fi
            ;;
        vless|vless-xhttp|vless-vision|trojan|anytls|snell-shadowtls|snell-v5-shadowtls|ss2022-shadowtls)
            # 这些协议需要对外暴露，优先使用 HTTPS 端口
            if ! ss -tuln 2>/dev/null | grep -q ":443 " && ! is_internal_port_occupied "443" >/dev/null; then
                echo "443"
            elif ! ss -tuln 2>/dev/null | grep -q ":8443 " && ! is_internal_port_occupied "8443" >/dev/null; then
                echo "8443"
            elif ! ss -tuln 2>/dev/null | grep -q ":2096 " && ! is_internal_port_occupied "2096" >/dev/null; then
                echo "2096"
            else
                gen_port
            fi
            ;;
        hy2|tuic)
            # UDP 协议直接随机
            while true; do
                local p=$(gen_port)
                if ! is_internal_port_occupied "$p" >/dev/null; then
                    echo "$p"
                    break
                fi
            done
            ;;
        *)
            gen_port
            ;;
    esac
}

# 交互式端口选择
ask_port() {
    local protocol="$1"
    local recommend=$(recommend_port "$protocol")
    
    # 检查是否已安装主协议
    local has_master=false
    if db_exists "xray" "vless-vision" || db_exists "xray" "vless" || db_exists "xray" "trojan"; then
        has_master=true
    fi
    
    echo "" >&2
    _line >&2
    echo -e "  ${W}端口配置${NC}" >&2
    
    # 根据协议类型和是否有主协议显示不同的提示
    case "$protocol" in
        vless-ws|vmess-ws)
            if [[ "$has_master" == "true" ]]; then
                # 回落子协议，内部端口
                echo -e "  ${D}(作为回落子协议，监听本地，外部通过 443 访问)${NC}" >&2
                echo -e "  ${C}建议: ${G}$recommend${NC} (内部端口，随机即可)" >&2
            elif [[ "$recommend" == "443" ]]; then
                echo -e "  ${C}建议: ${G}443${NC} (标准 HTTPS 端口)" >&2
            else
                local owner_443=$(is_internal_port_occupied "443")
                if [[ -n "$owner_443" ]]; then
                    echo -e "  ${Y}注意: 443 端口已被 [$owner_443] 协议占用${NC}" >&2
                fi
                echo -e "  ${C}建议: ${G}$recommend${NC} (已自动避开冲突)" >&2
            fi
            ;;
        vless|vless-xhttp|vless-vision|trojan)
            if [[ "$recommend" == "443" ]]; then
                echo -e "  ${C}建议: ${G}443${NC} (标准 HTTPS 端口)" >&2
            else
                local owner_443=$(is_internal_port_occupied "443")
                if [[ -n "$owner_443" ]]; then
                    echo -e "  ${Y}注意: 443 端口已被 [$owner_443] 协议占用${NC}" >&2
                fi
                echo -e "  ${C}建议: ${G}$recommend${NC} (已自动避开冲突)" >&2
            fi
            ;;
        *)
            echo -e "  ${C}建议: ${G}$recommend${NC}" >&2
            ;;
    esac
    
    echo "" >&2
    
    while true; do
        read -rp "  请输入端口 [回车使用 $recommend]: " custom_port
        
        # 如果用户直接回车，使用推荐端口
        if [[ -z "$custom_port" ]]; then
            custom_port="$recommend"
        fi
        
        # 0. 验证端口格式 (必须是1-65535的数字)
        if ! [[ "$custom_port" =~ ^[0-9]+$ ]] || [[ $custom_port -lt 1 ]] || [[ $custom_port -gt 65535 ]]; then
            _err "无效端口: $custom_port" >&2
            _warn "端口必须是 1-65535 之间的数字" >&2
            continue # 跳过本次循环，让用户重输
        fi
        
        # 0.1 检查是否使用了系统保留端口
        if [[ $custom_port -lt 1024 && $custom_port -ne 80 && $custom_port -ne 443 ]]; then
            _warn "端口 $custom_port 是系统保留端口，可能需要特殊权限" >&2
            read -rp "  是否继续使用? [y/N]: " use_reserved
            if [[ ! "$use_reserved" =~ ^[yY]$ ]]; then
                continue
            fi
        fi
        
        # 1. 检查是否被脚本内部其他协议占用 (最重要的一步！)
        local conflict_proto=$(is_internal_port_occupied "$custom_port")
        if [[ -n "$conflict_proto" ]]; then
            _err "端口 $custom_port 已被已安装的 [$conflict_proto] 占用！" >&2
            _warn "不同协议不能共用同一端口，请更换其他端口。" >&2
            continue # 跳过本次循环，让用户重输
        fi
        
        # 2. 检查系统端口占用 (Nginx 等外部程序)
        if ss -tuln 2>/dev/null | grep -q ":$custom_port " || netstat -tuln 2>/dev/null | grep -q ":$custom_port "; then
            _warn "端口 $custom_port 系统占用中" >&2
            read -rp "  是否强制使用? (可能导致启动失败) [y/N]: " force
            if [[ "$force" =~ ^[yY]$ ]]; then
                echo "$custom_port"
                return
            else
                continue
            fi
        else
            # 端口干净，通过
            echo "$custom_port"
            return
        fi
    done
}

#═══════════════════════════════════════════════════════════════════════════════
# 密钥与凭证生成
#═══════════════════════════════════════════════════════════════════════════════

# 生成 UUID
gen_uuid() { cat /proc/sys/kernel/random/uuid 2>/dev/null || printf '%04x%04x-%04x-%04x-%04x-%04x%04x%04x\n' $RANDOM $RANDOM $RANDOM $(($RANDOM&0x0fff|0x4000)) $(($RANDOM&0x3fff|0x8000)) $RANDOM $RANDOM $RANDOM; }

# 生成 ShortID (兼容无 xxd 的系统)
gen_sid() {
    if command -v xxd &>/dev/null; then
        head -c 4 /dev/urandom 2>/dev/null | xxd -p
    elif command -v od &>/dev/null; then
        head -c 4 /dev/urandom 2>/dev/null | od -An -tx1 | tr -d ' \n'
    else
        printf '%08x' $RANDOM
    fi
}

# 证书诊断函数
diagnose_certificate() {
    local domain="$1"
    
    echo ""
    _info "证书诊断报告："
    
    # 检查证书文件
    if [[ -f "$CFG/certs/server.crt" && -f "$CFG/certs/server.key" ]]; then
        _ok "证书文件存在"
        
        # 检查证书有效期
        local expiry=$(openssl x509 -in "$CFG/certs/server.crt" -noout -enddate 2>/dev/null | cut -d= -f2)
        if [[ -n "$expiry" ]]; then
            _ok "证书有效期: $expiry"
        fi
    else
        _err "证书文件不存在"
    fi
    
    # 检查端口监听 (从数据库读取)
    local port=$(db_get_field "xray" "vless-ws" "port")
    if [[ -n "$port" ]]; then
        if ss -tlnp | grep -q ":$port "; then
            _ok "端口 $port 正在监听"
        else
            _err "端口 $port 未监听"
        fi
    fi
    
    # DNS解析检查
    local resolved_ip=$(dig +short "$domain" 2>/dev/null | head -1)
    local server_ip=$(get_ipv4)
    if [[ "$resolved_ip" == "$server_ip" ]]; then
        _ok "DNS解析正确: $domain -> $resolved_ip"
    else
        _warn "DNS解析问题: $domain -> $resolved_ip (期望: $server_ip)"
    fi
    
    echo ""
}

# 创建伪装网页
create_fake_website() {
    local domain="$1"
    local protocol="$2"
    local custom_nginx_port="$3"  # 新增：自定义 Nginx 端口
    local web_dir="/var/www/html"
    
    # 根据系统确定 nginx 配置目录
    local nginx_conf_dir=""
    local nginx_conf_file=""
    if [[ -d "/etc/nginx/sites-available" ]]; then
        nginx_conf_dir="/etc/nginx/sites-available"
        nginx_conf_file="$nginx_conf_dir/vless-fake"
    elif [[ -d "/etc/nginx/conf.d" ]]; then
        nginx_conf_dir="/etc/nginx/conf.d"
        nginx_conf_file="$nginx_conf_dir/vless-fake.conf"
    elif [[ -d "/etc/nginx/http.d" ]]; then
        # Alpine
        nginx_conf_dir="/etc/nginx/http.d"
        nginx_conf_file="$nginx_conf_dir/vless-fake.conf"
    else
        nginx_conf_dir="/etc/nginx/conf.d"
        nginx_conf_file="$nginx_conf_dir/vless-fake.conf"
        mkdir -p "$nginx_conf_dir"
    fi
    
    # 删除旧配置，确保使用最新配置
    rm -f "$nginx_conf_file" /etc/nginx/sites-enabled/vless-fake 2>/dev/null
    # 同时删除可能冲突的 vless-sub.conf
    rm -f /etc/nginx/conf.d/vless-sub.conf 2>/dev/null
    
    # 创建网页目录
    mkdir -p "$web_dir"
    
    # 创建简单的伪装网页
    cat > "$web_dir/index.html" << 'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Welcome</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
        .container { max-width: 800px; margin: 0 auto; background: white; padding: 40px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h1 { color: #333; text-align: center; }
        p { color: #666; line-height: 1.6; }
        .footer { text-align: center; margin-top: 40px; color: #999; font-size: 14px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Welcome to Our Website</h1>
        <p>This is a simple website hosted on our server. We provide various web services and solutions for our clients.</p>
        <p>Our team is dedicated to delivering high-quality web hosting and development services. Feel free to contact us for more information about our services.</p>
        <div class="footer">
            <p>&copy; 2024 Web Services. All rights reserved.</p>
        </div>
    </div>
</body>
</html>
EOF
    
    # 检查是否有SSL证书，决定使用Nginx
    if [[ -n "$domain" ]] && [[ -f "/etc/vless-reality/certs/server.crt" ]]; then
        # 安装Nginx（如果未安装）
        if ! command -v nginx >/dev/null 2>&1; then
            _info "安装Nginx..."
            case "$DISTRO" in
                alpine) apk add --no-cache nginx >/dev/null 2>&1 ;;
                centos) yum install -y nginx >/dev/null 2>&1 ;;
                debian|ubuntu) DEBIAN_FRONTEND=noninteractive apt-get install -y -qq nginx >/dev/null 2>&1 ;;
            esac
        fi
        
        # 启用Nginx服务
        svc enable nginx 2>/dev/null
        
        # 根据协议选择Nginx监听端口和模式
        local nginx_port="80"
        local nginx_listen="127.0.0.1:$nginx_port"
        local nginx_comment="作为Xray的fallback后端"
        local nginx_ssl=""
        
        if [[ "$protocol" == "vless" || "$protocol" == "vless-xhttp" ]]; then
            # Reality协议：Nginx独立运行，提供HTTP订阅服务
            nginx_port="${custom_nginx_port:-8080}"
            nginx_listen="[::]:$nginx_port"
            nginx_comment="独立提供订阅服务 (HTTP)，不与Reality冲突"
        elif [[ "$protocol" == "vless-vision" || "$protocol" == "vless-ws" || "$protocol" == "vmess-ws" || "$protocol" == "trojan" ]]; then
            # 证书协议：Nginx 同时监听 80 (fallback) 和自定义端口 (HTTPS订阅)
            nginx_port="${custom_nginx_port:-8443}"
            nginx_listen="127.0.0.1:80"  # fallback 后端
            nginx_comment="80端口作为fallback，${nginx_port}端口提供HTTPS订阅"
            nginx_ssl="ssl"
        fi
        
        # 配置Nginx
        if [[ "$protocol" == "vless-vision" || "$protocol" == "vless-ws" || "$protocol" == "vmess-ws" || "$protocol" == "trojan" ]]; then
            # 证书协议：双端口配置
            cat > "$nginx_conf_file" << EOF
# Fallback 后端 (供 Xray 回落使用)
server {
    listen 127.0.0.1:80;
    server_name $domain;
    
    root $web_dir;
    index index.html;
    
    location / {
        try_files \$uri \$uri/ =404;
    }
    
    server_tokens off;
}

# HTTPS 订阅服务 (独立端口)
server {
    listen [::]:$nginx_port ssl http2;
    server_name $domain;
    
    ssl_certificate /etc/vless-reality/certs/server.crt;
    ssl_certificate_key /etc/vless-reality/certs/server.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    
    root $web_dir;
    index index.html;
    
    location / {
        try_files \$uri \$uri/ =404;
    }
    
    # 订阅文件目录 - v2ray 映射到 base64
    location ~ ^/sub/([a-f0-9-]+)/v2ray\$ {
        alias $CFG/subscription/\$1/base64;
        default_type text/plain;
        add_header Content-Type "text/plain; charset=utf-8";
    }
    
    # 订阅文件目录 - clash
    location ~ ^/sub/([a-f0-9-]+)/clash\$ {
        alias $CFG/subscription/\$1/clash.yaml;
        default_type text/yaml;
    }
    
    # 订阅文件目录 - surge
    location ~ ^/sub/([a-f0-9-]+)/surge\$ {
        alias $CFG/subscription/\$1/surge.conf;
        default_type text/plain;
    }
    
    # 订阅文件目录 - 通用
    location /sub/ {
        alias $CFG/subscription/;
        autoindex off;
        default_type text/plain;
    }
    
    server_tokens off;
}
EOF
        else
            # Reality协议：单端口配置
            cat > "$nginx_conf_file" << EOF
server {
    listen $nginx_listen;  # $nginx_comment
    server_name $domain;
    
    root $web_dir;
    index index.html;
    
    location / {
        try_files \$uri \$uri/ =404;
    }
    
    # 订阅文件目录 - v2ray 映射到 base64
    location ~ ^/sub/([a-f0-9-]+)/v2ray\$ {
        alias $CFG/subscription/\$1/base64;
        default_type text/plain;
        add_header Content-Type "text/plain; charset=utf-8";
    }
    
    # 订阅文件目录 - clash
    location ~ ^/sub/([a-f0-9-]+)/clash\$ {
        alias $CFG/subscription/\$1/clash.yaml;
        default_type text/yaml;
    }
    
    # 订阅文件目录 - surge
    location ~ ^/sub/([a-f0-9-]+)/surge\$ {
        alias $CFG/subscription/\$1/surge.conf;
        default_type text/plain;
    }
    
    # 订阅文件目录 - 通用
    location /sub/ {
        alias $CFG/subscription/;
        autoindex off;
        default_type text/plain;
    }
    
    # 隐藏Nginx版本
    server_tokens off;
}
EOF
        fi
        
        # 如果使用 sites-available 模式，创建软链接
        if [[ "$nginx_conf_dir" == "/etc/nginx/sites-available" ]]; then
            mkdir -p /etc/nginx/sites-enabled
            rm -f /etc/nginx/sites-enabled/default
            ln -sf "$nginx_conf_file" /etc/nginx/sites-enabled/vless-fake
        fi
        
        # 测试Nginx配置
        _info "配置Nginx并启动Web服务..."
        if nginx -t 2>/dev/null; then
            # 强制重启 Nginx 确保新配置生效（直接用 systemctl，更可靠）
            if [[ "$DISTRO" == "alpine" ]]; then
                rc-service nginx stop 2>/dev/null
                sleep 1
                rc-service nginx start 2>/dev/null
            else
                systemctl stop nginx 2>/dev/null
                sleep 1
                systemctl start nginx 2>/dev/null
            fi
            sleep 1
            
            # 验证端口是否监听（兼容不同系统）
            local port_listening=false
            if ss -tlnp 2>/dev/null | grep -qE ":${nginx_port}\s|:${nginx_port}$"; then
                port_listening=true
            elif netstat -tlnp 2>/dev/null | grep -q ":${nginx_port} "; then
                port_listening=true
            fi
            
            # 检查服务状态
            local nginx_running=false
            if [[ "$DISTRO" == "alpine" ]]; then
                rc-service nginx status &>/dev/null && nginx_running=true
            else
                systemctl is-active nginx &>/dev/null && nginx_running=true
            fi
            
            if [[ "$nginx_running" == "true" && "$port_listening" == "true" ]]; then
                _ok "伪装网页已创建并启动"
                _ok "Web服务器运行正常，订阅链接可用"
                if [[ "$protocol" == "vless" || "$protocol" == "vless-xhttp" ]]; then
                    _ok "伪装网页: http://$domain:$nginx_port"
                elif [[ "$protocol" == "vless-vision" || "$protocol" == "vless-ws" || "$protocol" == "vmess-ws" || "$protocol" == "trojan" ]]; then
                    _ok "伪装网页: https://$domain:$nginx_port"
                fi
                echo -e "  ${D}提示: 自定义伪装网页请将 HTML 文件放入 $web_dir${NC}"
            elif [[ "$nginx_running" == "true" ]]; then
                _ok "伪装网页已创建"
                _warn "端口 $nginx_port 未监听，请检查 Nginx 配置"
            else
                _ok "伪装网页已创建"
                _warn "Nginx 服务未运行，请手动启动: systemctl start nginx"
            fi
        else
            _warn "Nginx配置测试失败"
            echo "配置错误详情："
            nginx -t
            rm -f "$nginx_conf_file" /etc/nginx/sites-enabled/vless-fake 2>/dev/null
        fi
        
        # 保存订阅配置信息（关键！确保订阅链接显示正确）
        local sub_uuid=$(get_sub_uuid)
        local use_https="false"
        [[ "$protocol" == "vless-vision" || "$protocol" == "vless-ws" || "$protocol" == "vmess-ws" || "$protocol" == "trojan" ]] && use_https="true"
        
        cat > "$CFG/sub.info" << EOF
sub_uuid=$sub_uuid
sub_port=$nginx_port
sub_domain=$domain
sub_https=$use_https
EOF
        _log "INFO" "订阅配置已保存: UUID=${sub_uuid:0:8}..., 端口=$nginx_port, 域名=$domain"
    fi
    
}

gen_sni() { 
    # 稳定的 SNI 列表（国内可访问、大厂子域名、不易被封）
    local s=(
        # 科技巨头与云服务（最稳）
        "www.microsoft.com"
        "learn.microsoft.com"
        "azure.microsoft.com"
        "www.apple.com"
        "www.amazon.com"
        "aws.amazon.com"
        "www.icloud.com"
        "itunes.apple.com"
        # 硬件与芯片厂商（流量特征正常）
        "www.nvidia.com"
        "www.amd.com"
        "www.intel.com"
        "www.samsung.com"
        "www.dell.com"
        # 企业软件与网络安全（企业级白名单常客）
        "www.cisco.com"
        "www.oracle.com"
        "www.ibm.com"
        "www.adobe.com"
        "www.autodesk.com"
        "www.sap.com"
        "www.vmware.com"
    )
    # 使用 /dev/urandom 生成更好的随机数
    local idx=$(od -An -tu4 -N4 /dev/urandom 2>/dev/null | tr -d ' ')
    [[ -z "$idx" ]] && idx=$RANDOM
    echo "${s[$((idx % ${#s[@]}))]}"
}

gen_xhttp_path() {
    # 生成随机XHTTP路径，避免与Web服务器默认路由冲突
    local path="/$(head -c 32 /dev/urandom 2>/dev/null | base64 | tr -d '/+=' | head -c 8)"
    # 确保路径不为空
    if [[ -z "$path" || "$path" == "/" ]]; then
        path="/xhttp$(printf '%04x' $RANDOM)"
    fi
    echo "$path"
}
gen_password() { head -c 16 /dev/urandom 2>/dev/null | base64 | tr -d '/+=' | head -c 16 || printf '%s%s' $RANDOM $RANDOM | md5sum | head -c 16; }

urlencode() {
    local s="$1" i c o=""
    for ((i=0; i<${#s}; i++)); do
        c="${s:i:1}"
        case "$c" in
            [-_.~a-zA-Z0-9]) o+="$c" ;;
            *) printf -v c '%%%02x' "'$c"; o+="$c" ;;
        esac
    done
    echo "$o"
}

# 提取 IP 地址后缀（IPv4 取最后一段，IPv6 直接返回 "v6"）
get_ip_suffix() {
    local ip="$1"
    # 移除方括号
    ip="${ip#[}"
    ip="${ip%]}"
    
    if [[ "$ip" == *:* ]]; then
        # IPv6: 直接返回 "v6"
        echo "v6"
    else
        # IPv4: 取最后一个点后面的数字
        echo "${ip##*.}"
    fi
}

#═══════════════════════════════════════════════════════════════════════════════
# 分享链接生成
#═══════════════════════════════════════════════════════════════════════════════

gen_vless_link() {
    local ip="$1" port="$2" uuid="$3" pbk="$4" sid="$5" sni="$6" country="${7:-}"
    local ip_suffix=$(get_ip_suffix "$ip")
    local name="${country:+${country}-}VLESS+Reality${ip_suffix:+-${ip_suffix}}"
    printf '%s\n' "vless://${uuid}@${ip}:${port}?encryption=none&security=reality&type=tcp&sni=${sni}&fp=chrome&pbk=${pbk}&sid=${sid}&flow=xtls-rprx-vision#${name}"
}

gen_vless_xhttp_link() {
    local ip="$1" port="$2" uuid="$3" pbk="$4" sid="$5" sni="$6" path="${7:-/}" country="${8:-}"
    local ip_suffix=$(get_ip_suffix "$ip")
    local name="${country:+${country}-}VLESS-XHTTP${ip_suffix:+-${ip_suffix}}"
    printf '%s\n' "vless://${uuid}@${ip}:${port}?encryption=none&security=reality&type=xhttp&sni=${sni}&fp=chrome&pbk=${pbk}&sid=${sid}&path=$(urlencode "$path")&mode=auto#${name}"
}

gen_vmess_ws_link() {
    local ip="$1" port="$2" uuid="$3" sni="$4" path="$5" country="${6:-}"
    local clean_ip="${ip#[}"
    clean_ip="${clean_ip%]}"
    local ip_suffix=$(get_ip_suffix "$ip")
    local name="${country:+${country}-}VMess-WS${ip_suffix:+-${ip_suffix}}"

    # VMess ws 链接：vmess://base64(json)
    # 注意：allowInsecure 必须是字符串 "true"，不是布尔值
    local json
    json=$(cat <<EOF
{"v":"2","ps":"${name}","add":"${clean_ip}","port":"${port}","id":"${uuid}","aid":"0","scy":"auto","net":"ws","type":"none","host":"${sni}","path":"${path}","tls":"tls","sni":"${sni}","allowInsecure":"true"}
EOF
)
    printf 'vmess://%s\n' "$(echo -n "$json" | base64 -w 0 2>/dev/null || echo -n "$json" | base64 | tr -d '\n')"
}

gen_qr() { printf '%s\n' "https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=$(urlencode "$1")"; }



# 生成各协议分享链接
gen_hy2_link() {
    local ip="$1" port="$2" password="$3" sni="$4" country="${5:-}"
    local ip_suffix=$(get_ip_suffix "$ip")
    local name="${country:+${country}-}Hysteria2${ip_suffix:+-${ip_suffix}}"
    # 链接始终使用实际端口，端口跳跃需要客户端手动配置
    printf '%s\n' "hysteria2://${password}@${ip}:${port}?sni=${sni}&insecure=1#${name}"
}

gen_trojan_link() {
    local ip="$1" port="$2" password="$3" sni="$4" country="${5:-}"
    local ip_suffix=$(get_ip_suffix "$ip")
    local name="${country:+${country}-}Trojan${ip_suffix:+-${ip_suffix}}"
    printf '%s\n' "trojan://${password}@${ip}:${port}?security=tls&sni=${sni}&type=tcp&allowInsecure=1#${name}"
}

gen_vless_ws_link() {
    local ip="$1" port="$2" uuid="$3" sni="$4" path="${5:-/}" country="${6:-}"
    local ip_suffix=$(get_ip_suffix "$ip")
    local name="${country:+${country}-}VLESS-WS${ip_suffix:+-${ip_suffix}}"
    printf '%s\n' "vless://${uuid}@${ip}:${port}?encryption=none&security=tls&sni=${sni}&type=ws&host=${sni}&path=$(urlencode "$path")&allowInsecure=1#${name}"
}

gen_vless_vision_link() {
    local ip="$1" port="$2" uuid="$3" sni="$4" country="${5:-}"
    local ip_suffix=$(get_ip_suffix "$ip")
    local name="${country:+${country}-}VLESS-Vision${ip_suffix:+-${ip_suffix}}"
    printf '%s\n' "vless://${uuid}@${ip}:${port}?encryption=none&security=tls&sni=${sni}&type=tcp&flow=xtls-rprx-vision&allowInsecure=1#${name}"
}

gen_ss2022_link() {
    local ip="$1" port="$2" method="$3" password="$4" country="${5:-}"
    local ip_suffix=$(get_ip_suffix "$ip")
    local name="${country:+${country}-}SS2022${ip_suffix:+-${ip_suffix}}"
    local userinfo=$(printf '%s:%s' "$method" "$password" | base64 -w 0 2>/dev/null || printf '%s:%s' "$method" "$password" | base64)
    printf '%s\n' "ss://${userinfo}@${ip}:${port}#${name}"
}

gen_ss_legacy_link() {
    local ip="$1" port="$2" method="$3" password="$4" country="${5:-}"
    local ip_suffix=$(get_ip_suffix "$ip")
    local name="${country:+${country}-}SS${ip_suffix:+-${ip_suffix}}"
    local userinfo=$(printf '%s:%s' "$method" "$password" | base64 -w 0 2>/dev/null || printf '%s:%s' "$method" "$password" | base64)
    printf '%s\n' "ss://${userinfo}@${ip}:${port}#${name}"
}

gen_snell_link() {
    local ip="$1" port="$2" psk="$3" version="${4:-4}" country="${5:-}"
    local ip_suffix=$(get_ip_suffix "$ip")
    local name="${country:+${country}-}Snell-v${version}${ip_suffix:+-${ip_suffix}}"
    # Snell 没有标准URI格式，使用自定义格式
    printf '%s\n' "snell://${psk}@${ip}:${port}?version=${version}#${name}"
}

gen_tuic_link() {
    local ip="$1" port="$2" uuid="$3" password="$4" sni="$5" country="${6:-}"
    local ip_suffix=$(get_ip_suffix "$ip")
    local name="${country:+${country}-}TUIC${ip_suffix:+-${ip_suffix}}"
    printf '%s\n' "tuic://${uuid}:${password}@${ip}:${port}?congestion_control=bbr&alpn=h3&sni=${sni}&udp_relay_mode=native&allow_insecure=1#${name}"
}

gen_anytls_link() {
    local ip="$1" port="$2" password="$3" sni="$4" country="${5:-}"
    local ip_suffix=$(get_ip_suffix "$ip")
    local name="${country:+${country}-}AnyTLS${ip_suffix:+-${ip_suffix}}"
    printf '%s\n' "anytls://${password}@${ip}:${port}?sni=${sni}&allowInsecure=1#${name}"
}

gen_naive_link() {
    local host="$1" port="$2" username="$3" password="$4" country="${5:-}"
    local name="${country:+${country}-}Naive"
    # Shadowrocket HTTP/2 格式，使用域名
    printf '%s\n' "http2://${username}:${password}@${host}:${port}#${name}"
}

gen_shadowtls_link() {
    local ip="$1" port="$2" password="$3" method="$4" sni="$5" stls_password="$6" country="${7:-}"
    local ip_suffix=$(get_ip_suffix "$ip")
    local name="${country:+${country}-}ShadowTLS${ip_suffix:+-${ip_suffix}}"
    # ShadowTLS链接格式：ss://method:password@server:port#name + ShadowTLS参数
    local ss_link=$(echo -n "${method}:${password}" | base64 -w 0)
    printf '%s\n' "ss://${ss_link}@${ip}:${port}?plugin=shadow-tls;host=${sni};password=${stls_password}#${name}"
}

gen_snell_v5_link() {
    local ip="$1" port="$2" psk="$3" version="${4:-5}" country="${5:-}"
    local ip_suffix=$(get_ip_suffix "$ip")
    local name="${country:+${country}-}Snell-v5${ip_suffix:+-${ip_suffix}}"
    printf '%s\n' "snell://${psk}@${ip}:${port}?version=${version}#${name}"
}

gen_socks_link() {
    local ip="$1" port="$2" username="$3" password="$4" country="${5:-}"
    local ip_suffix=$(get_ip_suffix "$ip")
    local name="${country:+${country}-}SOCKS5${ip_suffix:+-${ip_suffix}}"
    if [[ -n "$username" && -n "$password" ]]; then
        printf '%s\n' "https://t.me/socks?server=${ip}&port=${port}&user=${username}&pass=${password}"
    else
        printf '%s\n' "socks5://${ip}:${port}#${name}"
    fi
}

#═══════════════════════════════════════════════════════════════════════════════
# 连接测试
#═══════════════════════════════════════════════════════════════════════════════

test_connection() {
    # 服务端：检查所有已安装协议的端口 (从数据库读取)
    local installed=$(get_installed_protocols)
    for proto in $installed; do
        local port=""
        # 尝试从 xray 或 singbox 读取
        if db_exists "xray" "$proto"; then
            port=$(db_get_field "xray" "$proto" "port")
        elif db_exists "singbox" "$proto"; then
            port=$(db_get_field "singbox" "$proto" "port")
        fi
        
        if [[ -n "$port" ]]; then
            if ss -tlnp 2>/dev/null | grep -q ":$port " || ss -ulnp 2>/dev/null | grep -q ":$port "; then
                _ok "$(get_protocol_name $proto) 端口 $port 已监听"
            else
                _err "$(get_protocol_name $proto) 端口 $port 未监听"
            fi
        fi
    done
}

test_latency() {
    local ip="$1" port="$2" proto="${3:-tcp}" start end
    start=$(date +%s%3N 2>/dev/null || echo $(($(date +%s)*1000)))
    
    if [[ "$proto" == "hy2" || "$proto" == "tuic" ]]; then
        if ping -c 1 -W 2 "$ip" &>/dev/null; then
            end=$(date +%s%3N 2>/dev/null || echo $(($(date +%s)*1000)))
            echo "$((end-start))ms"
        else
            echo "UDP"
        fi
    else
        # 优先使用 nc (netcat)，更通用且跨平台兼容性更好
        if command -v nc &>/dev/null; then
            if timeout 3 nc -z -w 2 "$ip" "$port" 2>/dev/null; then
                end=$(date +%s%3N 2>/dev/null || echo $(($(date +%s)*1000)))
                echo "$((end-start))ms"
            else
                echo "超时"
            fi
        # 回退到 bash /dev/tcp（某些系统可能不支持）
        elif timeout 3 bash -c "echo >/dev/tcp/$ip/$port" 2>/dev/null; then
            end=$(date +%s%3N 2>/dev/null || echo $(($(date +%s)*1000)))
            echo "$((end-start))ms"
        else
            echo "超时"
        fi
    fi
}

#═══════════════════════════════════════════════════════════════════════════════
# 软件安装
#═══════════════════════════════════════════════════════════════════════════════

# 安装系统依赖
install_deps() {
    _info "检查系统依赖..."
    if [[ "$DISTRO" == "alpine" ]]; then
        _info "更新软件包索引..."
        if ! timeout 60 apk update 2>&1 | grep -E '^(fetch|OK)' | sed 's/^/  /'; then
            if ! apk update &>/dev/null; then
                _err "更新软件包索引失败（可能超时）"
                return 1
            fi
        fi
        
        local deps="curl jq unzip iproute2 iptables ip6tables gcompat libc6-compat openssl socat bind-tools"
        _info "安装依赖: $deps"
        if ! timeout 180 apk add --no-cache $deps 2>&1 | grep -E '^(\(|OK|Installing|Executing)' | sed 's/^/  /'; then
            # 检查实际安装结果
            local missing=""
            for dep in $deps; do
                apk info -e "$dep" &>/dev/null || missing="$missing $dep"
            done
            if [[ -n "$missing" ]]; then
                _err "依赖安装失败:$missing"
                return 1
            fi
        fi
        _ok "依赖安装完成"
    elif [[ "$DISTRO" == "centos" ]]; then
        _info "安装 EPEL 源..."
        if ! timeout 120 yum install -y epel-release 2>&1 | grep -E '^(Installing|Verifying|Complete)' | sed 's/^/  /'; then
            if ! rpm -q epel-release &>/dev/null; then
                _err "EPEL 源安装失败（可能超时）"
                return 1
            fi
        fi
        
        local deps="curl jq unzip iproute iptables vim-common openssl socat bind-utils"
        _info "安装依赖: $deps"
        if ! timeout 300 yum install -y $deps 2>&1 | grep -E '^(Installing|Verifying|Complete|Downloading)' | sed 's/^/  /'; then
            # 检查实际安装结果
            local missing=""
            for dep in $deps; do
                rpm -q "$dep" &>/dev/null || missing="$missing $dep"
            done
            if [[ -n "$missing" ]]; then
                _err "依赖安装失败:$missing"
                return 1
            fi
        fi
        _ok "依赖安装完成"
    elif [[ "$DISTRO" == "debian" || "$DISTRO" == "ubuntu" ]]; then
        _info "更新软件包索引..."
        # 移除 -qq 让用户能看到进度，避免交互卡住
        if ! DEBIAN_FRONTEND=noninteractive apt-get update 2>&1 | grep -E '^(Hit|Get|Fetched|Reading)' | head -10 | sed 's/^/  /'; then
            # 即使 grep 没匹配到也继续，只要 apt-get 成功即可
            :
        fi
        
        local deps="curl jq unzip iproute2 xxd openssl socat dnsutils"
        _info "安装依赖: $deps"
        # 使用 DEBIAN_FRONTEND 避免交互，显示简化进度，移除 timeout 避免死锁
        if ! DEBIAN_FRONTEND=noninteractive apt-get install -y $deps 2>&1 | grep -E '^(Setting up|Unpacking|Processing|Get:|Fetched)' | sed 's/^/  /'; then
            # 检查实际安装结果
            if ! dpkg -l $deps >/dev/null 2>&1; then
                _err "依赖安装失败"
                return 1
            fi
        fi
        _ok "依赖安装完成"
    fi
}

#═══════════════════════════════════════════════════════════════════════════════
# 证书管理
#═══════════════════════════════════════════════════════════════════════════════

# 安装 acme.sh
install_acme_tool() {
    # 检查多个可能的安装位置
    local acme_paths=(
        "$HOME/.acme.sh/acme.sh"
        "/root/.acme.sh/acme.sh"
        "/usr/local/bin/acme.sh"
    )
    
    for acme_path in "${acme_paths[@]}"; do
        if [[ -f "$acme_path" ]]; then
            _ok "acme.sh 已安装 ($acme_path)"
            return 0
        fi
    done
    
    _info "安装 acme.sh 证书申请工具..."
    
    # 方法1: 官方安装脚本
    if curl -sL https://get.acme.sh | sh -s email=admin@example.com 2>&1 | grep -qE "Install success|already installed"; then
        source "$HOME/.acme.sh/acme.sh.env" 2>/dev/null || true
        if [[ -f "$HOME/.acme.sh/acme.sh" ]]; then
            _ok "acme.sh 安装成功"
            return 0
        fi
    fi
    
    # 方法2: 使用 git clone
    if command -v git &>/dev/null; then
        _info "尝试使用 git 安装..."
        if git clone --depth 1 https://github.com/acmesh-official/acme.sh.git /tmp/acme.sh 2>/dev/null; then
            cd /tmp/acme.sh && ./acme.sh --install -m admin@example.com 2>/dev/null
            cd - >/dev/null
            rm -rf /tmp/acme.sh
            if [[ -f "$HOME/.acme.sh/acme.sh" ]]; then
                _ok "acme.sh 安装成功 (git)"
                return 0
            fi
        fi
    fi
    
    # 方法3: 直接下载脚本
    _info "尝试直接下载..."
    mkdir -p "$HOME/.acme.sh"
    if curl -sL -o "$HOME/.acme.sh/acme.sh" "https://raw.githubusercontent.com/acmesh-official/acme.sh/master/acme.sh" 2>/dev/null; then
        chmod +x "$HOME/.acme.sh/acme.sh"
        if [[ -f "$HOME/.acme.sh/acme.sh" ]]; then
            _ok "acme.sh 安装成功 (直接下载)"
            return 0
        fi
    fi
    
    _err "acme.sh 安装失败，请检查网络连接"
    _warn "你可以手动安装: curl https://get.acme.sh | sh"
    return 1
}

# DNS-01 验证申请证书
# 参数: $1=域名 $2=证书目录 $3=协议
_issue_cert_dns() {
    local domain="$1"
    local cert_dir="$2"
    local protocol="$3"
    
    echo ""
    _line
    echo -e "  ${C}DNS-01 验证模式${NC}"
    _line
    echo ""
    echo -e "  ${Y}支持的 DNS 服务商：${NC}"
    echo -e "  1) Cloudflare"
    echo -e "  2) Aliyun (阿里云)"
    echo -e "  3) DNSPod (腾讯云)"
    echo -e "  4) 手动 DNS 验证"
    echo ""
    read -rp "  请选择 DNS 服务商 [1-4]: " dns_choice
    
    local dns_api=""
    local dns_env=""
    
    case "$dns_choice" in
        1)
            echo ""
            echo -e "  ${D}获取 Cloudflare API Token:${NC}"
            echo -e "  ${D}https://dash.cloudflare.com/profile/api-tokens${NC}"
            echo -e "  ${D}创建 Token 时选择 'Edit zone DNS' 模板${NC}"
            echo ""
            read -rp "  请输入 CF_Token: " cf_token
            [[ -z "$cf_token" ]] && { _err "Token 不能为空"; return 1; }
            dns_api="dns_cf"
            dns_env="CF_Token=$cf_token"
            ;;
        2)
            echo ""
            echo -e "  ${D}获取阿里云 AccessKey:${NC}"
            echo -e "  ${D}https://ram.console.aliyun.com/manage/ak${NC}"
            echo ""
            read -rp "  请输入 Ali_Key: " ali_key
            read -rp "  请输入 Ali_Secret: " ali_secret
            [[ -z "$ali_key" || -z "$ali_secret" ]] && { _err "Key/Secret 不能为空"; return 1; }
            dns_api="dns_ali"
            dns_env="Ali_Key=$ali_key Ali_Secret=$ali_secret"
            ;;
        3)
            echo ""
            echo -e "  ${D}获取 DNSPod Token:${NC}"
            echo -e "  ${D}https://console.dnspod.cn/account/token/token${NC}"
            echo ""
            read -rp "  请输入 DP_Id: " dp_id
            read -rp "  请输入 DP_Key: " dp_key
            [[ -z "$dp_id" || -z "$dp_key" ]] && { _err "ID/Key 不能为空"; return 1; }
            dns_api="dns_dp"
            dns_env="DP_Id=$dp_id DP_Key=$dp_key"
            ;;
        4)
            # 手动 DNS 验证
            _issue_cert_dns_manual "$domain" "$cert_dir" "$protocol"
            return $?
            ;;
        *)
            _err "无效选择"
            return 1
            ;;
    esac
    
    # 安装 acme.sh
    install_acme_tool || return 1
    local acme_sh="$HOME/.acme.sh/acme.sh"
    
    _info "正在通过 DNS 验证申请证书..."
    echo ""
    
    # 设置环境变量并申请证书
    eval "export $dns_env"
    
    local reload_cmd="chmod 600 $cert_dir/server.key; chmod 644 $cert_dir/server.crt"
    
    if "$acme_sh" --issue -d "$domain" --dns "$dns_api" --force 2>&1 | tee /tmp/acme_dns.log | grep -E "^\[|Verify finished|Cert success|error|Error" | sed 's/^/  /'; then
        echo ""
        _ok "证书申请成功，安装证书..."
        
        "$acme_sh" --install-cert -d "$domain" \
            --key-file       "$cert_dir/server.key"  \
            --fullchain-file "$cert_dir/server.crt" \
            --reloadcmd      "$reload_cmd" >/dev/null 2>&1
        
        # 保存域名
        echo "$domain" > "$CFG/cert_domain"
        
        rm -f /tmp/acme_dns.log
        
        # 读取自定义 nginx 端口
        local custom_port=""
        [[ -f "$CFG/.nginx_port_tmp" ]] && custom_port=$(cat "$CFG/.nginx_port_tmp")
        create_fake_website "$domain" "$protocol" "$custom_port"
        
        _ok "证书已配置到 $cert_dir"
        diagnose_certificate "$domain"
        return 0
    else
        echo ""
        _err "DNS 验证失败！"
        cat /tmp/acme_dns.log 2>/dev/null | grep -E "(error|Error)" | head -3
        rm -f /tmp/acme_dns.log
        return 1
    fi
}

# 手动 DNS 验证
_issue_cert_dns_manual() {
    local domain="$1"
    local cert_dir="$2"
    local protocol="$3"
    
    install_acme_tool || return 1
    local acme_sh="$HOME/.acme.sh/acme.sh"
    
    echo ""
    _info "开始手动 DNS 验证..."
    echo ""
    
    # 获取 DNS 记录
    local txt_record=$("$acme_sh" --issue -d "$domain" --dns --yes-I-know-dns-manual-mode-enough-go-ahead-please --force 2>&1 | grep -oP "TXT value: '\K[^']+")
    
    if [[ -z "$txt_record" ]]; then
        # 尝试另一种方式获取
        "$acme_sh" --issue -d "$domain" --dns --yes-I-know-dns-manual-mode-enough-go-ahead-please --force 2>&1 | tee /tmp/acme_manual.log
        txt_record=$(grep -oP "TXT value: '\K[^']+" /tmp/acme_manual.log 2>/dev/null)
    fi
    
    if [[ -z "$txt_record" ]]; then
        _err "无法获取 DNS TXT 记录值"
        return 1
    fi
    
    echo ""
    _line
    echo -e "  ${Y}请添加以下 DNS TXT 记录：${NC}"
    _line
    echo ""
    echo -e "  主机记录: ${G}_acme-challenge${NC}"
    echo -e "  记录类型: ${G}TXT${NC}"
    echo -e "  记录值:   ${G}$txt_record${NC}"
    echo ""
    _line
    echo ""
    echo -e "  ${D}添加完成后，等待 DNS 生效（通常 1-5 分钟）${NC}"
    echo ""
    read -rp "  DNS 记录添加完成后按回车继续..." _
    
    _info "验证 DNS 记录..."
    
    # 完成验证
    if "$acme_sh" --renew -d "$domain" --yes-I-know-dns-manual-mode-enough-go-ahead-please --force 2>&1 | grep -q "Cert success"; then
        echo ""
        _ok "证书申请成功，安装证书..."
        
        "$acme_sh" --install-cert -d "$domain" \
            --key-file       "$cert_dir/server.key"  \
            --fullchain-file "$cert_dir/server.crt" >/dev/null 2>&1
        
        echo "$domain" > "$CFG/cert_domain"
        
        local custom_port=""
        [[ -f "$CFG/.nginx_port_tmp" ]] && custom_port=$(cat "$CFG/.nginx_port_tmp")
        create_fake_website "$domain" "$protocol" "$custom_port"
        
        _ok "证书已配置到 $cert_dir"
        echo ""
        _warn "注意: 手动 DNS 模式无法自动续期，证书到期前需要手动更新"
        return 0
    else
        _err "DNS 验证失败，请检查 TXT 记录是否正确"
        return 1
    fi
}

# 申请 ACME 证书
# 参数: $1=域名
get_acme_cert() {
    local domain=$1
    local protocol="${2:-unknown}"
    local cert_dir="$CFG/certs"
    mkdir -p "$cert_dir"
    
    # 检查是否已有相同域名的证书
    if [[ -f "$CFG/cert_domain" ]]; then
        local existing_domain=$(cat "$CFG/cert_domain")
        if [[ "$existing_domain" == "$domain" && -f "$cert_dir/server.crt" && -f "$cert_dir/server.key" ]]; then
            _ok "检测到相同域名的现有证书，跳过申请"
            # 检查证书是否仍然有效
            if openssl x509 -in "$cert_dir/server.crt" -noout -checkend 2592000 >/dev/null 2>&1; then
                _ok "现有证书仍然有效（30天以上）"
                
                # 读取自定义 nginx 端口（如果有）
                local custom_port=""
                [[ -f "$CFG/.nginx_port_tmp" ]] && custom_port=$(cat "$CFG/.nginx_port_tmp")
                
                # 确保Web服务器也启动（复用证书时也需要）
                create_fake_website "$domain" "$protocol" "$custom_port"
                
                diagnose_certificate "$domain"
                return 0
            else
                _warn "现有证书即将过期，重新申请..."
            fi
        fi
    fi
    
    # 先检查域名解析 (快速验证)
    _info "检查域名解析..."
    if ! check_domain_dns "$domain"; then
        _err "域名解析检查失败，无法申请 Let's Encrypt 证书"
        echo ""
        echo -e "  ${Y}选项：${NC}"
        echo -e "  1) 使用自签证书 (安全性较低，易被识别)"
        echo -e "  2) 重新输入域名"
        echo -e "  3) 退出安装"
        echo ""
        read -rp "  请选择 [1-3]: " choice
        
        case "$choice" in
            1)
                _warn "将使用自签证书"
                return 1  # 返回失败，让调用方使用自签证书
                ;;
            2)
                return 2  # 返回特殊值，表示需要重新输入域名
                ;;
            3|"")
                _info "已退出安装"
                exit 0
                ;;
            *)
                _err "无效选择，退出安装"
                exit 0
                ;;
        esac
    fi
    
    # 域名解析通过，询问是否申请证书
    echo ""
    _ok "域名解析验证通过！"
    echo ""
    echo -e "  ${Y}接下来将申请 Let's Encrypt 证书：${NC}"
    echo -e "  • 域名: ${G}$domain${NC}"
    echo -e "  • 证书有效期: 90天 (自动续期)"
    echo ""
    echo -e "  ${Y}请选择验证方式：${NC}"
    echo -e "  1) HTTP 验证 (需要80端口，推荐)"
    echo -e "  2) DNS 验证 (无需80端口，适合NAT/无公网IP)"
    echo -e "  3) 取消"
    echo ""
    read -rp "  请选择 [1-3]: " verify_method
    
    case "$verify_method" in
        2)
            # DNS 验证模式
            _issue_cert_dns "$domain" "$cert_dir" "$protocol"
            return $?
            ;;
        3)
            _info "已取消证书申请"
            return 2
            ;;
        1|"")
            # HTTP 验证模式（默认）
            ;;
        *)
            _err "无效选择"
            return 1
            ;;
    esac
    
    # 用户确认后再安装 acme.sh
    _info "安装证书申请工具..."
    install_acme_tool || return 1
    
    local acme_sh="$HOME/.acme.sh/acme.sh"
    
    # 临时停止可能占用 80 端口的服务（兼容 Alpine/systemd）
    local nginx_was_running=false
    if svc status nginx 2>/dev/null; then
        nginx_was_running=true
        _info "临时停止 Nginx..."
        svc stop nginx
    fi
    
    _info "正在为 $domain 申请证书 (Let's Encrypt)..."
    echo ""
    
    # 获取服务器IP用于错误提示
    local server_ip=$(get_ipv4)
    [[ -z "$server_ip" ]] && server_ip=$(get_ipv6)
    
    # 构建 reloadcmd（兼容 systemd 和 OpenRC）
    local reload_cmd="chmod 600 $cert_dir/server.key; chmod 644 $cert_dir/server.crt; chown root:root $cert_dir/server.key $cert_dir/server.crt; if command -v systemctl >/dev/null 2>&1; then systemctl restart vless-reality vless-singbox 2>/dev/null || true; elif command -v rc-service >/dev/null 2>&1; then rc-service vless-reality restart 2>/dev/null || true; rc-service vless-singbox restart 2>/dev/null || true; fi"
    
    # 使用 standalone 模式申请证书，显示实时进度
    local acme_log="/tmp/acme_output.log"
    
    # 直接执行 acme.sh，不使用 timeout（避免某些系统兼容性问题）
    if "$acme_sh" --issue -d "$domain" --standalone --httpport 80 --force 2>&1 | tee "$acme_log" | grep -E "^\[|Verify finished|Cert success|error|Error" | sed 's/^/  /'; then
        echo ""
        _ok "证书申请成功，安装证书..."
        
        # 安装证书到指定目录，并设置权限和自动重启服务
        "$acme_sh" --install-cert -d "$domain" \
            --key-file       "$cert_dir/server.key"  \
            --fullchain-file "$cert_dir/server.crt" \
            --reloadcmd      "$reload_cmd" >/dev/null 2>&1
        
        rm -f "$acme_log"
        
        # 恢复 Nginx
        if [[ "$nginx_was_running" == "true" ]]; then
            svc start nginx
        fi
        
        _ok "证书已配置到 $cert_dir"
        _ok "证书自动续期已启用 (60天后)"
        
        # 读取自定义 nginx 端口（如果有）
        local custom_port=""
        [[ -f "$CFG/.nginx_port_tmp" ]] && custom_port=$(cat "$CFG/.nginx_port_tmp")
        
        # 创建简单的伪装网页
        create_fake_website "$domain" "$protocol" "$custom_port"
        
        # 验证证书文件
        if [[ -f "$cert_dir/server.crt" && -f "$cert_dir/server.key" ]]; then
            _ok "证书文件验证通过"
            # 运行证书诊断
            diagnose_certificate "$domain"
        else
            _err "证书文件不存在"
            return 1
        fi
        
        return 0
    else
        echo ""
        # 恢复 Nginx
        if [[ "$nginx_was_running" == "true" ]]; then
            svc start nginx
        fi
        
        _err "证书申请失败！"
        echo ""
        _err "详细错误信息："
        cat "$acme_log" 2>/dev/null | grep -E "(error|Error|ERROR|fail|Fail|FAIL)" | head -5 | while read -r line; do
            _err "  $line"
        done
        rm -f "$acme_log"
        echo ""
        _err "常见问题检查："
        _err "  1. 域名是否正确解析到本机 IP: $server_ip"
        _err "  2. 80 端口是否在防火墙中开放"
        _err "  3. 域名是否已被其他证书占用"
        _err "  4. 是否有其他程序占用80端口"
        echo ""
        _warn "回退到自签名证书模式..."
        return 1
    fi
}

# 检测并设置证书和 Nginx 配置（统一入口）
# 返回: 0=成功（有证书和Nginx），1=失败（无证书或用户取消）
# 设置全局变量: CERT_DOMAIN, NGINX_PORT
setup_cert_and_nginx() {
    local protocol="$1"
    local default_nginx_port="8443"
    
    # 全局变量，供调用方使用
    CERT_DOMAIN=""
    NGINX_PORT="$default_nginx_port"
    
    # === 回落子协议检测：如果是 WS 协议且有主协议，跳过 Nginx 配置 ===
    local is_fallback_mode=false
    if [[ "$protocol" == "vless-ws" || "$protocol" == "vmess-ws" ]]; then
        if db_exists "xray" "vless-vision" || db_exists "xray" "trojan"; then
            is_fallback_mode=true
        fi
    fi
    
    # 检测是否已有证书
    if [[ -f "$CFG/cert_domain" && -f "$CFG/certs/server.crt" ]]; then
        # 验证证书是否有效
        if openssl x509 -in "$CFG/certs/server.crt" -noout -checkend 2592000 >/dev/null 2>&1; then
            CERT_DOMAIN=$(cat "$CFG/cert_domain")
            
            # 检查是否是自签名证书
            local is_self_signed=true
            local issuer=$(openssl x509 -in "$CFG/certs/server.crt" -noout -issuer 2>/dev/null)
            if [[ "$issuer" == *"Let's Encrypt"* ]] || [[ "$issuer" == *"R3"* ]] || [[ "$issuer" == *"R10"* ]] || [[ "$issuer" == *"R11"* ]] || [[ "$issuer" == *"E1"* ]] || [[ "$issuer" == *"ZeroSSL"* ]] || [[ "$issuer" == *"Buypass"* ]]; then
                is_self_signed=false
            fi
            
            # 如果是自签名证书，询问用户是否申请真实证书
            if [[ "$is_self_signed" == "true" && "$is_fallback_mode" == "false" ]]; then
                echo ""
                _warn "检测到自签名证书 (域名: $CERT_DOMAIN)"
                echo -e "  ${G}1)${NC} 申请真实证书 (推荐 - 订阅功能可用)"
                echo -e "  ${G}2)${NC} 继续使用自签名证书 (订阅功能不可用)"
                echo ""
                read -rp "  请选择 [1]: " self_cert_choice
                
                if [[ "$self_cert_choice" != "2" ]]; then
                    # 用户选择申请真实证书，清除旧证书，走正常申请流程
                    rm -f "$CFG/certs/server.crt" "$CFG/certs/server.key" "$CFG/cert_domain"
                    CERT_DOMAIN=""
                    # 继续往下走到证书申请流程
                else
                    # 继续使用自签名证书，跳过 Nginx 配置
                    _ok "继续使用自签名证书: $CERT_DOMAIN"
                    return 0
                fi
            else
                # 真实证书，正常处理
                # 回落模式：只设置证书域名，跳过 Nginx 配置
                if [[ "$is_fallback_mode" == "true" ]]; then
                    _ok "检测到现有证书: $CERT_DOMAIN (回落模式，跳过 Nginx)"
                    return 0
                fi
                
                # 读取已有的订阅配置
                if [[ -f "$CFG/sub.info" ]]; then
                    source "$CFG/sub.info" 2>/dev/null
                    NGINX_PORT="${sub_port:-$default_nginx_port}"
                fi
                
                _ok "检测到现有证书: $CERT_DOMAIN"
                
                # 检查 Nginx 配置文件是否存在
                local nginx_conf_exists=false
                if [[ -f "/etc/nginx/conf.d/vless-fake.conf" ]] || [[ -f "/etc/nginx/sites-available/vless-fake" ]]; then
                    nginx_conf_exists=true
                fi
                
                # 检查订阅文件是否存在
                local sub_uuid=$(get_sub_uuid)  # 使用统一的函数获取或生成 UUID
                local sub_files_exist=false
                if [[ -f "$CFG/subscription/$sub_uuid/base64" ]]; then
                    sub_files_exist=true
                fi
                
                # 如果 Nginx 配置或订阅文件不存在，重新配置
                if [[ "$nginx_conf_exists" == "false" ]] || [[ "$sub_files_exist" == "false" ]]; then
                    _info "配置订阅服务 (端口: $NGINX_PORT)..."
                    generate_sub_files
                    create_fake_website "$CERT_DOMAIN" "$protocol" "$NGINX_PORT"
                else
                    # 检查 Nginx 配置是否有正确的订阅路由 (使用 alias 指向 subscription 目录)
                    local nginx_conf_valid=false
                    if grep -q "alias.*subscription" "/etc/nginx/conf.d/vless-fake.conf" 2>/dev/null; then
                        nginx_conf_valid=true
                    fi
                    
                    if [[ "$nginx_conf_valid" == "false" ]]; then
                        _warn "检测到旧版 Nginx 配置，正在更新..."
                        generate_sub_files
                        create_fake_website "$CERT_DOMAIN" "$protocol" "$NGINX_PORT"
                    fi
                    
                    _ok "订阅服务端口: $NGINX_PORT"
                    
                    # 确保订阅文件是最新的
                    generate_sub_files
                    
                    # 确保 Nginx 运行
                    if ! ss -tlnp 2>/dev/null | grep -qE ":${NGINX_PORT}\s|:${NGINX_PORT}$"; then
                        _info "启动 Nginx 服务..."
                        systemctl stop nginx 2>/dev/null
                        sleep 1
                        systemctl start nginx 2>/dev/null || rc-service nginx start 2>/dev/null
                        sleep 1
                    fi
                    
                    # 再次检查端口是否监听
                    if ss -tlnp 2>/dev/null | grep -qE ":${NGINX_PORT}\s|:${NGINX_PORT}$"; then
                        _ok "Nginx 服务运行正常"
                        _ok "伪装网页: https://$CERT_DOMAIN:$NGINX_PORT"
                    else
                        _warn "Nginx 端口 $NGINX_PORT 未监听，尝试重新配置..."
                        generate_sub_files
                        create_fake_website "$CERT_DOMAIN" "$protocol" "$NGINX_PORT"
                    fi
                fi
                
                return 0
            fi
        fi
    fi
    
    # 没有证书或用户选择申请新证书，询问用户
    echo ""
    _line
    echo -e "  ${W}证书配置模式${NC}"
    echo -e "  ${G}1)${NC} 使用真实域名 (推荐 - 自动申请 Let's Encrypt 证书)"
    echo -e "  ${G}2)${NC} 无域名 (使用自签证书 - 安全性较低，易被识别)"
    echo ""
    read -rp "  请选择 [1-2，默认 2]: " cert_choice
    
    if [[ "$cert_choice" == "1" ]]; then
        echo -e "  ${Y}提示: 域名必须已解析到本机 IP${NC}"
        read -rp "  请输入你的域名: " input_domain
        
        if [[ -n "$input_domain" ]]; then
            CERT_DOMAIN="$input_domain"
            
            # 确保配置目录存在
            mkdir -p "$CFG" 2>/dev/null
            
            # 保存端口到临时文件，供 create_fake_website 使用
            echo "$NGINX_PORT" > "$CFG/.nginx_port_tmp" 2>/dev/null
            
            # 申请证书（内部会调用 create_fake_website，会自动保存 sub.info）
            if get_acme_cert "$CERT_DOMAIN" "$protocol"; then
                echo "$CERT_DOMAIN" > "$CFG/cert_domain"
                # 确保订阅文件存在
                generate_sub_files
                rm -f "$CFG/.nginx_port_tmp"
                return 0
            else
                _warn "证书申请失败，使用自签证书"
                gen_self_cert "$CERT_DOMAIN"
                echo "$CERT_DOMAIN" > "$CFG/cert_domain"
                rm -f "$CFG/.nginx_port_tmp"
                return 1
            fi
        fi
    fi
    
    # 使用自签证书
    gen_self_cert "localhost"
    return 1
}

# SNI配置交互式询问
# 参数: $1=默认SNI (可选), $2=已申请的域名 (可选)
ask_sni_config() {
    local default_sni="${1:-$(gen_sni)}"
    local cert_domain="${2:-}"
    
    # 如果有证书域名，检查是否是真实证书
    if [[ -n "$cert_domain" && -f "$CFG/certs/server.crt" ]]; then
        local is_real_cert=false
        local issuer=$(openssl x509 -in "$CFG/certs/server.crt" -noout -issuer 2>/dev/null)
        if [[ "$issuer" == *"Let's Encrypt"* ]] || [[ "$issuer" == *"R3"* ]] || [[ "$issuer" == *"R10"* ]] || [[ "$issuer" == *"R11"* ]] || [[ "$issuer" == *"E1"* ]] || [[ "$issuer" == *"ZeroSSL"* ]] || [[ "$issuer" == *"Buypass"* ]]; then
            is_real_cert=true
        fi
        
        # 真实证书：直接使用证书域名，不询问
        if [[ "$is_real_cert" == "true" ]]; then
            _ok "使用证书域名: $cert_domain" >&2
            echo "$cert_domain"
            return 0
        fi
    fi
    
    echo "" >&2
    _line >&2
    echo -e "  ${W}SNI 配置${NC}" >&2
    
    # 生成一个真正的随机 SNI（用于"更隐蔽"选项）
    local random_sni=$(gen_sni)
    
    # 如果有证书域名（自签名证书），询问是否使用
    if [[ -n "$cert_domain" ]]; then
        echo -e "  ${G}1${NC}) 使用证书域名 (${G}$cert_domain${NC}) - 推荐" >&2
        echo -e "  ${G}2${NC}) 使用随机SNI (${G}$random_sni${NC}) - 更隐蔽" >&2
        echo -e "  ${G}3${NC}) 自定义SNI" >&2
        echo "" >&2
        
        local sni_choice=""
        while true; do
            read -rp "  请选择 [1-3，默认 1]: " sni_choice
            
            if [[ -z "$sni_choice" ]]; then
                sni_choice="1"
            fi
            
            if [[ "$sni_choice" == "1" ]]; then
                echo "$cert_domain"
                return 0
            elif [[ "$sni_choice" == "2" ]]; then
                echo "$random_sni"
                return 0
            elif [[ "$sni_choice" == "3" ]]; then
                break
            else
                _err "无效选择: $sni_choice" >&2
                _warn "请输入 1、2 或 3" >&2
            fi
        done
    else
        # 没有证书域名时（如Reality协议），提供随机SNI和自定义选项
        echo -e "  ${G}1${NC}) 使用随机SNI (${G}$default_sni${NC}) - 推荐" >&2
        echo -e "  ${G}2${NC}) 自定义SNI" >&2
        echo "" >&2
        
        local sni_choice=""
        while true; do
            read -rp "  请选择 [1-2，默认 1]: " sni_choice
            
            if [[ -z "$sni_choice" ]]; then
                sni_choice="1"
            fi
            
            if [[ "$sni_choice" == "1" ]]; then
                echo "$default_sni"
                return 0
            elif [[ "$sni_choice" == "2" ]]; then
                break
            else
                _err "无效选择: $sni_choice" >&2
                _warn "请输入 1 或 2" >&2
            fi
        done
    fi
    
    # 自定义SNI输入
    while true; do
        echo "" >&2
        echo -e "  ${C}请输入自定义SNI域名 (回车使用随机SNI):${NC}" >&2
        read -rp "  SNI: " custom_sni
        
        if [[ -z "$custom_sni" ]]; then
            # 重新生成一个随机SNI
            local new_random_sni=$(gen_sni)
            echo -e "  ${G}使用随机SNI: $new_random_sni${NC}" >&2
            echo "$new_random_sni"
            return 0
        else
            # 基本域名格式验证
            if [[ "$custom_sni" =~ ^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$ ]]; then
                echo "$custom_sni"
                return 0
            else
                _err "无效SNI格式: $custom_sni" >&2
                _warn "SNI格式示例: www.example.com" >&2
            fi
        fi
    done
}

# 证书配置交互式询问
# 参数: $1=默认SNI (可选)
ask_cert_config() {
    local default_sni="${1:-bing.com}"
    local protocol="${2:-unknown}"
    
    # 检查是否已有 ACME 证书，如果有则直接复用
    if [[ -f "$CFG/cert_domain" && -f "$CFG/certs/server.crt" ]]; then
        local existing_domain=$(cat "$CFG/cert_domain")
        local issuer=$(openssl x509 -in "$CFG/certs/server.crt" -noout -issuer 2>/dev/null)
        if [[ "$issuer" == *"Let's Encrypt"* ]] || [[ "$issuer" == *"R3"* ]] || [[ "$issuer" == *"R10"* ]] || [[ "$issuer" == *"R11"* ]]; then
            _ok "检测到现有 ACME 证书: $existing_domain，自动复用" >&2
            echo "$existing_domain"
            return 0
        fi
    fi
    
    # 所有提示信息输出到 stderr，避免污染返回值
    echo "" >&2
    _line >&2
    echo -e "  ${W}证书配置模式${NC}" >&2
    echo -e "  ${G}1${NC}) 使用真实域名 (推荐 - 自动申请 Let's Encrypt 证书)" >&2
    echo -e "  ${Y}2${NC}) 无域名 (使用自签证书 - 安全性较低，易被识别)" >&2
    echo "" >&2
    
    local cert_mode=""
    local domain=""
    local use_acme=false
    
    # 验证证书模式选择
    while true; do
        read -rp "  请选择 [1-2，默认 2]: " cert_mode
        
        # 如果用户直接回车，使用默认选项 2
        if [[ -z "$cert_mode" ]]; then
            cert_mode="2"
        fi
        
        # 验证输入是否为有效选项
        if [[ "$cert_mode" == "1" || "$cert_mode" == "2" ]]; then
            break
        else
            _err "无效选择: $cert_mode" >&2
            _warn "请输入 1 或 2" >&2
        fi
    done
    
    if [[ "$cert_mode" == "1" ]]; then
        # 域名输入循环，支持重新输入
        while true; do
            echo "" >&2
            echo -e "  ${C}提示: 域名必须已解析到本机 IP${NC}" >&2
            read -rp "  请输入你的域名: " domain
            
            if [[ -z "$domain" ]]; then
                _warn "域名不能为空，使用自签证书" >&2
                gen_self_cert "$default_sni" >&2
                domain=""
                break
            else
                # 基本域名格式验证
                if ! [[ "$domain" =~ ^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$ ]]; then
                    _err "无效域名格式: $domain" >&2
                    _warn "域名格式示例: example.com 或 sub.example.com" >&2
                    continue
                fi
                local cert_result
                get_acme_cert "$domain" "$protocol" >&2
                cert_result=$?
                
                if [[ $cert_result -eq 0 ]]; then
                    # ACME 成功
                    use_acme=true
                    echo "$domain" > "$CFG/cert_domain"
                    break
                elif [[ $cert_result -eq 2 ]]; then
                    # 需要重新输入域名，继续循环
                    continue
                else
                    # ACME 失败，使用自签证书，返回空字符串
                    gen_self_cert "$default_sni" >&2
                    domain=""
                    break
                fi
            fi
        done
    else
        # 无域名模式：使用自签证书，返回空字符串表示没有真实域名
        gen_self_cert "$default_sni" >&2
        domain=""
    fi
    
    # 只返回域名到 stdout（空字符串表示使用了自签证书）
    echo "$domain"
}

# 修复 SELinux 上下文 (CentOS/RHEL)
fix_selinux_context() {
    # 仅在 CentOS/RHEL 且 SELinux 启用时执行
    if [[ "$DISTRO" != "centos" ]]; then
        return 0
    fi
    
    # 检查 SELinux 是否启用
    if ! command -v getenforce &>/dev/null || [[ "$(getenforce 2>/dev/null)" == "Disabled" ]]; then
        return 0
    fi
    
    _info "配置 SELinux 上下文..."
    
    # 允许自定义端口
    if command -v semanage &>/dev/null; then
        local port="$1"
        if [[ -n "$port" ]]; then
            semanage port -a -t http_port_t -p tcp "$port" 2>/dev/null || true
            semanage port -a -t http_port_t -p udp "$port" 2>/dev/null || true
        fi
    fi
    
    # 恢复文件上下文
    if command -v restorecon &>/dev/null; then
        restorecon -Rv /usr/local/bin/xray /usr/local/bin/sing-box /usr/local/bin/snell-server \
            /usr/local/bin/snell-server-v5 /usr/local/bin/anytls-server /usr/local/bin/shadow-tls \
            /etc/vless-reality 2>/dev/null || true
    fi
    
    # 允许网络连接
    if command -v setsebool &>/dev/null; then
        setsebool -P httpd_can_network_connect 1 2>/dev/null || true
    fi
}

# 获取 GitHub 最新版本号
_get_latest_version() {
    local repo="$1"
    curl -sL "https://api.github.com/repos/$repo/releases/latest" 2>/dev/null | jq -r '.tag_name // empty' | sed 's/^v//'
}

# 架构映射 (减少重复代码)
# 用法: local mapped=$(_map_arch "amd64:arm64:armv7")
_map_arch() {
    local mapping="$1" arch=$(uname -m)
    local x86 arm64 arm7
    IFS=':' read -r x86 arm64 arm7 <<< "$mapping"
    case $arch in
        x86_64)  echo "$x86" ;;
        aarch64) echo "$arm64" ;;
        armv7l)  echo "$arm7" ;;
        *) return 1 ;;
    esac
}

# 通用二进制下载安装函数
_install_binary() {
    local name="$1" repo="$2" url_pattern="$3" extract_cmd="$4"
    check_cmd "$name" && { _ok "$name 已安装"; return 0; }
    
    _info "安装 $name (获取最新版本)..."
    local version=$(_get_latest_version "$repo")
    [[ -z "$version" ]] && { _err "获取 $name 版本失败"; return 1; }
    
    local arch=$(uname -m)
    local tmp=$(mktemp -d)
    local url=$(eval echo "$url_pattern")
    
    if curl -sLo "$tmp/pkg" --connect-timeout 60 "$url"; then
        eval "$extract_cmd"
        rm -rf "$tmp"
        _ok "$name v$version 已安装"
        return 0
    fi
    rm -rf "$tmp"
    _err "下载 $name 失败"
    return 1
}

install_xray() {
    local xarch=$(_map_arch "64:arm64-v8a:arm32-v7a") || { _err "不支持的架构"; return 1; }
    # Alpine 需要安装 gcompat 兼容层来运行 glibc 编译的二进制
    if [[ "$DISTRO" == "alpine" ]]; then
        apk add --no-cache gcompat libc6-compat &>/dev/null
    fi
    _install_binary "xray" "XTLS/Xray-core" \
        'https://github.com/XTLS/Xray-core/releases/download/v$version/Xray-linux-${xarch}.zip' \
        'unzip -oq "$tmp/pkg" -d "$tmp/" && install -m 755 "$tmp/xray" /usr/local/bin/xray && mkdir -p /usr/local/share/xray && cp "$tmp"/*.dat /usr/local/share/xray/ 2>/dev/null; fix_selinux_context'
}

#═══════════════════════════════════════════════════════════════════════════════
# Sing-box 核心 - 统一管理 UDP/QUIC 协议 (Hy2/TUIC)
#═══════════════════════════════════════════════════════════════════════════════

install_singbox() {
    local sarch=$(_map_arch "amd64:arm64:armv7") || { _err "不支持的架构"; return 1; }
    # Alpine 需要安装 gcompat 兼容层来运行 glibc 编译的二进制
    if [[ "$DISTRO" == "alpine" ]]; then
        apk add --no-cache gcompat libc6-compat &>/dev/null
    fi
    _install_binary "sing-box" "SagerNet/sing-box" \
        'https://github.com/SagerNet/sing-box/releases/download/v$version/sing-box-$version-linux-${sarch}.tar.gz' \
        'tar -xzf "$tmp/pkg" -C "$tmp/" && install -m 755 "$(find "$tmp" -name sing-box -type f | head -1)" /usr/local/bin/sing-box'
}

# 生成 Sing-box 统一配置 (Hy2 + TUIC 共用一个进程)
generate_singbox_config() {
    local singbox_protocols=$(db_list_protocols "singbox")
    [[ -z "$singbox_protocols" ]] && return 1
    
    mkdir -p "$CFG"
    
    # 收集所有需要的出口
    local outbounds='[{"type": "direct", "tag": "direct"}]'
    local routing_rules=""
    local has_routing=false
    
    # 获取分流规则
    local rules=$(db_get_routing_rules)
    
    if [[ -n "$rules" && "$rules" != "[]" ]]; then
        # 收集所有用到的出口 (支持多出口)
        local added_warp=false
        declare -A added_chains  # 记录已添加的链式代理节点
        
        while IFS= read -r outbound; do
            [[ -z "$outbound" ]] && continue
            
            if [[ "$outbound" == "warp" && "$added_warp" == "false" ]]; then
                local warp_out=$(gen_singbox_warp_outbound)
                [[ -n "$warp_out" ]] && {
                    outbounds=$(echo "$outbounds" | jq --argjson out "$warp_out" '. + [$out]')
                    added_warp=true
                }
            elif [[ "$outbound" == chain:* ]]; then
                local node_name="${outbound#chain:}"
                # 检查是否已添加该节点
                if [[ -z "${added_chains[$node_name]}" ]]; then
                    local tag="chain-${node_name}"
                    local chain_out=$(gen_singbox_chain_outbound "$node_name" "$tag")
                    [[ -n "$chain_out" ]] && {
                        outbounds=$(echo "$outbounds" | jq --argjson out "$chain_out" '. + [$out]')
                        added_chains[$node_name]=1
                    }
                fi
            fi
        done < <(echo "$rules" | jq -r '.[].outbound')
        
        routing_rules=$(gen_singbox_routing_rules)
        [[ -n "$routing_rules" && "$routing_rules" != "[]" ]] && has_routing=true
    fi
    
    # 构建基础配置
    local base_config=""
    if [[ "$has_routing" == "true" ]]; then
        base_config=$(jq -n --argjson outbounds "$outbounds" '{
            log: {level: "warn", timestamp: true},
            inbounds: [],
            outbounds: $outbounds,
            route: {rules: []}
        }')
        
        # 添加路由规则
        if [[ -n "$routing_rules" && "$routing_rules" != "[]" ]]; then
            base_config=$(echo "$base_config" | jq --argjson rules "$routing_rules" '.route.rules = $rules')
        fi
    else
        base_config=$(jq -n '{
            log: {level: "warn", timestamp: true},
            inbounds: [],
            outbounds: [{type: "direct", tag: "direct"}]
        }')
    fi
    
    local inbounds="[]"
    local success_count=0
    
    for proto in $singbox_protocols; do
        local cfg=$(db_get "singbox" "$proto")
        [[ -z "$cfg" ]] && continue
        
        local port=$(echo "$cfg" | jq -r '.port // empty')
        [[ -z "$port" ]] && continue
        
        local inbound=""
        
        case "$proto" in
            hy2)
                local password=$(echo "$cfg" | jq -r '.password // empty')
                local sni=$(echo "$cfg" | jq -r '.sni // "www.bing.com"')
                
                # 智能证书选择：优先使用 ACME 证书，否则使用 hy2 独立自签证书
                local cert_path="$CFG/certs/hy2/server.crt"
                local key_path="$CFG/certs/hy2/server.key"
                if [[ -f "$CFG/cert_domain" && -f "$CFG/certs/server.crt" ]]; then
                    local cert_domain=$(cat "$CFG/cert_domain" 2>/dev/null)
                    if [[ "$sni" == "$cert_domain" ]]; then
                        cert_path="$CFG/certs/server.crt"
                        key_path="$CFG/certs/server.key"
                    fi
                fi
                
                inbound=$(jq -n \
                    --argjson port "$port" \
                    --arg password "$password" \
                    --arg cert "$cert_path" \
                    --arg key "$key_path" \
                '{
                    type: "hysteria2",
                    tag: "hy2-in",
                    listen: "::",
                    listen_port: $port,
                    users: [{password: $password}],
                    tls: {
                        enabled: true,
                        certificate_path: $cert,
                        key_path: $key
                    },
                    masquerade: "https://www.bing.com"
                }')
                ;;
            tuic)
                local uuid=$(echo "$cfg" | jq -r '.uuid // empty')
                local password=$(echo "$cfg" | jq -r '.password // empty')
                
                # TUIC 使用独立证书目录
                local cert_path="$CFG/certs/tuic/server.crt"
                local key_path="$CFG/certs/tuic/server.key"
                [[ ! -f "$cert_path" ]] && { cert_path="$CFG/certs/server.crt"; key_path="$CFG/certs/server.key"; }
                
                inbound=$(jq -n \
                    --argjson port "$port" \
                    --arg uuid "$uuid" \
                    --arg password "$password" \
                    --arg cert "$cert_path" \
                    --arg key "$key_path" \
                '{
                    type: "tuic",
                    tag: "tuic-in",
                    listen: "::",
                    listen_port: $port,
                    users: [{uuid: $uuid, password: $password}],
                    congestion_control: "bbr",
                    tls: {
                        enabled: true,
                        certificate_path: $cert,
                        key_path: $key,
                        alpn: ["h3"]
                    }
                }')
                ;;
            ss2022|ss-legacy)
                local password=$(echo "$cfg" | jq -r '.password // empty')
                local default_method="2022-blake3-aes-128-gcm"
                [[ "$p" == "ss-legacy" ]] && default_method="aes-256-gcm"
                local method=$(echo "$cfg" | jq -r '.method // empty')
                [[ -z "$method" ]] && method="$default_method"
                
                inbound=$(jq -n \
                    --argjson port "$port" \
                    --arg method "$method" \
                    --arg password "$password" \
                    --arg tag "${p}-in" \
                '{
                    type: "shadowsocks",
                    tag: $tag,
                    listen: "::",
                    listen_port: $port,
                    method: $method,
                    password: $password
                }')
                ;;
        esac
        
        if [[ -n "$inbound" ]]; then
            inbounds=$(echo "$inbounds" | jq --argjson ib "$inbound" '. += [$ib]')
            ((success_count++))
        fi
    done
    
    if [[ $success_count -eq 0 ]]; then
        _err "没有有效的 Sing-box 协议配置"
        return 1
    fi
    
    # 合并配置并写入文件
    echo "$base_config" | jq --argjson ibs "$inbounds" '.inbounds = $ibs' > "$CFG/singbox.json"
    
    # 验证配置
    if ! jq empty "$CFG/singbox.json" 2>/dev/null; then
        _err "Sing-box 配置 JSON 格式错误"
        return 1
    fi
    
    _ok "Sing-box 配置生成成功 ($success_count 个协议)"
    return 0
}

# 创建 Sing-box 服务
create_singbox_service() {
    local service_name="vless-singbox"
    local exec_cmd="/usr/local/bin/sing-box run -c $CFG/singbox.json"
    
    # 检查是否有 hy2 协议且启用了端口跳跃
    local has_hy2_hop=false
    if db_exists "singbox" "hy2"; then
        local hop_enable=$(db_get_field "singbox" "hy2" "hop_enable")
        [[ "$hop_enable" == "1" ]] && has_hy2_hop=true
    fi
    
    local has_tuic_hop=false
    if db_exists "singbox" "tuic"; then
        local hop_enable=$(db_get_field "singbox" "tuic" "hop_enable")
        [[ "$hop_enable" == "1" ]] && has_tuic_hop=true
    fi
    
    if [[ "$DISTRO" == "alpine" ]]; then
        # Alpine: 在 start_pre 中执行端口跳跃脚本
        cat > /etc/init.d/$service_name << EOF
#!/sbin/openrc-run
name="Sing-box Proxy Server"
command="/usr/local/bin/sing-box"
command_args="run -c $CFG/singbox.json"
command_background="yes"
pidfile="/run/${service_name}.pid"
depend() { need net; }
start_pre() {
    [[ -x "$CFG/hy2-nat.sh" ]] && "$CFG/hy2-nat.sh" || true
    [[ -x "$CFG/tuic-nat.sh" ]] && "$CFG/tuic-nat.sh" || true
}
EOF
        chmod +x /etc/init.d/$service_name
    else
        # systemd: 添加 ExecStartPre 执行端口跳跃脚本
        local pre_cmd=""
        [[ -f "$CFG/hy2-nat.sh" ]] && pre_cmd="ExecStartPre=-/bin/bash $CFG/hy2-nat.sh"
        [[ -f "$CFG/tuic-nat.sh" ]] && pre_cmd="${pre_cmd}"$'\n'"ExecStartPre=-/bin/bash $CFG/tuic-nat.sh"
        
        cat > /etc/systemd/system/${service_name}.service << EOF
[Unit]
Description=Sing-box Proxy Server (Hy2/TUIC/SS2022)
After=network.target

[Service]
Type=simple
${pre_cmd}
ExecStart=$exec_cmd
Restart=always
RestartSec=3
LimitNOFILE=51200

[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload
    fi
}

# 安装 Snell v4
install_snell() {
    check_cmd snell-server && { _ok "Snell 已安装"; return 0; }
    local sarch=$(_map_arch "amd64:aarch64:armv7l") || { _err "不支持的架构"; return 1; }
    # Alpine 需要安装 upx 来解压 UPX 压缩的二进制 (musl 不兼容 UPX stub)
    if [[ "$DISTRO" == "alpine" ]]; then
        apk add --no-cache upx &>/dev/null
    fi
    _info "安装 Snell v4..."
    local tmp=$(mktemp -d)
    if curl -sLo "$tmp/snell.zip" --connect-timeout 60 "https://dl.nssurge.com/snell/snell-server-v4.1.1-linux-${sarch}.zip"; then
        unzip -oq "$tmp/snell.zip" -d "$tmp/" && install -m 755 "$tmp/snell-server" /usr/local/bin/snell-server
        # Alpine: 解压 UPX 压缩 (Snell 官方二进制使用 UPX，musl 不兼容 UPX stub)
        if [[ "$DISTRO" == "alpine" ]] && command -v upx &>/dev/null; then
            upx -d /usr/local/bin/snell-server &>/dev/null || true
        fi
        rm -rf "$tmp"; _ok "Snell v4 已安装"; return 0
    fi
    rm -rf "$tmp"; _err "下载失败"; return 1
}

# 安装 Snell v5
install_snell_v5() {
    check_cmd snell-server-v5 && { _ok "Snell v5 已安装"; return 0; }
    local sarch=$(_map_arch "amd64:aarch64:armv7l") || { _err "不支持的架构"; return 1; }
    # Alpine 需要安装 upx 来解压 UPX 压缩的二进制 (musl 不兼容 UPX stub)
    if [[ "$DISTRO" == "alpine" ]]; then
        apk add --no-cache upx &>/dev/null
    fi
    local version=$(_get_latest_version "surge-networks/snell"); [[ -z "$version" ]] && version="5.0.1"
    _info "安装 Snell v$version..."
    local tmp=$(mktemp -d)
    if curl -sLo "$tmp/snell.zip" --connect-timeout 60 "https://dl.nssurge.com/snell/snell-server-v${version}-linux-${sarch}.zip"; then
        unzip -oq "$tmp/snell.zip" -d "$tmp/" && install -m 755 "$tmp/snell-server" /usr/local/bin/snell-server-v5
        # Alpine: 解压 UPX 压缩 (Snell 官方二进制使用 UPX，musl 不兼容 UPX stub)
        if [[ "$DISTRO" == "alpine" ]] && command -v upx &>/dev/null; then
            upx -d /usr/local/bin/snell-server-v5 &>/dev/null || true
        fi
        rm -rf "$tmp"; _ok "Snell v$version 已安装"; return 0
    fi
    rm -rf "$tmp"; _err "下载失败"; return 1
}

# 安装 AnyTLS
install_anytls() {
    local aarch=$(_map_arch "amd64:arm64:armv7") || { _err "不支持的架构"; return 1; }
    # Alpine 需要安装 gcompat 兼容层（以防 Go 二进制使用 CGO）
    if [[ "$DISTRO" == "alpine" ]]; then
        apk add --no-cache gcompat libc6-compat &>/dev/null
    fi
    _install_binary "anytls-server" "anytls/anytls-go" \
        'https://github.com/anytls/anytls-go/releases/download/v$version/anytls_${version}_linux_${aarch}.zip' \
        'unzip -oq "$tmp/pkg" -d "$tmp/" && install -m 755 "$tmp/anytls-server" /usr/local/bin/anytls-server && install -m 755 "$tmp/anytls-client" /usr/local/bin/anytls-client 2>/dev/null'
}

# 安装 ShadowTLS
install_shadowtls() {
    local aarch=$(_map_arch "x86_64-unknown-linux-musl:aarch64-unknown-linux-musl:armv7-unknown-linux-musleabihf") || { _err "不支持的架构"; return 1; }
    _install_binary "shadow-tls" "ihciah/shadow-tls" \
        'https://github.com/ihciah/shadow-tls/releases/download/v$version/shadow-tls-${aarch}' \
        'install -m 755 "$tmp/pkg" /usr/local/bin/shadow-tls'
}

# 安装 NaïveProxy (Caddy with forwardproxy)
install_naive() {
    check_cmd caddy && caddy list-modules 2>/dev/null | grep -q "http.handlers.forward_proxy" && { _ok "NaïveProxy (Caddy) 已安装"; return 0; }
    
    local narch=$(_map_arch "amd64:arm64:armv7") || { _err "不支持的架构"; return 1; }
    # Alpine 需要安装 gcompat 兼容层
    if [[ "$DISTRO" == "alpine" ]]; then
        apk add --no-cache gcompat libc6-compat xz &>/dev/null
    fi
    _info "安装 NaïveProxy (Caddy with forwardproxy)..."
    
    local tmp=$(mktemp -d)
    
    # 获取 tar.xz 下载链接 (使用 jq 解析 JSON)
    local download_url=$(curl -sL --connect-timeout "$CURL_TIMEOUT_NORMAL" \
        "https://api.github.com/repos/klzgrad/forwardproxy/releases/latest" | \
        jq -r '.assets[] | select(.name | endswith(".tar.xz")) | .browser_download_url' 2>/dev/null | head -1)
    
    if [[ -z "$download_url" ]]; then
        _err "无法获取下载链接"
        rm -rf "$tmp"
        return 1
    fi
    
    _info "下载: $download_url"
    if curl -fSLo "$tmp/caddy.tar.xz" --connect-timeout 60 --retry 3 "$download_url"; then
        # 解压
        tar -xJf "$tmp/caddy.tar.xz" -C "$tmp/" 2>/dev/null || { _err "解压失败"; rm -rf "$tmp"; return 1; }
        
        # 查找对应架构的二进制文件 (优先精确匹配，然后尝试通用名称)
        local caddy_bin=""
        # 尝试匹配 linux-amd64 等架构名
        caddy_bin=$(find "$tmp" -type f \( -name "*linux-${narch}*" -o -name "*linux_${narch}*" \) 2>/dev/null | head -1)
        # 如果没找到，尝试在子目录中查找名为 caddy 的可执行文件
        [[ -z "$caddy_bin" ]] && caddy_bin=$(find "$tmp" -type f -name "caddy" 2>/dev/null | head -1)
        # 最后尝试查找任何 ELF 可执行文件
        [[ -z "$caddy_bin" ]] && caddy_bin=$(find "$tmp" -type f -exec sh -c 'file "$1" | grep -q "ELF.*executable"' _ {} \; -print 2>/dev/null | head -1)
        
        if [[ -n "$caddy_bin" ]] && file "$caddy_bin" | grep -q "ELF"; then
            install -m 755 "$caddy_bin" /usr/local/bin/caddy
            rm -rf "$tmp"
            _ok "NaïveProxy (Caddy) 已安装"
            return 0
        else
            _err "未找到架构 ${narch} 的二进制文件"
            find "$tmp" -type f -exec file {} \;
        fi
    fi
    
    rm -rf "$tmp"
    _err "下载失败，请检查网络或手动安装"
    return 1
}

# 生成通用自签名证书 (适配 Xray/Sing-box)
gen_self_cert() {
    local domain="${1:-localhost}"
    mkdir -p "$CFG/certs"
    
    # 检查是否应该保护现有证书
    if [[ -f "$CFG/certs/server.crt" ]]; then
        [[ -f "$CFG/cert_domain" ]] && { _ok "检测到已申请的证书，跳过"; return 0; }
        # 检查是否为 CA 签发的证书
        local issuer=$(openssl x509 -in "$CFG/certs/server.crt" -noout -issuer 2>/dev/null)
        [[ "$issuer" =~ (Let\'s\ Encrypt|R3|R10|R11|E1|E5|ZeroSSL|Buypass|DigiCert|Comodo|GlobalSign) ]] && \
            { _ok "检测到 CA 证书，跳过"; return 0; }
    fi
    
    rm -f "$CFG/certs/server.crt" "$CFG/certs/server.key"
    _info "生成自签名证书..."
    openssl req -x509 -nodes -newkey ec:<(openssl ecparam -name prime256v1) \
        -keyout "$CFG/certs/server.key" -out "$CFG/certs/server.crt" \
        -subj "/CN=$domain" -days 36500 2>/dev/null
    chmod 600 "$CFG/certs/server.key"
}


#═══════════════════════════════════════════════════════════════════════════════
# 配置生成
#═══════════════════════════════════════════════════════════════════════════════

# VLESS+Reality 服务端配置
gen_server_config() {
    local uuid="$1" port="$2" privkey="$3" pubkey="$4" sid="$5" sni="$6"
    mkdir -p "$CFG"
    
    register_protocol "vless" "$(build_config \
        uuid "$uuid" port "$port" private_key "$privkey" \
        public_key "$pubkey" short_id "$sid" sni "$sni")"
    
    _save_join_info "vless" "REALITY|%s|$port|$uuid|$pubkey|$sid|$sni" \
        "gen_vless_link %s $port $uuid $pubkey $sid $sni"
    echo "server" > "$CFG/role"
}

# VLESS+Reality+XHTTP 服务端配置
gen_vless_xhttp_server_config() {
    local uuid="$1" port="$2" privkey="$3" pubkey="$4" sid="$5" sni="$6" path="${7:-/}"
    mkdir -p "$CFG"
    
    register_protocol "vless-xhttp" "$(build_config \
        uuid "$uuid" port "$port" private_key "$privkey" \
        public_key "$pubkey" short_id "$sid" sni "$sni" path "$path")"
    
    _save_join_info "vless-xhttp" "REALITY-XHTTP|%s|$port|$uuid|$pubkey|$sid|$sni|$path" \
        "gen_vless_xhttp_link %s $port $uuid $pubkey $sid $sni $path"
    echo "server" > "$CFG/role"
}

# Hysteria2 服务端配置
gen_hy2_server_config() {
    local password="$1" port="$2" sni="${3:-bing.com}"
    local hop_enable="${4:-0}" hop_start="${5:-20000}" hop_end="${6:-50000}"
    mkdir -p "$CFG"
    
    # 生成自签证书（Sing-box 使用）
    local hy2_cert_dir="$CFG/certs/hy2"
    mkdir -p "$hy2_cert_dir"
    
    local cert_file="$hy2_cert_dir/server.crt"
    local key_file="$hy2_cert_dir/server.key"
    
    # 检查是否有真实域名的 ACME 证书可复用
    if [[ -f "$CFG/cert_domain" && -f "$CFG/certs/server.crt" ]]; then
        local cert_domain=$(cat "$CFG/cert_domain")
        local issuer=$(openssl x509 -in "$CFG/certs/server.crt" -noout -issuer 2>/dev/null)
        if [[ "$issuer" == *"Let's Encrypt"* ]] || [[ "$issuer" == *"R3"* ]] || [[ "$issuer" == *"R10"* ]] || [[ "$issuer" == *"R11"* ]]; then
            if [[ "$sni" == "$cert_domain" ]]; then
                _ok "复用现有 ACME 证书 (域名: $sni)"
            fi
        fi
    fi
    
    # 生成独立自签证书（无论是否有 ACME 证书都生成，Sing-box 配置会智能选择）
    local need_regen=false
    [[ ! -f "$cert_file" ]] && need_regen=true
    if [[ "$need_regen" == "false" ]]; then
        local cert_cn=$(openssl x509 -in "$cert_file" -noout -subject 2>/dev/null | sed 's/.*CN *= *//')
        [[ "$cert_cn" != "$sni" ]] && need_regen=true
    fi
    
    if [[ "$need_regen" == "true" ]]; then
        _info "为 Hysteria2 生成自签证书 (SNI: $sni)..."
        openssl req -x509 -nodes -newkey ec:<(openssl ecparam -name prime256v1) \
            -keyout "$key_file" -out "$cert_file" -subj "/CN=$sni" -days 36500 2>/dev/null
        chmod 600 "$key_file"
        _ok "Hysteria2 自签证书生成完成"
    fi

    # 写入数据库（Sing-box 从数据库读取配置生成 singbox.json）
    register_protocol "hy2" "$(build_config \
        password "$password" port "$port" sni "$sni" \
        hop_enable "$hop_enable" hop_start "$hop_start" hop_end "$hop_end")"
    
    # 保存 join 信息
    local extra_lines=()
    [[ "$hop_enable" == "1" ]] && extra_lines=("" "# 端口跳跃已启用" "# 客户端请手动将端口改为: ${hop_start}-${hop_end}")
    
    _save_join_info "hy2" "HY2|%s|$port|$password|$sni" \
        "gen_hy2_link %s $port $password $sni" "${extra_lines[@]}"
    cp "$CFG/hy2.join" "$CFG/join.txt" 2>/dev/null
    echo "server" > "$CFG/role"
}

# Trojan 服务端配置
gen_trojan_server_config() {
    local password="$1" port="$2" sni="${3:-bing.com}"
    mkdir -p "$CFG"
    
    [[ ! -f "$CFG/certs/server.crt" ]] && gen_self_cert "$sni"

    register_protocol "trojan" "$(build_config password "$password" port "$port" sni "$sni")"
    _save_join_info "trojan" "TROJAN|%s|$port|$password|$sni" \
        "gen_trojan_link %s $port $password $sni"
    echo "server" > "$CFG/role"
}

# VLESS+WS+TLS 服务端配置
gen_vless_ws_server_config() {
    local uuid="$1" port="$2" sni="${3:-bing.com}" path="${4:-/vless}" force_new_cert="${5:-false}"
    mkdir -p "$CFG"
    
    local outer_port=$(_get_master_port "$port")
    _has_master_protocol || _handle_standalone_cert "$sni" "$force_new_cert"

    register_protocol "vless-ws" "$(build_config \
        uuid "$uuid" port "$port" outer_port "$outer_port" sni "$sni" path "$path")"
    _save_join_info "vless-ws" "VLESS-WS|%s|$outer_port|$uuid|$sni|$path" \
        "gen_vless_ws_link %s $outer_port $uuid $sni $path"
    echo "server" > "$CFG/role"
}

# VMess+WS 服务端配置
gen_vmess_ws_server_config() {
    local uuid="$1" port="$2" sni="$3" path="$4" force_new_cert="${5:-false}"
    mkdir -p "$CFG"
    
    local outer_port=$(_get_master_port "$port")
    _has_master_protocol || _handle_standalone_cert "$sni" "$force_new_cert"

    register_protocol "vmess-ws" "$(build_config \
        uuid "$uuid" port "$port" outer_port "$outer_port" sni "$sni" path "$path")"
    _save_join_info "vmess-ws" "VMESSWS|%s|$outer_port|$uuid|$sni|$path" \
        "gen_vmess_ws_link %s $outer_port $uuid $sni $path"
    echo "server" > "$CFG/role"
}

# VLESS-XTLS-Vision 服务端配置
gen_vless_vision_server_config() {
    local uuid="$1" port="$2" sni="${3:-bing.com}"
    mkdir -p "$CFG"
    
    [[ ! -f "$CFG/certs/server.crt" ]] && gen_self_cert "$sni"

    register_protocol "vless-vision" "$(build_config uuid "$uuid" port "$port" sni "$sni")"
    _save_join_info "vless-vision" "VLESS-VISION|%s|$port|$uuid|$sni" \
        "gen_vless_vision_link %s $port $uuid $sni"
    echo "server" > "$CFG/role"
}

# Shadowsocks 2022 服务端配置
gen_ss2022_server_config() {
    local password="$1" port="$2" method="${3:-2022-blake3-aes-128-gcm}"
    mkdir -p "$CFG"

    register_protocol "ss2022" "$(build_config password "$password" port "$port" method "$method")"
    _save_join_info "ss2022" "SS2022|%s|$port|$method|$password" \
        "gen_ss2022_link %s $port $method $password"
    echo "server" > "$CFG/role"
}

# Shadowsocks 传统版服务端配置
gen_ss_legacy_server_config() {
    local password="$1" port="$2" method="${3:-aes-256-gcm}"
    mkdir -p "$CFG"

    register_protocol "ss-legacy" "$(build_config password "$password" port "$port" method "$method")"
    _save_join_info "ss-legacy" "SS|%s|$port|$method|$password" \
        "gen_ss_legacy_link %s $port $method $password"
    echo "server" > "$CFG/role"
}

# Snell v4 服务端配置
gen_snell_server_config() {
    local psk="$1" port="$2" version="${3:-4}"
    mkdir -p "$CFG"

    cat > "$CFG/snell.conf" << EOF
[snell-server]
listen = [::]:$port
psk = $psk
ipv6 = true
obfs = off
EOF

    register_protocol "snell" "$(build_config psk "$psk" port "$port" version "$version")"

    _save_join_info "snell" "SNELL|%s|$port|$psk|$version" \
        "gen_snell_link %s $port $psk $version"
    cp "$CFG/snell.join" "$CFG/join.txt" 2>/dev/null
    echo "server" > "$CFG/role"
}

# TUIC v5 服务端配置
gen_tuic_server_config() {
    local uuid="$1" password="$2" port="$3" sni="${4:-bing.com}"
    local hop_enable="${5:-0}" hop_start="${6:-20000}" hop_end="${7:-50000}"
    mkdir -p "$CFG"
    
    # 生成自签证书（Sing-box 使用）
    local tuic_cert_dir="$CFG/certs/tuic"
    mkdir -p "$tuic_cert_dir"
    local cert_file="$tuic_cert_dir/server.crt"
    local key_file="$tuic_cert_dir/server.key"
    
    local server_ip=$(get_ipv4)
    [[ -z "$server_ip" ]] && server_ip=$(get_ipv6)
    [[ -z "$server_ip" ]] && server_ip="$sni"
    
    # 检查是否有真实域名的 ACME 证书可复用
    local common_snis="www.microsoft.com learn.microsoft.com azure.microsoft.com www.apple.com www.amazon.com aws.amazon.com www.icloud.com itunes.apple.com www.nvidia.com www.amd.com www.intel.com www.samsung.com www.dell.com www.cisco.com www.oracle.com www.ibm.com www.adobe.com www.autodesk.com www.sap.com www.vmware.com"
    
    if ! echo "$common_snis" | grep -qw "$sni"; then
        # 真实域名：检查是否有共享证书
        if [[ -f "$CFG/certs/server.crt" && -f "$CFG/certs/server.key" ]]; then
            local cert_cn=$(openssl x509 -in "$CFG/certs/server.crt" -noout -subject 2>/dev/null | sed 's/.*CN *= *//')
            if [[ "$cert_cn" == "$sni" ]]; then
                _ok "复用现有证书 (域名: $sni)"
            fi
        fi
    fi
    
    # 生成独立自签证书（无论是否有 ACME 证书都生成，Sing-box 配置会智能选择）
    if [[ ! -f "$cert_file" ]]; then
        _info "为 TUIC 生成独立自签证书 (SNI: $sni)..."
        openssl req -x509 -nodes -newkey ec:<(openssl ecparam -name prime256v1) \
            -keyout "$key_file" -out "$cert_file" \
            -subj "/CN=$server_ip" -days 36500 \
            -addext "subjectAltName=DNS:$server_ip,IP:$server_ip" \
            -addext "basicConstraints=critical,CA:FALSE" \
            -addext "extendedKeyUsage=serverAuth" 2>/dev/null
        chmod 600 "$key_file"
        _ok "TUIC 自签证书生成完成"
    fi

    # 写入数据库（Sing-box 从数据库读取配置生成 singbox.json）
    register_protocol "tuic" "$(build_config \
        uuid "$uuid" password "$password" port "$port" sni "$sni" \
        hop_enable "$hop_enable" hop_start "$hop_start" hop_end "$hop_end")"
    
    # 保存 join 信息
    local extra_lines=()
    [[ "$hop_enable" == "1" ]] && extra_lines=("" "# 端口跳跃已启用" "# 客户端请手动将端口改为: ${hop_start}-${hop_end}")
    
    _save_join_info "tuic" "TUIC|%s|$port|$uuid|$password|$sni" \
        "gen_tuic_link %s $port $uuid $password $sni" "${extra_lines[@]}"
    cp "$CFG/tuic.join" "$CFG/join.txt" 2>/dev/null
    echo "server" > "$CFG/role"
}

# AnyTLS 服务端配置
gen_anytls_server_config() {
    local password="$1" port="$2" sni="${3:-bing.com}"
    mkdir -p "$CFG"

    register_protocol "anytls" "$(build_config password "$password" port "$port" sni "$sni")"
    _save_join_info "anytls" "ANYTLS|%s|$port|$password|$sni" \
        "gen_anytls_link %s $port $password $sni"
    cp "$CFG/anytls.join" "$CFG/join.txt" 2>/dev/null
    echo "server" > "$CFG/role"
}

# NaïveProxy 服务端配置
gen_naive_server_config() {
    local username="$1" password="$2" port="$3" domain="$4"
    mkdir -p "$CFG"
    
    # NaïveProxy 必须使用域名 + Caddy 自动申请证书
    cat > "$CFG/Caddyfile" << EOF
{
    order forward_proxy before file_server
    admin off
    log {
        output file /var/log/caddy/access.log
        level WARN
    }
}

:${port}, ${domain}:${port} {
    tls {
        protocols tls1.2 tls1.3
    }
    forward_proxy {
        basic_auth ${username} ${password}
        hide_ip
        hide_via
        probe_resistance
    }
    file_server {
        root /var/www/html
    }
}
EOF
    
    # 创建日志目录和伪装页面
    mkdir -p /var/log/caddy /var/www/html
    echo "<html><body><h1>Welcome</h1></body></html>" > /var/www/html/index.html
    
    register_protocol "naive" "$(build_config username "$username" password "$password" port "$port" domain "$domain")"
    # 链接使用域名而不是 IP
    _save_join_info "naive" "NAIVE|$domain|$port|$username|$password" \
        "gen_naive_link $domain $port $username $password"
    cp "$CFG/naive.join" "$CFG/join.txt" 2>/dev/null
    echo "server" > "$CFG/role"
}

# Snell + ShadowTLS 服务端配置 (v4/v5)
gen_snell_shadowtls_server_config() {
    local psk="$1" port="$2" sni="${3:-www.microsoft.com}" stls_password="$4" version="${5:-4}" custom_backend_port="${6:-}"
    mkdir -p "$CFG"
    
    local ipv4=$(get_ipv4) ipv6=$(get_ipv6)
    local protocol_name="snell-shadowtls"
    local snell_bin="snell-server"
    local snell_conf="snell-shadowtls.conf"
    
    if [[ "$version" == "5" ]]; then
        protocol_name="snell-v5-shadowtls"
        snell_bin="snell-server-v5"
        snell_conf="snell-v5-shadowtls.conf"
    fi
    
    # Snell 后端端口 (内部监听)
    local snell_backend_port
    if [[ -n "$custom_backend_port" ]]; then
        snell_backend_port="$custom_backend_port"
    else
        snell_backend_port=$((port + 10000))
        [[ $snell_backend_port -gt 65535 ]] && snell_backend_port=$((port - 10000))
    fi
    
    cat > "$CFG/$snell_conf" << EOF
[snell-server]
listen = 127.0.0.1:$snell_backend_port
psk = $psk
ipv6 = false
obfs = off
EOF
    
    register_protocol "$protocol_name" "$(build_config \
        psk "$psk" port "$port" sni "$sni" stls_password "$stls_password" \
        snell_backend_port "$snell_backend_port" version "$version")"
    echo "server" > "$CFG/role"
}

# SS2022 + ShadowTLS 服务端配置
gen_ss2022_shadowtls_server_config() {
    local password="$1" port="$2" method="${3:-2022-blake3-aes-256-gcm}" sni="${4:-www.microsoft.com}" stls_password="$5" custom_backend_port="${6:-}"
    mkdir -p "$CFG"
    
    # SS2022 后端端口
    local ss_backend_port
    if [[ -n "$custom_backend_port" ]]; then
        ss_backend_port="$custom_backend_port"
    else
        ss_backend_port=$((port + 10000))
        [[ $ss_backend_port -gt 65535 ]] && ss_backend_port=$((port - 10000))
    fi
    
    cat > "$CFG/ss2022-shadowtls-backend.json" << EOF
{
  "log": {"loglevel": "warning"},
  "inbounds": [{
    "port": $ss_backend_port,
    "listen": "127.0.0.1",
    "protocol": "shadowsocks",
    "settings": {"method": "$method", "password": "$password", "network": "tcp,udp"}
  }],
  "outbounds": [{"protocol": "freedom"}]
}
EOF
    
    register_protocol "ss2022-shadowtls" "$(build_config \
        password "$password" port "$port" method "$method" sni "$sni" \
        stls_password "$stls_password" ss_backend_port "$ss_backend_port")"
    echo "server" > "$CFG/role"
}

# SOCKS5 服务端配置
gen_socks_server_config() {
    local username="$1" password="$2" port="$3"
    mkdir -p "$CFG"

    register_protocol "socks" "$(build_config username "$username" password "$password" port "$port")"
    
    # SOCKS5 的 join 信息比较特殊，需要两种链接格式
    local ipv4=$(get_ipv4) ipv6=$(get_ipv6)
    > "$CFG/socks.join"
    if [[ -n "$ipv4" ]]; then
        local data="SOCKS|$ipv4|$port|$username|$password"
        local code=$(printf '%s' "$data" | base64 -w 0 2>/dev/null || printf '%s' "$data" | base64)
        local tg_link=$(gen_socks_link "$ipv4" "$port" "$username" "$password")
        local socks_link="socks5://${username}:${password}@${ipv4}:${port}#SOCKS5-${ipv4}"
        printf '%s\n' "# IPv4" >> "$CFG/socks.join"
        printf '%s\n' "JOIN_V4=$code" >> "$CFG/socks.join"
        printf '%s\n' "SOCKS_V4=$tg_link" >> "$CFG/socks.join"
        printf '%s\n' "SOCKS5_V4=$socks_link" >> "$CFG/socks.join"
    fi
    if [[ -n "$ipv6" ]]; then
        local data="SOCKS|[$ipv6]|$port|$username|$password"
        local code=$(printf '%s' "$data" | base64 -w 0 2>/dev/null || printf '%s' "$data" | base64)
        local tg_link="https://t.me/socks?server=[$ipv6]&port=${port}&user=${username}&pass=${password}"
        local socks_link="socks5://${username}:${password}@[$ipv6]:${port}#SOCKS5-[$ipv6]"
        printf '%s\n' "# IPv6" >> "$CFG/socks.join"
        printf '%s\n' "JOIN_V6=$code" >> "$CFG/socks.join"
        printf '%s\n' "SOCKS_V6=$tg_link" >> "$CFG/socks.join"
        printf '%s\n' "SOCKS5_V6=$socks_link" >> "$CFG/socks.join"
    fi
    echo "server" > "$CFG/role"
}

# Snell v5 服务端配置
gen_snell_v5_server_config() {
    local psk="$1" port="$2" version="${3:-5}"
    mkdir -p "$CFG"

    cat > "$CFG/snell-v5.conf" << EOF
[snell-server]
listen = [::]:$port
psk = $psk
version = $version
ipv6 = true
obfs = off
EOF

    register_protocol "snell-v5" "$(build_config psk "$psk" port "$port" version "$version")"
    _save_join_info "snell-v5" "SNELL-V5|%s|$port|$psk|$version" \
        "gen_snell_v5_link %s $port $psk $version"
    cp "$CFG/snell-v5.join" "$CFG/join.txt" 2>/dev/null
    echo "server" > "$CFG/role"
}

#═══════════════════════════════════════════════════════════════════════════════
# 服务端辅助脚本生成
#═══════════════════════════════════════════════════════════════════════════════
create_server_scripts() {
    # Watchdog 脚本 - 服务端监控进程（带重启次数限制）
    cat > "$CFG/watchdog.sh" << 'EOFSCRIPT'
#!/bin/bash
CFG="/etc/vless-reality"
LOG_FILE="/var/log/vless-watchdog.log"
MAX_RESTARTS=5           # 冷却期内最大重启次数
COOLDOWN_PERIOD=300      # 冷却期（秒）
declare -A restart_counts
declare -A first_restart_time

log() { 
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE"
    # 日志轮转：超过 2MB 时截断
    local size=$(stat -f%z "$LOG_FILE" 2>/dev/null || stat -c%s "$LOG_FILE" 2>/dev/null || echo 0)
    if [[ $size -gt 2097152 ]]; then
        tail -n 500 "$LOG_FILE" > "$LOG_FILE.tmp" && mv "$LOG_FILE.tmp" "$LOG_FILE"
    fi
}

restart_service() {
    local svc="$1"
    local now=$(date +%s)
    local first_time=${first_restart_time[$svc]:-0}
    local count=${restart_counts[$svc]:-0}
    
    # 检查是否在冷却期内
    if [[ $((now - first_time)) -gt $COOLDOWN_PERIOD ]]; then
        # 冷却期已过，重置计数
        restart_counts[$svc]=1
        first_restart_time[$svc]=$now
    else
        # 仍在冷却期内
        ((count++))
        restart_counts[$svc]=$count
        
        if [[ $count -gt $MAX_RESTARTS ]]; then
            log "ERROR: $svc 在 ${COOLDOWN_PERIOD}s 内重启次数超过 $MAX_RESTARTS 次，暂停监控该服务"
            return 1
        fi
    fi
    
    log "INFO: 正在重启 $svc (第 ${restart_counts[$svc]} 次)"
    
    if command -v systemctl >/dev/null 2>&1; then
        if systemctl restart "$svc" 2>&1; then
            log "OK: $svc 重启成功"
            return 0
        else
            log "ERROR: $svc 重启失败"
            return 1
        fi
    elif command -v rc-service >/dev/null 2>&1; then
        if rc-service "$svc" restart 2>&1; then
            log "OK: $svc 重启成功"
            return 0
        else
            log "ERROR: $svc 重启失败"
            return 1
        fi
    else
        log "ERROR: 无法找到服务管理命令"
        return 1
    fi
}

# 获取所有需要监控的服务 (支持多协议) - 从数据库读取
get_all_services() {
    local services=""
    local DB_FILE="$CFG/db.json"
    
    [[ ! -f "$DB_FILE" ]] && { echo ""; return; }
    
    # 检查 Xray 协议
    local xray_protos=$(jq -r '.xray | keys[]' "$DB_FILE" 2>/dev/null)
    [[ -n "$xray_protos" ]] && services+="vless-reality:xray "
    
    # 检查 Sing-box 协议 (hy2/tuic 由 vless-singbox 统一管理)
    local singbox_protos=$(jq -r '.singbox | keys[]' "$DB_FILE" 2>/dev/null)
    local has_singbox=false
    for proto in $singbox_protos; do
        case "$proto" in
            hy2|tuic) has_singbox=true ;;
            snell) services+="vless-snell:snell-server " ;;
            snell-v5) services+="vless-snell-v5:snell-server-v5 " ;;
            anytls) services+="vless-anytls:anytls-server " ;;
            snell-shadowtls) services+="vless-snell-shadowtls:shadow-tls " ;;
            snell-v5-shadowtls) services+="vless-snell-v5-shadowtls:shadow-tls " ;;
            ss2022-shadowtls) services+="vless-ss2022-shadowtls:shadow-tls " ;;
        esac
    done
    [[ "$has_singbox" == "true" ]] && services+="vless-singbox:sing-box "
    
    echo "$services"
}

log "INFO: Watchdog 启动"

while true; do
    for svc_info in $(get_all_services); do
        IFS=':' read -r svc_name proc_name <<< "$svc_info"
        # 多种方式检测进程 (使用兼容函数)
        if ! _pgrep "$proc_name" && ! pgrep -f "$proc_name" > /dev/null 2>&1; then
            log "CRITICAL: $proc_name 进程不存在，尝试重启 $svc_name..."
            restart_service "$svc_name"
            sleep 5
        fi
    done
    sleep 60
done
EOFSCRIPT

    # Hysteria2 端口跳跃规则脚本 (服务端) - 从数据库读取
    if is_protocol_installed "hy2"; then
        cat > "$CFG/hy2-nat.sh" << 'EOFSCRIPT'
#!/bin/bash
CFG=/etc/vless-reality
DB_FILE="$CFG/db.json"

[[ ! -f "$DB_FILE" ]] && exit 0

# 从数据库读取配置
port=$(jq -r '.singbox.hy2.port // empty' "$DB_FILE" 2>/dev/null)
hop_enable=$(jq -r '.singbox.hy2.hop_enable // empty' "$DB_FILE" 2>/dev/null)
hop_start=$(jq -r '.singbox.hy2.hop_start // empty' "$DB_FILE" 2>/dev/null)
hop_end=$(jq -r '.singbox.hy2.hop_end // empty' "$DB_FILE" 2>/dev/null)

[[ -z "$port" ]] && exit 0

hop_start="${hop_start:-20000}"
hop_end="${hop_end:-50000}"

if ! [[ "$hop_start" =~ ^[0-9]+$ && "$hop_end" =~ ^[0-9]+$ ]] || [[ "$hop_start" -ge "$hop_end" ]]; then
  exit 0
fi

iptables -t nat -D PREROUTING -p udp --dport ${hop_start}:${hop_end} -j REDIRECT --to-ports $port 2>/dev/null
iptables -t nat -D OUTPUT -p udp --dport ${hop_start}:${hop_end} -j REDIRECT --to-ports $port 2>/dev/null

[[ "${hop_enable:-0}" != "1" ]] && exit 0

iptables -t nat -C PREROUTING -p udp --dport ${hop_start}:${hop_end} -j REDIRECT --to-ports $port 2>/dev/null \
  || iptables -t nat -A PREROUTING -p udp --dport ${hop_start}:${hop_end} -j REDIRECT --to-ports $port

iptables -t nat -C OUTPUT -p udp --dport ${hop_start}:${hop_end} -j REDIRECT --to-ports $port 2>/dev/null \
  || iptables -t nat -A OUTPUT -p udp --dport ${hop_start}:${hop_end} -j REDIRECT --to-ports $port
EOFSCRIPT
    fi

    # TUIC 端口跳跃规则脚本 (服务端) - 从数据库读取
    if is_protocol_installed "tuic"; then
        cat > "$CFG/tuic-nat.sh" << 'EOFSCRIPT'
#!/bin/bash
CFG=/etc/vless-reality
DB_FILE="$CFG/db.json"

[[ ! -f "$DB_FILE" ]] && exit 0

# 从数据库读取配置
port=$(jq -r '.singbox.tuic.port // empty' "$DB_FILE" 2>/dev/null)
hop_enable=$(jq -r '.singbox.tuic.hop_enable // empty' "$DB_FILE" 2>/dev/null)
hop_start=$(jq -r '.singbox.tuic.hop_start // empty' "$DB_FILE" 2>/dev/null)
hop_end=$(jq -r '.singbox.tuic.hop_end // empty' "$DB_FILE" 2>/dev/null)

[[ -z "$port" ]] && exit 0

hop_start="${hop_start:-20000}"
hop_end="${hop_end:-50000}"

if ! [[ "$hop_start" =~ ^[0-9]+$ && "$hop_end" =~ ^[0-9]+$ ]] || [[ "$hop_start" -ge "$hop_end" ]]; then
  exit 0
fi

iptables -t nat -D PREROUTING -p udp --dport ${hop_start}:${hop_end} -j REDIRECT --to-ports $port 2>/dev/null
iptables -t nat -D OUTPUT -p udp --dport ${hop_start}:${hop_end} -j REDIRECT --to-ports $port 2>/dev/null

[[ "${hop_enable:-0}" != "1" ]] && exit 0

iptables -t nat -C PREROUTING -p udp --dport ${hop_start}:${hop_end} -j REDIRECT --to-ports $port 2>/dev/null \
  || iptables -t nat -A PREROUTING -p udp --dport ${hop_start}:${hop_end} -j REDIRECT --to-ports $port

iptables -t nat -C OUTPUT -p udp --dport ${hop_start}:${hop_end} -j REDIRECT --to-ports $port 2>/dev/null \
  || iptables -t nat -A OUTPUT -p udp --dport ${hop_start}:${hop_end} -j REDIRECT --to-ports $port
EOFSCRIPT
    fi

    chmod +x "$CFG"/*.sh 2>/dev/null
}

#═══════════════════════════════════════════════════════════════════════════════
# 服务管理
#═══════════════════════════════════════════════════════════════════════════════
create_service() {
    local protocol="${1:-$(get_protocol)}"
    local kind="${PROTO_KIND[$protocol]:-}"
    local service_name="${PROTO_SVC[$protocol]:-}"
    local exec_cmd="${PROTO_EXEC[$protocol]:-}"
    local exec_name="${PROTO_BIN[$protocol]:-}"
    local port password sni stls_password ss_backend_port snell_backend_port

    [[ -z "$service_name" ]] && { _err "未知协议: $protocol"; return 1; }

    _need_cfg() { db_exists "singbox" "$1" || { _err "$2 配置不存在"; return 1; }; }

    case "$kind" in
        anytls)
            _need_cfg "anytls" "AnyTLS" || return 1
            port=$(db_get_field "singbox" "anytls" "port")
            password=$(db_get_field "singbox" "anytls" "password")
            exec_cmd="/usr/local/bin/anytls-server -l [::]:${port} -p ${password}"
            exec_name="anytls-server"
            ;;
        naive)
            _need_cfg "naive" "NaïveProxy" || return 1
            exec_cmd="/usr/local/bin/caddy run --config $CFG/Caddyfile"
            exec_name="caddy"
            ;;
        shadowtls)
            _need_cfg "$protocol" "$protocol" || return 1
            port=$(db_get_field "singbox" "$protocol" "port")
            sni=$(db_get_field "singbox" "$protocol" "sni")
            stls_password=$(db_get_field "singbox" "$protocol" "stls_password")
            if [[ "$protocol" == "ss2022-shadowtls" ]]; then
                ss_backend_port=$(db_get_field "singbox" "$protocol" "ss_backend_port")
            else
                snell_backend_port=$(db_get_field "singbox" "$protocol" "snell_backend_port")
            fi
            exec_cmd="/usr/local/bin/shadow-tls --v3 server --listen [::]:${port} --server 127.0.0.1:${ss_backend_port:-$snell_backend_port} --tls ${sni}:443 --password ${stls_password}"
            exec_name="shadow-tls"
            ;;
    esac

    _write_openrc() { # name desc cmd args
        local name="$1" desc="$2" cmd="$3" args="$4"
        cat >"/etc/init.d/${name}" <<EOF
#!/sbin/openrc-run
name="${desc}"
command="${cmd}"
command_args="${args}"
command_background="yes"
pidfile="/run/${name}.pid"
depend() { need net; }
EOF
        chmod +x "/etc/init.d/${name}"
    }

    _write_systemd() { # name desc exec pre before env
        local name="$1" desc="$2" exec="$3" pre="$4" before="$5" env="$6"
        cat >"/etc/systemd/system/${name}.service" <<EOF
[Unit]
Description=${desc}
After=network.target
${before:+Before=${before}}

[Service]
Type=simple
${env:+Environment=${env}}
${pre:+ExecStartPre=${pre}}
ExecStart=${exec}
Restart=always
RestartSec=3
LimitNOFILE=51200

[Install]
WantedBy=multi-user.target
EOF
    }

    if [[ "$DISTRO" == "alpine" ]]; then
        local cmd="${exec_cmd%% *}" args=""; [[ "$exec_cmd" == *" "* ]] && args="${exec_cmd#* }"
        _write_openrc "$service_name" "Proxy Server ($protocol)" "$cmd" "$args"

        if [[ "$kind" == "shadowtls" ]]; then
            _write_openrc "${BACKEND_NAME[$protocol]}" "${BACKEND_DESC[$protocol]}" "${BACKEND_EXEC[$protocol]%% *}" "${BACKEND_EXEC[$protocol]#* }"
        fi

        _write_openrc "vless-watchdog" "VLESS Watchdog" "/bin/bash" "$CFG/watchdog.sh"
    else
        local pre="" env=""
        [[ "$kind" == "hy2" ]] && pre="-/bin/bash $CFG/hy2-nat.sh"
        # ShadowTLS CPU 100% 修复: 高版本内核 io_uring 问题
        [[ "$kind" == "shadowtls" ]] && env="MONOIO_FORCE_LEGACY_DRIVER=1"
        _write_systemd "$service_name" "Proxy Server ($protocol)" "$exec_cmd" "$pre" "" "$env"

        if [[ "$kind" == "shadowtls" ]]; then
            _write_systemd "${BACKEND_NAME[$protocol]}" "${BACKEND_DESC[$protocol]}" "${BACKEND_EXEC[$protocol]}" "" "${service_name}.service" ""
        fi

        cat > /etc/systemd/system/vless-watchdog.service << EOF
[Unit]
Description=VLESS Watchdog
After=${service_name}.service

[Service]
Type=simple
ExecStart=$CFG/watchdog.sh
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
    fi
}



svc() { # svc action service_name
    local action="$1" name="$2" err=/tmp/svc_error.log
    _svc_try() { : >"$err"; "$@" 2>"$err" || { [[ -s "$err" ]] && { _err "服务${action}失败:"; cat "$err"; }; rm -f "$err"; return 1; }; rm -f "$err"; }

    if [[ "$DISTRO" == "alpine" ]]; then
        case "$action" in
            start|restart) _svc_try rc-service "$name" "$action" ;;
            stop)    rc-service "$name" stop &>/dev/null ;;
            enable)  rc-update add "$name" default &>/dev/null ;;
            disable) rc-update del "$name" default &>/dev/null ;;
            reload)  rc-service "$name" reload &>/dev/null || rc-service "$name" restart &>/dev/null ;;
            status)
                rc-service "$name" status &>/dev/null && return 0
                local pidfile="/run/${name}.pid"
                [[ -f "$pidfile" ]] && kill -0 "$(cat "$pidfile" 2>/dev/null)" 2>/dev/null && return 0
                local p="${SVC_PROC[$name]:-}"
                [[ -n "$p" ]] && _pgrep "$p" && return 0
                return 1
                ;;
        esac
    else
        case "$action" in
            start|restart)
                _svc_try systemctl "$action" "$name" || { _err "详细状态信息:"; systemctl status "$name" --no-pager -l || true; return 1; }
                ;;
            stop|enable|disable) systemctl "$action" "$name" &>/dev/null ;;
            reload) systemctl reload "$name" &>/dev/null || systemctl restart "$name" &>/dev/null ;;
            status)
                local state; state=$(systemctl is-active "$name" 2>/dev/null)
                [[ "$state" == active || "$state" == activating ]]
                ;;
        esac
    fi
}



start_services() {
    local failed_services=()
    rm -f "$CFG/paused"
    
    # 初始化数据库
    init_db
    
    # 服务端：启动所有已注册的协议服务
    
    # 1. 启动 Xray 服务（TCP 协议）
    local xray_protocols=$(get_xray_protocols)
    if [[ -n "$xray_protocols" ]]; then
        if svc status vless-reality >/dev/null 2>&1; then
            _info "更新 Xray 配置..."
            if ! generate_xray_config; then
                _err "Xray 配置生成失败"
                failed_services+=("vless-reality")
            else
                if ! svc restart vless-reality; then
                    _err "Xray 服务重启失败"
                    failed_services+=("vless-reality")
                else
                    # Alpine OpenRC 重启较慢，等待进程启动
                    local wait_count=0
                    local max_wait=5
                    while [[ $wait_count -lt $max_wait ]]; do
                        if _pgrep xray; then
                            local xray_list=$(echo $xray_protocols | tr '\n' ' ')
                            _ok "Xray 服务已更新 (协议: $xray_list)"
                            break
                        fi
                        sleep 1
                        ((wait_count++))
                    done
                    if [[ $wait_count -ge $max_wait ]] && ! _pgrep xray; then
                        _err "Xray 进程未运行"
                        failed_services+=("vless-reality")
                    fi
                fi
            fi
        else
            if ! generate_xray_config; then
                _err "Xray 配置生成失败"
                failed_services+=("vless-reality")
            else
                svc enable vless-reality
                if ! svc start vless-reality; then
                    _err "Xray 服务启动失败"
                    failed_services+=("vless-reality")
                else
                    # Alpine OpenRC 启动较慢，等待进程启动
                    local wait_count=0
                    local max_wait=10
                    while [[ $wait_count -lt $max_wait ]]; do
                        if _pgrep xray; then
                            local xray_list=$(echo $xray_protocols | tr '\n' ' ')
                            _ok "Xray 服务已启动 (协议: $xray_list)"
                            break
                        fi
                        sleep 1
                        ((wait_count++))
                    done
                    if [[ $wait_count -ge $max_wait ]] && ! _pgrep xray; then
                        _err "Xray 进程未运行"
                        failed_services+=("vless-reality")
                    fi
                fi
            fi
        fi
    fi
    
    # 2. 启动 Sing-box 服务（UDP/QUIC 协议: Hy2/TUIC）
    local singbox_protocols=$(get_singbox_protocols)
    if [[ -n "$singbox_protocols" ]]; then
        # 确保 Sing-box 已安装
        if ! check_cmd sing-box; then
            _info "安装 Sing-box..."
            install_singbox || { _err "Sing-box 安装失败"; failed_services+=("vless-singbox"); }
        fi
        
        if check_cmd sing-box; then
            _info "生成 Sing-box 配置..."
            if generate_singbox_config; then
                create_singbox_service
                svc enable vless-singbox 2>/dev/null
                
                if svc status vless-singbox >/dev/null 2>&1; then
                    if ! svc restart vless-singbox; then
                        _err "Sing-box 服务重启失败"
                        failed_services+=("vless-singbox")
                    else
                        sleep 2
                        if _pgrep sing-box; then
                            local sb_list=$(echo $singbox_protocols | tr '\n' ' ')
                            _ok "Sing-box 服务已更新 (协议: $sb_list)"
                        else
                            _err "Sing-box 进程未运行"
                            failed_services+=("vless-singbox")
                        fi
                    fi
                else
                    if ! svc start vless-singbox; then
                        _err "Sing-box 服务启动失败"
                        failed_services+=("vless-singbox")
                    else
                        sleep 2
                        if _pgrep sing-box; then
                            local sb_list=$(echo $singbox_protocols | tr '\n' ' ')
                            _ok "Sing-box 服务已启动 (协议: $sb_list)"
                        else
                            _err "Sing-box 进程未运行"
                            failed_services+=("vless-singbox")
                        fi
                    fi
                fi
            else
                _err "Sing-box 配置生成失败"
                failed_services+=("vless-singbox")
            fi
        fi
    fi
    
    # 3. 启动独立进程协议 (Snell 等闭源协议)
    local standalone_protocols=$(get_standalone_protocols)
    local ind_proto
    for ind_proto in $standalone_protocols; do
        local service_name="vless-${ind_proto}"
        
        # ShadowTLS 组合协议需要先启动/重启后端服务
        if [[ "$ind_proto" == "snell-shadowtls" ]]; then
            svc enable "vless-snell-shadowtls-backend"
            if svc status "vless-snell-shadowtls-backend" >/dev/null 2>&1; then
                svc restart "vless-snell-shadowtls-backend" || true
            else
                if ! svc start "vless-snell-shadowtls-backend"; then
                    _err "Snell+ShadowTLS 后端服务启动失败"
                    failed_services+=("vless-snell-shadowtls-backend")
                    continue
                fi
            fi
            sleep 1
        elif [[ "$ind_proto" == "snell-v5-shadowtls" ]]; then
            svc enable "vless-snell-v5-shadowtls-backend"
            if svc status "vless-snell-v5-shadowtls-backend" >/dev/null 2>&1; then
                svc restart "vless-snell-v5-shadowtls-backend" || true
            else
                if ! svc start "vless-snell-v5-shadowtls-backend"; then
                    _err "Snell v5+ShadowTLS 后端服务启动失败"
                    failed_services+=("vless-snell-v5-shadowtls-backend")
                    continue
                fi
            fi
            sleep 1
        elif [[ "$ind_proto" == "ss2022-shadowtls" ]]; then
            svc enable "vless-ss2022-shadowtls-backend"
            if svc status "vless-ss2022-shadowtls-backend" >/dev/null 2>&1; then
                svc restart "vless-ss2022-shadowtls-backend" || true
            else
                if ! svc start "vless-ss2022-shadowtls-backend"; then
                    _err "SS2022+ShadowTLS 后端服务启动失败"
                    failed_services+=("vless-ss2022-shadowtls-backend")
                    continue
                fi
            fi
            sleep 1
        fi
        
        svc enable "$service_name"
        
        if svc status "$service_name" >/dev/null 2>&1; then
            # 服务已在运行，需要重启以加载新配置
            _info "重启 $ind_proto 服务以加载新配置..."
            if ! svc restart "$service_name"; then
                _err "$ind_proto 服务重启失败"
                failed_services+=("$service_name")
            else
                sleep 1
                _ok "$ind_proto 服务已重启"
            fi
        else
            if ! svc start "$service_name"; then
                _err "$ind_proto 服务启动失败"
                failed_services+=("$service_name")
            else
                sleep 1
                _ok "$ind_proto 服务已启动"
            fi
        fi
    done
    
    # 启动 Watchdog
    svc enable vless-watchdog 2>/dev/null
    svc start vless-watchdog 2>/dev/null
    
    if [[ ${#failed_services[@]} -gt 0 ]]; then
        _warn "以下服务启动失败: ${failed_services[*]}"
        return 1
    fi
    
    return 0
}

stop_services() {
    local stopped_services=()
    
    is_service_active() {
        local svc_name="$1"
        if [[ "$DISTRO" == "alpine" ]]; then
            rc-service "$svc_name" status &>/dev/null
        else
            systemctl is-active --quiet "$svc_name" 2>/dev/null
        fi
    }
    
    # 停止 Watchdog
    if is_service_active vless-watchdog; then
        svc stop vless-watchdog 2>/dev/null && stopped_services+=("vless-watchdog")
    fi
    
    # 停止 Xray 服务
    if is_service_active vless-reality; then
        svc stop vless-reality 2>/dev/null && stopped_services+=("vless-reality")
    fi
    
    # 停止 Sing-box 服务 (Hy2/TUIC)
    if is_service_active vless-singbox; then
        svc stop vless-singbox 2>/dev/null && stopped_services+=("vless-singbox")
    fi
    
    # 停止独立进程协议服务 (Snell 等)
    for proto in $STANDALONE_PROTOCOLS; do
        local service_name="vless-${proto}"
        if is_service_active "$service_name"; then
            svc stop "$service_name" 2>/dev/null && stopped_services+=("$service_name")
        fi
    done
    
    # 停止 ShadowTLS 组合协议的后端服务
    for backend_svc in vless-snell-shadowtls-backend vless-snell-v5-shadowtls-backend vless-ss2022-shadowtls-backend; do
        if is_service_active "$backend_svc"; then
            svc stop "$backend_svc" 2>/dev/null && stopped_services+=("$backend_svc")
        fi
    done
    
    # 清理 Hysteria2 端口跳跃 NAT 规则
    cleanup_hy2_nat_rules
    
    if [[ ${#stopped_services[@]} -gt 0 ]]; then
        echo "  ▸ 已停止服务: ${stopped_services[*]}"
    else
        echo "  ▸ 没有运行中的服务需要停止"
    fi
}

# 自动更新系统脚本 (启动时检测)
_auto_update_system_script() {
    local system_script="/usr/local/bin/vless-server.sh"
    local current_script="$0"
    
    # 获取当前脚本的绝对路径
    local real_path=""
    if [[ "$current_script" == /* ]]; then
        real_path="$current_script"
    elif [[ "$current_script" != "bash" && "$current_script" != "-bash" && -f "$current_script" ]]; then
        real_path="$(cd "$(dirname "$current_script")" 2>/dev/null && pwd)/$(basename "$current_script")"
    fi
    
    # 如果当前脚本不是系统脚本，检查是否需要更新
    if [[ -n "$real_path" && -f "$real_path" && "$real_path" != "$system_script" ]]; then
        local need_update=false
        
        if [[ ! -f "$system_script" ]]; then
            need_update=true
        else
            # 用 md5 校验文件内容是否不同
            local cur_md5 sys_md5
            cur_md5=$(md5sum "$real_path" 2>/dev/null | cut -d' ' -f1)
            sys_md5=$(md5sum "$system_script" 2>/dev/null | cut -d' ' -f1)
            [[ "$cur_md5" != "$sys_md5" ]] && need_update=true
        fi
        
        if [[ "$need_update" == "true" ]]; then
            cp -f "$real_path" "$system_script" 2>/dev/null
            chmod +x "$system_script" 2>/dev/null
            ln -sf "$system_script" /usr/local/bin/vless 2>/dev/null
            ln -sf "$system_script" /usr/bin/vless 2>/dev/null
            hash -r 2>/dev/null
            _ok "系统脚本已同步更新 (v$VERSION)"
        fi
    fi
}

create_shortcut() {
    local system_script="/usr/local/bin/vless-server.sh"
    local current_script="$0"

    # 获取当前脚本的绝对路径
    local real_path
    if [[ "$current_script" == /* ]]; then
        real_path="$current_script"
    elif [[ "$current_script" == "bash" || "$current_script" == "-bash" ]]; then
        # 内存运行模式 (curl | bash)，从网络下载
        real_path=""
    else
        real_path="$(cd "$(dirname "$current_script")" 2>/dev/null && pwd)/$(basename "$current_script")"
    fi

    # 如果系统目录没有脚本，需要创建
    if [[ ! -f "$system_script" ]]; then
        if [[ -n "$real_path" && -f "$real_path" ]]; then
            # 从当前脚本复制（不删除原文件）
            cp -f "$real_path" "$system_script"
        else
            # 内存运行模式，从网络下载
            local raw_url="https://raw.githubusercontent.com/Chil30/vless-all-in-one/main/vless-server.sh"
            if ! curl -sL --connect-timeout 10 -o "$system_script" "$raw_url"; then
                _warn "无法下载脚本到系统目录"
                return 1
            fi
        fi
    elif [[ -n "$real_path" && -f "$real_path" && "$real_path" != "$system_script" ]]; then
        # 系统目录已有脚本，用当前脚本更新（不删除原文件）
        cp -f "$real_path" "$system_script"
    fi

    chmod +x "$system_script" 2>/dev/null

    # 创建软链接
    ln -sf "$system_script" /usr/local/bin/vless 2>/dev/null
    ln -sf "$system_script" /usr/bin/vless 2>/dev/null
    hash -r 2>/dev/null

    _ok "快捷命令已创建: vless"
}

remove_shortcut() { 
    rm -f /usr/local/bin/vless /usr/local/bin/vless-server.sh /usr/bin/vless 2>/dev/null
    _ok "快捷命令已移除"
}


#═══════════════════════════════════════════════════════════════════════════════
# 分流管理 (WARP + 路由规则) - 双模式支持
# 模式 1: WGCF (Xray 内置 WireGuard) - UDP 协议，性能好但可能被封锁
# 模式 2: 官方客户端 (SOCKS5 代理) - TCP 协议，绕过 UDP 封锁
#═══════════════════════════════════════════════════════════════════════════════

# WARP 配置存储路径
WARP_CONF_FILE="$CFG/warp.json"
WARP_OFFICIAL_PORT=40000  # 官方客户端 SOCKS5 端口

# 保存 WARP 模式到数据库 (wgcf 或 official)
db_set_warp_mode() {
    local mode="$1"
    [[ ! -f "$DB_FILE" ]] && init_db
    local tmp=$(mktemp)
    jq --arg m "$mode" '.routing.warp_mode = $m' "$DB_FILE" > "$tmp" && mv "$tmp" "$DB_FILE"
}

# 获取 WARP 模式
db_get_warp_mode() {
    [[ ! -f "$DB_FILE" ]] && echo "wgcf" && return
    local mode=$(jq -r '.routing.warp_mode // "wgcf"' "$DB_FILE" 2>/dev/null)
    echo "$mode"
}

# WARP 状态检测 (支持双模式)
warp_status() {
    local mode=$(db_get_warp_mode)
    
    if [[ "$mode" == "official" ]]; then
        # 检查官方客户端状态
        if check_cmd warp-cli; then
            local status_output=$(warp-cli status 2>/dev/null)
            if echo "$status_output" | grep -qiE "Connected|Status:.*Connected"; then
                echo "connected"
                return
            elif echo "$status_output" | grep -qiE "Registration|Account|Disconnected|Status:"; then
                echo "registered"
                return
            fi
        fi
        echo "not_configured"
    else
        # 检查 WGCF 配置
        if [[ -f "$WARP_CONF_FILE" ]]; then
            local private_key=$(jq -r '.private_key // empty' "$WARP_CONF_FILE" 2>/dev/null)
            if [[ -n "$private_key" ]]; then
                echo "configured"
                return
            fi
        fi
        echo "not_configured"
    fi
}

# 下载 wgcf 工具
download_wgcf() {
    # 检查是否已存在有效的 wgcf
    if [[ -x /usr/local/bin/wgcf ]]; then
        if file /usr/local/bin/wgcf 2>/dev/null | grep -q "ELF"; then
            return 0
        fi
    fi
    
    local arch=$(uname -m)
    local wgcf_arch="amd64"
    [[ "$arch" == "aarch64" ]] && wgcf_arch="arm64"
    [[ "$arch" == "armv7l" ]] && wgcf_arch="armv7"
    
    # 自动获取最新版本
    echo -ne "  ${C}▸${NC} 获取 wgcf 最新版本..."
    local wgcf_ver=$(curl -sL --connect-timeout 10 "https://api.github.com/repos/ViRb3/wgcf/releases/latest" | jq -r '.tag_name' 2>/dev/null | tr -d 'v')
    [[ -z "$wgcf_ver" || "$wgcf_ver" == "null" ]] && wgcf_ver="2.2.29"
    echo -e " v${wgcf_ver}"
    
    local wgcf_urls=(
        "https://github.com/ViRb3/wgcf/releases/download/v${wgcf_ver}/wgcf_${wgcf_ver}_linux_${wgcf_arch}"
        "https://mirror.ghproxy.com/https://github.com/ViRb3/wgcf/releases/download/v${wgcf_ver}/wgcf_${wgcf_ver}_linux_${wgcf_arch}"
        "https://gh-proxy.com/https://github.com/ViRb3/wgcf/releases/download/v${wgcf_ver}/wgcf_${wgcf_ver}_linux_${wgcf_arch}"
    )
    
    rm -f /usr/local/bin/wgcf
    local try_num=1
    for url in "${wgcf_urls[@]}"; do
        echo -ne "  ${C}▸${NC} 下载 wgcf (尝试 $try_num/3)..."
        if curl -fL -o /usr/local/bin/wgcf "$url" --connect-timeout 30 --max-time 120 2>/dev/null; then
            if [[ -s /usr/local/bin/wgcf ]] && file /usr/local/bin/wgcf 2>/dev/null | grep -q "ELF"; then
                chmod +x /usr/local/bin/wgcf
                echo -e " ${G}✓${NC}"
                return 0
            fi
        fi
        echo -e " ${R}✗${NC}"
        rm -f /usr/local/bin/wgcf
        ((try_num++))
    done
    
    _err "wgcf 下载失败"
    return 1
}

# 注册 WARP 账号并获取 WireGuard 配置
register_warp() {
    _info "注册 Cloudflare WARP 账号..."
    
    if ! download_wgcf; then
        _err "wgcf 下载失败，无法注册 WARP"
        return 1
    fi
    
    cd /tmp
    rm -f /tmp/wgcf-account.toml /tmp/wgcf-profile.conf 2>/dev/null
    
    # 注册 WARP 账户
    echo -ne "  ${C}▸${NC} 注册 WARP 账户..."
    local register_output
    register_output=$(/usr/local/bin/wgcf register --accept-tos 2>&1)
    local register_ret=$?
    
    if [[ $register_ret -ne 0 ]] || [[ ! -f /tmp/wgcf-account.toml ]]; then
        echo -e " ${R}✗${NC}"
        _err "WARP 账户注册失败"
        [[ -n "$register_output" ]] && echo -e "  ${D}$register_output${NC}"
        return 1
    fi
    echo -e " ${G}✓${NC}"
    
    # 生成 WireGuard 配置
    echo -ne "  ${C}▸${NC} 生成 WireGuard 配置..."
    local generate_output
    generate_output=$(/usr/local/bin/wgcf generate 2>&1)
    local generate_ret=$?
    
    if [[ $generate_ret -ne 0 ]] || [[ ! -f /tmp/wgcf-profile.conf ]]; then
        echo -e " ${R}✗${NC}"
        _err "配置生成失败"
        [[ -n "$generate_output" ]] && echo -e "  ${D}$generate_output${NC}"
        return 1
    fi
    echo -e " ${G}✓${NC}"
    
    # 解析配置并保存到 JSON
    echo -ne "  ${C}▸${NC} 保存配置..."
    parse_and_save_warp_config /tmp/wgcf-profile.conf
    rm -f /tmp/wgcf-account.toml /tmp/wgcf-profile.conf
    echo -e " ${G}✓${NC}"
    
    # 显示配置信息
    echo ""
    _line
    echo -e "  ${G}WGCF 配置成功${NC}"
    _line
    local endpoint=$(jq -r '.endpoint' "$WARP_CONF_FILE" 2>/dev/null)
    local address_v4=$(jq -r '.address_v4' "$WARP_CONF_FILE" 2>/dev/null)
    local address_v6=$(jq -r '.address_v6' "$WARP_CONF_FILE" 2>/dev/null)
    echo -e "  WARP 端点: ${C}${endpoint}${NC}"
    echo -e "  内网 IPv4: ${G}${address_v4}${NC}"
    echo -e "  内网 IPv6: ${D}${address_v6}${NC}"
    _line
    
    return 0
}

# 解析 wgcf 生成的配置并保存为 JSON
parse_and_save_warp_config() {
    local conf_file="$1"
    
    local private_key=$(grep "PrivateKey" "$conf_file" | cut -d'=' -f2 | tr -d ' ')
    local public_key=$(grep "PublicKey" "$conf_file" | cut -d'=' -f2 | tr -d ' ')
    local endpoint=$(grep "Endpoint" "$conf_file" | cut -d'=' -f2 | tr -d ' ')
    
    # 解析 Address 行，可能有多行或逗号分隔
    local addresses=$(grep "Address" "$conf_file" | cut -d'=' -f2 | tr -d ' ' | tr '\n' ',' | sed 's/,$//')
    
    # 分离 IPv4 和 IPv6
    local address_v4=""
    local address_v6=""
    
    IFS=',' read -ra ADDR_ARRAY <<< "$addresses"
    for addr in "${ADDR_ARRAY[@]}"; do
        if [[ "$addr" == *":"* ]]; then
            # IPv6 地址
            address_v6="$addr"
        else
            # IPv4 地址
            address_v4="$addr"
        fi
    done
    
    mkdir -p "$CFG"
    jq -n \
        --arg pk "$private_key" \
        --arg pub "$public_key" \
        --arg v4 "$address_v4" \
        --arg v6 "$address_v6" \
        --arg ep "$endpoint" \
    '{
        private_key: $pk,
        public_key: $pub,
        address_v4: $v4,
        address_v6: $v6,
        endpoint: $ep,
        reserved: [0, 0, 0]
    }' > "$WARP_CONF_FILE"
}

# 生成 Xray WARP outbound 配置 (支持 WireGuard 和 SOCKS5 双模式)
gen_xray_warp_outbound() {
    local warp_mode=$(db_get_warp_mode)
    
    [[ -z "$warp_mode" || "$warp_mode" == "disabled" ]] && return
    
    # === 模式 A: 官方客户端 (SOCKS5) ===
    if [[ "$warp_mode" == "official" ]]; then
        # 检查官方客户端是否运行
        if ! check_cmd warp-cli; then
            return
        fi
        if ! warp-cli status 2>/dev/null | grep -qi "Connected"; then
            return
        fi
        
        # 生成指向本地 SOCKS5 端口的出站
        jq -n --argjson port "$WARP_OFFICIAL_PORT" '{
            tag: "warp",
            protocol: "socks",
            settings: {
                servers: [{
                    address: "127.0.0.1",
                    port: $port
                }]
            }
        }'
        return
    fi
    
    # === 模式 B: WGCF (WireGuard) ===
    [[ "$warp_mode" != "wgcf" ]] && return
    [[ ! -f "$WARP_CONF_FILE" ]] && return
    
    local private_key=$(jq -r '.private_key' "$WARP_CONF_FILE")
    local public_key=$(jq -r '.public_key' "$WARP_CONF_FILE")
    local address_v4=$(jq -r '.address_v4' "$WARP_CONF_FILE" | cut -d'/' -f1)
    local address_v6=$(jq -r '.address_v6' "$WARP_CONF_FILE" | cut -d'/' -f1)
    local endpoint=$(jq -r '.endpoint' "$WARP_CONF_FILE")
    local ep_host=$(echo "$endpoint" | cut -d':' -f1)
    local ep_port=$(echo "$endpoint" | cut -d':' -f2)
    
    jq -n \
        --arg pk "$private_key" \
        --arg pub "$public_key" \
        --arg v4 "$address_v4" \
        --arg v6 "$address_v6" \
        --arg host "$ep_host" \
        --argjson port "$ep_port" \
    '{
        tag: "warp",
        protocol: "wireguard",
        settings: {
            secretKey: $pk,
            address: [$v4, $v6],
            peers: [{
                publicKey: $pub,
                allowedIPs: ["0.0.0.0/0", "::/0"],
                endpoint: "\($host):\($port)"
            }],
            mtu: 1280
        }
    }'
}

# 测试 WARP 连接 (支持双模式)
test_warp_connection() {
    local warp_mode=$(db_get_warp_mode)
    _info "测试 WARP 连接..."
    
    if [[ "$warp_mode" == "official" ]]; then
        # 测试官方客户端
        if ! check_cmd warp-cli; then
            _warn "WARP 官方客户端未安装"
            return 1
        fi
        
        local status=$(warp-cli status 2>/dev/null)
        if echo "$status" | grep -qi "Connected"; then
            _ok "WARP 官方客户端已连接"
            echo -e "  模式: ${G}TCP/SOCKS5${NC} (端口 $WARP_OFFICIAL_PORT)"
            
            # 通过 SOCKS5 代理测试出口 IP (多源重试)
            echo -ne "  获取出口 IP..."
            local warp_ip=""
            local ip_apis=("https://api.ipify.org" "https://ifconfig.me" "https://ip.sb")
            for api in "${ip_apis[@]}"; do
                warp_ip=$(curl -s --connect-timeout 8 --max-time 12 --socks5 127.0.0.1:$WARP_OFFICIAL_PORT "$api" 2>/dev/null | grep -oE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -1)
                [[ -n "$warp_ip" ]] && break
            done
            if [[ -n "$warp_ip" ]]; then
                echo -e " ${G}${warp_ip}${NC}"
            else
                echo -e " ${Y}获取超时${NC}"
            fi
        else
            _warn "WARP 官方客户端未连接"
            echo -e "  ${D}状态: ${status}${NC}"
            return 1
        fi
    else
        # 测试 WGCF 配置
        if [[ ! -f "$WARP_CONF_FILE" ]]; then
            _warn "WARP (WGCF) 未配置"
            return 1
        fi
        
        echo -e "  模式: ${C}UDP/WireGuard${NC} (Xray 内置)"
        
        local endpoint=$(jq -r '.endpoint // "N/A"' "$WARP_CONF_FILE" 2>/dev/null)
        local address=$(jq -r '.address_v4 // "N/A"' "$WARP_CONF_FILE" 2>/dev/null)
        echo -e "  WARP 端点: ${G}${endpoint}${NC}"
        echo -e "  WARP 内网: ${D}${address}${NC}"
        
        _ok "WARP (WGCF) 配置已就绪"
    fi
    
    # 检查是否有分流规则
    local rules=$(db_get_routing_rules)
    if [[ -z "$rules" || "$rules" == "[]" ]]; then
        _warn "未配置分流规则，WARP 不会生效"
        echo -e "  ${D}请先配置分流规则${NC}"
        return 1
    fi
    
    # 获取直连 IP
    local direct_ip=$(curl -s --connect-timeout 5 https://api.ipify.org 2>/dev/null)
    echo -e "  直连出口 IP: ${C}${direct_ip:-获取失败}${NC}"
    
    echo ""
    echo -e "  ${Y}验证方法:${NC} 手机连接代理后访问 https://ip.sb"
    echo -e "  ${D}如果显示的 IP 不是 ${direct_ip}，说明 WARP 生效${NC}"
    
    return 0
}

# 重新获取 WARP IP (WGCF 模式)
refresh_warp_wgcf() {
    _info "重新获取 WARP (WGCF) 配置..."
    
    # 删除旧配置
    rm -f "$WARP_CONF_FILE"
    rm -f /usr/local/bin/wgcf
    rm -f ~/.wgcf-account.toml 2>/dev/null
    
    # 重新注册
    if register_warp; then
        db_set_warp_mode "wgcf"
        _regenerate_proxy_configs
        _ok "WARP (WGCF) 配置已更新"
        return 0
    fi
    return 1
}

# ==============================================================================
# WARP 官方客户端支持 (解决 UDP 封锁问题)
# ==============================================================================

# 安装 Cloudflare WARP 官方客户端
install_warp_official() {
    echo ""
    echo -e "  ${C}安装 WARP 官方客户端${NC}"
    _line
    
    # Alpine 不支持官方客户端 (依赖 glibc)
    if [[ "$DISTRO" == "alpine" ]]; then
        _err "Alpine 系统不支持 WARP 官方客户端 (依赖 glibc)"
        _info "请使用 WGCF 模式"
        return 1
    fi
    
    # 检查是否已安装
    if check_cmd warp-cli; then
        echo -e "  ${C}▸${NC} WARP 客户端已安装 ${G}✓${NC}"
        return 0
    fi
    
    # 检查架构
    local arch=$(uname -m)
    if [[ "$arch" != "x86_64" && "$arch" != "aarch64" ]]; then
        _err "WARP 官方客户端仅支持 x86_64 和 arm64 架构"
        return 1
    fi
    
    echo -ne "  ${C}▸${NC} 添加 Cloudflare 软件源..."
    
    if [[ "$DISTRO" == "ubuntu" || "$DISTRO" == "debian" ]]; then
        # 安装依赖
        apt-get update -qq >/dev/null 2>&1
        apt-get install -y -qq curl gnupg lsb-release >/dev/null 2>&1
        
        # 添加 GPG 密钥
        curl -fsSL https://pkg.cloudflareclient.com/pubkey.gpg 2>/dev/null | gpg --yes --dearmor --output /usr/share/keyrings/cloudflare-warp-archive-keyring.gpg 2>/dev/null
        
        # 获取发行版代号
        local codename=""
        if check_cmd lsb_release; then
            codename=$(lsb_release -cs 2>/dev/null)
        else
            codename=$(grep VERSION_CODENAME /etc/os-release 2>/dev/null | cut -d'=' -f2)
        fi
        
        # 某些新版本可能没有对应的源，回退到较新的稳定版
        case "$codename" in
            bookworm|trixie|sid) codename="bookworm" ;;
            noble|oracular) codename="jammy" ;;
        esac
        
        [[ -z "$codename" ]] && codename="jammy"
        
        echo "deb [arch=amd64,arm64 signed-by=/usr/share/keyrings/cloudflare-warp-archive-keyring.gpg] https://pkg.cloudflareclient.com/ $codename main" | tee /etc/apt/sources.list.d/cloudflare-client.list >/dev/null
        echo -e " ${G}✓${NC}"
        
        echo -ne "  ${C}▸${NC} 安装 cloudflare-warp..."
        apt-get update -qq >/dev/null 2>&1
        if apt-get install -y cloudflare-warp >/dev/null 2>&1; then
            echo -e " ${G}✓${NC}"
        else
            echo -e " ${R}✗${NC}"
            _warn "尝试使用备用源..."
            echo "deb [arch=amd64,arm64 signed-by=/usr/share/keyrings/cloudflare-warp-archive-keyring.gpg] https://pkg.cloudflareclient.com/ focal main" | tee /etc/apt/sources.list.d/cloudflare-client.list >/dev/null
            apt-get update -qq >/dev/null 2>&1
            if ! apt-get install -y cloudflare-warp >/dev/null 2>&1; then
                _err "安装失败"
                return 1
            fi
        fi
        
    elif [[ "$DISTRO" == "centos" ]]; then
        curl -fsSL https://pkg.cloudflareclient.com/cloudflare-warp-ascii.repo 2>/dev/null | tee /etc/yum.repos.d/cloudflare-warp.repo >/dev/null
        echo -e " ${G}✓${NC}"
        
        echo -ne "  ${C}▸${NC} 安装 cloudflare-warp..."
        if yum install -y cloudflare-warp >/dev/null 2>&1; then
            echo -e " ${G}✓${NC}"
        else
            echo -e " ${R}✗${NC}"
            _err "安装失败"
            return 1
        fi
    else
        echo -e " ${R}✗${NC}"
        _err "不支持的系统: $DISTRO"
        return 1
    fi
    
    # 验证安装
    if ! check_cmd warp-cli; then
        _err "WARP 官方客户端安装失败"
        return 1
    fi
    
    # 启动 warp-svc 服务
    echo -ne "  ${C}▸${NC} 启动 WARP 服务..."
    systemctl enable warp-svc >/dev/null 2>&1
    systemctl start warp-svc >/dev/null 2>&1
    
    local svc_retry=0
    while [[ $svc_retry -lt 5 ]]; do
        sleep 1
        if systemctl is-active warp-svc &>/dev/null; then
            echo -e " ${G}✓${NC}"
            echo ""
            _ok "WARP 官方客户端安装成功"
            return 0
        fi
        ((svc_retry++))
    done
    
    echo -e " ${Y}!${NC}"
    _warn "WARP 服务启动较慢，继续配置..."
    return 0
}

# 配置 WARP 官方客户端 (SOCKS5 代理模式)
configure_warp_official() {
    _info "配置 WARP 官方客户端..."
    
    # 检查 warp-cli 是否存在
    if ! check_cmd warp-cli; then
        _err "warp-cli 未安装"
        return 1
    fi
    
    # 确保 warp-svc 服务运行
    echo -ne "  ${C}▸${NC} 启动 WARP 服务..."
    if ! systemctl is-active warp-svc &>/dev/null; then
        systemctl start warp-svc 2>/dev/null
        local svc_retry=0
        while [[ $svc_retry -lt 10 ]]; do
            sleep 1
            if systemctl is-active warp-svc &>/dev/null; then
                break
            fi
            ((svc_retry++))
        done
    fi
    if systemctl is-active warp-svc &>/dev/null; then
        echo -e " ${G}✓${NC}"
    else
        echo -e " ${R}✗${NC}"
        _err "WARP 服务启动失败"
        return 1
    fi
    
    # 检查是否已注册 (新版 warp-cli 状态关键词: Status, Connected, Disconnected)
    local status=$(warp-cli status 2>/dev/null)
    local is_registered=false
    
    # 检测多种可能的已注册状态
    if echo "$status" | grep -qiE "Registration|Account|Status:|Connected|Disconnected"; then
        is_registered=true
    fi
    
    if [[ "$is_registered" != "true" ]]; then
        echo -ne "  ${C}▸${NC} 注册 WARP 账户..."
        local reg_output=""
        local reg_success=false
        
        # 等待服务完全启动
        sleep 2
        
        # 尝试新版命令 (warp-cli 2024+)
        for i in 1 2 3; do
            # 方法1: --accept-tos 放在前面（全局选项）
            reg_output=$(warp-cli --accept-tos registration new 2>&1)
            if [[ $? -eq 0 ]] || echo "$reg_output" | grep -qi "already\|success\|registered"; then
                reg_success=true
                break
            fi
            
            # 方法2: 用 yes 管道模拟输入
            reg_output=$(yes | warp-cli registration new 2>&1)
            if [[ $? -eq 0 ]] || echo "$reg_output" | grep -qi "already\|success\|registered"; then
                reg_success=true
                break
            fi
            
            # 方法3: 使用 script 命令模拟 TTY
            if command -v script &>/dev/null; then
                reg_output=$(script -q -c "warp-cli registration new" /dev/null 2>&1 <<< "y")
                if [[ $? -eq 0 ]] || echo "$reg_output" | grep -qi "already\|success\|registered"; then
                    reg_success=true
                    break
                fi
            fi
            sleep 2
        done
        
        # 如果新版命令失败，检查是否已经注册
        if [[ "$reg_success" != "true" ]]; then
            reg_output=$(warp-cli registration show 2>&1)
            if [[ $? -eq 0 ]] && ! echo "$reg_output" | grep -qi "error\|not found\|missing"; then
                reg_success=true
            fi
        fi
        
        # 再次检查状态确认注册成功
        sleep 1
        status=$(warp-cli status 2>/dev/null)
        if [[ "$reg_success" == "true" ]] || echo "$status" | grep -qiE "Registration|Account|Status:|Connected|Disconnected"; then
            echo -e " ${G}✓${NC}"
        else
            echo -e " ${R}✗${NC}"
            _err "WARP 账户注册失败"
            [[ -n "$reg_output" ]] && echo -e "  ${D}$reg_output${NC}"
            return 1
        fi
    else
        echo -e "  ${C}▸${NC} WARP 账户已注册 ${G}✓${NC}"
    fi
    
    # 先断开现有连接，释放端口
    warp-cli disconnect 2>/dev/null
    sleep 1
    
    # 设置为代理模式
    echo -ne "  ${C}▸${NC} 设置代理模式..."
    warp-cli mode proxy 2>/dev/null || warp-cli set-mode proxy 2>/dev/null
    echo -e " ${G}✓${NC}"
    
    # 重置端口为默认值
    WARP_OFFICIAL_PORT=40000
    
    # 设置代理端口
    echo -ne "  ${C}▸${NC} 设置代理端口 $WARP_OFFICIAL_PORT..."
    warp-cli proxy port "$WARP_OFFICIAL_PORT" 2>/dev/null || warp-cli set-proxy-port "$WARP_OFFICIAL_PORT" 2>/dev/null
    echo -e " ${G}✓${NC}"
    
    # 连接 WARP
    echo -ne "  ${C}▸${NC} 连接 WARP..."
    warp-cli connect 2>/dev/null
    
    # 等待连接成功 (带进度显示)
    local retry=0
    local connected=false
    while [[ $retry -lt 15 ]]; do
        sleep 2
        if warp-cli status 2>/dev/null | grep -qi "Connected"; then
            connected=true
            break
        fi
        echo -ne "."
        ((retry++))
    done
    
    if [[ "$connected" != "true" ]]; then
        echo -e " ${R}✗${NC}"
        _err "WARP 连接超时"
        echo -e "  ${D}当前状态:${NC}"
        warp-cli status 2>/dev/null | sed 's/^/  /'
        return 1
    fi
    
    echo -e " ${G}✓${NC}"
    
    # 保存模式到数据库
    db_set_warp_mode "official"
    
    # 获取 WARP 出口 IP (带重试和多源)
    _get_warp_official_ip
    return $?
}

# 获取 WARP 官方客户端出口 IP (带重试机制)
# 获取 WARP 官方客户端出口 IP
# 参数: $1 = "interactive" (带用户交互) 或 "simple" (静默模式)
_get_warp_official_ip() {
    local mode="${1:-interactive}"
    local ip_apis=("https://api.ipify.org" "https://ifconfig.me" "https://ip.sb" "https://api.ip.sb/ip")
    
    while true; do
        echo -e "  ${C}▸${NC} 获取 WARP 出口 IP..."
        local warp_ip="" attempt=1
        
        while [[ $attempt -le 3 && -z "$warp_ip" ]]; do
            echo -ne "    尝试 $attempt/3..."
            for api in "${ip_apis[@]}"; do
                warp_ip=$(curl -s --connect-timeout 8 --max-time 12 --socks5 127.0.0.1:$WARP_OFFICIAL_PORT "$api" 2>/dev/null | grep -oE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -1)
                [[ -n "$warp_ip" ]] && break
            done
            [[ -n "$warp_ip" ]] && echo -e " ${G}成功${NC}" && break
            echo -e " ${Y}超时${NC}"
            ((attempt++))
            [[ $attempt -le 3 ]] && sleep 2
        done
        
        if [[ -n "$warp_ip" ]]; then
            if [[ "$mode" == "simple" ]]; then
                _ok "WARP 已重新连接"
                echo -e "  WARP 出口 IP: ${G}${warp_ip}${NC}"
            else
                echo ""
                _line
                echo -e "  ${G}WARP 官方客户端配置成功${NC}"
                _line
                echo -e "  SOCKS5 代理: ${C}127.0.0.1:${WARP_OFFICIAL_PORT}${NC}"
                echo -e "  WARP 出口 IP: ${G}${warp_ip}${NC}"
                _line
            fi
            return 0
        fi
        
        # 获取失败
        if [[ "$mode" == "simple" ]]; then
            _ok "WARP 已重新连接"
            echo -e "  ${D}出口 IP 获取超时，请稍后手动验证${NC}"
            return 0
        fi
        
        # interactive 模式：询问用户
        echo ""
        _warn "无法获取 WARP 出口 IP"
        echo ""
        _item "1" "重试获取"
        _item "2" "跳过 (连接已建立，可能是 API 问题)"
        _item "3" "放弃配置"
        _line
        read -rp "  请选择: " ip_choice
        ip_choice=$(echo "$ip_choice" | tr -d ' \t')
        
        case "$ip_choice" in
            1) continue ;;
            2)
                echo ""
                _line
                echo -e "  ${G}WARP 官方客户端已连接${NC}"
                _line
                echo -e "  SOCKS5 代理: ${C}127.0.0.1:${WARP_OFFICIAL_PORT}${NC}"
                echo -e "  ${D}出口 IP 未获取，请稍后手动验证${NC}"
                _line
                return 0
                ;;
            *)
                _err "配置已取消"
                warp-cli disconnect 2>/dev/null
                db_set_warp_mode "wgcf"
                return 1
                ;;
        esac
    done
}

# 重新连接 WARP 官方客户端
reconnect_warp_official() {
    _info "重新连接 WARP 官方客户端..."
    
    if ! check_cmd warp-cli; then
        _err "warp-cli 未安装"
        return 1
    fi
    
    warp-cli disconnect 2>/dev/null
    sleep 2
    warp-cli connect 2>/dev/null
    
    # 等待连接 (带进度显示)
    echo -ne "  ${C}▸${NC} 等待连接..."
    local retry=0 connected=false
    while [[ $retry -lt 10 ]]; do
        sleep 2
        if warp-cli status 2>/dev/null | grep -qi "Connected"; then
            connected=true
            break
        fi
        echo -ne "."
        ((retry++))
    done
    
    if [[ "$connected" != "true" ]]; then
        echo -e " ${R}✗${NC}"
        _err "重新连接失败"
        warp-cli status 2>/dev/null | sed 's/^/  /'
        return 1
    fi
    
    echo -e " ${G}✓${NC}"
    _get_warp_official_ip "simple"
    return 0
}

# 卸载 WARP 官方客户端
uninstall_warp_official() {
    _info "卸载 WARP 官方客户端..."
    
    # 断开连接
    warp-cli disconnect 2>/dev/null
    
    # 停止服务
    systemctl stop warp-svc 2>/dev/null
    systemctl disable warp-svc 2>/dev/null
    
    # 卸载软件包
    if [[ "$DISTRO" == "ubuntu" || "$DISTRO" == "debian" ]]; then
        apt-get remove -y cloudflare-warp 2>/dev/null
        apt-get autoremove -y 2>/dev/null
        rm -f /etc/apt/sources.list.d/cloudflare-client.list
        rm -f /usr/share/keyrings/cloudflare-warp-archive-keyring.gpg
    elif [[ "$DISTRO" == "centos" ]]; then
        yum remove -y cloudflare-warp 2>/dev/null
        rm -f /etc/yum.repos.d/cloudflare-warp.repo
    fi
    
    _ok "WARP 官方客户端已卸载"
}

# 卸载 WARP (支持双模式)
uninstall_warp() {
    local warp_mode=$(db_get_warp_mode)
    _info "卸载 WARP..."
    
    if [[ "$warp_mode" == "official" ]]; then
        uninstall_warp_official
    else
        # 卸载 WGCF
        rm -f "$WARP_CONF_FILE"
        rm -f /usr/local/bin/wgcf
        rm -f ~/.wgcf-account.toml 2>/dev/null
        _ok "WARP (WGCF) 已卸载"
    fi
    
    # 清除模式设置和分流配置
    db_set_warp_mode "wgcf"
    db_clear_routing_rules
    
    # 重新生成配置 (移除 WARP outbound)
    _regenerate_proxy_configs
    _ok "WARP 已完全卸载"
}

#═══════════════════════════════════════════════════════════════════════════════
# 多出口分流规则系统
#═══════════════════════════════════════════════════════════════════════════════

# 预设规则类型定义
declare -A ROUTING_PRESETS=(
    [openai]="openai.com,chatgpt.com,chat.openai.com,ai.com,sora.com,oaistatic.com,oaiusercontent.com"
    [netflix]="netflix.com,netflix.net,nflximg.net,nflximg.com,nflxvideo.net,nflxso.net,nflxext.com"
    [disney]="disney.com,disneyplus.com,dssott.com,bamgrid.com,disney-plus.net,disneystreaming.com"
    [youtube]="youtube.com,googlevideo.com,ytimg.com,youtu.be,yt.be,youtube-nocookie.com"
    [spotify]="spotify.com,spotifycdn.com,scdn.co,spotify.net"
    [tiktok]="tiktok.com,tiktokcdn.com,musical.ly,tiktokv.com,byteoversea.com"
    [telegram]="telegram.org,t.me,telegram.me,telegra.ph,telesco.pe"
    [google]="google.com,googleapis.com,gstatic.com,google.co,googlesyndication.com,googleusercontent.com"
)

# 预设规则显示名称
declare -A ROUTING_PRESET_NAMES=(
    [openai]="OpenAI/ChatGPT"
    [netflix]="Netflix"
    [disney]="Disney+"
    [youtube]="YouTube"
    [spotify]="Spotify"
    [tiktok]="TikTok"
    [telegram]="Telegram"
    [google]="Google"
)

# 数据库：添加分流规则
db_add_routing_rule() {
    local rule_type="$1"    # openai, netflix, custom, all
    local outbound="$2"     # 出口标识: warp, chain:节点名
    local domains="$3"      # 自定义域名 (仅 custom 类型)
    
    [[ ! -f "$DB_FILE" ]] && echo '{}' > "$DB_FILE"
    
    # 生成规则 ID
    local rule_id="${rule_type}_$(date +%s)"
    [[ "$rule_type" != "custom" ]] && rule_id="$rule_type"
    
    # 获取域名
    local rule_domains="$domains"
    [[ "$rule_type" != "custom" && "$rule_type" != "all" ]] && rule_domains="${ROUTING_PRESETS[$rule_type]:-}"
    
    local tmp=$(mktemp)
    
    # custom 类型：追加规则，不删除已有的 custom 规则
    # 其他类型：覆盖同类型规则
    if [[ "$rule_type" == "custom" ]]; then
        jq --arg id "$rule_id" --arg type "$rule_type" --arg out "$outbound" --arg domains "$rule_domains" \
            '.routing_rules = ((.routing_rules // []) + [{id: $id, type: $type, outbound: $out, domains: $domains}])' \
            "$DB_FILE" > "$tmp" && mv "$tmp" "$DB_FILE"
    else
        jq --arg id "$rule_id" --arg type "$rule_type" --arg out "$outbound" --arg domains "$rule_domains" \
            '.routing_rules = ((.routing_rules // []) | map(select(.type != $type))) + [{id: $id, type: $type, outbound: $out, domains: $domains}]' \
            "$DB_FILE" > "$tmp" && mv "$tmp" "$DB_FILE"
    fi
}

# 数据库：删除分流规则 (支持按 id 或 type 删除)
# 用法: db_del_routing_rule "rule_id" 或 db_del_routing_rule "type" "by_type"
db_del_routing_rule() {
    local identifier="$1"
    local mode="${2:-by_id}"  # 默认按 id 删除
    [[ ! -f "$DB_FILE" ]] && return
    
    local tmp=$(mktemp)
    if [[ "$mode" == "by_type" ]]; then
        # 按 type 删除 (删除所有同类型规则)
        jq --arg type "$identifier" '.routing_rules = [.routing_rules[]? | select(.type != $type)]' "$DB_FILE" > "$tmp" && mv "$tmp" "$DB_FILE"
    else
        # 按 id 删除 (只删除单个规则)
        jq --arg id "$identifier" '.routing_rules = [.routing_rules[]? | select(.id != $id)]' "$DB_FILE" > "$tmp" && mv "$tmp" "$DB_FILE"
    fi
}

# 数据库：获取所有分流规则
db_get_routing_rules() {
    [[ ! -f "$DB_FILE" ]] && echo "[]" && return
    jq -r '.routing_rules // []' "$DB_FILE" 2>/dev/null
}

# 数据库：检查规则是否存在
db_has_routing_rule() {
    local rule_type="$1"
    [[ ! -f "$DB_FILE" ]] && return 1
    local count=$(jq --arg type "$rule_type" '[.routing_rules[]? | select(.type == $type)] | length' "$DB_FILE" 2>/dev/null)
    [[ "$count" -gt 0 ]]
}

# 数据库：清空所有分流规则
db_clear_routing_rules() {
    [[ ! -f "$DB_FILE" ]] && return
    local tmp=$(mktemp)
    jq '.routing_rules = []' "$DB_FILE" > "$tmp" && mv "$tmp" "$DB_FILE"
}

# 获取可用的出口列表
_get_available_outbounds() {
    local outbounds=()
    
    # WARP 出口
    local warp_st=$(warp_status 2>/dev/null)
    if [[ "$warp_st" == "configured" || "$warp_st" == "connected" ]]; then
        outbounds+=("warp|WARP")
    fi
    
    # 链式代理节点
    local nodes=$(db_get_chain_nodes 2>/dev/null)
    if [[ -n "$nodes" && "$nodes" != "[]" ]]; then
        while IFS= read -r node_name; do
            [[ -n "$node_name" ]] && outbounds+=("chain:${node_name}|${node_name}")
        done < <(echo "$nodes" | jq -r '.[].name' 2>/dev/null)
    fi
    
    # 输出格式: "id|显示名" 每行一个
    printf '%s\n' "${outbounds[@]}"
}

# 选择出口的交互函数 (带延迟检测)
_select_outbound() {
    local prompt="${1:-选择出口}"
    local outbounds=()
    local display_names=()
    
    # 获取节点完整信息
    local nodes=$(db_get_chain_nodes 2>/dev/null)
    local node_count=$(echo "$nodes" | jq 'length' 2>/dev/null || echo 0)
    
    # WARP 出口
    local warp_st=$(warp_status 2>/dev/null)
    if [[ "$warp_st" == "configured" || "$warp_st" == "connected" ]]; then
        outbounds+=("warp")
        display_names+=("WARP")
    fi
    
    # 链式代理节点
    if [[ "$node_count" -gt 0 ]]; then
        while IFS='|' read -r name type server port; do
            [[ -z "$name" ]] && continue
            outbounds+=("chain:${name}")
            display_names+=("${name}|${type}|${server}|${port}")
        done < <(echo "$nodes" | jq -r '.[] | "\(.name)|\(.type)|\(.server)|\(.port)"')
    fi
    
    if [[ ${#outbounds[@]} -eq 0 ]]; then
        echo -e "  ${Y}!${NC} 没有可用的出口，请先配置 WARP 或添加代理节点" >&2
        return 1
    fi
    
    # 检测延迟
    echo -e "  ${C}▸${NC} 检测 ${#outbounds[@]} 个节点延迟中..." >&2
    
    local latency_results=()
    local idx=0
    for info in "${display_names[@]}"; do
        if [[ "$info" == "WARP" ]]; then
            latency_results+=("-|WARP|-")
        else
            local server=$(echo "$info" | cut -d'|' -f3)
            local port=$(echo "$info" | cut -d'|' -f4)
            local result=$(check_node_latency "$server" "$port" 2>/dev/null)
            latency_results+=("$result")
        fi
        ((idx++))
        echo -ne "\r  ${C}▸${NC} 检测中... ($idx/${#outbounds[@]})  " >&2
    done
    echo -e "\r  ${G}✓${NC} 延迟检测完成                " >&2
    echo "" >&2
    
    # 构建排序数据: latency_num|idx|latency_display|name|type|ip
    local sort_data=()
    for i in "${!outbounds[@]}"; do
        local info="${display_names[$i]}"
        local result="${latency_results[$i]}"
        
        if [[ "$info" == "WARP" ]]; then
            sort_data+=("0|$i|WARP|WARP|warp|-")
        else
            local name=$(echo "$info" | cut -d'|' -f1)
            local type=$(echo "$info" | cut -d'|' -f2)
            local latency="${result%%|*}"
            local resolved_ip="${result##*|}"
            
            local latency_num=99999
            [[ "$latency" =~ ^[0-9]+$ ]] && latency_num="$latency"
            
            sort_data+=("${latency_num}|$i|${latency}|${name}|${type}|${resolved_ip}")
        fi
    done
    
    # 按延迟排序并显示
    local sorted_indices=()
    local display_idx=1
    while IFS='|' read -r latency_num orig_idx latency name type resolved_ip; do
        sorted_indices+=("$orig_idx")
        
        local latency_color="${G}"
        if [[ "$latency" == "超时" ]]; then
            latency_color="${R}"
        elif [[ "$latency" =~ ^[0-9]+$ && "$latency" -gt 300 ]]; then
            latency_color="${Y}"
        fi
        
        if [[ "$name" == "WARP" ]]; then
            echo -e "  ${G}${display_idx}${NC}) WARP" >&2
        elif [[ "$latency" == "超时" ]]; then
            echo -e "  ${G}${display_idx}${NC}) [${latency_color}${latency}${NC}] ${name} ${D}(${type})${NC} ${D}${resolved_ip}${NC}" >&2
        elif [[ "$latency" =~ ^[0-9]+$ ]]; then
            echo -e "  ${G}${display_idx}${NC}) [${latency_color}${latency}ms${NC}] ${name} ${D}(${type})${NC} ${D}${resolved_ip}${NC}" >&2
        else
            echo -e "  ${G}${display_idx}${NC}) ${name} ${D}(${type})${NC}" >&2
        fi
        ((display_idx++))
    done < <(printf '%s\n' "${sort_data[@]}" | sort -t'|' -k1 -n)
    
    # 返回选项
    echo -e "  ${G}0${NC}) 返回" >&2
    
    _line >&2
    read -rp "  $prompt [1]: " choice
    choice=${choice:-1}
    
    # 输入 0 返回
    if [[ "$choice" == "0" ]]; then
        return 1
    fi
    
    if [[ "$choice" =~ ^[0-9]+$ ]] && [[ "$choice" -ge 1 && "$choice" -le ${#sorted_indices[@]} ]]; then
        local orig_idx="${sorted_indices[$((choice-1))]}"
        echo "${outbounds[$orig_idx]}"
        return 0
    fi
    
    return 1
}

# 获取出口的显示名称
_get_outbound_display_name() {
    local outbound="$1"
    case "$outbound" in
        warp) echo "WARP" ;;
        chain:*) echo "${outbound#chain:}" ;;
        *) echo "$outbound" ;;
    esac
}

# 生成 Xray 分流路由配置 (支持多出口)
gen_xray_routing_rules() {
    local rules=$(db_get_routing_rules)
    [[ -z "$rules" || "$rules" == "[]" ]] && return
    
    local result="[]"
    while IFS= read -r rule; do
        [[ -z "$rule" ]] && continue
        local rule_type=$(echo "$rule" | jq -r '.type')
        local outbound=$(echo "$rule" | jq -r '.outbound')
        local domains=$(echo "$rule" | jq -r '.domains // ""')
        
        # 转换出口标识为 tag
        local tag="$outbound"
        if [[ "$outbound" == "warp" ]]; then
            tag="warp"
        elif [[ "$outbound" == chain:* ]]; then
            # 多出口：每个节点有独立的 tag，格式为 chain-节点名
            local node_name="${outbound#chain:}"
            tag="chain-${node_name}"
        fi
        
        if [[ "$rule_type" == "all" ]]; then
            result=$(echo "$result" | jq --arg tag "$tag" '. + [{"type": "field", "network": "tcp,udp", "outboundTag": $tag}]')
        elif [[ -n "$domains" ]]; then
            # 安全构建域名数组：过滤空行，验证 JSON 格式
            local domain_array
            domain_array=$(echo "$domains" | tr ',' '\n' | grep -v '^$' | sed 's/^/domain:/' | jq -R . 2>/dev/null | jq -s . 2>/dev/null)
            # 验证 domain_array 是有效的非空 JSON 数组
            if [[ -n "$domain_array" && "$domain_array" != "[]" && "$domain_array" != "null" ]] && echo "$domain_array" | jq empty 2>/dev/null; then
                result=$(echo "$result" | jq --argjson domains "$domain_array" --arg tag "$tag" '. + [{"type": "field", "domain": $domains, "outboundTag": $tag}]')
            fi
        fi
    done < <(echo "$rules" | jq -c '.[]')
    
    [[ "$result" != "[]" ]] && echo "$result"
}

# 生成 Sing-box 分流路由配置 (支持多出口)
gen_singbox_routing_rules() {
    local rules=$(db_get_routing_rules)
    [[ -z "$rules" || "$rules" == "[]" ]] && return
    
    local result="[]"
    while IFS= read -r rule; do
        [[ -z "$rule" ]] && continue
        local rule_type=$(echo "$rule" | jq -r '.type')
        local outbound=$(echo "$rule" | jq -r '.outbound')
        local domains=$(echo "$rule" | jq -r '.domains // ""')
        
        # 转换出口标识为 tag
        local tag="$outbound"
        if [[ "$outbound" == "warp" ]]; then
            tag="warp"
        elif [[ "$outbound" == chain:* ]]; then
            local node_name="${outbound#chain:}"
            tag="chain-${node_name}"
        fi
        
        if [[ "$rule_type" == "all" ]]; then
            result=$(echo "$result" | jq --arg tag "$tag" '. + [{"outbound": $tag}]')
        elif [[ -n "$domains" ]]; then
            # 安全构建域名数组：过滤空行，验证 JSON 格式
            local domain_array
            domain_array=$(echo "$domains" | tr ',' '\n' | grep -v '^$' | jq -R . 2>/dev/null | jq -s . 2>/dev/null)
            # 验证 domain_array 是有效的非空 JSON 数组
            if [[ -n "$domain_array" && "$domain_array" != "[]" && "$domain_array" != "null" ]] && echo "$domain_array" | jq empty 2>/dev/null; then
                result=$(echo "$result" | jq --argjson domains "$domain_array" --arg tag "$tag" '. + [{"domain_suffix": $domains, "outbound": $tag}]')
            fi
        fi
    done < <(echo "$rules" | jq -c '.[]')
    
    [[ "$result" != "[]" ]] && echo "$result"
}

# 生成 Sing-box WARP outbound 配置 (支持 WireGuard 和 SOCKS5 双模式)
gen_singbox_warp_outbound() {
    local warp_mode=$(db_get_warp_mode)
    
    [[ -z "$warp_mode" || "$warp_mode" == "disabled" ]] && return
    
    # === 模式 A: 官方客户端 (SOCKS5) ===
    if [[ "$warp_mode" == "official" ]]; then
        # 检查官方客户端是否运行
        if ! check_cmd warp-cli; then
            return
        fi
        if ! warp-cli status 2>/dev/null | grep -qi "Connected"; then
            return
        fi
        
        # 生成 SOCKS5 出站
        jq -n --argjson port "$WARP_OFFICIAL_PORT" '{
            tag: "warp",
            type: "socks",
            server: "127.0.0.1",
            server_port: $port
        }'
        return
    fi
    
    # === 模式 B: WGCF (WireGuard) ===
    [[ "$warp_mode" != "wgcf" ]] && return
    [[ ! -f "$WARP_CONF_FILE" ]] && return
    
    local private_key=$(jq -r '.private_key' "$WARP_CONF_FILE")
    local public_key=$(jq -r '.public_key' "$WARP_CONF_FILE")
    local address_v4=$(jq -r '.address_v4' "$WARP_CONF_FILE" | cut -d'/' -f1)
    local address_v6=$(jq -r '.address_v6' "$WARP_CONF_FILE" | cut -d'/' -f1)
    local endpoint=$(jq -r '.endpoint' "$WARP_CONF_FILE")
    local ep_host=$(echo "$endpoint" | cut -d':' -f1)
    local ep_port=$(echo "$endpoint" | cut -d':' -f2)
    
    jq -n \
        --arg pk "$private_key" \
        --arg pub "$public_key" \
        --arg v4 "$address_v4" \
        --arg v6 "$address_v6" \
        --arg host "$ep_host" \
        --argjson port "$ep_port" \
    '{
        tag: "warp",
        type: "wireguard",
        private_key: $pk,
        local_address: [$v4, $v6],
        peer_public_key: $pub,
        server: $host,
        server_port: $port,
        mtu: 1280
    }'
}

# 显示当前分流状态 (多规则版本)
show_routing_status() {
    local warp_st=$(warp_status)
    
    echo ""
    echo -e "  ${C}出口状态${NC}"
    _line
    
    # WARP 状态
    case "$warp_st" in
        connected)
            echo -e "  WARP: ${G}● 已连接${NC} (官方客户端/TCP)"
            ;;
        registered)
            echo -e "  WARP: ${Y}● 已注册${NC} (未连接)"
            ;;
        configured)
            echo -e "  WARP: ${G}● 已配置${NC} (WGCF/UDP)"
            ;;
        *)
            echo -e "  WARP: ${D}○ 未配置${NC}"
            ;;
    esac
    
    # 链式代理节点数量
    local nodes=$(db_get_chain_nodes 2>/dev/null)
    local node_count=$(echo "$nodes" | jq 'length' 2>/dev/null || echo 0)
    if [[ "$node_count" -gt 0 ]]; then
        echo -e "  代理: ${G}● ${node_count} 个节点${NC}"
    else
        echo -e "  代理: ${D}○ 无节点${NC}"
    fi
    
    _line
    echo -e "  ${C}分流规则${NC}"
    _line
    
    # 显示分流规则 (优化：一次性提取所有字段，避免多次调用 jq)
    local rules=$(db_get_routing_rules)
    
    if [[ -n "$rules" && "$rules" != "[]" ]]; then
        local rule_count=0
        # 一次性提取 type, outbound, domains，用 | 分隔
        while IFS='|' read -r rule_type outbound domains; do
            [[ -z "$rule_type" ]] && continue
            local outbound_name=$(_get_outbound_display_name "$outbound")
            
            local rule_name="${ROUTING_PRESET_NAMES[$rule_type]:-$rule_type}"
            if [[ "$rule_type" == "custom" ]]; then
                # 自定义规则显示域名
                if [[ -n "$domains" && "$domains" != "null" ]]; then
                    local display_domains="$domains"
                    if [[ ${#domains} -gt 20 ]]; then
                        display_domains="${domains:0:17}..."
                    fi
                    rule_name="自定义 (${display_domains})"
                else
                    rule_name="自定义"
                fi
            fi
            [[ "$rule_type" == "all" ]] && rule_name="所有流量"
            
            if [[ "$rule_type" == "all" ]]; then
                echo -e "  ${Y}●${NC} ${rule_name} → ${C}${outbound_name}${NC}"
            else
                echo -e "  ${G}●${NC} ${rule_name} → ${C}${outbound_name}${NC}"
            fi
            
            ((rule_count++))
        done < <(echo "$rules" | jq -r '.[] | "\(.type)|\(.outbound)|\(.domains // "")"')
        
        [[ $rule_count -eq 0 ]] && echo -e "  ${D}未配置分流规则${NC}"
    else
        echo -e "  ${D}未配置分流规则${NC}"
    fi
    _line
}

# 测试分流是否生效
test_routing() {
    local rules=$(db_get_routing_rules)
    
    # 检查是否有规则
    if [[ -z "$rules" || "$rules" == "[]" ]]; then
        _info "未配置分流规则"
        return 0
    fi
    
    echo ""
    _info "测试分流效果..."
    _line
    
    # 获取本机直连 IP
    local direct_ip=$(curl -s --connect-timeout 5 https://api.ipify.org 2>/dev/null)
    [[ -z "$direct_ip" ]] && direct_ip=$(curl -s --connect-timeout 5 https://ifconfig.me 2>/dev/null)
    echo -e "  直连出口 IP: ${C}${direct_ip:-获取失败}${NC}"
    
    # 测试 WARP 出口
    local warp_st=$(warp_status)
    if [[ "$warp_st" == "connected" ]]; then
        local warp_ip=$(curl -s --connect-timeout 10 --socks5 127.0.0.1:$WARP_OFFICIAL_PORT https://api.ipify.org 2>/dev/null)
        [[ -n "$warp_ip" ]] && echo -e "  WARP 出口 IP: ${G}${warp_ip}${NC}"
    elif [[ "$warp_st" == "configured" ]]; then
        echo -e "  WARP: ${G}已配置${NC} (WGCF/UDP)"
    fi
    
    _line
    
    # 显示规则测试信息
    echo -e "  ${Y}已配置的分流规则:${NC}"
    while IFS= read -r rule; do
        [[ -z "$rule" ]] && continue
        local rule_type=$(echo "$rule" | jq -r '.type')
        local outbound=$(echo "$rule" | jq -r '.outbound')
        local domains=$(echo "$rule" | jq -r '.domains // ""')
        
        local rule_name="${ROUTING_PRESET_NAMES[$rule_type]:-$rule_type}"
        [[ "$rule_type" == "custom" ]] && rule_name="自定义"
        [[ "$rule_type" == "all" ]] && rule_name="所有流量"
        local outbound_name=$(_get_outbound_display_name "$outbound")
        
        # 获取测试域名
        if [[ "$rule_type" == "all" ]]; then
            echo -e "  ${G}●${NC} ${rule_name} → ${outbound_name}"
        else
            local test_domain=""
            [[ -n "$domains" && "$domains" != "null" ]] && test_domain=$(echo "$domains" | cut -d',' -f1)
            echo -e "  ${G}●${NC} ${rule_name} → ${outbound_name} (${test_domain:-N/A})"
        fi
    done < <(echo "$rules" | jq -c '.[]')
    
    echo ""
    echo -e "  ${G}✓${NC} 分流规则已配置"
    _line
    echo -e "  ${Y}验证方法:${NC}"
    echo -e "  • 手机访问 ${C}https://ip.sb${NC} 查看出口 IP"
    echo ""
    echo -e "  ${Y}调试命令:${NC}"
    echo -e "  • 检查配置语法: ${C}xray run -test -c /etc/xray/config.json${NC}"
    echo -e "  • 开启调试日志: ${C}sed -i 's/\"loglevel\":\"warning\"/\"loglevel\":\"debug\"/' /etc/xray/config.json && systemctl restart xray${NC}"
    echo -e "  • 查看实时日志: ${C}journalctl -u xray -f${NC}"
    echo -e "  • 关闭调试日志: ${C}sed -i 's/\"loglevel\":\"debug\"/\"loglevel\":\"warning\"/' /etc/xray/config.json && systemctl restart xray${NC}"
    
    return 0
}

# 配置分流规则
configure_routing_rules() {
    while true; do
        _header
        echo -e "  ${W}配置分流规则${NC}"
        show_routing_status
        
        _item "1" "添加分流规则"
        _item "2" "删除分流规则"
        _item "3" "清空所有规则"
        _item "4" "测试分流效果"
        _item "0" "返回"
        _line
        
        read -rp "  请选择: " choice
        
        case "$choice" in
            1) _add_routing_rule ;;
            2) _del_routing_rule ;;
            3)
                read -rp "  确认清空所有分流规则? [y/N]: " confirm
                if [[ "$confirm" =~ ^[Yy]$ ]]; then
                    db_clear_routing_rules
                    _regenerate_proxy_configs
                    _ok "已清空所有分流规则"
                fi
                _pause
                ;;
            4)
                _header
                echo -e "  ${W}测试分流效果${NC}"
                test_routing
                _pause
                ;;
            0) return ;;
        esac
    done
}

# 添加分流规则
_add_routing_rule() {
    _header
    echo -e "  ${W}添加分流规则${NC}"
    _line
    
    # 检查可用出口
    local outbounds_list=$(_get_available_outbounds)
    if [[ -z "$outbounds_list" ]]; then
        _warn "没有可用的出口，请先配置 WARP 或添加代理节点"
        echo ""
        _item "1" "配置 WARP"
        _item "2" "快速配置代理出口"
        _item "0" "返回"
        _line
        read -rp "  请选择: " setup_choice
        case "$setup_choice" in
            1) manage_warp ;;
            2) add_quick_proxy ;;
        esac
        return
    fi
    
    echo -e "  ${Y}选择规则类型:${NC}"
    echo ""
    _item "1" "OpenAI/ChatGPT"
    _item "2" "Netflix"
    _item "3" "Disney+"
    _item "4" "YouTube"
    _item "5" "Spotify"
    _item "6" "TikTok"
    _item "7" "Telegram"
    _item "8" "Google"
    _item "9" "自定义域名"
    _item "a" "所有流量"
    _item "0" "返回"
    _line
    
    read -rp "  请选择: " rule_choice
    
    local rule_type="" custom_domains=""
    case "$rule_choice" in
        1) rule_type="openai" ;;
        2) rule_type="netflix" ;;
        3) rule_type="disney" ;;
        4) rule_type="youtube" ;;
        5) rule_type="spotify" ;;
        6) rule_type="tiktok" ;;
        7) rule_type="telegram" ;;
        8) rule_type="google" ;;
        9)
            rule_type="custom"
            echo ""
            echo -e "  ${Y}输入要分流的域名 (逗号分隔):${NC}"
            echo -e "  ${D}例如: example.com,test.org${NC}"
            read -rp "  域名: " custom_domains
            custom_domains=$(echo "$custom_domains" | tr -d ' \t')
            if [[ -z "$custom_domains" || ! "$custom_domains" =~ \. ]]; then
                _warn "域名格式无效"
                _pause
                return
            fi
            ;;
        a|A) rule_type="all" ;;
        0|"") return ;;
        *) _warn "无效选项"; _pause; return ;;
    esac
    
    # 检查规则是否已存在 (custom 类型允许多条，不检查)
    if [[ "$rule_type" != "custom" ]] && db_has_routing_rule "$rule_type"; then
        _warn "${ROUTING_PRESET_NAMES[$rule_type]:-$rule_type} 规则已存在"
        read -rp "  是否覆盖? [y/N]: " overwrite
        [[ ! "$overwrite" =~ ^[Yy]$ ]] && return
    fi
    
    # 选择出口
    echo ""
    echo -e "  ${Y}选择出口:${NC}"
    local outbound=$(_select_outbound "选择出口")
    [[ -z "$outbound" ]] && return
    
    # 保存规则
    if [[ "$rule_type" == "custom" ]]; then
        db_add_routing_rule "$rule_type" "$outbound" "$custom_domains"
    else
        db_add_routing_rule "$rule_type" "$outbound"
    fi
    
    local rule_name="${ROUTING_PRESET_NAMES[$rule_type]:-$rule_type}"
    [[ "$rule_type" == "custom" ]] && rule_name="自定义"
    [[ "$rule_type" == "all" ]] && rule_name="所有流量"
    local outbound_name=$(_get_outbound_display_name "$outbound")
    
    _ok "已添加规则: ${rule_name} → ${outbound_name}"
    
    # 更新配置
    _info "更新代理配置..."
    _regenerate_proxy_configs
    _ok "配置已更新"
    _pause
}

# 删除分流规则
_del_routing_rule() {
    _header
    echo -e "  ${W}删除分流规则${NC}"
    _line
    
    local rules=$(db_get_routing_rules)
    if [[ -z "$rules" || "$rules" == "[]" ]]; then
        _warn "没有分流规则"
        _pause
        return
    fi
    
    # 显示规则列表
    local idx=1
    local rule_ids=()
    while IFS= read -r rule; do
        [[ -z "$rule" ]] && continue
        local rule_id=$(echo "$rule" | jq -r '.id')
        local rule_type=$(echo "$rule" | jq -r '.type')
        local outbound=$(echo "$rule" | jq -r '.outbound')
        local domains=$(echo "$rule" | jq -r '.domains // ""')
        local rule_name="${ROUTING_PRESET_NAMES[$rule_type]:-$rule_type}"
        
        # 自定义规则显示域名
        if [[ "$rule_type" == "custom" ]]; then
            # 截取域名显示，过长则省略
            local display_domains="$domains"
            if [[ ${#domains} -gt 30 ]]; then
                display_domains="${domains:0:27}..."
            fi
            rule_name="自定义 (${display_domains})"
        fi
        [[ "$rule_type" == "all" ]] && rule_name="所有流量"
        local outbound_name=$(_get_outbound_display_name "$outbound")
        
        echo -e "  ${G}${idx})${NC} ${rule_name} → ${outbound_name}"
        rule_ids+=("$rule_id")
        ((idx++))
    done < <(echo "$rules" | jq -c '.[]')
    
    echo ""
    read -rp "  输入序号删除 (0 返回): " del_choice
    
    if [[ "$del_choice" =~ ^[0-9]+$ ]] && [[ "$del_choice" -ge 1 && "$del_choice" -le ${#rule_ids[@]} ]]; then
        local del_id="${rule_ids[$((del_choice-1))]}"
        db_del_routing_rule "$del_id"
        _regenerate_proxy_configs
        _ok "已删除规则"
    fi
    _pause
}

# 重新生成代理配置的辅助函数
_regenerate_proxy_configs() {
    local xray_protocols=$(get_xray_protocols)
    if [[ -n "$xray_protocols" ]]; then
        generate_xray_config
        svc restart vless-reality 2>/dev/null
    fi
    
    local singbox_protocols=$(get_singbox_protocols)
    if [[ -n "$singbox_protocols" ]]; then
        generate_singbox_config
        svc restart vless-singbox 2>/dev/null
    fi
}

# WARP 管理菜单 (二选一模式)
manage_warp() {
    _header
    echo -e "  ${W}WARP 管理${NC}"
    
    local status=$(warp_status)
    local current_mode=$(db_get_warp_mode)
    
    _line
    case "$status" in
        connected)
            echo -e "  状态: ${G}● 已连接${NC}"
            echo -e "  模式: ${C}官方客户端 (TCP/SOCKS5)${NC}"
            echo -e "  代理: ${G}127.0.0.1:${WARP_OFFICIAL_PORT}${NC}"
            echo -e "  ${D}抗 UDP 封锁，稳定性好${NC}"
            ;;
        registered)
            echo -e "  状态: ${Y}● 已注册${NC} (未连接)"
            echo -e "  模式: ${C}官方客户端${NC}"
            ;;
        configured)
            echo -e "  状态: ${G}● 已配置${NC}"
            echo -e "  模式: ${C}WGCF (UDP/WireGuard)${NC}"
            if [[ -f "$WARP_CONF_FILE" ]]; then
                local endpoint=$(jq -r '.endpoint // "N/A"' "$WARP_CONF_FILE" 2>/dev/null)
                echo -e "  端点: ${D}${endpoint}${NC}"
            fi
            echo -e "  ${D}性能好，但可能被 UDP 封锁${NC}"
            ;;
        *)
            echo -e "  状态: ${D}○ 未配置${NC}"
            echo ""
            echo -e "  ${D}WARP 提供 Cloudflare 的干净 IP 出口${NC}"
            echo -e "  ${D}用于解锁 ChatGPT/Netflix 等服务${NC}"
            echo ""
            echo -e "  ${Y}两种模式:${NC}"
            echo -e "  ${D}• WGCF: UDP/WireGuard，性能好${NC}"
            echo -e "  ${D}• 官方客户端: TCP/SOCKS5，绕过 UDP 封锁${NC}"
            ;;
    esac
    _line
    
    if [[ "$status" == "not_configured" ]]; then
        _item "1" "配置 WGCF 模式 (UDP/WireGuard)"
        _item "2" "配置官方客户端 (TCP/SOCKS5)"
    else
        if [[ "$current_mode" == "official" ]]; then
            _item "1" "切换到 WGCF 模式"
            _item "2" "重新连接官方客户端"
            _item "3" "测试 WARP 连接"
            _item "4" "卸载官方客户端"
        else
            _item "1" "切换到官方客户端模式"
            _item "2" "重新获取 WGCF 配置"
            _item "3" "测试 WARP 连接"
            _item "4" "卸载 WGCF"
        fi
    fi
    _item "0" "返回"
    _line
    
    read -rp "  请选择: " choice
    choice=$(echo "$choice" | tr -d ' \t')
    
    if [[ "$status" == "not_configured" ]]; then
        case "$choice" in
            1)
                # 配置 WGCF
                if register_warp; then
                    db_set_warp_mode "wgcf"
                    _regenerate_proxy_configs
                    _ok "WGCF 模式配置完成"
                fi
                _pause
                ;;
            2)
                # 配置官方客户端
                if [[ "$DISTRO" == "alpine" ]]; then
                    _err "Alpine 系统不支持官方客户端"
                    _info "请使用 WGCF 模式"
                    _pause
                    return
                fi
                if install_warp_official; then
                    if configure_warp_official; then
                        _regenerate_proxy_configs
                        _ok "官方客户端模式配置完成"
                    fi
                fi
                _pause
                ;;
            0) return ;;
            *) _warn "无效选项" ;;
        esac
    else
        case "$choice" in
            1)
                # 切换模式
                if [[ "$current_mode" == "official" ]]; then
                    # 切换到 WGCF
                    _info "切换到 WGCF 模式..."
                    warp-cli disconnect 2>/dev/null
                    if register_warp; then
                        db_set_warp_mode "wgcf"
                        _regenerate_proxy_configs
                        _ok "已切换到 WGCF 模式"
                    fi
                else
                    # 切换到官方客户端
                    if [[ "$DISTRO" == "alpine" ]]; then
                        _err "Alpine 系统不支持官方客户端"
                        _pause
                        return
                    fi
                    _info "切换到官方客户端模式..."
                    if install_warp_official; then
                        if configure_warp_official; then
                            _regenerate_proxy_configs
                            _ok "已切换到官方客户端模式"
                        fi
                    fi
                fi
                _pause
                ;;
            2)
                # 重新配置/连接
                if [[ "$current_mode" == "official" ]]; then
                    reconnect_warp_official
                else
                    refresh_warp_wgcf
                fi
                _pause
                ;;
            3)
                test_warp_connection
                _pause
                ;;
            4)
                echo ""
                read -rp "  确认卸载 WARP? [y/N]: " confirm
                if [[ "$confirm" =~ ^[Yy] ]]; then
                    uninstall_warp
                fi
                _pause
                ;;
            0) return ;;
            *) _warn "无效选项" ;;
        esac
    fi
}

#═══════════════════════════════════════════════════════════════════════════════
# 配置管理系统
#═══════════════════════════════════════════════════════════════════════════════

# 导出配置到文件
export_config() {
    _header
    echo -e "  ${W}导出配置${NC}"
    _line
    
    [[ ! -f "$DB_FILE" ]] && { _err "配置数据库不存在"; return 1; }
    
    # 生成导出文件名
    local timestamp=$(date '+%Y%m%d_%H%M%S')
    local export_file="${CFG}/backup_${timestamp}.json"
    
    echo -e "  ${C}▸${NC} 正在收集配置数据..."
    
    # 构建导出数据
    local export_data
    export_data=$(jq -n \
        --arg version "$VERSION" \
        --arg export_time "$(date -Iseconds 2>/dev/null || date '+%Y-%m-%dT%H:%M:%S')" \
        --arg ipv4 "$(get_ipv4)" \
        --arg ipv6 "$(get_ipv6)" \
        --slurpfile db "$DB_FILE" \
        '{
            export_info: {
                version: $version,
                export_time: $export_time,
                source_ipv4: $ipv4,
                source_ipv6: $ipv6
            },
            database: $db[0]
        }')
    
    # 添加证书信息 (如果存在)
    if [[ -f "$CFG/cert_domain" ]]; then
        local cert_domain=$(cat "$CFG/cert_domain")
        export_data=$(echo "$export_data" | jq --arg domain "$cert_domain" '.export_info.cert_domain = $domain')
    fi
    
    # 写入文件
    echo "$export_data" | jq . > "$export_file"
    
    if [[ -f "$export_file" ]]; then
        local file_size=$(stat -f%z "$export_file" 2>/dev/null || stat -c%s "$export_file" 2>/dev/null)
        _ok "配置导出成功"
        echo ""
        _line
        echo -e "  文件路径: ${G}$export_file${NC}"
        echo -e "  文件大小: ${file_size} 字节"
        _line
        echo ""
        # 获取本机 IP 用于示例
        local server_ip=$(get_ipv4)
        [[ -z "$server_ip" ]] && server_ip=$(get_ipv6)
        [[ -z "$server_ip" ]] && server_ip="服务器IP"
        echo -e "  ${D}提示: 可使用 scp 或 sftp 下载此文件${NC}"
        echo -e "  ${D}示例: scp root@${server_ip}:$export_file ./backup.json${NC}"
        echo -e "  ${D}自定义端口: scp -P 端口号 root@${server_ip}:$export_file ./backup.json${NC}"
    else
        _err "导出失败"
        return 1
    fi
}

# 验证导入文件格式
_validate_import_file() {
    local file="$1"
    
    # 检查文件是否存在
    [[ ! -f "$file" ]] && { _err "文件不存在: $file"; return 1; }
    
    # 检查 JSON 格式
    if ! jq empty "$file" 2>/dev/null; then
        _err "无效的 JSON 格式"
        return 1
    fi
    
    # 检查必要字段
    local has_db=$(jq 'has("database")' "$file" 2>/dev/null)
    if [[ "$has_db" != "true" ]]; then
        _err "配置文件缺少 database 字段"
        return 1
    fi
    
    # 检查数据库版本
    local db_version=$(jq -r '.database.version // "unknown"' "$file" 2>/dev/null)
    if [[ "$db_version" == "unknown" ]]; then
        _warn "无法识别配置版本，可能存在兼容性问题"
    fi
    
    return 0
}

# 检测配置内容
_detect_import_content() {
    local file="$1"
    
    echo -e "  ${C}▸${NC} 检测配置内容..."
    echo ""
    
    # 检测协议配置
    local xray_protos=$(jq -r '.database.xray | keys[]' "$file" 2>/dev/null | wc -l)
    local singbox_protos=$(jq -r '.database.singbox | keys[]' "$file" 2>/dev/null | wc -l)
    local total_protos=$((xray_protos + singbox_protos))
    
    # 检测分流规则
    local routing_rules=$(jq -r '.database.routing_rules | length' "$file" 2>/dev/null || echo 0)
    
    # 检测链式代理节点
    local chain_nodes=$(jq -r '.database.chain_proxy.nodes | length' "$file" 2>/dev/null || echo 0)
    
    # 检测源 IP
    local source_ipv4=$(jq -r '.export_info.source_ipv4 // "未知"' "$file" 2>/dev/null)
    local source_ipv6=$(jq -r '.export_info.source_ipv6 // "未知"' "$file" 2>/dev/null)
    local export_time=$(jq -r '.export_info.export_time // "未知"' "$file" 2>/dev/null)
    local export_version=$(jq -r '.export_info.version // "未知"' "$file" 2>/dev/null)
    
    _line
    echo -e "  ${W}配置文件信息${NC}"
    _line
    echo -e "  导出版本: $export_version"
    echo -e "  导出时间: $export_time"
    echo -e "  源 IPv4:  $source_ipv4"
    echo -e "  源 IPv6:  $source_ipv6"
    _line
    echo -e "  ${W}检测到的配置${NC}"
    _line
    echo -e "  协议配置: ${G}$total_protos${NC} 个"
    
    # 列出协议名称
    if [[ $total_protos -gt 0 ]]; then
        echo -ne "    "
        local proto_list=""
        for p in $(jq -r '.database.xray | keys[]' "$file" 2>/dev/null); do
            proto_list+="$p "
        done
        for p in $(jq -r '.database.singbox | keys[]' "$file" 2>/dev/null); do
            proto_list+="$p "
        done
        echo -e "${D}($proto_list)${NC}"
    fi
    
    echo -e "  分流规则: ${G}$routing_rules${NC} 条"
    echo -e "  外部节点: ${G}$chain_nodes${NC} 个"
    
    # 列出节点名称
    if [[ $chain_nodes -gt 0 ]]; then
        echo -ne "    "
        local node_list=$(jq -r '.database.chain_proxy.nodes[].name' "$file" 2>/dev/null | tr '\n' ' ')
        echo -e "${D}($node_list)${NC}"
    fi
    _line
    
    # 返回检测结果供后续使用
    echo "$total_protos:$routing_rules:$chain_nodes:$source_ipv4:$source_ipv6"
}

# 导入配置
import_config() {
    _header
    echo -e "  ${W}导入配置${NC}"
    _line
    
    # 列出可用的备份文件
    local backup_files=()
    while IFS= read -r f; do
        [[ -n "$f" ]] && backup_files+=("$f")
    done < <(ls -t "$CFG"/backup_*.json 2>/dev/null)
    
    if [[ ${#backup_files[@]} -gt 0 ]]; then
        echo -e "  ${C}可用的备份文件:${NC}"
        local i=1
        for f in "${backup_files[@]}"; do
            local fname=$(basename "$f")
            local fsize=$(stat -f%z "$f" 2>/dev/null || stat -c%s "$f" 2>/dev/null)
            echo -e "  ${G}$i)${NC} $fname (${fsize}B)"
            ((i++))
        done
        echo ""
    fi
    
    echo -e "  ${D}输入备份文件路径，或输入序号选择上方文件${NC}"
    read -rp "  文件路径: " import_path
    
    [[ -z "$import_path" ]] && { _warn "已取消"; return; }
    
    # 如果输入的是数字，选择对应的备份文件
    if [[ "$import_path" =~ ^[0-9]+$ ]] && [[ $import_path -le ${#backup_files[@]} ]]; then
        import_path="${backup_files[$((import_path-1))]}"
    fi
    
    # 验证文件
    if ! _validate_import_file "$import_path"; then
        return 1
    fi
    
    # 检测内容
    local detect_result
    detect_result=$(_detect_import_content "$import_path" | tail -1)
    _detect_import_content "$import_path" | head -n -1
    
    IFS=':' read -r total_protos routing_rules chain_nodes source_ipv4 source_ipv6 <<< "$detect_result"
    
    echo ""
    echo -e "  ${Y}选择导入内容:${NC}"
    echo -e "  ${G}1)${NC} 全部导入 (覆盖现有配置)"
    echo -e "  ${G}2)${NC} 仅导入协议配置"
    echo -e "  ${G}3)${NC} 仅导入分流规则"
    echo -e "  ${G}4)${NC} 仅导入外部节点"
    echo -e "  ${G}5)${NC} 选择性导入 (逐项确认)"
    echo -e "  ${G}0)${NC} 取消"
    _line
    
    read -rp "  请选择: " import_choice
    
    case "$import_choice" in
        1)
            # 全部导入
            echo ""
            _warn "此操作将覆盖现有配置!"
            read -rp "  确认导入? [y/N]: " confirm
            [[ ! "$confirm" =~ ^[Yy]$ ]] && { _warn "已取消"; return; }
            
            _import_all "$import_path"
            ;;
        2)
            _import_protocols "$import_path"
            ;;
        3)
            _import_routing_rules "$import_path"
            ;;
        4)
            _import_chain_nodes "$import_path"
            ;;
        5)
            _import_selective "$import_path"
            ;;
        0|*)
            _warn "已取消"
            return
            ;;
    esac
}

# 检测并安装导入配置所需的软件和服务
_ensure_import_dependencies() {
    local file="$1"
    local need_xray=false
    local need_singbox=false
    local need_snell=false
    local need_snell_v5=false
    local need_shadowtls=false
    local need_anytls=false
    local need_naive=false
    
    # 检测需要哪些软件
    local xray_protos=$(jq -r '.database.xray | keys[]' "$file" 2>/dev/null)
    local singbox_protos=$(jq -r '.database.singbox | keys[]' "$file" 2>/dev/null)
    
    # Xray 协议检测
    for proto in $xray_protos; do
        case "$proto" in
            vless|vless-xhttp|vless-ws|vmess-ws|vless-vision|trojan|socks|ss2022|ss-legacy)
                need_xray=true
                ;;
        esac
    done
    
    # Sing-box 协议检测
    for proto in $singbox_protos; do
        case "$proto" in
            hy2|tuic)
                need_singbox=true
                ;;
            snell)
                need_snell=true
                ;;
            snell-v5)
                need_snell_v5=true
                ;;
            snell-shadowtls)
                need_snell=true
                need_shadowtls=true
                ;;
            snell-v5-shadowtls)
                need_snell_v5=true
                need_shadowtls=true
                ;;
            ss2022-shadowtls)
                need_xray=true
                need_shadowtls=true
                ;;
            anytls)
                need_anytls=true
                ;;
            naive)
                need_naive=true
                ;;
        esac
    done
    
    # 安装系统依赖
    echo -e "  ${C}▸${NC} 检查系统依赖..."
    install_deps || { _err "系统依赖安装失败"; return 1; }
    
    # 安装所需软件
    if [[ "$need_xray" == "true" ]]; then
        if ! check_cmd xray; then
            echo -e "  ${C}▸${NC} 安装 Xray..."
            install_xray || { _err "Xray 安装失败"; return 1; }
        else
            _ok "Xray 已安装"
        fi
    fi
    
    if [[ "$need_singbox" == "true" ]]; then
        if ! check_cmd sing-box; then
            echo -e "  ${C}▸${NC} 安装 Sing-box..."
            install_singbox || { _err "Sing-box 安装失败"; return 1; }
        else
            _ok "Sing-box 已安装"
        fi
    fi
    
    if [[ "$need_snell" == "true" ]]; then
        if ! check_cmd snell-server; then
            echo -e "  ${C}▸${NC} 安装 Snell v4..."
            install_snell || { _err "Snell 安装失败"; return 1; }
        else
            _ok "Snell v4 已安装"
        fi
    fi
    
    if [[ "$need_snell_v5" == "true" ]]; then
        if ! check_cmd snell-server-v5; then
            echo -e "  ${C}▸${NC} 安装 Snell v5..."
            install_snell_v5 || { _err "Snell v5 安装失败"; return 1; }
        else
            _ok "Snell v5 已安装"
        fi
    fi
    
    if [[ "$need_shadowtls" == "true" ]]; then
        if ! check_cmd shadow-tls; then
            echo -e "  ${C}▸${NC} 安装 ShadowTLS..."
            install_shadowtls || { _err "ShadowTLS 安装失败"; return 1; }
        else
            _ok "ShadowTLS 已安装"
        fi
    fi
    
    if [[ "$need_anytls" == "true" ]]; then
        if ! check_cmd anytls-server; then
            echo -e "  ${C}▸${NC} 安装 AnyTLS..."
            install_anytls || { _err "AnyTLS 安装失败"; return 1; }
        else
            _ok "AnyTLS 已安装"
        fi
    fi
    
    if [[ "$need_naive" == "true" ]]; then
        if ! check_cmd caddy; then
            echo -e "  ${C}▸${NC} 安装 NaïveProxy (Caddy)..."
            install_naive || { _err "NaïveProxy 安装失败"; return 1; }
        else
            _ok "NaïveProxy 已安装"
        fi
    fi
    
    return 0
}

# 创建导入配置所需的服务文件
_create_import_services() {
    echo -e "  ${C}▸${NC} 创建服务文件..."
    
    # 获取已导入的协议
    local xray_protocols=$(get_xray_protocols)
    local singbox_protocols=$(get_singbox_protocols)
    local standalone_protocols=$(get_standalone_protocols)
    
    # 创建 Xray 服务文件
    if [[ -n "$xray_protocols" ]]; then
        local service_name="vless-reality"
        local exec_cmd="/usr/local/bin/xray run -c $CFG/config.json"
        
        if [[ "$DISTRO" == "alpine" ]]; then
            cat > "/etc/init.d/${service_name}" << EOF
#!/sbin/openrc-run
name="Xray Proxy Server"
command="/usr/local/bin/xray"
command_args="run -c $CFG/config.json"
command_background="yes"
pidfile="/run/${service_name}.pid"
depend() { need net; }
EOF
            chmod +x "/etc/init.d/${service_name}"
        else
            cat > "/etc/systemd/system/${service_name}.service" << EOF
[Unit]
Description=Xray Proxy Server
After=network.target

[Service]
Type=simple
ExecStart=${exec_cmd}
Restart=always
RestartSec=3
LimitNOFILE=51200

[Install]
WantedBy=multi-user.target
EOF
            systemctl daemon-reload
        fi
        _ok "Xray 服务文件已创建"
    fi
    
    # 创建 Sing-box 服务文件
    if [[ -n "$singbox_protocols" ]]; then
        create_singbox_service
        _ok "Sing-box 服务文件已创建"
    fi
    
    # 创建独立协议服务文件
    for proto in $standalone_protocols; do
        create_service "$proto" 2>/dev/null && _ok "${proto} 服务文件已创建"
    done
    
    # 创建 watchdog 服务
    _create_watchdog_service
    
    # 创建快捷命令
    echo -e "  ${C}▸${NC} 创建快捷命令..."
    create_shortcut
    _ok "快捷命令 'vless' 已创建"
}

# 创建 watchdog 服务
_create_watchdog_service() {
    # 生成 watchdog 脚本
    cat > "$CFG/watchdog.sh" << 'EOFWD'
#!/bin/bash
CFG="/etc/vless-reality"
LOG="/var/log/vless-watchdog.log"
check_and_restart() {
    local svc="$1" proc="$2"
    if ! pgrep -x "$proc" >/dev/null 2>&1; then
        echo "[$(date)] $svc 进程不存在，尝试重启..." >> "$LOG"
        if [[ -f /etc/alpine-release ]]; then
            rc-service "$svc" restart
        else
            systemctl restart "$svc"
        fi
    fi
}
while true; do
    [[ -f "$CFG/config.json" ]] && check_and_restart "vless-reality" "xray"
    [[ -f "$CFG/singbox.json" ]] && check_and_restart "vless-singbox" "sing-box"
    sleep 60
done
EOFWD
    chmod +x "$CFG/watchdog.sh"
    
    if [[ "$DISTRO" == "alpine" ]]; then
        cat > "/etc/init.d/vless-watchdog" << EOF
#!/sbin/openrc-run
name="VLESS Watchdog"
command="/bin/bash"
command_args="$CFG/watchdog.sh"
command_background="yes"
pidfile="/run/vless-watchdog.pid"
depend() { need net; }
EOF
        chmod +x "/etc/init.d/vless-watchdog"
    else
        cat > "/etc/systemd/system/vless-watchdog.service" << EOF
[Unit]
Description=VLESS Watchdog
After=network.target

[Service]
Type=simple
ExecStart=$CFG/watchdog.sh
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload
    fi
}

# 导入全部配置
_import_all() {
    local file="$1"
    
    echo ""
    echo -e "  ${C}▸${NC} 备份当前配置..."
    [[ -f "$DB_FILE" ]] && cp "$DB_FILE" "${DB_FILE}.import_backup"
    
    # 检测并安装所需软件
    echo -e "  ${C}▸${NC} 检测所需软件..."
    if ! _ensure_import_dependencies "$file"; then
        _err "依赖安装失败，导入中止"
        # 恢复备份
        [[ -f "${DB_FILE}.import_backup" ]] && mv "${DB_FILE}.import_backup" "$DB_FILE"
        return 1
    fi
    
    echo -e "  ${C}▸${NC} 导入数据库..."
    local new_db=$(jq '.database' "$file")
    echo "$new_db" | jq . > "$DB_FILE"
    
    # 更新 IP 地址和地区代码
    _update_config_ips
    
    # 创建服务文件
    _create_import_services
    
    # 重新生成配置文件
    echo -e "  ${C}▸${NC} 重新生成服务配置..."
    generate_xray_config 2>/dev/null
    generate_singbox_config 2>/dev/null
    
    # 重新生成 join 文件（使用新的 IP 和地区代码）
    echo -e "  ${C}▸${NC} 重新生成分享链接..."
    _regenerate_all_join_files
    
    _ok "配置导入完成"
    echo -e "  ${D}原配置已备份到: ${DB_FILE}.import_backup${NC}"
    echo ""
    _warn "请重启服务使配置生效"
    echo -e "  ${D}运行: vless -> 管理协议服务 -> 重启所有服务${NC}"
}

# 重新生成所有协议的 join 文件
_regenerate_all_join_files() {
    local ipv4=$(get_ipv4)
    local ipv6=$(get_ipv6)
    local country=$(get_ip_country "$ipv4")
    [[ -z "$country" ]] && country=$(get_ip_country "$ipv6")
    [[ -z "$country" || "$country" == "XX" ]] && country=""
    
    # 遍历所有 xray 协议
    for proto in $(jq -r '.xray | keys[]' "$DB_FILE" 2>/dev/null); do
        local cfg=$(db_get "xray" "$proto")
        [[ -z "$cfg" ]] && continue
        
        local uuid=$(echo "$cfg" | jq -r '.uuid // empty')
        local port=$(echo "$cfg" | jq -r '.port // empty')
        local sni=$(echo "$cfg" | jq -r '.sni // empty')
        local public_key=$(echo "$cfg" | jq -r '.public_key // empty')
        local short_id=$(echo "$cfg" | jq -r '.short_id // empty')
        local path=$(echo "$cfg" | jq -r '.path // empty')
        local password=$(echo "$cfg" | jq -r '.password // empty')
        local method=$(echo "$cfg" | jq -r '.method // empty')
        
        case "$proto" in
            vless)
                _save_join_info "vless" "REALITY|%s|$port|$uuid|$public_key|$short_id|$sni" \
                    "gen_vless_link %s $port $uuid $public_key $short_id $sni $country"
                ;;
            vless-xhttp)
                _save_join_info "vless-xhttp" "REALITY-XHTTP|%s|$port|$uuid|$public_key|$short_id|$sni|$path" \
                    "gen_vless_xhttp_link %s $port $uuid $public_key $short_id $sni $path $country"
                ;;
            vless-ws)
                local outer_port=$(_get_master_port "$port")
                _save_join_info "vless-ws" "VLESS-WS|%s|$outer_port|$uuid|$sni|$path" \
                    "gen_vless_ws_link %s $outer_port $uuid $sni $path $country"
                ;;
            vmess-ws)
                local outer_port=$(_get_master_port "$port")
                _save_join_info "vmess-ws" "VMESSWS|%s|$outer_port|$uuid|$sni|$path" \
                    "gen_vmess_ws_link %s $outer_port $uuid $sni $path $country"
                ;;
            vless-vision)
                _save_join_info "vless-vision" "VLESS-VISION|%s|$port|$uuid|$sni" \
                    "gen_vless_vision_link %s $port $uuid $sni $country"
                ;;
            trojan)
                _save_join_info "trojan" "TROJAN|%s|$port|$password|$sni" \
                    "gen_trojan_link %s $port $password $sni $country"
                ;;
            ss2022)
                _save_join_info "ss2022" "SS2022|%s|$port|$method|$password" \
                    "gen_ss2022_link %s $port $method $password $country"
                ;;
        esac
    done
    
    # 遍历 singbox 协议
    for proto in $(jq -r '.singbox | keys[]' "$DB_FILE" 2>/dev/null); do
        local cfg=$(db_get "singbox" "$proto")
        [[ -z "$cfg" ]] && continue
        
        local port=$(echo "$cfg" | jq -r '.port // empty')
        local password=$(echo "$cfg" | jq -r '.password // empty')
        local sni=$(echo "$cfg" | jq -r '.sni // empty')
        
        case "$proto" in
            hy2)
                _save_join_info "hy2" "HY2|%s|$port|$password|$sni" \
                    "gen_hy2_link %s $port $password $sni $country"
                ;;
        esac
    done
}

# 导入协议配置
_import_protocols() {
    local file="$1"
    
    echo ""
    
    # 检测并安装所需软件
    echo -e "  ${C}▸${NC} 检测所需软件..."
    if ! _ensure_import_dependencies "$file"; then
        _err "依赖安装失败，导入中止"
        return 1
    fi
    
    echo -e "  ${C}▸${NC} 导入协议配置..."
    
    # 导入 xray 协议
    local xray_protos=$(jq -r '.database.xray | keys[]' "$file" 2>/dev/null)
    for proto in $xray_protos; do
        local cfg=$(jq ".database.xray[\"$proto\"]" "$file")
        db_add "xray" "$proto" "$cfg"
        echo -e "    + $proto"
    done
    
    # 导入 singbox 协议
    local singbox_protos=$(jq -r '.database.singbox | keys[]' "$file" 2>/dev/null)
    for proto in $singbox_protos; do
        local cfg=$(jq ".database.singbox[\"$proto\"]" "$file")
        db_add "singbox" "$proto" "$cfg"
        echo -e "    + $proto"
    done
    
    # 更新 IP 和地区代码
    _update_config_ips
    
    # 创建服务文件
    _create_import_services
    
    # 重新生成配置
    generate_xray_config 2>/dev/null
    generate_singbox_config 2>/dev/null
    
    # 重新生成 join 文件
    echo -e "  ${C}▸${NC} 重新生成分享链接..."
    _regenerate_all_join_files
    
    _ok "协议配置导入完成"
}

# 导入分流规则
_import_routing_rules() {
    local file="$1"
    
    echo ""
    read -rp "  是否清空现有分流规则? [y/N]: " clear_rules
    
    if [[ "$clear_rules" =~ ^[Yy]$ ]]; then
        db_clear_routing_rules
        echo -e "  ${C}▸${NC} 已清空现有规则"
    fi
    
    echo -e "  ${C}▸${NC} 导入分流规则..."
    
    local rules=$(jq '.database.routing_rules // []' "$file")
    local count=$(echo "$rules" | jq 'length')
    
    if [[ "$count" -gt 0 ]]; then
        local tmp=$(mktemp)
        if [[ "$clear_rules" =~ ^[Yy]$ ]]; then
            jq --argjson rules "$rules" '.routing_rules = $rules' "$DB_FILE" > "$tmp" && mv "$tmp" "$DB_FILE"
        else
            jq --argjson rules "$rules" '.routing_rules = ((.routing_rules // []) + $rules)' "$DB_FILE" > "$tmp" && mv "$tmp" "$DB_FILE"
        fi
        
        # 重新生成配置
        generate_xray_config 2>/dev/null
        generate_singbox_config 2>/dev/null
        
        _ok "导入 $count 条分流规则"
    else
        _warn "配置文件中没有分流规则"
    fi
}

# 导入外部节点
_import_chain_nodes() {
    local file="$1"
    
    echo ""
    echo -e "  ${C}▸${NC} 导入外部节点..."
    
    local nodes=$(jq '.database.chain_proxy.nodes // []' "$file")
    local count=$(echo "$nodes" | jq 'length')
    
    if [[ "$count" -eq 0 ]]; then
        _warn "配置文件中没有外部节点"
        return
    fi
    
    local imported=0
    while IFS= read -r node_name; do
        [[ -z "$node_name" ]] && continue
        
        # 检查是否已存在
        if db_chain_node_exists "$node_name"; then
            echo -e "    ${Y}!${NC} $node_name (已存在，跳过)"
            continue
        fi
        
        local node_json=$(echo "$nodes" | jq --arg name "$node_name" '.[] | select(.name == $name)')
        db_add_chain_node "$node_json"
        echo -e "    ${G}+${NC} $node_name"
        ((imported++))
    done < <(echo "$nodes" | jq -r '.[].name')
    
    _ok "导入 $imported 个外部节点"
}

# 选择性导入
_import_selective() {
    local file="$1"
    
    echo ""
    echo -e "  ${W}选择性导入${NC}"
    
    # 协议
    local xray_protos=$(jq -r '.database.xray | keys[]' "$file" 2>/dev/null)
    local singbox_protos=$(jq -r '.database.singbox | keys[]' "$file" 2>/dev/null)
    
    for proto in $xray_protos; do
        read -rp "  导入协议 $proto? [Y/n]: " confirm
        if [[ ! "$confirm" =~ ^[Nn]$ ]]; then
            local cfg=$(jq ".database.xray[\"$proto\"]" "$file")
            db_add "xray" "$proto" "$cfg"
            echo -e "    ${G}+${NC} $proto"
        fi
    done
    
    for proto in $singbox_protos; do
        read -rp "  导入协议 $proto? [Y/n]: " confirm
        if [[ ! "$confirm" =~ ^[Nn]$ ]]; then
            local cfg=$(jq ".database.singbox[\"$proto\"]" "$file")
            db_add "singbox" "$proto" "$cfg"
            echo -e "    ${G}+${NC} $proto"
        fi
    done
    
    # 分流规则
    local rules_count=$(jq '.database.routing_rules | length' "$file" 2>/dev/null || echo 0)
    if [[ "$rules_count" -gt 0 ]]; then
        read -rp "  导入 $rules_count 条分流规则? [Y/n]: " confirm
        if [[ ! "$confirm" =~ ^[Nn]$ ]]; then
            _import_routing_rules "$file"
        fi
    fi
    
    # 外部节点
    local nodes_count=$(jq '.database.chain_proxy.nodes | length' "$file" 2>/dev/null || echo 0)
    if [[ "$nodes_count" -gt 0 ]]; then
        read -rp "  导入 $nodes_count 个外部节点? [Y/n]: " confirm
        if [[ ! "$confirm" =~ ^[Nn]$ ]]; then
            _import_chain_nodes "$file"
        fi
    fi
    
    # 更新 IP 并重新生成配置
    _update_config_ips
    generate_xray_config 2>/dev/null
    generate_singbox_config 2>/dev/null
    
    _ok "选择性导入完成"
}

# 更新配置中的 IP 地址和地区代码
_update_config_ips() {
    echo -e "  ${C}▸${NC} 更新 IP 地址..."
    
    local new_ipv4=$(get_ipv4)
    local new_ipv6=$(get_ipv6)
    
    [[ -z "$new_ipv4" && -z "$new_ipv6" ]] && { _warn "无法获取当前 IP"; return 1; }
    
    echo -e "    IPv4: ${new_ipv4:-无}"
    echo -e "    IPv6: ${new_ipv6:-无}"
    
    # 获取新的地区代码
    echo -e "  ${C}▸${NC} 检测服务器地区..."
    local new_country=""
    if [[ -n "$new_ipv4" ]]; then
        new_country=$(get_ip_country "$new_ipv4")
    elif [[ -n "$new_ipv6" ]]; then
        new_country=$(get_ip_country "$new_ipv6")
    fi
    [[ -z "$new_country" || "$new_country" == "XX" ]] && new_country="XX"
    echo -e "    地区: ${G}${new_country}${NC}"
    
    # 更新数据库中所有协议的 IP
    local tmp=$(mktemp)
    
    # 更新 xray 协议的 IP
    for proto in $(jq -r '.xray | keys[]' "$DB_FILE" 2>/dev/null); do
        if [[ -n "$new_ipv4" ]]; then
            jq --arg p "$proto" --arg ip "$new_ipv4" '.xray[$p].ipv4 = $ip' "$DB_FILE" > "$tmp" && mv "$tmp" "$DB_FILE"
        fi
        if [[ -n "$new_ipv6" ]]; then
            jq --arg p "$proto" --arg ip "$new_ipv6" '.xray[$p].ipv6 = $ip' "$DB_FILE" > "$tmp" && mv "$tmp" "$DB_FILE"
        fi
    done
    
    # 更新 singbox 协议的 IP
    for proto in $(jq -r '.singbox | keys[]' "$DB_FILE" 2>/dev/null); do
        if [[ -n "$new_ipv4" ]]; then
            jq --arg p "$proto" --arg ip "$new_ipv4" '.singbox[$p].ipv4 = $ip' "$DB_FILE" > "$tmp" && mv "$tmp" "$DB_FILE"
        fi
        if [[ -n "$new_ipv6" ]]; then
            jq --arg p "$proto" --arg ip "$new_ipv6" '.singbox[$p].ipv6 = $ip' "$DB_FILE" > "$tmp" && mv "$tmp" "$DB_FILE"
        fi
    done
    
    # 更新 join 文件中的地区前缀
    if [[ -n "$new_country" && "$new_country" != "XX" ]]; then
        echo -e "  ${C}▸${NC} 更新节点名称地区前缀..."
        _update_join_files_country "$new_country" "$new_ipv4" "$new_ipv6"
    fi
    
    rm -f "$tmp"
}

# 更新 join 文件中的地区前缀
_update_join_files_country() {
    local new_country="$1"
    local new_ipv4="$2"
    local new_ipv6="$3"
    
    # 常见地区代码列表
    local country_codes="HK|TW|JP|KR|SG|US|UK|DE|FR|NL|AU|CA|IN|RU|BR|XX"
    
    # 遍历所有 join 文件并更新
    for join_file in "$CFG"/*.join; do
        [[ ! -f "$join_file" ]] && continue
        
        local tmp=$(mktemp)
        # 替换节点名称中的地区前缀 (如 HK-VLESS -> US-VLESS)
        sed -E "s/(#|%23)(${country_codes})-/\1${new_country}-/g" "$join_file" > "$tmp" && mv "$tmp" "$join_file"
    done
    
    # 同时更新 join.txt
    if [[ -f "$CFG/join.txt" ]]; then
        local tmp=$(mktemp)
        sed -E "s/(#|%23)(${country_codes})-/\1${new_country}-/g" "$CFG/join.txt" > "$tmp" && mv "$tmp" "$CFG/join.txt"
    fi
    
    _ok "节点名称已更新为 ${new_country} 前缀"
}

# 自动检测并更换 IP
auto_update_ip() {
    _header
    echo -e "  ${W}自动检测更换 IP${NC}"
    _line
    
    echo -e "  ${C}▸${NC} 获取当前公网 IP..."
    local current_ipv4=$(get_ipv4)
    local current_ipv6=$(get_ipv6)
    
    echo -e "  当前 IPv4: ${current_ipv4:-${R}无${NC}}"
    echo -e "  当前 IPv6: ${current_ipv6:-${R}无${NC}}"
    echo ""
    
    [[ -z "$current_ipv4" && -z "$current_ipv6" ]] && { _err "无法获取公网 IP"; return 1; }
    
    # 获取数据库中存储的 IP
    local stored_ipv4="" stored_ipv6=""
    
    # 从第一个协议获取存储的 IP
    local first_proto=$(jq -r '.xray | keys[0] // empty' "$DB_FILE" 2>/dev/null)
    if [[ -n "$first_proto" ]]; then
        stored_ipv4=$(db_get_field "xray" "$first_proto" "ipv4")
        stored_ipv6=$(db_get_field "xray" "$first_proto" "ipv6")
    fi
    
    echo -e "  ${C}▸${NC} 检测 IP 变化..."
    echo -e "  存储 IPv4: ${stored_ipv4:-${D}无${NC}}"
    echo -e "  存储 IPv6: ${stored_ipv6:-${D}无${NC}}"
    echo ""
    
    local ip_changed=false
    
    if [[ -n "$current_ipv4" && "$current_ipv4" != "$stored_ipv4" ]]; then
        echo -e "  ${Y}!${NC} IPv4 已变化: $stored_ipv4 -> $current_ipv4"
        ip_changed=true
    fi
    
    if [[ -n "$current_ipv6" && "$current_ipv6" != "$stored_ipv6" ]]; then
        echo -e "  ${Y}!${NC} IPv6 已变化: $stored_ipv6 -> $current_ipv6"
        ip_changed=true
    fi
    
    if [[ "$ip_changed" == "false" ]]; then
        _ok "IP 地址未发生变化"
        return 0
    fi
    
    echo ""
    read -rp "  是否更新配置中的 IP 地址? [Y/n]: " confirm
    
    if [[ "$confirm" =~ ^[Nn]$ ]]; then
        _warn "已取消"
        return
    fi
    
    # 更新 IP
    _update_config_ips
    
    # 重新生成配置
    echo -e "  ${C}▸${NC} 重新生成服务配置..."
    generate_xray_config 2>/dev/null
    generate_singbox_config 2>/dev/null
    
    # 重新生成 JOIN 信息
    echo -e "  ${C}▸${NC} 更新节点链接..."
    _regenerate_all_join_files
    
    _ok "IP 地址更新完成"
    echo ""
    _warn "请重启服务使配置生效"
}

# 重新生成所有 JOIN 文件
_regenerate_all_join_files() {
    local protocols=$(get_installed_protocols)
    for proto in $protocols; do
        # 调用对应协议的 JOIN 生成函数 (如果存在)
        local gen_func="gen_${proto//-/_}_join"
        if type "$gen_func" &>/dev/null; then
            $gen_func 2>/dev/null
        fi
    done
}

# 配置管理主菜单
manage_config() {
    while true; do
        _header
        echo -e "  ${W}配置管理${NC}"
        _line
        
        # 显示当前配置概览
        local proto_count=$(get_installed_protocols | wc -l)
        local rules_count=$(jq '.routing_rules | length' "$DB_FILE" 2>/dev/null || echo 0)
        local nodes_count=$(jq '.chain_proxy.nodes | length' "$DB_FILE" 2>/dev/null || echo 0)
        
        echo -e "  已安装协议: ${G}$proto_count${NC} 个"
        echo -e "  分流规则:   ${G}$rules_count${NC} 条"
        echo -e "  外部节点:   ${G}$nodes_count${NC} 个"
        _line
        
        _item "1" "导出配置"
        _item "2" "导入配置"
        _item "3" "自动检测更换 IP"
        _item "4" "查看备份文件"
        _item "5" "清理旧备份"
        _item "0" "返回主菜单"
        _line
        
        read -rp "  请选择: " choice
        
        case "$choice" in
            1)
                export_config
                _pause
                ;;
            2)
                import_config
                _pause
                ;;
            3)
                auto_update_ip
                _pause
                ;;
            4)
                _header
                echo -e "  ${W}备份文件列表${NC}"
                _line
                local backups=$(ls -lh "$CFG"/backup_*.json 2>/dev/null)
                if [[ -n "$backups" ]]; then
                    echo "$backups"
                else
                    echo -e "  ${D}暂无备份文件${NC}"
                fi
                _line
                _pause
                ;;
            5)
                _header
                echo -e "  ${W}清理旧备份${NC}"
                _line
                local backup_count=$(ls "$CFG"/backup_*.json 2>/dev/null | wc -l)
                if [[ $backup_count -eq 0 ]]; then
                    echo -e "  ${D}暂无备份文件${NC}"
                else
                    echo -e "  当前备份数量: $backup_count"
                    echo ""
                    read -rp "  保留最近几个备份? [3]: " keep_count
                    keep_count=${keep_count:-3}
                    
                    if [[ $backup_count -le $keep_count ]]; then
                        echo -e "  ${D}当前备份数量不超过 $keep_count，无需清理${NC}"
                    else
                        # 删除旧备份，保留最新的 N 个
                        ls -t "$CFG"/backup_*.json 2>/dev/null | tail -n +$((keep_count+1)) | while read -r f; do
                            rm -f "$f"
                            echo -e "  ${R}-${NC} 已删除: $(basename "$f")"
                        done
                        _ok "清理完成，保留最近 $keep_count 个备份"
                    fi
                fi
                _pause
                ;;
            0) return ;;
            *) _warn "无效选项" ;;
        esac
    done
}

# 分流管理主菜单
manage_routing() {
    while true; do
        _header
        echo -e "  ${W}分流管理${NC}"
        show_routing_status
        
        _item "1" "WARP 管理"
        _item "2" "链式代理"
        _item "3" "快速配置代理出口"
        _item "4" "配置分流规则"
        _item "5" "测试分流效果"
        _item "6" "查看当前配置"
        _item "0" "返回主菜单"
        _line
        
        read -rp "  请选择: " choice
        
        case "$choice" in
            1) manage_warp ;;
            2) manage_chain_proxy ;;
            3) add_quick_proxy ;;
            4) configure_routing_rules ;;
            5)
                _header
                echo -e "  ${W}测试分流效果${NC}"
                test_routing
                _pause
                ;;
            6)
                _header
                echo -e "  ${W}当前分流配置${NC}"
                _line
                local rules=$(db_get_routing_rules)
                if [[ -n "$rules" && "$rules" != "[]" ]]; then
                    echo "$rules" | jq .
                else
                    echo -e "  ${D}未配置分流规则${NC}"
                fi
                _line
                read -rp "  按回车返回..." _
                ;;
            0) return ;;
        esac
    done
}

# 快速配置代理出口 (SOCKS5/HTTP/SS)
add_quick_proxy() {
    _header
    echo -e "  ${W}快速配置代理出口${NC}"
    _line
    echo -e "  ${D}直接输入代理服务器信息，无需分享链接${NC}"
    echo ""
    
    _item "1" "SOCKS5 代理"
    _item "2" "HTTP 代理"
    _item "3" "Shadowsocks (SS)"
    _item "0" "返回"
    _line
    
    read -rp "  请选择代理类型: " proxy_type
    
    local type="" name="" server="" port="" username="" password="" method=""
    
    case "$proxy_type" in
        1) type="socks"; name="SOCKS5" ;;
        2) type="http"; name="HTTP" ;;
        3) type="shadowsocks"; name="SS" ;;
        0|"") return ;;
        *) _warn "无效选项"; return ;;
    esac
    
    echo ""
    echo -e "  ${Y}配置 ${name} 代理${NC}"
    _line
    
    # 输入服务器地址
    read -rp "  服务器地址: " server
    server=$(echo "$server" | tr -d ' \t')
    [[ -z "$server" ]] && { _warn "服务器地址不能为空"; return; }
    
    # 输入端口
    read -rp "  端口 [1080]: " port
    port=$(echo "$port" | tr -d ' \t')
    [[ -z "$port" ]] && port="1080"
    if ! [[ "$port" =~ ^[0-9]+$ ]] || [[ "$port" -lt 1 || "$port" -gt 65535 ]]; then
        _warn "端口无效"; return
    fi
    
    # SS 需要加密方式和密码
    if [[ "$type" == "shadowsocks" ]]; then
        echo ""
        echo -e "  ${D}加密方式:${NC}"
        echo -e "  ${D}1) aes-256-gcm  2) aes-128-gcm  3) chacha20-ietf-poly1305${NC}"
        echo -e "  ${D}4) 2022-blake3-aes-256-gcm  5) 2022-blake3-aes-128-gcm${NC}"
        read -rp "  选择加密方式 [1]: " method_choice
        case "$method_choice" in
            2) method="aes-128-gcm" ;;
            3) method="chacha20-ietf-poly1305" ;;
            4) method="2022-blake3-aes-256-gcm" ;;
            5) method="2022-blake3-aes-128-gcm" ;;
            *) method="aes-256-gcm" ;;
        esac
        
        read -rp "  密码: " password
        [[ -z "$password" ]] && { _warn "密码不能为空"; return; }
    else
        # SOCKS5/HTTP 可选用户名密码
        echo ""
        echo -e "  ${D}认证信息 (可选，直接回车跳过)${NC}"
        read -rp "  用户名: " username
        if [[ -n "$username" ]]; then
            read -rp "  密码: " password
        fi
    fi
    
    # 生成节点名称
    local node_name="${name}-${server}:${port}"
    
    # 构建节点 JSON
    local node_json=""
    if [[ "$type" == "shadowsocks" ]]; then
        node_json=$(jq -n \
            --arg name "$node_name" \
            --arg type "$type" \
            --arg server "$server" \
            --argjson port "$port" \
            --arg method "$method" \
            --arg password "$password" \
            '{name:$name,type:$type,server:$server,port:$port,method:$method,password:$password}')
    elif [[ -n "$username" ]]; then
        node_json=$(jq -n \
            --arg name "$node_name" \
            --arg type "$type" \
            --arg server "$server" \
            --argjson port "$port" \
            --arg username "$username" \
            --arg password "$password" \
            '{name:$name,type:$type,server:$server,port:$port,username:$username,password:$password}')
    else
        node_json=$(jq -n \
            --arg name "$node_name" \
            --arg type "$type" \
            --arg server "$server" \
            --argjson port "$port" \
            '{name:$name,type:$type,server:$server,port:$port}')
    fi
    
    # 检查是否已存在同名节点
    if db_chain_node_exists "$node_name"; then
        read -rp "  节点已存在，是否覆盖? [y/N]: " overwrite
        if [[ "$overwrite" =~ ^[Yy]$ ]]; then
            db_del_chain_node "$node_name"
        else
            return
        fi
    fi
    
    # 保存节点
    if db_add_chain_node "$node_json"; then
        _ok "代理节点已添加: $node_name"
        
        # 询问是否立即启用
        read -rp "  是否立即启用此节点作为分流出口? [Y/n]: " enable_now
        if [[ ! "$enable_now" =~ ^[Nn]$ ]]; then
            db_set_chain_active "$node_name"
            _ok "已启用节点: $node_name"
            
            # 询问是否配置分流规则
            local rules=$(db_get_routing_rules)
            if [[ -z "$rules" || "$rules" == "[]" ]]; then
                echo ""
                read -rp "  是否现在配置分流规则? [Y/n]: " config_rules
                if [[ ! "$config_rules" =~ ^[Nn]$ ]]; then
                    configure_routing_rules
                    return
                fi
            else
                # 已有分流规则，更新配置
                _info "更新代理配置..."
                _regenerate_proxy_configs
                _ok "配置已更新"
            fi
        fi
    else
        _err "添加节点失败"
    fi
    
    _pause
}


#═══════════════════════════════════════════════════════════════════════════════
# 链式代理转发
#═══════════════════════════════════════════════════════════════════════════════

# 检测节点延迟和解析 IP
# 用法: check_node_latency "server" "port"
# 返回: "延迟ms|IP" 或 "超时|-"
check_node_latency() {
    local server="$1" port="$2"
    local resolved_ip="" latency=""
    local is_ipv6=false
    
    # 判断地址类型
    if [[ "$server" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        # IPv4 地址
        resolved_ip="$server"
    elif [[ "$server" =~ : ]]; then
        # IPv6 地址 (包含冒号)
        resolved_ip="$server"
        is_ipv6=true
    else
        # 域名，尝试解析
        resolved_ip=$(dig +short "$server" A 2>/dev/null | grep -E '^[0-9]+\.' | head -1)
        if [[ -z "$resolved_ip" ]]; then
            # 尝试解析 IPv6
            resolved_ip=$(dig +short "$server" AAAA 2>/dev/null | grep -E ':' | head -1)
            [[ -n "$resolved_ip" ]] && is_ipv6=true
        fi
        [[ -z "$resolved_ip" ]] && resolved_ip=$(host "$server" 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -1)
    fi
    [[ -z "$resolved_ip" ]] && resolved_ip="-"
    
    # 测试 TCP 连接延迟
    local start_time end_time
    local connect_addr="$server"
    
    # IPv6 地址需要用方括号包裹
    if [[ "$is_ipv6" == "true" || "$server" =~ : ]]; then
        # 移除可能已有的方括号，再统一添加
        connect_addr="${server#[}"
        connect_addr="${connect_addr%]}"
        connect_addr="[$connect_addr]"
    fi
    
    start_time=$(date +%s%3N)
    # 优先用 nc，对 IPv6 支持更好
    if command -v nc &>/dev/null; then
        if timeout 3 nc -z -w 2 "$server" "$port" 2>/dev/null; then
            end_time=$(date +%s%3N)
            latency=$((end_time - start_time))
        else
            latency="超时"
        fi
    elif timeout 3 bash -c "echo >/dev/tcp/${connect_addr}/$port" 2>/dev/null; then
        end_time=$(date +%s%3N)
        latency=$((end_time - start_time))
    else
        latency="超时"
    fi
    
    echo "${latency}|${resolved_ip}"
}

# 数据库：链式代理节点操作
db_get_chain_nodes() { jq -r '.chain_proxy.nodes // []' "$DB_FILE" 2>/dev/null; }
db_get_chain_node() { jq -r --arg name "$1" '.chain_proxy.nodes[] | select(.name == $name)' "$DB_FILE" 2>/dev/null; }
db_get_chain_active() { jq -r '.chain_proxy.active // empty' "$DB_FILE" 2>/dev/null; }
db_set_chain_active() {
    local tmp=$(mktemp)
    jq --arg name "$1" '.chain_proxy.active = $name' "$DB_FILE" > "$tmp" && mv "$tmp" "$DB_FILE"
}
db_add_chain_node() {
    local node_json="$1"
    # 验证 JSON 格式
    if ! echo "$node_json" | jq empty 2>/dev/null; then
        return 1
    fi
    local tmp=$(mktemp)
    jq --argjson node "$node_json" '.chain_proxy.nodes = ((.chain_proxy.nodes // []) + [$node])' "$DB_FILE" > "$tmp" && mv "$tmp" "$DB_FILE"
}
db_del_chain_node() {
    local tmp=$(mktemp)
    jq --arg name "$1" '.chain_proxy.nodes = [.chain_proxy.nodes[] | select(.name != $name)]' "$DB_FILE" > "$tmp" && mv "$tmp" "$DB_FILE"
    # 如果删除的是当前激活节点，清空激活状态
    [[ "$(db_get_chain_active)" == "$1" ]] && jq 'del(.chain_proxy.active)' "$DB_FILE" > "$tmp" && mv "$tmp" "$DB_FILE"
}

# 检查链式代理节点是否存在 (返回 0=存在, 1=不存在)
db_chain_node_exists() {
    local name="$1"
    local result=$(jq -r --arg name "$name" '.chain_proxy.nodes[]? | select(.name == $name) | .name' "$DB_FILE" 2>/dev/null)
    [[ -n "$result" && "$result" != "null" ]]
}

# 解析代理链接 (支持 ss/vmess/vless/trojan)
parse_proxy_link() {
    local link="$1"
    local result=""
    
    case "$link" in
        ss://*)
            # SS 格式: ss://base64(method:password)@host:port#name 或 ss://base64#name
            local encoded="${link#ss://}"
            local name="" host="" port="" method="" password=""
            
            # 提取名称
            [[ "$encoded" == *"#"* ]] && { name=$(urldecode "$(echo "$encoded" | sed 's/.*#//')"); encoded="${encoded%%#*}"; }
            
            # 新格式: base64(method:password)@host:port
            if [[ "$encoded" == *"@"* ]]; then
                local userinfo="${encoded%%@*}"
                local hostport="${encoded#*@}"
                # 解码 userinfo
                local decoded=$(echo "$userinfo" | base64 -d 2>/dev/null)
                method="${decoded%%:*}"
                password="${decoded#*:}"
                host="${hostport%%:*}"
                port="${hostport##*:}"
            else
                # 旧格式: 整体 base64
                local decoded=$(echo "$encoded" | base64 -d 2>/dev/null)
                method=$(echo "$decoded" | cut -d: -f1)
                password=$(echo "$decoded" | cut -d: -f2 | cut -d@ -f1)
                host=$(echo "$decoded" | cut -d@ -f2 | cut -d: -f1)
                port=$(echo "$decoded" | cut -d: -f3)
            fi
            
            # 确保 port 是纯数字
            port=$(echo "$port" | tr -d '"' | tr -d ' ')
            [[ ! "$port" =~ ^[0-9]+$ ]] && return 1
            
            [[ -z "$name" ]] && name="SS-${host##*.}"
            [[ -n "$host" && -n "$port" ]] && result=$(jq -nc \
                --arg name "$name" --arg type "shadowsocks" --arg host "$host" \
                --argjson port "$port" --arg method "$method" --arg password "$password" \
                '{name:$name,type:$type,server:$host,port:$port,method:$method,password:$password}')
            ;;
        vmess://*)
            # VMess 格式: vmess://base64(json)
            local decoded=$(echo "${link#vmess://}" | base64 -d 2>/dev/null)
            [[ -z "$decoded" ]] && return 1
            
            local name=$(echo "$decoded" | jq -r '.ps // .name // "VMess"')
            local host=$(echo "$decoded" | jq -r '.add // .server')
            local port=$(echo "$decoded" | jq -r '.port')
            local uuid=$(echo "$decoded" | jq -r '.id // .uuid')
            local aid=$(echo "$decoded" | jq -r '.aid // 0')
            local net=$(echo "$decoded" | jq -r '.net // "tcp"')
            local tls=$(echo "$decoded" | jq -r '.tls // ""')
            local ws_path=$(echo "$decoded" | jq -r '.path // "/"')
            local ws_host=$(echo "$decoded" | jq -r '.host // ""')
            
            # 确保 port 和 aid 是纯数字
            port=$(echo "$port" | tr -d '"' | tr -d ' ')
            [[ ! "$port" =~ ^[0-9]+$ ]] && return 1
            aid=$(echo "$aid" | tr -d '"' | tr -d ' ')
            [[ ! "$aid" =~ ^[0-9]+$ ]] && aid=0
            
            [[ -n "$host" && -n "$port" && -n "$uuid" ]] && result=$(jq -nc \
                --arg name "$name" --arg host "$host" --argjson port "$port" \
                --arg uuid "$uuid" --argjson aid "$aid" --arg net "$net" \
                --arg tls "$tls" --arg path "$ws_path" --arg wshost "$ws_host" \
                '{name:$name,type:"vmess",server:$host,port:$port,uuid:$uuid,alterId:$aid,network:$net,tls:$tls,wsPath:$path,wsHost:$wshost}')
            ;;
        vless://*)
            # VLESS 格式: vless://uuid@host:port?params#name
            local content="${link#vless://}"
            local name="" uuid="" host="" port=""
            
            [[ "$content" == *"#"* ]] && { name=$(urldecode "$(echo "$content" | sed 's/.*#//')"); content="${content%%#*}"; }
            uuid="${content%%@*}"
            local hostpart="${content#*@}"
            hostpart="${hostpart%%\?*}"
            host="${hostpart%%:*}"
            port="${hostpart##*:}"
            
            # 确保 port 是纯数字
            port=$(echo "$port" | tr -d '"' | tr -d ' ')
            [[ ! "$port" =~ ^[0-9]+$ ]] && return 1
            
            # 解析参数
            local params="${content#*\?}"
            local security=$(echo "$params" | grep -oP 'security=\K[^&]+' || echo "none")
            local sni=$(echo "$params" | grep -oP 'sni=\K[^&]+' || echo "")
            local fp=$(echo "$params" | grep -oP 'fp=\K[^&]+' || echo "chrome")
            local net=$(echo "$params" | grep -oP 'type=\K[^&]+' || echo "tcp")
            local pbk=$(echo "$params" | grep -oP 'pbk=\K[^&]+' || echo "")
            local sid=$(echo "$params" | grep -oP 'sid=\K[^&]+' || echo "")
            local flow=$(echo "$params" | grep -oP 'flow=\K[^&]+' || echo "")
            local encryption=$(echo "$params" | grep -oP 'encryption=\K[^&]+' || echo "none")
            [[ -z "$encryption" ]] && encryption="none"
            
            [[ -z "$name" ]] && name="VLESS-${host##*.}"
            [[ -n "$host" && -n "$port" && -n "$uuid" ]] && result=$(jq -nc \
                --arg name "$name" --arg host "$host" --argjson port "$port" \
                --arg uuid "$uuid" --arg security "$security" --arg sni "$sni" \
                --arg fp "$fp" --arg net "$net" --arg pbk "$pbk" --arg sid "$sid" --arg flow "$flow" --arg enc "$encryption" \
                '{name:$name,type:"vless",server:$host,port:$port,uuid:$uuid,security:$security,sni:$sni,fingerprint:$fp,network:$net,publicKey:$pbk,shortId:$sid,flow:$flow,encryption:$enc}')
            ;;
        trojan://*)
            # Trojan 格式: trojan://password@host:port?params#name
            local content="${link#trojan://}"
            local name="" password="" host="" port=""
            
            [[ "$content" == *"#"* ]] && { name=$(urldecode "$(echo "$content" | sed 's/.*#//')"); content="${content%%#*}"; }
            password="${content%%@*}"
            local hostpart="${content#*@}"
            hostpart="${hostpart%%\?*}"
            host="${hostpart%%:*}"
            port="${hostpart##*:}"
            
            # 确保 port 是纯数字
            port=$(echo "$port" | tr -d '"' | tr -d ' ')
            [[ ! "$port" =~ ^[0-9]+$ ]] && return 1
            
            local params="${content#*\?}"
            local sni=$(echo "$params" | grep -oP 'sni=\K[^&]+' || echo "$host")
            
            [[ -z "$name" ]] && name="Trojan-${host##*.}"
            [[ -n "$host" && -n "$port" && -n "$password" ]] && result=$(jq -nc \
                --arg name "$name" --arg host "$host" --argjson port "$port" \
                --arg password "$password" --arg sni "$sni" \
                '{name:$name,type:"trojan",server:$host,port:$port,password:$password,sni:$sni}')
            ;;
        hy2://*|hysteria2://*)
            # Hysteria2 格式: hy2://password@host:port?params#name
            local content="${link#hy2://}"
            content="${content#hysteria2://}"
            local name="" password="" host="" port=""
            
            [[ "$content" == *"#"* ]] && { name=$(urldecode "$(echo "$content" | sed 's/.*#//')"); content="${content%%#*}"; }
            password="${content%%@*}"
            local hostpart="${content#*@}"
            hostpart="${hostpart%%\?*}"
            host="${hostpart%%:*}"
            port="${hostpart##*:}"
            
            # 确保 port 是纯数字
            port=$(echo "$port" | tr -d '"' | tr -d ' ')
            [[ ! "$port" =~ ^[0-9]+$ ]] && return 1
            
            local params="${content#*\?}"
            local sni=$(echo "$params" | grep -oP 'sni=\K[^&]+' || echo "$host")
            local insecure=$(echo "$params" | grep -oP 'insecure=\K[^&]+' || echo "0")
            
            [[ -z "$name" ]] && name="HY2-${host##*.}"
            [[ -n "$host" && -n "$port" && -n "$password" ]] && result=$(jq -nc \
                --arg name "$name" --arg host "$host" --argjson port "$port" \
                --arg password "$password" --arg sni "$sni" --arg insecure "$insecure" \
                '{name:$name,type:"hysteria2",server:$host,port:$port,password:$password,sni:$sni,insecure:$insecure}')
            ;;
    esac
    
    [[ -n "$result" ]] && echo "$result" || return 1
}

# 解析订阅链接
parse_subscription() {
    local url="$1"
    local content nodes=()
    
    _info "获取订阅内容..."
    content=$(curl -sL --connect-timeout 10 "$url" 2>/dev/null)
    [[ -z "$content" ]] && { _err "获取订阅失败"; return 1; }
    
    # 尝试 base64 解码
    local decoded=$(echo "$content" | base64 -d 2>/dev/null)
    [[ -n "$decoded" ]] && content="$decoded"
    
    # 按行解析
    local count=0
    while IFS= read -r line; do
        line=$(echo "$line" | tr -d '\r')
        [[ -z "$line" || "$line" == "#"* ]] && continue
        
        local node=$(parse_proxy_link "$line")
        if [[ -n "$node" ]]; then
            echo "$node"
            ((count++))
        fi
    done <<< "$content"
    
    [[ $count -eq 0 ]] && { _err "未解析到有效节点"; return 1; }
    _ok "解析到 $count 个节点"
}

# 生成 Xray 链式代理 outbound (支持指定节点名和自定义 tag)
# 用法: gen_xray_chain_outbound [节点名] [tag]
# 如果不传参数，使用当前激活的节点，tag 为 "chain"
gen_xray_chain_outbound() {
    local node_name="${1:-$(db_get_chain_active)}"
    local tag="${2:-chain}"
    [[ -z "$node_name" ]] && return
    
    local node=$(db_get_chain_node "$node_name")
    [[ -z "$node" ]] && return
    
    local type=$(echo "$node" | jq -r '.type')
    local server=$(echo "$node" | jq -r '.server')
    local port=$(echo "$node" | jq -r '.port')
    
    # 确保 port 是纯数字（去除可能的引号和空白）
    port=$(echo "$port" | tr -d '"' | tr -d ' ')
    [[ ! "$port" =~ ^[0-9]+$ ]] && { echo ""; return 1; }
    
    case "$type" in
        socks)
            local username=$(echo "$node" | jq -r '.username // ""')
            local password=$(echo "$node" | jq -r '.password // ""')
            if [[ -n "$username" && -n "$password" ]]; then
                jq -n --arg tag "$tag" --arg server "$server" --argjson port "$port" \
                    --arg user "$username" --arg pass "$password" \
                    '{tag:$tag,protocol:"socks",settings:{servers:[{address:$server,port:$port,users:[{user:$user,pass:$pass}]}]}}'
            else
                jq -n --arg tag "$tag" --arg server "$server" --argjson port "$port" \
                    '{tag:$tag,protocol:"socks",settings:{servers:[{address:$server,port:$port}]}}'
            fi
            ;;
        http)
            local username=$(echo "$node" | jq -r '.username // ""')
            local password=$(echo "$node" | jq -r '.password // ""')
            if [[ -n "$username" && -n "$password" ]]; then
                jq -n --arg tag "$tag" --arg server "$server" --argjson port "$port" \
                    --arg user "$username" --arg pass "$password" \
                    '{tag:$tag,protocol:"http",settings:{servers:[{address:$server,port:$port,users:[{user:$user,pass:$pass}]}]}}'
            else
                jq -n --arg tag "$tag" --arg server "$server" --argjson port "$port" \
                    '{tag:$tag,protocol:"http",settings:{servers:[{address:$server,port:$port}]}}'
            fi
            ;;
        shadowsocks)
            local method=$(echo "$node" | jq -r '.method')
            local password=$(echo "$node" | jq -r '.password')
            jq -n --arg tag "$tag" --arg server "$server" --argjson port "$port" \
                --arg method "$method" --arg password "$password" \
                '{tag:$tag,protocol:"shadowsocks",settings:{servers:[{address:$server,port:$port,method:$method,password:$password}]}}'
            ;;
        vmess)
            local uuid=$(echo "$node" | jq -r '.uuid')
            local aid=$(echo "$node" | jq -r '.alterId // 0')
            # 确保 aid 是数字
            aid=$(echo "$aid" | tr -d '"' | tr -d ' ')
            [[ ! "$aid" =~ ^[0-9]+$ ]] && aid=0
            local net=$(echo "$node" | jq -r '.network // "tcp"')
            local tls=$(echo "$node" | jq -r '.tls')
            local path=$(echo "$node" | jq -r '.wsPath // "/"')
            local wshost=$(echo "$node" | jq -r '.wsHost // ""')
            
            local stream='{"network":"tcp"}'
            [[ "$net" == "ws" ]] && stream=$(jq -n --arg net "$net" --arg path "$path" --arg host "$wshost" \
                '{network:$net,wsSettings:{path:$path,headers:{Host:$host}}}')
            [[ "$tls" == "tls" ]] && stream=$(echo "$stream" | jq --arg sni "$server" '.security="tls"|.tlsSettings={serverName:$sni}')
            
            jq -n --arg tag "$tag" --arg server "$server" --argjson port "$port" --arg uuid "$uuid" --argjson aid "$aid" --argjson stream "$stream" \
                '{tag:$tag,protocol:"vmess",settings:{vnext:[{address:$server,port:$port,users:[{id:$uuid,alterId:$aid}]}]},streamSettings:$stream}'
            ;;
        vless)
            local uuid=$(echo "$node" | jq -r '.uuid')
            local security=$(echo "$node" | jq -r '.security // "none"')
            local sni=$(echo "$node" | jq -r '.sni // ""')
            local fp=$(echo "$node" | jq -r '.fingerprint // "chrome"')
            local pbk=$(echo "$node" | jq -r '.publicKey // ""')
            local sid=$(echo "$node" | jq -r '.shortId // ""')
            local flow=$(echo "$node" | jq -r '.flow // ""')
            local encryption=$(echo "$node" | jq -r '.encryption // "none"')
            # 如果 encryption 为空，默认使用 none
            [[ -z "$encryption" ]] && encryption="none"
            
            local stream='{"network":"tcp"}'
            if [[ "$security" == "reality" ]]; then
                stream=$(jq -n --arg sni "$sni" --arg fp "$fp" --arg pbk "$pbk" --arg sid "$sid" \
                    '{network:"tcp",security:"reality",realitySettings:{serverName:$sni,fingerprint:$fp,publicKey:$pbk,shortId:$sid}}')
            elif [[ "$security" == "tls" ]]; then
                stream=$(jq -n --arg sni "$sni" --arg fp "$fp" \
                    '{network:"tcp",security:"tls",tlsSettings:{serverName:$sni,fingerprint:$fp}}')
            fi
            
            # 生成 outbound，如果有 flow 则添加
            if [[ -n "$flow" && "$flow" != "null" && "$flow" != "" ]]; then
                jq -n --arg tag "$tag" --arg server "$server" --argjson port "$port" --arg uuid "$uuid" --arg enc "$encryption" --arg flow "$flow" --argjson stream "$stream" \
                    '{tag:$tag,protocol:"vless",settings:{vnext:[{address:$server,port:$port,users:[{id:$uuid,encryption:$enc,flow:$flow}]}]},streamSettings:$stream}'
            else
                jq -n --arg tag "$tag" --arg server "$server" --argjson port "$port" --arg uuid "$uuid" --arg enc "$encryption" --argjson stream "$stream" \
                    '{tag:$tag,protocol:"vless",settings:{vnext:[{address:$server,port:$port,users:[{id:$uuid,encryption:$enc}]}]},streamSettings:$stream}'
            fi
            ;;
        trojan)
            local password=$(echo "$node" | jq -r '.password')
            local sni=$(echo "$node" | jq -r '.sni // ""')
            [[ -z "$sni" ]] && sni="$server"
            
            jq -n --arg tag "$tag" --arg server "$server" --argjson port "$port" --arg password "$password" --arg sni "$sni" \
                '{tag:$tag,protocol:"trojan",settings:{servers:[{address:$server,port:$port,password:$password}]},streamSettings:{network:"tcp",security:"tls",tlsSettings:{serverName:$sni}}}'
            ;;
    esac
}

# 生成 Sing-box 链式代理 outbound (支持指定节点名和自定义 tag)
# 用法: gen_singbox_chain_outbound [节点名] [tag]
gen_singbox_chain_outbound() {
    local node_name="${1:-$(db_get_chain_active)}"
    local tag="${2:-chain}"
    [[ -z "$node_name" ]] && return
    
    local node=$(db_get_chain_node "$node_name")
    [[ -z "$node" ]] && return
    
    local type=$(echo "$node" | jq -r '.type')
    local server=$(echo "$node" | jq -r '.server')
    local port=$(echo "$node" | jq -r '.port')
    
    # 优先使用 IPv4，IPv4 不通再尝试 IPv6
    local domain_strategy="prefer_ipv4"
    
    case "$type" in
        socks)
            local username=$(echo "$node" | jq -r '.username // ""')
            local password=$(echo "$node" | jq -r '.password // ""')
            if [[ -n "$username" && -n "$password" ]]; then
                jq -n --arg tag "$tag" --arg server "$server" --argjson port "$port" \
                    --arg user "$username" --arg pass "$password" --arg ds "$domain_strategy" \
                    '{tag:$tag,type:"socks",server:$server,server_port:$port,username:$user,password:$pass,domain_strategy:$ds}'
            else
                jq -n --arg tag "$tag" --arg server "$server" --argjson port "$port" --arg ds "$domain_strategy" \
                    '{tag:$tag,type:"socks",server:$server,server_port:$port,domain_strategy:$ds}'
            fi
            ;;
        http)
            local username=$(echo "$node" | jq -r '.username // ""')
            local password=$(echo "$node" | jq -r '.password // ""')
            if [[ -n "$username" && -n "$password" ]]; then
                jq -n --arg tag "$tag" --arg server "$server" --argjson port "$port" \
                    --arg user "$username" --arg pass "$password" --arg ds "$domain_strategy" \
                    '{tag:$tag,type:"http",server:$server,server_port:$port,username:$user,password:$pass,domain_strategy:$ds}'
            else
                jq -n --arg tag "$tag" --arg server "$server" --argjson port "$port" --arg ds "$domain_strategy" \
                    '{tag:$tag,type:"http",server:$server,server_port:$port,domain_strategy:$ds}'
            fi
            ;;
        shadowsocks)
            local method=$(echo "$node" | jq -r '.method')
            local password=$(echo "$node" | jq -r '.password')
            jq -n --arg tag "$tag" --arg server "$server" --argjson port "$port" --arg method "$method" --arg password "$password" --arg ds "$domain_strategy" \
                '{tag:$tag,type:"shadowsocks",server:$server,server_port:$port,method:$method,password:$password,domain_strategy:$ds}'
            ;;
        vmess)
            local uuid=$(echo "$node" | jq -r '.uuid')
            local aid=$(echo "$node" | jq -r '.alterId // 0')
            local tls=$(echo "$node" | jq -r '.tls')
            
            local base=$(jq -n --arg tag "$tag" --arg server "$server" --argjson port "$port" --arg uuid "$uuid" --argjson aid "$aid" --arg ds "$domain_strategy" \
                '{tag:$tag,type:"vmess",server:$server,server_port:$port,uuid:$uuid,alter_id:$aid,domain_strategy:$ds}')
            [[ "$tls" == "tls" ]] && base=$(echo "$base" | jq --arg sni "$server" '.tls={enabled:true,server_name:$sni}')
            echo "$base"
            ;;
        vless)
            local uuid=$(echo "$node" | jq -r '.uuid')
            local security=$(echo "$node" | jq -r '.security // "none"')
            local sni=$(echo "$node" | jq -r '.sni // ""')
            local fp=$(echo "$node" | jq -r '.fingerprint // "chrome"')
            local pbk=$(echo "$node" | jq -r '.publicKey // ""')
            local sid=$(echo "$node" | jq -r '.shortId // ""')
            
            local base=$(jq -n --arg tag "$tag" --arg server "$server" --argjson port "$port" --arg uuid "$uuid" --arg ds "$domain_strategy" \
                '{tag:$tag,type:"vless",server:$server,server_port:$port,uuid:$uuid,domain_strategy:$ds}')
            
            if [[ "$security" == "reality" ]]; then
                base=$(echo "$base" | jq --arg sni "$sni" --arg fp "$fp" --arg pbk "$pbk" --arg sid "$sid" \
                    '.tls={enabled:true,server_name:$sni,reality:{enabled:true,public_key:$pbk,short_id:$sid},utls:{enabled:true,fingerprint:$fp}}')
            elif [[ "$security" == "tls" ]]; then
                base=$(echo "$base" | jq --arg sni "$sni" '.tls={enabled:true,server_name:$sni}')
            fi
            echo "$base"
            ;;
        trojan)
            local password=$(echo "$node" | jq -r '.password')
            local sni=$(echo "$node" | jq -r '.sni // ""')
            [[ -z "$sni" ]] && sni="$server"
            
            jq -n --arg tag "$tag" --arg server "$server" --argjson port "$port" --arg password "$password" --arg sni "$sni" --arg ds "$domain_strategy" \
                '{tag:$tag,type:"trojan",server:$server,server_port:$port,password:$password,tls:{enabled:true,server_name:$sni},domain_strategy:$ds}'
            ;;
        hysteria2)
            local password=$(echo "$node" | jq -r '.password')
            local sni=$(echo "$node" | jq -r '.sni // ""')
            local insecure=$(echo "$node" | jq -r '.insecure // "0"')
            [[ -z "$sni" ]] && sni="$server"
            
            local base=$(jq -n --arg tag "$tag" --arg server "$server" --argjson port "$port" --arg password "$password" --arg sni "$sni" --arg ds "$domain_strategy" \
                '{tag:$tag,type:"hysteria2",server:$server,server_port:$port,password:$password,tls:{enabled:true,server_name:$sni},domain_strategy:$ds}')
            [[ "$insecure" == "1" ]] && base=$(echo "$base" | jq '.tls.insecure=true')
            echo "$base"
            ;;
    esac
}

# 添加节点交互 (带解析预览和自定义名称)
_add_chain_node_interactive() {
    _header
    echo -e "  ${W}添加代理节点${NC}"
    _line
    echo -e "  ${D}支持: ss/vmess/vless/trojan/hysteria2${NC}"
    echo ""
    
    echo -e "  ${Y}粘贴代理链接:${NC}"
    read -rp "  链接: " link
    [[ -z "$link" ]] && return
    
    # 解析链接
    echo ""
    echo -e "  ${C}▸${NC} 解析链接中..."
    local node=$(parse_proxy_link "$link")
    
    if [[ -z "$node" ]]; then
        _err "链接解析失败，请检查格式"
        _pause
        return
    fi
    
    # 提取节点信息
    local orig_name=$(echo "$node" | jq -r '.name // "未知"')
    local type=$(echo "$node" | jq -r '.type // "未知"')
    local server=$(echo "$node" | jq -r '.server // "未知"')
    local port=$(echo "$node" | jq -r '.port // "未知"')
    
    # 显示解析预览
    echo ""
    _line
    echo -e "  ${G}✓${NC} 解析成功"
    _line
    echo -e "  节点名称: ${C}$orig_name${NC}"
    echo -e "  协议类型: ${C}$type${NC}"
    echo -e "  服务器:   ${C}$server${NC}"
    echo -e "  端口:     ${C}$port${NC}"
    _line
    
    # 询问是否自定义名称
    echo ""
    echo -e "  ${D}直接回车使用原名称，或输入新名称${NC}"
    read -rp "  自定义名称 [$orig_name]: " custom_name
    
    local final_name="${custom_name:-$orig_name}"
    
    # 检查是否已存在同名节点
    if db_chain_node_exists "$final_name"; then
        echo ""
        _warn "节点 '$final_name' 已存在"
        read -rp "  是否覆盖? [y/N]: " overwrite
        if [[ ! "$overwrite" =~ ^[Yy]$ ]]; then
            _info "已取消"
            _pause
            return
        fi
        db_del_chain_node "$final_name"
    fi
    
    # 更新节点名称
    if [[ "$final_name" != "$orig_name" ]]; then
        node=$(echo "$node" | jq --arg name "$final_name" '.name = $name')
    fi
    
    # 保存节点
    if db_add_chain_node "$node"; then
        echo ""
        _ok "节点已添加: $final_name"
        
        # 询问是否立即配置分流
        echo ""
        read -rp "  是否立即将此节点用于分流? [y/N]: " use_now
        if [[ "$use_now" =~ ^[Yy]$ ]]; then
            configure_routing_rules
            return
        fi
    else
        _err "添加节点失败"
    fi
    
    _pause
}

# 导入订阅交互 (带预览确认)
_import_subscription_interactive() {
    _header
    echo -e "  ${W}导入订阅${NC}"
    _line
    
    echo -e "  ${Y}输入订阅链接:${NC}"
    read -rp "  URL: " sub_url
    [[ -z "$sub_url" ]] && return
    
    echo ""
    echo -e "  ${C}▸${NC} 获取订阅内容..."
    
    # 解析订阅
    local parsed_nodes=$(parse_subscription "$sub_url")
    
    if [[ -z "$parsed_nodes" ]]; then
        _err "订阅解析失败，请检查链接"
        _pause
        return
    fi
    
    # 统计节点数量和类型
    local total_count=0
    declare -A types
    
    while IFS= read -r node; do
        [[ -z "$node" ]] && continue
        if ! echo "$node" | jq empty 2>/dev/null; then
            continue
        fi
        ((total_count++))
        local t=$(echo "$node" | jq -r '.type // "unknown"' 2>/dev/null)
        [[ -z "$t" || "$t" == "null" ]] && t="unknown"
        ((types[$t]++))
    done <<< "$parsed_nodes"
    
    if [[ $total_count -eq 0 ]]; then
        _err "订阅中没有有效节点"
        _pause
        return
    fi
    
    # 显示协议统计
    echo ""
    _line
    echo -e "  ${G}✓${NC} 解析成功，共 ${C}$total_count${NC} 个节点"
    _line
    echo -e "  ${W}协议统计:${NC}"
    for t in "${!types[@]}"; do
        echo -e "    • $t: ${types[$t]} 个"
    done
    
    # 预览阶段：检测延迟并显示 (复用测试延迟的逻辑)
    echo ""
    echo -e "  ${C}▸${NC} 检测节点延迟中..."
    
    local tmp_results=$(mktemp)
    local tmp_nodes=$(mktemp)
    local i=0
    
    while IFS= read -r node; do
        [[ -z "$node" ]] && continue
        if ! echo "$node" | jq empty 2>/dev/null; then
            continue
        fi
        ((i++))
        
        local name=$(echo "$node" | jq -r '.name // "未知"' 2>/dev/null)
        local type=$(echo "$node" | jq -r '.type // "?"' 2>/dev/null)
        local server=$(echo "$node" | jq -r '.server // "?"' 2>/dev/null)
        local port=$(echo "$node" | jq -r '.port // 443' 2>/dev/null)
        
        # 检测延迟
        local result=$(check_node_latency "$server" "$port")
        local latency="${result%%|*}"
        local resolved_ip="${result##*|}"
        local latency_num=99999
        [[ "$latency" =~ ^[0-9]+$ ]] && latency_num="$latency"
        
        # 保存结果用于排序显示
        echo "${latency_num}|${latency}|${name}|${type}|${resolved_ip}" >> "$tmp_results"
        # 保存原始节点 JSON 用于后续导入
        echo "$node" >> "$tmp_nodes"
        
        printf "\r  ${C}▸${NC} 检测中... (%d/%d)  " "$i" "$total_count" >&2
    done <<< "$parsed_nodes"
    
    echo ""
    echo ""
    echo -e "  ${W}节点列表 (按延迟排序):${NC}"
    _line
    
    # 按延迟排序显示
    sort -t'|' -k1 -n "$tmp_results" | while IFS='|' read -r _ latency name type resolved_ip; do
        local latency_color="${G}"
        local display_name="$name"
        [[ ${#display_name} -gt 28 ]] && display_name="${display_name:0:25}..."
        
        if [[ "$latency" == "超时" ]]; then
            latency_color="${R}"
            echo -e "  [${latency_color}超时${NC}] $display_name ${D}($type)${NC} ${D}${resolved_ip}${NC}"
        elif [[ "$latency" =~ ^[0-9]+$ ]]; then
            [[ "$latency" -gt 300 ]] && latency_color="${Y}"
            [[ "$latency" -gt 1000 ]] && latency_color="${R}"
            echo -e "  [${latency_color}${latency}ms${NC}] $display_name ${D}($type)${NC} ${D}${resolved_ip}${NC}"
        fi
    done
    
    _line
    
    # 确认导入
    echo ""
    read -rp "  确认导入这 $total_count 个节点? [Y/n]: " confirm
    
    if [[ "$confirm" =~ ^[Nn]$ ]]; then
        _info "已取消导入"
        rm -f "$tmp_results" "$tmp_nodes"
        _pause
        return
    fi
    
    # 执行导入
    echo ""
    echo -e "  ${C}▸${NC} 正在导入..."
    
    local added=0
    local skipped=0
    local failed=0
    
    while IFS= read -r node; do
        [[ -z "$node" ]] && continue
        if ! echo "$node" | jq empty 2>/dev/null; then
            ((failed++))
            continue
        fi
        
        local name=$(echo "$node" | jq -r '.name' 2>/dev/null)
        
        # 检查是否已存在
        if db_chain_node_exists "$name"; then
            ((skipped++))
            continue
        fi
        
        if db_add_chain_node "$node"; then
            ((added++))
        else
            ((failed++))
        fi
    done < "$tmp_nodes"
    
    rm -f "$tmp_results" "$tmp_nodes"
    
    echo ""
    _ok "导入完成"
    echo -e "  新增: ${G}$added${NC} 个"
    [[ $skipped -gt 0 ]] && echo -e "  跳过 (已存在): ${Y}$skipped${NC} 个"
    [[ $failed -gt 0 ]] && echo -e "  失败: ${R}$failed${NC} 个"
    
    _pause
}

# 链式代理管理菜单
manage_chain_proxy() {
    while true; do
        _header
        echo -e "  ${W}链式代理管理${NC}"
        _line
        
        # 显示当前状态
        local nodes=$(db_get_chain_nodes)
        local node_count=$(echo "$nodes" | jq 'length' 2>/dev/null || echo 0)
        
        # 获取分流规则使用的节点
        local routing_rules=$(db_get_routing_rules)
        local routing_count=0
        local routing_nodes=""
        if [[ -n "$routing_rules" && "$routing_rules" != "[]" ]]; then
            while IFS= read -r line; do
                local r_type=$(echo "$line" | cut -d'|' -f1)
                local r_outbound=$(echo "$line" | cut -d'|' -f2)
                if [[ "$r_outbound" == chain:* ]]; then
                    local node_name="${r_outbound#chain:}"
                    routing_nodes+="    ${C}•${NC} ${node_name} ${D}← ${r_type}${NC}\n"
                    ((routing_count++))
                fi
            done < <(echo "$routing_rules" | jq -r '.[] | "\(.type)|\(.outbound)"')
        fi
        
        if [[ $routing_count -gt 0 ]]; then
            echo -e "  状态: ${G}● 分流已配置${NC} (${routing_count} 条规则)"
            echo -e "  使用节点:"
            echo -e "$routing_nodes"
        else
            echo -e "  状态: ${D}○ 未配置分流${NC}"
        fi
        echo -e "  节点总数: ${C}$node_count${NC}"
        _line
        
        _item "1" "添加节点 (分享链接)"
        _item "2" "导入订阅"
        _item "3" "测试所有节点延迟"
        _item "4" "删除节点"
        _item "5" "禁用链式代理"
        _item "0" "返回"
        _line
        
        read -rp "  请选择: " choice
        
        case "$choice" in
            1)
                _add_chain_node_interactive
                ;;
            2)
                _import_subscription_interactive
                ;;
            3)
                # 测试所有节点延迟
                _header
                echo -e "  ${W}测试节点延迟 ${D}(TCP连接延迟，仅供参考)${NC}"
                _line
                
                local nodes=$(db_get_chain_nodes)
                local count=$(echo "$nodes" | jq 'length' 2>/dev/null || echo 0)
                
                if [[ "$count" -eq 0 ]]; then
                    echo -e "  ${D}暂无节点${NC}"
                    _pause
                    continue
                fi
                
                # 获取分流规则使用的节点
                local routing_rules=$(db_get_routing_rules)
                declare -A routing_marks
                if [[ -n "$routing_rules" && "$routing_rules" != "[]" ]]; then
                    while IFS= read -r line; do
                        local r_type=$(echo "$line" | cut -d'|' -f1)
                        local r_outbound=$(echo "$line" | cut -d'|' -f2)
                        if [[ "$r_outbound" == chain:* ]]; then
                            local node_name="${r_outbound#chain:}"
                            routing_marks["$node_name"]="$r_type"
                        fi
                    done < <(echo "$routing_rules" | jq -r '.[] | "\(.type)|\(.outbound)"')
                fi
                
                echo -e "  ${C}▸${NC} 检测 $count 个节点延迟中..."
                
                # 先收集所有节点信息到临时文件
                local tmp_results=$(mktemp)
                local i=0
                while IFS='|' read -r name type server port; do
                    [[ -z "$server" ]] && continue
                    local result=$(check_node_latency "$server" "$port")
                    local latency="${result%%|*}"
                    local resolved_ip="${result##*|}"
                    local latency_num=99999
                    [[ "$latency" =~ ^[0-9]+$ ]] && latency_num="$latency"
                    echo "${latency_num}|${latency}|${name}|${type}|${resolved_ip}" >> "$tmp_results"
                    ((i++))
                    printf "\r  ${C}▸${NC} 检测中... (%d/%d)  " "$i" "$count" >&2
                done < <(echo "$nodes" | jq -r '.[] | "\(.name)|\(.type)|\(.server)|\(.port)"')
                
                echo ""
                _ok "延迟检测完成 ($count 个节点)"
                echo ""
                echo -e "  ${W}TCP延迟排序 (从低到高):${NC}"
                _line
                
                # 排序并显示
                sort -t'|' -k1 -n "$tmp_results" | while IFS='|' read -r _ latency name type resolved_ip; do
                    local latency_color="${G}"
                    local mark=""
                    # 显示分流规则标记
                    if [[ -n "${routing_marks[$name]}" ]]; then
                        mark=" ${Y}← ${routing_marks[$name]}${NC}"
                    fi
                    
                    if [[ "$latency" == "超时" ]]; then
                        latency_color="${R}"
                        echo -e "  [${latency_color}${latency}${NC}] $name ${D}($type)${NC} ${D}${resolved_ip}${NC}$mark"
                    elif [[ "$latency" =~ ^[0-9]+$ ]]; then
                        [[ "$latency" -gt 300 ]] && latency_color="${Y}"
                        echo -e "  [${latency_color}${latency}ms${NC}] $name ${D}($type)${NC} ${D}${resolved_ip}${NC}$mark"
                    fi
                done
                
                rm -f "$tmp_results"
                _line
                _pause
                ;;
            4)
                _header
                echo -e "  ${W}删除节点${NC}"
                _line
                
                local nodes=$(db_get_chain_nodes)
                local count=$(echo "$nodes" | jq 'length' 2>/dev/null || echo 0)
                
                if [[ "$count" -eq 0 ]]; then
                    echo -e "  ${D}暂无节点${NC}"
                    _pause
                    continue
                fi
                
                local i=1
                echo "$nodes" | jq -r '.[] | .name' | while read -r name; do
                    echo -e "  ${C}$i)${NC} $name"
                    ((i++))
                done
                
                _line
                echo -e "  ${D}输入 all 删除全部${NC}"
                read -rp "  选择编号: " idx
                
                if [[ "$idx" == "all" ]]; then
                    local tmp=$(mktemp)
                    jq 'del(.chain_proxy)' "$DB_FILE" > "$tmp" && mv "$tmp" "$DB_FILE"
                    # 清理所有引用链式代理节点的分流规则
                    tmp=$(mktemp)
                    jq '.routing_rules = [.routing_rules[]? | select(.outbound | startswith("chain:") | not)]' "$DB_FILE" > "$tmp" && mv "$tmp" "$DB_FILE"
                    _ok "已删除所有节点"
                    _ok "已清理相关分流规则"
                    _regenerate_proxy_configs
                elif [[ -n "$idx" && "$idx" =~ ^[0-9]+$ ]]; then
                    local name=$(echo "$nodes" | jq -r ".[$((idx-1))].name // empty")
                    if [[ -n "$name" ]]; then
                        db_del_chain_node "$name"
                        # 清理引用该节点的分流规则
                        local tmp=$(mktemp)
                        jq --arg out "chain:$name" '.routing_rules = [.routing_rules[]? | select(.outbound != $out)]' "$DB_FILE" > "$tmp" && mv "$tmp" "$DB_FILE"
                        _ok "已删除: $name"
                        _regenerate_proxy_configs
                    fi
                fi
                _pause
                ;;
            5)
                local tmp=$(mktemp)
                jq 'del(.chain_proxy.active)' "$DB_FILE" > "$tmp" && mv "$tmp" "$DB_FILE"
                _ok "已禁用链式代理"
                _regenerate_proxy_configs
                _pause
                ;;
            0) return ;;
        esac
    done
}


#═══════════════════════════════════════════════════════════════════════════════
# BBR 网络优化
#═══════════════════════════════════════════════════════════════════════════════

# 检查 BBR 状态
check_bbr_status() {
    local cc=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)
    local qdisc=$(sysctl -n net.core.default_qdisc 2>/dev/null)
    [[ "$cc" == "bbr" && "$qdisc" == "fq" ]]
}

# 一键开启 BBR 优化
enable_bbr() {
    _header
    echo -e "  ${W}BBR 网络优化${NC}"
    _line
    
    # 检查内核版本
    local kernel_ver=$(uname -r | cut -d'-' -f1)
    local kernel_major=$(echo "$kernel_ver" | cut -d'.' -f1)
    local kernel_minor=$(echo "$kernel_ver" | cut -d'.' -f2)
    
    if [[ $kernel_major -lt 4 ]] || [[ $kernel_major -eq 4 && $kernel_minor -lt 9 ]]; then
        _err "内核版本 $(uname -r) 不支持 BBR (需要 4.9+)"
        return 1
    fi
    
    echo -e "  内核版本: ${G}$(uname -r)${NC} ✓"
    
    # 检查当前状态
    local current_cc=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)
    local current_qdisc=$(sysctl -n net.core.default_qdisc 2>/dev/null)
    
    echo -e "  当前拥塞控制: ${Y}$current_cc${NC}"
    echo -e "  当前队列调度: ${Y}$current_qdisc${NC}"
    
    if check_bbr_status; then
        _line
        _ok "BBR 已启用，无需重复操作"
        return 0
    fi
    
    _line
    read -rp "  确认开启 BBR 优化? [Y/n]: " confirm
    [[ "$confirm" =~ ^[nN]$ ]] && return
    
    _info "加载 BBR 模块..."
    modprobe tcp_bbr 2>/dev/null || true
    
    # 检查 BBR 是否可用
    if ! sysctl net.ipv4.tcp_available_congestion_control 2>/dev/null | grep -q bbr; then
        _err "BBR 模块不可用，请检查内核配置"
        return 1
    fi
    
    # 获取系统内存大小
    local mem_mb=$(free -m | awk '/^Mem:/{print $2}')
    
    # 根据内存动态计算参数
    local rmem_max wmem_max tcp_rmem tcp_wmem somaxconn file_max
    if [[ $mem_mb -le 512 ]]; then
        rmem_max=8388608; wmem_max=8388608
        tcp_rmem="4096 65536 8388608"; tcp_wmem="4096 65536 8388608"
        somaxconn=32768; file_max=262144
    elif [[ $mem_mb -le 1024 ]]; then
        rmem_max=16777216; wmem_max=16777216
        tcp_rmem="4096 65536 16777216"; tcp_wmem="4096 65536 16777216"
        somaxconn=49152; file_max=524288
    elif [[ $mem_mb -le 2048 ]]; then
        rmem_max=33554432; wmem_max=33554432
        tcp_rmem="4096 87380 33554432"; tcp_wmem="4096 65536 33554432"
        somaxconn=65535; file_max=1048576
    else
        rmem_max=67108864; wmem_max=67108864
        tcp_rmem="4096 131072 67108864"; tcp_wmem="4096 87380 67108864"
        somaxconn=65535; file_max=2097152
    fi
    
    _info "写入优化配置..."
    
    local conf_file="/etc/sysctl.d/99-bbr-proxy.conf"
    cat > "$conf_file" << EOF
# BBR 网络优化配置 (由 vless 脚本生成)
# 生成时间: $(date)
# 内存: ${mem_mb}MB

# BBR 拥塞控制
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr

# Socket 缓冲区
net.core.rmem_max = $rmem_max
net.core.wmem_max = $wmem_max
net.ipv4.tcp_rmem = $tcp_rmem
net.ipv4.tcp_wmem = $tcp_wmem

# 连接队列
net.core.somaxconn = $somaxconn
net.core.netdev_max_backlog = 32768
net.ipv4.tcp_max_syn_backlog = $somaxconn

# TCP 优化
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_max_tw_buckets = 180000
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_fastopen = 3

# 文件句柄
fs.file-max = $file_max

# 内存优化
vm.swappiness = 10
EOF
    
    _info "应用配置..."
    if sysctl --system >/dev/null 2>&1; then
        _ok "配置已生效"
    else
        _err "配置应用失败"
        return 1
    fi
    
    # 验证结果
    _line
    local new_cc=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)
    local new_qdisc=$(sysctl -n net.core.default_qdisc 2>/dev/null)
    
    echo -e "  拥塞控制: ${G}$new_cc${NC}"
    echo -e "  队列调度: ${G}$new_qdisc${NC}"
    
    if [[ "$new_cc" == "bbr" && "$new_qdisc" == "fq" ]]; then
        _ok "BBR 优化已成功启用!"
    else
        _warn "BBR 可能未完全生效，请检查系统日志"
    fi
}

#═══════════════════════════════════════════════════════════════════════════════
# 多协议管理菜单
#═══════════════════════════════════════════════════════════════════════════════

# 显示所有已安装协议的信息（带选择查看详情功能）
show_all_protocols_info() {
    local installed=$(get_installed_protocols)
    [[ -z "$installed" ]] && { _warn "未安装任何协议"; return; }
    
    while true; do
        _header
        echo -e "  ${W}已安装协议配置${NC}"
        _line
        
        local xray_protocols=$(get_xray_protocols)
        local singbox_protocols=$(get_singbox_protocols)
        local standalone_protocols=$(get_standalone_protocols)
        local all_protocols=()
        local idx=1
        
        if [[ -n "$xray_protocols" ]]; then
            echo -e "  ${Y}Xray 协议 (vless-reality 服务):${NC}"
            for protocol in $xray_protocols; do
                local port=$(db_get_field "xray" "$protocol" "port")
                if [[ -n "$port" ]]; then
                    echo -e "    ${G}$idx${NC}) $(get_protocol_name $protocol) - 端口: ${G}$port${NC}"
                    all_protocols+=("$protocol")
                    ((idx++))
                fi
            done
            echo ""
        fi
        
        if [[ -n "$singbox_protocols" ]]; then
            echo -e "  ${Y}Sing-box 协议 (vless-singbox 服务):${NC}"
            for protocol in $singbox_protocols; do
                local port=$(db_get_field "singbox" "$protocol" "port")
                if [[ -n "$port" ]]; then
                    echo -e "    ${G}$idx${NC}) $(get_protocol_name $protocol) - 端口: ${G}$port${NC}"
                    all_protocols+=("$protocol")
                    ((idx++))
                fi
            done
            echo ""
        fi
        
        if [[ -n "$standalone_protocols" ]]; then
            echo -e "  ${Y}独立进程协议:${NC}"
            for protocol in $standalone_protocols; do
                local port=$(db_get_field "singbox" "$protocol" "port")
                if [[ -n "$port" ]]; then
                    echo -e "    ${G}$idx${NC}) $(get_protocol_name $protocol) - 端口: ${G}$port${NC}"
                    all_protocols+=("$protocol")
                    ((idx++))
                fi
            done
            echo ""
        fi
        
        _line
        echo -e "  ${D}输入序号查看详细配置/链接/二维码${NC}"
        _item "0" "返回主菜单"
        _line
        
        read -rp "  请选择 [0-$((idx-1))]: " choice
        
        if [[ "$choice" == "0" ]]; then
            return
        elif [[ "$choice" =~ ^[0-9]+$ ]] && [[ $choice -ge 1 ]] && [[ $choice -lt $idx ]]; then
            local selected_protocol="${all_protocols[$((choice-1))]}"
            show_single_protocol_info "$selected_protocol"
        else
            _err "无效选择"
            sleep 1
        fi
    done
}

# 显示单个协议的详细配置信息（包含链接和二维码）
# 参数: $1=协议名, $2=是否清屏(可选，默认true)
show_single_protocol_info() {
    local protocol="$1"
    local clear_screen="${2:-true}"
    
    # 从数据库读取配置
    local cfg=""
    local core="xray"
    if db_exists "xray" "$protocol"; then
        cfg=$(db_get "xray" "$protocol")
    elif db_exists "singbox" "$protocol"; then
        cfg=$(db_get "singbox" "$protocol")
        core="singbox"
    else
        _err "协议配置不存在: $protocol"
        return
    fi
    
    # 从 JSON 提取字段
    local uuid=$(echo "$cfg" | jq -r '.uuid // empty')
    local port=$(echo "$cfg" | jq -r '.port // empty')
    local sni=$(echo "$cfg" | jq -r '.sni // empty')
    local short_id=$(echo "$cfg" | jq -r '.short_id // empty')
    local public_key=$(echo "$cfg" | jq -r '.public_key // empty')
    local private_key=$(echo "$cfg" | jq -r '.private_key // empty')
    local path=$(echo "$cfg" | jq -r '.path // empty')
    local password=$(echo "$cfg" | jq -r '.password // empty')
    local username=$(echo "$cfg" | jq -r '.username // empty')
    local method=$(echo "$cfg" | jq -r '.method // empty')
    local psk=$(echo "$cfg" | jq -r '.psk // empty')
    local version=$(echo "$cfg" | jq -r '.version // empty')
    local ipv4=$(echo "$cfg" | jq -r '.ipv4 // empty')
    local ipv6=$(echo "$cfg" | jq -r '.ipv6 // empty')
    local hop_enable=$(echo "$cfg" | jq -r '.hop_enable // empty')
    local hop_start=$(echo "$cfg" | jq -r '.hop_start // empty')
    local hop_end=$(echo "$cfg" | jq -r '.hop_end // empty')
    local stls_password=$(echo "$cfg" | jq -r '.stls_password // empty')
    
    # 重新获取 IP（数据库中的可能是旧的）
    [[ -z "$ipv4" ]] && ipv4=$(get_ipv4)
    [[ -z "$ipv6" ]] && ipv6=$(get_ipv6)
    
    # 检测是否为回落子协议（WS/VMess-WS 在有主协议时使用主协议端口）
    local display_port="$port"
    local is_fallback_protocol=false
    local master_name=""
    if [[ "$protocol" == "vless-ws" || "$protocol" == "vmess-ws" ]]; then
        # 检查是否有主协议 (Vision/Trojan/Reality)
        if db_exists "xray" "vless-vision"; then
            local master_port=$(db_get_field "xray" "vless-vision" "port")
            if [[ -n "$master_port" ]]; then
                display_port="$master_port"
                is_fallback_protocol=true
                master_name="Vision"
            fi
        elif db_exists "xray" "trojan"; then
            local master_port=$(db_get_field "xray" "trojan" "port")
            if [[ -n "$master_port" ]]; then
                display_port="$master_port"
                is_fallback_protocol=true
                master_name="Trojan"
            fi
        elif db_exists "xray" "vless"; then
            local master_port=$(db_get_field "xray" "vless" "port")
            if [[ -n "$master_port" ]]; then
                display_port="$master_port"
                is_fallback_protocol=true
                master_name="Reality"
            fi
        fi
    fi
    
    [[ "$clear_screen" == "true" ]] && _header
    _line
    echo -e "  ${W}$(get_protocol_name $protocol) 配置详情${NC}"
    _line
    
    [[ -n "$ipv4" ]] && echo -e "  IPv4: ${G}$ipv4${NC}"
    [[ -n "$ipv6" ]] && echo -e "  IPv6: ${G}$ipv6${NC}"
    echo -e "  端口: ${G}$display_port${NC}"
    [[ "$is_fallback_protocol" == "true" ]] && echo -e "  ${D}(通过 $master_name 主协议回落，内部端口: $port)${NC}"
    
    # 获取地区代码（只获取一次，用于所有显示）
    local country_code=$(get_ip_country "$ipv4")
    [[ -z "$country_code" ]] && country_code=$(get_ip_country "$ipv6")
    
    # 确定用于配置显示的 IP 地址：优先 IPv4，纯 IPv6 环境使用 IPv6（带方括号）
    local config_ip="$ipv4"
    [[ -z "$config_ip" ]] && config_ip="[$ipv6]"
    
    case "$protocol" in
        vless)
            echo -e "  UUID: ${G}$uuid${NC}"
            echo -e "  公钥: ${G}$public_key${NC}"
            echo -e "  SNI: ${G}$sni${NC}  ShortID: ${G}$short_id${NC}"
            echo ""
            echo -e "  ${Y}Loon 配置:${NC}"
            echo -e "  ${C}${country_code}-Vless-Reality = VLESS, ${config_ip}, ${display_port}, \"${uuid}\", transport=tcp, flow=xtls-rprx-vision, public-key=\"${public_key}\", short-id=${short_id}, udp=true, over-tls=true, sni=${sni}${NC}"
            ;;
        vless-xhttp)
            echo -e "  UUID: ${G}$uuid${NC}"
            echo -e "  公钥: ${G}$public_key${NC}"
            echo -e "  SNI: ${G}$sni${NC}  ShortID: ${G}$short_id${NC}"
            echo -e "  Path: ${G}$path${NC}"
            echo ""
            echo -e "  ${D}注: Loon/Surge 暂不支持 XHTTP 传输，请使用分享链接导入 Shadowrocket${NC}"
            ;;
        vless-vision)
            echo -e "  UUID: ${G}$uuid${NC}"
            echo -e "  SNI: ${G}$sni${NC}"
            [[ -n "$path" ]] && echo -e "  Path/ServiceName: ${G}$path${NC}"
            echo ""
            echo -e "  ${Y}Loon 配置:${NC}"
            echo -e "  ${C}${country_code}-Vless-Vision = VLESS, ${config_ip}, ${display_port}, \"${uuid}\", transport=tcp, flow=xtls-rprx-vision, udp=true, over-tls=true, sni=${sni}, skip-cert-verify=true${NC}"
            ;;
        vless-ws)
            echo -e "  UUID: ${G}$uuid${NC}"
            echo -e "  SNI: ${G}$sni${NC}"
            [[ -n "$path" ]] && echo -e "  Path/ServiceName: ${G}$path${NC}"
            echo ""
            echo -e "  ${Y}Loon 配置:${NC}"
            echo -e "  ${C}${country_code}-Vless-WS = VLESS, ${config_ip}, ${display_port}, \"${uuid}\", transport=ws, path=${path}, host=${sni}, udp=true, over-tls=true, sni=${sni}, skip-cert-verify=true${NC}"
            ;;
        vmess-ws)
            echo -e "  UUID: ${G}$uuid${NC}"
            echo -e "  SNI: ${G}$sni${NC}"
            [[ -n "$path" ]] && echo -e "  Path: ${G}$path${NC}"
            echo ""
            echo -e "  ${Y}Surge 配置:${NC}"
            echo -e "  ${C}${country_code}-VMess-WS = vmess, ${config_ip}, ${display_port}, ${uuid}, tls=true, ws=true, ws-path=${path}, sni=${sni}, skip-cert-verify=true${NC}"
            echo ""
            echo -e "  ${Y}Loon 配置:${NC}"
            echo -e "  ${C}${country_code}-VMess-WS = VMess, ${config_ip}, ${display_port}, aes-128-gcm, \"${uuid}\", transport=ws, path=${path}, host=${sni}, udp=true, over-tls=true, sni=${sni}, skip-cert-verify=true${NC}"
            ;;
        ss2022)
            echo -e "  密码: ${G}$password${NC}"
            echo -e "  加密: ${G}$method${NC}"
            echo ""
            echo -e "  ${Y}Surge 配置:${NC}"
            echo -e "  ${C}${country_code}-SS2022 = ss, ${config_ip}, ${display_port}, encrypt-method=${method}, password=${password}${NC}"
            echo ""
            echo -e "  ${Y}Loon 配置:${NC}"
            echo -e "  ${C}${country_code}-SS2022 = Shadowsocks, ${config_ip}, ${display_port}, ${method}, \"${password}\", udp=true${NC}"
            ;;
        ss-legacy)
            echo -e "  密码: ${G}$password${NC}"
            echo -e "  加密: ${G}$method${NC}"
            echo -e "  ${D}(传统版, 无时间校验)${NC}"
            echo ""
            echo -e "  ${Y}Surge 配置:${NC}"
            echo -e "  ${C}${country_code}-SS = ss, ${config_ip}, ${display_port}, encrypt-method=${method}, password=${password}${NC}"
            echo ""
            echo -e "  ${Y}Loon 配置:${NC}"
            echo -e "  ${C}${country_code}-SS = Shadowsocks, ${config_ip}, ${display_port}, ${method}, \"${password}\", udp=true${NC}"
            ;;
        hy2)
            echo -e "  密码: ${G}$password${NC}"
            echo -e "  SNI: ${G}$sni${NC}"
            if [[ "$hop_enable" == "1" ]]; then
                echo -e "  端口跳跃: ${G}${hop_start}-${hop_end}${NC}"
            fi
            echo ""
            echo -e "  ${Y}Surge 配置:${NC}"
            echo -e "  ${C}${country_code}-Hysteria2 = hysteria2, ${config_ip}, ${display_port}, password=${password}, sni=${sni}, skip-cert-verify=true${NC}"
            echo ""
            echo -e "  ${Y}Loon 配置:${NC}"
            echo -e "  ${C}${country_code}-Hysteria2 = Hysteria2, ${config_ip}, ${display_port}, \"${password}\", udp=true, sni=${sni}, skip-cert-verify=true${NC}"
            ;;
        trojan)
            echo -e "  密码: ${G}$password${NC}"
            echo -e "  SNI: ${G}$sni${NC}"
            echo ""
            echo -e "  ${Y}Surge 配置:${NC}"
            echo -e "  ${C}${country_code}-Trojan = trojan, ${config_ip}, ${display_port}, password=${password}, sni=${sni}, skip-cert-verify=true${NC}"
            echo ""
            echo -e "  ${Y}Loon 配置:${NC}"
            echo -e "  ${C}${country_code}-Trojan = trojan, ${config_ip}, ${display_port}, \"${password}\", udp=true, over-tls=true, sni=${sni}${NC}"
            ;;
        anytls)
            echo -e "  密码: ${G}$password${NC}"
            echo -e "  SNI: ${G}$sni${NC}"
            echo ""
            echo -e "  ${Y}Surge 配置:${NC}"
            echo -e "  ${C}${country_code}-AnyTLS = anytls, ${config_ip}, ${display_port}, password=${password}, sni=${sni}, skip-cert-verify=true${NC}"
            ;;
        naive)
            local domain=$(echo "$cfg" | jq -r '.domain // empty')
            echo -e "  域名: ${G}$domain${NC}"
            echo -e "  用户名: ${G}$username${NC}"
            echo -e "  密码: ${G}$password${NC}"
            echo ""
            echo -e "  ${Y}Shadowrocket (HTTP/2):${NC}"
            echo -e "  ${C}http2://${username}:${password}@${domain}:${display_port}${NC}"
            ;;
        snell-shadowtls)
            echo -e "  PSK: ${G}$psk${NC}"
            echo -e "  SNI: ${G}$sni${NC}"
            echo -e "  版本: ${G}v${version:-4}${NC}"
            echo ""
            echo -e "  ${Y}Surge 配置:${NC}"
            echo -e "  ${C}${country_code}-Snell-ShadowTLS = snell, ${config_ip}, ${display_port}, psk=${psk}, version=${version:-4}, reuse=true, tfo=true, shadow-tls-password=${stls_password}, shadow-tls-sni=${sni}, shadow-tls-version=3${NC}"
            ;;
        snell-v5-shadowtls)
            echo -e "  PSK: ${G}$psk${NC}"
            echo -e "  SNI: ${G}$sni${NC}"
            echo -e "  版本: ${G}v${version:-5}${NC}"
            echo ""
            echo -e "  ${Y}Surge 配置:${NC}"
            echo -e "  ${C}${country_code}-Snell5-ShadowTLS = snell, ${config_ip}, ${display_port}, psk=${psk}, version=${version:-5}, reuse=true, tfo=true, shadow-tls-password=${stls_password}, shadow-tls-sni=${sni}, shadow-tls-version=3${NC}"
            ;;
        ss2022-shadowtls)
            echo -e "  密码: ${G}$password${NC}"
            echo -e "  加密: ${G}$method${NC}"
            echo -e "  SNI: ${G}$sni${NC}"
            echo ""
            echo -e "  ${Y}Surge 配置:${NC}"
            echo -e "  ${C}${country_code}-SS2022-ShadowTLS = ss, ${config_ip}, ${display_port}, encrypt-method=${method}, password=${password}, shadow-tls-password=${stls_password}, shadow-tls-sni=${sni}, shadow-tls-version=3${NC}"
            echo ""
            echo -e "  ${Y}Loon 配置:${NC}"
            echo -e "  ${C}${country_code}-SS2022-ShadowTLS = Shadowsocks, ${config_ip}, ${display_port}, ${method}, \"${password}\", udp=true, shadow-tls-password=${stls_password}, shadow-tls-sni=${sni}, shadow-tls-version=3${NC}"
            ;;
        snell|snell-v5)
            echo -e "  PSK: ${G}$psk${NC}"
            echo -e "  版本: ${G}v$version${NC}"
            echo ""
            echo -e "  ${Y}Surge 配置 (Snell 为 Surge 专属协议):${NC}"
            echo -e "  ${C}${country_code}-Snell = snell, ${config_ip}, ${display_port}, psk=${psk}, version=${version}, reuse=true, tfo=true${NC}"
            ;;
        tuic)
            echo -e "  UUID: ${G}$uuid${NC}"
            echo -e "  密码: ${G}$password${NC}"
            echo -e "  SNI: ${G}$sni${NC}"
            if [[ "$hop_enable" == "1" ]]; then
                echo -e "  端口跳跃: ${G}${hop_start}-${hop_end}${NC}"
            fi
            echo ""
            echo -e "  ${Y}Surge 配置:${NC}"
            echo -e "  ${C}${country_code}-TUIC = tuic-v5, ${config_ip}, ${display_port}, password=${password}, uuid=${uuid}, sni=${sni}, skip-cert-verify=true, alpn=h3${NC}"
            echo ""
            echo -e "  ${Y}Loon 配置:${NC}"
            echo -e "  ${C}${country_code}-TUIC = TUIC, ${config_ip}, ${display_port}, \"${password}\", \"${uuid}\", udp=true, sni=${sni}, skip-cert-verify=true, alpn=h3${NC}"
            ;;
        socks)
            echo -e "  用户名: ${G}$username${NC}"
            echo -e "  密码: ${G}$password${NC}"
            echo ""
            echo -e "  ${Y}Surge 配置:${NC}"
            echo -e "  ${C}${country_code}-SOCKS5 = socks5, ${config_ip}, ${display_port}, ${username}, ${password}${NC}"
            echo ""
            echo -e "  ${Y}Loon 配置:${NC}"
            echo -e "  ${C}${country_code}-SOCKS5 = socks5, ${config_ip}, ${display_port}, ${username}, \"${password}\", udp=true${NC}"
            ;;
    esac
    
    _line
    
    # 获取地区代码（只获取一次，用于所有链接）
    local country_code=$(get_ip_country "$ipv4")
    [[ -z "$country_code" ]] && country_code=$(get_ip_country "$ipv6")
    
    # 确定使用的 IP 地址：优先 IPv4，纯 IPv6 环境使用 IPv6
    local ip_addr=""
    if [[ -n "$ipv4" ]]; then
        ip_addr="$ipv4"
    elif [[ -n "$ipv6" ]]; then
        ip_addr="[$ipv6]"  # IPv6 需要用方括号包裹
    fi
    
    # 显示分享链接和二维码
    if [[ -n "$ip_addr" ]]; then
        local link_port="$display_port"
        
        local link join_code
        case "$protocol" in
            vless)
                link=$(gen_vless_link "$ip_addr" "$link_port" "$uuid" "$public_key" "$short_id" "$sni" "$country_code")
                join_code=$(echo "REALITY|${ip_addr}|${link_port}|${uuid}|${public_key}|${short_id}|${sni}" | base64 -w 0)
                ;;
            vless-xhttp)
                link=$(gen_vless_xhttp_link "$ip_addr" "$link_port" "$uuid" "$public_key" "$short_id" "$sni" "$path" "$country_code")
                join_code=$(echo "REALITY-XHTTP|${ip_addr}|${link_port}|${uuid}|${public_key}|${short_id}|${sni}|${path}" | base64 -w 0)
                ;;
            vless-vision)
                link=$(gen_vless_vision_link "$ip_addr" "$link_port" "$uuid" "$sni" "$country_code")
                join_code=$(echo "VLESS-VISION|${ip_addr}|${link_port}|${uuid}|${sni}" | base64 -w 0)
                ;;
            vless-ws)
                link=$(gen_vless_ws_link "$ip_addr" "$link_port" "$uuid" "$sni" "$path" "$country_code")
                join_code=$(echo "VLESS-WS|${ip_addr}|${link_port}|${uuid}|${sni}|${path}" | base64 -w 0)
                ;;
            vmess-ws)
                link=$(gen_vmess_ws_link "$ip_addr" "$link_port" "$uuid" "$sni" "$path" "$country_code")
                join_code=$(echo "VMESS-WS|${ip_addr}|${link_port}|${uuid}|${sni}|${path}" | base64 -w 0)
                ;;
            ss2022)
                link=$(gen_ss2022_link "$ip_addr" "$link_port" "$method" "$password" "$country_code")
                join_code=$(echo "SS2022|${ip_addr}|${link_port}|${method}|${password}" | base64 -w 0)
                ;;
            ss-legacy)
                link=$(gen_ss_legacy_link "$ip_addr" "$link_port" "$method" "$password" "$country_code")
                join_code=$(echo "SS|${ip_addr}|${link_port}|${method}|${password}" | base64 -w 0)
                ;;
            hy2)
                link=$(gen_hy2_link "$ip_addr" "$link_port" "$password" "$sni" "$country_code")
                join_code=$(echo "HY2|${ip_addr}|${link_port}|${password}|${sni}" | base64 -w 0)
                ;;
            trojan)
                link=$(gen_trojan_link "$ip_addr" "$link_port" "$password" "$sni" "$country_code")
                join_code=$(echo "TROJAN|${ip_addr}|${link_port}|${password}|${sni}" | base64 -w 0)
                ;;
            snell)
                link=$(gen_snell_link "$ip_addr" "$link_port" "$psk" "$version" "$country_code")
                join_code=$(echo "SNELL|${ip_addr}|${link_port}|${psk}|${version}" | base64 -w 0)
                ;;
            snell-v5)
                link=$(gen_snell_v5_link "$ip_addr" "$link_port" "$psk" "$version" "$country_code")
                join_code=$(echo "SNELL-V5|${ip_addr}|${link_port}|${psk}|${version}" | base64 -w 0)
                ;;
            snell-shadowtls|snell-v5-shadowtls)
                local stls_ver="${version:-4}"
                [[ "$protocol" == "snell-v5-shadowtls" ]] && stls_ver="5"
                join_code=$(echo "SNELL-SHADOWTLS|${ip_addr}|${link_port}|${psk}|${stls_ver}|${stls_password}|${sni}" | base64 -w 0)
                link=""
                ;;
            ss2022-shadowtls)
                join_code=$(echo "SS2022-SHADOWTLS|${ip_addr}|${link_port}|${method}|${password}|${stls_password}|${sni}" | base64 -w 0)
                link=""
                ;;
            tuic)
                link=$(gen_tuic_link "$ip_addr" "$link_port" "$uuid" "$password" "$sni" "$country_code")
                join_code=$(echo "TUIC|${ip_addr}|${link_port}|${uuid}|${password}|${sni}" | base64 -w 0)
                ;;
            anytls)
                link=$(gen_anytls_link "$ip_addr" "$link_port" "$password" "$sni" "$country_code")
                join_code=$(echo "ANYTLS|${ip_addr}|${link_port}|${password}|${sni}" | base64 -w 0)
                ;;
            naive)
                local domain=$(echo "$cfg" | jq -r '.domain // empty')
                link=$(gen_naive_link "$domain" "$link_port" "$username" "$password" "$country_code")
                join_code=$(echo "NAIVE|${domain}|${link_port}|${username}|${password}" | base64 -w 0)
                ;;
            socks)
                link=$(gen_socks_link "$ip_addr" "$link_port" "$username" "$password" "$country_code")
                join_code=$(echo "SOCKS|${ip_addr}|${link_port}|${username}|${password}" | base64 -w 0)
                ;;
        esac
        
        # 显示 JOIN 码 (根据开关控制)
        if [[ "$SHOW_JOIN_CODE" == "on" ]]; then
            echo -e "  ${C}JOIN码:${NC}"
            echo -e "  ${G}$join_code${NC}"
            echo ""
        fi
        
        # ShadowTLS 组合协议只显示 JOIN 码
        if [[ "$protocol" != "snell-shadowtls" && "$protocol" != "snell-v5-shadowtls" && "$protocol" != "ss2022-shadowtls" ]]; then
            if [[ "$protocol" == "socks" ]]; then
                local socks_link="socks5://${username}:${password}@${ip_addr}:${link_port}#SOCKS5-${ip_addr}"
                echo -e "  ${C}分享链接:${NC}"
                echo -e "  ${G}$socks_link${NC}"
                echo ""
                echo -e "  ${C}二维码:${NC}"
                echo -e "  ${G}$(gen_qr "$socks_link")${NC}"
            else
                echo -e "  ${C}分享链接:${NC}"
                echo -e "  ${G}$link${NC}"
                echo ""
                echo -e "  ${C}二维码:${NC}"
                echo -e "  ${G}$(gen_qr "$link")${NC}"
            fi
        elif [[ "$SHOW_JOIN_CODE" != "on" ]]; then
            # ShadowTLS 协议且 JOIN 码关闭时，提示用户
            echo -e "  ${Y}提示: ShadowTLS 协议需要 JOIN 码才能配置客户端${NC}"
            echo -e "  ${D}如需显示 JOIN 码，请修改脚本头部 SHOW_JOIN_CODE=\"on\"${NC}"
            echo ""
        fi
    fi
    
    # IPv6 提示（仅双栈时显示，纯 IPv6 已经使用 IPv6 地址了）
    if [[ -n "$ipv4" && -n "$ipv6" ]]; then
        echo ""
        echo -e "  ${D}提示: 服务器支持 IPv6 ($ipv6)，如需使用请自行替换地址${NC}"
    fi
    
    # 自签名证书提示（VMess-WS、VLESS-WS、VLESS-Vision、Trojan、Hysteria2 使用自签名证书时）
    if [[ "$protocol" =~ ^(vmess-ws|vless-ws|vless-vision|trojan|hy2)$ ]]; then
        # 检查是否是自签名证书（没有真实域名）
        local is_self_signed=true
        if [[ -f "$CFG/cert_domain" ]]; then
            local cert_domain=$(cat "$CFG/cert_domain")
            # 检查证书是否由 CA 签发
            if [[ -f "$CFG/certs/server.crt" ]]; then
                local issuer=$(openssl x509 -in "$CFG/certs/server.crt" -noout -issuer 2>/dev/null)
                if [[ "$issuer" == *"Let's Encrypt"* ]] || [[ "$issuer" == *"R3"* ]] || [[ "$issuer" == *"R10"* ]] || [[ "$issuer" == *"ZeroSSL"* ]]; then
                    is_self_signed=false
                fi
            fi
        fi
        if [[ "$is_self_signed" == "true" ]]; then
            echo ""
            echo -e "  ${Y}⚠ 使用自签名证书，客户端需开启「跳过证书验证」或「允许不安全连接」${NC}"
        fi
    fi
    
    # Hysteria2 端口跳跃提示
    if [[ "$protocol" == "hy2" && "$hop_enable" == "1" ]]; then
        echo ""
        _line
        echo -e "  ${Y}⚠ 端口跳跃已启用${NC}"
        echo -e "  ${C}客户端请手动将端口改为: ${G}${hop_start}-${hop_end}${NC}"
        _line
    fi
    
    # 生成并显示订阅链接
    echo ""
    echo -e "  ${C}订阅链接:${NC}"
    
    local domain=""
    # 尝试获取域名
    if [[ -f "$CFG/cert_domain" ]]; then
        domain=$(cat "$CFG/cert_domain")
    fi
    
    # 检查Web服务状态
    local web_service_running=false
    local nginx_port=""
    
    # 检查是否有Reality协议（Reality 不需要 Nginx，不提供订阅服务）
    local has_reality=false
    if db_exists "xray" "vless" || db_exists "xray" "vless-xhttp"; then
        has_reality=true
        # Reality 协议不启用 Nginx，不设置 nginx_port
    fi
    
    # 检查是否有需要证书的协议（这些协议才需要 Nginx 订阅服务）
    local has_cert_protocol=false
    if db_exists "xray" "vless-ws" || db_exists "xray" "vless-vision" || db_exists "xray" "trojan"; then
        has_cert_protocol=true
        # 从 sub.info 读取实际配置的端口，否则使用默认 8443
        if [[ -f "$CFG/sub.info" ]]; then
            source "$CFG/sub.info"
            nginx_port="${sub_port:-8443}"
        else
            nginx_port="8443"
        fi
    fi
    
    # 判断Web服务是否运行 - 只有证书协议才检查
    if [[ -n "$nginx_port" ]]; then
        if ss -tlnp 2>/dev/null | grep -q ":${nginx_port} "; then
            web_service_running=true
        fi
    fi
    
    # 显示订阅链接提示
    if [[ "$has_cert_protocol" == "true" ]]; then
        # 有证书协议，显示订阅状态
        if [[ "$web_service_running" == "true" && -f "$CFG/sub.info" ]]; then
            source "$CFG/sub.info"
            local sub_protocol="http"
            [[ "$sub_https" == "true" ]] && sub_protocol="https"
            local base_url="${sub_protocol}://${sub_domain:-$ipv4}:${sub_port}/sub/${sub_uuid}"
            echo -e "  ${Y}Clash/Clash Verge:${NC}"
            echo -e "  ${G}$base_url/clash${NC}"
        elif [[ "$web_service_running" == "true" ]]; then
            echo -e "  ${Y}订阅服务未配置，请在主菜单选择「订阅管理」进行配置${NC}"
        else
            echo -e "  ${D}(Web服务未运行，订阅功能不可用)${NC}"
            echo -e "  ${D}提示: 请在主菜单选择「订阅管理」配置订阅服务${NC}"
        fi
    elif [[ "$has_reality" == "true" ]]; then
        # 只有 Reality 协议，不需要订阅服务
        echo -e "  ${D}(Reality 协议无需订阅服务，直接使用分享链接即可)${NC}"
    else
        echo -e "  ${D}(无可用订阅)${NC}"
    fi
    
    _line
    [[ "$clear_screen" == "true" ]] && _pause
}

# 管理协议服务
manage_protocol_services() {
    local installed=$(get_installed_protocols)
    [[ -z "$installed" ]] && { _warn "未安装任何协议"; return; }
    
    while true; do
        _header
        echo -e "  ${W}协议服务管理${NC}"
        _line
        show_protocols_overview  # 使用简洁概览
        
        _item "1" "重启所有服务"
        _item "2" "停止所有服务"
        _item "3" "启动所有服务"
        _item "4" "查看服务状态"
        _item "0" "返回主菜单"
        _line
        
        read -rp "  请选择: " choice
        case $choice in
            1) 
                _info "重启所有服务..."
                stop_services; sleep 2; start_services && _ok "所有服务已重启"
                _pause
                ;;
            2) 
                _info "停止所有服务..."
                stop_services; touch "$CFG/paused"; _ok "所有服务已停止"
                _pause
                ;;
            3) 
                _info "启动所有服务..."
                start_services && _ok "所有服务已启动"
                _pause
                ;;
            4) show_services_status; _pause ;;
            0) return ;;
            *) _err "无效选择"; _pause ;;
        esac
    done
}

# 简洁的协议概览（用于服务管理页面）
show_protocols_overview() {
    local xray_protocols=$(get_xray_protocols)
    local singbox_protocols=$(get_singbox_protocols)
    local standalone_protocols=$(get_standalone_protocols)
    
    echo -e "  ${C}已安装协议概览${NC}"
    _line
    
    if [[ -n "$xray_protocols" ]]; then
        echo -e "  ${Y}Xray 协议 (共享服务):${NC}"
        for protocol in $xray_protocols; do
            local port=$(db_get_field "xray" "$protocol" "port")
            [[ -n "$port" ]] && echo -e "    ${G}●${NC} $(get_protocol_name $protocol) - 端口: ${G}$port${NC}"
        done
        echo ""
    fi
    
    if [[ -n "$singbox_protocols" ]]; then
        echo -e "  ${Y}Sing-box 协议 (共享服务):${NC}"
        for protocol in $singbox_protocols; do
            local port=$(db_get_field "singbox" "$protocol" "port")
            [[ -n "$port" ]] && echo -e "    ${G}●${NC} $(get_protocol_name $protocol) - 端口: ${G}$port${NC}"
        done
        echo ""
    fi
    
    if [[ -n "$standalone_protocols" ]]; then
        echo -e "  ${Y}独立协议 (独立服务):${NC}"
        for protocol in $standalone_protocols; do
            local port=$(db_get_field "singbox" "$protocol" "port")
            [[ -n "$port" ]] && echo -e "    ${G}●${NC} $(get_protocol_name $protocol) - 端口: ${G}$port${NC}"
        done
        echo ""
    fi
    _line
}

# 显示服务状态
show_services_status() {
    _line
    echo -e "  ${C}服务状态${NC}"
    _line
    
    # Xray 服务状态 (TCP 协议)
    local xray_protocols=$(get_xray_protocols)
    if [[ -n "$xray_protocols" ]]; then
        if svc status vless-reality; then
            echo -e "  ${G}●${NC} Xray 服务 - ${G}运行中${NC}"
            for proto in $xray_protocols; do
                echo -e "      ${D}└${NC} $(get_protocol_name $proto)"
            done
        else
            echo -e "  ${R}●${NC} Xray 服务 - ${R}已停止${NC}"
        fi
    fi
    
    # Sing-box 服务状态 (UDP/QUIC 协议)
    local singbox_protocols=$(get_singbox_protocols)
    if [[ -n "$singbox_protocols" ]]; then
        if svc status vless-singbox 2>/dev/null; then
            echo -e "  ${G}●${NC} Sing-box 服务 - ${G}运行中${NC}"
            for proto in $singbox_protocols; do
                echo -e "      ${D}└${NC} $(get_protocol_name $proto)"
            done
        else
            echo -e "  ${R}●${NC} Sing-box 服务 - ${R}已停止${NC}"
        fi
    fi
    
    # 独立进程协议服务状态 (Snell 等)
    local standalone_protocols=$(get_standalone_protocols)
    for protocol in $standalone_protocols; do
        local service_name="vless-${protocol}"
        local proto_name=$(get_protocol_name $protocol)
        if svc status "$service_name" 2>/dev/null; then
            echo -e "  ${G}●${NC} $proto_name - ${G}运行中${NC}"
        else
            echo -e "  ${R}●${NC} $proto_name - ${R}已停止${NC}"
        fi
    done
    _line
}

# 卸载指定协议
uninstall_specific_protocol() {
    local installed=$(get_installed_protocols)
    [[ -z "$installed" ]] && { _warn "未安装任何协议"; return; }
    
    _header
    echo -e "  ${W}卸载指定协议${NC}"
    _line
    
    echo -e "  ${Y}已安装的协议:${NC}"
    local i=1
    for protocol in $installed; do
        echo -e "    ${G}$i${NC}) $(get_protocol_name $protocol)"
        ((i++))
    done
    echo ""
    
    read -rp "  选择要卸载的协议 [1-$((i-1))]: " choice
    [[ ! "$choice" =~ ^[0-9]+$ ]] && { _err "无效选择"; return; }
    
    local selected_protocol=$(echo "$installed" | sed -n "${choice}p")
    [[ -z "$selected_protocol" ]] && { _err "协议不存在"; return; }
    
    echo -e "  将卸载: ${R}$(get_protocol_name $selected_protocol)${NC}"
    read -rp "  确认卸载? [y/N]: " confirm
    [[ ! "$confirm" =~ ^[yY]$ ]] && return
    
    _info "卸载 $selected_protocol..."
    
    # 停止相关服务
    if [[ " $XRAY_PROTOCOLS " == *" $selected_protocol "* ]]; then
        # Xray 协议：需要重新生成配置
        unregister_protocol "$selected_protocol"
        rm -f "$CFG/${selected_protocol}.join"
        
        # 检查是否还有其他 Xray 协议
        local remaining_xray=$(get_xray_protocols)
        if [[ -n "$remaining_xray" ]]; then
            _info "重新生成 Xray 配置..."
            svc stop vless-reality 2>/dev/null
            rm -f "$CFG/config.json"
            
            if generate_xray_config; then
                _ok "Xray 配置已更新"
                svc start vless-reality
            else
                _err "Xray 配置生成失败"
            fi
        else
            _info "没有其他 Xray 协议，停止 Xray 服务..."
            svc stop vless-reality 2>/dev/null
            rm -f "$CFG/config.json"
            _ok "Xray 服务已停止"
        fi
    elif [[ " $SINGBOX_PROTOCOLS " == *" $selected_protocol "* ]]; then
        # Sing-box 协议 (hy2/tuic)：需要重新生成配置
        
        # Hysteria2: 先清理 iptables 端口跳跃规则
        if [[ "$selected_protocol" == "hy2" ]]; then
            cleanup_hy2_nat_rules
            rm -rf "$CFG/certs/hy2"
        fi
        
        # TUIC: 先清理 iptables 端口跳跃规则，删除证书目录
        if [[ "$selected_protocol" == "tuic" ]]; then
            cleanup_hy2_nat_rules
            rm -rf "$CFG/certs/tuic"
        fi
        
        unregister_protocol "$selected_protocol"
        rm -f "$CFG/${selected_protocol}.join"
        
        # 检查是否还有其他 Sing-box 协议
        local remaining_singbox=$(get_singbox_protocols)
        if [[ -n "$remaining_singbox" ]]; then
            _info "重新生成 Sing-box 配置..."
            svc stop vless-singbox 2>/dev/null
            rm -f "$CFG/singbox.json"
            
            if generate_singbox_config; then
                _ok "Sing-box 配置已更新"
                svc start vless-singbox
            else
                _err "Sing-box 配置生成失败"
            fi
        else
            _info "没有其他 Sing-box 协议，停止 Sing-box 服务..."
            svc stop vless-singbox 2>/dev/null
            svc disable vless-singbox 2>/dev/null
            rm -f "$CFG/singbox.json"
            # 删除 Sing-box 服务文件
            if [[ "$DISTRO" == "alpine" ]]; then
                rc-update del vless-singbox default 2>/dev/null
                rm -f "/etc/init.d/vless-singbox"
            else
                rm -f "/etc/systemd/system/vless-singbox.service"
                systemctl daemon-reload
            fi
            _ok "Sing-box 服务已停止"
        fi
    else
        # 独立协议 (Snell/AnyTLS/ShadowTLS)：停止服务，删除配置和服务文件
        local service_name="vless-${selected_protocol}"
        
        # 停止主服务
        svc stop "$service_name" 2>/dev/null
        
        # ShadowTLS 组合协议：还需要停止后端服务
        if [[ "$selected_protocol" == "snell-shadowtls" || "$selected_protocol" == "snell-v5-shadowtls" || "$selected_protocol" == "ss2022-shadowtls" ]]; then
            local backend_svc="${BACKEND_NAME[$selected_protocol]}"
            [[ -n "$backend_svc" ]] && svc stop "$backend_svc" 2>/dev/null
        fi
        
        unregister_protocol "$selected_protocol"
        rm -f "$CFG/${selected_protocol}.join"
        
        # 删除配置文件
        case "$selected_protocol" in
            snell) rm -f "$CFG/snell.conf" ;;
            snell-v5) rm -f "$CFG/snell-v5.conf" ;;
            snell-shadowtls) rm -f "$CFG/snell-shadowtls.conf" ;;
            snell-v5-shadowtls) rm -f "$CFG/snell-v5-shadowtls.conf" ;;
            ss2022-shadowtls) rm -f "$CFG/ss2022-shadowtls-backend.json" ;;
        esac
        
        # 删除服务文件
        if [[ "$DISTRO" == "alpine" ]]; then
            rc-update del "$service_name" default 2>/dev/null
            rm -f "/etc/init.d/$service_name"
            # ShadowTLS 后端服务
            if [[ -n "${BACKEND_NAME[$selected_protocol]:-}" ]]; then
                rc-update del "${BACKEND_NAME[$selected_protocol]}" default 2>/dev/null
                rm -f "/etc/init.d/${BACKEND_NAME[$selected_protocol]}"
            fi
        else
            systemctl disable "$service_name" 2>/dev/null
            rm -f "/etc/systemd/system/${service_name}.service"
            # ShadowTLS 后端服务
            if [[ -n "${BACKEND_NAME[$selected_protocol]:-}" ]]; then
                systemctl disable "${BACKEND_NAME[$selected_protocol]}" 2>/dev/null
                rm -f "/etc/systemd/system/${BACKEND_NAME[$selected_protocol]}.service"
            fi
            systemctl daemon-reload
        fi
    fi
    
    # 检查是否还有需要订阅服务的协议
    local has_sub_protocol=false
    for proto in vless-ws vless-vision trojan vmess-ws; do
        if is_protocol_installed "$proto"; then
            has_sub_protocol=true
            break
        fi
    done
    
    # 如果没有需要订阅的协议了，清理订阅相关配置
    if [[ "$has_sub_protocol" == "false" ]]; then
        _info "清理订阅服务..."
        # 停止并删除 Nginx 订阅配置
        rm -f /etc/nginx/conf.d/vless-sub.conf
        rm -f /etc/nginx/conf.d/vless-fake.conf
        nginx -s reload 2>/dev/null
        # 清理订阅目录和配置
        rm -rf "$CFG/subscription"
        rm -f "$CFG/sub.info"
        rm -f "$CFG/sub_uuid"
        _ok "订阅服务已清理"
    else
        # 还有其他协议，更新订阅文件
        _info "更新订阅文件..."
        generate_sub_files
    fi
    
    _ok "$selected_protocol 已卸载"
}

#═══════════════════════════════════════════════════════════════════════════════
# 信息显示与卸载
#═══════════════════════════════════════════════════════════════════════════════

show_server_info() {
    [[ "$(get_role)" != "server" ]] && return
    
    # 多协议模式：显示所有协议的配置
    local installed=$(get_installed_protocols)
    local protocol_count=$(echo "$installed" | wc -w)
    
    if [[ $protocol_count -eq 1 ]]; then
        # 单协议：直接显示详细信息
        show_single_protocol_info "$installed"
    else
        # 多协议：显示协议列表供选择
        show_all_protocols_info
    fi
}

do_uninstall() {
    check_installed || { _warn "未安装"; return; }
    read -rp "  确认卸载? [y/N]: " confirm
    [[ ! "$confirm" =~ ^[yY]$ ]] && return
    
    _info "停止所有服务..."
    stop_services
    
    # 卸载 WARP (如果已安装)
    local warp_st=$(warp_status 2>/dev/null)
    if [[ "$warp_st" == "configured" || "$warp_st" == "connected" ]] || check_cmd warp-cli; then
        _info "卸载 WARP..."
        local warp_mode=$(db_get_warp_mode 2>/dev/null)
        if [[ "$warp_mode" == "official" ]] || check_cmd warp-cli; then
            # 卸载官方客户端
            warp-cli disconnect 2>/dev/null
            systemctl stop warp-svc 2>/dev/null
            systemctl disable warp-svc 2>/dev/null
            if [[ "$DISTRO" == "ubuntu" || "$DISTRO" == "debian" ]]; then
                apt-get remove -y cloudflare-warp 2>/dev/null
                apt-get autoremove -y 2>/dev/null
                rm -f /etc/apt/sources.list.d/cloudflare-client.list
                rm -f /usr/share/keyrings/cloudflare-warp-archive-keyring.gpg
            elif [[ "$DISTRO" == "centos" ]]; then
                yum remove -y cloudflare-warp 2>/dev/null
                rm -f /etc/yum.repos.d/cloudflare-warp.repo
            fi
        fi
        # 清理 WGCF 相关文件
        rm -f "$CFG/warp.json" 2>/dev/null
        rm -f /usr/local/bin/wgcf 2>/dev/null
        rm -f ~/.wgcf-account.toml 2>/dev/null
        # 清理分流配置
        db_clear_routing_rules 2>/dev/null
        _ok "WARP 已卸载"
    fi
    
    # 清理伪装网页服务和订阅文件
    local cleaned_items=()
    
    if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet fake-web 2>/dev/null; then
        systemctl stop fake-web 2>/dev/null
        systemctl disable fake-web 2>/dev/null
        rm -f /etc/systemd/system/fake-web.service
        systemctl daemon-reload 2>/dev/null
        cleaned_items+=("fake-web服务")
    fi
    
    # 清理Nginx配置
    if [[ -f "/etc/nginx/sites-enabled/vless-fake" ]]; then
        rm -f /etc/nginx/sites-enabled/vless-fake /etc/nginx/sites-available/vless-fake
        # 尝试重载Nginx，忽略错误（兼容 systemd / openrc）
        if nginx -t 2>/dev/null; then
            svc reload nginx 2>/dev/null || svc restart nginx 2>/dev/null
        else
            _warn "Nginx配置有问题，跳过重载"
        fi
        cleaned_items+=("Nginx配置")
    fi
    
    # 显示清理结果
    if [[ ${#cleaned_items[@]} -gt 0 ]]; then
        echo "  ▸ 已清理: ${cleaned_items[*]}"
    fi
    
    # 清理网页文件
    rm -rf /var/www/html/index.html 2>/dev/null
    
    # 强力清理残留进程
    force_cleanup
    
    _info "删除服务文件..."
    if [[ "$DISTRO" == "alpine" ]]; then
        # Alpine: 删除所有 vless 相关的 OpenRC 服务
        for svc_file in /etc/init.d/vless-*; do
            [[ -f "$svc_file" ]] && {
                local svc_name=$(basename "$svc_file")
                rc-update del "$svc_name" default 2>/dev/null
                rm -f "$svc_file"
            }
        done
    else
        # Debian/Ubuntu/CentOS: 删除所有 vless 相关的 systemd 服务
        systemctl stop 'vless-*' 2>/dev/null
        systemctl disable 'vless-*' 2>/dev/null
        rm -f /etc/systemd/system/vless-*.service
        systemctl daemon-reload
    fi
    
    _info "删除配置目录..."
    
    # 保留证书目录和域名记录，避免重复申请
    local cert_backup_dir="/tmp/vless-certs-backup"
    if [[ -d "$CFG/certs" ]]; then
        _info "备份证书文件..."
        mkdir -p "$cert_backup_dir"
        cp -r "$CFG/certs" "$cert_backup_dir/" 2>/dev/null
        [[ -f "$CFG/cert_domain" ]] && cp "$CFG/cert_domain" "$cert_backup_dir/" 2>/dev/null
    fi
    
    # 删除配置目录（但保留证书）
    find "$CFG" -name "*.json" -delete 2>/dev/null
    find "$CFG" -name "*.join" -delete 2>/dev/null
    find "$CFG" -name "*.yaml" -delete 2>/dev/null
    find "$CFG" -name "*.conf" -delete 2>/dev/null
    rm -f "$CFG/installed_protocols" 2>/dev/null
    
    # 如果没有证书，删除整个目录
    if [[ ! -d "$CFG/certs" ]]; then
        rm -rf "$CFG"
    else
        _ok "证书已保留，配置文件已清理，下次安装将自动复用证书"
    fi
    
    _info "删除快捷命令..."
    rm -f /usr/local/bin/vless /usr/local/bin/vless.sh /usr/bin/vless 2>/dev/null
    
    _ok "卸载完成"
    echo ""
    echo -e "  ${Y}已保留的内容:${NC}"
    echo -e "  • 软件包: xray, sing-box, snell-server"
    echo -e "  • 软件包: anytls-server, shadow-tls"
    echo -e "  • ${G}域名证书: 下次安装将自动复用，无需重新申请${NC}"
    echo ""
    echo -e "  ${C}如需完全删除软件包，请执行:${NC}"
    echo -e "  ${G}rm -f /usr/local/bin/{xray,sing-box,snell-server*,anytls-*,shadow-tls}${NC}"
    echo ""
    echo -e "  ${C}如需删除证书，请执行:${NC}"
    echo -e "  ${G}rm -rf /etc/vless-reality/certs /etc/vless-reality/cert_domain${NC}"
}

#═══════════════════════════════════════════════════════════════════════════════
# 协议安装流程
#═══════════════════════════════════════════════════════════════════════════════

# 协议选择菜单
select_protocol() {
    echo ""
    _line
    echo -e "  ${W}选择代理协议${NC}"
    _line
    _item "1" "VLESS + Reality ${D}(推荐, 抗封锁)${NC}"
    _item "2" "VLESS + Reality + XHTTP ${D}(多路复用)${NC}"
    _item "3" "VLESS + WS + TLS ${D}(CDN友好, 可作回落)${NC}"
    _item "4" "VMess + WS ${D}(回落分流/免流)${NC}"
    _item "5" "VLESS-XTLS-Vision ${D}(支持回落)${NC}"
    _item "6" "Trojan ${D}(支持回落)${NC}"
    _item "7" "Hysteria2 ${D}(UDP高速)${NC}"
    _item "8" "Shadowsocks"
    _item "9" "SOCKS5"
    _line
    echo -e "  ${W}Surge 专属${NC}"
    _line
    _item "10" "Snell v4"
    _item "11" "Snell v5"
    _line
    echo -e "  ${W}其他协议${NC}"
    _line
    _item "12" "AnyTLS"
    _item "13" "TUIC v5"
    _item "14" "NaïveProxy"
    echo ""
    echo -e "  ${D}提示: 5/6 占用443端口，3/4 可作为回落共用${NC}"
    echo ""
    
    while true; do
        read -rp "  选择协议 [1-14]: " choice
        case $choice in
            1) SELECTED_PROTOCOL="vless"; break ;;
            2) SELECTED_PROTOCOL="vless-xhttp"; break ;;
            3) SELECTED_PROTOCOL="vless-ws"; break ;;
            4) SELECTED_PROTOCOL="vmess-ws"; break ;;
            5) SELECTED_PROTOCOL="vless-vision"; break ;;
            6) SELECTED_PROTOCOL="trojan"; break ;;
            7) SELECTED_PROTOCOL="hy2"; break ;;
            8) select_ss_version; break ;;
            9) SELECTED_PROTOCOL="socks"; break ;;
            10) SELECTED_PROTOCOL="snell"; break ;;
            11) SELECTED_PROTOCOL="snell-v5"; break ;;
            12) SELECTED_PROTOCOL="anytls"; break ;;
            13) SELECTED_PROTOCOL="tuic"; break ;;
            14) SELECTED_PROTOCOL="naive"; break ;;
            *) _err "无效选择" ;;
        esac
    done
}

# Shadowsocks 版本选择子菜单
select_ss_version() {
    echo ""
    _line
    echo -e "  ${W}选择 Shadowsocks 版本${NC}"
    _line
    _item "1" "SS2022 ${D}(新版加密, 需时间同步)${NC}"
    _item "2" "SS 传统版 ${D}(兼容性好, 无时间校验)${NC}"
    _item "0" "返回上级"
    echo ""
    
    while true; do
        read -rp "  选择版本 [0-2]: " ss_choice
        case $ss_choice in
            1) SELECTED_PROTOCOL="ss2022"; return ;;
            2) SELECTED_PROTOCOL="ss-legacy"; return ;;
            0) select_protocol; return ;;
            *) _err "无效选择" ;;
        esac
    done
}

do_install_server() {
    # check_installed && { _warn "已安装，请先卸载"; return; }
    _header
    echo -e "  ${W}服务端安装向导${NC}"
    echo -e "  系统: ${C}$DISTRO${NC}"
    
    # 选择协议
    select_protocol
    local protocol="$SELECTED_PROTOCOL"
    
    # 检查该协议是否已安装
    if is_protocol_installed "$protocol"; then
        _warn "协议 $(get_protocol_name $protocol) 已安装"
        read -rp "  是否重新安装? [y/N]: " reinstall
        if [[ "$reinstall" =~ ^[yY]$ ]]; then
            _info "卸载现有 $protocol 协议..."
            
            # 根据协议类型进行清理
            if [[ " $XRAY_PROTOCOLS " == *" $protocol "* ]]; then
                # Xray 协议：停止服务，删除配置，重新生成
                unregister_protocol "$protocol"
                rm -f "$CFG/${protocol}.join"
                
                local remaining_xray=$(get_xray_protocols)
                if [[ -n "$remaining_xray" ]]; then
                    svc stop vless-reality 2>/dev/null
                    rm -f "$CFG/config.json"
                    generate_xray_config
                    svc start vless-reality 2>/dev/null
                else
                    svc stop vless-reality 2>/dev/null
                    rm -f "$CFG/config.json"
                fi
                
            elif [[ " $SINGBOX_PROTOCOLS " == *" $protocol "* ]]; then
                # Sing-box 协议 (hy2/tuic)：清理特定资源
                
                # Hysteria2/TUIC: 先清理 iptables 端口跳跃规则
                [[ "$protocol" == "hy2" || "$protocol" == "tuic" ]] && cleanup_hy2_nat_rules
                
                # 停止服务
                svc stop vless-singbox 2>/dev/null
                
                unregister_protocol "$protocol"
                rm -f "$CFG/${protocol}.join"
                
                # 删除协议特定的证书目录
                [[ "$protocol" == "hy2" ]] && rm -rf "$CFG/certs/hy2"
                [[ "$protocol" == "tuic" ]] && rm -rf "$CFG/certs/tuic"
                
                local remaining_singbox=$(get_singbox_protocols)
                if [[ -n "$remaining_singbox" ]]; then
                    rm -f "$CFG/singbox.json"
                    generate_singbox_config
                    svc start vless-singbox 2>/dev/null
                else
                    rm -f "$CFG/singbox.json"
                fi
                
            elif [[ " $STANDALONE_PROTOCOLS " == *" $protocol "* ]]; then
                # 独立协议 (Snell/AnyTLS/ShadowTLS)：停止服务，删除配置和服务文件
                local service_name="vless-${protocol}"
                
                # 停止主服务
                svc stop "$service_name" 2>/dev/null
                
                # ShadowTLS 组合协议：还需要停止后端服务
                if [[ "$protocol" == "snell-shadowtls" || "$protocol" == "snell-v5-shadowtls" || "$protocol" == "ss2022-shadowtls" ]]; then
                    local backend_svc="${BACKEND_NAME[$protocol]}"
                    [[ -n "$backend_svc" ]] && svc stop "$backend_svc" 2>/dev/null
                fi
                
                unregister_protocol "$protocol"
                rm -f "$CFG/${protocol}.join"
                
                # 删除配置文件
                case "$protocol" in
                    snell) rm -f "$CFG/snell.conf" ;;
                    snell-v5) rm -f "$CFG/snell-v5.conf" ;;
                    snell-shadowtls) rm -f "$CFG/snell-shadowtls.conf" ;;
                    snell-v5-shadowtls) rm -f "$CFG/snell-v5-shadowtls.conf" ;;
                    ss2022-shadowtls) rm -f "$CFG/ss2022-shadowtls-backend.json" ;;
                esac
                
                # 删除服务文件
                if [[ "$DISTRO" == "alpine" ]]; then
                    rc-update del "$service_name" default 2>/dev/null
                    rm -f "/etc/init.d/$service_name"
                    # ShadowTLS 后端服务
                    if [[ -n "${BACKEND_NAME[$protocol]:-}" ]]; then
                        rc-update del "${BACKEND_NAME[$protocol]}" default 2>/dev/null
                        rm -f "/etc/init.d/${BACKEND_NAME[$protocol]}"
                    fi
                else
                    systemctl disable "$service_name" 2>/dev/null
                    rm -f "/etc/systemd/system/${service_name}.service"
                    # ShadowTLS 后端服务
                    if [[ -n "${BACKEND_NAME[$protocol]:-}" ]]; then
                        systemctl disable "${BACKEND_NAME[$protocol]}" 2>/dev/null
                        rm -f "/etc/systemd/system/${BACKEND_NAME[$protocol]}.service"
                    fi
                    systemctl daemon-reload
                fi
            fi
            
            _ok "旧配置已清理"
        else
            return
        fi
    fi
    
    # 只有 SS2022 需要时间同步
    if [[ "$protocol" == "ss2022" || "$protocol" == "ss2022-shadowtls" ]]; then
        sync_time
    fi

    # 检测并安装基础依赖
    _info "检测基础依赖..."
    check_dependencies || { _err "依赖检测失败"; return 1; }

    _info "检测网络环境..."
    local ipv4=$(get_ipv4) ipv6=$(get_ipv6)
    echo -e "  IPv4: ${ipv4:-${R}无${NC}}"
    echo -e "  IPv6: ${ipv6:-${R}无${NC}}"
    [[ -z "$ipv4" && -z "$ipv6" ]] && { _err "无法获取公网IP"; return 1; }
    echo ""

    # === 主协议冲突检测 ===
    # Vision 和 Trojan 都是 443 端口主协议，不能同时安装
    local master_protocols="vless-vision trojan"
    if echo "$master_protocols" | grep -qw "$protocol"; then
        local existing_master=""
        local existing_master_name=""
        
        if [[ "$protocol" == "vless-vision" ]] && db_exists "xray" "trojan"; then
            existing_master="trojan"
            existing_master_name="Trojan"
        elif [[ "$protocol" == "trojan" ]] && db_exists "xray" "vless-vision"; then
            existing_master="vless-vision"
            existing_master_name="VLESS-XTLS-Vision"
        fi
        
        if [[ -n "$existing_master" ]]; then
            echo ""
            _warn "检测到已安装 $existing_master_name (443端口主协议)"
            echo ""
            echo -e "  ${Y}$existing_master_name 和 $(get_protocol_name $protocol) 都需要 443 端口${NC}"
            echo -e "  ${Y}它们不能同时作为主协议运行${NC}"
            echo ""
            echo -e "  ${W}选项：${NC}"
            echo -e "  1) 卸载 $existing_master_name，安装 $(get_protocol_name $protocol)"
            echo -e "  2) 使用其他端口安装 $(get_protocol_name $protocol) (非标准端口)"
            echo -e "  3) 取消安装"
            echo ""
            
            while true; do
                read -rp "  请选择 [1-3]: " master_choice
                case "$master_choice" in
                    1)
                        _info "卸载 $existing_master_name..."
                        unregister_protocol "$existing_master"
                        rm -f "$CFG/${existing_master}.join"
                        # 重新生成 Xray 配置
                        local remaining_xray=$(get_xray_protocols)
                        if [[ -n "$remaining_xray" ]]; then
                            svc stop vless-reality 2>/dev/null
                            rm -f "$CFG/config.json"
                            generate_xray_config
                            svc start vless-reality 2>/dev/null
                        else
                            svc stop vless-reality 2>/dev/null
                            rm -f "$CFG/config.json"
                        fi
                        _ok "$existing_master_name 已卸载"
                        break
                        ;;
                    2)
                        _warn "将使用非 443 端口，可能影响伪装效果"
                        break
                        ;;
                    3)
                        _info "已取消安装"
                        return
                        ;;
                    *)
                        _err "无效选择"
                        ;;
                esac
            done
        fi
    fi

    install_deps || return
    
    # 根据协议安装对应软件
    case "$protocol" in
        vless|vless-xhttp|vless-ws|vless-vision|ss2022|ss-legacy|trojan)
            install_xray || return
            ;;
        hy2|tuic)
            install_singbox || return
            ;;
        snell)
            install_snell || return
            ;;
        snell-v5)
            install_snell_v5 || return
            ;;
        snell-shadowtls)
            install_snell || return
            install_shadowtls || return
            ;;
        snell-v5-shadowtls)
            install_snell_v5 || return
            install_shadowtls || return
            ;;
        ss2022-shadowtls)
            install_xray || return
            install_shadowtls || return
            ;;
        anytls)
            install_anytls || return
            ;;
        naive)
            install_naive || return
            ;;
    esac

    _info "生成配置参数..."
    
    # 使用新的智能端口选择
    local port=$(ask_port "$protocol")
    
    case "$protocol" in
        vless)
            local uuid=$(gen_uuid) sid=$(gen_sid)
            local keys=$(xray x25519 2>/dev/null)
            [[ -z "$keys" ]] && { _err "密钥生成失败"; return 1; }
            local privkey=$(echo "$keys" | grep "PrivateKey:" | awk '{print $2}')
            local pubkey=$(echo "$keys" | grep "Password:" | awk '{print $2}')
            [[ -z "$privkey" || -z "$pubkey" ]] && { _err "密钥提取失败"; return 1; }
            
            # Reality协议不需要证书，直接选择SNI
            echo "" >&2
            echo -e "  ${Y}Reality协议无需本地证书，直接配置SNI...${NC}" >&2
            local final_sni=$(ask_sni_config "$(gen_sni)" "")
            
            echo ""
            _line
            echo -e "  ${C}VLESS+Reality 配置${NC}"
            _line
            echo -e "  端口: ${G}$port${NC}  UUID: ${G}${uuid:0:8}...${NC}"
            echo -e "  SNI: ${G}$final_sni${NC}  ShortID: ${G}$sid${NC}"
            _line
            echo ""
            read -rp "  确认安装? [Y/n]: " confirm
            [[ "$confirm" =~ ^[nN]$ ]] && return
            
            _info "生成配置..."
            gen_server_config "$uuid" "$port" "$privkey" "$pubkey" "$sid" "$final_sni"
            ;;
        vless-xhttp)
            local uuid=$(gen_uuid) sid=$(gen_sid) path="$(gen_xhttp_path)"
            local keys=$(xray x25519 2>/dev/null)
            [[ -z "$keys" ]] && { _err "密钥生成失败"; return 1; }
            local privkey=$(echo "$keys" | grep "PrivateKey:" | awk '{print $2}')
            local pubkey=$(echo "$keys" | grep "Password:" | awk '{print $2}')
            [[ -z "$privkey" || -z "$pubkey" ]] && { _err "密钥提取失败"; return 1; }
            
            # Reality+XHTTP协议不需要证书，直接选择SNI
            echo "" >&2
            echo -e "  ${Y}Reality+XHTTP协议无需本地证书，直接配置SNI...${NC}" >&2
            local final_sni=$(ask_sni_config "$(gen_sni)" "")
            
            echo ""
            _line
            echo -e "  ${C}VLESS+Reality+XHTTP 配置${NC}"
            _line
            echo -e "  端口: ${G}$port${NC}  UUID: ${G}${uuid:0:8}...${NC}"
            echo -e "  SNI: ${G}$final_sni${NC}  ShortID: ${G}$sid${NC}"
            echo -e "  Path: ${G}$path${NC}"
            _line
            echo ""
            read -rp "  确认安装? [Y/n]: " confirm
            [[ "$confirm" =~ ^[nN]$ ]] && return
            
            _info "生成配置..."
            gen_vless_xhttp_server_config "$uuid" "$port" "$privkey" "$pubkey" "$sid" "$final_sni" "$path"
            ;;
        vless-ws)
            local uuid=$(gen_uuid) path="/vless"
            
            # 检查是否有主协议（用于回落）
            local master_domain=""
            local master_protocol=""
            if db_exists "xray" "vless-vision"; then
                master_domain=$(db_get_field "xray" "vless-vision" "sni")
                master_protocol="vless-vision"
            elif db_exists "xray" "trojan"; then
                master_domain=$(db_get_field "xray" "trojan" "sni")
                master_protocol="trojan"
            fi
            
            # 检查证书域名
            local cert_domain=""
            if [[ -f "$CFG/cert_domain" ]]; then
                cert_domain=$(cat "$CFG/cert_domain")
            fi
            
            local final_sni=""
            # 如果是回落子协议，强制使用证书域名（必须和 TLS 证书匹配）
            if [[ -n "$master_protocol" ]]; then
                if [[ -n "$cert_domain" ]]; then
                    final_sni="$cert_domain"
                    echo ""
                    _warn "作为回落子协议，SNI 必须与主协议证书域名一致"
                    _ok "自动使用证书域名: $cert_domain"
                elif [[ -n "$master_domain" ]]; then
                    final_sni="$master_domain"
                    _ok "自动使用主协议 SNI: $master_domain"
                else
                    # 使用统一的证书和 Nginx 配置函数
                    setup_cert_and_nginx "vless-ws"
                    cert_domain="$CERT_DOMAIN"
                    final_sni=$(ask_sni_config "$(gen_sni)" "$cert_domain")
                fi
            else
                # 独立安装，使用统一的证书和 Nginx 配置函数
                setup_cert_and_nginx "vless-ws"
                cert_domain="$CERT_DOMAIN"
                final_sni=$(ask_sni_config "$(gen_sni)" "$cert_domain")
            fi
            
            read -rp "  WS Path [回车默认 $path]: " _p
            [[ -n "$_p" ]] && path="$_p"
            [[ "$path" != /* ]] && path="/$path"
            
            echo ""
            _line
            echo -e "  ${C}VLESS+WS+TLS 配置${NC}"
            _line
            echo -e "  端口: ${G}$port${NC}  UUID: ${G}${uuid:0:8}...${NC}"
            echo -e "  SNI: ${G}$final_sni${NC}  Path: ${G}$path${NC}"
            [[ -n "$cert_domain" ]] && echo -e "  订阅端口: ${G}${NGINX_PORT:-8443}${NC}"
            _line
            echo ""
            read -rp "  确认安装? [Y/n]: " confirm
            [[ "$confirm" =~ ^[nN]$ ]] && return
            
            _info "生成配置..."
            gen_vless_ws_server_config "$uuid" "$port" "$final_sni" "$path"
            ;;
        vmess-ws)
            local uuid=$(gen_uuid)

            # 检查是否有主协议（用于回落）
            local master_domain=""
            local master_protocol=""
            if db_exists "xray" "vless-vision"; then
                master_domain=$(db_get_field "xray" "vless-vision" "sni")
                master_protocol="vless-vision"
            elif db_exists "xray" "trojan"; then
                master_domain=$(db_get_field "xray" "trojan" "sni")
                master_protocol="trojan"
            fi
            
            # 检查证书域名
            local cert_domain=""
            if [[ -f "$CFG/cert_domain" ]]; then
                cert_domain=$(cat "$CFG/cert_domain")
            elif [[ -f "$CFG/certs/server.crt" ]]; then
                # 从证书中提取域名
                cert_domain=$(openssl x509 -in "$CFG/certs/server.crt" -noout -subject 2>/dev/null | sed -n 's/.*CN *= *\([^,]*\).*/\1/p')
            fi
            
            local final_sni=""
            local use_new_cert=false
            # 如果是回落子协议，强制使用主协议的 SNI（必须和证书匹配）
            if [[ -n "$master_protocol" ]]; then
                if [[ -n "$cert_domain" ]]; then
                    final_sni="$cert_domain"
                    echo ""
                    _warn "作为回落子协议，SNI 必须与主协议证书域名一致"
                    _ok "自动使用证书域名: $cert_domain"
                elif [[ -n "$master_domain" ]]; then
                    final_sni="$master_domain"
                    _ok "自动使用主协议 SNI: $master_domain"
                else
                    final_sni=$(ask_sni_config "$(gen_sni)" "")
                fi
            else
                # 独立安装
                # 检查是否有真实证书（CA 签发的）
                local is_real_cert=false
                if [[ -f "$CFG/certs/server.crt" ]]; then
                    local issuer=$(openssl x509 -in "$CFG/certs/server.crt" -noout -issuer 2>/dev/null)
                    if [[ "$issuer" == *"Let's Encrypt"* ]] || [[ "$issuer" == *"R3"* ]] || [[ "$issuer" == *"R10"* ]] || [[ "$issuer" == *"R11"* ]] || [[ "$issuer" == *"E1"* ]] || [[ "$issuer" == *"ZeroSSL"* ]] || [[ "$issuer" == *"Buypass"* ]]; then
                        is_real_cert=true
                    fi
                fi
                
                if [[ "$is_real_cert" == "true" && -n "$cert_domain" ]]; then
                    # 有真实证书，强制使用证书域名
                    final_sni="$cert_domain"
                    echo ""
                    _ok "检测到真实证书 (域名: $cert_domain)"
                    _ok "SNI 将使用证书域名: $cert_domain"
                    use_new_cert=false
                else
                    # 没有证书或只有自签名证书，询问 SNI 并生成对应证书
                    use_new_cert=true
                    final_sni=$(ask_sni_config "$(gen_sni)" "")
                fi
            fi

            local path="/vmess"
            read -rp "  WS Path [回车默认 $path]: " _p
            [[ -n "$_p" ]] && path="$_p"
            [[ "$path" != /* ]] && path="/$path"

            # 避免和 vless-ws path 撞车（简单提示）
            if db_exists "xray" "vless-ws"; then
                local used_path=$(db_get_field "xray" "vless-ws" "path")
                if [[ -n "$used_path" && "$used_path" == "$path" ]]; then
                    _warn "该 Path 已被 vless-ws 使用：$used_path（回落会冲突），建议换一个"
                fi
            fi

            echo ""
            _line
            echo -e "  ${C}VMess + WS 配置${NC}"
            _line
            echo -e "  内部端口: ${G}$port${NC} (若启用 443 回落复用，会走 ${master_protocol:-主协议} 的 443 对外)"
            echo -e "  UUID: ${G}$uuid${NC}"
            echo -e "  SNI/Host: ${G}$final_sni${NC}"
            echo -e "  WS Path: ${G}$path${NC}"
            _line
            echo ""
            read -rp "  确认安装? [Y/n]: " confirm
            [[ "$confirm" =~ ^[nN]$ ]] && return

            _info "生成配置..."
            gen_vmess_ws_server_config "$uuid" "$port" "$final_sni" "$path" "$use_new_cert"
            ;;
        vless-vision)
            local uuid=$(gen_uuid)
            
            # 使用统一的证书和 Nginx 配置函数
            setup_cert_and_nginx "vless-vision"
            local cert_domain="$CERT_DOMAIN"
            
            # 询问SNI配置
            local final_sni=$(ask_sni_config "$(gen_sni)" "$cert_domain")
            
            echo ""
            _line
            echo -e "  ${C}VLESS-XTLS-Vision 配置${NC}"
            _line
            echo -e "  端口: ${G}$port${NC}  UUID: ${G}${uuid:0:8}...${NC}"
            echo -e "  SNI: ${G}$final_sni${NC}"
            [[ -n "$CERT_DOMAIN" ]] && echo -e "  订阅端口: ${G}$NGINX_PORT${NC}"
            _line
            echo ""
            read -rp "  确认安装? [Y/n]: " confirm
            [[ "$confirm" =~ ^[nN]$ ]] && return
            
            _info "生成配置..."
            gen_vless_vision_server_config "$uuid" "$port" "$final_sni"
            ;;
        socks)
            local username=$(gen_password 8) password=$(gen_password)
            
            echo ""
            _line
            echo -e "  ${C}SOCKS5 配置${NC}"
            _line
            echo -e "  端口: ${G}$port${NC}"
            echo -e "  用户名: ${G}$username${NC}"
            echo -e "  密码: ${G}$password${NC}"
            _line
            echo ""
            
            read -rp "  确认安装? [Y/n]: " confirm
            [[ "$confirm" =~ ^[nN]$ ]] && return
            
            _info "生成配置..."
            gen_socks_server_config "$username" "$password" "$port"
            ;;
        ss2022)
            # SS2022 加密方式选择
            echo ""
            _line
            echo -e "  ${W}选择 SS2022 加密方式${NC}"
            _line
            _item "1" "2022-blake3-aes-128-gcm ${D}(推荐, 16字节密钥)${NC}"
            _item "2" "2022-blake3-aes-256-gcm ${D}(更强, 32字节密钥)${NC}"
            _item "3" "2022-blake3-chacha20-poly1305 ${D}(ARM优化, 32字节密钥)${NC}"
            echo ""
            
            local method key_len
            while true; do
                read -rp "  选择加密 [1-3]: " enc_choice
                case $enc_choice in
                    1) method="2022-blake3-aes-128-gcm"; key_len=16; break ;;
                    2) method="2022-blake3-aes-256-gcm"; key_len=32; break ;;
                    3) method="2022-blake3-chacha20-poly1305"; key_len=32; break ;;
                    *) _err "无效选择" ;;
                esac
            done
            
            local password=$(head -c $key_len /dev/urandom 2>/dev/null | base64 -w 0)
            
            echo ""
            _line
            echo -e "  ${W}ShadowTLS 插件${NC}"
            _line
            echo -e "  ${D}在高阻断环境下，您可能需要 ShadowTLS 伪装。${NC}"
            echo ""
            read -rp "  是否启用 ShadowTLS (v3) 插件? [y/N]: " enable_stls
            
            if [[ "$enable_stls" =~ ^[yY]$ ]]; then
                # 安装 ShadowTLS
                _info "安装 ShadowTLS..."
                install_shadowtls || { _err "ShadowTLS 安装失败"; return 1; }
                
                # 启用 ShadowTLS 模式
                local stls_password=$(gen_password)
                local default_sni=$(gen_sni)
                
                echo ""
                read -rp "  ShadowTLS 握手域名 [回车使用 $default_sni]: " final_sni
                final_sni="${final_sni:-$default_sni}"
                
                # ShadowTLS 监听端口（对外暴露）
                echo ""
                echo -e "  ${D}ShadowTLS 监听端口 (对外暴露，建议 443)${NC}"
                local stls_port=$(ask_port "ss2022-shadowtls")
                
                # SS2022 内部端口（自动随机生成）
                local internal_port=$(gen_port)
                
                echo ""
                _line
                echo -e "  ${C}SS2022 + ShadowTLS 配置${NC}"
                _line
                echo -e "  对外端口: ${G}$stls_port${NC} (ShadowTLS)"
                echo -e "  内部端口: ${G}$internal_port${NC} (SS2022, 自动生成)"
                echo -e "  加密: ${G}$method${NC}"
                echo -e "  SNI: ${G}$final_sni${NC}"
                _line
                echo ""
                read -rp "  确认安装? [Y/n]: " confirm
                [[ "$confirm" =~ ^[nN]$ ]] && return
                
                # 切换协议为 ss2022-shadowtls
                protocol="ss2022-shadowtls"
                SELECTED_PROTOCOL="ss2022-shadowtls"
                
                _info "生成配置..."
                gen_ss2022_shadowtls_server_config "$password" "$stls_port" "$method" "$final_sni" "$stls_password" "$internal_port"
            else
                # 普通 SS2022 模式
                echo ""
                _line
                echo -e "  ${C}Shadowsocks 2022 配置${NC}"
                _line
                echo -e "  端口: ${G}$port${NC}"
                echo -e "  加密: ${G}$method${NC}"
                echo -e "  密钥: ${G}$password${NC}"
                _line
                echo ""
                read -rp "  确认安装? [Y/n]: " confirm
                [[ "$confirm" =~ ^[nN]$ ]] && return
                
                _info "生成配置..."
                gen_ss2022_server_config "$password" "$port" "$method"
            fi
            ;;
        ss-legacy)
            # SS 传统版加密方式选择
            echo ""
            _line
            echo -e "  ${W}选择 Shadowsocks 加密方式${NC}"
            _line
            _item "1" "aes-256-gcm ${D}(推荐, 兼容性好)${NC}"
            _item "2" "aes-128-gcm"
            _item "3" "chacha20-ietf-poly1305 ${D}(ARM优化)${NC}"
            echo ""
            
            local method
            while true; do
                read -rp "  选择加密 [1-3]: " enc_choice
                case $enc_choice in
                    1) method="aes-256-gcm"; break ;;
                    2) method="aes-128-gcm"; break ;;
                    3) method="chacha20-ietf-poly1305"; break ;;
                    *) _err "无效选择" ;;
                esac
            done
            
            local password=$(gen_password)
            
            echo ""
            _line
            echo -e "  ${C}Shadowsocks 传统版配置${NC}"
            _line
            echo -e "  端口: ${G}$port${NC}"
            echo -e "  加密: ${G}$method${NC}"
            echo -e "  密码: ${G}$password${NC}"
            echo -e "  ${D}(无时间校验，兼容性好)${NC}"
            _line
            echo ""
            read -rp "  确认安装? [Y/n]: " confirm
            [[ "$confirm" =~ ^[nN]$ ]] && return
            
            _info "生成配置..."
            gen_ss_legacy_server_config "$password" "$port" "$method"
            ;;
        hy2)
            local password=$(gen_password)
            local cert_domain=$(ask_cert_config "$(gen_sni)")
            
            # 询问SNI配置（在证书申请完成后）
            local final_sni=$(ask_sni_config "$(gen_sni)" "$cert_domain")
            
            # ===== 新增：端口跳跃开关 + 范围（默认不启用）=====
            local hop_enable=0
            local hop_start=20000
            local hop_end=50000

            echo ""
            _line
            echo -e "  ${C}Hysteria2 配置${NC}"
            _line
            echo -e "  端口: ${G}$port${NC} (UDP)"
            echo -e "  密码: ${G}$password${NC}"
            echo -e "  伪装: ${G}$final_sni${NC}"
            echo ""

            echo -e "  ${W}端口跳跃(Port Hopping)${NC}"
            echo -e "  ${D}说明：会将一段 UDP 端口范围重定向到 ${G}$port${NC}；高位随机端口有暴露风险，默认关闭。${NC}"
            read -rp "  是否启用端口跳跃? [y/N]: " hop_ans
            if [[ "$hop_ans" =~ ^[yY]$ ]]; then
                hop_enable=1

                read -rp "  起始端口 [回车默认 $hop_start]: " _hs
                [[ -n "$_hs" ]] && hop_start="$_hs"
                read -rp "  结束端口 [回车默认 $hop_end]: " _he
                [[ -n "$_he" ]] && hop_end="$_he"

                # 基础校验：数字 + 范围 + start<end
                if ! [[ "$hop_start" =~ ^[0-9]+$ && "$hop_end" =~ ^[0-9]+$ ]] \
                   || [[ "$hop_start" -lt 1 || "$hop_start" -gt 65535 ]] \
                   || [[ "$hop_end" -lt 1 || "$hop_end" -gt 65535 ]] \
                   || [[ "$hop_start" -ge "$hop_end" ]]; then
                    _warn "端口范围无效，已自动关闭端口跳跃"
                    hop_enable=0
                    hop_start=20000
                    hop_end=50000
                else
                    echo -e "  ${C}将启用：${G}${hop_start}-${hop_end}${NC} → 转发至 ${G}$port${NC}"
                fi
            else
                echo -e "  ${D}已选择：不启用端口跳跃${NC}"
            fi

            _line
            echo ""
            read -rp "  确认安装? [Y/n]: " confirm
            [[ "$confirm" =~ ^[nN]$ ]] && return

            _info "生成配置..."
            # ★改：把 hop 参数传进去
            gen_hy2_server_config "$password" "$port" "$final_sni" "$hop_enable" "$hop_start" "$hop_end"
            ;;
        trojan)
            local password=$(gen_password)
            
            # 使用统一的证书和 Nginx 配置函数
            setup_cert_and_nginx "trojan"
            local cert_domain="$CERT_DOMAIN"
            
            # 询问SNI配置
            local final_sni=$(ask_sni_config "$(gen_sni)" "$cert_domain")
            
            echo ""
            _line
            echo -e "  ${C}Trojan 配置${NC}"
            _line
            echo -e "  端口: ${G}$port${NC}"
            echo -e "  密码: ${G}$password${NC}"
            echo -e "  SNI: ${G}$final_sni${NC}"
            [[ -n "$CERT_DOMAIN" ]] && echo -e "  订阅端口: ${G}$NGINX_PORT${NC}"
            _line
            echo ""
            read -rp "  确认安装? [Y/n]: " confirm
            [[ "$confirm" =~ ^[nN]$ ]] && return
            
            _info "生成配置..."
            gen_trojan_server_config "$password" "$port" "$final_sni"
            ;;
        snell)
            # Snell PSK 需要随机生成
            local psk=$(head -c 16 /dev/urandom 2>/dev/null | base64 -w 0 | tr -d '/+=' | head -c 22)
            local version="4"
            
            echo ""
            _line
            echo -e "  ${W}ShadowTLS 插件${NC}"
            _line
            echo -e "  ${D}Surge 用户通常建议直接使用 Snell。${NC}"
            echo -e "  ${D}但在高阻断环境下，您可能需要 ShadowTLS 伪装。${NC}"
            echo ""
            read -rp "  是否启用 ShadowTLS (v3) 插件? [y/N]: " enable_stls
            
            if [[ "$enable_stls" =~ ^[yY]$ ]]; then
                # 安装 ShadowTLS
                _info "安装 ShadowTLS..."
                install_shadowtls || { _err "ShadowTLS 安装失败"; return 1; }
                
                # 启用 ShadowTLS 模式
                local stls_password=$(gen_password)
                local default_sni=$(gen_sni)
                
                echo ""
                read -rp "  ShadowTLS 握手域名 [回车使用 $default_sni]: " final_sni
                final_sni="${final_sni:-$default_sni}"
                
                # ShadowTLS 监听端口（对外暴露）
                echo ""
                echo -e "  ${D}ShadowTLS 监听端口 (对外暴露，建议 443)${NC}"
                local stls_port=$(ask_port "snell-shadowtls")
                
                # Snell 内部端口（自动随机生成）
                local internal_port=$(gen_port)
                
                echo ""
                _line
                echo -e "  ${C}Snell v4 + ShadowTLS 配置${NC}"
                _line
                echo -e "  对外端口: ${G}$stls_port${NC} (ShadowTLS)"
                echo -e "  内部端口: ${G}$internal_port${NC} (Snell, 自动生成)"
                echo -e "  PSK: ${G}$psk${NC}"
                echo -e "  SNI: ${G}$final_sni${NC}"
                _line
                echo ""
                read -rp "  确认安装? [Y/n]: " confirm
                [[ "$confirm" =~ ^[nN]$ ]] && return
                
                # 切换协议为 snell-shadowtls
                protocol="snell-shadowtls"
                SELECTED_PROTOCOL="snell-shadowtls"
                
                _info "生成配置..."
                gen_snell_shadowtls_server_config "$psk" "$stls_port" "$final_sni" "$stls_password" "4" "$internal_port"
            else
                # 普通 Snell 模式
                echo ""
                _line
                echo -e "  ${C}Snell v4 配置${NC}"
                _line
                echo -e "  端口: ${G}$port${NC}"
                echo -e "  PSK: ${G}$psk${NC}"
                echo -e "  版本: ${G}v$version${NC}"
                _line
                echo ""
                read -rp "  确认安装? [Y/n]: " confirm
                [[ "$confirm" =~ ^[nN]$ ]] && return
                
                _info "生成配置..."
                gen_snell_server_config "$psk" "$port" "$version"
            fi
            ;;
        tuic)
            local uuid=$(gen_uuid) password=$(gen_password)
            
            # TUIC不需要证书申请，直接询问SNI配置
            local final_sni=$(ask_sni_config "$(gen_sni)" "")
            
            # ===== 端口跳跃开关 + 范围（默认不启用）=====
            local hop_enable=0
            local hop_start=20000
            local hop_end=50000

            echo ""
            _line
            echo -e "  ${C}TUIC v5 配置${NC}"
            _line
            echo -e "  端口: ${G}$port${NC} (UDP/QUIC)"
            echo -e "  UUID: ${G}${uuid:0:8}...${NC}"
            echo -e "  密码: ${G}$password${NC}"
            echo -e "  SNI: ${G}$final_sni${NC}"
            echo ""

            echo -e "  ${W}端口跳跃(Port Hopping)${NC}"
            echo -e "  ${D}说明：会将一段 UDP 端口范围重定向到 ${G}$port${NC}；高位随机端口有暴露风险，默认关闭。${NC}"
            read -rp "  是否启用端口跳跃? [y/N]: " hop_ans
            if [[ "$hop_ans" =~ ^[yY]$ ]]; then
                hop_enable=1

                read -rp "  起始端口 [回车默认 $hop_start]: " _hs
                [[ -n "$_hs" ]] && hop_start="$_hs"
                read -rp "  结束端口 [回车默认 $hop_end]: " _he
                [[ -n "$_he" ]] && hop_end="$_he"

                # 基础校验：数字 + 范围 + start<end
                if ! [[ "$hop_start" =~ ^[0-9]+$ && "$hop_end" =~ ^[0-9]+$ ]] \
                   || [[ "$hop_start" -lt 1 || "$hop_start" -gt 65535 ]] \
                   || [[ "$hop_end" -lt 1 || "$hop_end" -gt 65535 ]] \
                   || [[ "$hop_start" -ge "$hop_end" ]]; then
                    _warn "端口范围无效，已自动关闭端口跳跃"
                    hop_enable=0
                    hop_start=20000
                    hop_end=50000
                else
                    echo -e "  ${C}将启用：${G}${hop_start}-${hop_end}${NC} → 转发至 ${G}$port${NC}"
                fi
            else
                echo -e "  ${D}已选择：不启用端口跳跃${NC}"
            fi

            _line
            echo ""
            read -rp "  确认安装? [Y/n]: " confirm
            [[ "$confirm" =~ ^[nN]$ ]] && return
            
            _info "生成配置..."
            gen_tuic_server_config "$uuid" "$password" "$port" "$final_sni" "$hop_enable" "$hop_start" "$hop_end"
            ;;
        anytls)
            local password=$(gen_password)
            
            # AnyTLS不需要证书申请，直接询问SNI配置
            local final_sni=$(ask_sni_config "$(gen_sni)" "")
            
            echo ""
            _line
            echo -e "  ${C}AnyTLS 配置${NC}"
            _line
            echo -e "  端口: ${G}$port${NC}"
            echo -e "  密码: ${G}$password${NC}"
            echo -e "  SNI: ${G}$final_sni${NC}"
            _line
            echo ""
            read -rp "  确认安装? [Y/n]: " confirm
            [[ "$confirm" =~ ^[nN]$ ]] && return
            
            _info "生成配置..."
            gen_anytls_server_config "$password" "$port" "$final_sni"
            ;;
        naive)
            local username=$(gen_password 8) password=$(gen_password)
            
            # NaïveProxy 推荐使用 443 端口
            echo ""
            _line
            echo -e "  ${W}NaïveProxy 配置${NC}"
            _line
            echo -e "  ${D}NaïveProxy 需要域名，Caddy 会自动申请证书${NC}"
            echo -e "  ${D}请确保域名已解析到本机 IP${NC}"
            echo ""
            
            local domain="" local_ipv4=$(get_ipv4) local_ipv6=$(get_ipv6)
            while true; do
                read -rp "  请输入域名: " domain
                [[ -z "$domain" ]] && { _err "域名不能为空"; continue; }
                
                # 验证域名解析
                _info "验证域名解析..."
                local resolved_ip=$(dig +short "$domain" A 2>/dev/null | head -1)
                local resolved_ip6=$(dig +short "$domain" AAAA 2>/dev/null | head -1)
                
                if [[ "$resolved_ip" == "$local_ipv4" ]] || [[ "$resolved_ip6" == "$local_ipv6" ]]; then
                    _ok "域名解析验证通过"
                    break
                else
                    _warn "域名解析不匹配"
                    echo -e "  ${D}本机 IP: ${local_ipv4:-无} / ${local_ipv6:-无}${NC}"
                    echo -e "  ${D}解析 IP: ${resolved_ip:-无} / ${resolved_ip6:-无}${NC}"
                    read -rp "  是否继续使用此域名? [y/N]: " force
                    [[ "$force" =~ ^[yY]$ ]] && break
                fi
            done
            
            # 端口选择
            echo ""
            local default_port="443"
            if ss -tuln 2>/dev/null | grep -q ":443 "; then
                default_port="8443"
                echo -e "  ${Y}443 端口已被占用${NC}"
            fi
            
            while true; do
                read -rp "  请输入端口 [回车使用 $default_port]: " port
                port="${port:-$default_port}"
                if ss -tuln 2>/dev/null | grep -q ":${port} "; then
                    _err "端口 $port 已被占用，请换一个"
                else
                    break
                fi
            done
            
            echo ""
            _line
            echo -e "  ${C}NaïveProxy 配置${NC}"
            _line
            echo -e "  域名: ${G}$domain${NC}"
            echo -e "  端口: ${G}$port${NC}"
            echo -e "  用户名: ${G}$username${NC}"
            echo -e "  密码: ${G}$password${NC}"
            _line
            echo ""
            read -rp "  确认安装? [Y/n]: " confirm
            [[ "$confirm" =~ ^[nN]$ ]] && return
            
            _info "生成配置..."
            gen_naive_server_config "$username" "$password" "$port" "$domain"
            ;;
        snell-v5)
            local psk=$(gen_password) version="5"
            
            echo ""
            _line
            echo -e "  ${W}ShadowTLS 插件${NC}"
            _line
            echo -e "  ${D}Surge 用户通常建议直接使用 Snell。${NC}"
            echo -e "  ${D}但在高阻断环境下，您可能需要 ShadowTLS 伪装。${NC}"
            echo ""
            read -rp "  是否启用 ShadowTLS (v3) 插件? [y/N]: " enable_stls
            
            if [[ "$enable_stls" =~ ^[yY]$ ]]; then
                # 安装 ShadowTLS
                _info "安装 ShadowTLS..."
                install_shadowtls || { _err "ShadowTLS 安装失败"; return 1; }
                
                # 启用 ShadowTLS 模式
                local stls_password=$(gen_password)
                local default_sni=$(gen_sni)
                
                echo ""
                read -rp "  ShadowTLS 握手域名 [回车使用 $default_sni]: " final_sni
                final_sni="${final_sni:-$default_sni}"
                
                # ShadowTLS 监听端口（对外暴露）
                echo ""
                echo -e "  ${D}ShadowTLS 监听端口 (对外暴露，建议 443)${NC}"
                local stls_port=$(ask_port "snell-v5-shadowtls")
                
                # Snell 内部端口（自动随机生成）
                local internal_port=$(gen_port)
                
                echo ""
                _line
                echo -e "  ${C}Snell v5 + ShadowTLS 配置${NC}"
                _line
                echo -e "  对外端口: ${G}$stls_port${NC} (ShadowTLS)"
                echo -e "  内部端口: ${G}$internal_port${NC} (Snell, 自动生成)"
                echo -e "  PSK: ${G}$psk${NC}"
                echo -e "  SNI: ${G}$final_sni${NC}"
                _line
                echo ""
                read -rp "  确认安装? [Y/n]: " confirm
                [[ "$confirm" =~ ^[nN]$ ]] && return
                
                # 切换协议为 snell-v5-shadowtls
                protocol="snell-v5-shadowtls"
                SELECTED_PROTOCOL="snell-v5-shadowtls"
                
                _info "生成配置..."
                gen_snell_shadowtls_server_config "$psk" "$stls_port" "$final_sni" "$stls_password" "5" "$internal_port"
            else
                # 普通 Snell v5 模式
                echo ""
                _line
                echo -e "  ${C}Snell v5 配置${NC}"
                _line
                echo -e "  端口: ${G}$port${NC}"
                echo -e "  PSK: ${G}$psk${NC}"
                echo -e "  版本: ${G}$version${NC}"
                _line
                echo ""
                read -rp "  确认安装? [Y/n]: " confirm
                [[ "$confirm" =~ ^[nN]$ ]] && return
                
                _info "生成配置..."
                gen_snell_v5_server_config "$psk" "$port" "$version"
            fi
            ;;
    esac
    
    _info "创建服务..."
    create_server_scripts  # 生成服务端辅助脚本（watchdog、hy2-nat、tuic-nat）
    create_service "$protocol"
    _info "启动服务..."
    
    # 保存当前安装的协议名（防止被后续函数中的循环变量覆盖）
    local current_protocol="$protocol"
    
    if start_services; then
        create_shortcut   # 安装成功才创建快捷命令
        
        # 更新订阅文件（此时数据库已更新，订阅内容才会正确）
        if [[ -f "$CFG/sub.info" ]]; then
            generate_sub_files
        fi
        
        _dline
        _ok "服务端安装完成! 快捷命令: vless"
        _ok "协议: $(get_protocol_name $current_protocol)"
        _dline
        
        # UDP协议提示开放防火墙
        if [[ "$current_protocol" == "hy2" || "$current_protocol" == "tuic" ]]; then
            # 从数据库读取端口
            local port=""
            if db_exists "singbox" "$current_protocol"; then
                port=$(db_get_field "singbox" "$current_protocol" "port")
            fi
            if [[ -n "$port" ]]; then
                echo ""
                _warn "重要: 请确保防火墙开放 UDP 端口 $port"
                echo -e "  ${D}# iptables 示例:${NC}"
                echo -e "  ${C}iptables -A INPUT -p udp --dport $port -j ACCEPT${NC}"
                echo -e "  ${D}# 或使用 ufw:${NC}"
                echo -e "  ${C}ufw allow $port/udp${NC}"
                echo ""
            fi
        fi
        
        # TUIC 协议需要客户端持有证书
        if [[ "$current_protocol" == "tuic" ]]; then
            echo ""
            _warn "TUIC v5 要求客户端必须持有服务端证书!"
            _line
            echo -e "  ${C}请在客户端执行以下命令下载证书:${NC}"
            echo ""
            echo -e "  ${G}mkdir -p /etc/vless-reality/certs${NC}"
            echo -e "  ${G}scp root@$(get_ipv4):$CFG/certs/server.crt /etc/vless-reality/certs/${NC}"
            echo ""
            echo -e "  ${D}或手动复制证书内容到客户端 /etc/vless-reality/certs/server.crt${NC}"
            _line
        fi
        
        # 清理临时文件
        rm -f "$CFG/.nginx_port_tmp" 2>/dev/null
        
        # 显示刚安装的协议配置（不清屏）
        show_single_protocol_info "$current_protocol" false
    else
        _err "安装失败"
    fi
}


show_status() {
    # 优化：单次 jq 调用获取所有数据，输出为简单文本格式便于 bash 解析
    # 设置全局变量 _INSTALLED_CACHE 供 main_menu 复用，避免重复查询
    _INSTALLED_CACHE=""
    
    [[ ! -f "$DB_FILE" ]] && { echo -e "  状态: ${D}○ 未安装${NC}"; return; }
    
    # 一次 jq 调用，输出格式: XRAY:proto1,proto2 SINGBOX:proto3 PORTS:proto1=443,proto2=8080 RULES:count
    local db_parsed=$(jq -r '
        "XRAY:" + ((.xray // {}) | keys | join(",")) + 
        " SINGBOX:" + ((.singbox // {}) | keys | join(",")) + 
        " RULES:" + ((.routing_rules // []) | length | tostring) +
        " PORTS:" + ([(.xray // {} | to_entries[] | "\(.key)=\(.value.port)"), (.singbox // {} | to_entries[] | "\(.key)=\(.value.port)")] | join(","))
    ' "$DB_FILE" 2>/dev/null)
    
    # 解析结果
    local xray_keys="" singbox_keys="" rules_count="0" ports_map=""
    local part
    for part in $db_parsed; do
        case "$part" in
            XRAY:*) xray_keys="${part#XRAY:}" ;;
            SINGBOX:*) singbox_keys="${part#SINGBOX:}" ;;
            RULES:*) rules_count="${part#RULES:}" ;;
            PORTS:*) ports_map="${part#PORTS:}" ;;
        esac
    done
    
    # 转换逗号分隔为换行分隔
    local installed=$(echo -e "${xray_keys//,/\\n}\n${singbox_keys//,/\\n}" | grep -v '^$' | sort -u)
    [[ -z "$installed" ]] && { echo -e "  状态: ${D}○ 未安装${NC}"; return; }
    
    # 缓存已安装协议供 main_menu 使用
    _INSTALLED_CACHE="$installed"
    
    local status_icon status_text
    local protocol_count=$(echo "$installed" | wc -l)
    
    # 在内存中过滤协议类型
    local xray_protocols="" singbox_protocols="" standalone_protocols=""
    local p
    for p in $XRAY_PROTOCOLS; do
        [[ ",$xray_keys," == *",$p,"* ]] && xray_protocols="$xray_protocols $p"
    done
    for p in $SINGBOX_PROTOCOLS; do
        [[ ",$singbox_keys," == *",$p,"* ]] && singbox_protocols="$singbox_protocols $p"
    done
    for p in $STANDALONE_PROTOCOLS; do
        [[ ",$singbox_keys," == *",$p,"* ]] && standalone_protocols="$standalone_protocols $p"
    done
    xray_protocols="${xray_protocols# }"
    singbox_protocols="${singbox_protocols# }"
    standalone_protocols="${standalone_protocols# }"
    
    # 检查服务运行状态
    local xray_running=false singbox_running=false
    local standalone_running=0 standalone_total=0
    
    [[ -n "$xray_protocols" ]] && svc status vless-reality >/dev/null 2>&1 && xray_running=true
    [[ -n "$singbox_protocols" ]] && svc status vless-singbox >/dev/null 2>&1 && singbox_running=true
    
    local ind_proto
    for ind_proto in $standalone_protocols; do
        ((standalone_total++))
        svc status "vless-${ind_proto}" >/dev/null 2>&1 && ((standalone_running++))
    done
    
    # 计算运行状态
    local xray_count=0 singbox_count=0
    [[ -n "$xray_protocols" ]] && xray_count=$(echo "$xray_protocols" | wc -w)
    [[ -n "$singbox_protocols" ]] && singbox_count=$(echo "$singbox_protocols" | wc -w)
    local running_protocols=0
    
    [[ "$xray_running" == "true" ]] && running_protocols=$xray_count
    [[ "$singbox_running" == "true" ]] && running_protocols=$((running_protocols + singbox_count))
    running_protocols=$((running_protocols + standalone_running))
    
    if is_paused; then
        status_icon="${Y}⏸${NC}"; status_text="${Y}已暂停${NC}"
    elif [[ $running_protocols -eq $protocol_count ]]; then
        status_icon="${G}●${NC}"; status_text="${G}运行中${NC}"
    elif [[ $running_protocols -gt 0 ]]; then
        status_icon="${Y}●${NC}"; status_text="${Y}部分运行${NC} (${running_protocols}/${protocol_count})"
    else
        status_icon="${R}●${NC}"; status_text="${R}已停止${NC}"
    fi
    
    echo -e "  状态: $status_icon $status_text"
    
    # 从 ports_map 获取端口的辅助函数（纯字符串匹配）
    _get_port() {
        local proto=$1 pair
        for pair in ${ports_map//,/ }; do
            [[ "$pair" == "$proto="* ]] && echo "${pair#*=}" && return
        done
    }
    
    # 显示协议概要
    if [[ $protocol_count -eq 1 ]]; then
        local proto_name=$(echo "$installed" | head -1)
        local port=$(_get_port "$proto_name")
        echo -e "  协议: ${C}$(get_protocol_name $proto_name)${NC}"
        echo -e "  端口: ${C}$port${NC}"
    else
        echo -e "  协议: ${C}多协议 (${protocol_count}个)${NC}"
        for proto in $installed; do
            local proto_port=$(_get_port "$proto")
            echo -e "    ${G}•${NC} $(get_protocol_name $proto) ${D}- 端口: ${proto_port}${NC}"
        done
    fi
    
    # 显示分流状态
    if [[ "$rules_count" -gt 0 ]]; then
        local warp_st=$(warp_status)
        
        # 获取第一条规则的出口类型来判断显示
        local first_outbound=$(jq -r '.routing_rules[0].outbound // ""' "$DB_FILE" 2>/dev/null)
        
        if [[ "$first_outbound" == chain:* ]]; then
            # 链式代理出口 - chain:节点名 格式已包含节点信息
            local node_name="${first_outbound#chain:}"
            # 检查该节点是否存在
            if db_chain_node_exists "$node_name"; then
                echo -e "  分流: ${G}${rules_count}条规则→${node_name}${NC}"
            else
                echo -e "  分流: ${Y}${rules_count}条规则→链式代理 (节点不存在)${NC}"
            fi
        elif [[ "$first_outbound" == "warp" ]]; then
            # WARP 出口
            if [[ "$warp_st" == "configured" || "$warp_st" == "connected" ]]; then
                echo -e "  分流: ${G}${rules_count}条规则→WARP${NC}"
            else
                echo -e "  分流: ${Y}${rules_count}条规则→WARP (未运行)${NC}"
            fi
        else
            echo -e "  分流: ${G}${rules_count}条规则${NC}"
        fi
    fi
}

#═══════════════════════════════════════════════════════════════════════════════
# 订阅与外部节点管理
#═══════════════════════════════════════════════════════════════════════════════

# 安装 Nginx
install_nginx() {
    if check_cmd nginx; then
        _ok "Nginx 已安装"
        return 0
    fi
    
    _info "安装 Nginx..."
    case "$DISTRO" in
        alpine) apk add --no-cache nginx ;;
        centos) yum install -y nginx ;;
        *) apt-get install -y -qq nginx ;;
    esac
    
    if check_cmd nginx; then
        _ok "Nginx 安装完成"
        return 0
    else
        _err "Nginx 安装失败"
        return 1
    fi
}

EXTERNAL_LINKS_FILE="$CFG/external_links.txt"
EXTERNAL_SUBS_FILE="$CFG/external_subs.txt"
EXTERNAL_CACHE_DIR="$CFG/external_nodes_cache"

# 解析 vless:// 链接
parse_vless_link() {
    local link="$1"
    # vless://uuid@server:port?params#name
    local content="${link#vless://}"
    local name="${content##*#}"
    name=$(printf '%b' "${name//%/\\x}")  # URL 解码
    # 转义 JSON 特殊字符
    name="${name//\\/\\\\}"
    name="${name//\"/\\\"}"
    content="${content%%#*}"
    
    local uuid="${content%%@*}"
    content="${content#*@}"
    
    local server_port="${content%%\?*}"
    local server="" port=""
    # 处理 IPv6 地址 [xxxx]:port
    if [[ "$server_port" == \[*\]:* ]]; then
        server="${server_port%%]:*}]"
        port="${server_port##*]:}"
    else
        server="${server_port%:*}"
        port="${server_port##*:}"
    fi
    
    local params="${content#*\?}"
    
    # 解析参数
    local security="" type="" sni="" pbk="" sid="" flow="" path="" host="" fp="" encryption=""
    IFS='&' read -ra PARAMS <<< "$params"
    for param in "${PARAMS[@]}"; do
        local key="${param%%=*}"
        local value="${param#*=}"
        value=$(printf '%b' "${value//%/\\x}")  # URL 解码
        case "$key" in
            security) security="$value" ;;
            type) type="$value" ;;
            sni) sni="$value" ;;
            pbk) pbk="$value" ;;
            sid) sid="$value" ;;
            flow) flow="$value" ;;
            path) path="$value" ;;
            host) host="$value" ;;
            fp) fp="$value" ;;
            encryption) encryption="$value" ;;
            headerType) ;; # 忽略
        esac
    done
    
    # 确保 port 是纯数字，无效则报错
    port=$(echo "$port" | tr -d '"' | tr -d ' ')
    if [[ ! "$port" =~ ^[0-9]+$ ]]; then
        echo "错误: 无法解析端口号 '$port'" >&2
        return 1
    fi
    
    # 输出 JSON 格式 (使用 jq 确保正确转义，port 使用 argjson 存储为数字)
    # 注意：字段名使用完整名称以便 gen_xray_chain_outbound 正确读取
    jq -nc \
        --arg type "vless" \
        --arg name "$name" \
        --arg server "$server" \
        --argjson port "$port" \
        --arg uuid "$uuid" \
        --arg security "$security" \
        --arg transport "${type:-tcp}" \
        --arg sni "$sni" \
        --arg publicKey "$pbk" \
        --arg shortId "$sid" \
        --arg flow "$flow" \
        --arg path "$path" \
        --arg host "$host" \
        --arg fingerprint "${fp:-chrome}" \
        --arg encryption "$encryption" \
        '{type:$type,name:$name,server:$server,port:$port,uuid:$uuid,security:$security,transport:$transport,sni:$sni,publicKey:$publicKey,shortId:$shortId,flow:$flow,path:$path,host:$host,fingerprint:$fingerprint,encryption:$encryption}'
}

# 解析 vmess:// 链接
parse_vmess_link() {
    local link="$1"
    # vmess://base64(json)
    local content="${link#vmess://}"
    local json=$(echo "$content" | base64 -d 2>/dev/null)
    [[ -z "$json" ]] && return 1
    
    local name=$(echo "$json" | jq -r '.ps // .name // "VMess"')
    local server=$(echo "$json" | jq -r '.add // .server')
    local port=$(echo "$json" | jq -r '.port')
    local uuid=$(echo "$json" | jq -r '.id // .uuid')
    local aid=$(echo "$json" | jq -r '.aid // "0"')
    local net=$(echo "$json" | jq -r '.net // "tcp"')
    local type=$(echo "$json" | jq -r '.type // "none"')
    local host=$(echo "$json" | jq -r '.host // ""')
    local path=$(echo "$json" | jq -r '.path // ""')
    local tls=$(echo "$json" | jq -r '.tls // ""')
    local sni=$(echo "$json" | jq -r '.sni // ""')
    
    # 确保 port 和 aid 是数字
    port=$(echo "$port" | tr -d '"' | tr -d ' ')
    if [[ ! "$port" =~ ^[0-9]+$ ]]; then
        echo "错误: 无法解析端口号 '$port'" >&2
        return 1
    fi
    aid=$(echo "$aid" | tr -d '"' | tr -d ' ')
    [[ ! "$aid" =~ ^[0-9]+$ ]] && aid="0"
    
    # 使用 jq 生成 JSON，确保 port 和 aid 是数字
    jq -nc \
        --arg type "vmess" \
        --arg name "$name" \
        --arg server "$server" \
        --argjson port "$port" \
        --arg uuid "$uuid" \
        --argjson aid "$aid" \
        --arg network "$net" \
        --arg host "$host" \
        --arg path "$path" \
        --arg tls "$tls" \
        --arg sni "$sni" \
        '{type:$type,name:$name,server:$server,port:$port,uuid:$uuid,aid:$aid,network:$network,host:$host,path:$path,tls:$tls,sni:$sni}'
}

# 解析 trojan:// 链接
parse_trojan_link() {
    local link="$1"
    # trojan://password@server:port?params#name
    local content="${link#trojan://}"
    local name="${content##*#}"
    name=$(printf '%b' "${name//%/\\x}")  # URL 解码
    content="${content%%#*}"
    
    local password="${content%%@*}"
    content="${content#*@}"
    
    local server_port="${content%%\?*}"
    local server="" port=""
    # 处理 IPv6 地址 [xxxx]:port
    if [[ "$server_port" == \[*\]:* ]]; then
        server="${server_port%%]:*}]"
        port="${server_port##*]:}"
    else
        server="${server_port%:*}"
        port="${server_port##*:}"
    fi
    
    local params="${content#*\?}"
    local sni="" type="tcp"
    IFS='&' read -ra PARAMS <<< "$params"
    for param in "${PARAMS[@]}"; do
        local key="${param%%=*}"
        local value="${param#*=}"
        case "$key" in
            sni) sni="$value" ;;
            type) type="$value" ;;
        esac
    done
    
    # 确保 port 是数字
    port=$(echo "$port" | tr -d '"' | tr -d ' ')
    if [[ ! "$port" =~ ^[0-9]+$ ]]; then
        echo "错误: 无法解析端口号 '$port'" >&2
        return 1
    fi
    
    # 使用 jq 生成 JSON
    jq -nc \
        --arg type "trojan" \
        --arg name "$name" \
        --arg server "$server" \
        --argjson port "$port" \
        --arg password "$password" \
        --arg sni "$sni" \
        --arg transport "$type" \
        '{type:$type,name:$name,server:$server,port:$port,password:$password,sni:$sni,transport:$transport}'
}

# 解析 ss:// 链接
parse_ss_link() {
    local link="$1"
    # ss://base64(method:password)@server:port#name
    # 或 ss://base64(method:password@server:port)#name
    local content="${link#ss://}"
    local name="${content##*#}"
    name=$(printf '%b' "${name//%/\\x}")
    content="${content%%#*}"
    
    local server="" port="" method="" password=""
    
    if [[ "$content" == *"@"* ]]; then
        # 格式: base64@server:port
        local encoded="${content%%@*}"
        local decoded=$(echo "$encoded" | base64 -d 2>/dev/null)
        if [[ "$decoded" == *":"* ]]; then
            method="${decoded%%:*}"
            password="${decoded#*:}"
        fi
        local server_port="${content#*@}"
        # 处理 IPv6 地址 [xxxx]:port
        if [[ "$server_port" == \[*\]:* ]]; then
            server="${server_port%%]:*}]"
            port="${server_port##*]:}"
        else
            server="${server_port%:*}"
            port="${server_port##*:}"
        fi
    else
        # 格式: base64(全部)
        local decoded=$(echo "$content" | base64 -d 2>/dev/null)
        if [[ "$decoded" == *"@"* ]]; then
            local method_pass="${decoded%%@*}"
            method="${method_pass%%:*}"
            password="${method_pass#*:}"
            local server_port="${decoded#*@}"
            # 处理 IPv6 地址 [xxxx]:port
            if [[ "$server_port" == \[*\]:* ]]; then
                server="${server_port%%]:*}]"
                port="${server_port##*]:}"
            else
                server="${server_port%:*}"
                port="${server_port##*:}"
            fi
        fi
    fi
    
    # 确保 port 是数字
    port=$(echo "$port" | tr -d '"' | tr -d ' ')
    if [[ ! "$port" =~ ^[0-9]+$ ]]; then
        echo "错误: 无法解析端口号 '$port'" >&2
        return 1
    fi
    
    # 使用 jq 生成 JSON
    jq -nc \
        --arg type "ss" \
        --arg name "$name" \
        --arg server "$server" \
        --argjson port "$port" \
        --arg method "$method" \
        --arg password "$password" \
        '{type:$type,name:$name,server:$server,port:$port,method:$method,password:$password}'
}

# 解析 hysteria2:// 链接
parse_hy2_link() {
    local link="$1"
    # hysteria2://password@server:port?params#name
    local content="${link#hysteria2://}"
    content="${content#hy2://}"
    local name="${content##*#}"
    name=$(printf '%b' "${name//%/\\x}")  # URL 解码
    content="${content%%#*}"
    
    local password="${content%%@*}"
    content="${content#*@}"
    
    local server_port="${content%%\?*}"
    local server="" port=""
    # 处理 IPv6 地址 [xxxx]:port
    if [[ "$server_port" == \[*\]:* ]]; then
        server="${server_port%%]:*}]"
        port="${server_port##*]:}"
    else
        server="${server_port%:*}"
        port="${server_port##*:}"
    fi
    
    local params="${content#*\?}"
    local sni="" insecure="1"
    IFS='&' read -ra PARAMS <<< "$params"
    for param in "${PARAMS[@]}"; do
        local key="${param%%=*}"
        local value="${param#*=}"
        case "$key" in
            sni) sni="$value" ;;
            insecure) insecure="$value" ;;
        esac
    done
    
    # 确保 port 是数字
    port=$(echo "$port" | tr -d '"' | tr -d ' ')
    if [[ ! "$port" =~ ^[0-9]+$ ]]; then
        echo "错误: 无法解析端口号 '$port'" >&2
        return 1
    fi
    
    # 使用 jq 生成 JSON
    jq -nc \
        --arg type "hysteria2" \
        --arg name "$name" \
        --arg server "$server" \
        --argjson port "$port" \
        --arg password "$password" \
        --arg sni "$sni" \
        '{type:$type,name:$name,server:$server,port:$port,password:$password,sni:$sni}'
}

# 解析 anytls:// 链接
parse_anytls_link() {
    local link="$1"
    # anytls://password@server:port?sni=xxx#name
    local content="${link#anytls://}"
    local name="${content##*#}"
    name=$(printf '%b' "${name//%/\\x}")
    content="${content%%#*}"
    
    local password="${content%%@*}"
    content="${content#*@}"
    
    local server_port="${content%%\?*}"
    local server="" port=""
    # 处理 IPv6 地址 [xxxx]:port
    if [[ "$server_port" == \[*\]:* ]]; then
        server="${server_port%%]:*}]"
        port="${server_port##*]:}"
    else
        server="${server_port%:*}"
        port="${server_port##*:}"
    fi
    
    local params="${content#*\?}"
    local sni=""
    IFS='&' read -ra PARAMS <<< "$params"
    for param in "${PARAMS[@]}"; do
        local key="${param%%=*}"
        local value="${param#*=}"
        case "$key" in
            sni) sni="$value" ;;
        esac
    done
    
    # 确保 port 是数字
    port=$(echo "$port" | tr -d '"' | tr -d ' ')
    if [[ ! "$port" =~ ^[0-9]+$ ]]; then
        echo "错误: 无法解析端口号 '$port'" >&2
        return 1
    fi
    
    # 使用 jq 生成 JSON
    jq -nc \
        --arg type "anytls" \
        --arg name "$name" \
        --arg server "$server" \
        --argjson port "$port" \
        --arg password "$password" \
        --arg sni "$sni" \
        '{type:$type,name:$name,server:$server,port:$port,password:$password,sni:$sni}'
}

# 解析任意分享链接
parse_share_link() {
    local link="$1"
    case "$link" in
        vless://*) parse_vless_link "$link" ;;
        vmess://*) parse_vmess_link "$link" ;;
        trojan://*) parse_trojan_link "$link" ;;
        ss://*) parse_ss_link "$link" ;;
        hysteria2://*|hy2://*) parse_hy2_link "$link" ;;
        anytls://*) parse_anytls_link "$link" ;;
        *) echo "" ;;
    esac
}

# 从分享链接提取节点名称
get_link_name() {
    local link="$1"
    local name="${link##*#}"
    name=$(printf '%b' "${name//%/\\x}")
    [[ -z "$name" || "$name" == "$link" ]] && name="未命名节点"
    echo "$name"
}

# 拉取订阅内容
fetch_subscription() {
    local url="$1"
    local content=$(curl -sL --connect-timeout 10 --max-time 30 "$url" 2>/dev/null)
    [[ -z "$content" ]] && return 1
    
    # 尝试 Base64 解码
    local decoded=$(echo "$content" | base64 -d 2>/dev/null)
    if [[ -n "$decoded" && "$decoded" == *"://"* ]]; then
        echo "$decoded"
        return 0
    fi
    
    # 检查是否是 Clash YAML
    if [[ "$content" == *"proxies:"* ]]; then
        # 解析 Clash YAML 节点，转换为分享链接
        local links=""
        local in_proxies=false
        local current_proxy=""
        local name="" type="" server="" port="" uuid="" password="" method=""
        local network="" tls="" sni="" path="" host="" flow="" pbk="" sid=""
        
        while IFS= read -r line || [[ -n "$line" ]]; do
            # 检测 proxies 段
            if [[ "$line" =~ ^proxies: ]]; then
                in_proxies=true
                continue
            fi
            
            # 检测离开 proxies 段
            if [[ "$in_proxies" == "true" && "$line" =~ ^[a-z-]+: && ! "$line" =~ ^[[:space:]] ]]; then
                in_proxies=false
            fi
            
            [[ "$in_proxies" != "true" ]] && continue
            
            # 新节点开始
            if [[ "$line" =~ ^[[:space:]]*-[[:space:]]*name: ]]; then
                # 保存上一个节点
                if [[ -n "$name" && -n "$type" && -n "$server" && -n "$port" ]]; then
                    case "$type" in
                        vless)
                            local link="vless://${uuid}@${server}:${port}?encryption=none"
                            [[ -n "$flow" ]] && link+="&flow=$flow"
                            [[ "$tls" == "true" ]] && link+="&security=reality&type=${network:-tcp}&sni=$sni&fp=chrome&pbk=$pbk&sid=$sid" || link+="&security=none&type=${network:-tcp}"
                            [[ "$network" == "ws" ]] && link+="&type=ws&path=$(urlencode "$path")&host=$host"
                            link+="#$(urlencode "$name")"
                            links+="$link"$'\n'
                            ;;
                        vmess)
                            local vmess_json="{\"v\":\"2\",\"ps\":\"$name\",\"add\":\"$server\",\"port\":\"$port\",\"id\":\"$uuid\",\"aid\":\"0\",\"scy\":\"auto\",\"net\":\"${network:-tcp}\",\"type\":\"none\",\"host\":\"$host\",\"path\":\"$path\",\"tls\":\"$([[ "$tls" == "true" ]] && echo "tls" || echo "")\",\"sni\":\"$sni\"}"
                            links+="vmess://$(echo -n "$vmess_json" | base64 -w 0)"$'\n'
                            ;;
                        trojan)
                            links+="trojan://${password}@${server}:${port}?sni=$sni#$(urlencode "$name")"$'\n'
                            ;;
                        ss)
                            local ss_encoded=$(echo -n "${method}:${password}" | base64 -w 0)
                            links+="ss://${ss_encoded}@${server}:${port}#$(urlencode "$name")"$'\n'
                            ;;
                        hysteria2)
                            links+="hysteria2://${password}@${server}:${port}?sni=$sni#$(urlencode "$name")"$'\n'
                            ;;
                        tuic)
                            links+="tuic://${uuid}:${password}@${server}:${port}?sni=$sni#$(urlencode "$name")"$'\n'
                            ;;
                    esac
                fi
                # 重置变量
                name="" type="" server="" port="" uuid="" password="" method=""
                network="" tls="" sni="" path="" host="" flow="" pbk="" sid=""
                name=$(echo "$line" | sed 's/.*name:[[:space:]]*"\?\([^"]*\)"\?.*/\1/')
                continue
            fi
            
            # 解析属性 (去掉引号)
            _strip_quotes() { local v="$1"; v="${v#\"}"; v="${v%\"}"; v="${v#\'}"; v="${v%\'}"; echo "$v"; }
            [[ "$line" =~ ^[[:space:]]*type:[[:space:]]*(.*) ]] && type=$(_strip_quotes "${BASH_REMATCH[1]}")
            [[ "$line" =~ ^[[:space:]]*server:[[:space:]]*(.*) ]] && server=$(_strip_quotes "${BASH_REMATCH[1]}")
            [[ "$line" =~ ^[[:space:]]*port:[[:space:]]*(.*) ]] && port=$(_strip_quotes "${BASH_REMATCH[1]}")
            [[ "$line" =~ ^[[:space:]]*uuid:[[:space:]]*(.*) ]] && uuid=$(_strip_quotes "${BASH_REMATCH[1]}")
            [[ "$line" =~ ^[[:space:]]*password:[[:space:]]*(.*) ]] && password=$(_strip_quotes "${BASH_REMATCH[1]}")
            [[ "$line" =~ ^[[:space:]]*cipher:[[:space:]]*(.*) ]] && method=$(_strip_quotes "${BASH_REMATCH[1]}")
            [[ "$line" =~ ^[[:space:]]*network:[[:space:]]*(.*) ]] && network=$(_strip_quotes "${BASH_REMATCH[1]}")
            [[ "$line" =~ ^[[:space:]]*tls:[[:space:]]*(.*) ]] && tls=$(_strip_quotes "${BASH_REMATCH[1]}")
            [[ "$line" =~ ^[[:space:]]*sni:[[:space:]]*(.*) ]] && sni=$(_strip_quotes "${BASH_REMATCH[1]}")
            [[ "$line" =~ ^[[:space:]]*servername:[[:space:]]*(.*) ]] && sni=$(_strip_quotes "${BASH_REMATCH[1]}")
            [[ "$line" =~ ^[[:space:]]*flow:[[:space:]]*(.*) ]] && flow=$(_strip_quotes "${BASH_REMATCH[1]}")
            [[ "$line" =~ ^[[:space:]]*path:[[:space:]]*(.*) ]] && path=$(_strip_quotes "${BASH_REMATCH[1]}")
            [[ "$line" =~ ^[[:space:]]*Host:[[:space:]]*(.*) ]] && host=$(_strip_quotes "${BASH_REMATCH[1]}")
            [[ "$line" =~ ^[[:space:]]*public-key:[[:space:]]*(.*) ]] && pbk=$(_strip_quotes "${BASH_REMATCH[1]}")
            [[ "$line" =~ ^[[:space:]]*short-id:[[:space:]]*(.*) ]] && sid=$(_strip_quotes "${BASH_REMATCH[1]}")
        done <<< "$content"
        
        # 处理最后一个节点
        if [[ -n "$name" && -n "$type" && -n "$server" && -n "$port" ]]; then
            case "$type" in
                vless)
                    local link="vless://${uuid}@${server}:${port}?encryption=none"
                    [[ -n "$flow" ]] && link+="&flow=$flow"
                    [[ "$tls" == "true" ]] && link+="&security=reality&type=${network:-tcp}&sni=$sni&fp=chrome&pbk=$pbk&sid=$sid" || link+="&security=none&type=${network:-tcp}"
                    link+="#$(urlencode "$name")"
                    links+="$link"$'\n'
                    ;;
                vmess)
                    local vmess_json="{\"v\":\"2\",\"ps\":\"$name\",\"add\":\"$server\",\"port\":\"$port\",\"id\":\"$uuid\",\"aid\":\"0\",\"scy\":\"auto\",\"net\":\"${network:-tcp}\",\"type\":\"none\",\"host\":\"$host\",\"path\":\"$path\",\"tls\":\"$([[ "$tls" == "true" ]] && echo "tls" || echo "")\",\"sni\":\"$sni\"}"
                    links+="vmess://$(echo -n "$vmess_json" | base64 -w 0)"$'\n'
                    ;;
                trojan)
                    links+="trojan://${password}@${server}:${port}?sni=$sni#$(urlencode "$name")"$'\n'
                    ;;
                ss)
                    local ss_encoded=$(echo -n "${method}:${password}" | base64 -w 0)
                    links+="ss://${ss_encoded}@${server}:${port}#$(urlencode "$name")"$'\n'
                    ;;
                hysteria2)
                    links+="hysteria2://${password}@${server}:${port}?sni=$sni#$(urlencode "$name")"$'\n'
                    ;;
                tuic)
                    links+="tuic://${uuid}:${password}@${server}:${port}?sni=$sni#$(urlencode "$name")"$'\n'
                    ;;
            esac
        fi
        
        [[ -n "$links" ]] && echo "$links" && return 0
        return 1
    fi
    
    # 原样返回（可能已经是链接列表）
    if [[ "$content" == *"://"* ]]; then
        echo "$content"
        return 0
    fi
    
    return 1
}

# 刷新所有订阅
refresh_external_subs() {
    [[ ! -f "$EXTERNAL_SUBS_FILE" ]] && return 0
    
    mkdir -p "$EXTERNAL_CACHE_DIR"
    local count=0
    local idx=0
    
    while IFS= read -r url || [[ -n "$url" ]]; do
        [[ -z "$url" || "$url" == \#* ]] && continue
        ((idx++))
        
        _info "拉取订阅 $idx: $url"
        local content=$(fetch_subscription "$url")
        
        if [[ -n "$content" ]]; then
            echo "$content" > "$EXTERNAL_CACHE_DIR/sub_$idx.txt"
            local node_count=$(echo "$content" | grep -c '://' || echo 0)
            _ok "获取 $node_count 个节点"
            ((count+=node_count))
        else
            _warn "拉取失败: $url"
        fi
    done < "$EXTERNAL_SUBS_FILE"
    
    _ok "共刷新 $count 个外部节点"
    
    # 自动更新订阅文件
    [[ -f "$CFG/sub.info" ]] && generate_sub_files
}

# 获取所有外部节点链接
get_all_external_links() {
    local links=""
    
    # 直接添加的分享链接
    if [[ -f "$EXTERNAL_LINKS_FILE" ]]; then
        while IFS= read -r link || [[ -n "$link" ]]; do
            [[ -z "$link" || "$link" == \#* ]] && continue
            links+="$link"$'\n'
        done < "$EXTERNAL_LINKS_FILE"
    fi
    
    # 订阅缓存的节点
    if [[ -d "$EXTERNAL_CACHE_DIR" ]]; then
        for cache_file in "$EXTERNAL_CACHE_DIR"/*.txt; do
            [[ ! -f "$cache_file" ]] && continue
            while IFS= read -r link || [[ -n "$link" ]]; do
                [[ -z "$link" || "$link" == \#* ]] && continue
                [[ "$link" != *"://"* ]] && continue
                links+="$link"$'\n'
            done < "$cache_file"
        done
    fi
    
    echo -n "$links"
}

# 将外部节点转换为 Clash 格式
external_link_to_clash() {
    local link="$1"
    local json=$(parse_share_link "$link")
    [[ -z "$json" ]] && return
    
    local type=$(echo "$json" | jq -r '.type')
    local name=$(echo "$json" | jq -r '.name')
    local server=$(echo "$json" | jq -r '.server')
    local port=$(echo "$json" | jq -r '.port')
    
    # 给外部节点名称加上服务器标识，避免与本地节点重复
    local server_suffix=$(get_ip_suffix "$server")
    [[ -n "$server_suffix" && "$name" != *"-${server_suffix}"* && "$name" != *"-${server_suffix}" ]] && name="${name}-${server_suffix}"
    
    case "$type" in
        vless)
            local uuid=$(echo "$json" | jq -r '.uuid')
            local security=$(echo "$json" | jq -r '.security')
            local transport=$(echo "$json" | jq -r '.transport')
            local sni=$(echo "$json" | jq -r '.sni')
            local pbk=$(echo "$json" | jq -r '.pbk')
            local sid=$(echo "$json" | jq -r '.sid')
            local flow=$(echo "$json" | jq -r '.flow')
            local path=$(echo "$json" | jq -r '.path')
            
            if [[ "$security" == "reality" ]]; then
                cat << EOF
  - name: "$name"
    type: vless
    server: "$server"
    port: $port
    uuid: $uuid
    network: ${transport:-tcp}
    tls: true
    udp: true
    flow: $flow
    servername: $sni
    reality-opts:
      public-key: $pbk
      short-id: $sid
    client-fingerprint: chrome
EOF
            elif [[ "$transport" == "ws" ]]; then
                cat << EOF
  - name: "$name"
    type: vless
    server: "$server"
    port: $port
    uuid: $uuid
    network: ws
    tls: true
    udp: true
    skip-cert-verify: true
    servername: $sni
    ws-opts:
      path: $path
      headers:
        Host: $sni
EOF
            else
                cat << EOF
  - name: "$name"
    type: vless
    server: "$server"
    port: $port
    uuid: $uuid
    network: tcp
    tls: true
    udp: true
    skip-cert-verify: true
    servername: $sni
EOF
            fi
            ;;
        vmess)
            local uuid=$(echo "$json" | jq -r '.uuid')
            local network=$(echo "$json" | jq -r '.network')
            local tls=$(echo "$json" | jq -r '.tls')
            local sni=$(echo "$json" | jq -r '.sni')
            local path=$(echo "$json" | jq -r '.path')
            local host=$(echo "$json" | jq -r '.host')
            
            cat << EOF
  - name: "$name"
    type: vmess
    server: "$server"
    port: $port
    uuid: $uuid
    alterId: 0
    cipher: auto
    network: ${network:-tcp}
    tls: $([[ "$tls" == "tls" ]] && echo "true" || echo "false")
    skip-cert-verify: true
    servername: ${sni:-$host}
EOF
            if [[ "$network" == "ws" ]]; then
                cat << EOF
    ws-opts:
      path: ${path:-/}
      headers:
        Host: ${host:-$sni}
EOF
            fi
            ;;
        trojan)
            local password=$(echo "$json" | jq -r '.password')
            local sni=$(echo "$json" | jq -r '.sni')
            cat << EOF
  - name: "$name"
    type: trojan
    server: "$server"
    port: $port
    password: $password
    sni: $sni
    skip-cert-verify: true
    udp: true
EOF
            ;;
        ss)
            local method=$(echo "$json" | jq -r '.method')
            local password=$(echo "$json" | jq -r '.password')
            cat << EOF
  - name: "$name"
    type: ss
    server: "$server"
    port: $port
    cipher: $method
    password: $password
    udp: true
EOF
            ;;
        hysteria2)
            local password=$(echo "$json" | jq -r '.password')
            local sni=$(echo "$json" | jq -r '.sni')
            cat << EOF
  - name: "$name"
    type: hysteria2
    server: "$server"
    port: $port
    password: $password
    sni: $sni
    skip-cert-verify: true
EOF
            ;;
        anytls)
            local password=$(echo "$json" | jq -r '.password')
            local sni=$(echo "$json" | jq -r '.sni')
            cat << EOF
  - name: "$name"
    type: anytls
    server: "$server"
    port: $port
    password: $password
    sni: $sni
    skip-cert-verify: true
EOF
            ;;
    esac
}

# 将外部节点转换为 Surge 格式
external_link_to_surge() {
    local link="$1"
    local json=$(parse_share_link "$link")
    [[ -z "$json" ]] && return
    
    local type=$(echo "$json" | jq -r '.type')
    local name=$(echo "$json" | jq -r '.name')
    local server=$(echo "$json" | jq -r '.server')
    local port=$(echo "$json" | jq -r '.port')
    
    # 给外部节点名称加上服务器标识，避免与本地节点重复
    local server_suffix=$(get_ip_suffix "$server")
    [[ -n "$server_suffix" && "$name" != *"-${server_suffix}"* && "$name" != *"-${server_suffix}" ]] && name="${name}-${server_suffix}"
    
    case "$type" in
        vmess)
            local uuid=$(echo "$json" | jq -r '.uuid')
            local network=$(echo "$json" | jq -r '.network')
            local tls=$(echo "$json" | jq -r '.tls')
            local sni=$(echo "$json" | jq -r '.sni')
            local path=$(echo "$json" | jq -r '.path')
            if [[ "$network" == "ws" ]]; then
                echo "$name = vmess, $server, $port, $uuid, tls=$([[ "$tls" == "tls" ]] && echo "true" || echo "false"), ws=true, ws-path=${path:-/}, sni=$sni, skip-cert-verify=true"
            else
                echo "$name = vmess, $server, $port, $uuid, tls=$([[ "$tls" == "tls" ]] && echo "true" || echo "false"), skip-cert-verify=true"
            fi
            ;;
        trojan)
            local password=$(echo "$json" | jq -r '.password')
            local sni=$(echo "$json" | jq -r '.sni')
            echo "$name = trojan, $server, $port, password=$password, sni=$sni, skip-cert-verify=true"
            ;;
        ss)
            local method=$(echo "$json" | jq -r '.method')
            local password=$(echo "$json" | jq -r '.password')
            echo "$name = ss, $server, $port, encrypt-method=$method, password=$password"
            ;;
        hysteria2)
            local password=$(echo "$json" | jq -r '.password')
            local sni=$(echo "$json" | jq -r '.sni')
            echo "$name = hysteria2, $server, $port, password=$password, sni=$sni, skip-cert-verify=true"
            ;;
        anytls)
            local password=$(echo "$json" | jq -r '.password')
            local sni=$(echo "$json" | jq -r '.sni')
            echo "$name = anytls, $server, $port, password=$password, sni=$sni, skip-cert-verify=true"
            ;;
    esac
}

# 添加分享链接
add_external_link() {
    echo ""
    _line
    echo -e "  ${W}添加分享链接${NC}"
    echo -e "  ${D}支持: vless://, vmess://, trojan://, ss://, hysteria2://, anytls://${NC}"
    _line
    echo ""
    read -rp "  请输入分享链接: " link
    
    [[ -z "$link" ]] && return
    
    # 验证链接格式
    if [[ "$link" != *"://"* ]]; then
        _err "无效的链接格式"
        return 1
    fi
    
    # 检查是否已存在
    if [[ -f "$EXTERNAL_LINKS_FILE" ]] && grep -qF "$link" "$EXTERNAL_LINKS_FILE"; then
        _warn "该链接已存在"
        return 1
    fi
    
    # 解析获取名称
    local name=$(get_link_name "$link")
    
    # 保存
    mkdir -p "$(dirname "$EXTERNAL_LINKS_FILE")"
    echo "$link" >> "$EXTERNAL_LINKS_FILE"
    
    _ok "已添加节点: $name"
    
    # 自动更新订阅文件
    if [[ -f "$CFG/sub.info" ]]; then
        generate_sub_files
    fi
}

# 添加订阅链接
add_external_sub() {
    echo ""
    _line
    echo -e "  ${W}添加订阅链接${NC}"
    echo -e "  ${D}支持 V2Ray/Base64 订阅、Clash YAML 订阅${NC}"
    _line
    echo ""
    read -rp "  请输入订阅链接: " url
    
    [[ -z "$url" ]] && return
    
    # 验证 URL 格式
    if [[ "$url" != http://* && "$url" != https://* ]]; then
        _err "无效的 URL 格式"
        return 1
    fi
    
    # 检查是否已存在
    if [[ -f "$EXTERNAL_SUBS_FILE" ]] && grep -qF "$url" "$EXTERNAL_SUBS_FILE"; then
        _warn "该订阅已存在"
        return 1
    fi
    
    # 测试拉取
    _info "测试订阅链接..."
    local content=$(fetch_subscription "$url")
    
    if [[ -z "$content" ]]; then
        _err "无法获取订阅内容"
        return 1
    fi
    
    local node_count=$(echo "$content" | grep -c '://' || echo 0)
    
    # 保存
    mkdir -p "$(dirname "$EXTERNAL_SUBS_FILE")"
    echo "$url" >> "$EXTERNAL_SUBS_FILE"
    
    # 缓存节点
    mkdir -p "$EXTERNAL_CACHE_DIR"
    local idx=$(wc -l < "$EXTERNAL_SUBS_FILE" 2>/dev/null || echo 1)
    echo "$content" > "$EXTERNAL_CACHE_DIR/sub_$idx.txt"
    
    _ok "已添加订阅，包含 $node_count 个节点"
    
    # 自动更新订阅文件
    if [[ -f "$CFG/sub.info" ]]; then
        generate_sub_files
    fi
}

# 查看外部节点
show_external_nodes() {
    echo ""
    _line
    echo -e "  ${W}外部节点列表${NC}"
    _line
    
    local count=0
    
    # 显示分享链接
    if [[ -f "$EXTERNAL_LINKS_FILE" ]]; then
        echo -e "\n  ${Y}[分享链接]${NC}"
        local idx=0
        while IFS= read -r link || [[ -n "$link" ]]; do
            [[ -z "$link" || "$link" == \#* ]] && continue
            ((idx++))
            ((count++))
            local name=$(get_link_name "$link")
            local proto="${link%%://*}"
            echo -e "  ${G}$idx)${NC} [$proto] $name"
        done < "$EXTERNAL_LINKS_FILE"
        [[ $idx -eq 0 ]] && echo -e "  ${D}(无)${NC}"
    fi
    
    # 显示订阅
    if [[ -f "$EXTERNAL_SUBS_FILE" ]]; then
        echo -e "\n  ${Y}[订阅链接]${NC}"
        local idx=0
        while IFS= read -r url || [[ -n "$url" ]]; do
            [[ -z "$url" || "$url" == \#* ]] && continue
            ((idx++))
            local cache_file="$EXTERNAL_CACHE_DIR/sub_$idx.txt"
            local node_count=0
            [[ -f "$cache_file" ]] && node_count=$(grep -c '://' "$cache_file" 2>/dev/null || echo 0)
            ((count+=node_count))
            echo -e "  ${G}$idx)${NC} $url ${D}($node_count 个节点)${NC}"
        done < "$EXTERNAL_SUBS_FILE"
        [[ $idx -eq 0 ]] && echo -e "  ${D}(无)${NC}"
    fi
    
    echo ""
    _line
    echo -e "  ${C}共 $count 个外部节点${NC}"
    _line
}

# 删除外部节点
delete_external_node() {
    echo ""
    _line
    echo -e "  ${W}删除外部节点${NC}"
    _line
    echo -e "  ${G}1)${NC} 删除分享链接"
    echo -e "  ${G}2)${NC} 删除订阅链接"
    echo -e "  ${G}3)${NC} 清空所有外部节点"
    echo -e "  ${G}0)${NC} 返回"
    _line
    
    read -rp "  请选择: " choice
    
    case "$choice" in
        1)
            [[ ! -f "$EXTERNAL_LINKS_FILE" ]] && { _warn "没有分享链接"; return; }
            echo ""
            local idx=0
            while IFS= read -r link || [[ -n "$link" ]]; do
                [[ -z "$link" || "$link" == \#* ]] && continue
                ((idx++))
                local name=$(get_link_name "$link")
                echo -e "  ${G}$idx)${NC} $name"
            done < "$EXTERNAL_LINKS_FILE"
            echo ""
            read -rp "  输入序号删除 (0 取消): " del_idx
            [[ "$del_idx" == "0" || -z "$del_idx" ]] && return
            
            sed -i "${del_idx}d" "$EXTERNAL_LINKS_FILE" 2>/dev/null && _ok "已删除" || _err "删除失败"
            # 自动更新订阅文件
            [[ -f "$CFG/sub.info" ]] && generate_sub_files
            ;;
        2)
            [[ ! -f "$EXTERNAL_SUBS_FILE" ]] && { _warn "没有订阅链接"; return; }
            echo ""
            local idx=0
            while IFS= read -r url || [[ -n "$url" ]]; do
                [[ -z "$url" || "$url" == \#* ]] && continue
                ((idx++))
                echo -e "  ${G}$idx)${NC} $url"
            done < "$EXTERNAL_SUBS_FILE"
            echo ""
            read -rp "  输入序号删除 (0 取消): " del_idx
            [[ "$del_idx" == "0" || -z "$del_idx" ]] && return
            
            sed -i "${del_idx}d" "$EXTERNAL_SUBS_FILE" 2>/dev/null
            rm -f "$EXTERNAL_CACHE_DIR/sub_$del_idx.txt" 2>/dev/null
            _ok "已删除"
            # 自动更新订阅文件
            [[ -f "$CFG/sub.info" ]] && generate_sub_files
            ;;
        3)
            read -rp "  确认清空所有外部节点? [y/N]: " confirm
            [[ "$confirm" =~ ^[yY]$ ]] || return
            rm -f "$EXTERNAL_LINKS_FILE" "$EXTERNAL_SUBS_FILE"
            rm -rf "$EXTERNAL_CACHE_DIR"
            _ok "已清空所有外部节点"
            # 自动更新订阅文件
            [[ -f "$CFG/sub.info" ]] && generate_sub_files
            ;;
    esac
}

# 外部节点管理菜单
manage_external_nodes() {
    while true; do
        _header
        echo -e "  ${W}外部节点管理${NC}"
        _line
        _item "1" "添加分享链接"
        _item "2" "添加订阅链接"
        _item "3" "查看外部节点"
        _item "4" "删除外部节点"
        _item "5" "刷新订阅"
        _line
        _item "0" "返回"
        _line
        
        read -rp "  请选择: " choice
        
        case "$choice" in
            1) add_external_link ;;
            2) add_external_sub ;;
            3) show_external_nodes ;;
            4) delete_external_node ;;
            5) refresh_external_subs ;;
            0|"") return ;;
            *) _err "无效选择" ;;
        esac
        
        echo ""
        read -rp "按回车继续..."
    done
}

# 获取或生成订阅 UUID
get_sub_uuid() {
    local uuid_file="$CFG/sub_uuid"
    if [[ -f "$uuid_file" ]]; then
        cat "$uuid_file"
    else
        local new_uuid=$(gen_uuid)
        echo "$new_uuid" > "$uuid_file"
        chmod 600 "$uuid_file"
        echo "$new_uuid"
    fi
}

# 重置订阅 UUID（生成新的）
reset_sub_uuid() {
    local uuid_file="$CFG/sub_uuid"
    local new_uuid=$(gen_uuid)
    echo "$new_uuid" > "$uuid_file"
    chmod 600 "$uuid_file"
    echo "$new_uuid"
}

# 生成 V2Ray/通用 Base64 订阅内容
gen_v2ray_sub() {
    local installed=$(get_installed_protocols)
    local links=""
    local ipv4=$(get_ipv4)
    local ipv6=$(get_ipv6)
    
    # 获取地区代码
    local country_code=$(get_ip_country "$ipv4")
    [[ -z "$country_code" ]] && country_code=$(get_ip_country "$ipv6")
    
    # 确定使用的 IP 地址：优先 IPv4，纯 IPv6 环境使用 IPv6（带方括号）
    local server_ip="$ipv4"
    if [[ -z "$server_ip" && -n "$ipv6" ]]; then
        server_ip="[$ipv6]"
    fi
    
    # 检查是否有主协议（用于判断 WS 协议是否为回落子协议）
    local master_port=""
    master_port=$(_get_master_port "")
    
    for protocol in $installed; do
        # 从数据库读取配置
        local cfg=""
        if db_exists "xray" "$protocol"; then
            cfg=$(db_get "xray" "$protocol")
        elif db_exists "singbox" "$protocol"; then
            cfg=$(db_get "singbox" "$protocol")
        fi
        [[ -z "$cfg" ]] && continue
        
        # 提取字段
        local uuid=$(echo "$cfg" | jq -r '.uuid // empty')
        local port=$(echo "$cfg" | jq -r '.port // empty')
        local sni=$(echo "$cfg" | jq -r '.sni // empty')
        local short_id=$(echo "$cfg" | jq -r '.short_id // empty')
        local public_key=$(echo "$cfg" | jq -r '.public_key // empty')
        local path=$(echo "$cfg" | jq -r '.path // empty')
        local password=$(echo "$cfg" | jq -r '.password // empty')
        local username=$(echo "$cfg" | jq -r '.username // empty')
        local method=$(echo "$cfg" | jq -r '.method // empty')
        local psk=$(echo "$cfg" | jq -r '.psk // empty')
        
        # 对于回落子协议，使用主协议端口
        local actual_port="$port"
        if [[ -n "$master_port" && ("$protocol" == "vless-ws" || "$protocol" == "vmess-ws") ]]; then
            actual_port="$master_port"
        fi
        
        local link=""
        case "$protocol" in
            vless)
                [[ -n "$server_ip" ]] && link=$(gen_vless_link "$server_ip" "$actual_port" "$uuid" "$public_key" "$short_id" "$sni" "$country_code")
                ;;
            vless-xhttp)
                [[ -n "$server_ip" ]] && link=$(gen_vless_xhttp_link "$server_ip" "$actual_port" "$uuid" "$public_key" "$short_id" "$sni" "$path" "$country_code")
                ;;
            vless-ws)
                [[ -n "$server_ip" ]] && link=$(gen_vless_ws_link "$server_ip" "$actual_port" "$uuid" "$sni" "$path" "$country_code")
                ;;
            vless-vision)
                [[ -n "$server_ip" ]] && link=$(gen_vless_vision_link "$server_ip" "$actual_port" "$uuid" "$sni" "$country_code")
                ;;
            vmess-ws)
                [[ -n "$server_ip" ]] && link=$(gen_vmess_ws_link "$server_ip" "$actual_port" "$uuid" "$sni" "$path" "$country_code")
                ;;
            trojan)
                [[ -n "$server_ip" ]] && link=$(gen_trojan_link "$server_ip" "$actual_port" "$password" "$sni" "$country_code")
                ;;
            ss2022)
                [[ -n "$server_ip" ]] && link=$(gen_ss2022_link "$server_ip" "$actual_port" "$method" "$password" "$country_code")
                ;;
            ss-legacy)
                [[ -n "$server_ip" ]] && link=$(gen_ss_legacy_link "$server_ip" "$actual_port" "$method" "$password" "$country_code")
                ;;
            hy2)
                [[ -n "$server_ip" ]] && link=$(gen_hy2_link "$server_ip" "$actual_port" "$password" "$sni" "$country_code")
                ;;
            tuic)
                [[ -n "$server_ip" ]] && link=$(gen_tuic_link "$server_ip" "$actual_port" "$uuid" "$password" "$sni" "$country_code")
                ;;
            anytls)
                [[ -n "$server_ip" ]] && link=$(gen_anytls_link "$server_ip" "$actual_port" "$password" "$sni" "$country_code")
                ;;
            snell)
                [[ -n "$server_ip" ]] && link=$(gen_snell_link "$server_ip" "$actual_port" "$psk" "4" "$country_code")
                ;;
            snell-v5)
                [[ -n "$server_ip" ]] && link=$(gen_snell_v5_link "$server_ip" "$actual_port" "$psk" "5" "$country_code")
                ;;
            socks)
                [[ -n "$server_ip" ]] && link=$(gen_socks_link "$server_ip" "$actual_port" "$username" "$password" "$country_code")
                ;;
        esac
        
        [[ -n "$link" ]] && links+="$link"$'\n'
    done
    
    # 合并外部节点
    local external_links=$(get_all_external_links)
    [[ -n "$external_links" ]] && links+="$external_links"
    
    # Base64 编码
    printf '%s' "$links" | base64 -w 0 2>/dev/null || printf '%s' "$links" | base64
}

# 生成 Clash 订阅内容
gen_clash_sub() {
    local installed=$(get_installed_protocols)
    local ipv4=$(get_ipv4)
    local ipv6=$(get_ipv6)
    local proxies=""
    local proxy_names=""
    
    # 获取地区代码和IP后缀
    local country_code=$(get_ip_country "$ipv4")
    [[ -z "$country_code" ]] && country_code=$(get_ip_country "$ipv6")
    
    # 确定使用的 IP 地址：优先 IPv4，纯 IPv6 环境使用 IPv6
    local server_ip="$ipv4"
    local ip_suffix="${ipv4##*.}"
    if [[ -z "$server_ip" && -n "$ipv6" ]]; then
        server_ip="$ipv6"
        ip_suffix=$(get_ip_suffix "$ipv6")
    fi
    
    # 检查是否有主协议（用于判断 WS 协议是否为回落子协议）
    local master_port=""
    master_port=$(_get_master_port "")
    
    for protocol in $installed; do
        # 从数据库读取配置
        local cfg=""
        if db_exists "xray" "$protocol"; then
            cfg=$(db_get "xray" "$protocol")
        elif db_exists "singbox" "$protocol"; then
            cfg=$(db_get "singbox" "$protocol")
        fi
        [[ -z "$cfg" ]] && continue
        
        # 提取字段
        local uuid=$(echo "$cfg" | jq -r '.uuid // empty')
        local port=$(echo "$cfg" | jq -r '.port // empty')
        local sni=$(echo "$cfg" | jq -r '.sni // empty')
        local short_id=$(echo "$cfg" | jq -r '.short_id // empty')
        local public_key=$(echo "$cfg" | jq -r '.public_key // empty')
        local path=$(echo "$cfg" | jq -r '.path // empty')
        local password=$(echo "$cfg" | jq -r '.password // empty')
        local username=$(echo "$cfg" | jq -r '.username // empty')
        local method=$(echo "$cfg" | jq -r '.method // empty')
        local psk=$(echo "$cfg" | jq -r '.psk // empty')
        
        # 对于回落子协议，使用主协议端口
        local actual_port="$port"
        if [[ -n "$master_port" && ("$protocol" == "vless-ws" || "$protocol" == "vmess-ws") ]]; then
            actual_port="$master_port"
        fi
        
        local name="${country_code}-$(get_protocol_name $protocol)-${ip_suffix}"
        local proxy=""
        
        case "$protocol" in
            vless)
                [[ -n "$server_ip" ]] && proxy="  - name: \"$name\"
    type: vless
    server: \"$server_ip\"
    port: $actual_port
    uuid: $uuid
    network: tcp
    tls: true
    udp: true
    flow: xtls-rprx-vision
    servername: $sni
    reality-opts:
      public-key: $public_key
      short-id: $short_id
    client-fingerprint: chrome"
                ;;
            vless-xhttp)
                [[ -n "$server_ip" ]] && proxy="  - name: \"$name\"
    type: vless
    server: \"$server_ip\"
    port: $actual_port
    uuid: $uuid
    network: xhttp
    tls: true
    udp: true
    servername: $sni
    xhttp-opts:
      path: $path
      mode: auto
    reality-opts:
      public-key: $public_key
      short-id: $short_id
    client-fingerprint: chrome"
                ;;
            vless-ws)
                [[ -n "$server_ip" ]] && proxy="  - name: \"$name\"
    type: vless
    server: \"$server_ip\"
    port: $actual_port
    uuid: $uuid
    network: ws
    tls: true
    udp: true
    skip-cert-verify: true
    servername: $sni
    ws-opts:
      path: $path
      headers:
        Host: $sni"
                ;;
            vless-vision)
                [[ -n "$server_ip" ]] && proxy="  - name: \"$name\"
    type: vless
    server: \"$server_ip\"
    port: $actual_port
    uuid: $uuid
    network: tcp
    tls: true
    udp: true
    flow: xtls-rprx-vision
    skip-cert-verify: true
    servername: $sni
    client-fingerprint: chrome"
                ;;
            vmess-ws)
                [[ -n "$server_ip" ]] && proxy="  - name: \"$name\"
    type: vmess
    server: \"$server_ip\"
    port: $actual_port
    uuid: $uuid
    alterId: 0
    cipher: auto
    network: ws
    tls: true
    skip-cert-verify: true
    servername: $sni
    ws-opts:
      path: $path
      headers:
        Host: $sni"
                ;;
            trojan)
                [[ -n "$server_ip" ]] && proxy="  - name: \"$name\"
    type: trojan
    server: \"$server_ip\"
    port: $actual_port
    password: $password
    udp: true
    skip-cert-verify: true
    sni: $sni"
                ;;
            ss2022)
                [[ -n "$server_ip" ]] && proxy="  - name: \"$name\"
    type: ss
    server: \"$server_ip\"
    port: $port
    cipher: $method
    password: $password
    udp: true"
                ;;
            ss-legacy)
                [[ -n "$server_ip" ]] && proxy="  - name: \"$name\"
    type: ss
    server: \"$server_ip\"
    port: $port
    cipher: $method
    password: $password
    udp: true"
                ;;
            hy2)
                [[ -n "$server_ip" ]] && proxy="  - name: \"$name\"
    type: hysteria2
    server: \"$server_ip\"
    port: $port
    password: $password
    sni: $sni
    skip-cert-verify: true"
                ;;
            tuic)
                [[ -n "$server_ip" ]] && proxy="  - name: \"$name\"
    type: tuic
    server: \"$server_ip\"
    port: $port
    uuid: $uuid
    password: $password
    alpn: [h3]
    udp-relay-mode: native
    congestion-controller: bbr
    sni: $sni
    skip-cert-verify: true"
                ;;
            anytls)
                [[ -n "$server_ip" ]] && proxy="  - name: \"$name\"
    type: anytls
    server: \"$server_ip\"
    port: $port
    password: $password
    sni: $sni
    skip-cert-verify: true"
                ;;
        esac
        
        if [[ -n "$proxy" ]]; then
            proxies+="$proxy"$'\n'
            proxy_names+="      - \"$name\""$'\n'
        fi
    done
    
    # 合并外部节点
    local external_links=$(get_all_external_links)
    while IFS= read -r link || [[ -n "$link" ]]; do
        [[ -z "$link" || "$link" != *"://"* ]] && continue
        local ext_proxy=$(external_link_to_clash "$link")
        if [[ -n "$ext_proxy" ]]; then
            proxies+="$ext_proxy"$'\n'
            # 从生成的 proxy 中提取名称
            local ext_name=$(echo "$ext_proxy" | grep -m1 'name:' | sed 's/.*name:[[:space:]]*"\([^"]*\)".*/\1/')
            proxy_names+="      - \"$ext_name\""$'\n'
        fi
    done <<< "$external_links"
    
    # 生成完整 Clash 配置
    cat << EOF
mixed-port: 7897
allow-lan: false
mode: rule
log-level: info

proxies:
$proxies
proxy-groups:
  - name: "Proxy"
    type: select
    proxies:
$proxy_names
rules:
  - GEOIP,CN,DIRECT
  - MATCH,Proxy
EOF
}

# 生成 Surge 订阅内容
gen_surge_sub() {
    local installed=$(get_installed_protocols)
    local ipv4=$(get_ipv4)
    local ipv6=$(get_ipv6)
    local proxies=""
    local proxy_names=""
    
    # 获取地区代码
    local country_code=$(get_ip_country "$ipv4")
    [[ -z "$country_code" ]] && country_code=$(get_ip_country "$ipv6")
    
    # 确定使用的 IP 地址：优先 IPv4，纯 IPv6 环境使用 IPv6
    local server_ip="$ipv4"
    local ip_suffix="${ipv4##*.}"
    if [[ -z "$server_ip" && -n "$ipv6" ]]; then
        server_ip="[$ipv6]"
        ip_suffix=$(get_ip_suffix "$ipv6")
    fi
    
    for protocol in $installed; do
        # 从数据库读取配置
        local cfg=""
        if db_exists "xray" "$protocol"; then
            cfg=$(db_get "xray" "$protocol")
        elif db_exists "singbox" "$protocol"; then
            cfg=$(db_get "singbox" "$protocol")
        fi
        [[ -z "$cfg" ]] && continue
        
        local uuid=$(echo "$cfg" | jq -r '.uuid // empty')
        local port=$(echo "$cfg" | jq -r '.port // empty')
        local sni=$(echo "$cfg" | jq -r '.sni // empty')
        local password=$(echo "$cfg" | jq -r '.password // empty')
        local method=$(echo "$cfg" | jq -r '.method // empty')
        local psk=$(echo "$cfg" | jq -r '.psk // empty')
        local version=$(echo "$cfg" | jq -r '.version // empty')
        
        local name="${country_code}-$(get_protocol_name $protocol)-${ip_suffix}"
        local proxy=""
        
        case "$protocol" in
            trojan)
                [[ -n "$server_ip" ]] && proxy="$name = trojan, $server_ip, $port, password=$password, sni=$sni, skip-cert-verify=true"
                ;;
            ss2022)
                [[ -n "$server_ip" ]] && proxy="$name = ss, $server_ip, $port, encrypt-method=$method, password=$password"
                ;;
            ss-legacy)
                [[ -n "$server_ip" ]] && proxy="$name = ss, $server_ip, $port, encrypt-method=$method, password=$password"
                ;;
            hy2)
                [[ -n "$server_ip" ]] && proxy="$name = hysteria2, $server_ip, $port, password=$password, sni=$sni, skip-cert-verify=true"
                ;;
            snell|snell-v5)
                [[ -n "$server_ip" ]] && proxy="$name = snell, $server_ip, $port, psk=$psk, version=${version:-4}"
                ;;
        esac
        
        if [[ -n "$proxy" ]]; then
            proxies+="$proxy"$'\n'
            [[ -n "$proxy_names" ]] && proxy_names+=", "
            proxy_names+="$name"
        fi
    done
    
    # 合并外部节点 (仅支持 vmess/trojan/ss/hysteria2)
    local external_links=$(get_all_external_links)
    while IFS= read -r link || [[ -n "$link" ]]; do
        [[ -z "$link" || "$link" != *"://"* ]] && continue
        local ext_proxy=$(external_link_to_surge "$link")
        if [[ -n "$ext_proxy" ]]; then
            proxies+="$ext_proxy"$'\n'
            # 从生成的 proxy 中提取名称
            local ext_name=$(echo "$ext_proxy" | cut -d'=' -f1 | xargs)
            [[ -n "$proxy_names" ]] && proxy_names+=", "
            proxy_names+="$ext_name"
        fi
    done <<< "$external_links"
    
    cat << EOF
[General]
loglevel = notify

[Proxy]
$proxies
[Proxy Group]
Proxy = select, $proxy_names

[Rule]
GEOIP,CN,DIRECT
FINAL,Proxy
EOF
}

# 生成订阅文件
generate_sub_files() {
    local sub_uuid=$(get_sub_uuid)
    local sub_dir="$CFG/subscription/$sub_uuid"
    mkdir -p "$sub_dir"
    
    _info "生成订阅文件..."
    
    # V2Ray/通用订阅
    gen_v2ray_sub > "$sub_dir/base64"
    
    # Clash 订阅
    gen_clash_sub > "$sub_dir/clash.yaml"
    
    # Surge 订阅
    gen_surge_sub > "$sub_dir/surge.conf"
    
    chmod -R 644 "$sub_dir"/*
    _ok "订阅文件已生成"
}

# 配置 Nginx 订阅服务
setup_nginx_sub() {
    local sub_uuid=$(get_sub_uuid)
    local sub_port="${1:-8443}" domain="${2:-}" use_https="${3:-true}"

    generate_sub_files
    local sub_dir="$CFG/subscription/$sub_uuid"
    local fake_conf="/etc/nginx/conf.d/vless-fake.conf"

    # 检查现有配置：已存在且路由正确则直接复用
    if [[ -f "$fake_conf" ]] &&
       grep -q "listen.*$sub_port" "$fake_conf" 2>/dev/null &&
       grep -q "location.*sub.*alias.*subscription" "$fake_conf" 2>/dev/null; then
        _ok "Nginx 已配置订阅服务: 端口 $sub_port"
        return 0
    fi

    local cert_file="$CFG/certs/server.crt" key_file="$CFG/certs/server.key"
    local nginx_conf="/etc/nginx/conf.d/vless-sub.conf"
    rm -f "$nginx_conf" 2>/dev/null
    mkdir -p /etc/nginx/conf.d

    if [[ "$use_https" == "true" && ( ! -f "$cert_file" || ! -f "$key_file" ) ]]; then
        _warn "证书不存在，生成自签名证书..."
        gen_self_cert "${domain:-localhost}"
    fi
    if [[ "$use_https" == "true" && ( ! -f "$cert_file" || ! -f "$key_file" ) ]]; then
        _warn "证书仍不存在，切换到 HTTP 模式..."
        use_https="false"
    fi

    local ssl_listen="" ssl_block=""
    if [[ "$use_https" == "true" ]]; then
        ssl_listen=" ssl http2"
        ssl_block=$(cat <<EOF
    ssl_certificate $cert_file;
    ssl_certificate_key $key_file;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
EOF
)
    fi

    cat > "$nginx_conf" << EOF
server {
    listen $sub_port$ssl_listen;
    listen [::]:$sub_port$ssl_listen;
    server_name ${domain:-_};
$ssl_block
    # 订阅路径 (alias 直指文件，避免 try_files 误判)
    location /sub/$sub_uuid/ {
        alias $sub_dir/;
        default_type text/plain;
        add_header Content-Type 'text/plain; charset=utf-8';
    }

    location /sub/$sub_uuid/clash {
        alias $sub_dir/clash.yaml;
        default_type text/yaml;
        add_header Content-Disposition 'attachment; filename="clash.yaml"';
    }

    location /sub/$sub_uuid/surge {
        alias $sub_dir/surge.conf;
        default_type text/plain;
        add_header Content-Disposition 'attachment; filename="surge.conf"';
    }

    location /sub/$sub_uuid/v2ray {
        alias $sub_dir/base64;
        default_type text/plain;
    }

    # 伪装网页
    root /var/www/html;
    index index.html;

    location / { try_files \$uri \$uri/ =404; }

    # 隐藏 Nginx 版本
    server_tokens off;
}
EOF

    if nginx -t 2>/dev/null; then
        if [[ "$DISTRO" == "alpine" ]]; then
            rc-service nginx restart 2>/dev/null || nginx -s reload
        else
            systemctl reload nginx 2>/dev/null || nginx -s reload
        fi
        _ok "Nginx 配置完成"
        return 0
    fi

    _err "Nginx 配置错误"
    rm -f "$nginx_conf"
    return 1
}


# 显示订阅链接
show_sub_links() {
    [[ ! -f "$CFG/sub.info" ]] && { _warn "订阅服务未配置"; return; }
    
    # 清除变量避免污染
    local sub_uuid="" sub_port="" sub_domain="" sub_https=""
    source "$CFG/sub.info"
    local ipv4=$(get_ipv4)
    local protocol="http"
    [[ "$sub_https" == "true" ]] && protocol="https"
    
    local base_url="${protocol}://${sub_domain:-$ipv4}:${sub_port}/sub/${sub_uuid}"
    
    _line
    echo -e "  ${W}订阅链接${NC}"
    _line
    echo -e "  ${Y}Clash/Clash Verge (推荐):${NC}"
    echo -e "  ${G}${base_url}/clash${NC}"
    echo ""
    echo -e "  ${Y}Surge:${NC}"
    echo -e "  ${G}${base_url}/surge${NC}"
    echo ""
    echo -e "  ${Y}V2Ray/Loon/通用:${NC}"
    echo -e "  ${G}${base_url}/v2ray${NC}"
    _line
    echo -e "  ${D}订阅路径包含随机UUID，请妥善保管${NC}"
    
    # HTTPS 自签名证书提示
    if [[ "$sub_https" == "true" && -z "$sub_domain" ]]; then
        echo -e "  ${Y}提示: 使用自签名证书，部分客户端可能无法解析订阅${NC}"
        echo -e "  ${D}建议使用 HTTP 或绑定真实域名申请证书${NC}"
    fi
}

# 订阅服务管理菜单
manage_subscription() {
    while true; do
        _header
        echo -e "  ${W}订阅服务管理${NC}"
        _line
        
        if [[ -f "$CFG/sub.info" ]]; then
            # 清除变量避免污染
            local sub_uuid="" sub_port="" sub_domain="" sub_https=""
            source "$CFG/sub.info"
            echo -e "  状态: ${G}已配置${NC}"
            echo -e "  端口: ${G}$sub_port${NC}"
            [[ -n "$sub_domain" ]] && echo -e "  域名: ${G}$sub_domain${NC}"
            echo -e "  HTTPS: ${G}$sub_https${NC}"
            echo ""
            _item "1" "查看订阅链接"
            _item "2" "更新订阅内容"
            _item "3" "外部节点管理"
            _item "4" "重新配置"
            _item "5" "停用订阅服务"
        else
            echo -e "  状态: ${D}未配置${NC}"
            echo ""
            _item "1" "启用订阅服务"
            _item "2" "外部节点管理"
        fi
        _item "0" "返回"
        _line
        
        read -rp "  请选择: " choice
        
        if [[ -f "$CFG/sub.info" ]]; then
            case $choice in
                1) show_sub_links; _pause ;;
                2) generate_sub_files; _ok "订阅内容已更新"; _pause ;;
                3) manage_external_nodes ;;
                4) setup_subscription_interactive ;;
                5) 
                    rm -f /etc/nginx/conf.d/vless-sub.conf "$CFG/sub.info"
                    rm -rf "$CFG/subscription"
                    nginx -s reload 2>/dev/null
                    _ok "订阅服务已停用"
                    _pause
                    ;;
                0) return ;;
            esac
        else
            case $choice in
                1) setup_subscription_interactive ;;
                2) manage_external_nodes ;;
                0) return ;;
            esac
        fi
    done
}

# 交互式配置订阅
setup_subscription_interactive() {
    _header
    echo -e "  ${W}配置订阅服务${NC}"
    _line
    
    # 询问是否重新生成 UUID
    if [[ -f "$CFG/sub_uuid" ]]; then
        echo -e "  ${Y}检测到已有订阅 UUID${NC}"
        read -rp "  是否重新生成 UUID? [y/N]: " regen_uuid
        if [[ "$regen_uuid" =~ ^[yY]$ ]]; then
            local old_uuid=$(cat "$CFG/sub_uuid")
            reset_sub_uuid
            local new_uuid=$(cat "$CFG/sub_uuid")
            _ok "UUID 已更新: ${old_uuid:0:8}... → ${new_uuid:0:8}..."
            # 清理旧的订阅目录
            rm -rf "$CFG/subscription/$old_uuid" 2>/dev/null
        fi
        echo ""
    fi
    
    # 安装 Nginx
    if ! check_cmd nginx; then
        _info "需要安装 Nginx..."
        install_nginx || { _err "Nginx 安装失败"; _pause; return; }
    fi
    
    # 端口（带冲突检测）
    local default_port=8443
    local sub_port=""
    
    while true; do
        read -rp "  订阅端口 [$default_port]: " sub_port
        sub_port="${sub_port:-$default_port}"
        
        # 检查是否被已安装协议占用
        local conflict_proto=$(is_internal_port_occupied "$sub_port")
        if [[ -n "$conflict_proto" ]]; then
            _err "端口 $sub_port 已被 [$conflict_proto] 协议占用"
            _warn "请选择其他端口"
            continue
        fi
        
        # 检查系统端口占用
        if ss -tuln 2>/dev/null | grep -q ":$sub_port " || netstat -tuln 2>/dev/null | grep -q ":$sub_port "; then
            _warn "端口 $sub_port 已被系统占用"
            read -rp "  是否强制使用? [y/N]: " force
            [[ "$force" =~ ^[yY]$ ]] && break
            continue
        fi
        
        break
    done
    
    # 域名
    echo -e "  ${D}留空使用服务器IP${NC}"
    read -rp "  域名 (可选): " sub_domain
    
    # HTTPS
    local use_https="true"
    read -rp "  启用 HTTPS? [Y/n]: " https_choice
    [[ "$https_choice" =~ ^[nN]$ ]] && use_https="false"
    
    # 生成订阅文件
    generate_sub_files
    
    # 获取订阅 UUID
    local sub_uuid=$(get_sub_uuid)
    local sub_dir="$CFG/subscription/$sub_uuid"
    local server_name="${sub_domain:-$(get_ipv4)}"
    
    # 配置 Nginx
    local nginx_conf="/etc/nginx/conf.d/vless-sub.conf"
    mkdir -p /etc/nginx/conf.d
    
    # 删除可能冲突的旧配置
    rm -f /etc/nginx/conf.d/vless-fake.conf 2>/dev/null
    rm -f /etc/nginx/sites-enabled/vless-fake 2>/dev/null
    
    if [[ "$use_https" == "true" ]]; then
        # HTTPS 模式：需要证书
        local cert_file="$CFG/certs/server.crt"
        local key_file="$CFG/certs/server.key"
        
        # 检查证书是否存在，不存在则生成自签名证书
        if [[ ! -f "$cert_file" || ! -f "$key_file" ]]; then
            _info "生成自签名证书..."
            mkdir -p "$CFG/certs"
            openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
                -keyout "$key_file" -out "$cert_file" \
                -subj "/CN=$server_name" 2>/dev/null
        fi
        
        cat > "$nginx_conf" << EOF
server {
    listen $sub_port ssl http2;
    listen [::]:$sub_port ssl http2;
    server_name $server_name;

    ssl_certificate $cert_file;
    ssl_certificate_key $key_file;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;

    root /var/www/html;
    index index.html;

    # 订阅路径
    location ~ ^/sub/([a-f0-9-]+)/v2ray\$ {
        alias $CFG/subscription/\$1/base64;
        default_type text/plain;
        add_header Content-Type "text/plain; charset=utf-8";
    }

    location ~ ^/sub/([a-f0-9-]+)/clash\$ {
        alias $CFG/subscription/\$1/clash.yaml;
        default_type text/yaml;
    }

    location ~ ^/sub/([a-f0-9-]+)/surge\$ {
        alias $CFG/subscription/\$1/surge.conf;
        default_type text/plain;
    }

    location / {
        try_files \$uri \$uri/ =404;
    }

    server_tokens off;
}
EOF
    else
        # HTTP 模式
        cat > "$nginx_conf" << EOF
server {
    listen $sub_port;
    listen [::]:$sub_port;
    server_name $server_name;

    root /var/www/html;
    index index.html;

    # 订阅路径
    location ~ ^/sub/([a-f0-9-]+)/v2ray\$ {
        alias $CFG/subscription/\$1/base64;
        default_type text/plain;
        add_header Content-Type "text/plain; charset=utf-8";
    }

    location ~ ^/sub/([a-f0-9-]+)/clash\$ {
        alias $CFG/subscription/\$1/clash.yaml;
        default_type text/yaml;
    }

    location ~ ^/sub/([a-f0-9-]+)/surge\$ {
        alias $CFG/subscription/\$1/surge.conf;
        default_type text/plain;
    }

    location / {
        try_files \$uri \$uri/ =404;
    }

    server_tokens off;
}
EOF
    fi
    
    # 确保伪装网页存在
    mkdir -p /var/www/html
    if [[ ! -f "/var/www/html/index.html" ]]; then
        cat > /var/www/html/index.html << 'HTMLEOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Welcome</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
        .container { max-width: 800px; margin: 0 auto; background: white; padding: 40px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h1 { color: #333; text-align: center; }
        p { color: #666; line-height: 1.6; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Welcome to Our Website</h1>
        <p>This is a simple website hosted on our server.</p>
    </div>
</body>
</html>
HTMLEOF
    fi
    
    # 保存订阅配置
    cat > "$CFG/sub.info" << EOF
sub_uuid=$sub_uuid
sub_port=$sub_port
sub_domain=$sub_domain
sub_https=$use_https
EOF
    
    # 测试并重载 Nginx
    if nginx -t 2>/dev/null; then
        if [[ "$DISTRO" == "alpine" ]]; then
            rc-update add nginx default 2>/dev/null
            rc-service nginx restart 2>/dev/null
        else
            systemctl enable nginx 2>/dev/null
            systemctl restart nginx 2>/dev/null
        fi
        _ok "订阅服务已配置"
    else
        _err "Nginx 配置错误"
        nginx -t
        rm -f "$nginx_conf"
        _pause
        return
    fi
    
    echo ""
    show_sub_links
    _pause
}

#═══════════════════════════════════════════════════════════════════════════════
# 日志查看
#═══════════════════════════════════════════════════════════════════════════════

show_logs() {
    _header
    echo -e "  ${W}运行日志${NC}"
    _line
    
    echo -e "  ${G}1${NC}) 查看脚本日志 (最近 50 行)"
    echo -e "  ${G}2${NC}) 查看 Watchdog 日志 (最近 50 行)"
    echo -e "  ${G}3${NC}) 查看服务日志 (按协议选择)"
    echo -e "  ${G}4${NC}) 实时跟踪脚本日志"
    echo -e "  ${G}0${NC}) 返回"
    _line
    
    read -rp "  请选择: " log_choice
    
    case $log_choice in
        1)
            _line
            echo -e "  ${C}脚本日志 ($LOG_FILE):${NC}"
            _line
            if [[ -f "$LOG_FILE" ]]; then
                tail -n 50 "$LOG_FILE"
            else
                _warn "日志文件不存在"
            fi
            ;;
        2)
            _line
            echo -e "  ${C}Watchdog 日志:${NC}"
            _line
            if [[ -f "/var/log/vless-watchdog.log" ]]; then
                tail -n 50 /var/log/vless-watchdog.log
            else
                _warn "Watchdog 日志文件不存在"
            fi
            ;;
        3)
            show_service_logs
            ;;
        4)
            _line
            echo -e "  ${C}实时跟踪日志 (Ctrl+C 退出):${NC}"
            _line
            if [[ -f "$LOG_FILE" ]]; then
                tail -f "$LOG_FILE"
            else
                _warn "日志文件不存在"
            fi
            ;;
        0|"")
            return
            ;;
        *)
            _err "无效选择"
            ;;
    esac
}

# 按协议查看服务日志
show_service_logs() {
    _header
    echo -e "  ${W}服务日志${NC}"
    _line
    
    local installed=$(get_installed_protocols)
    if [[ -z "$installed" ]]; then
        _warn "未安装任何协议"
        return
    fi
    
    # 构建菜单
    local idx=1
    local proto_array=()
    
    # Xray 协议组
    local xray_protocols=$(get_xray_protocols)
    if [[ -n "$xray_protocols" ]]; then
        echo -e "  ${G}$idx${NC}) Xray 服务日志 (vless/vmess/trojan/ss2022/socks)"
        proto_array+=("xray")
        ((idx++))
    fi
    
    # Sing-box 协议组 (hy2/tuic)
    local singbox_protocols=$(get_singbox_protocols)
    if [[ -n "$singbox_protocols" ]]; then
        echo -e "  ${G}$idx${NC}) Sing-box 服务日志 (hy2/tuic)"
        proto_array+=("singbox")
        ((idx++))
    fi
    
    # 独立进程协议 (Snell/AnyTLS/ShadowTLS)
    local standalone_protocols=$(get_standalone_protocols)
    for proto in $standalone_protocols; do
        local proto_name=$(get_protocol_name $proto)
        echo -e "  ${G}$idx${NC}) $proto_name 服务日志"
        proto_array+=("$proto")
        ((idx++))
    done
    
    echo -e "  ${G}0${NC}) 返回"
    _line
    
    read -rp "  请选择: " svc_choice
    
    if [[ "$svc_choice" == "0" || -z "$svc_choice" ]]; then
        return
    fi
    
    if ! [[ "$svc_choice" =~ ^[0-9]+$ ]] || [[ $svc_choice -lt 1 ]] || [[ $svc_choice -ge $idx ]]; then
        _err "无效选择"
        return
    fi
    
    local selected="${proto_array[$((svc_choice-1))]}"
    local service_name=""
    local proc_name=""
    
    case "$selected" in
        xray)
            service_name="vless-reality"
            proc_name="xray"
            ;;
        singbox)
            service_name="vless-singbox"
            proc_name="sing-box"
            ;;
        snell)
            service_name="vless-snell"
            proc_name="snell-server"
            ;;
        snell-v5)
            service_name="vless-snell-v5"
            proc_name="snell-server-v5"
            ;;
        snell-shadowtls|snell-v5-shadowtls|ss2022-shadowtls)
            service_name="vless-${selected}"
            proc_name="shadow-tls"
            ;;
        anytls)
            service_name="vless-anytls"
            proc_name="anytls-server"
            ;;
    esac
    
    _line
    echo -e "  ${C}$selected 服务日志 (最近 50 行):${NC}"
    _line
    
    if [[ "$DISTRO" == "alpine" ]]; then
        # Alpine: 从系统日志中过滤
        if [[ -f /var/log/messages ]]; then
            grep -iE "$proc_name|$service_name" /var/log/messages 2>/dev/null | tail -n 50
            if [[ $? -ne 0 ]]; then
                _warn "未找到相关日志"
            fi
        else
            _warn "系统日志不可用 (/var/log/messages)"
        fi
    else
        # systemd: 使用 journalctl
        if journalctl -u "$service_name" --no-pager -n 50 2>/dev/null; then
            :
        else
            _warn "无法获取服务日志，尝试从系统日志查找..."
            journalctl --no-pager -n 50 2>/dev/null | grep -iE "$proc_name|$service_name" || _warn "未找到相关日志"
        fi
    fi
}

#═══════════════════════════════════════════════════════════════════════════════
# 脚本更新与主入口
#═══════════════════════════════════════════════════════════════════════════════

do_update() {
    _header
    echo -e "  ${W}脚本更新${NC}"
    _line
    
    echo -e "  当前版本: ${G}v${VERSION}${NC}"
    _info "检查最新版本..."
    
    local raw_url="https://raw.githubusercontent.com/Chil30/vless-all-in-one/main/vless-server.sh"
    local tmp_file=$(mktemp)
    
    # 下载最新脚本
    if ! curl -sL --connect-timeout 10 -o "$tmp_file" "$raw_url"; then
        rm -f "$tmp_file"
        _err "下载失败，请检查网络连接"
        return 1
    fi
    
    # 获取远程版本号
    local remote_ver=$(grep -m1 '^readonly VERSION=' "$tmp_file" 2>/dev/null | cut -d'"' -f2)
    if [[ -z "$remote_ver" ]]; then
        rm -f "$tmp_file"
        _err "无法获取远程版本信息"
        return 1
    fi
    
    echo -e "  最新版本: ${C}v${remote_ver}${NC}"
    
    # 语义化版本比较函数
    _version_gt() {
        local v1="$1" v2="$2"
        [[ "$v1" == "$v2" ]] && return 1
        local IFS=.
        local i v1_arr=($v1) v2_arr=($v2)
        for ((i=0; i<${#v1_arr[@]} || i<${#v2_arr[@]}; i++)); do
            local n1=${v1_arr[i]:-0} n2=${v2_arr[i]:-0}
            ((n1 > n2)) && return 0
            ((n1 < n2)) && return 1
        done
        return 1
    }
    
    # 比较版本 - 只有远程版本更新时才提示更新
    if ! _version_gt "$remote_ver" "$VERSION"; then
        rm -f "$tmp_file"
        _ok "已是最新版本"
        return 0
    fi
    
    _line
    read -rp "  发现新版本，是否更新? [Y/n]: " confirm
    if [[ "$confirm" =~ ^[nN]$ ]]; then
        rm -f "$tmp_file"
        return 0
    fi
    
    _info "更新中..."
    
    # 获取当前脚本路径
    local script_path=$(readlink -f "$0")
    local script_dir=$(dirname "$script_path")
    local script_name=$(basename "$script_path")
    
    # 系统目录的脚本路径
    local system_script="/usr/local/bin/vless-server.sh"
    
    # 备份当前脚本
    cp "$script_path" "${script_path}.bak" 2>/dev/null
    
    # 替换当前运行的脚本
    if mv "$tmp_file" "$script_path" && chmod +x "$script_path"; then
        # 如果当前脚本不是系统目录的脚本，也更新系统目录
        if [[ "$script_path" != "$system_script" && -f "$system_script" ]]; then
            cp -f "$script_path" "$system_script" 2>/dev/null
            chmod +x "$system_script" 2>/dev/null
            _info "已同步更新系统目录脚本"
        fi
        
        _ok "更新成功! v${VERSION} -> v${remote_ver}"
        echo ""
        echo -e "  ${C}请重新运行脚本以使用新版本${NC}"
        echo -e "  ${D}备份文件: ${script_path}.bak${NC}"
        _line
        exit 0
    else
        # 恢复备份
        [[ -f "${script_path}.bak" ]] && mv "${script_path}.bak" "$script_path"
        rm -f "$tmp_file"
        _err "更新失败"
        return 1
    fi
}

main_menu() {
    check_root
    init_log  # 初始化日志
    init_db   # 初始化 JSON 数据库
    
    # 自动更新系统脚本 (确保 vless 命令始终是最新版本)
    _auto_update_system_script
    
    while true; do
        _header
        echo -e "  ${W}服务端管理${NC}"
        echo -e "  ${D}系统: $DISTRO | 架构: Xray+Sing-box ${NC}"
        echo ""
        show_status
        echo ""
        _line
        
        # 复用 show_status 缓存的结果，避免重复查询数据库
        local installed="$_INSTALLED_CACHE"
        if [[ -n "$installed" ]]; then
            # 多协议服务端菜单
            _item "1" "安装新协议 (多协议共存)"
            _item "2" "查看所有协议配置"
            _item "3" "订阅服务管理"
            _item "4" "管理协议服务"
            _item "5" "分流管理"
            _item "6" "配置管理 (导入/导出)"
            _item "7" "BBR 网络优化"
            _item "8" "卸载指定协议"
            _item "9" "完全卸载"
            _item "l" "查看运行日志"
        else
            _item "1" "安装协议"
            _item "2" "导入配置 (从备份恢复)"
        fi
        _item "u" "检查更新"
        _item "0" "退出"
        _line
        
        read -rp "  请选择: " choice || exit 0
        
        if [[ -n "$installed" ]]; then
            case $choice in
                1) do_install_server ;;
                2) show_all_protocols_info ;;
                3) manage_subscription ;;
                4) manage_protocol_services ;;
                5) manage_routing ;;
                6) manage_config ;;
                7) enable_bbr ;;
                8) uninstall_specific_protocol ;;
                9) do_uninstall ;;
                l|L) show_logs ;;
                u|U) do_update ;;
                0) exit 0 ;;
                *) _err "无效选择" ;;
            esac
        else
            case $choice in
                1) do_install_server ;;
                2) import_config ;;
                u|U) do_update ;;
                0) exit 0 ;;
                *) _err "无效选择" ;;
            esac
        fi
        _pause
    done
}

# 启动主菜单
main_menu
