# net-tcp-tune.sh 安全性与可靠性优化计划

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** 修复脚本中的安全漏洞、Bug 和代码质量问题，提升整体可靠性和可维护性

**Architecture:** 分四个阶段进行：P0 紧急安全修复 → P1 Bug 修复 → P2 代码质量改进 → P3 架构优化

**Tech Stack:** Bash 4.0+, jq, ShellCheck

---

## 阶段概览

| 阶段 | 优先级 | 任务数 | 预计影响 |
|------|--------|--------|----------|
| Phase 1 | P0 Critical | 6 个任务 | 修复安全漏洞 |
| Phase 2 | P1 Important | 8 个任务 | 修复功能 Bug |
| Phase 3 | P2 Quality | 6 个任务 | 代码质量改进 |
| Phase 4 | P3 Architecture | 4 个任务 | 架构优化 |

---

# Phase 1: P0 Critical 安全修复

## Task 1.1: 修复 curl | bash 不安全执行（Node.js 安装）

**Files:**
- Modify: `net-tcp-tune.sh:13970-13985`

**Step 1: 定位并读取当前代码**

```bash
grep -n "curl.*nodesource.*bash" net-tcp-tune.sh
```

**Step 2: 创建安全的 Node.js 安装函数**

将原代码：
```bash
curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
```

替换为：
```bash
# 安全下载并验证 Node.js 设置脚本
install_nodejs_safe() {
    local script_url="https://deb.nodesource.com/setup_20.x"
    local script_file=$(mktemp)
    local expected_header="#!/bin/bash"

    echo "正在下载 Node.js 安装脚本..."
    if ! curl -fsSL --connect-timeout 10 --max-time 60 "$script_url" -o "$script_file"; then
        echo -e "${gl_hong}❌ 下载失败${gl_bai}"
        rm -f "$script_file"
        return 1
    fi

    # 验证脚本头部
    if ! head -1 "$script_file" | grep -q "^#!"; then
        echo -e "${gl_hong}❌ 脚本格式验证失败${gl_bai}"
        rm -f "$script_file"
        return 1
    fi

    # 检查脚本大小（应该在合理范围内）
    local file_size=$(stat -c%s "$script_file" 2>/dev/null || stat -f%z "$script_file" 2>/dev/null)
    if [ "$file_size" -lt 1000 ] || [ "$file_size" -gt 100000 ]; then
        echo -e "${gl_hong}❌ 脚本大小异常${gl_bai}"
        rm -f "$script_file"
        return 1
    fi

    chmod +x "$script_file"
    bash "$script_file"
    local result=$?
    rm -f "$script_file"
    return $result
}
```

**Step 3: 验证修改**

```bash
grep -A 30 "install_nodejs_safe" net-tcp-tune.sh
```

**Step 4: Commit**

```bash
git add net-tcp-tune.sh
git commit -m "security: 修复 Node.js 安装的 curl|bash 漏洞

- 下载脚本到临时文件而非直接执行
- 验证脚本头部格式
- 检查文件大小是否合理
- 执行后清理临时文件"
```

---

## Task 1.2: 修复 curl | bash 不安全执行（Docker 安装）

**Files:**
- Modify: `net-tcp-tune.sh:14805`

**Step 1: 定位当前代码**

```bash
grep -n "get.docker.com.*sh" net-tcp-tune.sh
```

**Step 2: 替换为安全版本**

将原代码：
```bash
curl -fsSL https://get.docker.com | sh
```

替换为：
```bash
# 安全安装 Docker
install_docker_safe() {
    local script_url="https://get.docker.com"
    local script_file=$(mktemp)

    echo "正在下载 Docker 安装脚本..."
    if ! curl -fsSL --connect-timeout 10 --max-time 120 "$script_url" -o "$script_file"; then
        echo -e "${gl_hong}❌ Docker 安装脚本下载失败${gl_bai}"
        rm -f "$script_file"
        return 1
    fi

    # 验证是 shell 脚本
    if ! file "$script_file" | grep -qi "shell\|script\|text"; then
        echo -e "${gl_hong}❌ 文件类型验证失败${gl_bai}"
        rm -f "$script_file"
        return 1
    fi

    chmod +x "$script_file"
    sh "$script_file"
    local result=$?
    rm -f "$script_file"
    return $result
}
```

**Step 3: Commit**

```bash
git add net-tcp-tune.sh
git commit -m "security: 修复 Docker 安装的 curl|bash 漏洞"
```

---

## Task 1.3: 修复 sed 直接修改 JSON（Realm 配置）

**Files:**
- Modify: `net-tcp-tune.sh:1749-1780`

**Step 1: 定位问题代码**

```bash
sed -n '1745,1785p' net-tcp-tune.sh
```

**Step 2: 替换 sed 为 jq 处理**

将原代码：
```bash
sed -i '0,/{/s/{/{\n    "resolve": "ipv4",/' "$temp_config"
sed -i 's/":::/"0.0.0.0:/g' "$temp_config"
```

替换为：
```bash
# 使用 jq 安全修改 JSON 配置
modify_realm_config_safe() {
    local config_file="$1"
    local temp_output=$(mktemp)

    # 确保 jq 已安装
    if ! command -v jq &>/dev/null; then
        install_package jq
    fi

    # 添加 resolve: ipv4 到每个 endpoint
    if ! jq '
        if .endpoints then
            .endpoints |= map(. + {"resolve": "ipv4"})
        else
            . + {"resolve": "ipv4"}
        end
    ' "$config_file" > "$temp_output" 2>/dev/null; then
        echo -e "${gl_hong}❌ JSON 修改失败${gl_bai}"
        rm -f "$temp_output"
        return 1
    fi

    # 验证输出是有效 JSON
    if ! jq empty "$temp_output" 2>/dev/null; then
        echo -e "${gl_hong}❌ 生成的 JSON 无效${gl_bai}"
        rm -f "$temp_output"
        return 1
    fi

    # 替换 ::: 为 0.0.0.0:
    jq 'walk(if type == "string" then gsub(":::"; "0.0.0.0:") else . end)' \
        "$temp_output" > "${temp_output}.2" && mv "${temp_output}.2" "$temp_output"

    mv "$temp_output" "$config_file"
    return 0
}
```

**Step 3: 更新调用位置**

找到所有调用 sed 修改 JSON 的地方，替换为调用新函数。

**Step 4: Commit**

```bash
git add net-tcp-tune.sh
git commit -m "security: 使用 jq 替代 sed 修改 JSON 配置

- 避免 sed 破坏 JSON 结构
- 添加 JSON 有效性验证
- 支持复杂嵌套结构"
```

---

## Task 1.4: 修复 DNS 删除规则过于激进

**Files:**
- Modify: `net-tcp-tune.sh:1716`

**Step 1: 定位问题代码**

```bash
grep -n "nameserver.*:/d" net-tcp-tune.sh
```

**Step 2: 替换为精确匹配**

将原代码：
```bash
sed -i '/nameserver.*:/d' /etc/resolv.conf
```

替换为：
```bash
# 精确删除 IPv6 DNS 记录（仅匹配 IPv6 地址格式）
remove_ipv6_nameservers() {
    local resolv_file="${1:-/etc/resolv.conf}"

    # 备份原文件
    cp "$resolv_file" "${resolv_file}.bak.$(date +%s)"

    # 仅删除包含 IPv6 地址的 nameserver 行
    # IPv6 地址格式: 包含多个冒号分隔的十六进制段
    sed -i '/^nameserver[[:space:]]\+[0-9a-fA-F]*:[0-9a-fA-F:]*$/d' "$resolv_file"

    echo "已删除 IPv6 DNS 记录，备份保存在 ${resolv_file}.bak.*"
}
```

**Step 3: Commit**

```bash
git add net-tcp-tune.sh
git commit -m "security: 修复 DNS 删除规则，精确匹配 IPv6 地址"
```

---

## Task 1.5: 修复临时文件密码泄露

**Files:**
- Modify: `net-tcp-tune.sh:800-835`

**Step 1: 定位问题代码**

```bash
sed -n '800,840p' net-tcp-tune.sh
```

**Step 2: 安全处理密码存储**

```bash
# 安全设置 SOCKS5 代理（不写入密码到文件）
set_temp_socks5_proxy_safe() {
    # ... 获取用户输入 ...

    # 使用 umask 限制权限
    local old_umask=$(umask)
    umask 077

    # 创建安全的临时文件（仅 root 可读）
    local config_file=$(mktemp -p /run/user/${UID:-0} socks5_proxy.XXXXXX 2>/dev/null || mktemp)

    # 直接设置环境变量而非写入文件
    export http_proxy="socks5://${proxy_user}:${proxy_pass}@${proxy_ip}:${proxy_port}"
    export https_proxy="$http_proxy"
    export HTTP_PROXY="$http_proxy"
    export HTTPS_PROXY="$http_proxy"

    # 恢复 umask
    umask "$old_umask"

    # 不在进程列表中显示密码
    echo "代理已设置（仅当前会话有效）"

    # 清除密码变量
    unset proxy_pass
}
```

**Step 3: Commit**

```bash
git add net-tcp-tune.sh
git commit -m "security: 修复临时文件密码泄露问题

- 使用安全目录存储临时文件
- 设置严格的文件权限 (600)
- 使用后清除密码变量"
```

---

## Task 1.6: 修复配置文件权限过宽

**Files:**
- Modify: `net-tcp-tune.sh:8676-8677` 及其他位置

**Step 1: 搜索所有 chmod 644 配置文件的位置**

```bash
grep -n "chmod 644.*config\|chmod 644.*\.json\|chmod 644.*\.conf" net-tcp-tune.sh
```

**Step 2: 批量替换为安全权限**

```bash
# 敏感配置文件使用 600 权限
sed -i 's/chmod 644 "\$xray_config_path"/chmod 600 "\$xray_config_path"/g' net-tcp-tune.sh
sed -i 's/chmod 644 "\$config_file"/chmod 600 "\$config_file"/g' net-tcp-tune.sh
```

**Step 3: 添加通用的安全权限函数**

```bash
# 安全设置配置文件权限
secure_config_file() {
    local file="$1"
    local owner="${2:-root:root}"

    chown "$owner" "$file"
    chmod 600 "$file"
}
```

**Step 4: Commit**

```bash
git add net-tcp-tune.sh
git commit -m "security: 修复配置文件权限过宽 (644 -> 600)"
```

---

# Phase 2: P1 Important Bug 修复

## Task 2.1: 修复子 shell 变量作用域问题

**Files:**
- Modify: `net-tcp-tune.sh:2332-2397`

**Step 1: 定位问题代码**

```bash
sed -n '2330,2400p' net-tcp-tune.sh
```

**Step 2: 替换管道为 process substitution**

将原代码：
```bash
echo "$connections" | while read count ip; do
    source_num=$((source_num + 1))
done
```

替换为：
```bash
while read count ip; do
    source_num=$((source_num + 1))
    # 处理逻辑...
done < <(echo "$connections" | sort -rn)
```

**Step 3: Commit**

```bash
git add net-tcp-tune.sh
git commit -m "fix: 修复子 shell 变量作用域问题

使用 process substitution 替代管道，确保循环中的变量修改对父 shell 可见"
```

---

## Task 2.2: 修复 $? 检查顺序错误

**Files:**
- Modify: `net-tcp-tune.sh:1278, 2358` 等

**Step 1: 搜索所有 $? 延迟检查的位置**

```bash
grep -n '\$(.*)' net-tcp-tune.sh | head -20
grep -n 'if \[ \$? ' net-tcp-tune.sh
```

**Step 2: 修改为直接条件判断**

将原代码：
```bash
ip_info=$(timeout 2 curl -s "http://ip-api.com/json/${source_ip}")
if [ $? -eq 0 ] && [ -n "$ip_info" ]; then
```

替换为：
```bash
if ip_info=$(timeout 2 curl -s "http://ip-api.com/json/${source_ip}" 2>/dev/null) && [ -n "$ip_info" ]; then
```

**Step 3: Commit**

```bash
git add net-tcp-tune.sh
git commit -m "fix: 修复 \$? 检查顺序错误

直接在 if 语句中检查命令返回值，避免被中间操作覆盖"
```

---

## Task 2.3: 修复 Crontab 操作不安全

**Files:**
- Modify: `net-tcp-tune.sh:1480-1495`

**Step 1: 定位问题代码**

```bash
sed -n '1478,1500p' net-tcp-tune.sh
```

**Step 2: 替换为安全的 cron.d 方式**

将原代码：
```bash
local current_cron=$(crontab -l 2>/dev/null)
(echo "$current_cron"; echo "$cron_job") | crontab -
```

替换为：
```bash
# 安全添加 cron 任务（使用 cron.d 目录）
add_cron_job_safe() {
    local job_name="$1"
    local job_schedule="$2"
    local job_command="$3"
    local cron_file="/etc/cron.d/net-tcp-tune-${job_name}"

    # 检查任务是否已存在
    if [ -f "$cron_file" ]; then
        echo "Cron 任务已存在: $job_name"
        return 0
    fi

    # 写入 cron 文件
    cat > "$cron_file" << EOF
# net-tcp-tune.sh auto-generated cron job
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

${job_schedule} root ${job_command}
EOF

    chmod 644 "$cron_file"
    echo "Cron 任务已添加: $cron_file"
}

# 安全删除 cron 任务
remove_cron_job_safe() {
    local job_name="$1"
    local cron_file="/etc/cron.d/net-tcp-tune-${job_name}"

    if [ -f "$cron_file" ]; then
        rm -f "$cron_file"
        echo "Cron 任务已删除: $job_name"
    fi
}
```

**Step 3: Commit**

```bash
git add net-tcp-tune.sh
git commit -m "fix: 使用 cron.d 目录替代 crontab -l 管道操作

- 避免覆盖用户其他 cron 任务
- 任务存在性检查
- 独立文件便于管理"
```

---

## Task 2.4: 修复 IPv6 统计逻辑错误

**Files:**
- Modify: `net-tcp-tune.sh:1263-1320`

**Step 1: 定位问题代码**

```bash
sed -n '1260,1325p' net-tcp-tune.sh
```

**Step 2: 修复判断逻辑**

将原代码：
```bash
if [ $conn_count_v6_mapped -gt 0 ]; then
    protocol_type="✅ IPv4（IPv6映射格式）"
    ipv4_total=$((ipv4_total + conn_count))
else
    protocol_type="✅ 纯IPv4"
    ipv4_total=$((ipv4_total + conn_count))
fi
```

替换为：
```bash
# 正确区分 IPv4 和 IPv6 连接
if [ $conn_count_v6_mapped -gt 0 ]; then
    # IPv4-mapped IPv6 地址 (::ffff:x.x.x.x) 算作 IPv4
    protocol_type="✅ IPv4（IPv6映射格式）"
    ipv4_total=$((ipv4_total + conn_count))
elif echo "$source_ip" | grep -qE '^[0-9a-fA-F]*:[0-9a-fA-F:]+$'; then
    # 纯 IPv6 地址
    protocol_type="✅ 纯IPv6"
    ipv6_total=$((ipv6_total + conn_count))
else
    # 纯 IPv4 地址
    protocol_type="✅ 纯IPv4"
    ipv4_total=$((ipv4_total + conn_count))
fi
```

**Step 3: Commit**

```bash
git add net-tcp-tune.sh
git commit -m "fix: 修复 IPv6 连接统计逻辑

正确区分 IPv4、IPv6 和 IPv4-mapped IPv6 地址"
```

---

## Task 2.5: 修复无限循环无优雅退出

**Files:**
- Modify: `net-tcp-tune.sh:1397` 等多处

**Step 1: 搜索所有 while true 循环**

```bash
grep -n "while true" net-tcp-tune.sh
```

**Step 2: 添加 trap 处理**

在每个无限循环前添加：
```bash
# 设置中断处理
setup_loop_trap() {
    trap 'echo -e "\n${gl_huang}已中止${gl_bai}"; return 0' INT TERM
}

# 在循环中使用
monitor_connections() {
    setup_loop_trap

    while true; do
        # 循环逻辑...
        sleep 5
    done

    trap - INT TERM  # 清理 trap
}
```

**Step 3: Commit**

```bash
git add net-tcp-tune.sh
git commit -m "fix: 为无限循环添加优雅退出处理

- 添加 INT/TERM 信号处理
- Ctrl+C 可正常退出
- 清理资源后退出"
```

---

## Task 2.6: 修复 Caddy 删除域名注释残留（已完成）

**状态**: ✅ 已在之前的对话中修复

**验证**:
```bash
sed -n '17795,17825p' net-tcp-tune.sh
```

---

## Task 2.7: 修复数组初始化验证缺失

**Files:**
- Modify: `net-tcp-tune.sh:2536-2550`

**Step 1: 定位代码**

```bash
sed -n '2533,2555p' net-tcp-tune.sh
```

**Step 2: 添加数组验证**

```bash
# MTU 检测目标地址
declare -A targets=(
    ["香港"]="147.8.17.13 202.45.170.1"
    # ... 其他地区 ...
)

# 验证数组不为空
if [ ${#targets[@]} -eq 0 ]; then
    echo -e "${gl_hong}❌ MTU 检测目标列表为空${gl_bai}"
    return 1
fi
```

**Step 3: Commit**

```bash
git add net-tcp-tune.sh
git commit -m "fix: 添加 MTU 检测目标数组验证"
```

---

## Task 2.8: 修复边界条件处理

**Files:**
- Modify: `net-tcp-tune.sh:1240-1245`

**Step 1: 添加空字符串检查**

```bash
# 合并并去重 IP 列表
local all_source_ips=$(echo -e "${source_ips}\n${source_ips_v6}" | grep -v "^$" | sort -u)

# 检查是否有连接
if [ -z "$all_source_ips" ]; then
    echo -e "${gl_huang}暂无检测到任何连接${gl_bai}"
    return 0
fi

local total_sources=$(echo "$all_source_ips" | wc -l)
```

**Step 2: Commit**

```bash
git add net-tcp-tune.sh
git commit -m "fix: 添加空连接列表边界条件处理"
```

---

# Phase 3: P2 代码质量改进

## Task 3.1: 提取重复的 sysctl 操作为公共函数

**Files:**
- Modify: `net-tcp-tune.sh` (多处)

**Step 1: 在文件开头添加公共函数**

```bash
# ===== 公共函数定义 =====

# 注释 sysctl.conf 中的指定参数
comment_sysctl_params() {
    local file="${1:-/etc/sysctl.conf}"
    local params=(
        "net.core.rmem_max"
        "net.core.wmem_max"
        "net.ipv4.tcp_rmem"
        "net.ipv4.tcp_wmem"
        "net.core.default_qdisc"
        "net.ipv4.tcp_congestion_control"
    )

    for param in "${params[@]}"; do
        sed -i "/^${param//./\\.}/s/^/# /" "$file" 2>/dev/null
    done
}

# 清理 sysctl.d 目录中的冲突配置
clean_sysctl_conflicts() {
    local exclude_file="${1:-99-bbr-ultimate.conf}"

    for f in /etc/sysctl.d/*.conf; do
        [ "$(basename "$f")" = "$exclude_file" ] && continue
        if grep -qE "^net\.(core|ipv4)\.(rmem|wmem|tcp_)" "$f" 2>/dev/null; then
            mv "$f" "${f}.disabled.$(date +%Y%m%d_%H%M%S)"
        fi
    done
}
```

**Step 2: 替换所有重复代码为函数调用**

```bash
# 搜索并替换
grep -n "sed -i '/^net\.core\.rmem_max/s/^/# /'" net-tcp-tune.sh
# 替换为 comment_sysctl_params 调用
```

**Step 3: Commit**

```bash
git add net-tcp-tune.sh
git commit -m "refactor: 提取重复的 sysctl 操作为公共函数

减少代码重复，提高可维护性"
```

---

## Task 3.2: 统一定义常量（URLs 和版本号）

**Files:**
- Modify: `net-tcp-tune.sh` (文件开头)

**Step 1: 在文件开头添加常量定义区**

```bash
# ===== 常量定义 =====

# 版本信息
readonly SCRIPT_VERSION="2.3"
readonly CADDY_VERSION="2.9.0"
readonly SNELL_VERSION="4.0.1"

# 下载源
readonly SPEEDTEST_BASE_URL="https://install.speedtest.net/app/cli"
readonly XANMOD_KEY_URL="https://dl.xanmod.org/archive.key"
readonly XANMOD_REPO_URL="https://deb.xanmod.org"

# IP 查询服务（按优先级排序）
readonly IP_CHECK_URLS=(
    "https://api.ipify.org"
    "https://ipinfo.io/ip"
    "https://api.ip.sb/ip"
    "https://ifconfig.me/ip"
)

# 配置路径
readonly SYSCTL_CONF="/etc/sysctl.d/99-bbr-ultimate.conf"
readonly XRAY_CONFIG_DIR="${XRAY_CONFIG_DIR:-/usr/local/etc/xray}"
readonly CADDY_CONFIG_DIR="/etc/caddy"
readonly CONFIG_BACKUP_DIR="/root/.net-tcp-tune/backups"
```

**Step 2: 替换硬编码为常量引用**

**Step 3: Commit**

```bash
git add net-tcp-tune.sh
git commit -m "refactor: 统一定义 URL 和版本号常量

- 集中管理所有外部依赖 URL
- 便于版本升级和维护"
```

---

## Task 3.3: 添加统一的日志记录机制

**Files:**
- Modify: `net-tcp-tune.sh`

**Step 1: 添加日志函数**

```bash
# ===== 日志系统 =====

readonly LOG_FILE="/var/log/net-tcp-tune.log"
readonly LOG_LEVEL="${LOG_LEVEL:-INFO}"

# 日志函数
log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')

    # 写入日志文件
    echo "[$timestamp] [$level] $message" >> "$LOG_FILE" 2>/dev/null

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

log_error() { log "ERROR" "$@"; }
log_warn() { log "WARN" "$@"; }
log_info() { log "INFO" "$@"; }
log_debug() { log "DEBUG" "$@"; }
```

**Step 2: Commit**

```bash
git add net-tcp-tune.sh
git commit -m "feat: 添加统一的日志记录机制

- 支持 ERROR/WARN/INFO/DEBUG 级别
- 写入 /var/log/net-tcp-tune.log
- 彩色终端输出"
```

---

## Task 3.4: 添加通用的错误处理

**Files:**
- Modify: `net-tcp-tune.sh`

**Step 1: 在文件开头添加错误处理**

```bash
# ===== 错误处理 =====

# 全局错误处理器
error_handler() {
    local exit_code=$1
    local line_no=$2
    local command="$3"

    log_error "脚本执行失败"
    log_error "  退出码: $exit_code"
    log_error "  行号: $line_no"
    log_error "  命令: $command"

    # 尝试清理
    cleanup_on_error
}

# 错误时的清理
cleanup_on_error() {
    # 清理临时文件
    rm -f /tmp/net-tcp-tune.* 2>/dev/null

    # 恢复关键配置（如果有备份）
    if [ -f "${SYSCTL_CONF}.bak" ]; then
        log_warn "正在恢复 sysctl 配置..."
        mv "${SYSCTL_CONF}.bak" "$SYSCTL_CONF"
    fi
}

# 安全执行模式（可选启用）
enable_strict_mode() {
    set -euo pipefail
    trap 'error_handler $? $LINENO "$BASH_COMMAND"' ERR
}
```

**Step 2: Commit**

```bash
git add net-tcp-tune.sh
git commit -m "feat: 添加通用的错误处理机制

- 全局错误捕获
- 自动清理临时文件
- 可选的严格模式"
```

---

## Task 3.5: 统一命名规范

**Files:**
- Modify: `net-tcp-tune.sh`

**Step 1: 定义颜色常量（替换中文缩写）**

```bash
# ===== 颜色定义 =====
# 保留原有变量名以兼容，同时添加英文别名

readonly gl_hong='\033[31m'      # 红色
readonly gl_lv='\033[32m'        # 绿色
readonly gl_huang='\033[33m'     # 黄色
readonly gl_lan='\033[34m'       # 蓝色
readonly gl_zi='\033[35m'        # 紫色
readonly gl_kjlan='\033[96m'     # 亮青色
readonly gl_bai='\033[0m'        # 重置
readonly gl_hui='\033[90m'       # 灰色

# 英文别名
readonly COLOR_RED="$gl_hong"
readonly COLOR_GREEN="$gl_lv"
readonly COLOR_YELLOW="$gl_huang"
readonly COLOR_CYAN="$gl_kjlan"
readonly COLOR_RESET="$gl_bai"
readonly COLOR_GRAY="$gl_hui"
```

**Step 2: Commit**

```bash
git add net-tcp-tune.sh
git commit -m "refactor: 统一颜色常量定义

添加英文别名，保持向后兼容"
```

---

## Task 3.6: 运行 ShellCheck 并修复警告

**Step 1: 安装并运行 ShellCheck**

```bash
# 安装 ShellCheck
brew install shellcheck  # macOS
# apt install shellcheck  # Debian/Ubuntu

# 运行检查
shellcheck -x net-tcp-tune.sh > shellcheck_report.txt 2>&1 || true
```

**Step 2: 修复主要警告**

- SC2086: 添加双引号
- SC2046: 使用 mapfile 或引用
- SC2034: 删除未使用变量

**Step 3: Commit**

```bash
git add net-tcp-tune.sh
git commit -m "fix: 修复 ShellCheck 警告

- SC2086: 变量添加双引号
- SC2046: 防止分词问题
- 其他警告修复"
```

---

# Phase 4: P3 架构优化（可选）

## Task 4.1: 创建模块化目录结构

**Step 1: 创建目录**

```bash
mkdir -p modules/{core,network,proxy,deploy}
mkdir -p lib
```

**Step 2: 提取模块**

```
modules/
├── core/
│   ├── constants.sh      # 常量定义
│   ├── logging.sh        # 日志系统
│   └── utils.sh          # 通用工具函数
├── network/
│   ├── bbr.sh            # BBR 配置
│   ├── mtu.sh            # MTU/MSS 优化
│   └── dns.sh            # DNS 净化
├── proxy/
│   ├── xray.sh           # Xray 管理
│   ├── realm.sh          # Realm 转发
│   └── snell.sh          # Snell 协议
└── deploy/
    ├── caddy.sh          # Caddy 部署
    ├── ag-proxy.sh       # AG Proxy
    └── openwebui.sh      # Open WebUI
```

---

## Task 4.2: 实现模块加载系统

```bash
# 模块加载器
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODULES_DIR="$SCRIPT_DIR/modules"

load_module() {
    local module="$1"
    local module_path="$MODULES_DIR/$module.sh"

    if [ -f "$module_path" ]; then
        source "$module_path"
        log_debug "模块已加载: $module"
    else
        log_error "模块不存在: $module"
        return 1
    fi
}

# 加载所有核心模块
load_core_modules() {
    load_module "core/constants"
    load_module "core/logging"
    load_module "core/utils"
}
```

---

## Task 4.3: 添加命令行参数支持

```bash
# 命令行参数解析
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
            -q|--quiet)
                LOG_LEVEL="ERROR"
                shift
                ;;
            --debug)
                LOG_LEVEL="DEBUG"
                shift
                ;;
            bbr)
                load_module "network/bbr"
                bbr_menu
                exit 0
                ;;
            *)
                echo "未知参数: $1"
                show_help
                exit 1
                ;;
        esac
    done
}
```

---

## Task 4.4: 添加配置文件支持

```bash
# 配置文件路径
readonly USER_CONFIG="$HOME/.net-tcp-tune.conf"
readonly SYSTEM_CONFIG="/etc/net-tcp-tune.conf"

# 加载配置
load_config() {
    # 系统配置
    [ -f "$SYSTEM_CONFIG" ] && source "$SYSTEM_CONFIG"

    # 用户配置（覆盖系统配置）
    [ -f "$USER_CONFIG" ] && source "$USER_CONFIG"
}

# 示例配置文件
# ~/.net-tcp-tune.conf
# LOG_LEVEL=DEBUG
# XRAY_CONFIG_DIR=/custom/path
# PREFERRED_DNS=cloudflare
```

---

# 执行检查清单

## Phase 1 完成检查
- [ ] curl | bash 已替换为安全下载模式
- [ ] sed 修改 JSON 已替换为 jq
- [ ] DNS 删除规则已精确化
- [ ] 临时文件权限已修复
- [ ] 配置文件权限已修复

## Phase 2 完成检查
- [ ] 子 shell 变量作用域已修复
- [ ] $? 检查顺序已修复
- [ ] Crontab 操作已安全化
- [ ] IPv6 统计逻辑已修复
- [ ] 无限循环已添加 trap

## Phase 3 完成检查
- [ ] 重复代码已提取为函数
- [ ] 常量已统一定义
- [ ] 日志系统已添加
- [ ] 错误处理已添加
- [ ] ShellCheck 警告已修复

## Phase 4 完成检查（可选）
- [ ] 模块化目录结构已创建
- [ ] 模块加载系统已实现
- [ ] 命令行参数已支持
- [ ] 配置文件已支持

---

# 测试计划

## 功能测试
```bash
# 测试 BBR 配置
./net-tcp-tune.sh bbr

# 测试 Caddy 部署
./net-tcp-tune.sh
# 选择 43

# 测试 DNS 净化
./net-tcp-tune.sh
# 选择 5
```

## 回归测试
```bash
# 确保所有菜单选项可正常进入
for i in {1..43}; do
    echo "$i" | timeout 5 ./net-tcp-tune.sh 2>/dev/null || echo "菜单 $i 可能有问题"
done
```

---

**计划完成，保存到 `docs/plans/2026-01-22-security-reliability-optimization.md`**
