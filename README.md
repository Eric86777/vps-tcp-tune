# BBR v3 优化脚本 - Ultimate Edition v4.2.1

🚀 **XanMod 内核 + BBR v3 + 全方位 VPS 管理工具集**  
一键安装 XanMod 内核，启用 BBR v3 拥塞控制，集成 38+ 实用工具，优化你的 VPS 服务器。

> **版本**: v4.2.1 (安全下载校验与规则保护版)  
> **快速上手**: [📖 快速使用指南](QUICK_START.md)

---

## 🚀 一键安装

### 方式1：快捷别名（⭐ 强烈推荐）

**如果是新机器（未安装 curl），请先手动执行：**

```bash
apt update -y && apt install curl -y
```

**安装脚本（安装后只需输入 `bbr` 即可运行）：**

```bash
# 安装别名
bash <(curl -fsSL "https://raw.githubusercontent.com/Eric86777/vps-tcp-tune/main/install-alias.sh?$(date +%s)")

# 重新加载配置
source ~/.bashrc  # 或 source ~/.zshrc

# 以后直接使用
bbr
```

**✨ 优势**：
- ✅ 每次运行自动获取最新版本
- ✅ 只需输入 3 个字符即可启动
- ✅ 无需记忆复杂命令
- ✅ 支持 bash 和 zsh


<details>
<summary>💡 其他安装方式（点击展开）</summary>

### 方式2：在线运行（临时使用）

```bash
# 推荐：使用时间戳参数确保获取最新版本（无缓存）
bash <(curl -fsSL "https://raw.githubusercontent.com/Eric86777/vps-tcp-tune/main/net-tcp-tune.sh?$(date +%s)")
```

### 方式3：下载到本地

```bash
wget -O net-tcp-tune.sh "https://raw.githubusercontent.com/Eric86777/vps-tcp-tune/main/net-tcp-tune.sh?$(date +%s)"
chmod +x net-tcp-tune.sh
./net-tcp-tune.sh
```

</details>

---

## 🎯 最佳实践流程（作者推荐）

这是经过多次实测总结出的**推荐**优化路径，建议按顺序执行：

### 1️⃣ 第一步：安装内核
*   执行 **功能 1**：安装 XanMod 内核 + BBR v3。
*   **注意**：安装完成后**必须重启 VPS** 才能生效。

### 2️⃣ 第二步：BBR 调优（核心步骤）
*   执行 **功能 3**：BBR 直连/落地优化。
*   **如何选择**：
    *   **小白用户**：选择 `1` (自动检测)，脚本会跑一次 Speedtest 并自动计算最佳参数。
    *   **进阶用户（推荐）**：如果你清楚自己的线路带宽，直接手动选择档位（如 `500Mbps` 或 `1Gbps`）。
    *   *作者经验：我自己一般手动选 500M 或 700M 档位，效果最稳。*

### 3️⃣ 第三步：网络路径优化
*   执行 **功能 4**：MTU 检测与 MSS 优化。
*   **作用**：尝试消除数据包分片导致的丢包，改善连接稳定性。

### 4️⃣ 第四步：DNS 净化（可选，慎用）
*   执行 **功能 5**：NS 论坛-DNS 净化。
*   **新增三选一模式**：
    *   `1. 纯国外模式`：Google + Cloudflare，无备用，强制 DoT 加密（**抗污染推荐**）
    *   `2. 纯国内模式`：阿里云 + 腾讯 DNSPod，无备用，机会性 DoT
    *   `3. 混合模式`：国外首选 + 国内备用，最大容错
*   **警告**：此功能涉及系统底层网络配置，虽然能解决 DNS 污染和 DHCP 抢占问题，但有 **约 1% 的概率** 导致 VPS 失联（取决于商家的网络环境）。**请务必在有 VNC/控制台救援手段的情况下使用！**

---

## 📋 功能菜单概览

本脚本包含 **38** 个核心功能，涵盖内核优化、网络加速、代理部署、系统管理等全方位需求。

### 🟢 核心功能
| 编号 | 功能名称 | 说明 |
|------|---------|------|
| **1** | **安装/更新 XanMod 内核 + BBR v3** | ⭐ **推荐**，系统性能基石 |
| **2** | 卸载 XanMod 内核 | 恢复系统默认内核 |

### 🔵 BBR/网络优化
| 编号 | 功能名称 | 说明 |
|------|---------|------|
| **3** | **BBR 直连/落地优化** | ⭐ **推荐**，智能带宽检测 + Reality终极优化参数 |
| **4** | **MTU检测与MSS优化** | ⭐ **推荐**，消除丢包与重传，提升稳定性 |
| **5** | NS论坛-DNS净化 | 抗污染、驯服DHCP，**新增三选一模式**（纯国外/纯国内/混合） |
| **6** | **Realm转发timeout修复** | ⭐ **推荐**，解决中转断流问题 |

### 🟡 系统配置
| 编号 | 功能名称 | 说明 |
|------|---------|------|
| **7** | 设置IPv4/IPv6优先级 | 解决 Google 验证码跳验证等问题 |
| **8** | IPv6管理 | 临时/永久禁用或恢复 IPv6 |
| **9** | 设置临时SOCKS5代理 | 终端临时走代理，支持认证 |
| **10** | 虚拟内存管理 | 智能计算并添加 Swap，防止 OOM |
| **11** | 查看系统详细状态 | CPU/内存/磁盘/网络/内核信息 |

### 🟣 转发/代理配置
| 编号 | 功能名称 | 说明 |
|------|---------|------|
| **12** | Realm转发连接分析 | 实时监控转发流量与来源 IP |
| **13** | **Realm强制使用IPv4** | ⭐ **推荐**，提升转发稳定性 |
| **14** | IPv4/IPv6连接检测 | 测试双栈连通性 |
| **15** | 查看Xray配置 | 显示当前节点配置信息 |
| **16** | 设置Xray IPv6出站 | 让 Xray 优先走 IPv6 |
| **17** | 恢复Xray默认配置 | 救砖功能 |

### 🟠 代理部署
| 编号 | 功能名称 | 说明 |
|------|---------|------|
| **18** | **星辰大海Snell协议** | ⭐ **推荐**，v5.0.1内核，支持多实例/多端口 |
| **19** | **星辰大海Xray一键多协议** | ⭐ **推荐**，VLESS+Reality + SS2022 + TUIC v5 + AnyTLS |
| **20** | 禁止端口通过中国大陆直连 | 安全防护，防止被扫 |
| **21** | 一键部署SOCKS5代理 | 快速搭建 SOCKS5 服务 |
| **22** | Sub-Store多实例管理 | 强大的订阅转换工具 |
| **23** | **一键反代 🎯** | ⭐ **推荐**，Cloudflare Tunnel 内网穿透 |

### 🔴 测试检测
| 编号 | 功能名称 | 说明 |
|------|---------|------|
| **24** | IP质量检测（IPv4+IPv6） | 综合欺诈分数检测 |
| **25** | **IP质量检测（仅IPv4）** | ⭐ **推荐**，快速检测 |
| **26** | 服务器带宽测试 | Speedtest 测速 |
| **27** | iperf3单线程测试 | 精准测试网络吞吐量 |
| **28** | **国际互联速度测试** | ⭐ **推荐**，全球节点测速 |
| **29** | **网络延迟质量检测** | ⭐ **推荐**，丢包率与延迟抖动 |
| **30** | **三网回程路由测试** | ⭐ **推荐**，检测线路质量（CN2/9929/CMIN2） |
| **31** | **IP媒体/AI解锁检测** | ⭐ **推荐**，Netflix/Disney+/ChatGPT 等 |
| **32** | NS一键检测脚本 | 综合系统信息检测 |

### 🟤 第三方工具
| 编号 | 功能名称 | 说明 |
|------|---------|------|
| **33** | zywe_realm转发脚本 | 强大的端口转发工具 |
| **34** | F佬一键sing box脚本 | 全能代理工具 |
| **35** | 科技lion脚本 | 综合运维脚本 |
| **36** | 酷雪云脚本 | 综合运维脚本 |


### ⚪ 原注销脚本恢复
| 编号 | 功能名称 | 说明 |
|------|---------|------|
| **37** | NS论坛CAKE调优 | 队列算法优化，提升网络性能 |
| **38** | 科技lion高性能模式 | 高性能内核参数优化 |

---

## 🌟 核心特性详解

### 1. Snell v5 多实例管理 (功能 18)
脚本内置了最新的 **Snell v5.0.1** 管理功能，提供比官方脚本更灵活的功能：
- ✅ **多实例支持**：可以在同一台机器上通过不同端口运行多个 Snell 节点。
- ✅ **自定义配置**：支持自定义端口、自定义节点名称。
- ✅ **智能更新**：一键更新所有运行中的 Snell 实例到最新内核，无需手动逐个重启。
- ✅ **双栈支持**：可选 IPv4 / IPv6 / 双栈监听模式。

### 2. BBR v3 + 智能带宽优化 (功能 3)
基于 Google BBR v3 算法，配合脚本独家的**智能带宽检测**：
- 自动运行 Speedtest 测速。
- 根据上传带宽自动计算最佳 TCP 窗口大小 (BDP)。
- 动态调整 `rmem` 和 `wmem` 缓冲区，避免小内存机器 OOM，同时跑满大带宽机器性能。

### 3. MTU/MSS 路径优化 (功能 4)
解决跨国网络中常见的“能 Ping 通但连不上”或“速度极慢”的问题：
- 自动检测到目标 IP 的最佳 MTU 值。
- 设置 MSS Clamping，防止数据包因过大而在路由途中被丢弃。
- 改善丢包率，提升连接稳定性。

### 4. Realm 转发全家桶 (功能 6, 12, 13)
专为中转用户打造的 Realm 增强套件：
- **Timeout 修复**：解决 Realm 转发断流、超时问题。
- **强制 IPv4**：强制 Realm 解析和转发走 IPv4 链路，提升稳定性。
- **连接分析**：实时看到是谁连了你的转发端口，IP 归属地一目了然。

---

## ⚠️ 常见问题

**Q: 安装后运行 `bbr` 提示找不到命令？**
A: 请执行 `source ~/.bashrc` 重新加载配置，或者断开 SSH 重连即可。

**Q: Snell 更新后旧版本还在？**
A: 请使用脚本菜单中的 **功能 4 (更新 Snell 服务)**，脚本会自动停止所有旧进程、下载新内核并重启所有实例。

**Q: 开启 BBR v3 需要重启吗？**
A: 是的，首次安装内核后必须重启服务器。后续修改参数（如功能 3）通常无需重启。

---

**⭐ 如果这个脚本对你有帮助，欢迎 Star！**

---

---

## 🐶 端口流量狗 (Port Traffic Dog)

一款轻量级、高性能的端口流量统计与限制工具，专为合租/通过流量计费的场景设计。

### 📦 全新安装

**如果是第一次安装，直接执行：**

```bash
# 安装别名
bash <(curl -fsSL "https://raw.githubusercontent.com/Eric86777/vps-tcp-tune/main/install-alias.sh?$(date +%s)")

# 重新加载配置
source ~/.bashrc  # 或 source ~/.zshrc

# 以后直接使用
dog
```

### 🔄 从旧版本迁移（重要！）

**如果你之前使用过原版流量狗或手动安装过脚本，请先执行清理：**

> ⚠️ **放心**：以下操作只删除脚本文件，**不会删除你的流量数据和配置**！  
> 所有数据都保存在 `/etc/port-traffic-dog/` 目录中，完全不受影响。

```bash
# 1. 清理旧的脚本文件和软链接（数据不受影响）
rm -f /usr/local/bin/dog /usr/local/bin/port-traffic-dog.sh

# 2. 安装新的别名（从 GitHub 拉取最新版）
bash <(curl -fsSL "https://raw.githubusercontent.com/Eric86777/vps-tcp-tune/main/install-alias.sh?$(date +%s)")

# 3. 重新加载配置
source ~/.bashrc

# 4. 验证安装（应该显示 "dog is aliased to ..."）
type dog

# 5. 运行新版本
dog
```

**迁移后的优势**：
- ✅ 每次运行 `dog` 自动获取 GitHub 上的最新版本
- ✅ 无需手动更新脚本
- ✅ 所有历史数据、端口配置、通知设置完整保留

### 🔍 计数器健康检查（排查用）

**如果发现多台机器的流量统计不一致，可以用这个命令快速排查：**

```bash
bash -c 'counters=$(nft list counters inet port_traffic_monitor 2>/dev/null | grep -oP "counter port_\K[0-9_]+(?=_in)" | sort -u); echo "=== 端口计数器检查 ==="; echo "Uptime: $(cat /proc/uptime | awk "{print int(\$1/86400)\"天\"int((\$1%86400)/3600)\"时\"}")"; echo ""; for p in $counters; do in_data=$(nft list counter inet port_traffic_monitor "port_${p}_in" 2>/dev/null); out_data=$(nft list counter inet port_traffic_monitor "port_${p}_out" 2>/dev/null); in_pkt=$(echo "$in_data" | grep -oP "packets \K[0-9]+" || echo 0); out_pkt=$(echo "$out_data" | grep -oP "packets \K[0-9]+" || echo 0); in_b=$(echo "$in_data" | grep -oP "bytes \K[0-9]+" || echo 0); out_b=$(echo "$out_data" | grep -oP "bytes \K[0-9]+" || echo 0); status="✅正常"; [ "$in_pkt" = "0" ] && [ "$out_pkt" = "0" ] && [ "$in_b" != "0" -o "$out_b" != "0" ] && status="⚠️已恢复"; echo "端口$p: packets=$in_pkt/$out_pkt bytes=$in_b/$out_b $status"; done'
```

**状态说明**：
- **✅正常** - 原始统计数据，`packets > 0`，数据可信
- **⚠️已恢复** - 从备份恢复的数据，`packets = 0` 但 `bytes > 0`，可能有偏差

> 💡 **提示**：如果多台机器的流量数据不一致，通常是因为某台机器重启过，数据从备份恢复导致不准。可以在所有相关机器上同时重置流量计数器，从零开始统计。

### ✨ 功能亮点

- ✅ 计费级精度 (nftables)
- ✅ 自动阻断与恢复
- ✅ 流量自动备份
- ✅ 只需要输入 3 个字符

---

## ⭐ 支持项目

如果这个脚本对你有帮助，欢迎 Star！

[![GitHub stars](https://img.shields.io/github/stars/Eric86777/vps-tcp-tune?style=social)](https://github.com/Eric86777/vps-tcp-tune)

## Star History

<a href="https://star-history.com/#Eric86777/vps-tcp-tune&Date">
  <img src="https://api.star-history.com/svg?repos=Eric86777/vps-tcp-tune&type=Date" alt="Star History Chart" width="600">
</a>
