# BBR v3 优化脚本 - Ultimate Edition v4.9.0

**XanMod 内核 + BBR v3 + 全方位 VPS 管理工具集**

一键安装 XanMod 内核，启用 BBR v3 拥塞控制，集成 32 项实用功能，优化你的 VPS 服务器。

> **版本**: v4.9.0

---

## 一键安装

### 方式1：快捷别名（推荐）

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

**优势**：
- 每次运行自动获取最新版本
- 只需输入 3 个字符即可启动
- 无需记忆复杂命令
- 支持 bash 和 zsh


<details>
<summary>其他安装方式（点击展开）</summary>

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

## 最佳实践流程（作者推荐）

这是经过多次实测总结出的**推荐**优化路径，建议按顺序执行：

> **懒人方案**：直接执行 **功能 66**（一键全自动优化），脚本会自动完成以下所有步骤。

### 第一步：安装内核
- 执行 **功能 1**：安装 XanMod 内核 + BBR v3
- **注意**：安装完成后**必须重启 VPS** 才能生效

### 第二步：BBR 调优（核心步骤）
- 执行 **功能 3**：BBR 直连/落地优化
- **如何选择**：
  - **小白用户**：选择 `1` (自动检测)，脚本会跑一次 Speedtest 并自动计算最佳参数
  - **进阶用户（推荐）**：如果你清楚自己的线路带宽，直接手动选择档位（如 `500Mbps` 或 `1Gbps`）
  - *作者经验：我自己一般手动选 500M 或 700M 档位，效果最稳*

### 第三步：网络路径优化
- 执行 **功能 4**：MTU 检测与 MSS 优化
- **作用**：尝试消除数据包分片导致的丢包，改善连接稳定性

### 第四步：DNS 净化（可选，慎用）
- 执行 **功能 5**：NS 论坛-DNS 净化
- **两种模式**：
  - `1. 纯国外模式`：Google + Cloudflare，强制 DoT 加密（**抗污染推荐**）
  - `2. 纯国内模式`：阿里云 + 腾讯 DNSPod，无加密（国内DNS不支持DoT）
- **安全说明**：已内置完整的事务性回滚机制（执行前全量快照 → 任意步骤失败自动恢复原始状态），重启持久化也已修复。如仍有顾虑，建议在有 VNC/控制台的情况下首次使用。

---

## 功能菜单概览

本脚本包含 **32** 项功能，涵盖内核优化、网络加速、代理部署、系统管理等全方位需求。

### 核心功能
| 编号 | 功能名称 | 说明 |
|:----:|---------|------|
| 1 | **安装/更新 XanMod 内核 + BBR v3** | 推荐，系统性能基石 |
| 2 | 卸载 XanMod 内核 | 恢复系统默认内核 |

### BBR/网络优化
| 编号 | 功能名称 | 说明 |
|:----:|---------|------|
| 3 | **BBR 直连/落地优化** | 推荐，智能带宽检测 + Reality 终极优化参数 |
| 4 | **MTU 检测与 MSS 优化** | 推荐，消除丢包与重传，提升稳定性 |
| 5 | NS 论坛-DNS 净化 | 抗污染、驯服 DHCP，两种模式 |
| 6 | **Realm 转发 timeout 修复** | 推荐，解决中转断流问题 |

### 系统配置
| 编号 | 功能名称 | 说明 |
|:----:|---------|------|
| 7 | 设置 IPv4/IPv6 优先级 | 解决 Google 验证码跳验证等问题 |
| 8 | IPv6 管理 | 临时/永久禁用或恢复 IPv6 |
| 9 | 设置临时 SOCKS5 代理 | 终端临时走代理，支持认证 |
| 10 | 虚拟内存管理 | 智能计算并添加 Swap，防止 OOM |
| 11 | 查看系统详细状态 | CPU/内存/磁盘/网络/内核信息 |

### 代理部署
| 编号 | 功能名称 | 说明 |
|:----:|---------|------|
| 12 | **星辰大海 Snell 协议** | 推荐，v5.0.1 内核，支持多实例/多端口 |
| 13 | **星辰大海 Xray 一键多协议** | 推荐，VLESS+Reality + SS2022 + TUIC v5 + AnyTLS |
| 14 | 禁止端口通过中国大陆直连 | 安全防护，防止被扫 |
| 15 | 一键部署 SOCKS5 代理 | 快速搭建 SOCKS5 服务 |
| 16 | Sub-Store 多实例管理 | 强大的订阅转换工具 |
| 17 | **一键反代** | 推荐，Cloudflare Tunnel 内网穿透 |

### 测试检测
| 编号 | 功能名称 | 说明 |
|:----:|---------|------|
| 18 | IP 质量检测（IPv4+IPv6） | 综合欺诈分数检测 |
| 19 | **IP 质量检测（仅 IPv4）** | 推荐，快速检测 |
| 20 | 服务器带宽测试 | Speedtest 测速 |
| 21 | iperf3 单线程测试 | 精准测试网络吞吐量 |
| 22 | **国际互联速度测试** | 推荐，全球节点测速 |
| 23 | **网络延迟质量检测** | 推荐，丢包率与延迟抖动 |
| 24 | **三网回程路由测试** | 推荐，检测线路质量（CN2/9929/CMIN2） |
| 25 | **IP 媒体/AI 解锁检测** | 推荐，Netflix/Disney+/ChatGPT 等 |
| 26 | **NQ 一键检测** | 推荐，综合系统信息检测 |

### 第三方工具
| 编号 | 功能名称 | 说明 |
|:----:|---------|------|
| 27 | zywe_realm 转发脚本 | 查看原版仓库信息 |
| 28 | F 佬一键 sing box 脚本 | 全能代理工具 |
| 29 | 科技 lion 脚本 | 综合运维脚本 |
| 30 | NS 论坛 CAKE 调优 | 队列算法优化，提升网络性能 |
| 31 | 科技 lion 高性能模式 | 高性能内核参数优化 |

### AI 代理服务工具箱
| 编号 | 功能名称 | 说明 |
|:----:|---------|------|
| 32 | **AI 代理工具箱** | 推荐，包含以下子功能 |

### 一键优化
| 编号 | 功能名称 | 说明 |
|:----:|---------|------|
| 66 | **⭐ 一键全自动优化 (BBR v3 + 网络调优)** | 推荐，两阶段自动执行 1→3→4→5→6→8 |

AI 代理工具箱包含：
- **Antigravity Claude Proxy**：Claude Code 反代服务，systemd 托管
- **Open WebUI**：AI 聊天界面，Docker 容器化
- **CRS 部署管理**：Claude API 多账户中转/拼车服务
- **Fuclaude**：Claude 网页版共享工具
- **Caddy 多域名反代**：HTTPS 反向代理，自动 SSL 证书
- **OpenAI Responses API 转换代理**：Chat Completions → Responses API 转换
- **OpenClaw 部署管理**：AI 多渠道消息网关，支持 Telegram/WhatsApp/Discord/Slack

---

## 核心特性详解

### 1. Snell v5 多实例管理 (功能 12)
脚本内置了最新的 **Snell v5.0.1** 管理功能，提供比官方脚本更灵活的功能：
- **多实例支持**：可以在同一台机器上通过不同端口运行多个 Snell 节点
- **自定义配置**：支持自定义端口、自定义节点名称
- **智能更新**：一键更新所有运行中的 Snell 实例到最新内核，无需手动逐个重启
- **双栈支持**：可选 IPv4 / IPv6 / 双栈监听模式

### 2. BBR v3 + 智能带宽优化 (功能 3)
基于 Google BBR v3 算法，配合脚本独家的**智能带宽检测**：
- 自动运行 Speedtest 测速
- 根据上传带宽自动计算最佳 TCP 窗口大小 (BDP)
- 动态调整 `rmem` 和 `wmem` 缓冲区，避免小内存机器 OOM，同时跑满大带宽机器性能

### 3. MTU/MSS 路径优化 (功能 4)
解决跨国网络中常见的"能 Ping 通但连不上"或"速度极慢"的问题：
- 自动检测到目标 IP 的最佳 MTU 值
- 设置 MSS Clamping，防止数据包因过大而在路由途中被丢弃
- 改善丢包率，提升连接稳定性

### 4. Caddy 多域名反代 (功能 32 子菜单)
全功能的 HTTPS 反向代理解决方案：
- **一键部署**: 自动安装 Caddy，配置 systemd 服务
- **智能检测**: 自动检测端口占用、防火墙配置、域名解析
- **SSL 自动化**: Let's Encrypt 证书自动申请和续期
- **多域名管理**: 轻松添加、删除、查看多个反代域名
- **安全备份**: 配置修改前自动备份，失败自动回滚
- **热重载**: 配置更新无需重启服务

**典型使用场景**:
- 用好线路 VPS 反代垃圾线路服务，加速访问
- 为 HTTP 服务快速添加 HTTPS 支持
- 多个后端服务统一使用 443 端口对外

### 5. OpenClaw AI 多渠道消息网关 (功能 32 子菜单)
自托管的 AI 多渠道消息网关，让你通过 Telegram/WhatsApp/Discord/Slack 与 AI 对话：
- **一键部署**: 自动安装 Node.js 22+、npm 全局安装、systemd 服务配置
- **多渠道支持**: Telegram Bot、WhatsApp、Discord Bot、Slack App 一键配置
- **灵活模型接入**: 支持 Anthropic 直连/反代、OpenAI 兼容中转（new-api/one-api/LiteLLM）、OpenRouter
- **Antigravity 预设**: 内置 Antigravity Claude Proxy 快速接入模板
- **快速替换 API**: 一键更换反代地址和 API Key，无需重新配置
- **部署信息查看**: 格式化展示当前配置、SSH 隧道命令、管理命令

---

## 常见问题

**Q: 安装后运行 `bbr` 提示找不到命令？**

A: 请执行 `source ~/.bashrc` 重新加载配置，或者断开 SSH 重连即可。

**Q: Snell 更新后旧版本还在？**

A: 请使用脚本菜单中的更新 Snell 服务功能，脚本会自动停止所有旧进程、下载新内核并重启所有实例。

**Q: 开启 BBR v3 需要重启吗？**

A: 是的，首次安装内核后必须重启服务器。后续修改参数（如功能 3）通常无需重启。

---

## 支持项目

如果这个脚本对你有帮助，欢迎 Star！

[![GitHub stars](https://img.shields.io/github/stars/Eric86777/vps-tcp-tune?style=social)](https://github.com/Eric86777/vps-tcp-tune)

## Star History

<a href="https://star-history.com/#Eric86777/vps-tcp-tune&Date">
  <img src="https://api.star-history.com/svg?repos=Eric86777/vps-tcp-tune&type=Date" alt="Star History Chart" width="600">
</a>
