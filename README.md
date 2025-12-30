# VPS TCP 优化 & 端口流量狗工具箱
> **项目地址**: https://github.com/Eric86777/vps-tcp-tune

🚀 **一站式 VPS 优化与管理解决方案**  
本项目集成两大核心神器，助您榨干 VPS 性能，精准掌控流量。

| 🔧 **系统优化 (BBR)** | 🐶 **端口流量狗 (Dog)** |
| :--- | :--- |
| **命令**: `bbr` | **命令**: `dog` |
| ✅ XanMod 内核 + BBR v3 | ✅ 精准流量统计 (nftables) |
| ✅ 智能带宽/MTU 优化 | ✅ 多端口/端口段/端口组管理 |
| ✅ DNS 净化 & 安全加固 | ✅ 自动断网/重置/告警 |
| ✅ Proxy/转发一键部署 | ✅ 实时速率/历史账单 |

> **版本**: v4.1.0 (系统优化) / v1.5.4 (流量狗)  
> **快速上手**: [📖 快速使用指南](QUICK_START.md)

---

## 🚀 极速安装 (推荐)

只需一行命令，同时安装 `bbr` 和 `dog` 两个快捷指令：

**如果是新机器（未安装 curl），请先手动执行：**
```bash
apt update -y && apt install curl -y
```

**一键安装命令：**
```bash
# 安装快捷别名 (支持 bash 和 zsh)
bash <(curl -fsSL "https://raw.githubusercontent.com/Eric86777/vps-tcp-tune/main/install-alias.sh?$(date +%s)")

# 重新加载配置
source ~/.bashrc  # 或 source ~/.zshrc
```

**现在，您可以直接输入命令使用：**
- 输入 `bbr` 👉 进入系统优化菜单
- 输入 `dog` 👉 进入流量监控菜单

---

## 🐶 端口流量狗 (Port Traffic Dog)

> **致谢**: 本脚本基于 [zywe03/realm-xwPF](https://github.com/zywe03/realm-xwPF) 进行深度魔改与增强。

一款轻量级、高性能的端口流量统计与限制工具，专为合租/通过流量计费的场景设计。

### 🔥 核心增强功能
- **🛡️ 计费级精度**：基于 `nftables` 内核级统计，不漏算一个字节。
- **📊 灵活计费**：支持**双向计费**、**单向计费** (出站x2) 等策略。
- **🛑 自动阻断**：流量超额毫秒级自动切断，防止超支。
- **📅 账单管理**：支持设置**月度重置日** (如每月1号或28号自动清零)。
- **👥 合租神器**：
    - **端口组**：多个端口共享一个流量包 (如 10001,10002 共用 1TB)。
    - **租期管理**：设置到期日，到期自动停机 + 邮件通知。
- **💾 数据安全**：
    - **自动备份**：每日自动备份流量数据，防止重启丢数据。
    - **配置检测**：内置智能诊断工具，一键修复异常规则。

### 🎮 常用操作
```bash
dog             # 启动主菜单
dog --list      # 快速查看所有端口流量
dog --help      # 查看更多参数
```

---

## 🔧 系统优化 (BBR & Tune)

### 🎯 最佳实践流程
1.  **安装内核**：运行 `bbr` -> 选 `1` (安装 XanMod 内核 + BBR v3)，**重启**。
2.  **BBR 调优**：运行 `bbr` -> 选 `3` (智能带宽优化)，自动匹配最佳 TCP 参数。
3.  **网络优化**：运行 `bbr` -> 选 `4` (MTU/MSS 优化)，修复断流和丢包。
4.  **DNS 净化**：运行 `bbr` -> 选 `5` (DNS 净化)，抗污染、防劫持。

### 📋 功能列表
| 分类 | 功能 |
| :--- | :--- |
| **内核优化** | XanMod 内核安装、BBR v3 启用、卸载内核 |
| **网络调优** | BBR 参数调优、MTU/MSS 检测修复、DNS 净化 (DoT/DNSSEC) |
| **系统配置** | IPv4/IPv6 优先级、虚拟内存 (Swap) 管理、系统信息查看 |
| **代理部署** | Snell v5 (多实例)、Xray (多协议)、Socks5、Cloudflare Tunnel |
| **测试工具** | 速度测试、回程路由 (CN2/9929)、流媒体解锁检测、IP 质量检测 |

---

## ⚠️ 常见问题

**Q: 安装后运行 `bbr` 或 `dog` 提示找不到命令？**
A: 请执行 `source ~/.bashrc` 重新加载配置，或者断开 SSH 重连即可。

**Q: 流量狗支持 Docker 映射的端口吗？**
A: 支持！脚本会自动识别 Docker 映射的端口并进行统计。

**Q: 开启 BBR v3 需要重启吗？**
A: 是的，首次安装内核后必须重启服务器。后续修改参数（如功能 3）通常无需重启。

---

**⭐ 如果这个项目对你有帮助，欢迎 Star！**

## Star History

[![Star History Chart](https://api.star-history.com/svg?repos=Eric86777/vps-tcp-tune&type=Date)](https://www.star-history.com/#Eric86777/vps-tcp-tune&Date)
