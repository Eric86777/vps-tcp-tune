# 多协议代理一键部署脚本 v3.1.3

一个简单易用的多协议代理部署脚本，支持 **14 种主流协议**，服务端/客户端一键安装，适用于 Alpine、Debian、Ubuntu、CentOS 等 Linux 发行版。

> 🙏 **声明**：本人只是一个搬运工，脚本灵感来源于网络上的各种优秀项目，特别感谢 [mack-a/v2ray-agent](https://github.com/mack-a/v2ray-agent) 八合一脚本的启发。

---
💬 [Telegram 交流群](https://t.me/+BdstYRZh8GA2ZTFh)

## 🆕 v3.1.3 更新

### 🐛 修复
- 修复删除链式代理节点后，分流规则未同步清理的问题
- 修复删除全部链式代理节点后，导入订阅仍提示"已存在"的问题


---

## ✨ 支持协议

| # | 协议 | 特点 | 推荐场景 |
|---|------|------|----------|
| 1 | **VLESS + Reality** | 抗封锁能力强，无需域名 | 🌟 首选推荐 |
| 2 | **VLESS + Reality + XHTTP** | 多路复用，性能更优 | 高并发场景 |
| 3 | **VLESS + WS + TLS** | CDN 友好，可作回落 | 被墙 IP 救活 |
| 4 | **VMess + WS** | 回落分流/免流 | 端口复用 |
| 5 | **VLESS-XTLS-Vision** | TLS主协议，支持回落 | ⭐ 稳定传输 |
| 6 | **SOCKS5** | 经典代理协议 | 🔥 通用性强 |
| 7 | **Shadowsocks 2022** | 新版加密，性能好 | SS 用户迁移 |
| 8 | **Hysteria2** | UDP 加速，端口跳跃 | 🔥 游戏/视频 |
| 9 | **Trojan** | TLS主协议，支持回落 | ⭐ 伪装 HTTPS |
| 10 | **Snell v4** | Surge 专用协议 (支持 ShadowTLS) | iOS/Mac 用户 |
| 11 | **Snell v5** | Surge 5.0 新版协议 (支持 ShadowTLS) | 最新 Surge |
| 12 | **AnyTLS** | 多协议 TLS 代理 | 抗审查能力强 |
| 13 | **TUIC v5** | QUIC 协议，端口跳跃 | 低延迟 |
| 14 | **NaïveProxy** | HTTP/2 代理，抗检测 | 伪装能力强 |

> 💡 **ShadowTLS 插件**：Snell v4、Snell v5、SS2022 安装时可选择启用 ShadowTLS (v3) 插件，实现 TLS 流量伪装。

### 📊 协议特性对比

| 协议 | 过 CDN | 多路复用 | 可做回落 | 需要域名 | 传输层 |
|------|:------:|:--------:|:--------:|:--------:|:------:|
| VLESS + Reality | ❌ | ❌ | ❌ | ❌ | TCP |
| VLESS + XHTTP | ❌ | ✅ | ❌ | ❌ | HTTP/2 |
| VLESS + WS | ✅ | ❌ | ✅ | ✅ | WebSocket |
| VMess + WS | ✅ | ❌ | ✅ | ✅ | WebSocket |
| VLESS-Vision | ❌ | ❌ | ✅(主) | ✅ | XTLS |
| Trojan | ❌ | ❌ | ✅(主) | ✅ | TLS |
| Hysteria2 | ❌ | ✅ | ❌ | ✅ | QUIC |
| TUIC v5 | ❌ | ✅ | ❌ | ✅ | QUIC |
| AnyTLS | ❌ | ❌ | ❌ | ❌ | TLS |
| ShadowTLS 套壳 | ❌ | ❌ | ❌ | ❌ | TLS 伪装 |

### 🎯 协议选择指南

**抗封锁首选：**
- **VLESS + Reality** - 无需域名，流量特征像正常 TLS，抗封锁能力最强
- **AnyTLS** - 多协议 TLS 代理，抗审查能力强

**被墙 IP 救活：**
- **VLESS + WS + TLS** - 可套 CDN（如 Cloudflare），IP 被墙也能用
- **VMess + WS** - 同样支持 CDN，兼容性好

**高性能传输：**
- **VLESS + XHTTP** - HTTP/2 多路复用，高并发场景性能优异
- **Hysteria2** - QUIC 协议，UDP 加速，游戏/视频体验好
- **TUIC v5** - QUIC 协议，低延迟

**端口复用：**
- **VLESS-Vision / Trojan** - 作为 TLS 主协议监听 443
- **VLESS-WS / VMess-WS** - 作为回落子协议，共享 443 端口

---

## 🚀 快速开始

### 一键安装服务端

```bash
wget -O vless-server.sh https://raw.githubusercontent.com/Chil30/vless-all-in-one/main/vless-server.sh && chmod +x vless-server.sh && bash vless-server.sh
```

### 服务端安装

```bash
vless
# 选择 1) 安装新协议
# 选择协议 (推荐 1-VLESS+Reality)
# 确认安装
```

安装完成后显示：
- **JOIN 码** - 复制给客户端使用
- **分享链接** - 可导入 v2rayN、Clash、小火箭等
- **二维码** - 手机扫码导入
- **订阅链接** - Clash/Surge/V2Ray/Loon 订阅

### 一键安装客户端

```bash
wget -O vless-client.sh https://raw.githubusercontent.com/Chil30/vless-all-in-one/main/vless-client.sh && chmod +x vless-client.sh && bash vless-client.sh
```

### 客户端安装

```bash
vlessc
# 选择 2) 安装客户端 (JOIN码)
# 粘贴服务端的 JOIN 码
# 选择代理模式 (推荐 TUN)
```

---

## 🌐 分流功能 (多出口)

分流功能让你可以为不同网站配置不同的代理出口，实现精细化流量控制。

### 核心概念

```
┌─────────────────────────────────────────────────────────────┐
│                    多出口分流示意图                          │
├─────────────────────────────────────────────────────────────┤
│  用户请求                                                   │
│     │                                                       │
│     ▼                                                       │
│  ┌─────────┐                                                │
│  │  VPS    │                                                │
│  │ (入口)  │                                                │
│  └────┬────┘                                                │
│       │                                                     │
│       ├──── ChatGPT ────→ 🇸🇬 新加坡节点 ────→ OpenAI       │
│       │                                                     │
│       ├──── TikTok  ────→ 🇯🇵 日本节点   ────→ TikTok      │
│       │                                                     │
│       ├──── Netflix ────→ 🇺🇸 美国节点   ────→ Netflix     │
│       │                                                     │
│       └──── 其他    ────→ 直连出口       ────→ 目标网站     │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### 两种出口来源

| 模式 | 说明 | 适用场景 |
|------|------|----------|
| **WARP** | Cloudflare 免费出口 | 免费解锁 |
| **链式代理** | 导入已解锁的节点 | 用自己的解锁机落地 |

### WARP 两种子模式

| 模式 | 协议 | 特点 | 适用场景 |
|------|------|------|----------|
| **WGCF** | UDP/WireGuard | Xray 内置，性能好 | UDP 未被封锁 |
| **官方客户端** | TCP/SOCKS5 | 绕过 UDP 封锁，稳定 | UDP 被封锁环境 |

### 链式代理转发

导入机场订阅或分享链接，用已解锁的节点作为分流出口。

**支持的节点类型：**
- ✅ VMess (含 WS/TLS)
- ✅ VLESS (含 Reality)
- ✅ Shadowsocks
- ✅ Trojan
- ✅ Hysteria2

**使用方法：**
```bash
vless
# 主菜单 → 5) 分流管理 → 3) 链式代理管理
# 1) 添加节点 (粘贴分享链接)
# 2) 导入订阅 (粘贴机场订阅链接)
# 3) 测试所有节点延迟
```

### 智能节点选择

配置分流规则时，自动检测所有节点延迟并按延迟排序：

```
选择出口:
▸ 检测 33 个节点延迟中...
✓ 延迟检测完成

1) [10ms] 🇭🇰Hong Kong 03 (vless) 123.123.123.123
2) [10ms] 🇭🇰Hong Kong 04 (vless) 123.123.123.123
3) [44ms] 🇸🇬Singapore 04 (vless) 123.123.123.123
4) [59ms] 🇯🇵Japan 01 (vless) 123.123.123.123 ← tiktok
...
32) [超时] 🇰🇷Korea 01 (hysteria2) 123.123.123.123
```

---

## � 配置管务理

配置管理功能支持一键备份和恢复所有配置，方便服务器迁移或 IP 更换。

### 功能入口

```bash
vless
# 主菜单 → 6) 配置管理 (导入/导出)
```

### 导出配置

一键备份所有配置到 JSON 文件：
- 所有已安装协议的配置参数
- 分流规则 (WARP/链式代理)
- 链式代理节点列表
- 外部节点配置

备份文件保存在 `/etc/vless-reality/backup/` 目录。

### 导入配置

支持两种导入方式：
- **全部导入** - 恢复所有配置
- **选择性导入** - 只导入协议配置 / 分流规则 / 外部节点

### 自动检测更换 IP

服务器 IP 变化后，自动更新所有配置中的 IP 地址：
- 检测当前服务器 IPv4/IPv6
- 更新数据库中的 IP 记录
- 重新生成订阅文件
- 重新生成 JOIN 码

---

## 📡 订阅服务

### 订阅链接格式

安装需要证书的协议 (VLESS-Vision/VLESS-WS/Trojan) 后，自动生成订阅链接：

```
https://你的域名:8443/sub/随机UUID/clash   # Clash/Clash Verge
https://你的域名:8443/sub/随机UUID/surge   # Surge
https://你的域名:8443/sub/随机UUID/v2ray   # V2Ray/通用
```

### 订阅特性

- ✅ 自动包含所有已安装协议
- ✅ 安装/卸载协议后自动更新
- ✅ HTTPS 加密传输
- ✅ 伪装网页，访问根路径显示正常网站
- ✅ 随机 UUID 路径，防止被扫描
- ✅ 外部节点管理，多机聚合订阅

---

## 🔌 端口复用说明

### 工作原理

```
客户端 → 443 端口 → VLESS-Vision/Trojan (TLS主协议)
                              ↓ 回落
                         VLESS-WS (子协议，监听 127.0.0.1)
                         VMess-WS (子协议，监听 127.0.0.1)
```

### 使用方法

1. **先安装 TLS 主协议** (VLESS-Vision 或 Trojan)
2. **再安装回落子协议** (VLESS-WS 或 VMess-WS)
3. 子协议自动识别为回落模式，推荐随机内部端口
4. 订阅链接自动使用 443 端口

### 优势

- 🔒 只需开放 443 端口，防火墙配置简单
- 🎭 流量特征像正常 HTTPS 网站
- 📱 多协议共用一个端口，客户端配置简单

---

## ⚡ 端口跳跃 (Hysteria2 / TUIC)

### 什么是端口跳跃

端口跳跃 (Port Hopping) 是 Hysteria2 和 TUIC 的抗封锁特性：
- 服务端用 iptables 将一段端口范围（如 20000-50000）转发到实际监听端口
- 客户端在这个范围内随机切换端口连接
- 流量分散在多个端口，更难被识别和封锁

### 工作原理

```
客户端 → 随机端口 (20000-50000) → iptables NAT → Hysteria2/TUIC (实际端口)
         ↓ 定时切换
客户端 → 另一个随机端口 → iptables NAT → Hysteria2/TUIC (实际端口)
```

### 安装时配置

```
端口跳跃(Port Hopping)
说明：会将一段 UDP 端口范围重定向到 15999
是否启用端口跳跃? [y/N]: y
起始端口 [回车默认 20000]: 
结束端口 [回车默认 50000]: 
```

### 客户端配置

启用端口跳跃后，需要手动修改客户端端口为范围格式：
- 原端口：`15999`
- 改为：`20000-50000`

### 客户端支持情况

| 客户端 | 支持端口范围 |
|--------|-------------|
| Shadowrocket | ✅ |
| Stash | ✅ |
| Surge | ✅ |
| Clash Meta | ✅ |
| NekoBox | ✅ |
| V2RayN/NG | ✅ |

---

## 🔐 DNS-01 证书验证

支持 NAT 机器无 80 端口申请证书：

- Cloudflare DNS 验证
- 阿里云 DNS 验证
- DNSPod (腾讯云) DNS 验证
- 手动 DNS 验证 (适合任何 DNS 服务商)

---

## 🖥️ 界面预览

### 主菜单
```
═════════════════════════════════════════════
      多协议代理 一键部署 v3.1.3 [服务端]
      作者: Chil30  快捷命令: vless
      https://github.com/Chil30/vless-all-in-one
═════════════════════════════════════════════
  服务端管理
  系统: ubuntu | 架构: Xray+Sing-box 双核
  状态: ● 运行中
  协议: VLESS+Reality, Hysteria2
  端口: 10999, 15999
  分流: 3条规则→Japan+04+Amazon
─────────────────────────────────────────────
  1) 安装新协议 (多协议共存)
  2) 查看所有协议配置
  3) 订阅服务管理
  4) 管理协议服务
  5) 分流管理
  6) 配置管理 (导入/导出)
  7) BBR 网络优化
  8) 卸载指定协议
  9) 完全卸载
  l) 查看运行日志
  u) 检查更新
  0) 退出
─────────────────────────────────────────────
```

### 导入订阅 (延迟预览)
```
═════════════════════════════════════════════
  导入订阅
─────────────────────────────────────────────
  输入订阅链接:
  URL: https://example.com/api/v1/subscribe

  ▸ 获取订阅内容...
─────────────────────────────────────────────
  ✓ 解析成功，共 22 个节点
─────────────────────────────────────────────
  协议统计:
    • vless: 22 个

  ▸ 检测节点延迟中...
  ▸ 检测中... (22/22)

  节点列表 (按延迟排序):
─────────────────────────────────────────────
  [8ms] 🇯🇵日本高速06 (BGP) (vless) 123.123.123.123
  [9ms] 🇭🇰香港高速03 (BGP) (vless) 123.123.123.123
  [10ms] 🇭🇰香港高速04 (BGP) (vless) 123.123.123.123
  [38ms] 🇸🇬新加坡高速01 (BGP) (vless) 123.123.123.123
  [56ms] 🇯🇵日本高速01 (BGP) (vless) 123.123.123.123
  [147ms] 🇺🇸美国高速01 (vless) 123.123.123.123
  [223ms] v6节点 (shadowsocks) 2a0f:7803::1
  [超时] 🇰🇷韩国高速01 (BGP) (vless) -
─────────────────────────────────────────────
  确认导入这 22 个节点? [Y/n]:
```

### 分流管理菜单
```
═════════════════════════════════════════════
  分流管理
─────────────────────────────────────────────
  WARP: ● 已启用 (WGCF模式)
  链式代理: 38 个节点
  分流规则: 4 条
─────────────────────────────────────────────
  1) WARP 管理
  2) 链式代理
  3) 快速配置代理出口
  4) 配置分流规则
  5) 测试分流效果
  6) 查看当前配置
  0) 返回主菜单
─────────────────────────────────────────────
```

### 链式代理管理
```
═════════════════════════════════════════════
  链式代理管理
─────────────────────────────────────────────
  状态: ● 分流已配置 (4 条规则)
  使用节点:
    • 🇯🇵Japan+04+Amazon ← tiktok
    • 🇸🇬Singapore+02+Amazon ← openai
    • 🇹🇼Taiwan+01+Hinet ← custom
    • 🇭🇰Hong+Kong+Telecom+04 ← telegram
  节点总数: 38
─────────────────────────────────────────────
  1) 添加节点 (分享链接)
  2) 导入订阅
  3) 测试所有节点延迟
  4) 删除节点
  5) 禁用链式代理
  0) 返回
─────────────────────────────────────────────
```

### 测试节点延迟
```
═════════════════════════════════════════════
  测试节点延迟 (TCP连接延迟，仅供参考)
─────────────────────────────────────────────
  ▸ 检测 23 个节点延迟中...
  ▸ 检测中... (23/23)
  ✓ 延迟检测完成 (23 个节点)

  TCP延迟排序 (从低到高):
─────────────────────────────────────────────
  [9ms] 🇭🇰香港高速01 (vless) 123.123.123.123
  [10ms] 🇯🇵日本高速02 (vless) 123.123.123.123
  [223ms] v6节点 (shadowsocks) 2a0f:7803:
  [超时] ��台湾台湾高速01 (BGP) (vless) -
─────────────────────────────────────────────
```

### 订阅服务管理菜单
```
═════════════════════════════════════════════
  订阅服务管理
─────────────────────────────────────────────
  状态: 已配置
  端口: 8443
  域名: example.com
  HTTPS: true

  1) 查看订阅链接
  2) 更新订阅内容
  3) 外部节点管理
  4) 重新配置
  5) 停用订阅服务
  0) 返回
─────────────────────────────────────────────
```

---

## 📱 客户端推荐

| 平台 | 推荐客户端 | 订阅支持 |
|------|-----------|----------|
| **Windows** | [Clash Verge Rev](https://github.com/clash-verge-rev/clash-verge-rev) | ✅ Clash 订阅 |
| **Windows** | [V2rayN](https://github.com/2dust/v2rayN) | ✅ V2Ray 订阅 |
| **macOS** | [Clash Verge Rev](https://github.com/clash-verge-rev/clash-verge-rev) | ✅ Clash 订阅 |
| **macOS** | [Surge](https://nssurge.com/) | ✅ Surge 订阅 |
| **iOS** | [Shadowrocket](https://apps.apple.com/app/shadowrocket/id932747118) | ✅ 通用订阅 |
| **iOS** | [Surge](https://apps.apple.com/app/surge-5/id1442620678) | ✅ Surge 订阅 |
| **Android** | [Clash Meta](https://github.com/MetaCubeX/ClashMetaForAndroid) | ✅ Clash 订阅 |
| **Android** | [V2rayNG](https://github.com/2dust/v2rayNG) | ✅ V2Ray 订阅 |

---

## 🔧 代理模式说明 (客户端)

### 1️⃣ TUN 网卡模式 (推荐)
```
创建虚拟网卡 tun0，修改系统路由表
✅ 全局透明代理，所有应用自动走代理
✅ 支持 TCP/UDP
❌ LXC 容器可能不支持
```

### 2️⃣ 全局代理模式 (iptables)
```
使用 iptables 劫持流量
✅ 兼容性好
✅ 支持纯 IPv6 + WARP 环境
❌ 仅代理 TCP 流量
```

### 3️⃣ SOCKS5 模式
```
仅启动 SOCKS5 代理 (127.0.0.1:10808)
✅ 无需特殊权限，兼容性最好
❌ 需要手动配置应用使用代理
```

---

## 📋 系统要求

### 支持的系统
- Debian 9+ / Ubuntu 18.04+
- CentOS 7+ 
- Alpine Linux 3.12+

### 架构支持
- x86_64 (amd64)
- ARM64 (aarch64)

### WARP 官方客户端限制
- ❌ Alpine Linux 不支持（依赖 glibc）
- ✅ Debian/Ubuntu/CentOS 支持

---

## ❓ 常见问题

### Q: 订阅链接返回 404
- 检查 Nginx 是否运行：`ss -tlnp | grep 8443`
- 检查订阅文件是否存在：`ls /etc/vless-reality/subscription/`
- 重新配置订阅：主菜单 → 订阅管理 → 重新配置

### Q: Clash 订阅导入后部分协议超时
- 检查是否为回落子协议，确认使用 443 端口
- 更新订阅文件：主菜单 → 订阅管理 → 刷新订阅内容

### Q: 安装失败，提示依赖安装失败
```bash
# Debian/Ubuntu
apt update && apt install -y curl jq unzip iproute2 nginx

# CentOS
yum install -y curl jq unzip iproute nginx

# Alpine
apk add curl jq unzip iproute2 nginx
```

### Q: TUN 模式启动失败
- LXC 容器不支持 TUN，请使用全局代理或 SOCKS5 模式
- 检查 TUN 模块：`ls -la /dev/net/tun`

### Q: Hysteria2/TUIC 端口跳跃不生效
- 检查 iptables 规则：`iptables -t nat -L PREROUTING -n | grep REDIRECT`
- NAT 机器不支持端口跳跃（服务商只给固定端口）

### Q: WARP 官方客户端注册失败
- 确保系统不是 Alpine（不支持官方客户端）
- 检查 warp-svc 服务：`systemctl status warp-svc`

### Q: WARP 分流不生效
- 检查 WARP 状态：分流管理 → WARP 管理 → 测试连接
- 确认分流规则已配置：分流管理 → 查看当前配置

---

## 📁 文件位置

```
/etc/vless-reality/
├── config.json           # Xray 主配置文件
├── singbox.json          # Sing-box 配置文件
├── db.json               # JSON 数据库 (协议配置、分流规则)
├── warp.json             # WGCF 配置文件
├── sub.info              # 订阅服务配置
├── subscription/         # 订阅文件目录
│   └── {uuid}/
│       ├── clash.yaml
│       ├── surge.conf
│       └── base64
├── certs/                # 证书目录
└── ...
```

---

## 🙏 致谢

### 灵感来源
- [mack-a/v2ray-agent](https://github.com/mack-a/v2ray-agent) - 八合一共存脚本

### 核心组件
- [XTLS/Xray-core](https://github.com/XTLS/Xray-core) - 代理核心引擎
- [SagerNet/sing-box](https://github.com/SagerNet/sing-box) - Sing-box 核心
- [apernet/hysteria](https://github.com/apernet/hysteria) - Hysteria2 协议
- [EAimTY/tuic](https://github.com/EAimTY/tuic) - TUIC 协议
- [ihciah/shadow-tls](https://github.com/ihciah/shadow-tls) - ShadowTLS 协议
- [ViRb3/wgcf](https://github.com/ViRb3/wgcf) - WARP WireGuard 配置生成

---

## ⚠️ 免责声明

- 本脚本仅供学习交流使用
- 作者不对使用本脚本造成的任何后果负责

---

## 📄 许可证

MIT License

---

**⭐ 如果觉得有用，欢迎 Star！**
