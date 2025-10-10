# BBR v3 终极优化脚本 - Ultimate Edition

🚀 **XanMod 内核 + BBR v3 + 全方位 VPS 管理工具集**
一键安装 XanMod 内核，启用 BBR v3 拥塞控制，集成 24+ 实用工具，全面优化你的 VPS 服务器。

> **版本**: 2.0 Ultimate Edition
> **视频教程**: [B站教程](https://www.bilibili.com/video/BV14K421x7BS)

---

## 🚀 一键安装（推荐）

### 远程运行最新版（无需下载）

```bash
bash <(wget -qO- https://raw.githubusercontent.com/Eric86777/vps-tcp-tune/main/net-tcp-tune.sh)
```

**优点**:
- ✅ 最简洁，只需一行命令
- ✅ 每次都运行最新版
- ✅ 不产生本地文件

---

## 🌟 核心特性

### ✨ 七大功能模块

1. **🔧 内核管理**
   - XanMod 内核安装/更新/卸载
   - 支持 x86_64 & ARM64 架构
   - 自动检测 CPU 最优版本（v2/v3/v4）

2. **⚡ BBR v3 配置**
   - 快速启用 BBR + FQ（≤1GB 内存）
   - 快速启用 BBR + FQ（2GB+ 内存）
   - 自动优化 TCP 缓冲区

3. **🛠️ 系统设置**
   - 虚拟内存管理（智能计算推荐值）
   - IPv4/IPv6 优先级设置
   - 出口 IP 地址查看

4. **🔐 Xray 配置**
   - 查看 Xray 配置
   - 设置 Xray IPv6 出站
   - 恢复 Xray 默认配置

5. **📊 网络测试**
   - 服务器带宽测试（Speedtest）
   - 三网回程路由测试
   - IP 质量检测（IPv4/IPv6）
   - 网络延迟质量检测
   - 国际互联速度测试

6. **🎯 流媒体/解锁检测**
   - IP 媒体/AI 解锁检测
   - NS 一键检测脚本

7. **🔌 第三方工具集成**
   - PF_realm 转发脚本
   - 酷雪云脚本
   - 御坂美琴一键双协议
   - NS 论坛 cake 调优
   - 科技lion 脚本
   - F佬一键 sing-box 脚本

---

## 📋 完整功能列表

### [内核管理]
1. 安装 XanMod 内核 + BBR v3
   - *已安装时选项 1 变为"更新 XanMod 内核"*
   - *已安装时选项 2 变为"卸载 XanMod 内核"*

### [BBR TCP调优]
2. 快速启用 BBR + FQ（≤1GB 内存）
3. 快速启用 BBR + FQ（2GB+ 内存）

### [系统设置]
4. 虚拟内存管理
   - 分配 1024M (1GB)
   - 分配 2048M (2GB)
   - 分配 4096M (4GB)
   - 智能计算推荐值
5. 设置 IPv4 优先
6. 设置 IPv6 优先

### [Xray配置]
7. 查看 Xray 配置
8. 设置 Xray IPv6 出站
9. 恢复 Xray 默认配置

### [系统信息]
10. 查看详细状态

### [服务器检测合集]
11. NS一键检测脚本
12. 服务器带宽测试
13. 三网回程路由测试
14. IP质量检测
15. IP质量检测-仅IPv4
16. 网络延迟质量检测
17. 国际互联速度测试
18. IP媒体/AI解锁检测

### [脚本合集]
19. PF_realm转发脚本
20. 御坂美琴一键双协议
21. NS论坛的cake调优
22. 酷雪云脚本
23. 科技lion脚本
24. F佬一键sing box脚本

---

## 📋 支持系统

| 系统 | 架构 | 支持状态 |
|------|------|---------|
| **Debian 10+** | x86_64 | ✅ 完整支持 |
| **Ubuntu 20.04+** | x86_64 | ✅ 完整支持 |
| **Debian/Ubuntu** | ARM64 | ✅ 专用脚本 |
| 其他发行版 | - | ❌ 不支持 |

---

## 🛠️ 使用流程

### 第一步：运行脚本

```bash
bash <(wget -qO- https://raw.githubusercontent.com/Eric86777/vps-tcp-tune/main/net-tcp-tune.sh)
```

### 第二步：安装 XanMod 内核

- 选择菜单选项 **1**
- 脚本会自动：
  - ✅ 检测 CPU 架构（x86-64-v2/v3/v4 自动适配）
  - ✅ 添加 XanMod 官方仓库
  - ✅ 安装对应内核版本
  - ✅ 检查磁盘空间（需要 3GB+）
  - ✅ 创建 SWAP（如无虚拟内存）

⚠️ **安装完成后必须重启系统！**

### 第三步：配置 BBR

重启后再次运行脚本：

```bash
bash <(wget -qO- https://raw.githubusercontent.com/Eric86777/vps-tcp-tune/main/net-tcp-tune.sh)
```

**推荐配置：**
- 选项 **2**：BBR + FQ（≤1GB 内存）
  - 16MB 缓冲区，85KB 默认值
- 选项 **3**：BBR + FQ（2GB+ 内存）
  - 32MB 缓冲区，256KB 默认值
  - 额外高级优化（禁用慢启动、MTU探测等）

---

## 📊 验证配置

### 检查 BBR 状态

```bash
# 查看拥塞控制算法
sysctl net.ipv4.tcp_congestion_control

# 查看队列算法
sysctl net.core.default_qdisc

# 验证 BBR 版本
modinfo tcp_bbr | grep version
```

### 预期输出

```
net.ipv4.tcp_congestion_control = bbr
net.core.default_qdisc = fq
version:        3
```

---

## 🔧 虚拟内存智能计算

脚本提供智能 SWAP 计算功能（菜单选项 **4** → **4**），根据物理内存自动推荐：

| 物理内存 | 推荐 SWAP | 计算公式 |
|---------|-----------|---------|
| < 512MB | 1GB（固定） | 固定值 |
| 512MB - 1GB | 内存 × 2 | 例：512MB → 1GB SWAP |
| 1GB - 2GB | 内存 × 1.5 | 例：1GB → 1.5GB SWAP |
| 2GB - 4GB | 内存 × 1 | 例：2GB → 2GB SWAP |
| 4GB - 8GB | 4GB（固定） | 固定值 |
| ≥ 8GB | 4GB（固定） | 固定值 |

---

## 🌐 IPv4/IPv6 优先级设置

### 设置 IPv4 优先（选项 5）
- 修改 `/etc/gai.conf` 配置
- 启用 IPv4 优先解析
- 自动显示当前出口 IP

### 设置 IPv6 优先（选项 6）
- 修改 `/etc/gai.conf` 配置
- 禁用 IPv4 优先（即 IPv6 优先）
- 自动显示当前出口 IP

---

## 🔐 Xray 配置管理

### 查看配置（选项 7）
- 显示 `/usr/local/etc/xray/config.json` 完整内容

### IPv6 出站（选项 8）
- 自动备份当前配置
- 使用 `jq` 修改为 IPv6 出站
- 测试配置有效性
- 失败自动回滚

### 恢复默认（选项 9）
- 恢复双栈模式（IPv4/IPv6）
- 自动备份和测试

---

## 📊 网络测试工具

### 服务器带宽测试（选项 12）
- 自动检测系统架构（x86_64/ARM64）
- 下载并安装 Speedtest CLI
- 运行完整带宽测试

### 三网回程路由测试（选项 13）
- 测试电信/联通/移动回程路由
- 显示完整路由追踪

### IP 质量检测（选项 14/15）
- 完整检测：IPv4 + IPv6
- 仅 IPv4 检测

### 网络延迟质量检测（选项 16）
- 测试到全球多个节点的延迟
- 评估网络质量

### 国际互联速度测试（选项 17）
- 测试国际互联带宽
- 下载 latency.sh 脚本执行

---

## 🎯 流媒体解锁检测

### IP 媒体/AI 解锁检测（选项 18）
- 检测 Netflix、Disney+、HBO 等流媒体
- 检测 OpenAI、Claude 等 AI 服务
- 显示解锁状态

---

## 🔌 第三方工具集成

### PF_realm 转发脚本（选项 19）
- 高性能端口转发工具
- 支持 TCP/UDP

### 御坂美琴一键双协议（选项 20）
- Xray 双协议一键安装

### NS 论坛 cake 调优（选项 21）
- CAKE 队列算法优化脚本

### 酷雪云脚本（选项 22）
- 酷雪云官方工具集

### 科技lion 脚本（选项 23）
- 综合 VPS 管理工具

### F佬一键 sing-box 脚本（选项 24）
- sing-box 一键安装配置

---

## 🔧 配置文件说明

脚本生成的配置文件位于：

```
/etc/sysctl.d/99-bbr-ultimate.conf
```

### ≤1GB 内存版本配置

```bash
# BBR v3 Ultimate Configuration
# Generated on 2025-01-10

# 队列调度算法
net.core.default_qdisc=fq

# 拥塞控制算法
net.ipv4.tcp_congestion_control=bbr

# TCP 缓冲区优化（16MB 上限，适合小内存 VPS）
net.core.rmem_max=16777216
net.core.wmem_max=16777216
net.ipv4.tcp_rmem=4096 87380 16777216
net.ipv4.tcp_wmem=4096 65536 16777216
```

### 2GB+ 内存版本配置

```bash
# BBR v3 Ultimate Configuration (2GB+ Memory)
# Generated on 2025-01-10

# 队列调度算法
net.core.default_qdisc=fq

# 拥塞控制算法
net.ipv4.tcp_congestion_control=bbr

# TCP 缓冲区优化（32MB 上限，256KB 默认值）
net.core.rmem_max=33554432
net.core.wmem_max=33554432
net.ipv4.tcp_rmem=4096 262144 33554432
net.ipv4.tcp_wmem=4096 262144 33554432

# 高级优化（适合高带宽场景）
net.ipv4.tcp_slow_start_after_idle=0
net.ipv4.tcp_mtu_probing=1
net.core.netdev_max_backlog=16384
net.ipv4.tcp_max_syn_backlog=8192
```

---

## 🗑️ 卸载说明

### 卸载 XanMod 内核

```bash
# 运行脚本
bash <(wget -qO- https://raw.githubusercontent.com/Eric86777/vps-tcp-tune/main/net-tcp-tune.sh)

# 选择菜单选项 2（仅在已安装 XanMod 后显示）
```

脚本会自动：
- 移除所有 XanMod 内核包
- 删除配置文件 `/etc/sysctl.d/99-bbr-ultimate.conf`
- 更新 GRUB 引导
- 询问是否重启

---

## ⚠️ 注意事项

1. **磁盘空间**：确保根分区至少有 3GB 可用空间
2. **内存要求**：低内存 VPS 会自动创建 1GB SWAP
3. **备份建议**：升级内核前建议备份重要数据
4. **重启需求**：内核升级后必须重启才能生效
5. **兼容性**：仅支持 Debian/Ubuntu，不支持 CentOS/RHEL
6. **root 权限**：所有操作都需要 root 权限

---

## 💬 常见问题

### Q: 为什么推荐用远程运行而不是下载？
A: 远程运行每次都是最新版，避免使用缓存的旧版本，一行命令更简洁。

### Q: BBR v3 和 BBR v2 有什么区别？
A: BBR v3 改进了拥塞窗口计算，减少了丢包，提升了跨国高延迟链路的性能。

### Q: ARM 服务器能用吗？
A: 可以，脚本会自动检测 ARM64 架构并调用专用安装脚本。

### Q: 虚拟内存（SWAP）应该设置多大？
A: 使用脚本的智能计算功能（菜单选项 **4** → **4**），会根据物理内存自动推荐最佳大小。

### Q: 安装失败怎么办？
A: 检查：
- 磁盘空间是否充足（≥3GB）
- 网络连接是否正常
- 系统是否为 Debian/Ubuntu
- 尝试更换软件源

### Q: Xray 配置修改后无法连接？
A: 使用菜单选项 **9** 恢复默认配置，或检查备份文件：
```bash
ls -la /usr/local/etc/xray/config.json.bak.*
```

---

## 🤝 参考资料

- **XanMod 官网**: [https://xanmod.org/](https://xanmod.org/)
- **BBR v3 论文**: [Google BBR v3](https://github.com/google/bbr)
- **FQ 文档**: [Fair Queue](https://www.kernel.org/doc/html/latest/networking/fq.html)
- **Xray 文档**: [https://xtls.github.io/](https://xtls.github.io/)

---

## 🌐 相关链接

- **GitHub**: [https://github.com/Eric86777/vps-tcp-tune](https://github.com/Eric86777/vps-tcp-tune)
- **问题反馈**: [Issues](https://github.com/Eric86777/vps-tcp-tune/issues)
- **视频教程**: [B站](https://www.bilibili.com/video/BV14K421x7BS)

---

## 📄 License

MIT

---

## 📝 更新日志

### v2.0 Ultimate Edition (2025-01-10)
- ✅ 新增一键远程运行方式
- ✅ 集成 IPv4/IPv6 优先级设置
- ✅ 集成 Xray 配置管理（查看/IPv6出站/恢复默认）
- ✅ 集成虚拟内存智能计算
- ✅ 集成 8 大网络测试工具
- ✅ 集成流媒体/AI 解锁检测
- ✅ 集成 6 大第三方工具脚本
- ✅ 优化配置冲突检测与清理
- ✅ 新增立即生效功能（tc fq + MSS clamp）
- ✅ 完善错误处理和回滚机制
- ✅ 总计 24 项实用功能

---

**⭐ 如果这个脚本对你有帮助，欢迎 Star！**
