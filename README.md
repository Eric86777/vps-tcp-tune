# BBR v3 终极优化脚本 - Ultimate Edition

🚀 **XanMod 内核 + BBR v3 + 全方位 VPS 管理工具集**
一键安装 XanMod 内核，启用 BBR v3 拥塞控制，集成 25+ 实用工具，全面优化你的 VPS 服务器。

> **版本**: 2.3 (Smart Edition)
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

### ✨ 八大功能模块

1. **🔧 内核管理**
   - XanMod 内核安装/更新/卸载
   - 支持 x86_64 & ARM64 架构
   - 自动检测 CPU 最优版本（v2/v3/v4）

2. **⚡ BBR v3 智能配置**
   - 快速启用 BBR + FQ（≤1GB 内存）+ 智能SWAP检测
   - 快速启用 BBR + FQ（2GB+ 内存）+ 智能SWAP检测
   - 自动检测内存并建议SWAP配置
   - 一键式完整优化流程（5步走）

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

8. **⚙️ 系统优化**
   - Linux 系统内核参数优化
   - 6种优化模式（高性能/均衡/网站/直播/游戏服/还原）
   - 文件描述符、虚拟内存、网络设置全方位优化

---

## 📋 完整功能列表

### [内核管理]
1. 安装 XanMod 内核 + BBR v3
   - *已安装时选项 1 变为"更新 XanMod 内核"*
   - *已安装时选项 2 变为"卸载 XanMod 内核"*

### [BBR TCP调优]
2. 快速启用 BBR + FQ（≤1GB 内存）+ 智能SWAP检测
3. 快速启用 BBR + FQ（2GB+ 内存）+ 智能SWAP检测
   - **新特性**: 执行前自动检测内存并建议SWAP配置
   - **智能判断**: 小内存机器会询问是否配置SWAP
   - **5步流程**: SWAP检测 → 冲突清理 → 配置创建 → 应用参数 → 验证

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

### [系统优化]
25. Linux系统内核参数优化
   - 高性能优化模式
   - 均衡优化模式
   - 网站优化模式
   - 直播优化模式
   - 游戏服优化模式
   - 还原默认设置

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

### 第三步：配置 BBR（v2.3 智能SWAP集成版）

重启后再次运行脚本：

```bash
bash <(wget -qO- https://raw.githubusercontent.com/Eric86777/vps-tcp-tune/main/net-tcp-tune.sh)
```

**推荐配置：**
- 选项 **2**：BBR + FQ（≤1GB 内存）+ 🧠智能SWAP检测
  - 16MB 缓冲区，85KB 默认值
  - 19个优化参数（含精华参数）
  - **新增**: 执行前智能检测SWAP
- 选项 **3**：BBR + FQ（2GB+ 内存）+ 🧠智能SWAP检测
  - 32MB 缓冲区，256KB 默认值
  - 23个优化参数（含精华参数）
  - **新增**: 执行前智能检测SWAP

#### 🎯 智能SWAP检测（v2.3新特性）

执行BBR配置时，脚本会自动：

**📋 5步执行流程**
1. **检测虚拟内存** → 分析内存大小并建议SWAP配置
2. **清理冲突** → 备份并清理旧配置
3. **创建配置** → 生成优化参数文件
4. **应用参数** → 立即生效所有优化
5. **验证配置** → 确认配置成功

**🧠 智能判断逻辑**

| 物理内存 | 是否询问 | 推荐SWAP | 说明 |
|---------|---------|---------|------|
| < 512MB | ✅ 是 | 1GB（固定） | 内存极小，必须配置 |
| 512MB-1GB | ✅ 是 | 内存 × 2 | 小内存，强烈建议 |
| 1-2GB | ✅ 是 | 内存 × 1.5 | 适中内存，建议配置 |
| 2-4GB | ✅ 是（无SWAP时） | 内存 × 1 | 充足内存，可选配置 |
| ≥ 4GB | ❌ 跳过 | 无需 | 内存充裕，自动跳过 |

**💬 操作示例（1GB内存机器）**
```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
检测到虚拟内存（SWAP）需要优化
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  物理内存:       1024MB
  当前 SWAP:      0MB
  推荐 SWAP:      2048MB
  
原因: 1-2GB内存建议配置SWAP，提供缓冲空间
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
是否现在配置虚拟内存？(Y/N): Y  ← 输入Y确认配置
```

**📊 你的服务器推荐**
- **DMIT洛杉矶 1c1g** → 输入 `Y`，配置2GB SWAP
- **西雅图Misaka 1c1g** → 输入 `Y`，配置2GB SWAP
- **日本软银 4c8g** → 自动跳过（内存充足）
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

## ⚙️ 系统内核参数优化

### Linux 系统内核参数优化（选项 25）

提供多种系统参数调优模式，用户可以根据自身使用场景进行选择切换。

**⚠️ 提示：生产环境请谨慎使用！**

### 6种优化模式

#### 1. 高性能优化模式
- **适用场景**：高负载生产环境，追求最大性能
- **优化内容**：
  - 文件描述符：65535
  - 虚拟内存：swappiness=10，优化内存管理
  - 网络设置：BBR拥塞控制 + 16MB缓冲区
  - 缓存管理：减少缓存压力
  - CPU设置：禁用自动分组调度
  - 其他优化：禁用透明大页面、NUMA balancing

#### 2. 均衡优化模式
- **适用场景**：日常使用，性能与资源消耗平衡
- **优化内容**：
  - 文件描述符：32768
  - 虚拟内存：swappiness=30
  - 网络设置：BBR拥塞控制 + 8MB缓冲区
  - 适中的资源配置

#### 3. 网站优化模式
- **适用场景**：Web服务器、网站托管
- **优化内容**：
  - 高并发连接处理能力
  - 提高响应速度
  - 优化网络队列和连接数

#### 4. 直播优化模式
- **适用场景**：直播推流服务器
- **优化内容**：
  - 减少网络延迟
  - 提高传输性能
  - 优化实时数据传输

#### 5. 游戏服优化模式
- **适用场景**：游戏服务器
- **优化内容**：
  - 提高并发处理能力
  - 降低响应延迟
  - 优化网络包处理

#### 6. 还原默认设置
- 将所有系统参数还原为系统默认配置
- 取消所有自定义优化

### 优化参数说明

| 参数类型 | 高性能模式 | 均衡模式 | 默认值 |
|---------|-----------|---------|--------|
| 文件描述符 | 65535 | 32768 | 1024 |
| vm.swappiness | 10 | 30 | 60 |
| TCP缓冲区 | 16MB | 8MB | 6MB |
| 拥塞控制 | BBR | BBR | cubic |
| 连接队列 | 4096 | 2048 | 128 |

### 注意事项

1. **临时生效**：优化参数在重启后会失效
2. **持久化配置**：如需永久生效，需要写入 `/etc/sysctl.conf`
3. **root权限**：所有优化操作都需要 root 权限
4. **内核支持**：部分参数（如BBR）需要内核支持
5. **谨慎使用**：生产环境请先在测试环境验证

---

## 🔧 配置文件说明

脚本生成的配置文件位于：

```
/etc/sysctl.d/99-bbr-ultimate.conf
```

### ≤1GB 内存版本配置（增强版）

```bash
# BBR v3 Ultimate Configuration (Enhanced Edition)
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

# ===== 精华参数优化（1GB内存版）=====

# TIME_WAIT 重用（高并发必备）
net.ipv4.tcp_tw_reuse=1

# 端口范围扩大（代理/转发必备）
net.ipv4.ip_local_port_range=1024 65535

# 连接队列增大（Web服务器必备）
net.core.somaxconn=4096

# 虚拟内存优化（1GB内存优化）
vm.swappiness=20
vm.dirty_ratio=20
vm.dirty_background_ratio=5
vm.overcommit_memory=1
vm.min_free_kbytes=32768
vm.vfs_cache_pressure=50

# CPU调度优化
kernel.sched_autogroup_enabled=0
kernel.numa_balancing=0

# 文件描述符（/etc/security/limits.conf）
* soft nofile 65535
* hard nofile 65535

# 透明大页面禁用
echo never > /sys/kernel/mm/transparent_hugepage/enabled
```

### 2GB+ 内存版本配置（增强版）

```bash
# BBR v3 Ultimate Configuration (2GB+ Memory - Enhanced Edition)
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

# ===== 精华参数优化（完整版）=====

# TIME_WAIT 重用（高并发必备）
net.ipv4.tcp_tw_reuse=1

# 端口范围扩大（代理/转发必备）
net.ipv4.ip_local_port_range=1024 65535

# 连接队列增大（Web服务器必备）
net.core.somaxconn=4096

# 虚拟内存优化（2GB+完整版）
vm.swappiness=10
vm.dirty_ratio=15
vm.dirty_background_ratio=5
vm.overcommit_memory=1
vm.min_free_kbytes=65536
vm.vfs_cache_pressure=50

# CPU调度优化
kernel.sched_autogroup_enabled=0
kernel.numa_balancing=0

# 文件描述符（/etc/security/limits.conf）
* soft nofile 65535
* hard nofile 65535

# 透明大页面禁用
echo never > /sys/kernel/mm/transparent_hugepage/enabled
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

### v2.3 (2025-01-10)
- ✅ **BBR TCP调优智能版**
  - **智能SWAP集成**: 选项2/3 现在包含自动SWAP检测
  - 自动分析物理内存大小，智能推荐SWAP配置
  - **触发条件**:
    - 物理内存 < 2GB：强烈建议配置SWAP
    - 2-4GB且无SWAP：建议配置少量SWAP
    - ≥4GB：通常无需SWAP，跳过检测
  - **智能计算规则**:
    - < 512MB: 固定1GB
    - 512MB-1GB: 2倍内存
    - 1-2GB: 1.5倍内存
    - 2-4GB: 与内存同大小
    - ≥4GB: 固定4GB
  - **用户友好**: 询问确认后才配置，可跳过（Y/N）
  - **执行流程优化**: 5步式清晰流程
    1. 检测虚拟内存（SWAP）
    2. 清理配置冲突
    3. 创建配置文件
    4. 应用所有优化参数
    5. 验证配置

### v2.2 (2025-01-10)
- ✅ **BBR TCP调优增强版**
  - 选项2/3 集成精华参数优化
  - TIME_WAIT重用（高并发场景必备）
  - 端口范围扩大至64511（代理/转发必备）
  - 连接队列增至4096（突发流量不丢连接）
  - 文件描述符扩大至65535
  - 虚拟内存优化（减少IO延迟）
  - CPU调度优化（提升响应速度）
  - 透明大页面禁用（减少延迟抖动）
  - **选项2**: 从6个参数增加到19个参数
  - **选项3**: 从10个参数增加到23个参数

### v2.1 (2025-01-10)
- ✅ 新增系统信息查询功能（增强版）
  - CPU详情（架构、型号、核心数、频率、实时占用率）
  - 内存使用（物理+虚拟内存）
  - 网络流量统计（总接收/总发送）
  - 地理位置、运营商信息
  - 系统运行时长
- ✅ 新增Linux系统内核参数优化功能
  - 6种优化模式（高性能/均衡/网站/直播/游戏服/还原）
  - 全方位系统参数调优
  - 文件描述符、虚拟内存、网络设置优化
  - CPU、缓存管理优化
- ✅ 总计 25 项实用功能

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
