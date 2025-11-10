# DNS净化与安全加固脚本 - 智能修复版

## 📋 功能说明

这个脚本会自动：
1. ✅ 检测 `systemd-resolved` 是否被屏蔽 (masked)
2. ✅ 如果被屏蔽，自动解除并修复
3. ✅ 配置 DNS over TLS (DoT) + DNSSEC
4. ✅ 清除所有DNS冲突源（dhclient、resolvconf等）
5. ✅ 使用 Google DNS (8.8.8.8) + Cloudflare DNS (1.1.1.1)

## 🚀 快速使用

### 方法1：直接执行（推荐）

```bash
# 下载脚本
wget https://raw.githubusercontent.com/Eric86777/vps-tcp-tune/main/dns-purify-smart.sh

# 添加执行权限
chmod +x dns-purify-smart.sh

# 执行（需要root权限）
./dns-purify-smart.sh
```

### 方法2：一键执行

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/Eric86777/vps-tcp-tune/main/dns-purify-smart.sh)
```

### 方法3：本地执行

如果你已经有脚本文件：

```bash
# 如果你是root用户
bash dns-purify-smart.sh

# 如果你是普通用户
sudo bash dns-purify-smart.sh
```

## 🔍 脚本做了什么

### 阶段一：健康检查
脚本会检查以下4项：
1. systemd-resolved 服务状态
2. dhclient.conf 配置
3. if-up.d 冲突脚本
4. **systemd-resolved 是否被屏蔽** ⭐ 新增

### 阶段二：智能修复（如果需要）
如果检测到 `systemd-resolved` 被屏蔽：
```bash
# 自动执行以下操作
systemctl unmask systemd-resolved
systemctl enable systemd-resolved
systemctl start systemd-resolved
```

### 阶段三：DNS配置
应用以下安全配置：
```ini
[Resolve]
DNS=8.8.8.8#dns.google 1.1.1.1#cloudflare-dns.com
LLMNR=no
MulticastDNS=no
DNSSEC=allow-downgrade
DNSOverTLS=yes
```

## ✅ 执行后验证

脚本执行完成后，运行以下命令验证：

```bash
# 1. 检查服务状态
systemctl status systemd-resolved

# 2. 查看DNS配置
resolvectl status

# 3. 测试DNS解析
dig google.com

# 4. 验证DoT是否生效
resolvectl query cloudflare.com

# 5. 查看当前DNS
cat /etc/resolv.conf
```

## 🎯 适用环境

### ✅ 支持的系统
- Debian 10/11/12
- Ubuntu 18.04/20.04/22.04/24.04
- 其他基于Debian的发行版

### ✅ 适用场景
- 个人VPS
- 测试服务器
- 需要DNS加密的环境
- DMIT/Vultr/DigitalOcean等VPS

### ⚠️ 不适用场景
- 企业内网（需要内部DNS）
- 容器环境（Docker/K8s）
- 使用NetworkManager的桌面系统

## 🔧 与原版的区别

| 功能 | 原版脚本 | 智能修复版 |
|------|---------|-----------|
| 检测masked状态 | ❌ | ✅ |
| 自动unmask | ❌ | ✅ |
| 手动修复fallback | ❌ | ✅ |
| 服务状态验证 | ⚠️ 基础 | ✅ 完整 |
| 错误处理 | ⚠️ 基础 | ✅ 增强 |

## 🛡️ 安全性

### 脚本会修改的文件
- `/etc/systemd/resolved.conf` - DNS配置
- `/etc/resolv.conf` - DNS解析器（符号链接）
- `/etc/dhcp/dhclient.conf` - DHCP客户端配置
- `/etc/network/interfaces` - 网络接口配置（仅注释）

### 不会删除的内容
- 原有配置会被注释而非删除
- 不会删除任何用户数据

## 🔄 回滚方法

如果需要恢复原始配置：

```bash
# 停止 systemd-resolved
systemctl stop systemd-resolved
systemctl disable systemd-resolved

# 恢复传统DNS配置
rm /etc/resolv.conf
echo "nameserver 8.8.8.8" > /etc/resolv.conf
echo "nameserver 1.1.1.1" >> /etc/resolv.conf

# 重启网络
systemctl restart networking
```

## 📊 常见问题

### Q1: 执行后SSH断开了怎么办？
**A:** 这是正常现象（网络服务重启），等待30秒后重新连接即可。

### Q2: 提示 "Failed to enable unit: Unit file is masked"
**A:** 这正是脚本要解决的问题！智能修复版会自动处理。

### Q3: DoT连接失败
**A:** 可能是防火墙阻断了853端口，检查：
```bash
# 检查防火墙
iptables -L -n | grep 853

# 如果被阻断，允许DoT
iptables -A OUTPUT -p tcp --dport 853 -j ACCEPT
```

### Q4: DNS解析变慢了
**A:** 可能是DoT握手延迟，可以：
1. 等待几分钟（缓存建立后会变快）
2. 或者禁用DoT（修改脚本中的 `DNSOverTLS=no`）

### Q5: 在阿里云/AWS上能用吗？
**A:** 可以，但可能影响云平台元数据服务。如果遇到问题，检查：
```bash
# 阿里云
curl http://100.100.100.200/latest/meta-data/

# AWS
curl http://169.254.169.254/latest/meta-data/
```

## 📝 更新日志

### v2.0 (智能修复版)
- ✅ 新增 systemd-resolved masked 状态检测
- ✅ 新增自动 unmask 功能
- ✅ 新增手动修复 fallback
- ✅ 增强错误处理
- ✅ 优化日志输出

### v1.0 (原版)
- 基础DNS配置功能
- DoT + DNSSEC 支持

## 👨‍💻 贡献者

- **NSdesk** - 原始脚本作者
- **AI优化** - 智能修复功能

## 🔗 相关链接

- 原作者主页: https://www.nodeseek.com/space/23129/
- GitHub仓库: https://github.com/Eric86777/vps-tcp-tune

## 📄 许可证

本脚本基于原作者NSdesk的工作进行优化，遵循开源精神自由使用。

---

**⚠️ 重要提示：**
- 建议在测试环境先运行
- 确保有VNC/控制台访问权限
- 生产环境请谨慎使用

