# VPS TCP 调优 (BBR) - 私有版

一键 TCP 优化脚本，支持 BBR/BBRv3、内核参数调优等。

---

## 一键安装（复制粘贴到服务器执行）

### 全新服务器（从未安装过 dog/bbr）

```bash
# 1. 保存 Token
echo "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" > ~/.Eric_port-traffic-dog_token && chmod 600 ~/.Eric_port-traffic-dog_token

# 2. 添加 bbr 别名
echo 'alias bbr='\''bash <(curl -fsSL -H "Authorization: token $(cat ~/.Eric_port-traffic-dog_token)" -H "Accept: application/vnd.github.v3.raw" "https://api.github.com/repos/Eric86777/vps-tcp-tune/contents/net-tcp-tune.sh")'\''' >> ~/.bashrc && source ~/.bashrc

# 3. 测试
bbr
```

---

### 已有旧版 bbr 的服务器（迁移）

```bash
# 1. 清理旧的 bbr 别名
sed -i '/alias bbr=/d' ~/.bashrc

# 2. 保存 Token（如果已安装过 dog，跳过此步）
echo "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" > ~/.Eric_port-traffic-dog_token && chmod 600 ~/.Eric_port-traffic-dog_token

# 3. 添加新的 bbr 别名
echo 'alias bbr='\''bash <(curl -fsSL -H "Authorization: token $(cat ~/.Eric_port-traffic-dog_token)" -H "Accept: application/vnd.github.v3.raw" "https://api.github.com/repos/Eric86777/vps-tcp-tune/contents/net-tcp-tune.sh")'\''' >> ~/.bashrc && source ~/.bashrc

# 4. 测试
bbr
```

---

## 功能亮点

- ✅ 一键开启 BBR/BBRv3
- ✅ 内核参数自动调优
- ✅ 支持多种 Linux 发行版
- ✅ 每次运行自动获取最新版本
- ✅ 100% 私有，只有你能访问
