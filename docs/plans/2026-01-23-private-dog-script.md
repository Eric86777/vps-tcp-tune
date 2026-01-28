# 私有化 Port Traffic Dog 脚本实现方案

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** 将 `Eric_port-traffic-dog.sh` 脚本私有化，同时保持 `dog` 快捷命令能一键调用最新版本

**Architecture:** 由于 GitHub 私有仓库无法直接通过 raw URL 访问，需要通过认证机制或替代托管方案实现

**Tech Stack:** GitHub Private Repo + Personal Access Token / GitHub Gist (Secret) / 自建服务器

---

## 当前情况分析

### 现有机制
```bash
alias dog="bash <(curl -fsSL \"https://raw.githubusercontent.com/Eric86777/vps-tcp-tune/main/Eric_port-traffic-dog.sh?\$(date +%s)\")"
```

### 问题
- 仓库私有化后，raw.githubusercontent.com 的 URL 需要认证
- 直接 curl 无法访问私有仓库文件

---

## 方案对比

| 方案 | 安全性 | 便利性 | 维护成本 | 推荐度 |
|------|--------|--------|----------|--------|
| 方案 A: GitHub API + PAT | ⭐⭐⭐ | ⭐⭐ | 低 | ⭐⭐⭐ |
| 方案 B: Secret Gist | ⭐⭐ | ⭐⭐⭐ | 低 | ⭐⭐⭐⭐ |
| 方案 C: 自建服务器 | ⭐⭐⭐⭐ | ⭐⭐ | 高 | ⭐⭐ |
| 方案 D: 混合方案 | ⭐⭐⭐ | ⭐⭐⭐ | 中 | ⭐⭐⭐ |

---

## 方案 A: GitHub API + Personal Access Token

### 原理
使用 GitHub Personal Access Token (PAT) 通过 API 获取私有仓库文件内容

### 步骤

#### Step 1: 创建 GitHub Personal Access Token
1. 访问 https://github.com/settings/tokens
2. 点击 "Generate new token (classic)"
3. 选择权限：`repo` (Full control of private repositories)
4. 设置过期时间（建议 90 天或更长）
5. 复制生成的 token

#### Step 2: 在服务器上配置 Token
```bash
# 将 token 保存到服务器（只需执行一次）
echo "YOUR_GITHUB_TOKEN" > ~/.dog_token
chmod 600 ~/.dog_token
```

#### Step 3: 修改别名
```bash
alias dog='bash <(curl -fsSL -H "Authorization: token $(cat ~/.dog_token)" -H "Accept: application/vnd.github.v3.raw" "https://api.github.com/repos/Eric86777/vps-tcp-tune/contents/Eric_port-traffic-dog.sh?ref=main&$(date +%s)")'
```

### 优点
- 脚本仍在主仓库管理，版本控制一致
- 每次运行获取最新版本

### 缺点
- 需要在每台服务器配置 token
- Token 泄露风险（虽然权限可控）
- Token 过期需要更新

---

## 方案 B: Secret Gist（⭐ 推荐）

### 原理
将脚本放到 GitHub Secret Gist，Secret Gist 的 raw URL 不需要认证即可访问

### 步骤

#### Step 1: 创建 Secret Gist
1. 访问 https://gist.github.com
2. 文件名：`Eric_port-traffic-dog.sh`
3. 内容：粘贴脚本内容
4. 选择 **"Create secret gist"**（不是 public）

#### Step 2: 获取 Raw URL
- Gist 创建后，点击 "Raw" 按钮
- URL 格式：`https://gist.githubusercontent.com/Eric86777/<gist_id>/raw/<file_id>/Eric_port-traffic-dog.sh`
- **注意**：去掉 file_id 部分，使用 `https://gist.githubusercontent.com/Eric86777/<gist_id>/raw/Eric_port-traffic-dog.sh`
- 这样每次访问都会获取最新版本

#### Step 3: 更新别名
```bash
alias dog="bash <(curl -fsSL \"https://gist.githubusercontent.com/Eric86777/<gist_id>/raw/Eric_port-traffic-dog.sh?\$(date +%s)\")"
```

### 优点
- ✅ 无需 token，URL 本身就是"密钥"
- ✅ 只有知道 URL 的人才能访问（URL 包含随机 gist_id）
- ✅ 不影响现有服务器的使用体验
- ✅ 更新 Gist 后，所有服务器自动获取最新

### 缺点
- 需要手动同步脚本到 Gist（或写自动化）
- URL 如果泄露，任何人都能访问

### 自动同步方案（可选）
可以写一个 GitHub Action，当私有仓库的脚本更新时，自动同步到 Gist

---

## 方案 C: 自建服务器托管

### 原理
将脚本托管在你自己控制的服务器上

### 步骤

#### Step 1: 在你的 VPS 上创建脚本目录
```bash
mkdir -p /var/www/scripts
cp Eric_port-traffic-dog.sh /var/www/scripts/
```

#### Step 2: 配置 Nginx/Caddy 反代
```nginx
location /scripts/ {
    alias /var/www/scripts/;
    # 可选：添加 IP 白名单或 Basic Auth
}
```

#### Step 3: 更新别名
```bash
alias dog="bash <(curl -fsSL \"https://your-domain.com/scripts/Eric_port-traffic-dog.sh?\$(date +%s)\")"
```

### 优点
- 完全自主控制
- 可以添加 IP 白名单等安全措施

### 缺点
- 需要维护服务器
- 更新脚本需要手动上传或配置 CI/CD

---

## 方案 D: 混合方案 - 私有仓库 + 部署脚本

### 原理
脚本在私有仓库管理，通过 GitHub Actions 自动部署到可访问的位置（Gist 或自建服务器）

### 实现
1. 主脚本在私有仓库开发
2. 配置 GitHub Action，push 时自动同步到 Secret Gist
3. 服务器通过 Gist URL 访问

---

## 推荐方案：方案 B (Secret Gist)

### 理由
1. **零配置**：服务器不需要任何额外配置
2. **安全性足够**：Secret Gist 的 URL 本身就是访问密钥
3. **维护简单**：更新 Gist 即可，所有服务器自动生效
4. **体验一致**：`dog` 命令使用方式完全不变

### 实施步骤

#### Task 1: 创建 Secret Gist
1. 复制 `Eric_port-traffic-dog.sh` 的完整内容
2. 在 https://gist.github.com 创建 Secret Gist
3. 记录 Gist ID（URL 中的那串随机字符）

#### Task 2: 更新 install-alias.sh
修改 `install-alias.sh`，将 dog 别名的 URL 改为 Gist URL：
```bash
alias dog="bash <(curl -fsSL \"https://gist.githubusercontent.com/Eric86777/<GIST_ID>/raw/Eric_port-traffic-dog.sh?\$(date +%s)\")"
```

#### Task 3: 从公开仓库删除脚本
```bash
git rm Eric_port-traffic-dog.sh
git commit -m "chore: 移除 port-traffic-dog 脚本（已迁移至私有 Gist）"
git push
```

#### Task 4: 已安装用户迁移
已安装的用户需要重新运行 `install-alias.sh` 来更新别名

---

## 其他注意事项

### 如果选择方案 A (GitHub API + PAT)

需要创建一个新的安装脚本来引导用户配置 token：

```bash
# install-dog-private.sh
#!/bin/bash
echo "请输入你的 GitHub Personal Access Token:"
read -s TOKEN
echo "$TOKEN" > ~/.dog_token
chmod 600 ~/.dog_token
echo "Token 已保存到 ~/.dog_token"

# 添加别名...
```

### 更新 README.md

无论选择哪个方案，都需要更新 README 中关于 `dog` 的安装说明：
- 如果是 Secret Gist：README 中不要暴露 Gist URL
- 可以只保留 `bbr` 的公开安装方式，`dog` 通过私下分享安装命令
