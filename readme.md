# Certbot Let's Encrypt 腾讯云 DNS 自动签发

基于 Certbot 和腾讯云 DNSPod 的 SSL 证书自动签发工具，支持单域名、多域名和通配符证书签发。

## 功能特性

- 自动 DNS-01 挑战验证
- 支持单域名证书签发
- 支持通配符证书签发 (`*.example.com`)
- 支持自定义证书存储目录
- 支持证书自动续期
- 支持二级域名证书签发

## 环境要求

- Node.js >= 14.0.0
- Certbot 已安装
- 腾讯云 DNSPod 账号及 API 密钥

## 安装

```bash
npm install
```

## 使用方法

### 1. 签发单域名证书

```bash
node index.js -d example.com --secret-id YOUR_SECRET_ID --secret-key YOUR_SECRET_KEY
```

### 2. 签发通配符证书

```bash
node index.js -d "*.example.com" --secret-id YOUR_SECRET_ID --secret-key YOUR_SECRET_KEY --wildcard
```

### 3. 指定证书存储目录

```bash
node index.js -d example.com \
    --secret-id YOUR_SECRET_ID \
    --secret-key YOUR_SECRET_KEY \
    --cert-dir /path/to/certificates
```

### 4. 使用测试环境（避免触发速率限制）

```bash
node index.js -d example.com \
    --secret-id YOUR_SECRET_ID \
    --secret-key YOUR_SECRET_KEY \
    --staging
```

### 5. 证书续期

```bash
node index.js --renew --secret-id YOUR_SECRET_ID --secret-key YOUR_SECRET_KEY
```

## 命令行参数

| 参数 | 简写 | 说明 | 必填 |
|------|------|------|------|
| `--domain` | `-d` | 要签发证书的域名 | 是（续期时除外） |
| `--secret-id` | - | 腾讯云 SecretId | 是 |
| `--secret-key` | - | 腾讯云 SecretKey | 是 |
| `--cert-dir` | - | 证书存储目录（默认: `/etc/letsencrypt`） | 否 |
| `--email` | - | 联系邮箱 | 否 |
| `--wildcard` | `-w` | 签发通配符证书 | 否 |
| `--staging` | - | 使用测试环境 | 否 |
| `--sleep` | - | DNS 传播等待时间（秒，默认: 30） | 否 |
| `--renew` | - | 续期现有证书 | 否 |
| `--help` | `-h` | 显示帮助信息 | 否 |

## 获取腾讯云 API 密钥

1. 登录 [腾讯云控制台](https://console.cloud.tencent.com/)
2. 进入 "访问管理" -> "访问密钥" -> "API 密钥管理"
3. 创建密钥并获取 `SecretId` 和 `SecretKey`

## 证书文件位置

签发成功后，证书文件默认存储在：

```
/etc/letsencrypt/live/<domain>/
├── cert.pem      # 服务器证书
├── chain.pem     # 中间证书
├── fullchain.pem # 完整证书链（服务器证书 + 中间证书）
└── privkey.pem   # 私钥
```

## 项目结构

```
.
├── index.js              # 主入口脚本
├── package.json          # 项目配置
├── lib/                  # 核心库
│   ├── certbot.js       # Certbot 集成
│   ├── dns-record.js    # DNS 记录管理
│   ├── file-utils.js    # 文件工具
│   └── tcy-signature.js # 腾讯云签名
├── hooks/                # Certbot 钩子
│   ├── auth.js          # DNS 验证钩子
│   └── cleanup.js       # 清理钩子
├── add.js               # 旧版添加脚本（保留兼容）
├── remove.js            # 旧版删除脚本（保留兼容）
└── readme.md            # 说明文档
```

## 自动续期配置

使用 crontab 配置自动续期：

```bash
# 每天凌晨 2 点检查并续期证书
0 2 * * * cd /path/to/certbot-letencrypt-txy-ssl && node index.js --renew --secret-id YOUR_SECRET_ID --secret-key YOUR_SECRET_KEY >> /var/log/certbot-renew.log 2>&1
```

## 注意事项

1. 确保域名 DNS 已托管在腾讯云 DNSPod
2. 首次使用建议先用 `--staging` 参数测试
3. 生产环境请设置联系邮箱 `--email`
4. 确保证书存储目录有写入权限
5. DNS 传播时间可能因网络环境而异，可通过 `--sleep` 调整

## 许可证

MIT
