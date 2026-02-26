<p align="center">
  <img src="https://img.shields.io/badge/Go-1.21+-00ADD8?style=for-the-badge&logo=go" alt="Go Version">
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="License">
  <img src="https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey?style=for-the-badge" alt="Platform">
</p>

<h1 align="center">🔍 Asset Probe</h1>

<p align="center">
  <b>高性能网络资产探测工具</b><br>
  <sub>参考 nmap 和 masscan 设计，专为大规模网络资产探测而生</sub>
</p>

<p align="center">
  <a href="#-功能特性">功能特性</a> •
  <a href="#-快速开始">快速开始</a> •
  <a href="#-使用指南">使用指南</a> •
  <a href="#-代答检测">代答检测</a> •
  <a href="#-输出格式">输出格式</a>
</p>

---

## ✨ 功能特性

### 🚀 核心能力

| 功能 | 描述 | 状态 |
|:-----|:-----|:----:|
| **主机发现** | 支持 ICMP Echo、TCP SYN、ARP 多种探测方式 | ✅ |
| **端口扫描** | 高并发 SYN 扫描，支持 Top100 / 全端口 | ✅ |
| **服务识别** | 基于指纹匹配识别服务类型、产品、版本 | ✅ |
| **代答检测** | 自动识别 NAT 代理、反向代理、负载均衡 | ✅ |
| **后端推断** | 智能推断真实后端 IP 和端口 | ✅ |
| **多格式输出** | 支持 TXT / JSON / CSV / XML / Markdown | ✅ |
| **白名单** | 自动跳过指定 IP/CIDR，避免误扫 | ✅ |
| **IP列表文件** | 从文件加载目标列表，支持批量扫描 | ✅ |

### 🎯 特色亮点

- **大规模扫描** - 支持两个 A 段网络（约 131,072 IP）的资产探测
- **Top100端口** - 默认扫描常用 Top100 端口，快速高效
- **代答识别** - 独创的 C 段存活检测算法，精准识别代理设备
- **高性能** - 可配置发包速率，最高支持 100,000 PPS
- **智能分析** - TTL 差异分析 + 指纹相似度分析双重检测
- **白名单过滤** - 支持跳过指定IP，避免误扫关键资产

---

## 📦 快速开始

### 环境要求

- Go 1.21+
- Linux / macOS / Windows
- **root 权限** (ICMP 探测需要)

### 安装方式

**方式一：源码编译**

```bash
# 克隆仓库
git clone https://github.com/veryok1231/hello.git
cd hello

# 编译
make build

# 安装到系统路径
sudo make install
```

**方式二：直接下载**

```bash
# linux可直接下载预编译二进制
wget https://github.com/veryok1231/hello/probe
chmod +x probe
sudo mv probe /usr/local/bin/probe
```

### 验证安装

```bash
probe --help
```

---

## 📖 使用指南

### 命令概览

```
probe [command] [flags]

Commands:
  scan      执行完整扫描（主机发现 + 端口扫描 + 服务识别 + 代答分析）
  discover  仅执行主机发现
  analyze   分析已有扫描结果，识别代答资产
  help      帮助信息
```

### 🎯 scan - 完整扫描

最常用的扫描命令，一键完成资产探测全流程。

#### 基础用法

```bash
# 扫描单个 C 段（默认 Top100 端口）
./probe scan -t 192.168.1.0/24

# 扫描多个网段
./probe scan -t 10.0.0.0/24 -t 172.16.0.0/24

# 从文件加载IP列表
./probe scan -l targets.txt

# 扫描单个 IP
./probe scan -t 192.168.1.100
```

#### 端口控制

```bash
# Top100 常用端口（默认）
./probe scan -t 192.168.1.0/24 -p top100

# 全端口扫描
./probe scan -t 192.168.1.0/24 -p all

# 指定端口范围
./probe scan -t 192.168.1.0/24 -p 1-1000

# 指定具体端口
./probe scan -t 192.168.1.0/24 -p 22,80,443,3306,8080

# 混合指定
./probe scan -t 192.168.1.0/24 -p 1-1000,8080,8443
```

#### 输出格式

```bash
# TXT 格式（默认，简洁易读）
./probe scan -t 192.168.1.0/24 -f txt -o result.txt

# JSON 格式（机器可读）
./probe scan -t 192.168.1.0/24 -f json -o result.json

# CSV 格式（Excel 可打开）
./probe scan -t 192.168.1.0/24 -f csv -o result.csv

# Markdown 格式（文档报告）
./probe scan -t 192.168.1.0/24 -f md -o report.md

# XML 格式
./probe scan -t 192.168.1.0/24 -f xml -o result.xml
```

#### 白名单功能

```bash
# 直接指定白名单 IP
./probe scan -t 192.168.1.0/24 --whitelist 192.168.1.1 --whitelist 192.168.1.254

# 指定白名单 CIDR
./probe scan -t 10.0.0.0/16 --whitelist 10.0.1.0/24

# 从文件加载白名单
./probe scan -t 192.168.0.0/16 -w whitelist.txt

# 组合使用
./probe scan -t 192.168.0.0/16 --whitelist 192.168.1.1 -w whitelist.txt
```

#### 性能调优

```bash
# 高速扫描（适合本地网络）
./probe scan -t 192.168.0.0/16 -r 50000 -c 2000

# 低速扫描（适合跨网段/公网扫描）
./probe scan -t 10.0.0.0/8 -r 1000 -c 100

# 自定义超时
./probe scan -t 192.168.1.0/24 --timeout 5s
```

#### 功能开关

```bash
# 跳过服务识别
./probe scan -t 192.168.1.0/24 --service-detection=false

# 跳过代答分析
./probe scan -t 192.168.1.0/24 --proxy-detection=false

# 最小化扫描
./probe scan -t 192.168.1.0/24 --service-detection=false --proxy-detection=false
```

### 🔍 discover - 主机发现

快速发现存活主机，不进行端口扫描。

```bash
# TCP 探测（默认，不需要 root）
./probe discover -t 192.168.1.0/24

# 从文件加载IP
./probe discover -l targets.txt

# 使用白名单
./probe discover -t 192.168.1.0/24 -w whitelist.txt

# 指定输出格式
./probe discover -t 192.168.1.0/24 -f txt -o hosts.txt
./probe discover -t 192.168.1.0/24 -f json -o hosts.json
```

### 📊 analyze - 代答分析

对已有扫描结果进行深度分析。

```bash
# 分析扫描结果
./probe analyze -i result.json -o analysis.json

# 自定义检测阈值
./probe analyze -i result.json --subnet-threshold 200 --ttl-threshold 5
```

### 📋 参数详解

#### scan 命令参数

| 参数 | 简写 | 默认值 | 说明 |
|:-----|:----:|:------:|:-----|
| `--target` | `-t` | 必填 | 目标网络范围，支持 CIDR 格式 |
| `--list` | `-l` | - | IP列表文件路径 |
| `--ports` | `-p` | top100 | 端口范围 (top100/all/1-1000/80,443) |
| `--output` | `-o` | result.txt | 输出文件路径 |
| `--format` | `-f` | txt | 输出格式 (txt/json/csv/xml/md) |
| `--rate` | `-r` | 10000 | 发包速率 (PPS) |
| `--concurrency` | `-c` | 1000 | 并发连接数 |
| `--timeout` | - | 3s | 单个探测超时时间 |
| `--whitelist` | - | - | 白名单IP/CIDR |
| `--whitelist-file` | `-w` | - | 白名单文件路径 |
| `--service-detection` | - | true | 是否进行服务识别 |
| `--proxy-detection` | - | true | 是否进行代答检测 |

#### discover 命令参数

| 参数 | 简写 | 默认值 | 说明 |
|:-----|:----:|:------:|:-----|
| `--target` | `-t` | 必填 | 目标网络范围 |
| `--list` | `-l` | - | IP列表文件路径 |
| `--output` | `-o` | hosts.txt | 输出文件路径 |
| `--format` | `-f` | txt | 输出格式 (txt/json/csv) |
| `--whitelist` | - | - | 白名单IP/CIDR |
| `--whitelist-file` | `-w` | - | 白名单文件路径 |

---

## 📁 IP列表文件格式

支持从文件加载目标IP列表，每行一个条目：

```
# 注释行
192.168.1.1              # 单个IP
192.168.1.0/24           # CIDR
10.0.0.1-10.0.0.100      # IP范围
```

**使用示例：**

```bash
./probe scan -l targets.txt -p top100
```

---

## 🛡️ 白名单文件格式

白名单文件支持相同的格式：

```
# 白名单 - 这些IP将被跳过
192.168.1.1
192.168.1.0/28
10.0.0.1-10.0.0.10
```

**使用示例：**

```bash
./probe scan -t 192.168.0.0/16 -w whitelist.txt
```

---

## 📄 输出格式

### TXT 格式（默认）

简洁易读，只显示存活主机和开放端口：

```
=============================================================
                    存活主机端口扫描结果
=============================================================

主机: 192.168.1.100
--------------------------------------------------
  服务: http (nginx 1.18.0)
  开放端口: 22, 80, 443

主机: 192.168.1.200
--------------------------------------------------
  开放端口: 22, 3306
  [!] 检测到代答: nat-proxy (置信度: 95%)

=============================================================
共发现 2 个存活主机，5 个开放端口
=============================================================
```

### JSON 格式

```json
[
  {
    "ip": "192.168.1.100",
    "port": 80,
    "protocol": "tcp",
    "state": "open",
    "service": {
      "name": "http",
      "product": "nginx",
      "version": "1.18.0"
    }
  }
]
```

### CSV 格式

```csv
IP,Port,Protocol,Service,Product,Version,IsProxy,ProxyType
192.168.1.100,80,tcp,http,nginx,1.18.0,false,
192.168.1.200,443,tcp,https,,,,true,nat-proxy
```

### Markdown 格式

```markdown
# 扫描结果报告

**扫描时间:** 2024-01-01 12:00:00

## 存活主机

| IP地址 | 开放端口 | 服务 | 产品/版本 | 代答 |
|--------|----------|------|-----------|------|
| 192.168.1.100 | 22, 80, 443 | http | nginx 1.18.0 | |
| 192.168.1.200 | 22, 3306 | mysql | MySQL 8.0 | ⚠️ nat-proxy |
```

---

## 🎭 代答检测

### 检测原理

#### 1️⃣ C 段存活检测

当某个 C 段存活主机 ≥254 台时，判定为代答网段。

```
正常网段：192.168.1.0/24 → 存活主机 23 台
代答网段：10.0.0.0/24   → 存活主机 254 台 ⚠️
```

#### 2️⃣ TTL 差异分析

```
正常主机：
  192.168.1.1:80  → TTL: 64
  192.168.1.1:443 → TTL: 64

可疑代理：
  10.0.0.1:80   → TTL: 127
  10.0.0.1:8080 → TTL: 62   ⚠️
```

#### 3️⃣ 指纹相似度分析

多个IP返回相同指纹，可能为负载均衡。

### 代答类型

| 类型 | 描述 | 置信度 |
|:-----|:-----|:------:|
| `nat-proxy` | NAT 网关代理 | 95% |
| `reverse-proxy` | 反向代理/负载均衡 | 80% |
| `multi-hop` | 多跳路由 | 70% |

---

## 📊 性能参考

### 硬件配置建议

| 扫描规模 | CPU | 内存 | 网络 |
|:---------|:----|:-----|:-----|
| /24 (254 IP) | 2 核 | 1 GB | 100 Mbps |
| /16 (65K IP) | 4 核 | 4 GB | 1 Gbps |
| /8 (16M IP) | 8+ 核 | 16+ GB | 10 Gbps |

### 扫描速度

| 配置 | 速率 | /24 网段 | Top100端口 |
|:-----|:----:|:--------:|:----------:|
| 默认 | 10K PPS | ~8s | ~8s |
| 高速 | 50K PPS | ~4s | ~4s |

---

## ⚠️ 注意事项

### 权限要求

| 功能 | root 权限 | 说明 |
|:-----|:--------:|:-----|
| ICMP 探测 | ✅ 必需 | 需要原始套接字 |
| TCP 探测 | ❌ 不需要 | 使用标准 socket |
| 完整功能 | ✅ 推荐 | 获得最佳探测效果 |

### 合规提醒

```
⚠️  重要提示：

1. 本工具仅供合法授权的安全测试使用
2. 未经授权扫描他人网络可能违反法律法规
3. 高速扫描可能对目标网络造成压力，请合理配置参数
4. 使用前请确保已获得目标网络所有者的书面授权
```

---

## 🛠️ 项目结构

```
asset-probe/
├── cmd/probe/               # 命令行入口
├── internal/
│   ├── engine/              # 核心引擎
│   ├── network/             # 网络层
│   └── data/                # 数据存储
├── pkg/utils/               # 工具库
├── config/                  # 配置文件
├── go.mod
├── Makefile
└── README.md
```

---

## 🤝 参与贡献

欢迎提交 Issue 和 Pull Request！

---

## 📜 开源协议

本项目基于 [MIT License](LICENSE) 开源。

---

## 🙏 致谢

- [nmap](https://nmap.org/) - 网络扫描领域的标杆
- [masscan](https://github.com/robertdavidgraham/masscan) - 互联网级高速扫描

---

<p align="center">
  <b>⭐ 如果这个项目对你有帮助，请给一个 Star！</b>
</p>
