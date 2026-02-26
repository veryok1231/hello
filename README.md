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
| **端口扫描** | 高并发 SYN 扫描，支持全端口 1-65535 | ✅ |
| **服务识别** | 基于指纹匹配识别服务类型、产品、版本 | ✅ |
| **代答检测** | 自动识别 NAT 代理、反向代理、负载均衡 | ✅ |
| **后端推断** | 智能推断真实后端 IP 和端口 | ✅ |
| **多格式输出** | 支持 JSON / CSV / XML 格式导出 | ✅ |

### 🎯 特色亮点

- **大规模扫描** - 支持两个 A 段网络（约 131,072 IP）的资产探测
- **代答识别** - 独创的 C 段存活检测算法，精准识别代理设备
- **高性能** - 可配置发包速率，最高支持 100,000 PPS
- **智能分析** - TTL 差异分析 + 指纹相似度分析双重检测
- **断点续扫** - 支持扫描状态持久化，意外中断可恢复

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
# 下载预编译二进制
wget https://github.com/veryok1231/hello/releases/latest/download/probe-linux-amd64
chmod +x probe-linux-amd64
sudo mv probe-linux-amd64 /usr/local/bin/probe
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
# 扫描单个 C 段（推荐使用 sudo 获得完整功能）
sudo probe scan -t 192.168.1.0/24

# 扫描多个网段
sudo probe scan -t 10.0.0.0/24 -t 172.16.0.0/24

# 扫描单个 IP
sudo probe scan -t 192.168.1.100
```

#### 端口控制

```bash
# 扫描常用端口（推荐快速扫描）
sudo probe scan -t 192.168.1.0/24 -p 21,22,23,25,80,443,3389,8080

# 扫描端口范围
sudo probe scan -t 192.168.1.0/24 -p 1-1000

# 混合指定
sudo probe scan -t 192.168.1.0/24 -p 1-1000,8080,8443,9000-9999

# 全端口扫描（默认行为）
sudo probe scan -t 192.168.1.0/24 -p 1-65535
```

#### 性能调优

```bash
# 高速扫描（适合本地网络）
sudo probe scan -t 192.168.0.0/16 -r 50000 -c 2000

# 低速扫描（适合跨网段/公网扫描）
sudo probe scan -t 10.0.0.0/8 -r 1000 -c 100

# 自定义超时
sudo probe scan -t 192.168.1.0/24 --timeout 5s
```

#### 输出控制

```bash
# 指定输出文件
sudo probe scan -t 192.168.1.0/24 -o my_scan.json

# 指定输出格式
sudo probe scan -t 192.168.1.0/24 -f csv -o scan.csv
sudo probe scan -t 192.168.1.0/24 -f xml -o scan.xml

# 追加模式（保留上次结果）
sudo probe scan -t 192.168.1.0/24 --resume
```

#### 功能开关

```bash
# 仅端口扫描，跳过服务识别
sudo probe scan -t 192.168.1.0/24 --service-detection=false

# 仅端口扫描，跳过代答分析
sudo probe scan -t 192.168.1.0/24 --proxy-detection=false

# 最小化扫描（仅主机发现+端口扫描）
sudo probe scan -t 192.168.1.0/24 --service-detection=false --proxy-detection=false
```

### 🔍 discover - 主机发现

快速发现存活主机，不进行端口扫描。

```bash
# ICMP + TCP 混合探测（默认）
sudo probe discover -t 192.168.1.0/24

# 仅 ICMP 探测
sudo probe discover -t 192.168.1.0/24 --method icmp

# 仅 TCP 探测（不需要 root）
probe discover -t 192.168.1.0/24 --method tcp

# 多种方式组合
sudo probe discover -t 192.168.1.0/24 --method icmp,tcp,arp

# 指定输出文件
sudo probe discover -t 192.168.1.0/24 -o alive_hosts.json
```

### 📊 analyze - 代答分析

对已有扫描结果进行深度分析，识别代答资产。

```bash
# 分析扫描结果
probe analyze -i result.json -o analysis.json

# 自定义检测阈值
probe analyze -i result.json --subnet-threshold 200 --ttl-threshold 5
```

### 📋 参数详解

#### scan 命令参数

| 参数 | 简写 | 默认值 | 说明 |
|:-----|:----:|:------:|:-----|
| `--target` | `-t` | 必填 | 目标网络范围，支持 CIDR 格式，可指定多个 |
| `--ports` | `-p` | 1-65535 | 端口范围，支持 `1-1000`、`80,443` 等格式 |
| `--rate` | `-r` | 10000 | 发包速率 (PPS)，范围 1-100000 |
| `--concurrency` | `-c` | 1000 | 并发连接数 |
| `--timeout` | - | 3s | 单个探测超时时间 |
| `--output` | `-o` | result.json | 输出文件路径 |
| `--format` | `-f` | json | 输出格式：json / csv / xml |
| `--interface` | `-i` | auto | 网络接口名称 |
| `--resume` | - | false | 恢复上次扫描 |
| `--service-detection` | - | true | 是否进行服务识别 |
| `--proxy-detection` | - | true | 是否进行代答检测 |

#### discover 命令参数

| 参数 | 简写 | 默认值 | 说明 |
|:-----|:----:|:------:|:-----|
| `--target` | `-t` | 必填 | 目标网络范围 |
| `--rate` | `-r` | 10000 | 发包速率 (PPS) |
| `--timeout` | - | 3s | 响应超时时间 |
| `--output` | `-o` | hosts.json | 输出文件路径 |
| `--method` | - | icmp,tcp | 探测方式：icmp / tcp / arp |

#### analyze 命令参数

| 参数 | 简写 | 默认值 | 说明 |
|:-----|:----:|:------:|:-----|
| `--input` | `-i` | result.json | 扫描结果文件 |
| `--output` | `-o` | analysis.json | 分析结果输出路径 |
| `--subnet-threshold` | - | 254 | C 段存活阈值（用于代答检测） |
| `--ttl-threshold` | - | 3 | TTL 差异阈值 |

---

## 🎭 代答检测

### 检测原理

#### 1️⃣ C 段存活检测

当某个 C 段的存活主机数量达到 **254 台或 255 台** 时，系统判定为代答网段。

**检测场景：**
- 🏢 企业 NAT 网关统一出口
- 🛡️ 防火墙统一响应（策略隐藏真实主机）
- ⚖️ 负载均衡器代理后端服务

```
正常网段：192.168.1.0/24 → 存活主机 23 台
代答网段：10.0.0.0/24   → 存活主机 254 台 ⚠️
```

#### 2️⃣ TTL 差异分析

分析同一 IP 不同端口返回的 TTL 值差异。

```
正常主机：
  192.168.1.1:80  → TTL: 64
  192.168.1.1:443 → TTL: 64

可疑代理：
  10.0.0.1:80   → TTL: 127  (经过 1 跳)
  10.0.0.1:8080 → TTL: 62   (经过 2 跳) ⚠️
```

#### 3️⃣ 指纹相似度分析

检测多个 IP 是否返回相同的服务指纹特征。

```
发现疑似负载均衡：
  10.0.0.1:80  → nginx/1.18.0, 指纹: a1b2c3
  10.0.0.2:80  → nginx/1.18.0, 指纹: a1b2c3  ⚠️
  10.0.0.3:80  → nginx/1.18.0, 指纹: a1b2c3  ⚠️
  
→ 推断：同一后端服务器，反向代理分发
```

#### 4️⃣ 后端推断

尝试推断真实后端服务信息。

- HTTP 头分析：`X-Real-IP`、`X-Forwarded-For`
- TTL 跳数估算网络距离
- 服务指纹一致性匹配

### 代答类型

| 类型 | 描述 | 置信度 |
|:-----|:-----|:------:|
| `nat-proxy` | NAT 网关代理 | 95% |
| `reverse-proxy` | 反向代理/负载均衡 | 80% |
| `multi-hop` | 多跳路由 | 70% |

---

## 📄 输出格式

### JSON 格式（默认）

```json
[
  {
    "ip": "192.168.1.100",
    "port": 80,
    "protocol": "tcp",
    "state": "open",
    "ttl": 64,
    "service": {
      "name": "http",
      "product": "nginx",
      "version": "1.18.0",
      "os_type": "linux",
      "raw_banner": "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n"
    },
    "is_proxy": false
  },
  {
    "ip": "10.0.0.50",
    "port": 443,
    "protocol": "tcp",
    "state": "open",
    "ttl": 127,
    "service": {
      "name": "https",
      "product": "Apache httpd",
      "version": "2.4.41"
    },
    "is_proxy": true,
    "proxy_info": {
      "type": "nat-proxy",
      "confidence": 0.95,
      "backend_ip": "10.0.0.1",
      "backend_port": 8080,
      "evidence": [
        "Subnet 10.0.0.0/24 has 254 alive hosts",
        "Uniform service distribution across subnet"
      ]
    }
  }
]
```

### CSV 格式

```csv
IP,Port,Protocol,State,TTL,Service,Product,Version,IsProxy,ProxyType,BackendIP,BackendPort
192.168.1.100,80,tcp,open,64,http,nginx,1.18.0,false,,,
10.0.0.50,443,tcp,open,127,https,Apache httpd,2.4.41,true,nat-proxy,10.0.0.1,8080
```

### 代答分析报告

```json
[
  {
    "cidr": "10.0.0.0/24",
    "is_proxy_subnet": true,
    "alive_host_count": 254,
    "total_host_count": 256,
    "proxy_type": "nat-proxy",
    "confidence": 0.95,
    "affected_ips": ["10.0.0.1", "10.0.0.2", "..."],
    "inferred_backends": [
      {
        "port": 80,
        "service": "http",
        "confidence": 0.7,
        "evidence": ["Uniform service http on port 80 across subnet"]
      },
      {
        "port": 443,
        "service": "https",
        "confidence": 0.7,
        "evidence": ["Uniform service https on port 443 across subnet"]
      }
    ]
  }
]
```

---

## 🔧 高级用法

### 大规模扫描示例

```bash
# 扫描两个 A 段（约 131,072 IP）
sudo probe scan -t 10.0.0.0/8 -t 172.16.0.0/8 \
  -p 21,22,23,25,80,443,3389,8080,8443 \
  -r 50000 -c 3000 \
  -o enterprise_scan.json

# 离线分析结果
probe analyze -i enterprise_scan.json -o proxy_analysis.json
```

### 自定义扫描流程

```bash
# 第一步：快速主机发现
sudo probe discover -t 192.168.0.0/16 -o hosts.json

# 第二步：针对性端口扫描（对存活主机）
# （编辑 hosts.json 筛选目标后）
sudo probe scan -t targets.txt -p 1-65535 -o ports.json

# 第三步：服务深度识别
sudo probe scan -t targets.txt -p discovered_ports.txt \
  --service-detection=true --proxy-detection=false \
  -o services.json

# 第四步：代答分析
probe analyze -i services.json -o proxy_report.json
```

### 配置文件

支持通过 YAML 配置文件设置默认参数：

```yaml
# config/config.yaml
scan:
  default_rate: 10000
  max_rate: 100000
  default_timeout: 3s
  max_concurrent: 5000

discovery:
  methods:
    - icmp
    - tcp
  tcp_probe_ports:
    - 80
    - 443
    - 22

proxy_detection:
  subnet_threshold: 254
  ttl_diff_threshold: 3
  confidence_threshold: 0.5

output:
  default_format: json
  include_raw_banner: true
```

使用配置文件：

```bash
probe scan -t 192.168.1.0/24 --config ./config/config.yaml
```

---

## 📊 性能参考

### 硬件配置建议

| 扫描规模 | CPU | 内存 | 网络 |
|:---------|:----|:-----|:-----|
| /24 (254 IP) | 2 核 | 1 GB | 100 Mbps |
| /16 (65K IP) | 4 核 | 4 GB | 1 Gbps |
| /8 (16M IP) | 8+ 核 | 16+ GB | 10 Gbps |

### 扫描速度参考

| 配置 | 速率 | /24 网段 | /16 网段 |
|:-----|:----:|:--------:|:--------:|
| 默认 | 10K PPS | ~2 分钟 | ~5 小时 |
| 高速 | 50K PPS | ~30 秒 | ~1 小时 |
| 极速 | 100K PPS | ~15 秒 | ~30 分钟 |

---

## ⚠️ 注意事项

### 权限要求

| 功能 | root 权限 | 说明 |
|:-----|:--------:|:-----|
| ICMP 探测 | ✅ 必需 | 需要原始套接字 |
| TCP 探测 | ❌ 不需要 | 使用标准 socket |
| ARP 探测 | ✅ 必需 | 需要原始套接字 |
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
│   ├── main.go              # 程序入口
│   └── cli/                 # CLI 定义
│       └── root.go          # 命令定义
├── internal/
│   ├── engine/              # 核心引擎
│   │   ├── scheduler.go     # 任务调度器
│   │   ├── discovery.go     # 主机发现引擎
│   │   ├── scanner.go       # 端口扫描引擎
│   │   ├── service.go       # 服务识别引擎
│   │   ├── proxy_analyzer.go # 代答分析引擎
│   │   └── types.go         # 类型定义
│   ├── network/             # 网络层
│   │   ├── socket.go        # 原始套接字封装
│   │   └── ratelimit.go     # 速率限制
│   └── data/                # 数据层
│       └── storage.go       # 结果存储
├── pkg/utils/               # 工具库
│   └── ip.go                # IP/端口解析
├── config/                  # 配置文件
│   └── config.yaml          # 默认配置
├── data/                    # 数据文件
│   └── fingerprints         # 服务指纹库
├── go.mod
├── Makefile
└── README.md
```

---

## 🤝 参与贡献

欢迎提交 Issue 和 Pull Request！

```bash
# Fork 项目
git clone https://github.com/your-username/hello.git

# 创建分支
git checkout -b feature/your-feature

# 提交代码
git commit -m "feat: add your feature"
git push origin feature/your-feature

# 创建 Pull Request
```

---

## 📜 开源协议

本项目基于 [MIT License](LICENSE) 开源。

---

## 🙏 致谢

本项目设计参考了以下优秀项目：

- [nmap](https://nmap.org/) - 网络扫描领域的标杆
- [masscan](https://github.com/robertdavidgraham/masscan) - 互联网级高速扫描
- [gopacket](https://github.com/google/gopacket) - Go 语言数据包处理库

---

<p align="center">
  <b>⭐ 如果这个项目对你有帮助，请给一个 Star！</b>
</p>
