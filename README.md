# 资产探测工具 (Asset Probe)

一款参考 nmap 和 masscan 实现的高性能网络资产探测工具，支持大规模网络主机发现、端口扫描、服务识别和代答资产检测。

## 功能特性

- **主机发现**: 支持 ICMP、TCP、ARP 多种探测方式
- **端口扫描**: 高性能 SYN 扫描，支持全端口范围
- **服务识别**: 基于指纹匹配的服务版本识别
- **代答检测**: 自动识别 NAT 代理、反向代理等代答资产
- **后端推断**: 尝试推断真实后端 IP 和端口
- **多格式输出**: 支持 JSON、CSV、XML 格式

## 编译安装

```bash
# 编译
make build

# 或直接安装到 GOPATH/bin
make install

# 下载依赖
make deps
```

## 使用方法

### 扫描命令

```bash
# 完整扫描 (需要 root 权限)
sudo ./probe scan -t 192.168.1.0/24

# 指定端口范围
sudo ./probe scan -t 10.0.0.0/8 -p 1-1000

# 自定义速率和并发
sudo ./probe scan -t 192.168.0.0/16 -r 50000 -c 2000

# 仅主机发现
sudo ./probe discover -t 192.168.1.0/24

# 分析扫描结果
./probe analyze -i result.json -o analysis.json
```

### 参数说明

#### scan 命令

| 参数 | 简写 | 默认值 | 说明 |
|------|------|--------|------|
| --target | -t | 必填 | 目标网络范围 (CIDR格式，支持多个) |
| --ports | -p | 1-65535 | 端口范围 |
| --rate | -r | 10000 | 发包速率 (PPS) |
| --concurrency | -c | 1000 | 并发数 |
| --timeout | | 3s | 响应超时时间 |
| --output | -o | result.json | 输出文件路径 |
| --format | -f | json | 输出格式 (json/csv/xml) |
| --resume | | false | 恢复上次扫描 |
| --interface | -i | auto | 网络接口 |
| --service-detection | | true | 是否进行服务识别 |
| --proxy-detection | | true | 是否进行代答检测 |

#### discover 命令

| 参数 | 简写 | 默认值 | 说明 |
|------|------|--------|------|
| --target | -t | 必填 | 目标网络范围 |
| --rate | -r | 10000 | 发包速率 |
| --timeout | | 3s | 响应超时时间 |
| --output | -o | hosts.json | 输出文件路径 |
| --method | | icmp,tcp | 发现方法 |

#### analyze 命令

| 参数 | 简写 | 默认值 | 说明 |
|------|------|--------|------|
| --input | -i | result.json | 扫描结果文件 |
| --output | -o | analysis.json | 分析结果输出路径 |
| --subnet-threshold | | 254 | C段存活阈值 |
| --ttl-threshold | | 3 | TTL差异阈值 |

## 代答检测原理

### C段存活检测

当某个 C 段的存活主机数量达到 254 或 255 台时，系统会标记该网段为疑似代答网段。这种情况通常表示：

- NAT 网关代理
- 防火墙统一响应
- 负载均衡器代答

### TTL 差异分析

分析同一 IP 不同端口返回的 TTL 值差异：

- TTL 差异 > 阈值 (默认3)：标记为可疑
- 可能表示多跳路由或代理设备

### 指纹相似度分析

检测多个 IP 是否返回相同的服务指纹：

- 相同指纹可能表示同一后端服务器
- 用于识别反向代理场景

### 后端推断

尝试推断真实后端服务：

- HTTP 头部分析 (X-Real-IP, X-Forwarded-For)
- TTL 跳数推断
- 服务指纹一致性分析

## 输出示例

### JSON 格式

```json
[
  {
    "ip": "192.168.1.1",
    "port": 80,
    "protocol": "tcp",
    "state": "open",
    "ttl": 64,
    "service": {
      "name": "http",
      "product": "nginx",
      "version": "1.18.0"
    },
    "is_proxy": false
  }
]
```

### 代答分析结果

```json
[
  {
    "cidr": "10.0.0.0/24",
    "is_proxy_subnet": true,
    "alive_host_count": 254,
    "total_host_count": 256,
    "proxy_type": "nat-proxy",
    "confidence": 0.95,
    "affected_ips": ["10.0.0.1", "10.0.0.2", ...],
    "inferred_backends": [
      {
        "port": 80,
        "service": "http",
        "confidence": 0.7,
        "evidence": ["Uniform service http on port 80 across subnet"]
      }
    ]
  }
]
```

## 性能建议

- **大范围扫描**: 建议使用 `-r 50000` 或更高的发包速率
- **网络带宽**: 确保网络带宽足够支持高速扫描
- **系统资源**: 扫描大规模网络时注意内存使用
- **断点续扫**: 使用 `--resume` 参数支持断点续扫

## 注意事项

1. **权限要求**: 需要使用 root 权限运行 (原始套接字操作)
2. **网络影响**: 高速扫描可能对目标网络造成压力，请合理设置速率
3. **合法性**: 请确保您有权对目标网络进行扫描

## 项目结构

```
asset-probe/
├── cmd/probe/           # 命令行入口
├── internal/
│   ├── engine/          # 核心引擎
│   ├── network/         # 网络层
│   ├── data/            # 数据存储
│   └── analysis/        # 分析模块
├── pkg/utils/           # 工具函数
├── config/              # 配置文件
├── data/                # 指纹库
├── go.mod
├── Makefile
└── README.md
```

## License

MIT License
