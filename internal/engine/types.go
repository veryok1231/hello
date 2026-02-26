package engine

import (
	"net"
	"time"
)

type Config struct {
	Targets          []string
	PortRange        string
	Rate             int
	Concurrency      int
	Timeout          time.Duration
	OutputFile       string
	OutputFormat     string
	Resume           bool
	ScanType         string
	Interface        string
	ServiceDetection bool
	ProxyDetection   bool
	DiscoveryOnly    bool
	DiscoveryMethods []string
	Whitelist        []string // 白名单IP列表
	WhitelistFile    string   // 白名单文件路径
}

func (c *Config) ApplyDefaults() {
	if c.Rate <= 0 {
		c.Rate = 10000
	}
	if c.Concurrency <= 0 {
		c.Concurrency = 1000
	}
	if c.Timeout <= 0 {
		c.Timeout = 3 * time.Second
	}
	if c.OutputFile == "" {
		c.OutputFile = "result.json"
	}
	if c.OutputFormat == "" {
		c.OutputFormat = "json"
	}
	if c.PortRange == "" {
		c.PortRange = "1-65535"
	}
}

type ScanTarget struct {
	IP    net.IP
	Ports []int
}

type ScanStatus struct {
	TotalHosts   int
	ScannedHosts int
	TotalPorts   int
	ScannedPorts int
	StartTime    time.Time
	EstimatedEnd time.Time
	CurrentRate  int
	SkippedIPs   int // 跳过的白名单IP数量
}

type ProxyAnalyzerConfig struct {
	SubnetThreshold int
	TTLThreshold    int
}

func (c *ProxyAnalyzerConfig) ApplyDefaults() {
	if c.SubnetThreshold <= 0 {
		c.SubnetThreshold = 254
	}
	if c.TTLThreshold <= 0 {
		c.TTLThreshold = 3
	}
}
