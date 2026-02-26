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
}

type ProxyAnalyzerConfig struct {
	SubnetThreshold int
	TTLThreshold    int
}
