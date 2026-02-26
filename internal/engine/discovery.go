package engine

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/asset-probe/internal/data"
	"github.com/asset-probe/internal/network"
	"github.com/asset-probe/pkg/utils"
)

type DiscoveryEngine struct {
	config *Config
	socket *network.RawSocket
}

func NewDiscoveryEngine(config *Config) *DiscoveryEngine {
	return &DiscoveryEngine{
		config: config,
	}
}

func (d *DiscoveryEngine) Discover(ctx context.Context, targets []string) ([]data.HostInfo, error) {
	var hosts []data.HostInfo

	var allIPs []net.IP
	for _, target := range targets {
		ips, err := utils.ParseIPList(target)
		if err != nil {
			return nil, fmt.Errorf("解析目标失败 %s: %w", target, err)
		}
		allIPs = append(allIPs, ips...)
	}

	fmt.Printf("[INFO] 目标IP总数: %d\n", len(allIPs))

	if len(allIPs) == 0 {
		return hosts, nil
	}

	workerCount := d.config.Concurrency
	if workerCount <= 0 {
		workerCount = 50
	}
	if workerCount > 200 {
		workerCount = 200
	}

	var mu sync.Mutex
	var wg sync.WaitGroup

	sem := make(chan struct{}, workerCount)

	fmt.Printf("[DEBUG] 使用 %d 个工作线程\n", workerCount)

	start := time.Now()
	for _, ip := range allIPs {
		wg.Add(1)
		sem <- struct{}{}

		go func(targetIP net.IP) {
			defer wg.Done()
			defer func() { <-sem }()

			if host := d.probeHost(targetIP); host != nil {
				mu.Lock()
				hosts = append(hosts, *host)
				mu.Unlock()
			}
		}(ip)
	}

	wg.Wait()
	elapsed := time.Since(start)
	fmt.Printf("[DEBUG] 扫描完成，耗时: %v\n", elapsed)

	return hosts, nil
}

func (d *DiscoveryEngine) probeHost(ip net.IP) *data.HostInfo {
	probePorts := []int{22, 80, 443, 8080}
	timeout := d.config.Timeout
	if timeout <= 0 {
		timeout = 2 * time.Second
	}

	for _, port := range probePorts {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip.String(), port), timeout)
		if err == nil {
			conn.Close()
			return &data.HostInfo{
				IP:           ip,
				DiscoveryWay: "tcp",
				TTL:          64,
			}
		}
	}

	return nil
}

func (d *DiscoveryEngine) probeICMP(ctx context.Context, ip net.IP) (*data.HostInfo, error) {
	start := time.Now()
	resp, err := network.SendICMPProbe(ip, d.config.Timeout)
	if err != nil {
		return nil, err
	}

	return &data.HostInfo{
		IP:           ip,
		DiscoveryWay: "icmp",
		TTL:          resp.TTL,
		RespondTime:  time.Since(start),
	}, nil
}

func (d *DiscoveryEngine) probeTCP(ctx context.Context, ip net.IP) *data.HostInfo {
	probePorts := []int{80, 443, 22, 8080}
	openCount := 0
	closedCount := 0
	var firstOpenHost *data.HostInfo

	for _, port := range probePorts {
		start := time.Now()
		resp, err := network.SendSYNProbe(ip, port, d.config.Timeout)
		if err != nil {
			continue
		}

		if resp.Open {
			openCount++
			if firstOpenHost == nil {
				firstOpenHost = &data.HostInfo{
					IP:           ip,
					DiscoveryWay: "tcp",
					TTL:          resp.TTL,
					RespondTime:  time.Since(start),
				}
			}
		} else if resp.Closed {
			closedCount++
		}
	}

	if openCount >= 1 {
		return firstOpenHost
	}

	if closedCount >= 2 {
		return &data.HostInfo{
			IP:           ip,
			DiscoveryWay: "tcp-closed",
			TTL:          64,
			RespondTime:  0,
		}
	}

	return nil
}

func (d *DiscoveryEngine) probeARP(ctx context.Context, ip net.IP) (*data.HostInfo, error) {
	if !ip.IsPrivate() && !ip.IsLoopback() {
		return nil, fmt.Errorf("ARP only works on local network")
	}

	start := time.Now()
	resp, err := network.SendARPProbe(ip, d.config.Timeout)
	if err != nil {
		return nil, err
	}

	return &data.HostInfo{
		IP:           ip,
		MAC:          resp.MAC,
		DiscoveryWay: "arp",
		TTL:          64,
		RespondTime:  time.Since(start),
	}, nil
}

func (d *DiscoveryEngine) Run() error {
	ctx := context.Background()
	hosts, err := d.Discover(ctx, d.config.Targets)
	if err != nil {
		return err
	}

	fmt.Printf("[INFO] 发现 %d 个存活主机\n", len(hosts))

	for _, h := range hosts {
		fmt.Printf("  %s (%s) TTL: %d\n", h.IP, h.DiscoveryWay, h.TTL)
	}

	return nil
}
