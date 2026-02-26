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
	config    *Config
	socket    *network.RawSocket
	rateLimit *network.RateLimiter
}

func NewDiscoveryEngine(config *Config) *DiscoveryEngine {
	return &DiscoveryEngine{
		config:    config,
		rateLimit: network.NewRateLimiter(config.Rate),
	}
}

func (d *DiscoveryEngine) Discover(ctx context.Context, cidrs []string) ([]data.HostInfo, error) {
	var hosts []data.HostInfo
	var mu sync.Mutex

	var allIPs []net.IP
	for _, cidr := range cidrs {
		ips, err := utils.ParseCIDR(cidr)
		if err != nil {
			return nil, fmt.Errorf("解析CIDR失败 %s: %w", cidr, err)
		}
		allIPs = append(allIPs, ips...)
	}

	fmt.Printf("[INFO] 目标IP总数: %d\n", len(allIPs))

	if len(allIPs) == 0 {
		return hosts, nil
	}

	workerCount := d.config.Concurrency
	if workerCount <= 0 {
		workerCount = 10
	}
	if workerCount > 100 {
		workerCount = 100
	}

	var wg sync.WaitGroup
	resultCh := make(chan *data.HostInfo, workerCount)

	ipChan := make(chan net.IP, workerCount*2)

	go func() {
		for _, ip := range allIPs {
			select {
			case ipChan <- ip:
			case <-ctx.Done():
				return
			}
		}
		close(ipChan)
	}()

	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ip := range ipChan {
				select {
				case <-ctx.Done():
					return
				default:
					if host := d.probeHost(ctx, ip); host != nil {
						select {
						case resultCh <- host:
						case <-ctx.Done():
							return
						}
					}
				}
			}
		}()
	}

	go func() {
		wg.Wait()
		close(resultCh)
	}()

	for host := range resultCh {
		mu.Lock()
		hosts = append(hosts, *host)
		mu.Unlock()
	}

	return hosts, nil
}

func (d *DiscoveryEngine) probeHost(ctx context.Context, ip net.IP) *data.HostInfo {
	methods := d.config.DiscoveryMethods
	if len(methods) == 0 {
		methods = []string{"icmp", "tcp"}
	}

	for _, method := range methods {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		var host *data.HostInfo
		var err error

		switch method {
		case "icmp":
			host, err = d.probeICMP(ctx, ip)
		case "tcp":
			host, err = d.probeTCP(ctx, ip)
		case "arp":
			host, err = d.probeARP(ctx, ip)
		}

		if err == nil && host != nil {
			return host
		}
	}
	return nil
}

func (d *DiscoveryEngine) probeICMP(ctx context.Context, ip net.IP) (*data.HostInfo, error) {
	d.rateLimit.Wait()

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

func (d *DiscoveryEngine) probeTCP(ctx context.Context, ip net.IP) (*data.HostInfo, error) {
	probePorts := []int{80, 443, 22, 3389, 8080}

	for _, port := range probePorts {
		d.rateLimit.Wait()

		start := time.Now()
		resp, err := network.SendSYNProbe(ip, port, d.config.Timeout)
		if err != nil {
			continue
		}

		if resp.Open {
			return &data.HostInfo{
				IP:           ip,
				DiscoveryWay: "tcp",
				TTL:          resp.TTL,
				RespondTime:  time.Since(start),
			}, nil
		}
	}

	return nil, fmt.Errorf("no response")
}

func (d *DiscoveryEngine) probeARP(ctx context.Context, ip net.IP) (*data.HostInfo, error) {
	if !ip.IsPrivate() && !ip.IsLoopback() {
		return nil, fmt.Errorf("ARP only works on local network")
	}

	d.rateLimit.Wait()

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
