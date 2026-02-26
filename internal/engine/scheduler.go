package engine

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/asset-probe/internal/data"
	"github.com/asset-probe/pkg/utils"
)

type Scheduler struct {
	config        *Config
	discovery     *DiscoveryEngine
	scanner       *PortScanner
	serviceDet    *ServiceDetector
	proxyAnalyzer *ProxyAnalyzer
	storage       *data.Storage
	whitelist     *utils.Whitelist

	status   ScanStatus
	pauseCh  chan struct{}
	resumeCh chan struct{}
	stopCh   chan struct{}
	paused   atomic.Bool
	stopped  atomic.Bool

	mu sync.RWMutex
}

func NewScheduler(config *Config) *Scheduler {
	return &Scheduler{
		config:   config,
		pauseCh:  make(chan struct{}),
		resumeCh: make(chan struct{}),
		stopCh:   make(chan struct{}),
	}
}

func (s *Scheduler) SetWhitelist(w *utils.Whitelist) {
	s.whitelist = w
}

func (s *Scheduler) Start() error {
	s.status.StartTime = time.Now()

	if err := s.initComponents(); err != nil {
		return fmt.Errorf("初始化组件失败: %w", err)
	}

	if s.config.Resume {
		if err := s.loadState(); err != nil {
			fmt.Printf("[WARN] 加载扫描状态失败，将从头开始: %v\n", err)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go s.monitorStatus()

	var allResults []data.ScanResult

	fmt.Printf("[INFO] 开始主机发现...\n")
	hosts, err := s.discovery.Discover(ctx, s.config.Targets)
	if err != nil {
		return fmt.Errorf("主机发现失败: %w", err)
	}
	fmt.Printf("[INFO] 发现 %d 个存活主机\n", len(hosts))

	if s.config.DiscoveryOnly {
		return s.saveHostResults(hosts)
	}

	s.status.TotalHosts = len(hosts)
	ports := utils.ParsePortRange(s.config.PortRange)
	s.status.TotalPorts = len(hosts) * len(ports)
	fmt.Printf("[INFO] 扫描 %d 个端口\n", len(ports))

	fmt.Printf("[INFO] 开始端口扫描...\n")
	results, err := s.scanPorts(ctx, hosts, ports)
	if err != nil {
		return fmt.Errorf("端口扫描失败: %w", err)
	}
	allResults = append(allResults, results...)

	if s.config.ServiceDetection {
		fmt.Printf("[INFO] 开始服务识别...\n")
		s.detectServices(ctx, allResults)
	}

	if s.config.ProxyDetection {
		fmt.Printf("[INFO] 开始代答分析...\n")
		analysis := s.proxyAnalyzer.Analyze(allResults)
		s.applyProxyInfo(allResults, analysis)
	}

	if err := s.saveResults(allResults); err != nil {
		return fmt.Errorf("保存结果失败: %w", err)
	}

	s.printSummary(allResults)
	return nil
}

func (s *Scheduler) initComponents() error {
	storage, err := data.NewStorage(s.config.OutputFile)
	if err != nil {
		return err
	}
	s.storage = storage

	s.discovery = NewDiscoveryEngine(s.config)

	s.scanner = NewPortScanner(&PortScannerConfig{
		Rate:        s.config.Rate,
		Concurrency: s.config.Concurrency,
		Timeout:     s.config.Timeout,
	})

	s.serviceDet = NewServiceDetector(&ServiceDetectorConfig{
		Timeout: s.config.Timeout * 2,
	})

	s.proxyAnalyzer = NewProxyAnalyzer(&ProxyAnalyzerConfig{
		SubnetThreshold: 254,
		TTLThreshold:    3,
	})

	return nil
}

func (s *Scheduler) scanPorts(ctx context.Context, hosts []data.HostInfo, ports []int) ([]data.ScanResult, error) {
	var results []data.ScanResult
	resultCh := make(chan []data.ScanResult, 100)

	targets := make([]ScanTarget, len(hosts))
	for i, h := range hosts {
		targets[i] = ScanTarget{IP: h.IP, Ports: ports}
	}

	go func() {
		if err := s.scanner.Scan(ctx, targets, resultCh, s.pauseCh, s.resumeCh, s.stopCh); err != nil {
			fmt.Printf("[ERROR] 扫描错误: %v\n", err)
		}
	}()

	for batch := range resultCh {
		results = append(results, batch...)
		s.mu.Lock()
		s.status.ScannedPorts += len(batch)
		s.mu.Unlock()

		if s.stopped.Load() {
			break
		}
	}

	return results, nil
}

func (s *Scheduler) detectServices(ctx context.Context, results []data.ScanResult) {
	var wg sync.WaitGroup
	sem := make(chan struct{}, s.config.Concurrency)

	for i := range results {
		if results[i].State != "open" {
			continue
		}

		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			svc, err := s.serviceDet.Detect(ctx, results[idx].IP, results[idx].Port)
			if err == nil {
				results[idx].Service = svc
			}
		}(i)
	}
	wg.Wait()
}

func (s *Scheduler) applyProxyInfo(results []data.ScanResult, analysis []data.ProxyAnalysis) {
	proxyMap := make(map[string]*data.ProxyInfo)
	for _, a := range analysis {
		for _, ip := range a.AffectedIPs {
			proxyMap[ip.String()] = &data.ProxyInfo{
				Type:       a.ProxyType,
				Confidence: a.Confidence,
			}
			if len(a.InferredBackends) > 0 {
				proxyMap[ip.String()].BackendIP = a.InferredBackends[0].IP
				proxyMap[ip.String()].BackendPort = a.InferredBackends[0].Port
			}
		}
	}

	for i := range results {
		if pi, ok := proxyMap[results[i].IP.String()]; ok {
			results[i].IsProxy = true
			results[i].ProxyInfo = pi
		}
	}
}

func (s *Scheduler) saveHostResults(hosts []data.HostInfo) error {
	return s.storage.SaveHosts(hosts, s.config.OutputFormat)
}

func (s *Scheduler) saveResults(results []data.ScanResult) error {
	return s.storage.Save(results, s.config.OutputFormat)
}

func (s *Scheduler) loadState() error {
	state, err := s.storage.LoadState()
	if err != nil {
		return err
	}
	s.status.ScannedHosts = state.ScannedHosts
	s.status.ScannedPorts = state.ScannedPorts
	return nil
}

func (s *Scheduler) monitorStatus() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			s.mu.RLock()
			elapsed := time.Since(s.status.StartTime)
			s.status.CurrentRate = 0
			s.status.EstimatedEnd = time.Time{}

			if s.status.ScannedPorts > 0 && elapsed.Seconds() > 0 {
				rate := float64(s.status.ScannedPorts) / elapsed.Seconds()
				s.status.CurrentRate = int(rate)

				if s.status.TotalPorts > 0 && rate > 0 {
					remaining := float64(s.status.TotalPorts-s.status.ScannedPorts) / rate
					if remaining > 0 {
						s.status.EstimatedEnd = time.Now().Add(time.Duration(remaining) * time.Second)
					}
				}
			}

			progress := 0.0
			if s.status.TotalPorts > 0 {
				progress = float64(s.status.ScannedPorts) / float64(s.status.TotalPorts) * 100
			}

			remainingStr := "计算中..."
			if !s.status.EstimatedEnd.IsZero() {
				remainingStr = time.Until(s.status.EstimatedEnd).Round(time.Second).String()
			}

			fmt.Printf("\r[进度] %.1f%% | 已扫描: %d/%d 端口 | 速率: %d PPS | 预计剩余: %s  ",
				progress, s.status.ScannedPorts, s.status.TotalPorts, s.status.CurrentRate, remainingStr)
			s.mu.RUnlock()

		case <-s.stopCh:
			return
		}
	}
}

func (s *Scheduler) Pause() {
	s.paused.Store(true)
	s.pauseCh <- struct{}{}
}

func (s *Scheduler) Resume() {
	s.paused.Store(false)
	s.resumeCh <- struct{}{}
}

func (s *Scheduler) Stop() {
	s.stopped.Store(true)
	s.stopCh <- struct{}{}
}

func (s *Scheduler) Status() ScanStatus {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.status
}

func (s *Scheduler) printSummary(results []data.ScanResult) {
	fmt.Printf("\n\n========== 扫描摘要 ==========\n")
	fmt.Printf("总扫描端口: %d\n", len(results))

	openPorts := 0
	proxyAssets := 0
	serviceMap := make(map[string]int)

	for _, r := range results {
		if r.State == "open" {
			openPorts++
			if r.IsProxy {
				proxyAssets++
			}
			if r.Service.Name != "" {
				serviceMap[r.Service.Name]++
			}
		}
	}

	fmt.Printf("开放端口: %d\n", openPorts)
	fmt.Printf("代答资产: %d\n", proxyAssets)
	fmt.Printf("\n服务分布:\n")
	for svc, count := range serviceMap {
		fmt.Printf("  %s: %d\n", svc, count)
	}
	fmt.Printf("结果已保存到: %s\n", s.config.OutputFile)
}
