package engine

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/asset-probe/internal/data"
	"github.com/asset-probe/internal/network"
)

type PortScanner struct {
	config *PortScannerConfig

	stats   PortScannerStats
	paused  atomic.Bool
	stopped atomic.Bool
	mu      sync.RWMutex
}

type PortScannerConfig struct {
	Rate        int
	Concurrency int
	Timeout     time.Duration
	SrcIP       net.IP
	SrcPort     int
}

type PortScannerStats struct {
	TotalScanned  int64
	OpenPorts     int64
	ClosedPorts   int64
	FilteredPorts int64
}

func NewPortScanner(config *PortScannerConfig) *PortScanner {
	return &PortScanner{
		config: config,
	}
}

func (s *PortScanner) Scan(ctx context.Context, targets []ScanTarget, resultCh chan<- []data.ScanResult, pauseCh, resumeCh, stopCh chan struct{}) error {
	defer close(resultCh)

	rateLimiter := network.NewRateLimiter(s.config.Rate)

	var wg sync.WaitGroup
	workerCount := s.config.Concurrency
	if workerCount > 500 {
		workerCount = 500
	}

	traffic := make(chan ScanTarget, workerCount*2)
	results := make(chan data.ScanResult, workerCount)

	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go s.scanWorker(ctx, &wg, traffic, results, rateLimiter, pauseCh, resumeCh, stopCh)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	go func() {
		for _, target := range targets {
			for _, port := range target.Ports {
				select {
				case traffic <- ScanTarget{IP: target.IP, Ports: []int{port}}:
				case <-stopCh:
					return
				case <-ctx.Done():
					return
				}
			}
		}
		close(traffic)
	}()

	batch := make([]data.ScanResult, 0, 100)
	for r := range results {
		batch = append(batch, r)
		if len(batch) >= 100 {
			resultCh <- batch
			batch = make([]data.ScanResult, 0, 100)
		}

		s.mu.Lock()
		s.stats.TotalScanned++
		switch r.State {
		case "open":
			s.stats.OpenPorts++
		case "closed":
			s.stats.ClosedPorts++
		case "filtered":
			s.stats.FilteredPorts++
		}
		s.mu.Unlock()
	}

	if len(batch) > 0 {
		resultCh <- batch
	}

	return nil
}

func (s *PortScanner) scanWorker(ctx context.Context, wg *sync.WaitGroup, traffic <-chan ScanTarget, results chan<- data.ScanResult, rateLimiter *network.RateLimiter, pauseCh, resumeCh, stopCh chan struct{}) {
	defer wg.Done()

	for {
		select {
		case <-ctx.Done():
			return
		case <-stopCh:
			return
		case <-pauseCh:
			<-resumeCh
		case target, ok := <-traffic:
			if !ok {
				return
			}

			rateLimiter.Wait()

			port := target.Ports[0]
			result := s.scanPort(ctx, target.IP, port)
			results <- result
		}
	}
}

func (s *PortScanner) scanPort(ctx context.Context, ip net.IP, port int) data.ScanResult {
	result := data.ScanResult{
		IP:       ip,
		Port:     port,
		Protocol: "tcp",
		State:    "filtered",
	}

	resp, err := network.SendSYNProbe(ip, port, s.config.Timeout)
	if err != nil {
		return result
	}

	result.TTL = resp.TTL
	if resp.Open {
		result.State = "open"
	} else if resp.Closed {
		result.State = "closed"
	}

	return result
}

func (s *PortScanner) Stats() PortScannerStats {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.stats
}

func (s *PortScanner) Pause() {
	s.paused.Store(true)
}

func (s *PortScanner) Resume() {
	s.paused.Store(false)
}

func (s *PortScanner) Stop() {
	s.stopped.Store(true)
}
