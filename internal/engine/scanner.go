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

	workerCount := s.config.Concurrency
	if workerCount <= 0 {
		workerCount = 10
	}
	if workerCount > 500 {
		workerCount = 500
	}

	var wg sync.WaitGroup
	results := make(chan data.ScanResult, workerCount)

	type scanJob struct {
		IP   net.IP
		Port int
	}
	jobChan := make(chan scanJob, workerCount*2)

	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobChan {
				select {
				case <-ctx.Done():
					return
				case <-stopCh:
					return
				default:
				}

				rateLimiter.Wait()
				result := s.scanPort(ctx, job.IP, job.Port)
				select {
				case results <- result:
				case <-ctx.Done():
					return
				case <-stopCh:
					return
				}
			}
		}()
	}

	go func() {
		defer close(jobChan)
		for _, target := range targets {
			for _, port := range target.Ports {
				select {
				case jobChan <- scanJob{IP: target.IP, Port: port}:
				case <-stopCh:
					return
				case <-ctx.Done():
					return
				}
			}
		}
	}()

	go func() {
		wg.Wait()
		close(results)
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
