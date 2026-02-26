package engine

import (
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/asset-probe/internal/data"
)

type ProxyAnalyzer struct {
	config *ProxyAnalyzerConfig
}

func NewProxyAnalyzer(config *ProxyAnalyzerConfig) *ProxyAnalyzer {
	return &ProxyAnalyzer{config: config}
}

func (a *ProxyAnalyzer) Analyze(results []data.ScanResult) []data.ProxyAnalysis {
	var analyses []data.ProxyAnalysis

	subnetAnalysis := a.analyzeSubnets(results)
	for _, analysis := range subnetAnalysis {
		analyses = append(analyses, analysis)
	}

	ttlAnalysis := a.analyzeTTL(results)
	for ip, ttls := range ttlAnalysis {
		analysis := data.ProxyAnalysis{
			AffectedIPs:    []net.IP{net.ParseIP(ip)},
			TTLDifferences: map[string]int{ip: a.calculateTTLDiff(ttls)},
			ProxyType:      "multi-hop",
			Confidence:     0.7,
		}
		analyses = append(analyses, analysis)
	}

	fingerprintAnalysis := a.analyzeFingerprints(results)
	for _, analysis := range fingerprintAnalysis {
		analyses = append(analyses, analysis)
	}

	analyses = a.inferBackends(results, analyses)

	return analyses
}

func (a *ProxyAnalyzer) analyzeSubnets(results []data.ScanResult) []data.ProxyAnalysis {
	subnetMap := make(map[string][]data.ScanResult)

	for _, r := range results {
		if r.State == "open" {
			subnet := a.getSubnetC(r.IP)
			subnetMap[subnet] = append(subnetMap[subnet], r)
		}
	}

	var analyses []data.ProxyAnalysis
	for cidr, hosts := range subnetMap {
		uniqueIPs := make(map[string]bool)
		for _, h := range hosts {
			uniqueIPs[h.IP.String()] = true
		}

		aliveCount := len(uniqueIPs)
		if aliveCount >= a.config.SubnetThreshold {
			analysis := data.ProxyAnalysis{
				Cidr:           cidr,
				IsProxySubnet:  true,
				AliveHostCount: aliveCount,
				TotalHostCount: 256,
				ProxyType:      "nat-proxy",
				Confidence:     0.95,
				AffectedIPs:    a.getUniqueIPs(hosts),
			}
			analyses = append(analyses, analysis)
		}
	}

	return analyses
}

func (a *ProxyAnalyzer) analyzeTTL(results []data.ScanResult) map[string][]int {
	ipTTLMap := make(map[string][]int)

	for _, r := range results {
		if r.State == "open" && r.TTL > 0 {
			ip := r.IP.String()
			ipTTLMap[ip] = append(ipTTLMap[ip], r.TTL)
		}
	}

	differences := make(map[string][]int)
	for ip, ttls := range ipTTLMap {
		if len(ttls) >= 2 {
			diff := a.calculateTTLDiff(ttls)
			if diff > a.config.TTLThreshold {
				differences[ip] = ttls
			}
		}
	}

	return differences
}

func (a *ProxyAnalyzer) calculateTTLDiff(ttls []int) int {
	if len(ttls) == 0 {
		return 0
	}

	min, max := ttls[0], ttls[0]
	for _, t := range ttls {
		if t < min {
			min = t
		}
		if t > max {
			max = t
		}
	}
	return max - min
}

func (a *ProxyAnalyzer) analyzeFingerprints(results []data.ScanResult) []data.ProxyAnalysis {
	fingerprintMap := make(map[string][]data.ScanResult)

	for _, r := range results {
		if r.State == "open" && r.Service.Fingerprint != "" {
			key := r.Service.Fingerprint
			fingerprintMap[key] = append(fingerprintMap[key], r)
		} else if r.State == "open" && r.Service.Product != "" {
			key := fmt.Sprintf("%s:%s", r.Service.Name, r.Service.Product)
			fingerprintMap[key] = append(fingerprintMap[key], r)
		}
	}

	var analyses []data.ProxyAnalysis
	for fp, hosts := range fingerprintMap {
		if len(hosts) >= 2 {
			uniqueIPs := make(map[string]bool)
			for _, h := range hosts {
				uniqueIPs[h.IP.String()] = true
			}

			if len(uniqueIPs) >= 2 {
				analysis := data.ProxyAnalysis{
					ProxyType:        "reverse-proxy",
					Confidence:       0.8,
					AffectedIPs:      a.getUniqueIPs(hosts),
					FingerprintMatch: map[string]int{fp: len(uniqueIPs)},
				}
				analyses = append(analyses, analysis)
			}
		}
	}

	return analyses
}

func (a *ProxyAnalyzer) inferBackends(results []data.ScanResult, analyses []data.ProxyAnalysis) []data.ProxyAnalysis {
	for i := range analyses {
		if analyses[i].ProxyType == "nat-proxy" && analyses[i].Confidence >= 0.9 {
			analyses[i].InferredBackends = a.inferBackendsFromSubnet(results, analyses[i])
		} else if analyses[i].ProxyType == "reverse-proxy" {
			analyses[i].InferredBackends = a.inferBackendsFromFingerprint(results, analyses[i])
		}
	}

	return analyses
}

func (a *ProxyAnalyzer) inferBackendsFromSubnet(results []data.ScanResult, analysis data.ProxyAnalysis) []data.BackendInfo {
	var backends []data.BackendInfo

	portServiceMap := make(map[int]map[string]int)
	for _, r := range results {
		if r.State == "open" {
			if _, ok := portServiceMap[r.Port]; !ok {
				portServiceMap[r.Port] = make(map[string]int)
			}
			svc := r.Service.Name
			if svc == "" {
				svc = "unknown"
			}
			portServiceMap[r.Port][svc]++
		}
	}

	for port, services := range portServiceMap {
		if len(services) == 1 {
			for svc := range services {
				backends = append(backends, data.BackendInfo{
					Port:       port,
					Service:    svc,
					Confidence: 0.7,
					Evidence:   []string{fmt.Sprintf("Uniform service %s on port %d across subnet", svc, port)},
				})
			}
		}
	}

	sort.Slice(backends, func(i, j int) bool {
		return backends[i].Confidence > backends[j].Confidence
	})

	if len(backends) > 5 {
		backends = backends[:5]
	}

	return backends
}

func (a *ProxyAnalyzer) inferBackendsFromFingerprint(results []data.ScanResult, analysis data.ProxyAnalysis) []data.BackendInfo {
	var backends []data.BackendInfo

	affectedSet := make(map[string]bool)
	for _, ip := range analysis.AffectedIPs {
		affectedSet[ip.String()] = true
	}

	for _, r := range results {
		if r.State == "open" && !affectedSet[r.IP.String()] {
			for _, affected := range analysis.AffectedIPs {
				if a.similarService(r.Service, a.getServiceForIP(results, affected)) {
					backend := data.BackendInfo{
						IP:         r.IP,
						Port:       r.Port,
						Service:    r.Service.Name,
						Confidence: 0.6,
						Evidence:   []string{"Similar service fingerprint match"},
					}
					backends = append(backends, backend)
				}
			}
		}
	}

	return backends
}

func (a *ProxyAnalyzer) similarService(s1, s2 data.ServiceInfo) bool {
	if s1.Name != "" && s2.Name != "" && s1.Name == s2.Name {
		if s1.Product != "" && s2.Product != "" {
			return s1.Product == s2.Product
		}
		return true
	}
	return false
}

func (a *ProxyAnalyzer) getServiceForIP(results []data.ScanResult, ip net.IP) data.ServiceInfo {
	for _, r := range results {
		if r.IP.Equal(ip) && r.State == "open" {
			return r.Service
		}
	}
	return data.ServiceInfo{}
}

func (a *ProxyAnalyzer) getSubnetC(ip net.IP) string {
	if ip.To4() == nil {
		return ip.String()
	}
	return fmt.Sprintf("%d.%d.%d.0/24", ip[0], ip[1], ip[2])
}

func (a *ProxyAnalyzer) getUniqueIPs(results []data.ScanResult) []net.IP {
	ipSet := make(map[string]net.IP)
	for _, r := range results {
		ipSet[r.IP.String()] = r.IP
	}

	var ips []net.IP
	for _, ip := range ipSet {
		ips = append(ips, ip)
	}
	return ips
}

func (a *ProxyAnalyzer) GenerateReport(analyses []data.ProxyAnalysis) string {
	var sb strings.Builder

	sb.WriteString("========== 代答资产分析报告 ==========\n\n")

	for i, analysis := range analyses {
		sb.WriteString(fmt.Sprintf("--- 分析结果 #%d ---\n", i+1))

		if analysis.Cidr != "" {
			sb.WriteString(fmt.Sprintf("网段: %s\n", analysis.Cidr))
		}

		sb.WriteString(fmt.Sprintf("代答类型: %s\n", analysis.ProxyType))
		sb.WriteString(fmt.Sprintf("置信度: %.2f%%\n", analysis.Confidence*100))

		if analysis.IsProxySubnet {
			sb.WriteString(fmt.Sprintf("存活主机: %d/%d\n", analysis.AliveHostCount, analysis.TotalHostCount))
		}

		if len(analysis.AffectedIPs) > 0 {
			sb.WriteString(fmt.Sprintf("受影响IP数量: %d\n", len(analysis.AffectedIPs)))
			if len(analysis.AffectedIPs) <= 10 {
				sb.WriteString("受影响IP列表:\n")
				for _, ip := range analysis.AffectedIPs {
					sb.WriteString(fmt.Sprintf("  - %s\n", ip.String()))
				}
			}
		}

		if len(analysis.InferredBackends) > 0 {
			sb.WriteString("推断的后端服务:\n")
			for _, backend := range analysis.InferredBackends {
				if backend.IP != nil {
					sb.WriteString(fmt.Sprintf("  - %s:%d (%s) [置信度: %.2f%%]\n",
						backend.IP.String(), backend.Port, backend.Service, backend.Confidence*100))
				} else {
					sb.WriteString(fmt.Sprintf("  - :%d (%s) [置信度: %.2f%%]\n",
						backend.Port, backend.Service, backend.Confidence*100))
				}
				for _, e := range backend.Evidence {
					sb.WriteString(fmt.Sprintf("      证据: %s\n", e))
				}
			}
		}

		sb.WriteString("\n")
	}

	return sb.String()
}

type AnalysisResult struct {
	Analyses []data.ProxyAnalysis `json:"analyses"`
	Summary  AnalysisSummary      `json:"summary"`
}

type AnalysisSummary struct {
	TotalSubnetsScanned  int     `json:"total_subnets_scanned"`
	ProxySubnetsDetected int     `json:"proxy_subnets_detected"`
	TotalAffectedIPs     int     `json:"total_affected_ips"`
	AverageConfidence    float64 `json:"average_confidence"`
}

func (a *ProxyAnalyzer) Summarize(analyses []data.ProxyAnalysis) AnalysisSummary {
	summary := AnalysisSummary{
		TotalSubnetsScanned: len(analyses),
	}

	affectedSet := make(map[string]bool)
	var totalConfidence float64

	for _, analysis := range analyses {
		if analysis.IsProxySubnet {
			summary.ProxySubnetsDetected++
		}

		for _, ip := range analysis.AffectedIPs {
			affectedSet[ip.String()] = true
		}

		totalConfidence += analysis.Confidence
	}

	summary.TotalAffectedIPs = len(affectedSet)
	if len(analyses) > 0 {
		summary.AverageConfidence = totalConfidence / float64(len(analyses))
	}

	return summary
}
