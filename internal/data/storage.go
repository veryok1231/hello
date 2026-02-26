package data

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type ScanResult struct {
	IP        net.IP      `json:"ip"`
	Port      int         `json:"port"`
	Protocol  string      `json:"protocol"`
	State     string      `json:"state"`
	TTL       int         `json:"ttl"`
	Banner    []byte      `json:"banner,omitempty"`
	Service   ServiceInfo `json:"service,omitempty"`
	IsProxy   bool        `json:"is_proxy"`
	ProxyInfo *ProxyInfo  `json:"proxy_info,omitempty"`
}

type ServiceInfo struct {
	Name        string            `json:"name,omitempty"`
	Version     string            `json:"version,omitempty"`
	Product     string            `json:"product,omitempty"`
	OSType      string            `json:"os_type,omitempty"`
	CPE         string            `json:"cpe,omitempty"`
	Fingerprint string            `json:"fingerprint,omitempty"`
	RawBanner   string            `json:"raw_banner,omitempty"`
	Extra       map[string]string `json:"extra,omitempty"`
}

type ProxyInfo struct {
	Type        string   `json:"type"`
	Confidence  float64  `json:"confidence"`
	BackendIP   net.IP   `json:"backend_ip,omitempty"`
	BackendPort int      `json:"backend_port,omitempty"`
	Evidence    []string `json:"evidence,omitempty"`
}

type HostInfo struct {
	IP           net.IP           `json:"ip"`
	MAC          net.HardwareAddr `json:"mac,omitempty"`
	Hostname     string           `json:"hostname,omitempty"`
	DiscoveryWay string           `json:"discovery_way"`
	TTL          int              `json:"ttl"`
	RespondTime  time.Duration    `json:"respond_time"`
}

type ProxyAnalysis struct {
	Cidr             string         `json:"cidr,omitempty"`
	IsProxySubnet    bool           `json:"is_proxy_subnet"`
	AliveHostCount   int            `json:"alive_host_count,omitempty"`
	TotalHostCount   int            `json:"total_host_count,omitempty"`
	ProxyType        string         `json:"proxy_type"`
	Confidence       float64        `json:"confidence"`
	AffectedIPs      []net.IP       `json:"affected_ips,omitempty"`
	InferredBackends []BackendInfo  `json:"inferred_backends,omitempty"`
	TTLDifferences   map[string]int `json:"ttl_differences,omitempty"`
	FingerprintMatch map[string]int `json:"fingerprint_match,omitempty"`
}

type BackendInfo struct {
	IP         net.IP   `json:"ip,omitempty"`
	Port       int      `json:"port"`
	Service    string   `json:"service,omitempty"`
	Confidence float64  `json:"confidence"`
	Evidence   []string `json:"evidence,omitempty"`
}

type ScanState struct {
	LastIP       string    `json:"last_ip"`
	LastPort     int       `json:"last_port"`
	ScannedHosts int       `json:"scanned_hosts"`
	ScannedPorts int       `json:"scanned_ports"`
	Timestamp    time.Time `json:"timestamp"`
	Completed    []string  `json:"completed"`
	InProgress   []string  `json:"in_progress"`
}

type Storage struct {
	outputFile string
}

func NewStorage(outputFile string) (*Storage, error) {
	return &Storage{outputFile: outputFile}, nil
}

func (s *Storage) Save(results []ScanResult, format string) error {
	// 只保存存活主机（开放端口的）
	aliveResults := filterAliveResults(results)

	switch strings.ToLower(format) {
	case "json":
		return s.saveJSON(aliveResults)
	case "csv":
		return s.saveCSV(aliveResults)
	case "xml":
		return s.saveXML(aliveResults)
	case "txt", "text":
		return s.saveTXT(aliveResults)
	case "md", "markdown":
		return s.saveMarkdown(aliveResults)
	default:
		return s.saveJSON(aliveResults)
	}
}

func filterAliveResults(results []ScanResult) []ScanResult {
	var alive []ScanResult
	for _, r := range results {
		if r.State == "open" {
			alive = append(alive, r)
		}
	}
	return alive
}

func (s *Storage) saveJSON(results []ScanResult) error {
	data, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		return fmt.Errorf("JSON encoding failed: %w", err)
	}
	return os.WriteFile(s.outputFile, data, 0644)
}

func (s *Storage) saveCSV(results []ScanResult) error {
	file, err := os.Create(s.outputFile)
	if err != nil {
		return fmt.Errorf("create CSV file failed: %w", err)
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// 表头
	header := []string{"IP", "Port", "Protocol", "Service", "Product", "Version", "IsProxy", "ProxyType"}
	if err := writer.Write(header); err != nil {
		return err
	}

	for _, r := range results {
		record := []string{
			r.IP.String(),
			fmt.Sprintf("%d", r.Port),
			r.Protocol,
			r.Service.Name,
			r.Service.Product,
			r.Service.Version,
			fmt.Sprintf("%v", r.IsProxy),
		}
		if r.ProxyInfo != nil {
			record = append(record, r.ProxyInfo.Type)
		} else {
			record = append(record, "")
		}
		if err := writer.Write(record); err != nil {
			return err
		}
	}

	return nil
}

func (s *Storage) saveXML(results []ScanResult) error {
	// 按 IP 分组
	hostMap := make(map[string][]ScanResult)
	for _, r := range results {
		ip := r.IP.String()
		hostMap[ip] = append(hostMap[ip], r)
	}

	var sb strings.Builder
	sb.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
	sb.WriteString("<scan>\n")

	for ip, ports := range hostMap {
		sb.WriteString(fmt.Sprintf("  <host ip=\"%s\">\n", ip))
		for _, p := range ports {
			sb.WriteString(fmt.Sprintf("    <port number=\"%d\" protocol=\"%s\">\n", p.Port, p.Protocol))
			sb.WriteString(fmt.Sprintf("      <state>%s</state>\n", p.State))
			if p.Service.Name != "" {
				sb.WriteString(fmt.Sprintf("      <service>%s</service>\n", p.Service.Name))
			}
			if p.Service.Product != "" {
				sb.WriteString(fmt.Sprintf("      <product>%s</product>\n", p.Service.Product))
			}
			if p.Service.Version != "" {
				sb.WriteString(fmt.Sprintf("      <version>%s</version>\n", p.Service.Version))
			}
			sb.WriteString("    </port>\n")
		}
		sb.WriteString("  </host>\n")
	}

	sb.WriteString("</scan>\n")

	return os.WriteFile(s.outputFile, []byte(sb.String()), 0644)
}

func (s *Storage) saveTXT(results []ScanResult) error {
	var sb strings.Builder

	sb.WriteString("=" + strings.Repeat("=", 60) + "\n")
	sb.WriteString("                    存活主机端口扫描结果\n")
	sb.WriteString("=" + strings.Repeat("=", 60) + "\n\n")

	// 按 IP 分组
	hostMap := make(map[string][]ScanResult)
	for _, r := range results {
		ip := r.IP.String()
		hostMap[ip] = append(hostMap[ip], r)
	}

	for ip, ports := range hostMap {
		sb.WriteString(fmt.Sprintf("主机: %s\n", ip))
		sb.WriteString(strings.Repeat("-", 50) + "\n")

		// 获取第一个端口的服务信息
		if len(ports) > 0 {
			p := ports[0]
			if p.Service.Name != "" || p.Service.Product != "" {
				sb.WriteString(fmt.Sprintf("  服务: %s", p.Service.Name))
				if p.Service.Product != "" {
					sb.WriteString(fmt.Sprintf(" (%s", p.Service.Product))
					if p.Service.Version != "" {
						sb.WriteString(fmt.Sprintf(" %s", p.Service.Version))
					}
					sb.WriteString(")")
				}
				sb.WriteString("\n")
			}
		}

		sb.WriteString("  开放端口: ")
		portStrs := make([]string, len(ports))
		for i, p := range ports {
			portStrs[i] = fmt.Sprintf("%d", p.Port)
		}
		sb.WriteString(strings.Join(portStrs, ", "))
		sb.WriteString("\n")

		// 检查是否为代理
		for _, p := range ports {
			if p.IsProxy && p.ProxyInfo != nil {
				sb.WriteString(fmt.Sprintf("  [!] 检测到代答: %s (置信度: %.0f%%)\n", p.ProxyInfo.Type, p.ProxyInfo.Confidence*100))
			}
		}

		sb.WriteString("\n")
	}

	sb.WriteString("=" + strings.Repeat("=", 60) + "\n")
	sb.WriteString(fmt.Sprintf("共发现 %d 个存活主机，%d 个开放端口\n", len(hostMap), len(results)))
	sb.WriteString("=" + strings.Repeat("=", 60) + "\n")

	return os.WriteFile(s.outputFile, []byte(sb.String()), 0644)
}

func (s *Storage) saveMarkdown(results []ScanResult) error {
	var sb strings.Builder

	sb.WriteString("# 扫描结果报告\n\n")
	sb.WriteString(fmt.Sprintf("**扫描时间:** %s\n\n", time.Now().Format("2006-01-02 15:04:05")))

	// 按 IP 分组
	hostMap := make(map[string][]ScanResult)
	for _, r := range results {
		ip := r.IP.String()
		hostMap[ip] = append(hostMap[ip], r)
	}

	sb.WriteString("## 存活主机\n\n")
	sb.WriteString("| IP地址 | 开放端口 | 服务 | 产品/版本 | 代答 |\n")
	sb.WriteString("|--------|----------|------|-----------|------|\n")

	for ip, ports := range hostMap {
		portStrs := make([]string, len(ports))
		services := make(map[string]bool)
		products := make([]string, 0)
		isProxy := false
		proxyType := ""

		for i, p := range ports {
			portStrs[i] = fmt.Sprintf("%d", p.Port)
			if p.Service.Name != "" {
				services[p.Service.Name] = true
			}
			if p.Service.Product != "" {
				prod := p.Service.Product
				if p.Service.Version != "" {
					prod += " " + p.Service.Version
				}
				products = append(products, prod)
			}
			if p.IsProxy {
				isProxy = true
				if p.ProxyInfo != nil {
					proxyType = p.ProxyInfo.Type
				}
			}
		}

		serviceList := ""
		for svc := range services {
			if serviceList != "" {
				serviceList += ", "
			}
			serviceList += svc
		}

		productStr := ""
		if len(products) > 0 {
			productStr = products[0]
		}

		proxyStr := ""
		if isProxy {
			proxyStr = fmt.Sprintf("⚠️ %s", proxyType)
		}

		sb.WriteString(fmt.Sprintf("| %s | %s | %s | %s | %s |\n",
			ip, strings.Join(portStrs, ", "), serviceList, productStr, proxyStr))
	}

	sb.WriteString("\n## 统计信息\n\n")
	sb.WriteString(fmt.Sprintf("- 存活主机: %d\n", len(hostMap)))
	sb.WriteString(fmt.Sprintf("- 开放端口: %d\n", len(results)))
	sb.WriteString(fmt.Sprintf("- 平均端口/主机: %.1f\n", float64(len(results))/float64(len(hostMap))))

	return os.WriteFile(s.outputFile, []byte(sb.String()), 0644)
}

func (s *Storage) SaveHosts(hosts []HostInfo, format string) error {
	// 只保存存活主机
	if len(hosts) == 0 {
		return os.WriteFile(s.outputFile, []byte(""), 0644)
	}

	switch strings.ToLower(format) {
	case "txt", "text":
		return s.saveHostsTXT(hosts)
	case "csv":
		return s.saveHostsCSV(hosts)
	default:
		return s.saveHostsJSON(hosts)
	}
}

func (s *Storage) saveHostsTXT(hosts []HostInfo) error {
	var sb strings.Builder

	sb.WriteString("=" + strings.Repeat("=", 50) + "\n")
	sb.WriteString("              存活主机列表\n")
	sb.WriteString("=" + strings.Repeat("=", 50) + "\n\n")

	for _, h := range hosts {
		sb.WriteString(fmt.Sprintf("%-18s TTL: %-3d (%s)\n", h.IP.String(), h.TTL, h.DiscoveryWay))
	}

	sb.WriteString("\n" + strings.Repeat("-", 50) + "\n")
	sb.WriteString(fmt.Sprintf("共发现 %d 个存活主机\n", len(hosts)))

	return os.WriteFile(s.outputFile, []byte(sb.String()), 0644)
}

func (s *Storage) saveHostsJSON(hosts []HostInfo) error {
	data, err := json.MarshalIndent(hosts, "", "  ")
	if err != nil {
		return fmt.Errorf("JSON encoding failed: %w", err)
	}
	return os.WriteFile(s.outputFile, data, 0644)
}

func (s *Storage) saveHostsCSV(hosts []HostInfo) error {
	file, err := os.Create(s.outputFile)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	writer.Write([]string{"IP", "MAC", "TTL", "DiscoveryWay"})

	for _, h := range hosts {
		mac := ""
		if h.MAC != nil {
			mac = h.MAC.String()
		}
		writer.Write([]string{h.IP.String(), mac, fmt.Sprintf("%d", h.TTL), h.DiscoveryWay})
	}

	return nil
}

func (s *Storage) SaveState(state ScanState) error {
	state.Timestamp = time.Now()
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("state encoding failed: %w", err)
	}
	stateFile := s.outputFile + ".state"
	return os.WriteFile(stateFile, data, 0644)
}

func (s *Storage) LoadState() (*ScanState, error) {
	stateFile := s.outputFile + ".state"
	data, err := os.ReadFile(stateFile)
	if err != nil {
		return nil, fmt.Errorf("read state file failed: %w", err)
	}
	var state ScanState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("state decoding failed: %w", err)
	}
	return &state, nil
}

func LoadResults(filePath string) ([]ScanResult, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("read file failed: %w", err)
	}

	ext := strings.ToLower(filepath.Ext(filePath))
	if ext == ".txt" || ext == ".md" {
		return nil, fmt.Errorf("txt/md format not supported for input, use json")
	}

	var results []ScanResult
	if err := json.Unmarshal(data, &results); err != nil {
		return nil, fmt.Errorf("JSON decoding failed: %w", err)
	}
	return results, nil
}

func SaveAnalysis(outputPath string, analysis []ProxyAnalysis) error {
	// 根据文件扩展名选择格式
	ext := strings.ToLower(filepath.Ext(outputPath))

	if ext == ".txt" || ext == ".text" {
		return saveAnalysisTXT(outputPath, analysis)
	}

	data, err := json.MarshalIndent(analysis, "", "  ")
	if err != nil {
		return fmt.Errorf("analysis encoding failed: %w", err)
	}
	return os.WriteFile(outputPath, data, 0644)
}

func saveAnalysisTXT(outputPath string, analysis []ProxyAnalysis) error {
	var sb strings.Builder

	sb.WriteString("=" + strings.Repeat("=", 60) + "\n")
	sb.WriteString("                    代答资产分析报告\n")
	sb.WriteString("=" + strings.Repeat("=", 60) + "\n\n")

	for i, a := range analysis {
		sb.WriteString(fmt.Sprintf("[%d] 网段: %s\n", i+1, a.Cidr))
		sb.WriteString(fmt.Sprintf("    类型: %s\n", a.ProxyType))
		sb.WriteString(fmt.Sprintf("    置信度: %.0f%%\n", a.Confidence*100))
		sb.WriteString(fmt.Sprintf("    存活主机: %d/%d\n", a.AliveHostCount, a.TotalHostCount))

		if len(a.AffectedIPs) > 0 {
			sb.WriteString("    受影响IP: ")
			for j, ip := range a.AffectedIPs {
				if j > 0 && j%8 == 0 {
					sb.WriteString("\n               ")
				}
				sb.WriteString(ip.String() + " ")
			}
			sb.WriteString("\n")
		}

		if len(a.InferredBackends) > 0 {
			sb.WriteString("    推断后端:\n")
			for _, b := range a.InferredBackends {
				if b.IP != nil {
					sb.WriteString(fmt.Sprintf("      - %s:%d (%s)\n", b.IP.String(), b.Port, b.Service))
				}
			}
		}

		sb.WriteString("\n")
	}

	sb.WriteString("=" + strings.Repeat("=", 60) + "\n")

	return os.WriteFile(outputPath, []byte(sb.String()), 0644)
}
