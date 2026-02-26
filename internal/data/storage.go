package data

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
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
	data, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		return fmt.Errorf("JSON encoding failed: %w", err)
	}
	return os.WriteFile(s.outputFile, data, 0644)
}

func (s *Storage) SaveHosts(hosts []HostInfo, format string) error {
	data, err := json.MarshalIndent(hosts, "", "  ")
	if err != nil {
		return fmt.Errorf("JSON encoding failed: %w", err)
	}
	return os.WriteFile(s.outputFile, data, 0644)
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
	var results []ScanResult
	if err := json.Unmarshal(data, &results); err != nil {
		return nil, fmt.Errorf("JSON decoding failed: %w", err)
	}
	return results, nil
}

func SaveAnalysis(outputPath string, analysis []ProxyAnalysis) error {
	data, err := json.MarshalIndent(analysis, "", "  ")
	if err != nil {
		return fmt.Errorf("analysis encoding failed: %w", err)
	}
	return os.WriteFile(outputPath, data, 0644)
}
