package engine

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/asset-probe/internal/data"
)

type ServiceDetector struct {
	config       *ServiceDetectorConfig
	fingerprints []Fingerprint
	mu           sync.RWMutex
}

type ServiceDetectorConfig struct {
	Timeout       time.Duration
	MaxProbes     int
	FingerprintDB string
}

type Fingerprint struct {
	Service   string
	Product   string
	Version   string
	Pattern   *regexp.Regexp
	CPE       string
	MatchType string
}

func NewServiceDetector(config *ServiceDetectorConfig) *ServiceDetector {
	sd := &ServiceDetector{
		config: config,
	}
	sd.loadDefaultFingerprints()
	return sd
}

func (s *ServiceDetector) Detect(ctx context.Context, ip net.IP, port int) (data.ServiceInfo, error) {
	info := data.ServiceInfo{}

	banner, err := s.grabBanner(ctx, ip, port)
	if err != nil {
		return info, err
	}
	info.RawBanner = string(banner)

	matched := s.matchFingerprint(banner)
	if matched != nil {
		info.Name = matched.Service
		info.Product = matched.Product
		info.Version = matched.Version
		info.CPE = matched.CPE
		info.Fingerprint = matched.Pattern.String()
	}

	if info.Name == "" {
		info = s.identifyByPort(port, banner)
	}

	return info, nil
}

func (s *ServiceDetector) grabBanner(ctx context.Context, ip net.IP, port int) ([]byte, error) {
	d := net.Dialer{Timeout: s.config.Timeout}
	conn, err := d.DialContext(ctx, "tcp", fmt.Sprintf("%s:%d", ip.String(), port))
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	probes := s.getProbesForPort(port)
	for _, probe := range probes {
		if _, err := conn.Write([]byte(probe)); err != nil {
			continue
		}

		conn.SetReadDeadline(time.Now().Add(s.config.Timeout))
		reader := bufio.NewReader(conn)

		response := make([]byte, 4096)
		n, err := reader.Read(response)
		if err != nil {
			continue
		}

		if n > 0 {
			return response[:n], nil
		}
	}

	conn.SetReadDeadline(time.Now().Add(s.config.Timeout))
	reader := bufio.NewReader(conn)
	response := make([]byte, 4096)
	n, err := reader.Read(response)
	if err != nil {
		return nil, err
	}

	return response[:n], nil
}

func (s *ServiceDetector) getProbesForPort(port int) []string {
	probes := []string{""}

	switch {
	case port == 80:
		probes = append(probes, "GET / HTTP/1.0\r\n\r\n")
	case port == 443:
		probes = append(probes, "GET / HTTP/1.0\r\nHost: localhost\r\n\r\n")
	case port == 21:
		probes = append(probes, "")
	case port == 22:
		probes = append(probes, "")
	case port == 25 || port == 587:
		probes = append(probes, "EHLO localhost\r\n")
	case port == 110 || port == 143 || port == 993 || port == 995:
		probes = append(probes, "")
	case port == 3306:
		probes = append(probes, "")
	}

	return probes
}

func (s *ServiceDetector) matchFingerprint(banner []byte) *Fingerprint {
	s.mu.RLock()
	defer s.mu.RUnlock()

	bannerStr := string(banner)
	for i := range s.fingerprints {
		if s.fingerprints[i].Pattern.MatchString(bannerStr) {
			return &s.fingerprints[i]
		}
	}

	return nil
}

func (s *ServiceDetector) identifyByPort(port int, banner []byte) data.ServiceInfo {
	info := data.ServiceInfo{}
	bannerStr := strings.ToLower(string(banner))

	switch port {
	case 21:
		info.Name = "ftp"
		if strings.Contains(bannerStr, "vsftpd") {
			info.Product = "vsftpd"
		} else if strings.Contains(bannerStr, "proftpd") {
			info.Product = "ProFTPD"
		}
	case 22:
		info.Name = "ssh"
		if strings.Contains(bannerStr, "openssh") {
			info.Product = "OpenSSH"
		}
	case 23:
		info.Name = "telnet"
	case 25, 587:
		info.Name = "smtp"
		if strings.Contains(bannerStr, "postfix") {
			info.Product = "Postfix"
		} else if strings.Contains(bannerStr, "exim") {
			info.Product = "Exim"
		} else if strings.Contains(bannerStr, "sendmail") {
			info.Product = "Sendmail"
		}
	case 53:
		info.Name = "dns"
		if strings.Contains(bannerStr, "bind") {
			info.Product = "BIND"
		}
	case 80, 8080, 8000, 8888:
		info.Name = "http"
		info = s.identifyHTTPServer(bannerStr, info)
	case 110:
		info.Name = "pop3"
	case 143:
		info.Name = "imap"
	case 443, 8443:
		info.Name = "https"
		info = s.identifyHTTPServer(bannerStr, info)
	case 3306:
		info.Name = "mysql"
		if strings.Contains(bannerStr, "mariadb") {
			info.Product = "MariaDB"
		} else {
			info.Product = "MySQL"
		}
	case 3389:
		info.Name = "rdp"
		info.Product = "Microsoft Terminal Services"
	case 5432:
		info.Name = "postgresql"
		info.Product = "PostgreSQL"
	case 6379:
		info.Name = "redis"
		info.Product = "Redis"
	case 27017:
		info.Name = "mongodb"
		info.Product = "MongoDB"
	case 9200:
		info.Name = "elasticsearch"
		info.Product = "Elasticsearch"
	default:
		info.Name = "unknown"
	}

	return info
}

func (s *ServiceDetector) identifyHTTPServer(bannerStr string, info data.ServiceInfo) data.ServiceInfo {
	switch {
	case strings.Contains(bannerStr, "nginx"):
		info.Product = "nginx"
	case strings.Contains(bannerStr, "apache"):
		info.Product = "Apache httpd"
	case strings.Contains(bannerStr, "microsoft-iis"):
		info.Product = "Microsoft IIS"
	case strings.Contains(bannerStr, "lighttpd"):
		info.Product = "lighttpd"
	case strings.Contains(bannerStr, "caddy"):
		info.Product = "Caddy"
	case strings.Contains(bannerStr, "tomcat"):
		info.Product = "Apache Tomcat"
	case strings.Contains(bannerStr, "jetty"):
		info.Product = "Jetty"
	}
	return info
}

func (s *ServiceDetector) loadDefaultFingerprints() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.fingerprints = []Fingerprint{
		{
			Service: "ssh",
			Product: "OpenSSH",
			Pattern: regexp.MustCompile(`(?i)^SSH-2\.0-OpenSSH[_\s]([\d\.p]+)`),
		},
		{
			Service: "ftp",
			Product: "vsftpd",
			Pattern: regexp.MustCompile(`(?i)^220.*vsftpd\s*([\d\.]+)`),
		},
		{
			Service: "http",
			Product: "nginx",
			Pattern: regexp.MustCompile(`(?i)^Server:\s*nginx/([\d\.]+)`),
		},
		{
			Service: "http",
			Product: "Apache httpd",
			Pattern: regexp.MustCompile(`(?i)^Server:\s*Apache(/([\d\.]+))?`),
		},
		{
			Service: "mysql",
			Product: "MySQL",
			Pattern: regexp.MustCompile(`^[\x00-\xff]{1,2}\x00\x00\x00([\d\.]+)-`),
		},
		{
			Service: "redis",
			Product: "Redis",
			Pattern: regexp.MustCompile(`^-NOAUTH\s|^-ERR\s|^\+OK|^\+PONG`),
		},
		{
			Service: "smtp",
			Product: "Postfix",
			Pattern: regexp.MustCompile(`(?i)^220.*ESMTP\s+Postfix`),
		},
		{
			Service: "vnc",
			Product: "VNC",
			Pattern: regexp.MustCompile(`^RFB\s+(\d+\.\d+)`),
		},
		{
			Service: "rdp",
			Product: "Microsoft Terminal Services",
			Pattern: regexp.MustCompile(`^\x03\x00\x00\x0b\x06\xd0\x00\x00`),
		},
	}
}

func (s *ServiceDetector) AddFingerprint(fp Fingerprint) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.fingerprints = append(s.fingerprints, fp)
	return nil
}
