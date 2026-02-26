package utils

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

func ParseCIDR(cidr string) ([]net.IP, error) {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR format: %w", err)
	}

	ones, bits := ipnet.Mask.Size()
	totalIPs := 1 << (bits - ones)

	maxIPs := 2 << 23
	if totalIPs > maxIPs {
		return nil, fmt.Errorf("CIDR range too large (max /9 for two A segments), got %d IPs", totalIPs)
	}

	var ips []net.IP
	for ip := ipnet.IP.Mask(ipnet.Mask); ipnet.Contains(ip); incIP(ip) {
		newIP := make(net.IP, len(ip))
		copy(newIP, ip)
		ips = append(ips, newIP)
	}

	if len(ips) > 2 {
		ips = ips[1 : len(ips)-1]
	}

	return ips, nil
}

func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func ParsePortRange(portStr string) []int {
	if portStr == "" {
		portStr = "1-65535"
	}

	var ports []int
	portMap := make(map[int]bool)

	parts := strings.Split(portStr, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		if strings.Contains(part, "-") {
			rangeParts := strings.Split(part, "-")
			if len(rangeParts) != 2 {
				continue
			}

			start, err1 := strconv.Atoi(strings.TrimSpace(rangeParts[0]))
			end, err2 := strconv.Atoi(strings.TrimSpace(rangeParts[1]))

			if err1 != nil || err2 != nil {
				continue
			}

			if start > end {
				start, end = end, start
			}

			for i := start; i <= end; i++ {
				if i >= 1 && i <= 65535 && !portMap[i] {
					ports = append(ports, i)
					portMap[i] = true
				}
			}
		} else {
			port, err := strconv.Atoi(part)
			if err == nil && port >= 1 && port <= 65535 && !portMap[port] {
				ports = append(ports, port)
				portMap[port] = true
			}
		}
	}

	if len(ports) == 0 {
		ports = []int{80, 443, 22, 3389, 8080}
	}

	return ports
}

func ParseIPRange(ipRange string) ([]net.IP, error) {
	if strings.Contains(ipRange, "/") {
		return ParseCIDR(ipRange)
	}

	if strings.Contains(ipRange, "-") {
		parts := strings.Split(ipRange, "-")
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid IP range format")
		}

		startIP := net.ParseIP(strings.TrimSpace(parts[0])).To4()
		endIP := net.ParseIP(strings.TrimSpace(parts[1])).To4()

		if startIP == nil || endIP == nil {
			return nil, fmt.Errorf("invalid IPv4 address in range")
		}

		start := IPToInt(startIP)
		end := IPToInt(endIP)

		if start > end {
			start, end = end, start
		}

		maxRange := 2 << 23
		if end-start > uint32(maxRange) {
			return nil, fmt.Errorf("IP range too large (max %d IPs)", maxRange)
		}

		var ips []net.IP
		for i := start; i <= end; i++ {
			ips = append(ips, IntToIP(i))
		}

		return ips, nil
	}

	ip := net.ParseIP(strings.TrimSpace(ipRange))
	if ip == nil {
		return nil, fmt.Errorf("invalid IP address: %s", ipRange)
	}

	return []net.IP{ip.To4()}, nil
}

func ParseTargets(targets []string) ([]net.IP, error) {
	var allIPs []net.IP

	for _, target := range targets {
		ips, err := ParseIPRange(target)
		if err != nil {
			return nil, fmt.Errorf("parse target %s failed: %w", target, err)
		}
		allIPs = append(allIPs, ips...)
	}

	return allIPs, nil
}

func IPToInt(ip net.IP) uint32 {
	ip = ip.To4()
	if ip == nil {
		return 0
	}
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}

func IntToIP(n uint32) net.IP {
	return net.IPv4(
		byte(n>>24),
		byte(n>>16),
		byte(n>>8),
		byte(n),
	)
}

func GetSubnetC(ip net.IP) string {
	ip = ip.To4()
	if ip == nil {
		return ""
	}
	return fmt.Sprintf("%d.%d.%d.0/24", ip[0], ip[1], ip[2])
}

func GetSubnetB(ip net.IP) string {
	ip = ip.To4()
	if ip == nil {
		return ""
	}
	return fmt.Sprintf("%d.%d.0.0/16", ip[0], ip[1])
}

func GetSubnetA(ip net.IP) string {
	ip = ip.To4()
	if ip == nil {
		return ""
	}
	return fmt.Sprintf("%d.0.0.0/8", ip[0])
}

func CountIPsInCIDR(cidr string) (int, error) {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return 0, err
	}

	ones, bits := ipnet.Mask.Size()
	return 1 << (bits - ones), nil
}

func ValidateTargetSize(targets []string, maxSize int) error {
	total := 0
	for _, target := range targets {
		var count int
		var err error

		if strings.Contains(target, "/") {
			count, err = CountIPsInCIDR(target)
			if err != nil {
				return fmt.Errorf("invalid CIDR: %s", target)
			}
		} else if strings.Contains(target, "-") {
			ips, err := ParseIPRange(target)
			if err != nil {
				return fmt.Errorf("invalid IP range: %s: %w", target, err)
			}
			count = len(ips)
		} else {
			if net.ParseIP(target) == nil {
				return fmt.Errorf("invalid IP address: %s", target)
			}
			count = 1
		}
		total += count
	}

	if total > maxSize {
		return fmt.Errorf("target size %d exceeds maximum allowed %d (two A segments)", total, maxSize)
	}

	return nil
}
