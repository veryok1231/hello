package utils

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
)

// Top100Ports 常用Top 100端口列表
var Top100Ports = []int{
	// Web服务
	80, 443, 8080, 8443, 8000, 8888, 9000, 3000, 5000, 4000,
	// 远程访问
	22, 23, 3389, 5900, 5901, 5902, 5800, 5801,
	// 文件服务
	21, 20, 69, 445, 139, 138, 137, 873, 2049,
	// 邮件服务
	25, 110, 143, 993, 995, 587, 465, 2525,
	// 数据库
	3306, 1433, 1521, 5432, 6379, 27017, 9200, 9042, 5984, 7000, 7001,
	// DNS/DHCP
	53, 67, 68, 5353,
	// 其他常用
	111, 135, 139, 161, 162, 389, 636, 646, 860, 1099,
	1080, 1434, 1723, 1883, 2181, 2375, 2376, 3307, 4444,
	4505, 4506, 464, 465, 4949, 500, 502, 504, 514, 515,
	520, 543, 631, 639, 646, 691, 767, 768, 8291, 8292,
	8400, 8401, 8402, 8530, 8531, 8883, 9001, 9090, 9091,
	9999, 10000, 10001, 10050, 10051, 11211, 11214, 123,
}

// ParsePortRange 解析端口范围字符串
func ParsePortRange(portStr string) []int {
	if portStr == "" {
		return GetTop100Ports()
	}

	portStr = strings.ToLower(strings.TrimSpace(portStr))

	if portStr == "all" || portStr == "full" {
		return GetAllPorts()
	}

	if portStr == "top100" || portStr == "top" {
		return GetTop100Ports()
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
		return GetTop100Ports()
	}

	return ports
}

// GetTop100Ports 返回Top 100端口列表
func GetTop100Ports() []int {
	result := make([]int, len(Top100Ports))
	copy(result, Top100Ports)
	return result
}

// GetAllPorts 返回全端口1-65535
func GetAllPorts() []int {
	ports := make([]int, 65535)
	for i := 1; i <= 65535; i++ {
		ports[i-1] = i
	}
	return ports
}

// ParseIPList 从文件或字符串解析IP列表
func ParseIPList(input string) ([]net.IP, error) {
	// 检查是否是文件路径
	if _, err := os.Stat(input); err == nil {
		return LoadIPsFromFile(input)
	}

	// 尝试解析为IP/CIDR
	if strings.Contains(input, "/") {
		return ParseCIDR(input)
	}

	if strings.Contains(input, "-") {
		return ParseIPRange(input)
	}

	// 尝试解析为单个IP
	ip := net.ParseIP(strings.TrimSpace(input))
	if ip != nil {
		return []net.IP{ip}, nil
	}

	return nil, fmt.Errorf("invalid IP input: %s", input)
}

// LoadIPsFromFile 从文件加载IP列表
func LoadIPsFromFile(filePath string) ([]net.IP, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("打开文件失败: %w", err)
	}
	defer file.Close()

	var ips []net.IP
	scanner := bufio.NewScanner(file)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		// 跳过空行和注释
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}

		// 解析IP/CIDR/Range
		parsedIPs, err := ParseIPList(line)
		if err != nil {
			// 如果解析失败，尝试作为单个IP处理
			ip := net.ParseIP(line)
			if ip != nil {
				ips = append(ips, ip)
				continue
			}
			return nil, fmt.Errorf("第%d行解析失败: %w", lineNum, err)
		}
		ips = append(ips, parsedIPs...)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("读取文件失败: %w", err)
	}

	return ips, nil
}

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
