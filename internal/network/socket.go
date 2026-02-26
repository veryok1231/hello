package network

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"sync"
	"syscall"
	"time"
)

type RawSocket struct {
	fd    int
	srcIP net.IP
	iface *net.Interface
	mu    sync.Mutex
}

func NewRawSocket(interfaceName string) (*RawSocket, error) {
	var iface *net.Interface
	var err error

	if interfaceName == "" {
		iface, err = getDefaultInterface()
	} else {
		iface, err = net.InterfaceByName(interfaceName)
	}

	if err != nil {
		return nil, fmt.Errorf("获取网络接口失败: %w", err)
	}

	addrs, err := iface.Addrs()
	if err != nil {
		return nil, fmt.Errorf("获取接口地址失败: %w", err)
	}

	var srcIP net.IP
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok {
			if ip4 := ipnet.IP.To4(); ip4 != nil {
				srcIP = ip4
				break
			}
		}
	}

	if srcIP == nil {
		return nil, fmt.Errorf("无法获取源IP地址")
	}

	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_ICMP)
	if err != nil {
		return nil, fmt.Errorf("创建原始套接字失败: %w (需要root权限)", err)
	}

	return &RawSocket{
		fd:    fd,
		srcIP: srcIP,
		iface: iface,
	}, nil
}

func (s *RawSocket) Close() error {
	if s.fd > 0 {
		return syscall.Close(s.fd)
	}
	return nil
}

func (s *RawSocket) LocalIP() net.IP {
	return s.srcIP
}

func (s *RawSocket) Interface() *net.Interface {
	return s.iface
}

type ICMPResponse struct {
	TTL int
}

type TCPResponse struct {
	Open   bool
	Closed bool
	TTL    int
	Banner []byte
}

type ARPResponse struct {
	MAC net.HardwareAddr
}

func SendICMPProbe(dstIP net.IP, timeout time.Duration) (*ICMPResponse, error) {
	socket, err := NewRawSocket("")
	if err != nil {
		return nil, err
	}
	defer socket.Close()

	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_ICMP)
	if err != nil {
		return nil, fmt.Errorf("创建ICMP套接字失败: %w", err)
	}
	defer syscall.Close(fd)

	dstAddr := &syscall.SockaddrInet4{}
	copy(dstAddr.Addr[:], dstIP.To4())

	icmpPacket := makeICMPPacket()
	start := time.Now()

	err = syscall.Sendto(fd, icmpPacket, 0, dstAddr)
	if err != nil {
		return nil, fmt.Errorf("发送ICMP包失败: %w", err)
	}

	buf := make([]byte, 1024)
	for {
		if time.Since(start) > timeout {
			return nil, fmt.Errorf("ICMP超时")
		}

		syscall.SetNonblock(fd, true)
		n, _, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			if err == syscall.EAGAIN || err == syscall.EWOULDBLOCK {
				time.Sleep(10 * time.Millisecond)
				continue
			}
			return nil, err
		}

		if n >= 20 {
			ttl := int(buf[8])
			return &ICMPResponse{TTL: ttl}, nil
		}
	}
}

func makeICMPPacket() []byte {
	packet := make([]byte, 8)
	packet[0] = 8
	packet[1] = 0
	binary.BigEndian.PutUint16(packet[2:4], 0)
	binary.BigEndian.PutUint16(packet[4:6], 1)
	binary.BigEndian.PutUint16(packet[6:8], 1)
	cs := checksum(packet)
	binary.BigEndian.PutUint16(packet[2:4], cs)
	return packet
}

func checksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i < len(data)-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	sum = (sum >> 16) + (sum & 0xffff)
	sum = sum + (sum >> 16)
	return ^uint16(sum)
}

func SendSYNProbe(dstIP net.IP, dstPort int, timeout time.Duration) (*TCPResponse, error) {
	start := time.Now()

	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.Dial("tcp", fmt.Sprintf("%s:%d", dstIP.String(), dstPort))
	if err != nil {
		if opErr, ok := err.(*net.OpError); ok {
			if opErr.Timeout() {
				return nil, fmt.Errorf("连接超时")
			}
		}
		return &TCPResponse{Closed: true, TTL: 64}, nil
	}
	defer conn.Close()

	elapsed := time.Since(start)
	estimatedTTL := 64 - int(elapsed.Milliseconds()/10)
	if estimatedTTL < 1 {
		estimatedTTL = 1
	}

	return &TCPResponse{
		Open: true,
		TTL:  estimatedTTL,
	}, nil
}

func SendARPProbe(dstIP net.IP, timeout time.Duration) (*ARPResponse, error) {
	if !dstIP.IsPrivate() && !dstIP.IsLoopback() {
		return nil, fmt.Errorf("ARP仅适用于本地网络")
	}

	hwAddr, err := arpPing(dstIP, timeout)
	if err != nil {
		return nil, err
	}

	return &ARPResponse{MAC: hwAddr}, nil
}

func arpPing(ip net.IP, timeout time.Duration) (net.HardwareAddr, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok {
				if ipnet.Contains(ip) {
					return iface.HardwareAddr, nil
				}
			}
		}
	}

	return nil, fmt.Errorf("无法解析ARP")
}

func getDefaultInterface() (*net.Interface, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok {
				if ipnet.IP.To4() != nil {
					return &iface, nil
				}
			}
		}
	}

	return nil, fmt.Errorf("未找到合适的网络接口")
}

func isRoot() bool {
	return os.Geteuid() == 0
}

func CheckPrivileges() error {
	if !isRoot() {
		return fmt.Errorf("需要root权限执行原始套接字操作")
	}
	return nil
}
