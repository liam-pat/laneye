package network

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

type Uint32IP uint32
type IPSlice []Uint32IP

func (ip IPSlice) Len() int {
	return len(ip)
}
func (ip IPSlice) Swap(i, j int) {
	ip[i], ip[j] = ip[j], ip[i]
}
func (ip IPSlice) Less(i, j int) bool {
	return ip[i] < ip[j]
}

func (ip Uint32IP) String() string {
	builder := strings.Builder{}
	builder.Grow(15) // xxx.xxx.xxx.xxx
	for i := 1; i <= 4; i++ {
		builder.WriteString(strconv.Itoa(int((ip >> ((4 - uint(i)) * 8)) & 0xff)))
		if i != 4 {
			builder.WriteByte('.')
		}
	}
	return builder.String()
}

func IPV4RangeTable(localIpNet *net.IPNet) ([]Uint32IP, error) {
	if localIpNet == nil {
		return nil, fmt.Errorf("nil IPNet provided")
	}
	localIPV4 := localIpNet.IP.To4() //[4]byte
	if localIPV4 == nil {
		return nil, fmt.Errorf("invalid IPv4 address")
	}

	var minIPV4, maxIPV4 Uint32IP

	// 192.168.10.200/24.  first value is `24` , second value is `32`
	_, bits := localIpNet.Mask.Size()
	if bits != net.IPv4len*8 {
		return nil, fmt.Errorf("unexpected mask size")
	}
	// 192.168.10.200/24
	// ip   -> 11000000.10101000.00001010.xxxxxxxx
	// mask -> 11111111.11111111.11111111.00000000
	// min : ip & mask ; max : min | ~mask
	minIPV4 = ParseIPV44byte2Uint32(localIPV4) & ParseIPV44byte2Uint32(localIpNet.Mask)
	maxIPV4 = minIPV4 | ^ParseIPV44byte2Uint32(localIpNet.Mask)

	var IPs []Uint32IP
	IPs = make([]Uint32IP, 0, int(maxIPV4-minIPV4-1))
	for IP := minIPV4 + 1; IP < maxIPV4; IP++ {
		IPs = append(IPs, IP)
	}
	return IPs, nil
}

func ParseIPV4String2Uint32(s string) (Uint32IP, error) {
	var b []byte
	b = make([]byte, 0, 4)
	parts := strings.Split(s, ".")

	if len(parts) != 4 {
		return 0, fmt.Errorf("invalid IP format: %s", s)
	}
	for _, i := range parts {
		v, err := strconv.Atoi(i)
		if err != nil {
			return 0, fmt.Errorf("invalid IP segment: %s", i)
		}
		if v < 0 || v > 255 {
			return 0, fmt.Errorf("IP segment out of range: %d", v)
		}
		b = append(b, uint8(v))
	}
	return ParseIPV44byte2Uint32(b), nil
}

func ParseIPV44byte2Uint32(b []byte) Uint32IP {
	if len(b) != 4 {
		return 0
	}
	// 192.168.10.200/24
	// ip string 2 uint32 : (192 << 24) + (168 << 16) + (10 << 8) + (200 << 0) = 3232238280
	return Uint32IP(Uint32IP(b[0])<<24 + Uint32IP(b[1])<<16 + Uint32IP(b[2])<<8 + Uint32IP(b[3]))
}
