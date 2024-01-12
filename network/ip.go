package network

import (
	"bytes"
	"math"
	"net"
	"strconv"
	"strings"
)

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

type Uint32IP uint32

func (ip Uint32IP) String() string {
	var bf bytes.Buffer
	for i := 1; i <= 4; i++ {
		bf.WriteString(strconv.Itoa(int((ip >> ((4 - uint(i)) * 8)) & 0xff)))
		if i != 4 {
			bf.WriteByte('.')
		}
	}
	return bf.String()
}

func IpRangeTable(localIpNet *net.IPNet) (lanNetworkIps []Uint32IP) {
	localIPV4 := localIpNet.IP.To4() //[4]byte

	var minIpUint32, maxIpUint32 Uint32IP
	maskSize, _ := localIpNet.Mask.Size()

	// (192.168.10.200/24) ip -> 11111111.111111111.11111111.00000000  mask -> 00000000.00000000.00000000.11111111
	// ip string 2 uint : (192 << 24) + (168 << 16) + (10 << 8) + (200 << 0) = 3232238280
	// min : ip & mask
	// min : min | ~mask
	minIpUint32 = ParseIP2Uint32(localIPV4) & ParseIP2Uint32(localIpNet.Mask)

	maxIpUint32 = minIpUint32 | Uint32IP(math.Pow(2, float64(32-maskSize)))

	for ipUint32 := minIpUint32; ipUint32 < maxIpUint32; ipUint32++ {
		if ipUint32&0x000000ff == 0 || ipUint32&0x000000ff == 255 {
			continue
		}
		lanNetworkIps = append(lanNetworkIps, ipUint32)
	}
	return
}

func ParseString2Uint32(s string) Uint32IP {
	var b []byte
	for _, i := range strings.Split(s, ".") {
		v, _ := strconv.Atoi(i)
		b = append(b, uint8(v))
	}
	return ParseIP2Uint32(b)
}

func ParseIP2Uint32(b []byte) Uint32IP {
	return Uint32IP(Uint32IP(b[0])<<24 + Uint32IP(b[1])<<16 + Uint32IP(b[2])<<8 + Uint32IP(b[3]))
}
