package main

import (
	"bytes"
	"math"
	"net"
	"strconv"
	"strings"
)

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

/**
the other way to transfer uint32 ip to string
*/
//func (ip Uint32IP) ipInt32ToString() string {
//	bitStr := ""
//	ipStr := ""
//	for ; ip > 0; ip /= 2 {
//		lsb := ip % 2
//		bitStr = strconv.Itoa(int(lsb)) + bitStr
//	}
//	if len(bitStr) < 32 {
//		bitStr = strings.Repeat("0", 32-len(bitStr)) + bitStr
//	}
//
//	for i := 1; i <= 4; i++ {
//		s := bitStr[(i-1)*8 : i*8]
//		parseInt, err := strconv.ParseInt(s, 2, 0)
//		if err != nil {
//			return ""
//		}
//
//		if i != 4 {
//			ipStr = ipStr + strconv.Itoa(int(parseInt)) + "."
//		} else {
//			ipStr = ipStr + strconv.Itoa(int(parseInt))
//		}
//	}
//
//	return ipStr
//}

func IpRangeTable(ipNet *net.IPNet) []Uint32IP {
	localhostIp := ipNet.IP.To4()
	log.Info("local ip:", localhostIp)
	var min, max Uint32IP
	var lanNetworkIps []Uint32IP
	/**
		calc the min ip in local network
	 eg.
		 ip : 192.168.10.200  netmask : 255.255.255.0
		(192 << 24) + (168 << 16) + (10 << 8) + (0 << 0) = 3232238080
	*/
	for i := 0; i < 4; i++ {
		b := Uint32IP(localhostIp[i] & ipNet.Mask[i])
		min += b << ((3 - uint(i)) * 8)
	}
	/**
		ipNet.Mask.Size() 24 , 11111111.111111111.11111111.00000000
		~maskSize , 00000000.00000000.00000000.11111111
	eg :
	    min : 192.168.0.0  ~mask 0.0.0.255
	  	max : min | ~mask
	*/
	maskSize, _ := ipNet.Mask.Size()
	max = min | Uint32IP(math.Pow(2, float64(32-maskSize))-1)
	log.Infof("local Network IP Range :%s --- %s", min+1, max-1)
	for i := min; i < max; i++ {
		if i&0x000000ff == 0 || i&0x000000ff == 255 {
			continue
		}
		lanNetworkIps = append(lanNetworkIps, i)
	}
	return lanNetworkIps
}

// IPSlice uint32 Uint32IP define function
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

func ParseIPString(s string) Uint32IP {
	var b []byte
	for _, i := range strings.Split(s, ".") {
		v, _ := strconv.Atoi(i)
		b = append(b, uint8(v))
	}
	return ParseIP(b)
}

// ParseIP convert [4]byte to uint32
func ParseIP(b []byte) Uint32IP {
	return Uint32IP(Uint32IP(b[0])<<24 + Uint32IP(b[1])<<16 + Uint32IP(b[2])<<8 + Uint32IP(b[3]))
}
