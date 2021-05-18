package main

import (
	"bytes"
	"math"
	"net"
	"strconv"
	"strings"
)

type IP uint32

func (ip IP) String() string {
	var bf bytes.Buffer
	for i := 1; i <= 4; i++ {
		bf.WriteString(strconv.Itoa(int((ip >> ((4 - uint(i)) * 8)) & 0xff)))
		if i != 4 {
			bf.WriteByte('.')
		}
	}
	return bf.String()
}

func (ip IP) ipInt32ToString() string {
	bitStr := ""
	ipStr := ""
	for ; ip > 0; ip /= 2 {
		lsb := ip % 2
		bitStr = strconv.Itoa(int(lsb)) + bitStr
	}
	if len(bitStr) < 32 {
		bitStr = strings.Repeat("0", 32-len(bitStr)) + bitStr
	}

	for i := 1; i <= 4; i++ {
		s := bitStr[(i-1)*8 : i*8]
		parseInt, err := strconv.ParseInt(s, 2, 0)
		if err != nil {
			return ""
		}

		if i != 4 {
			ipStr = ipStr + strconv.Itoa(int(parseInt)) + "."
		} else {
			ipStr = ipStr + strconv.Itoa(int(parseInt))
		}
	}

	return ipStr
}

func Table(ipNet *net.IPNet) []IP {
	ip := ipNet.IP.To4()
	log.Info("本机ip:", ip)
	var min, max IP
	var data []IP
	for i := 0; i < 4; i++ {
		b := IP(ip[i] & ipNet.Mask[i])
		min += b << ((3 - uint(i)) * 8)
	}
	one, _ := ipNet.Mask.Size()
	max = min | IP(math.Pow(2, float64(32 - one)) - 1)
	log.Infof("local network IP范 range :%s --- %s", min, max)
	// i & 0x000000ff  == 0 是尾段为0的IP，根据RFC的规定，忽略
	for i := min; i < max; i++ {
		if i & 0x000000ff == 0 {
			continue
		}
		data = append(data, i)
	}
	return data
}

// IPSlice uint32 IP define function
type IPSlice []IP

func (ip IPSlice) Len() int {
	return len(ip)
}
func (ip IPSlice) Swap(i, j int) {
	ip[i], ip[j] = ip[j], ip[i]
}
func (ip IPSlice) Less(i, j int) bool {
	return ip[i] < ip[j]
}

func ParseIPString(s string) IP{
	var b []byte
	for _, i := range strings.Split(s, ".") {
		v, _ := strconv.Atoi(i)
		b = append(b, uint8(v))
	}
	return ParseIP(b)
}

// ParseIP convert [4]byte to uint32
func ParseIP(b []byte) IP {
	return IP(IP(b[0]) << 24 + IP(b[1]) << 16 + IP(b[2]) << 8 + IP(b[3]))
}
