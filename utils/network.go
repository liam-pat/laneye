package utils

import (
	"fmt"
	"log"
	"net"
)

type NetworkInfo struct {
	IPNet *net.IPNet
	MAC   net.HardwareAddr
	Name  string
}

func GetInterfaces(interfaceName string) ([]net.Interface, error) {
	if interfaceName == "" {
		return net.Interfaces()
	}
	appointedInterface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return nil, fmt.Errorf("interface %s not found: %v", interfaceName, err)
	}
	return []net.Interface{*appointedInterface}, nil
}

func GetIPnMacFromInterface(interfaceName string, lanNames *[]string) *NetworkInfo {
	interfaces, err := GetInterfaces(interfaceName)
	networkInfo := &NetworkInfo{}

	if err != nil {
		log.Fatalf("Failed to get network interfaces: %v", err)
	}
	for _, lan := range interfaces {
		addresses, err := lan.Addrs()
		if err != nil {
			log.Printf("Failed to get addresses for interface %s: %v", lan.Name, err)
			continue
		}
		for _, addr := range addresses {
			if ipNet, ok := addr.(*net.IPNet); ok && !ipNet.IP.IsLoopback() {
				if ipNet.IP.To4() != nil && lan.HardwareAddr != nil {
					networkInfo.IPNet = ipNet
					networkInfo.MAC = lan.HardwareAddr
					networkInfo.Name = lan.Name
					*lanNames = append(*lanNames, lan.Name)
					fmt.Printf("Interface: %s, IP: %s, MAC: %s\n", lan.Name, ipNet.IP.String(), lan.HardwareAddr.String())
				}
			}
		}
	}
	return networkInfo
}
