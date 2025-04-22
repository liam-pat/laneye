package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/YaoMiss/macmap"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/sirupsen/logrus"
	"net"
	"os"
	"packie/lanscan-go/network"
	"packie/lanscan-go/utils"
	"sort"
	"strings"
	"sync"
	"time"
)

type machineInfo struct {
	Hostname    string
	MacAddress  net.HardwareAddr
	FactoryInfo string
}

const (
	DoSignalStart = "start"
	DoSignalEnd   = "end"
)

var log = logrus.New()

var machines map[string]machineInfo

func main() {
	var interfaceName string
	flag.StringVar(&interfaceName, "interface", "", "ur net lan")
	flag.Parse()

	var lanNames = make([]string, 0)

	machines = make(map[string]machineInfo)
	pushMachineInfoSignal := make(chan string)
	networkInfo := utils.GetIPnMacFromInterface(interfaceName, &lanNames)

	//fmt.Println(strings.Repeat("####", 5) + " interfaces: " + lanNames[0])
	//fmt.Println(strings.Repeat("####", 5) + " sudo go run main.go -interface=" + lanNames[0])

	fmt.Println(strings.Repeat("####", 5)+" IP ", networkInfo.IPNet.String())

	if networkInfo.IPNet == nil || len(networkInfo.MAC.String()) == 0 {
		log.Fatal("Cannot get the lan name or lan mac")
	}

	ctx, cancel := context.WithCancel(context.Background())

	// listen the arp reply package
	go listenARPPackets(networkInfo.Name, ctx, pushMachineInfoSignal)

	// send the arp package to all lan machine
	go func() {
		ips, _ := network.IPV4RangeTable(networkInfo.IPNet)
		for _, ip := range ips {
			go sendArpPackage(ip, networkInfo.IPNet, networkInfo.MAC, networkInfo.Name)
		}
	}()

	go func() {
		host, _ := os.Hostname()
		//vendorInfo := manuf.Search(networkInfo.MAC.String())
		vendorInfo := macmap.Search(networkInfo.MAC.String())
		machines[networkInfo.IPNet.IP.String()] = machineInfo{
			MacAddress: networkInfo.MAC,
			Hostname:   strings.TrimSuffix(host, ".local"), FactoryInfo: vendorInfo,
		}
	}()
	timeCounter := time.NewTicker(10 * time.Second)

	for {
		select {
		case <-timeCounter.C:
			printLanMachines()
			cancel()
			return
		case d := <-pushMachineInfoSignal:
			switch d {
			case DoSignalStart:
				timeCounter.Stop()
			case DoSignalEnd:
				timeCounter = time.NewTicker(2 * time.Second)
			}
		}
	}
}

func listenARPPackets(listenInterfaceName string, context context.Context, pushMachineInfoSignal chan string) {
	handle, _ := pcap.OpenLive(listenInterfaceName, 1024, false, 5*time.Second)
	defer handle.Close()

	_ = handle.SetBPFFilter("arp")

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for {
		select {
		case <-context.Done():
			return
		case packet := <-packetSource.Packets():
			arp := packet.Layer(layers.LayerTypeARP).(*layers.ARP)
			// https://www.iana.org/assignments/arp-parameters/arp-parameters.xhtml
			if arp.Operation == layers.ARPReply {
				mac := net.HardwareAddr(arp.SourceHwAddress)
				//factoryInfo := manuf.Search(mac.String())
				factoryInfo := macmap.Search(mac.String())

				pushMachineInfo(network.ParseIPV44byte2Uint32(arp.SourceProtAddress).String(), mac, "", factoryInfo, pushMachineInfoSignal)
			}
		}
	}
}

func pushMachineInfo(ip string, mac net.HardwareAddr, hostname, factoryInfo string, pushMachineInfoSignal chan string) {
	pushMachineInfoSignal <- DoSignalStart
	var mu sync.RWMutex
	mu.RLock()

	defer func() {
		pushMachineInfoSignal <- DoSignalEnd
		mu.RUnlock()
	}()
	if _, ok := machines[ip]; !ok {
		machines[ip] = machineInfo{MacAddress: mac, Hostname: hostname, FactoryInfo: factoryInfo}
	} else {
		machine := machines[ip]
		if len(hostname) > 0 {
			machine.Hostname = hostname
		}
		if len(factoryInfo) > 0 {
			machine.FactoryInfo = factoryInfo
		}
		machines[ip] = machine
	}
}

func printLanMachines() {
	var ips network.IPSlice
	for ip := range machines {
		ip, err := network.ParseIPV4String2Uint32(ip)
		if err != nil {
			continue
		}
		ips = append(ips, ip)
	}
	fmt.Printf("%-15s %-20s %-30s %-10s\n", "ip", "mac", "hostname", "vendorname")
	sort.Sort(ips)
	for _, ipUint32 := range ips {
		lanMachine := machines[ipUint32.String()]
		var mac = ""
		if lanMachine.MacAddress != nil {
			mac = lanMachine.MacAddress.String()
		}

		fmt.Printf("%-15s %-20s %-30s %-10s\n", ipUint32.String(), mac, lanMachine.Hostname, lanMachine.FactoryInfo)
	}
	fmt.Printf("---------%d machines in lan network----------", len(machines))
}

func sendArpPackage(ip network.Uint32IP, localIPNet *net.IPNet, localMacAddress net.HardwareAddr, scanNetInterfaceName string) {
	srcIp := net.ParseIP(localIPNet.IP.String()).To4()
	dstIp := net.ParseIP(ip.String()).To4()
	if srcIp == nil || dstIp == nil {
		log.Fatal("ip parse fail")
	}
	ether := &layers.Ethernet{
		SrcMAC:       localMacAddress,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}
	arpStruct := &layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     uint8(6),  // mac has 6 byte
		ProtAddressSize:   uint8(4),  // ip has 4 byte
		Operation:         uint16(1), // 0x0001 arp request 0x0002 arp response
		SourceHwAddress:   localMacAddress,
		SourceProtAddress: srcIp,
		DstHwAddress:      net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		DstProtAddress:    dstIp,
	}

	serializeBuffer := gopacket.NewSerializeBuffer()
	var options gopacket.SerializeOptions
	err := gopacket.SerializeLayers(serializeBuffer, options, ether, arpStruct)
	if err != nil {
		log.Fatal("init the arp package error:", err)
	}
	outgoingPacket := serializeBuffer.Bytes()
	handle, err := pcap.OpenLive(scanNetInterfaceName, 2048, false, 30*time.Second)
	if err != nil {
		log.Fatal("pcap open fail:", err)
	}
	defer handle.Close()
	err = handle.WritePacketData(outgoingPacket)
	if err != nil {
		log.Fatal("send arp package fail..")
	}
}
