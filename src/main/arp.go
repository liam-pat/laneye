package main

import (
	"context"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	manuf "github.com/timest/gomanuf"
	"net"
	"time"
)

func listenARP(context context.Context) {
	const WaitSecond = 5
	handle, err := pcap.OpenLive(localNetInterfaceName, 1024, false, WaitSecond*time.Second)
	defer handle.Close()

	err = handle.SetBPFFilter("arp")
	if err != nil {
		log.Fatal("pcap open failed:", err)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for {
		select {
		// the main cro process call context cancel , exit
		case <-context.Done():
			return
		case packet := <-packetSource.Packets():
			arp := packet.Layer(layers.LayerTypeARP).(*layers.ARP)
			// 2 sign return package
			if arp.Operation == 2 {
				mac := net.HardwareAddr(arp.SourceHwAddress)
				factoryInfo := manuf.Search(mac.String())
				pushMachineInfo(ParseIP(arp.SourceProtAddress).String(), mac, "", factoryInfo)
			}
		}
	}
}

func sendArpPackage(ip Uint32IP) {
	// uint32 convert to []byte
	srcIp := net.ParseIP(localIpNet.IP.String()).To4()
	dstIp := net.ParseIP(ip.String()).To4()
	if srcIp == nil || dstIp == nil {
		log.Fatal("ip parse fail")
	}
	// EthernetType 0x0806  ARP
	ether := &layers.Ethernet{
		SrcMAC:       localMac,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}

	arpStruct := &layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     uint8(6),  // mac has 6 byte
		ProtAddressSize:   uint8(4),  // ip has 4 byte
		Operation:         uint16(1), // 0x0001 arp request 0x0002 arp response
		SourceHwAddress:   localMac,
		SourceProtAddress: srcIp,
		DstHwAddress:      net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		DstProtAddress:    dstIp,
	}

	// got the &serializeBuffer
	serializeBuffer := gopacket.NewSerializeBuffer()
	var options gopacket.SerializeOptions
	err := gopacket.SerializeLayers(serializeBuffer, options, ether, arpStruct)
	if err != nil {
		log.Fatal("init the arp package error:", err)
	}

	// get the struct serializeBuffer data slice
	outgoingPacket := serializeBuffer.Bytes()

	handle, err := pcap.OpenLive(localNetInterfaceName, 2048, false, 30*time.Second)
	if err != nil {
		log.Fatal("pcap open fail:", err)
	}
	defer handle.Close()

	err = handle.WritePacketData(outgoingPacket)
	if err != nil {
		log.Fatal("send arp package fail..")
	}
}
