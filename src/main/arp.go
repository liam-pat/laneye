package main

import (
	"context"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	manuf "github.com/timest/gomanuf"
	"net"
	"strings"
	"time"
)

func listenARP(context context.Context) {
	handle, err := pcap.OpenLive(localNetInterface, 1024, false, 10*time.Second)
	defer handle.Close()

	err = handle.SetBPFFilter("arp")
	if err != nil {
		log.Fatal("pcap open failed:", err)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for {
		select {
		case <-context.Done():
			return
		case packet := <-packetSource.Packets():
			arp := packet.Layer(layers.LayerTypeARP).(*layers.ARP)

			if arp.Operation == 2 {
				mac := net.HardwareAddr(arp.SourceHwAddress)
				factoryInfo := manuf.Search(mac.String())
				pushMachineInfo(ParseIP(arp.SourceProtAddress).String(), mac, "", factoryInfo)

				if strings.Contains(factoryInfo, "Apple") {
					go sendMdns(ParseIP(arp.SourceProtAddress), mac)
				} else {
					go sendNbns(ParseIP(arp.SourceProtAddress), mac)
				}
			}
		}
	}
}

func sendArpPackage(ip IP) {
	srcIp := net.ParseIP(localIpNet.IP.String()).To4()
	dstIp := net.ParseIP(ip.String()).To4()
	if srcIp == nil || dstIp == nil {
		log.Fatal("ip parse fail")
	}
	// EthernetType 0x0806  ARP
	ether := &layers.Ethernet{
		SrcMAC: localMac,
		DstMAC: net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}

	a := &layers.ARP{
		AddrType: layers.LinkTypeEthernet,
		Protocol: layers.EthernetTypeIPv4,
		HwAddressSize: uint8(6),
		ProtAddressSize: uint8(4),
		Operation: uint16(1), // 0x0001 arp request 0x0002 arp response
		SourceHwAddress: localMac,
		SourceProtAddress: srcIp,
		DstHwAddress: net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		DstProtAddress: dstIp,
	}

	buffer := gopacket.NewSerializeBuffer()
	var opt gopacket.SerializeOptions
	gopacket.SerializeLayers(buffer, opt, ether, a)
	outgoingPacket := buffer.Bytes()

	handle, err := pcap.OpenLive(localNetInterface, 2048, false, 30 * time.Second)
	if err != nil {
		log.Fatal("pcap open fail:", err)
	}
	defer handle.Close()

	err = handle.WritePacketData(outgoingPacket)
	if err != nil {
		log.Fatal("send arp package fail..")
	}
}

