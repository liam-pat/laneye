package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/sirupsen/logrus"
	manuf "github.com/timest/gomanuf"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

type machineInfo struct {
	// Mac address
	Mac net.HardwareAddr
	// Host name
	Hostname string
	// hardware factory info
	FactoryInfo string
}

const (
	START = "start"
	END   = "end"
)

var log = logrus.New()

// struct to save ip and netmask
var localIpNet *net.IPNet

// localhost mac
var localMac net.HardwareAddr

// local net interface , maybe wifi eth0
var localNetInterface string

// all machine in lan network
var lanMachines map[string]machineInfo

var timeCounter *time.Ticker

var do chan string

func PrintLanMachines() {
	// []uint32 , as same as the IP struct
	var ips IPSlice
	for ip := range lanMachines {
		ips = append(ips, ParseIPString(ip))
	}
	sort.Sort(ips)
	for _, ipUint32 := range ips {
		lanMachine := lanMachines[ipUint32.String()]
		var mac = ""
		if lanMachine.Mac != nil {
			mac = lanMachine.Mac.String()
		}

		fmt.Printf("%-15s %-17s %-30s %-10s\n", ipUint32.String(), mac, lanMachine.Hostname, lanMachine.FactoryInfo)
	}
}

func pushMachineInfo(ip string, mac net.HardwareAddr, hostname, factoryInfo string) {
	do <- START
	var mu sync.RWMutex
	mu.RLock()

	defer func() {
		do <- END
		mu.RUnlock()
	}()
	if _, ok := lanMachines[ip]; !ok {
		lanMachines[ip] = machineInfo{Mac: mac, Hostname: hostname, FactoryInfo: factoryInfo}
	} else {
		machine := lanMachines[ip]
		if len(hostname) > 0 {
			machine.Hostname = hostname
		}
		if len(factoryInfo) > 0 {
			machine.FactoryInfo = factoryInfo
		}
		if mac != nil {
			machine.Mac = mac
		}
		lanMachines[ip] = machine
	}
}

func setupLocalNetInfo(netInterfaceName string) {
	var localNetInterfaces []net.Interface

	if netInterfaceName == "" {
		localNetInterfaces, _ = net.Interfaces()
	} else {
		localNetInterface, err := net.InterfaceByName(netInterfaceName)
		if err == nil {
			localNetInterfaces = append(localNetInterfaces, *localNetInterface)
		}
	}
Loop:
	for _, localInterface := range localNetInterfaces {
		addresses, _ := localInterface.Addrs()
		for _, addr := range addresses {
			// addr.(*net.IPNet) using addr convert to (*net.IPNet)
			// netIpNet.IP.IsLoopback() to avoid to get 127.0.0.1
			if netIpNet, ok := addr.(*net.IPNet); ok && !netIpNet.IP.IsLoopback() {
				if netIpNet.IP.To4() != nil {
					localIpNet = netIpNet
					localMac = localInterface.HardwareAddr
					localNetInterface = localInterface.Name
					break Loop
				}
			}
		}
	}
	if localIpNet == nil || len(localMac) == 0 {
		log.Fatal("Cannot get the local machine network information")
	}
}

func sendARP() {
	ips := Table(localIpNet)
	for _, ip := range ips {
		go sendArpPackage(ip)
	}
}
func localHost() {
	host, _ := os.Hostname()
	lanMachines[localIpNet.IP.String()] = machineInfo{Mac: localMac, Hostname: strings.TrimSuffix(host, ".local"), FactoryInfo: manuf.Search(localMac.String())}
}

func main() {
	// if return 0 ,using the root to run cmd
	if os.Geteuid() != 0 {
		log.Fatal("lanScan must run as root.")
	}

	//cmd : go run main.go -I=eth0
	flag.StringVar(&localNetInterface, "I", "en0", "Network Interface Name")
	flag.Parse()

	// init network data
	lanMachines = make(map[string]machineInfo)
	do = make(chan string)

	// init local network info
	setupLocalNetInfo(localNetInterface)

	ctx, cancel := context.WithCancel(context.Background())
	go listenARP(ctx)
	go listenMDNS(ctx)
	go listenNBNS(ctx)
	go sendARP()
	go localHost()

	timeCounter = time.NewTicker(20 * time.Second)
	for {
		select {
		case <-timeCounter.C:
			PrintLanMachines()
			cancel()
			return
		case d := <-do:
			switch d {
			case START:
				timeCounter.Stop()
			case END:
				timeCounter = time.NewTicker(2 * time.Second)
			}
		}
	}
}
