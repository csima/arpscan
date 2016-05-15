package main

import (
	"encoding/binary"
	"fmt"
	"os"
	"bufio"
	"log"
	"net"
	"flag"
	"strconv"
	"net/smtp"
	"errors"
	"sync"
	"path/filepath"
	"gopkg.in/yaml.v2"
	"strings"
	"io/ioutil"
	"regexp"
	"time"
	"github.com/jasonlvhit/gocron"
    //"github.com/davecgh/go-spew/spew"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type Config struct {
    Whitelist []string
	Email map[string]string
	Interface string
}

type Manufacturer struct {
	Mac string
	Name string
	Description string
}

type Device struct {
	Ip string
	Name string
	Timestamp time.Time
	Mac Manufacturer
}

var newDevices = make(map[string]Device)
var lastDevices = make(map[string]Device)
var devices = make(map[string]Device)
var macs = make(map[string]Manufacturer)
var outputMac = false
var config Config

func main() {
	outputArg := flag.String("output","default", "specify what is displayed. valid options are 'mac,default'")
	flag.Parse()

	loadManufacturerDB()
	loadConfig()

	if config.Email["enabled"] == "true" {
		go cron()
	}

	if *outputArg == "mac" {
		outputMac = true
	}

	// Get a list of all interfaces.
	ifaces, err := net.Interfaces()
	if err != nil {
		panic(err)
	}

	var wg sync.WaitGroup
	//var addr net.IPNet

	for _, iface := range ifaces {
		wg.Add(1)
		// Start up a scan on each interface.
		go func(iface net.Interface) {
			defer wg.Done()
			addr, err := grabAddress(&iface)
			if err != nil {
				log.Printf("interface %v: %v", iface.Name, err)
			} else {
				if config.Interface != "" {
					if iface.Name == config.Interface {
						log.Printf("using interface %v", iface.Name)
		
						if err := scan(&iface, &addr); err != nil {
							log.Printf("error using interface %v: %v", iface.Name, err)
						}
					}
				} else {
					log.Printf("using interface %v", iface.Name)
	
					if err := scan(&iface, &addr); err != nil {
						log.Printf("error using interface %v: %v", iface.Name, err)
					}
				}
			}
		}(iface)
	}
	// Wait for all interfaces' scans to complete.  They'll try to run
	// forever, but will stop on an error, so if we get past this Wait
	// it means all attempts to write have failed.
	wg.Wait()
}

func cron() {
	freq, err := strconv.ParseUint(config.Email["frequency"],10,64)
	if err != nil {
		log.Println("Error parsing frequency value from arpscan.yaml")
		freq = 8
	}
	gocron.Every(freq).Hours().Do(sendEmailAlert)
	<- gocron.Start()
}

func grabAddress(iface *net.Interface) (net.IPNet, error) {
	var addr *net.IPNet
	if addrs, err := iface.Addrs(); err != nil {
		return net.IPNet{}, err
	} else {
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok {
				if ip4 := ipnet.IP.To4(); ip4 != nil {
					addr = &net.IPNet{
						IP:   ip4,
						Mask: ipnet.Mask[len(ipnet.Mask)-4:],
					}
					break
				}
			}
		}
	}
	// Sanity-check that the interface has a good address.
	if addr == nil {
		return net.IPNet{}, fmt.Errorf("no good IP network found")
	} else if addr.IP[0] == 127 {
		return net.IPNet{}, fmt.Errorf("skipping localhost")
	} else if addr.Mask[0] != 0xff || addr.Mask[1] != 0xff {
		return net.IPNet{}, fmt.Errorf("mask means network is too large")
	}
	log.Printf("found network range %v for interface %v", addr, iface.Name)
	return *addr, nil
}
// scan scans an individual interface's local network for machines using ARP requests/replies.
//
// scan loops forever, sending packets out regularly.  It returns an error if
// it's ever unable to write a packet.
func scan(iface *net.Interface, addr *net.IPNet) error {
	// We just look for IPv4 addresses, so try to find if the interface has one.


	// Open up a pcap handle for packet reads/writes.
	handle, err := pcap.OpenLive(iface.Name, 65536, true, pcap.BlockForever)
	if err != nil {
		return err
	}
	defer handle.Close()

	// Start up a goroutine to read in packet data.
	stop := make(chan struct{})
	go readARP(handle, iface, stop)
	defer close(stop)
	
	for {
		
		for k,v := range devices {
			lastDevices[k] = v
		}
		devices = make(map[string]Device)

		// I'm looping multiple times here and sending 2 broadcast arps because
		// of the responses & devices being unreliable. 
		for count := 1; count <= 3; count++ {
			// Write our scan packets out to the handle.
			if err := writeARP(handle, iface, addr); err != nil {
				log.Printf("error writing packets on %v: %v", iface.Name, err)
				return err
			}
			if err := writeARP(handle, iface, addr); err != nil {
				log.Printf("error writing packets on %v: %v", iface.Name, err)
				return err
			}

			// Sleep here to wait for arp responses - 3 secs seems to be the most reliable
			time.Sleep(3 * time.Second)
		}
		
		
		if outputMac {
			// Just print out MAC addrs - good for helping build the whitelist
			printMacAddrs()
		} else if len(config.Whitelist) > 0 {
			printDevices()
			printAlert()
		} else {
			printDevices()
		}
		
		// Waiting here for a minute because we don't need to flood the 
		// network constantly looking for devices. scanning once per minute 
		// seems reasonable
		log.Println("---------------------------------------")
		time.Sleep(60 * time.Second)
	}
}

func printAlert() {
	for _,device := range devices {
		if stringInSlice(device.Mac.Mac, config.Whitelist) == false {
			alert := fmt.Sprintf("new device detected: %s %s '%s : %s'", device.Ip, device.Mac.Mac, device.Mac.Description, device.Name)
			log.Println(alert)
			newDevices[device.Mac.Mac] = device
		}
	}	
}

func sendEmailAlert() {
	data := ""
	if len(newDevices) > 0 {
		for _,device := range newDevices {
			alert := fmt.Sprintf("%s new device detected: %s %s '%s : %s'", time.Now().Local(), device.Ip, device.Mac.Mac, device.Mac.Description, device.Name)
			data = data + alert + "\r\n"
		}
		
		send("New Device Report", data)
		
		// Clear out the newDevices log
		newDevices = make(map[string]Device)
	}
}

func printMacAddrs() {
	for _,device := range devices {
		fmt.Printf("%s\n", device.Mac.Mac)
	}	
	fmt.Printf("Total Devices: %d\n", len(devices))
	fmt.Printf("Last Total Devices: %d\n", len(lastDevices))
}

func printDevices() {
	for _,device := range devices {
		log.Printf("IP %s is at %s '%s : %s'", device.Ip, device.Mac.Mac, device.Mac.Description, device.Name)
	}	
	log.Printf("Total Devices: %d", len(devices))
	log.Printf("Last Total Devices: %d", len(lastDevices))
	
	for _,device := range devices {
		n := lastDevices[device.Mac.Mac]
		if n.Ip == "" && len(lastDevices) > 0 {
			alert := fmt.Sprintf("device online: %s %s '%s : %s'", device.Ip, device.Mac.Mac, device.Mac.Description, device.Name)
			log.Println(alert)
		}
	}
	
	for _,device := range lastDevices {
		n := devices[device.Mac.Mac]
		if n.Ip == "" && len(lastDevices) > 0 {
			alert := fmt.Sprintf("device offline: %s %s '%s : %s'", device.Ip, device.Mac.Mac, device.Mac.Description, device.Name)
			log.Println(alert)
		}
	}
}

func loadManufacturerDB() {

	file, err := os.Open("manuf.txt")
    if err != nil {
        log.Fatal(err)
    }
    defer file.Close()

    scanner := bufio.NewScanner(file)
    for scanner.Scan() {
	    mac, err := parseManufacturer(scanner.Text())
	    if err == nil {
			macs[mac.Mac] = mac
	    } 
    }

    if err := scanner.Err(); err != nil {
        log.Fatal(err)
    }
}

func loadConfig() {
	/*
	yamlFile, err := os.Open("arpscan.yaml")
    if err != nil {
        log.Fatal(err)
    }
    defer yamlFile.Close()*/
    
	filename, _ := filepath.Abs("arpscan.yaml")
    yamlFile, err := ioutil.ReadFile(filename)

    if err != nil {
        panic(err)
    }
    
    err = yaml.Unmarshal(yamlFile, &config)
    if err != nil {
        panic(err)
    }
}

func parseManufacturer(line string) (Manufacturer, error) {
	if len(line) == 0 || line[:1] == "#" {
		// Ignore line
        return Manufacturer{}, errors.New("Skipping comment")
	}
	
	re, err := regexp.Compile(`^(\S+)\s+([^(\t| |\n)]+)(?:\n|\s*(.+))`)
	if err != nil {
        return Manufacturer{}, errors.New("Error in regex for parseManufacturer")
	}
	
    result := re.FindAllStringSubmatch(line, -1)

	mac := Manufacturer{}
    for i := range result {
	    if len(result[i]) == 4 {
		    mac = Manufacturer{Mac: strings.ToLower(result[i][1]), Name: result[i][2], Description: result[i][3]}
        } else {
	        mac = Manufacturer{Mac: strings.ToLower(result[i][1]), Name: result[i][2]}
        }
    }
    return mac, nil
}

func grabManufacturer(macAddr string) Manufacturer {
	name := macs[macAddr]
	return name
}

func nslookup(ip string) string {
	addr, _ := net.LookupAddr(ip)
	if len(addr) > 0 {
    	return addr[0]
    }
    return ""
}

// readARP watches a handle for incoming ARP responses we might care about, and prints them.
// readARP loops until 'stop' is closed.
func readARP(handle *pcap.Handle, iface *net.Interface, stop chan struct{}) {
	src := gopacket.NewPacketSource(handle, layers.LayerTypeEthernet)
	in := src.Packets()
	for {
		var packet gopacket.Packet
		select {
		case <-stop:
			return
		case packet = <-in:
			arpLayer := packet.Layer(layers.LayerTypeARP)
			if arpLayer == nil {
				continue
			}
			arp := arpLayer.(*layers.ARP)
			if arp.Operation != layers.ARPReply {
				// This is a packet I sent.
				continue
			}
			
			macaddr := net.HardwareAddr(arp.SourceHwAddress).String()
			mac := grabManufacturer(macaddr[:8])
			mac.Mac = macaddr
			devices[macaddr] = Device{Name: nslookup(net.IP(arp.SourceProtAddress).String()), Ip: net.IP(arp.SourceProtAddress).String(), Timestamp: time.Now(), Mac: mac}
		}
	}
}

// writeARP writes an ARP request for each address on our local network to the
// pcap handle.
func writeARP(handle *pcap.Handle, iface *net.Interface, addr *net.IPNet) error {
	// Set up all the layers' fields we can.
	eth := layers.Ethernet{
		SrcMAC:       iface.HardwareAddr,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}
	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   []byte(iface.HardwareAddr),
		SourceProtAddress: []byte(addr.IP),
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
	}
	// Set up buffer and options for serialization.
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	// Send one packet for every address.
	for _, ip := range ips(addr) {
		arp.DstProtAddress = []byte(ip)
		gopacket.SerializeLayers(buf, opts, &eth, &arp)
		if err := handle.WritePacketData(buf.Bytes()); err != nil {
			return err
		}
	}
	return nil
}

// ips is a simple and not very good method for getting all IPv4 addresses from a
// net.IPNet.  It returns all IPs it can over the channel it sends back, closing
// the channel when done.
func ips(n *net.IPNet) (out []net.IP) {
	num := binary.BigEndian.Uint32([]byte(n.IP))
	mask := binary.BigEndian.Uint32([]byte(n.Mask))
	num &= mask
	for mask < 0xffffffff {
		var buf [4]byte
		binary.BigEndian.PutUint32(buf[:], num)
		out = append(out, net.IP(buf[:]))
		mask += 1
		num += 1
	}
	return
}

func send(subject string, body string) {
	from := config.Email["username"]
	pass := config.Email["password"]
	to := config.Email["to"]
	server := config.Email["server"]
	port := config.Email["port"]
	
	msg := "From: " + from + "\r\n" +
		"To: " + to + "\r\n" +
		"Subject: " + subject + "\r\n\r\n" +
		body

	auth := smtp.PlainAuth("", from, pass, server)
	err := smtp.SendMail(server + ":" + port,auth,from, []string{to}, []byte(msg))

	if err != nil {
		log.Printf("smtp error: %s", err)
		return
	}
	
	log.Print("Sent new device report to email to: " + to)
}

func stringInSlice(a string, list []string) bool {
    for _, b := range list {
        if b == a {
            return true
        }
    }
    return false
}