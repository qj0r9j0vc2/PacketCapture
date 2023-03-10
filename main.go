package main

import (
	"bufio"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/manifoldco/promptui"
	"log"
	"os"
	"strconv"
	"strings"
	"time"
)

var filter string = ""
var ifc string = "en0"
var snaplen int = 1024
var promisc bool = false
var tSec int = 1

func main() {
	openMenu()
}

func FindDevices() {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatalf("Error occurred while find devices - %v", err)
	}

	for _, device := range devices {
		fmt.Printf("Device Name: %s\n", device.Name)
		fmt.Printf("Device Description: %s\n", device.Description)
		fmt.Printf("Device Flags: %d\n", device.Flags)
		for _, address := range device.Addresses {
			fmt.Printf("\tInterface IP: %s\n", address.IP)
			fmt.Printf("\tInterface NetMask: %s\n", address.Netmask)
		}
	}
}

func readInt(description string) int {
	str := readString(description)
	if str != "" {
		parseInt, err := strconv.ParseInt(str, 0, 64)
		if err != nil {
			log.Fatalln("Invalid int type")
		}
		return int(parseInt)
	}
	return -1
}

func readString(description string) string {
	reader := bufio.NewReader(os.Stdin)
	fmt.Printf("Enter %s : ", description)

	strName, err := reader.ReadString('\n')
	if err != nil {
		log.Fatal(err)
	}
	return strings.TrimSpace(strName)
}

func inputDataSetup() {
	str := readString("BPF filter")
	if str != "" {
		filter = str
	}

	str = readString("Interface")
	if str != "" {
		ifc = str
	}

	i := readInt("Capture size")
	if i != -1 {
		snaplen = i
	}

	bool := readString("Promiscuous mode T or F")
	if bool == "T" {
		promisc = true
	} else {
		promisc = false
	}

	i = readInt("Timeout")
	if i != -1 {
		tSec = i
	}
}

func capturePacket() {
	inputDataSetup()
	fmt.Printf("BPF filter: %s, Interface: %s, Capture Size: %d, Promiscuous mode: %t, Timeout: %d\n", filter, ifc, snaplen, promisc, tSec)
	time.Sleep(5)

	log.Println("start")
	defer log.Println("end")

	var timeout = time.Duration(tSec) * time.Second

	handle, err := pcap.OpenLive(ifc, int32(snaplen), promisc, timeout)
	if err != nil {
		log.Fatal(err)
	}

	defer handle.Close()

	if filter != "" {
		log.Println("applying filter ", filter)
		err := handle.SetBPFFilter(filter)
		if err != nil {
			log.Fatalf("error applyign BPF Filter %s - %v", filter, err)
		}
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	for packet := range packetSource.Packets() {
		fmt.Println(packet)
	}
}

func openMenu() {
	fmt.Printf("\033[2J")
	fmt.Printf("\033[1;1H")
	for {
		menu := []string{"Show network devices", "Capture packet", "Exit"}
		prompt := promptui.Select{Label: "Select Menu", Items: menu}
		i, _, err := prompt.Run()
		if err != nil {
			log.Fatal(err)
		}
		switch i {
		case 0:
			FindDevices()
			break
		case 1:
			capturePacket()
			break
		case 3:
			println("Exit..!!")
			return
		}
	}
}
