package main

import (
	"errors"
	"fmt"
	"log"
	"math"
	"net"
	ebpfbinds "ping_fooler/ebpf-binds"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	flag "github.com/spf13/pflag"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go  -go-package ebpfbinds -output-dir=./ebpf-binds PingFooler ping_fooler.c

var ifaceDefaultName = "wlan0"
var ifaceName string

func main() {
	// Remove resource limits for kernels <5.11.
	if err := rlimit.RemoveMemlock(); err != nil {

		log.Fatal("Removing memlock: ", err)
	}

	var pingFoolObj ebpfbinds.PingFoolerObjects
	err := ebpfbinds.LoadPingFoolerObjects(&pingFoolObj, &ebpf.CollectionOptions{Programs: ebpf.ProgramOptions{LogSizeStart: math.MaxInt32}})
	if err != nil {
		var verr *ebpf.VerifierError
		// look up for full verifier's trace
		if errors.As(err, &verr) {
			log.Fatalf("Loading EBPF program: %+v\n", verr)
		}
		log.Fatalf("Loading EBPF program: %v\n", err)
	}

	defer pingFoolObj.Close()
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Fatal("Get interface by name: ", err)
	}

	xdp, err := link.AttachXDP(link.XDPOptions{Program: pingFoolObj.XdpPass, Interface: iface.Index})
	if err != nil {
		log.Fatal("Attaching XDP:", err)
	}
	defer xdp.Close()

	tick := time.Tick(time.Millisecond * 50)
	packetCount := 0
	for range tick {
		var pktlen int32
		var pktCountIter int32
		if err := pingFoolObj.PktLen.Lookup(uint32(0), &pktlen); err != nil {
			log.Fatal("cannot lookup map pkt_len")
		}

		if err := pingFoolObj.PktCount.Get(&pktCountIter); err != nil {
			log.Fatal("cannot get var pkt_count")
		}

		if packetCount != int(pktCountIter) {
			packetCount = int(pktCountIter)
			fmt.Printf("packet len: %d\n", pktlen)
		}
	}
}

func init() {
	flag.StringVarP(&ifaceName, "interface", "i", ifaceDefaultName, "interface to bind XDP program")
	flag.Parse()
}
