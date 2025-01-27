package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	ebpfbinds "ping_fooler/ebpf-binds"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	flag "github.com/spf13/pflag"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -go-package ebpfbinds -output-dir=./ebpf-binds PingFooler ping_fooler.c

const (
	ifaceDefaultName = "wlan0"
	timeDateFormat   = "02-01-2006 15:04:05"
)

var ifaceName string

type timestamp struct {
	Sec  int64
	Msec int64
}

type packetInfo struct {
	Length       uint32
	SrcIP        uint32
	DestIP       uint32
	ID           uint16
	Seq          uint16
	TTL          uint8
	OldTimestamp timestamp
	NewTimestamp timestamp
}

func main() {
	// Remove resource limits for kernels <5.11.
	if err := rlimit.RemoveMemlock(); err != nil {

		log.Fatal("Removing memlock: ", err)
	}

	var pingFoolObj ebpfbinds.PingFoolerObjects
	err := ebpfbinds.LoadPingFoolerObjects(&pingFoolObj, nil)
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
		log.Fatal("Get interface \""+ifaceDefaultName+"\" by name: ", err)
	}

	xdp, err := link.AttachXDP(link.XDPOptions{Program: pingFoolObj.XdpPass, Interface: iface.Index})
	if err != nil {
		log.Fatal("Attaching XDP:", err)
	}
	defer xdp.Close()

	packetInfoReader, err := ringbuf.NewReader(pingFoolObj.PacketInfoBuf)
	if err != nil {
		log.Fatal("cannot get ringbuf packet_info_buf")
	}
	defer packetInfoReader.Close()

	for {
		var pktCountIter int32
		var packetInfoEvent packetInfo

		packetInfoRecord, err := packetInfoReader.Read()
		if err != nil {
			log.Fatalf("cannot get entry from ringbuf: %v", err)
		}

		if err := binary.Read(bytes.NewBuffer(packetInfoRecord.RawSample), binary.LittleEndian, &packetInfoEvent); err != nil {
			log.Fatalf("cannot parse record from ringbuf. error: %v, entry: %v", err, packetInfoRecord.RawSample)
		}

		if err := pingFoolObj.PktCount.Get(&pktCountIter); err != nil {
			log.Fatal("cannot get var pkt_count")
		}

		fmt.Printf("%s -> %s ICMP %d echo reply id=%d seq=%d ttl=%d time=%s modified_time=%s\n",
			parseIPAddress(packetInfoEvent.SrcIP), parseIPAddress(packetInfoEvent.DestIP), pktCountIter,
			packetInfoEvent.ID, uint16LEtoBE(packetInfoEvent.Seq), packetInfoEvent.TTL,
			time.Unix(packetInfoEvent.OldTimestamp.Sec, packetInfoEvent.OldTimestamp.Msec).Format(timeDateFormat),
			time.Unix(packetInfoEvent.NewTimestamp.Sec, packetInfoEvent.NewTimestamp.Msec).Format(timeDateFormat))
	}
}

func init() {
	flag.StringVarP(&ifaceName, "interface", "i", ifaceDefaultName, "interface to bind XDP program")
	flag.Parse()
}

func uint16LEtoBE(input uint16) uint16 {
	binaryLE := make([]byte, 2)

	_, err := binary.Encode(binaryLE, binary.LittleEndian, input)
	if err != nil {
		log.Fatalf("cannot encode %v as binary: %v", input, err)
	}

	return binary.BigEndian.Uint16(binaryLE)
}

func parseIPAddress(input uint32) string {
	binInput := make([]byte, 4)
	_, err := binary.Encode(binInput, binary.LittleEndian, input)
	if err != nil {
		log.Fatalf("cannot encode %v as binary: %v", input, err)
	}

	// cast from []byte to []string
	finalResult := make([]string, 4)
	for index, value := range binInput {
		finalResult[index] = fmt.Sprintf("%v", int(value))
	}

	return strings.Join(finalResult, ".")
}
