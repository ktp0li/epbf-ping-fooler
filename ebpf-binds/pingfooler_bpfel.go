// Code generated by bpf2go; DO NOT EDIT.
//go:build 386 || amd64 || arm || arm64 || loong64 || mips64le || mipsle || ppc64le || riscv64

package ebpfbinds

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

// LoadPingFooler returns the embedded CollectionSpec for PingFooler.
func LoadPingFooler() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_PingFoolerBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load PingFooler: %w", err)
	}

	return spec, err
}

// LoadPingFoolerObjects loads PingFooler and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*PingFoolerObjects
//	*PingFoolerPrograms
//	*PingFoolerMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func LoadPingFoolerObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := LoadPingFooler()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// PingFoolerSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type PingFoolerSpecs struct {
	PingFoolerProgramSpecs
	PingFoolerMapSpecs
	PingFoolerVariableSpecs
}

// PingFoolerProgramSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type PingFoolerProgramSpecs struct {
	XdpPass *ebpf.ProgramSpec `ebpf:"xdp_pass"`
}

// PingFoolerMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type PingFoolerMapSpecs struct {
	PacketInfoBuf *ebpf.MapSpec `ebpf:"packet_info_buf"`
	PktLen        *ebpf.MapSpec `ebpf:"pkt_len"`
}

// PingFoolerVariableSpecs contains global variables before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type PingFoolerVariableSpecs struct {
	ICMP_TYPE_REPLY *ebpf.VariableSpec `ebpf:"ICMP_TYPE_REPLY"`
	PktCount        *ebpf.VariableSpec `ebpf:"pkt_count"`
}

// PingFoolerObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to LoadPingFoolerObjects or ebpf.CollectionSpec.LoadAndAssign.
type PingFoolerObjects struct {
	PingFoolerPrograms
	PingFoolerMaps
	PingFoolerVariables
}

func (o *PingFoolerObjects) Close() error {
	return _PingFoolerClose(
		&o.PingFoolerPrograms,
		&o.PingFoolerMaps,
	)
}

// PingFoolerMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to LoadPingFoolerObjects or ebpf.CollectionSpec.LoadAndAssign.
type PingFoolerMaps struct {
	PacketInfoBuf *ebpf.Map `ebpf:"packet_info_buf"`
	PktLen        *ebpf.Map `ebpf:"pkt_len"`
}

func (m *PingFoolerMaps) Close() error {
	return _PingFoolerClose(
		m.PacketInfoBuf,
		m.PktLen,
	)
}

// PingFoolerVariables contains all global variables after they have been loaded into the kernel.
//
// It can be passed to LoadPingFoolerObjects or ebpf.CollectionSpec.LoadAndAssign.
type PingFoolerVariables struct {
	ICMP_TYPE_REPLY *ebpf.Variable `ebpf:"ICMP_TYPE_REPLY"`
	PktCount        *ebpf.Variable `ebpf:"pkt_count"`
}

// PingFoolerPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to LoadPingFoolerObjects or ebpf.CollectionSpec.LoadAndAssign.
type PingFoolerPrograms struct {
	XdpPass *ebpf.Program `ebpf:"xdp_pass"`
}

func (p *PingFoolerPrograms) Close() error {
	return _PingFoolerClose(
		p.XdpPass,
	)
}

func _PingFoolerClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed pingfooler_bpfel.o
var _PingFoolerBytes []byte
