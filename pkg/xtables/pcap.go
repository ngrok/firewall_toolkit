//go:build linux && !arm && !arm64

/*
A wrapper for google/gopacket pcap compilation for use with xt_bpf
*/
package xtables

import (
	"fmt"

	"github.com/google/gopacket/pcap"
	"golang.org/x/net/bpf"
)

// Compile a tcpdump-style filter string to bpf compatible with xtables
func CompileBpfForXtInfo(filter string) ([]bpf.RawInstruction, error) {
	// requires libpcap and gopacket
	// xt_bpf uses the IP layer so normal pcap compilation like with tcpdump doesnt work
	// 12 is RAW IP for some reason gopacket is wrong?
	// pcap_datalink_name_to_val says 12, gopacket says 101
	// https://github.com/the-tcpdump-group/libpcap/blob/master/pcap/dlt.h#L88
	// https://github.com/google/gopacket/blob/master/layers/enums.go#L103
	// gopacket gets it right later:
	// https://github.com/google/gopacket/blob/master/layers/enums.go#L381
	// seems like a gopacket bug or something
	pcapBpf, err := pcap.CompileBPFFilter(12, 65535, filter)
	if err != nil {
		return []bpf.RawInstruction{}, fmt.Errorf("pcap compile error: %v", err)
	}

	allInstructions := []bpf.RawInstruction{}
	for _, ins := range pcapBpf {
		oneInstruction := bpf.RawInstruction{
			Op: ins.Code,
			Jt: ins.Jt,
			Jf: ins.Jf,
			K:  ins.K,
		}
		allInstructions = append(allInstructions, oneInstruction)
	}

	return allInstructions, nil
}
