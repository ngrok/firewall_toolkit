//go:build linux

/*
A library for marshaling xt_bpf structs for use with nftables
*/
package xtables

import (
	"fmt"

	"github.com/google/nftables/alignedbuff"
	"golang.org/x/net/bpf"
)

// Constants for designating the mode xt_bpf can run in
const (
	// https://github.com/torvalds/linux/blob/master/include/uapi/linux/netfilter/xt_bpf.h
	XtBpfModeBytecode = iota
	XtBpfModeFdPinned
	XtBpfModeFdElf
)

// Constants for specifying bpf program lengths and attributes
const (
	XtBpfModePathPinned = XtBpfModeFdPinned

	XtBpfMaxNumInstr = 64

	// sizeof(struct sock_filter) == 8
	XtBpfPathMax = XtBpfMaxNumInstr * 8

	// XT_ALIGN(sizeof(struct xt_bpf_info)) == 528
	// the xt_bpf_info_v1 is expected to be aligned and padded to the max
	XtBpfInfoV1Size = 528
)

/*
the following is equivalent to:

	fill := ""
	for i := len(fill); i < XT_BPF_PATH_MAX; i++ {
		fill = fill + "\x00"
	}

we need this for padding out the bpf info struct in FD mode
*/
const (
	nullSockfilterPathUnion = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
)

type bpfInfoV1 struct {
	Mode    int
	Fd      int
	Program []bpf.RawInstruction
	Path    string
}

// Marshal a pinned program path into bytes compatible with xtables
func MarshalBpfPinned(path string) ([]byte, error) {
	if len(path) > XtBpfPathMax {
		return []byte{}, fmt.Errorf("bpf path too long %v > %v", len(path), XtBpfPathMax)
	}

	xtBpfInfoBytes, err := marshallBpfInfoV1(bpfInfoV1{
		Mode: XtBpfModeFdPinned,
		Path: path,
	})

	if err != nil {
		return []byte{}, err
	}

	return xtBpfInfoBytes, nil
}

// Marshal a tcpdump-style filter string into bytes compatible with xtables
func MarshalBpfBytecode(filter string) ([]byte, error) {
	bpfFilter, err := CompileBpfForXtInfo(filter)
	if err != nil {
		return []byte{}, err
	}

	if len(bpfFilter) > XtBpfMaxNumInstr {
		return []byte{}, fmt.Errorf("bpf filter too long %v > %v", len(bpfFilter), XtBpfMaxNumInstr)
	}

	xtBpfInfoBytes, err := marshallBpfInfoV1(bpfInfoV1{
		Mode:    XtBpfModeBytecode,
		Program: bpfFilter,
	})

	if err != nil {
		return []byte{}, err
	}

	return xtBpfInfoBytes, nil
}

// Marshal a socket file descriptor into bytes compatible with xtables
func MarshalBpfFd(fd int) ([]byte, error) {
	if fd < 0 {
		return []byte{}, fmt.Errorf("bad bpf file descriptor %v", fd)
	}

	xtBpfInfoBytes, err := marshallBpfInfoV1(bpfInfoV1{
		Mode: XtBpfModeFdElf,
		Fd:   fd,
	})

	if err != nil {
		return []byte{}, err
	}

	return xtBpfInfoBytes, nil
}

func marshallBpfInfoV1(xtBpfInfo bpfInfoV1) ([]byte, error) {
	// https://github.com/torvalds/linux/blob/master/net/netfilter/xt_bpf.c#L73
	// unix.SockFilter and bpf.RawInstruction are equivalent
	realSockFilter := [XtBpfMaxNumInstr]bpf.RawInstruction{}
	realPath := xtBpfInfo.Path

	data := alignedbuff.New()

	switch xtBpfInfo.Mode {
	case XtBpfModeBytecode:
		copy(realSockFilter[:], xtBpfInfo.Program)
	case XtBpfModeFdPinned:
		for i := len(xtBpfInfo.Path); i < XtBpfPathMax; i++ {
			realPath = realPath + "\x00"
		}
	case XtBpfModeFdElf:
		// do nothing
	default:
		return nil, fmt.Errorf("unkown bpf mode: %v", xtBpfInfo.Mode)
	}

	// __u16 mode;
	data.PutUint16(uint16(xtBpfInfo.Mode))

	// __u16 bpf_program_num_elem;
	data.PutUint16(uint16(len(xtBpfInfo.Program)))

	// __s32 fd;
	data.PutInt32(int32(xtBpfInfo.Fd))

	switch xtBpfInfo.Mode {
	case XtBpfModeBytecode:
		// struct sock_filter bpf_program[XT_BPF_MAX_NUM_INSTR];
		for _, ins := range realSockFilter {
			data.PutUint16(ins.Op)
			data.PutUint8(ins.Jt)
			data.PutUint8(ins.Jf)
			data.PutUint32(ins.K)
		}
	case XtBpfModeFdPinned:
		// char path[XT_BPF_PATH_MAX];
		data.PutString(realPath)
	case XtBpfModeFdElf:
		// the sockfilter/path union isn't used in this mode but we still have to fill it up with something
		data.PutString(nullSockfilterPathUnion)
	}

	// only used in the kernel but we have to set it
	// struct bpf_prog *filter __attribute__((aligned(8)));
	data.PutUint64(0)

	out := data.Data()

	if len(out) != XtBpfInfoV1Size {
		return nil, fmt.Errorf("xtBpfInfoV1 is the wrong size %v != %v", len(out), XtBpfInfoV1Size)
	}

	return out, nil
}
