//go:build linux

/*
A collection of google/nftables expression partials used to compose rules
*/
package expressions

import (
	"fmt"
	"net/netip"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"github.com/google/nftables/xt"
	"golang.org/x/sys/unix"

	"github.com/ngrok/firewall_toolkit/pkg/utils"
)

// Transport protocol lengths and offsets
const (
	SrcPortOffset = 0
	DstPortOffset = 2
	PortLen       = 2
)

// IPv4 lengths and offsets
const (
	IPv4SrcOffset = 12
	IPv4DstOffset = 16
	IPv4AddrLen   = 4
)

// IPv6 lengths and offsets
const (
	IPv6SrcOffest = 8
	IPv6DstOffset = 24
	IPv6AddrLen   = 16
)

// Default register and default xt_bpf version
const (
	defaultRegister = 1
	bpfRevision     = 1
)

// Returns a source port payload expression
func SourcePort(reg int) *expr.Payload {
	return &expr.Payload{
		DestRegister: uint32(reg),
		Base:         expr.PayloadBaseTransportHeader,
		Offset:       SrcPortOffset,
		Len:          PortLen,
	}
}

// Returns a destination port payload expression
func DestinationPort(reg int) *expr.Payload {
	return &expr.Payload{
		DestRegister: uint32(reg),
		Base:         expr.PayloadBaseTransportHeader,
		Offset:       DstPortOffset,
		Len:          PortLen,
	}
}

// Returns a IPv4 source address payload expression
func IPv4SourceAddress(reg int) *expr.Payload {
	return &expr.Payload{
		DestRegister: uint32(reg),
		Base:         expr.PayloadBaseNetworkHeader,
		Offset:       IPv4SrcOffset,
		Len:          IPv4AddrLen,
	}
}

// Returns a IPv6 source address payload expression
func IPv6SourceAddress(reg int) *expr.Payload {
	return &expr.Payload{
		DestRegister: uint32(reg),
		Base:         expr.PayloadBaseNetworkHeader,
		Offset:       IPv6SrcOffest,
		Len:          IPv6AddrLen,
	}
}

// Returns a IPv4 destination address payload expression
func IPv4DestinationAddress(reg int) *expr.Payload {
	return &expr.Payload{
		DestRegister: uint32(reg),
		Base:         expr.PayloadBaseNetworkHeader,
		Offset:       IPv4DstOffset,
		Len:          IPv4AddrLen,
	}
}

// Returns a IPv6 destination address payload expression
func IPv6DestinationAddress(reg int) *expr.Payload {
	return &expr.Payload{
		DestRegister: uint32(reg),
		Base:         expr.PayloadBaseNetworkHeader,
		Offset:       IPv6DstOffset,
		Len:          IPv6AddrLen,
	}
}

// Returns a port set lookup expression
func PortSetLookUp(set *nftables.Set, reg int) *expr.Lookup {
	return &expr.Lookup{
		SourceRegister: uint32(reg),
		SetName:        set.Name,
		SetID:          set.ID,
	}
}

// Returns an IP set lookup expression
func IPSetLookUp(set *nftables.Set, reg int) *expr.Lookup {
	return &expr.Lookup{
		SourceRegister: uint32(reg),
		SetName:        set.Name,
		SetID:          set.ID,
	}
}

// Returns a meta expression
func Meta(meta expr.MetaKey, reg int) *expr.Meta {
	return &expr.Meta{
		Key:      meta,
		Register: uint32(reg),
	}
}

// Returns a counter expression
func Counter() *expr.Counter {
	return &expr.Counter{}
}

// Returns an equal comparison expression
func Equals(data []byte, reg int) *expr.Cmp {
	return &expr.Cmp{
		Op:       expr.CmpOpEq,
		Register: uint32(reg),
		Data:     data,
	}
}

// Returns an accept verdict expression
func Accept() *expr.Verdict {
	return &expr.Verdict{
		Kind: expr.VerdictAccept,
	}
}

// Returns an drop verdict expression
func Drop() *expr.Verdict {
	return &expr.Verdict{
		Kind: expr.VerdictDrop,
	}
}

// Returns a xtables match expression
func Match(name string, revision int, info xt.InfoAny) *expr.Match {
	return &expr.Match{
		Name: name,
		Rev:  uint32(revision),
		Info: info,
	}
}

// Returns a xtables match expression of unknown type
func MatchUnknown(name string, revision int, info []byte) *expr.Match {
	infoBytes := xt.Unknown(info)
	return Match(name, revision, &infoBytes)
}

// Returns a xtables match bpf expression
func MatchBpf(info []byte) *expr.Match {
	return MatchUnknown("bpf", bpfRevision, info)
}

// Returns a xtables match bpf expression with a verdict
func MatchBpfWithVerdict(info []byte, verdict *expr.Verdict) []expr.Any {
	return []expr.Any{
		MatchBpf(info),
		verdict,
	}
}

// Returns a list of expressions that will compare the netfilter protocol family of traffic
func CompareProtocolFamily(proto byte) ([]expr.Any, error) {
	return CompareProtocolFamilyWithRegister(proto, defaultRegister)
}

// Returns a list of expressions that will compare the protocol family of traffic, with a user defined register
func CompareProtocolFamilyWithRegister(proto byte, reg int) ([]expr.Any, error) {
	if int(proto) >= unix.NFPROTO_NUMPROTO {
		return []expr.Any{}, fmt.Errorf("invalid protocol family %v", proto)
	}

	out := []expr.Any{
		Meta(expr.MetaKeyNFPROTO, reg),
		Equals([]byte{proto}, reg),
	}
	return out, nil
}

// Returns a list of expressions that will compare the transport protocol of traffic
func CompareTransportProtocol(proto byte) ([]expr.Any, error) {
	return CompareTransportProtocolWithRegister(proto, defaultRegister)
}

// Returns a list of expressions that will compare the transport protocol of traffic, with a user defined register
func CompareTransportProtocolWithRegister(proto byte, reg int) ([]expr.Any, error) {
	// it seems like netlink and/or nftables assume proto is unint8 but it can be larger
	// https://elixir.bootlin.com/linux/latest/source/include/uapi/linux/in.h#L83
	// we use byte here to work around this and support everything but MPTCP
	// using a uint16 value doesn't seem to work with nftables, resulting in
	// "netlink: Error: Relational expression size mismatch"

	return []expr.Any{
		Meta(expr.MetaKeyL4PROTO, reg),
		Equals([]byte{proto}, reg),
	}, nil
}

// Returns a list of expressions that will compare the source port of traffic
func CompareSourcePort(port int) ([]expr.Any, error) {
	return CompareSourcePortWithRegister(port, defaultRegister)
}

// Returns a list of expressions that will compare the source port of traffic, with a user defined register
func CompareSourcePortWithRegister(port int, reg int) ([]expr.Any, error) {
	if err := utils.ValidatePort(port); err != nil {
		return []expr.Any{}, err
	}

	return []expr.Any{
		SourcePort(reg),
		Equals(binaryutil.BigEndian.PutUint16(uint16(port)), reg),
	}, nil
}

// Returns a list of expressions that will compare the destination port of traffic
func CompareDestinationPort(port int) ([]expr.Any, error) {
	return CompareDestinationPortWithRegister(port, defaultRegister)
}

// Returns a list of expressions that will compare the destination port of traffic, with a user defined register
func CompareDestinationPortWithRegister(port int, reg int) ([]expr.Any, error) {
	if err := utils.ValidatePort(port); err != nil {
		return []expr.Any{}, err
	}

	return []expr.Any{
		DestinationPort(reg),
		Equals(binaryutil.BigEndian.PutUint16(uint16(port)), reg),
	}, nil
}

// Returns a list of expressions that will compare the source address of traffic
func CompareSourceAddress(ip netip.Addr) ([]expr.Any, error) {
	return CompareSourceAddressWithRegister(ip, defaultRegister)
}

// Returns a list of expressions that will compare the source address of traffic, with a user defined register
func CompareSourceAddressWithRegister(ip netip.Addr, reg int) ([]expr.Any, error) {
	if err := utils.ValidateAddress(ip); err != nil {
		return []expr.Any{}, err
	}

	if ip.Is4() {
		return []expr.Any{
			IPv4SourceAddress(reg),
			Equals(ip.AsSlice(), reg),
		}, nil
	} else if ip.Is6() {
		return []expr.Any{
			IPv6SourceAddress(reg),
			Equals(ip.AsSlice(), reg),
		}, nil
	} else {
		return []expr.Any{}, fmt.Errorf("unknown ip type %v", ip)
	}
}

// Returns a list of expressions that will compare the destination address of traffic
func CompareDestinationAddress(ip netip.Addr) ([]expr.Any, error) {
	return CompareDestinationAddressWithRegister(ip, defaultRegister)
}

// Returns a list of expressions that will compare the destination address of traffic, with a user defined register
func CompareDestinationAddressWithRegister(ip netip.Addr, reg int) ([]expr.Any, error) {
	if err := utils.ValidateAddress(ip); err != nil {
		return []expr.Any{}, err
	}

	if ip.Is4() {
		return []expr.Any{
			IPv4DestinationAddress(reg),
			Equals(ip.AsSlice(), reg),
		}, nil
	} else if ip.Is6() {
		return []expr.Any{
			IPv6DestinationAddress(reg),
			Equals(ip.AsSlice(), reg),
		}, nil
	} else {
		return []expr.Any{}, fmt.Errorf("unknown ip type %v", ip)
	}
}

// Returns a list of expressions that will compare the source address of traffic against a set
func CompareSourceAddressSet(set *nftables.Set) ([]expr.Any, error) {
	return CompareSourceAddressSetWithRegister(set, defaultRegister)
}

// Returns a list of expressions that will compare the source address of traffic against a set, with a user defined register
func CompareSourceAddressSetWithRegister(set *nftables.Set, reg int) ([]expr.Any, error) {
	var srcAddr *expr.Payload
	switch set.KeyType {
	case nftables.TypeIPAddr:
		srcAddr = IPv4SourceAddress(reg)
	case nftables.TypeIP6Addr:
		srcAddr = IPv6SourceAddress(reg)
	default:
		return []expr.Any{}, fmt.Errorf("unsupported set key type %v", set.KeyType.Name)
	}

	return []expr.Any{srcAddr, IPSetLookUp(set, reg)}, nil
}

// Returns a list of expressions that will compare the destination address of traffic against a set
func CompareDestinationAddressSet(set *nftables.Set) ([]expr.Any, error) {
	return CompareDestinationAddressSetWithRegister(set, defaultRegister)
}

// Returns a list of expressions that will compare the destnation address of traffic against a set, with a user defined register
func CompareDestinationAddressSetWithRegister(set *nftables.Set, reg int) ([]expr.Any, error) {
	var dstAddr *expr.Payload
	switch set.KeyType {
	case nftables.TypeIPAddr:
		dstAddr = IPv4DestinationAddress(reg)
	case nftables.TypeIP6Addr:
		dstAddr = IPv6DestinationAddress(reg)
	default:
		return []expr.Any{}, fmt.Errorf("unsupported set key type %v", set.KeyType.Name)
	}

	return []expr.Any{dstAddr, IPSetLookUp(set, reg)}, nil
}

// Returns a list of expressions that will compare the source port of traffic against a set
func CompareSourcePortSet(set *nftables.Set) ([]expr.Any, error) {
	return CompareSourcePortSetWithRegister(set, defaultRegister)
}

// Returns a list of expressions that will compare the source port of traffic against a set, with a user defined register
func CompareSourcePortSetWithRegister(set *nftables.Set, reg int) ([]expr.Any, error) {
	return []expr.Any{SourcePort(reg), PortSetLookUp(set, reg)}, nil
}

// Returns a list of expressions that will compare the destination port of traffic against a set
func CompareDestinationPortSet(set *nftables.Set) ([]expr.Any, error) {
	return CompareDestinationPortSetWithRegister(set, defaultRegister)
}

// Returns a list of expressions that will compare the destination port of traffic against a set, with a user defined register
func CompareDestinationPortSetWithRegister(set *nftables.Set, reg int) ([]expr.Any, error) {
	return []expr.Any{DestinationPort(reg), PortSetLookUp(set, reg)}, nil
}
