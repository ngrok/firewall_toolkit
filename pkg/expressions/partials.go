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
func SourcePort(reg uint32) *expr.Payload {
	return &expr.Payload{
		DestRegister: reg,
		Base:         expr.PayloadBaseTransportHeader,
		Offset:       SrcPortOffset,
		Len:          PortLen,
	}
}

// Returns a destination port payload expression
func DestinationPort(reg uint32) *expr.Payload {
	return &expr.Payload{
		DestRegister: reg,
		Base:         expr.PayloadBaseTransportHeader,
		Offset:       DstPortOffset,
		Len:          PortLen,
	}
}

// Returns a IPv4 source address payload expression
func IPv4SourceAddress(reg uint32) *expr.Payload {
	return &expr.Payload{
		DestRegister: reg,
		Base:         expr.PayloadBaseNetworkHeader,
		Offset:       IPv4SrcOffset,
		Len:          IPv4AddrLen,
	}
}

// Returns a IPv6 source address payload expression
func IPv6SourceAddress(reg uint32) *expr.Payload {
	return &expr.Payload{
		DestRegister: reg,
		Base:         expr.PayloadBaseNetworkHeader,
		Offset:       IPv6SrcOffest,
		Len:          IPv6AddrLen,
	}
}

// Returns a IPv4 destination address payload expression
func IPv4DestinationAddress(reg uint32) *expr.Payload {
	return &expr.Payload{
		DestRegister: reg,
		Base:         expr.PayloadBaseNetworkHeader,
		Offset:       IPv4DstOffset,
		Len:          IPv4AddrLen,
	}
}

// Returns a IPv6 destination address payload expression
func IPv6DestinationAddress(reg uint32) *expr.Payload {
	return &expr.Payload{
		DestRegister: reg,
		Base:         expr.PayloadBaseNetworkHeader,
		Offset:       IPv6DstOffset,
		Len:          IPv6AddrLen,
	}
}

// Returns a port set lookup expression
func PortSetLookUp(set *nftables.Set, reg uint32) *expr.Lookup {
	return &expr.Lookup{
		SourceRegister: reg,
		SetName:        set.Name,
		SetID:          set.ID,
	}
}

// Returns an IP set lookup expression
func IPSetLookUp(set *nftables.Set, reg uint32) *expr.Lookup {
	return &expr.Lookup{
		SourceRegister: reg,
		SetName:        set.Name,
		SetID:          set.ID,
	}
}

// Returns a meta expression
func Meta(meta expr.MetaKey, reg uint32) *expr.Meta {
	return &expr.Meta{
		Key:      meta,
		Register: reg,
	}
}

// Returns a counter expression
func Counter() *expr.Counter {
	return &expr.Counter{}
}

// Returns an equal comparison expression
func Equals(data []byte, reg uint32) *expr.Cmp {
	return &expr.Cmp{
		Op:       expr.CmpOpEq,
		Register: reg,
		Data:     data,
	}
}

// Returns a not-equal comparison expression
func NotEquals(data []byte, reg uint32) *expr.Cmp {
	return &expr.Cmp{
		Op:       expr.CmpOpNeq,
		Register: reg,
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
func Match(name string, revision uint32, info xt.InfoAny) *expr.Match {
	return &expr.Match{
		Name: name,
		Rev:  revision,
		Info: info,
	}
}

// Returns a xtables match expression of unknown type
func MatchUnknown(name string, revision uint32, info []byte) *expr.Match {
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
func CompareProtocolFamilyWithRegister(proto byte, reg uint32) ([]expr.Any, error) {
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
func CompareTransportProtocolWithRegister(proto byte, reg uint32) ([]expr.Any, error) {
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
func CompareSourcePort(port uint16) ([]expr.Any, error) {
	return CompareSourcePortWithRegister(port, defaultRegister)
}

// Returns a list of expressions that will compare the source port of traffic, with a user defined register
func CompareSourcePortWithRegister(port uint16, reg uint32) ([]expr.Any, error) {
	if err := utils.ValidatePort(port); err != nil {
		return []expr.Any{}, err
	}

	return []expr.Any{
		SourcePort(reg),
		Equals(binaryutil.BigEndian.PutUint16(port), reg),
	}, nil
}

// Returns a list of expressions that will compare the destination port of traffic
func CompareDestinationPort(port uint16) ([]expr.Any, error) {
	return CompareDestinationPortWithRegister(port, defaultRegister)
}

// Returns a list of expressions that will compare the destination port of traffic, with a user defined register
func CompareDestinationPortWithRegister(port uint16, reg uint32) ([]expr.Any, error) {
	if err := utils.ValidatePort(port); err != nil {
		return []expr.Any{}, err
	}

	return []expr.Any{
		DestinationPort(reg),
		Equals(binaryutil.BigEndian.PutUint16(port), reg),
	}, nil
}

// Returns a list of expressions that will compare the source address of traffic
func CompareSourceAddress(ip netip.Addr) ([]expr.Any, error) {
	return CompareSourceAddressWithRegister(ip, defaultRegister)
}

// Returns a list of expressions that will compare the source address of traffic, with a user defined register
func CompareSourceAddressWithRegister(ip netip.Addr, reg uint32) ([]expr.Any, error) {
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
func CompareDestinationAddressWithRegister(ip netip.Addr, reg uint32) ([]expr.Any, error) {
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
func CompareSourceAddressSetWithRegister(set *nftables.Set, reg uint32) ([]expr.Any, error) {
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
func CompareDestinationAddressSetWithRegister(set *nftables.Set, reg uint32) ([]expr.Any, error) {
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
func CompareSourcePortSetWithRegister(set *nftables.Set, reg uint32) ([]expr.Any, error) {
	return []expr.Any{SourcePort(reg), PortSetLookUp(set, reg)}, nil
}

// Returns a list of expressions that will compare the destination port of traffic against a set
func CompareDestinationPortSet(set *nftables.Set) ([]expr.Any, error) {
	return CompareDestinationPortSetWithRegister(set, defaultRegister)
}

// Returns a list of expressions that will compare the destination port of traffic against a set, with a user defined register
func CompareDestinationPortSetWithRegister(set *nftables.Set, reg uint32) ([]expr.Any, error) {
	return []expr.Any{DestinationPort(reg), PortSetLookUp(set, reg)}, nil
}

func BitwiseWithRegisters(sourceRegister uint32, destRegister uint32, length uint32, mask []byte, xor []byte) *expr.Bitwise {
	return &expr.Bitwise{
		SourceRegister: sourceRegister,
		DestRegister:   destRegister,
		Len:            length,
		Mask:           mask,
		Xor:            xor,
	}
}

func Bitwise(length uint32, mask []byte, xor []byte) *expr.Bitwise {
	return BitwiseWithRegisters(defaultRegister, defaultRegister, length, mask, xor)
}

func LoadCtByKeyWithRegister(ctKey expr.CtKey, reg uint32) (*expr.Ct, error) {
	// Current upper and lower bound for valid CtKey values
	if ctKey < expr.CtKeySTATE || ctKey > expr.CtKeyEVENTMASK {
		return &expr.Ct{}, fmt.Errorf("invalid CtKey given")
	}

	return &expr.Ct{
		Register: reg,
		Key:      ctKey,
	}, nil
}

func LoadCtByKey(ctKey expr.CtKey) (*expr.Ct, error) {
	return LoadCtByKeyWithRegister(ctKey, defaultRegister)
}

// Makes the comparison specified by `mask` to the CT State already loaded in `reg`.
// Valid values for mask are:
// expr.CtStateBitInvalid = 1
// expr.CtStateBitESTABLISHED = 2
// expr.CtStateBitRELATED = 4
// expr.CtStateBitNEW = 8
// expr.CtStateBitUNTRACKED = 64
// Or combinations with a bitwise OR: `expr.CtStateBitNEW | expr.CtStateBitUNTRACKED`
func CompareCtStateWithRegister(reg uint32, mask uint32) ([]expr.Any, error) {
	if mask == 0 {
		return []expr.Any{}, fmt.Errorf("invalid input mask, mask cannot be empty")
	}
	// Assuming any combination of the listed values are valid, the only "invalid"
	// values are ones where a bit in the uint32 is set where that bit doesn't
	// represent a value. I.e., the bit for 16 doesn't map to a valid value, so
	// if it is set, it's invalid.
	// The following check will fail if any bits are set in invalid positions
	validMask := expr.CtStateBitINVALID | expr.CtStateBitESTABLISHED | expr.CtStateBitRELATED | expr.CtStateBitNEW | expr.CtStateBitUNTRACKED
	if (validMask | mask) != validMask {
		return []expr.Any{}, fmt.Errorf("invalid input mask, not a valid combination of CT states")
	}

	return []expr.Any{
		BitwiseWithRegisters(reg, reg, 4, binaryutil.NativeEndian.PutUint32(mask), binaryutil.BigEndian.PutUint32(0)),
		NotEquals([]byte{0, 0, 0, 0}, reg),
	}, nil
}

func CompareCtState(mask uint32) ([]expr.Any, error) {
	return CompareCtStateWithRegister(defaultRegister, mask)
}
