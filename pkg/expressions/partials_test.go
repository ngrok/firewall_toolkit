//go:build linux

package expressions

import (
	"net/netip"
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"github.com/google/nftables/xt"
	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

func TestCompareProtocolFamily(t *testing.T) {
	res, err := CompareProtocolFamily(unix.NFPROTO_IPV4)
	assert.Nil(t, err)
	assert.Equal(t, 2, len(res))
	assert.Equal(t, &expr.Meta{Key: 0xf, SourceRegister: false, Register: 0x1}, res[0])
	assert.Equal(t, &expr.Cmp{Op: 0x0, Register: 0x1, Data: []uint8{0x2}}, res[1])
}

func TestCompareBadProtocolFamily(t *testing.T) {
	res, err := CompareProtocolFamily(0xf6)
	assert.Error(t, err)
	assert.Equal(t, []expr.Any{}, res)
}

func TestCompareTransportProtocol(t *testing.T) {
	res, err := CompareTransportProtocol(unix.IPPROTO_TCP)
	assert.Nil(t, err)
	assert.Equal(t, 2, len(res))
	assert.Equal(t, &expr.Meta{Key: 0x10, SourceRegister: false, Register: 0x1}, res[0])
	assert.Equal(t, &expr.Cmp{Op: 0x0, Register: 0x1, Data: []uint8{0x6}}, res[1])
}

func TestCompareSourcePort(t *testing.T) {
	res, err := CompareSourcePort(8080)
	assert.Nil(t, err)
	assert.Equal(t, 2, len(res))
	assert.Equal(t, &expr.Payload{OperationType: 0x0, DestRegister: 0x1, SourceRegister: 0x0, Base: 0x2, Offset: 0x0, Len: 0x2, CsumType: 0x0, CsumOffset: 0x0, CsumFlags: 0x0}, res[0])
	assert.Equal(t, &expr.Cmp{Op: 0x0, Register: 0x1, Data: []uint8{0x1f, 0x90}}, res[1])
}

func TestCompareDestinationPort(t *testing.T) {
	res, err := CompareDestinationPort(8181)
	assert.Nil(t, err)
	assert.Equal(t, 2, len(res))
	assert.Equal(t, &expr.Payload{OperationType: 0x0, DestRegister: 0x1, SourceRegister: 0x0, Base: 0x2, Offset: 0x2, Len: 0x2, CsumType: 0x0, CsumOffset: 0x0, CsumFlags: 0x0}, res[0])
	assert.Equal(t, &expr.Cmp{Op: 0x0, Register: 0x1, Data: []uint8{0x1f, 0xf5}}, res[1])
}

func TestCompareSourceV4Address(t *testing.T) {
	ip := netip.MustParseAddr("198.51.100.200")
	res, err := CompareSourceAddress(ip)
	assert.Nil(t, err)
	assert.Equal(t, 2, len(res))
	assert.Equal(t, &expr.Payload{OperationType: 0x0, DestRegister: 0x1, SourceRegister: 0x0, Base: 0x1, Offset: 0xc, Len: 0x4, CsumType: 0x0, CsumOffset: 0x0, CsumFlags: 0x0}, res[0])
	assert.Equal(t, &expr.Cmp{Op: 0x0, Register: 0x1, Data: []uint8{0xc6, 0x33, 0x64, 0xc8}}, res[1])
}

func TestCompareDestinationV4Address(t *testing.T) {
	ip := netip.MustParseAddr("198.51.100.200")
	res, err := CompareDestinationAddress(ip)
	assert.Nil(t, err)
	assert.Equal(t, 2, len(res))
	assert.Equal(t, &expr.Payload{OperationType: 0x0, DestRegister: 0x1, SourceRegister: 0x0, Base: 0x1, Offset: 0x10, Len: 0x4, CsumType: 0x0, CsumOffset: 0x0, CsumFlags: 0x0}, res[0])
	assert.Equal(t, &expr.Cmp{Op: 0x0, Register: 0x1, Data: []uint8{0xc6, 0x33, 0x64, 0xc8}}, res[1])
}

func TestCompareSourceV6Address(t *testing.T) {
	ip := netip.MustParseAddr("2001:db80:85a3:1:1:8a2e:1370:7334")
	res, err := CompareSourceAddress(ip)
	assert.Nil(t, err)
	assert.Equal(t, 2, len(res))
	assert.Equal(t, &expr.Payload{OperationType: 0x0, DestRegister: 0x1, SourceRegister: 0x0, Base: 0x1, Offset: 0x8, Len: 0x10, CsumType: 0x0, CsumOffset: 0x0, CsumFlags: 0x0}, res[0])
	assert.Equal(t, &expr.Cmp{Op: 0x0, Register: 0x1, Data: []uint8{0x20, 0x1, 0xdb, 0x80, 0x85, 0xa3, 0x0, 0x1, 0x0, 0x1, 0x8a, 0x2e, 0x13, 0x70, 0x73, 0x34}}, res[1])
}

func TestCompareDestinationV6Address(t *testing.T) {
	ip := netip.MustParseAddr("2001:db80:85a3:1:1:8a2e:1370:7334")
	res, err := CompareDestinationAddress(ip)
	assert.Nil(t, err)
	assert.Equal(t, 2, len(res))
	assert.Equal(t, &expr.Payload{OperationType: 0x0, DestRegister: 0x1, SourceRegister: 0x0, Base: 0x1, Offset: 0x18, Len: 0x10, CsumType: 0x0, CsumOffset: 0x0, CsumFlags: 0x0}, res[0])
	assert.Equal(t, &expr.Cmp{Op: 0x0, Register: 0x1, Data: []uint8{0x20, 0x1, 0xdb, 0x80, 0x85, 0xa3, 0x0, 0x1, 0x0, 0x1, 0x8a, 0x2e, 0x13, 0x70, 0x73, 0x34}}, res[1])
}

func TestCompareSourceV4AddressSet(t *testing.T) {
	res, err := CompareSourceAddressSet(&nftables.Set{Name: "testsets", KeyType: nftables.TypeIPAddr})
	assert.Nil(t, err)
	assert.Equal(t, 2, len(res))
	assert.Equal(t, &expr.Payload{OperationType: 0x0, DestRegister: 0x1, SourceRegister: 0x0, Base: 0x1, Offset: 0xc, Len: 0x4, CsumType: 0x0, CsumOffset: 0x0, CsumFlags: 0x0}, res[0])
	assert.Equal(t, &expr.Lookup{SourceRegister: 0x1, DestRegister: 0x0, IsDestRegSet: false, SetID: 0x0, SetName: "testsets", Invert: false}, res[1])
}

func TestCompareDestinationV4AddressSet(t *testing.T) {
	res, err := CompareDestinationAddressSet(&nftables.Set{Name: "testsets", KeyType: nftables.TypeIPAddr})
	assert.Nil(t, err)
	assert.Equal(t, 2, len(res))
	assert.Equal(t, &expr.Payload{OperationType: 0x0, DestRegister: 0x1, SourceRegister: 0x0, Base: 0x1, Offset: 0x10, Len: 0x4, CsumType: 0x0, CsumOffset: 0x0, CsumFlags: 0x0}, res[0])
	assert.Equal(t, &expr.Lookup{SourceRegister: 0x1, DestRegister: 0x0, IsDestRegSet: false, SetID: 0x0, SetName: "testsets", Invert: false}, res[1])
}

func TestCompareSourceV6AddressSet(t *testing.T) {
	res, err := CompareSourceAddressSet(&nftables.Set{Name: "testsets", KeyType: nftables.TypeIP6Addr})
	assert.Nil(t, err)
	assert.Equal(t, 2, len(res))
	assert.Equal(t, &expr.Payload{OperationType: 0x0, DestRegister: 0x1, SourceRegister: 0x0, Base: 0x1, Offset: 0x8, Len: 0x10, CsumType: 0x0, CsumOffset: 0x0, CsumFlags: 0x0}, res[0])
	assert.Equal(t, &expr.Lookup{SourceRegister: 0x1, DestRegister: 0x0, IsDestRegSet: false, SetID: 0x0, SetName: "testsets", Invert: false}, res[1])
}

func TestCompareDestinationV6AddressSet(t *testing.T) {
	res, err := CompareDestinationAddressSet(&nftables.Set{Name: "testsets", KeyType: nftables.TypeIP6Addr})
	assert.Nil(t, err)
	assert.Equal(t, 2, len(res))
	assert.Equal(t, &expr.Payload{OperationType: 0x0, DestRegister: 0x1, SourceRegister: 0x0, Base: 0x1, Offset: 0x18, Len: 0x10, CsumType: 0x0, CsumOffset: 0x0, CsumFlags: 0x0}, res[0])
	assert.Equal(t, &expr.Lookup{SourceRegister: 0x1, DestRegister: 0x0, IsDestRegSet: false, SetID: 0x0, SetName: "testsets", Invert: false}, res[1])
}

func TestCompareSourcePortSet(t *testing.T) {
	res, err := CompareSourcePortSet(&nftables.Set{Name: "testsets", KeyType: nftables.TypeInetService})
	assert.Nil(t, err)
	assert.Equal(t, 2, len(res))
	assert.Equal(t, &expr.Payload{OperationType: 0x0, DestRegister: 0x1, SourceRegister: 0x0, Base: 0x2, Offset: 0x0, Len: 0x2, CsumType: 0x0, CsumOffset: 0x0, CsumFlags: 0x0}, res[0])
	assert.Equal(t, &expr.Lookup{SourceRegister: 0x1, DestRegister: 0x0, IsDestRegSet: false, SetID: 0x0, SetName: "testsets", Invert: false}, res[1])
}

func TestCompareDestinationPortSet(t *testing.T) {
	res, err := CompareDestinationPortSet(&nftables.Set{Name: "testsets", KeyType: nftables.TypeInetService})
	assert.Nil(t, err)
	assert.Equal(t, 2, len(res))
	assert.Equal(t, &expr.Payload{OperationType: 0x0, DestRegister: 0x1, SourceRegister: 0x0, Base: 0x2, Offset: 0x2, Len: 0x2, CsumType: 0x0, CsumOffset: 0x0, CsumFlags: 0x0}, res[0])
	assert.Equal(t, &expr.Lookup{SourceRegister: 0x1, DestRegister: 0x0, IsDestRegSet: false, SetID: 0x0, SetName: "testsets", Invert: false}, res[1])
}

func TestSimplePartials(t *testing.T) {
	assert.Equal(t, &expr.Counter{}, Counter())
	assert.Equal(t, &expr.Verdict{Kind: expr.VerdictAccept}, Accept())
	assert.Equal(t, &expr.Verdict{Kind: expr.VerdictDrop}, Drop())
}

func TestMatch(t *testing.T) {
	info := []byte{0xd, 0xe, 0xa, 0xd}
	match := MatchUnknown("test", 9999, info)
	assert.Equal(t, "test", match.Name)
	assert.Equal(t, uint32(9999), match.Rev)
	assert.Equal(t, &xt.Unknown{0xd, 0xe, 0xa, 0xd}, match.Info)
}

func TestMatchBpfWithVerdict(t *testing.T) {
	info := []byte{0xd, 0xe, 0xa, 0xd}
	match := MatchBpfWithVerdict(info, Drop())
	assert.Equal(t, 2, len(match))
	assert.Equal(t, &expr.Match{Name: "bpf", Rev: 1, Info: &xt.Unknown{0xd, 0xe, 0xa, 0xd}}, match[0])
	assert.Equal(t, &expr.Verdict{Kind: expr.VerdictDrop}, match[1])
}

func TestCompareBadAddress(t *testing.T) {
	res, err := CompareSourceAddress(netip.Addr{})
	assert.Error(t, err)
	assert.Equal(t, []expr.Any{}, res)

	res, err = CompareDestinationAddress(netip.Addr{})
	assert.Error(t, err)
	assert.Equal(t, []expr.Any{}, res)
}

func TestCompareBadAddressSet(t *testing.T) {
	res, err := CompareSourceAddressSet(&nftables.Set{Name: "testsets", KeyType: nftables.TypeARPHRD})
	assert.Error(t, err)
	assert.Equal(t, []expr.Any{}, res)

	res, err = CompareDestinationAddressSet(&nftables.Set{Name: "testsets", KeyType: nftables.TypeARPHRD})
	assert.Error(t, err)
	assert.Equal(t, []expr.Any{}, res)
}

func TestLoadCtStateInput(t *testing.T) {
	ct, err := LoadCtByKey(expr.CtKeyDIRECTION)
	assert.Nil(t, err)
	assert.Equal(t, &expr.Ct{Register: defaultRegister, SourceRegister: false, Key: expr.CtKeyDIRECTION}, ct)
}

func TestLoadCtStateInvalidInput(t *testing.T) {
	state, err := LoadCtByKey(20) // not a valid value
	assert.Error(t, err)
	assert.Equal(t, &expr.Ct{}, state)
}

func TestCompareCtStateWithRegisterValidInput(t *testing.T) {
	cmp, err := CompareCtStateWithRegister(defaultRegister, expr.CtStateBitNEW|expr.CtStateBitUNTRACKED)
	assert.Nil(t, err)
	assert.Equal(t, &expr.Bitwise{SourceRegister: defaultRegister, DestRegister: defaultRegister, Len: 4, Mask: binaryutil.NativeEndian.PutUint32(expr.CtStateBitNEW | expr.CtStateBitUNTRACKED), Xor: binaryutil.NativeEndian.PutUint32(0)}, cmp[0])
	assert.Equal(t, &expr.Cmp{Op: expr.CmpOpNeq, Register: defaultRegister, Data: []byte{0, 0, 0, 0}}, cmp[1])
}

func TestCompareCtStateWithRegisterInvalidInput(t *testing.T) {
	res, err := CompareCtStateWithRegister(defaultRegister, expr.CtStateBitNEW|16) // 16 isn't a valid value
	assert.Error(t, err)
	assert.Equal(t, []expr.Any{}, res)
}
