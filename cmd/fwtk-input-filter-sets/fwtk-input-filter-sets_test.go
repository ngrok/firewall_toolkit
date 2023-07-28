//go:build linux

package main

import (
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/ngrok/firewall_toolkit/pkg/expressions"
	"github.com/ngrok/firewall_toolkit/pkg/rule"
	"github.com/stretchr/testify/assert"
)

func TestGenerateIPv4Rule(t *testing.T) {
	want := []expr.Any{
		&expr.Meta{Key: 0xf, SourceRegister: false, Register: 0x1},
		&expr.Cmp{Op: 0x0, Register: 0x1, Data: []uint8{0x2}},
		&expr.Meta{Key: 0x10, SourceRegister: false, Register: 0x1},
		&expr.Cmp{Op: 0x0, Register: 0x1, Data: []uint8{0x6}},
		&expr.Payload{OperationType: 0x0, DestRegister: 0x1, SourceRegister: 0x0, Base: 0x1, Offset: 0xc, Len: 0x4, CsumType: 0x0, CsumOffset: 0x0, CsumFlags: 0x0},
		&expr.Lookup{SourceRegister: 0x1, DestRegister: 0x0, IsDestRegSet: false, SetID: 0x0, SetName: "testipset", Invert: false},
		&expr.Payload{OperationType: 0x0, DestRegister: 0x1, SourceRegister: 0x0, Base: 0x2, Offset: 0x2, Len: 0x2, CsumType: 0x0, CsumOffset: 0x0, CsumFlags: 0x0},
		&expr.Lookup{SourceRegister: 0x1, DestRegister: 0x0, IsDestRegSet: false, SetID: 0x0, SetName: "testportset", Invert: false},
		&expr.Counter{Bytes: 0x0, Packets: 0x0},
		&expr.Verdict{Kind: 0, Chain: ""},
	}

	portSet := nftables.Set{Name: "testportset", KeyType: nftables.TypeInetService}
	ipSet := nftables.Set{Name: "testipset", KeyType: nftables.TypeIPAddr}
	// res, err := generateExpression(&portSet, &ipSet)
	res, err := rule.Build(
		expr.VerdictDrop,
		rule.AddressFamily(expressions.IPv4),
		rule.TransportProtocol(expressions.TCP),
		rule.SourceAddressSet(&ipSet),
		rule.DestinationPortSet(&portSet),
		rule.Any(expressions.Counter()),
	)
	assert.Nil(t, err)

	assert.Equal(t, len(want), len(res))

	for i, e := range res {
		assert.Equal(t, want[i], e)
	}
}

func TestGenerateIPv6Rule(t *testing.T) {
	want := []expr.Any{
		&expr.Meta{Key: 0xf, SourceRegister: false, Register: 0x1},
		&expr.Cmp{Op: 0x0, Register: 0x1, Data: []uint8{0xa}},
		&expr.Meta{Key: 0x10, SourceRegister: false, Register: 0x1},
		&expr.Cmp{Op: 0x0, Register: 0x1, Data: []uint8{0x6}},
		&expr.Payload{OperationType: 0x0, DestRegister: 0x1, SourceRegister: 0x0, Base: 0x1, Offset: 0x8, Len: 0x10, CsumType: 0x0, CsumOffset: 0x0, CsumFlags: 0x0},
		&expr.Lookup{SourceRegister: 0x1, DestRegister: 0x0, IsDestRegSet: false, SetID: 0x0, SetName: "testipset", Invert: false},
		&expr.Payload{OperationType: 0x0, DestRegister: 0x1, SourceRegister: 0x0, Base: 0x2, Offset: 0x2, Len: 0x2, CsumType: 0x0, CsumOffset: 0x0, CsumFlags: 0x0},
		&expr.Lookup{SourceRegister: 0x1, DestRegister: 0x0, IsDestRegSet: false, SetID: 0x0, SetName: "testportset", Invert: false},
		&expr.Counter{Bytes: 0x0, Packets: 0x0},
		&expr.Verdict{Kind: 0, Chain: ""},
	}

	portSet := nftables.Set{Name: "testportset", KeyType: nftables.TypeInetService}
	ipSet := nftables.Set{Name: "testipset", KeyType: nftables.TypeIP6Addr}
	// res, err := generateExpression(&portSet, &ipSet)
	res, err := rule.Build(
		expr.VerdictDrop,
		rule.AddressFamily(expressions.IPv6),
		rule.TransportProtocol(expressions.TCP),
		rule.SourceAddressSet(&ipSet),
		rule.DestinationPortSet(&portSet),
		rule.Any(expressions.Counter()),
	)
	assert.Nil(t, err)

	assert.Equal(t, len(want), len(res))

	for i, e := range res {
		assert.Equal(t, want[i], e)
	}
}

func TestCreateRuleData(t *testing.T) {
	portSet := &nftables.Set{Name: "testportset", KeyType: nftables.TypeInetService}
	ipv4Set := &nftables.Set{Name: "testipv4set", KeyType: nftables.TypeIPAddr}
	ipv6Set := &nftables.Set{Name: "testipv6set", KeyType: nftables.TypeIP6Addr}

	ruleInfo := newRuleInfo(portSet, ipv4Set, ipv6Set)
	ruleData, err := ruleInfo.createRuleData()
	assert.Nil(t, err)

	assert.Equal(t, ruleData[0].ID, []byte{0xd, 0xe, 0xa, 0xd})
	assert.Equal(t, ruleData[1].ID, []byte{0xc, 0xa, 0xf, 0xe})
}
