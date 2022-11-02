//go:build linux

package main

import (
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/stretchr/testify/assert"
)

func TestGenerateIPv4Rule(t *testing.T) {
	want := []expr.Any{
		&expr.Meta{Key: 0xf, SourceRegister: false, Register: 0x1},
		&expr.Cmp{Op: 0x0, Register: 0x1, Data: []uint8{0x2}},
		&expr.Payload{OperationType: 0x0, DestRegister: 0x1, SourceRegister: 0x0, Base: 0x1, Offset: 0xc, Len: 0x4, CsumType: 0x0, CsumOffset: 0x0, CsumFlags: 0x0},
		&expr.Lookup{SourceRegister: 0x1, DestRegister: 0x0, IsDestRegSet: false, SetID: 0x0, SetName: "testipset", Invert: false},
		&expr.Meta{Key: 0x10, SourceRegister: false, Register: 0x1},
		&expr.Cmp{Op: 0x0, Register: 0x1, Data: []uint8{0x6}},
		&expr.Payload{OperationType: 0x0, DestRegister: 0x1, SourceRegister: 0x0, Base: 0x2, Offset: 0x2, Len: 0x2, CsumType: 0x0, CsumOffset: 0x0, CsumFlags: 0x0},
		&expr.Lookup{SourceRegister: 0x1, DestRegister: 0x0, IsDestRegSet: false, SetID: 0x0, SetName: "testportset", Invert: false},
		&expr.Counter{Bytes: 0x0, Packets: 0x0},
		&expr.Verdict{Kind: 0, Chain: ""},
	}

	portSet := nftables.Set{Name: "testportset", KeyType: nftables.TypeInetService}
	ipSet := nftables.Set{Name: "testipset", KeyType: nftables.TypeIPAddr}
	res, err := generateRule(&portSet, &ipSet)
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
		&expr.Payload{OperationType: 0x0, DestRegister: 0x1, SourceRegister: 0x0, Base: 0x1, Offset: 0x8, Len: 0x10, CsumType: 0x0, CsumOffset: 0x0, CsumFlags: 0x0},
		&expr.Lookup{SourceRegister: 0x1, DestRegister: 0x0, IsDestRegSet: false, SetID: 0x0, SetName: "testipset", Invert: false},
		&expr.Meta{Key: 0x10, SourceRegister: false, Register: 0x1},
		&expr.Cmp{Op: 0x0, Register: 0x1, Data: []uint8{0x6}},
		&expr.Payload{OperationType: 0x0, DestRegister: 0x1, SourceRegister: 0x0, Base: 0x2, Offset: 0x2, Len: 0x2, CsumType: 0x0, CsumOffset: 0x0, CsumFlags: 0x0},
		&expr.Lookup{SourceRegister: 0x1, DestRegister: 0x0, IsDestRegSet: false, SetID: 0x0, SetName: "testportset", Invert: false},
		&expr.Counter{Bytes: 0x0, Packets: 0x0},
		&expr.Verdict{Kind: 0, Chain: ""},
	}

	portSet := nftables.Set{Name: "testportset", KeyType: nftables.TypeInetService}
	ipSet := nftables.Set{Name: "testipset", KeyType: nftables.TypeIP6Addr}
	res, err := generateRule(&portSet, &ipSet)
	assert.Nil(t, err)

	assert.Equal(t, len(want), len(res))

	for i, e := range res {
		assert.Equal(t, want[i], e)
	}
}
