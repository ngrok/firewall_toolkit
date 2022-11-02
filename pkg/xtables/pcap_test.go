//go:build linux && !arm && !arm64

package xtables

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/net/bpf"
)

func TestBadFilter(t *testing.T) {
	_, err := CompileBpfForXtInfo("asdf")

	assert.Error(t, err)
}

func TestGoodFilter(t *testing.T) {
	filter, err := CompileBpfForXtInfo("host 192.0.2.0")

	expected := []bpf.RawInstruction{{Op: 0x30, Jt: 0x0, Jf: 0x0, K: 0x0}, {Op: 0x54, Jt: 0x0, Jf: 0x0, K: 0xf0}, {Op: 0x15, Jt: 0x0, Jf: 0x5, K: 0x40}, {Op: 0x20, Jt: 0x0, Jf: 0x0, K: 0xc}, {Op: 0x15, Jt: 0x2, Jf: 0x0, K: 0xc0000200}, {Op: 0x20, Jt: 0x0, Jf: 0x0, K: 0x10}, {Op: 0x15, Jt: 0x0, Jf: 0x1, K: 0xc0000200}, {Op: 0x6, Jt: 0x0, Jf: 0x0, K: 0xffff}, {Op: 0x6, Jt: 0x0, Jf: 0x0, K: 0x0}}
	assert.Nil(t, err)
	assert.Equal(t, expected, filter)
}
