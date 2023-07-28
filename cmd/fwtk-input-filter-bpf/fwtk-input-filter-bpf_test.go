//go:build linux && !arm && !arm64

package main

import (
	"testing"

	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"github.com/stretchr/testify/assert"
)

func TestGetXtBpfInfoBytesBytecode(t *testing.T) {
	b, err := getXtBpfInfoBytes("src 198.51.100.200")
	assert.Nil(t, err)
	// xtBpfModeBytecode
	assert.Equal(t, 0, int(binaryutil.NativeEndian.Uint16(b[0:1])))
}

func TestGetXtBpfInfoBytesPinned(t *testing.T) {
	b, err := getXtBpfInfoBytes("/test/123")
	assert.Nil(t, err)
	// xtBpfModeFdPinned
	assert.Equal(t, 1, int(binaryutil.NativeEndian.Uint16(b[0:1])))
}

func TestGetXtBpfInfoBytesFd(t *testing.T) {
	b, err := getXtBpfInfoBytes("1234")
	assert.Nil(t, err)
	// xtBpfModeFdElf
	assert.Equal(t, 2, int(binaryutil.NativeEndian.Uint16(b[0:1])))
}

func TestGetVerdictDrop(t *testing.T) {
	e, err := getVerdict("drop")
	assert.Nil(t, err)
	assert.Equal(t, expr.VerdictDrop, e)
}

func TestGetVerdictAccept(t *testing.T) {
	e, err := getVerdict("accept")
	assert.Nil(t, err)
	assert.Equal(t, expr.VerdictAccept, e)
}

func TestGetVerdictBad(t *testing.T) {
	e, err := getVerdict("bad")
	assert.Error(t, err)
	assert.Equal(t, expr.VerdictKind(-99), e)
}
