#!/bin/bash

if [ -f /.dockerenv ]; then
    echo "doesn't work inside docker, quitting"
    exit 0
fi

MISSING_TOOLS=0
BPFTOOL=`which bpftool`
export CLANG=`which clang`

if [ -z $BPFTOOL ]; then
    MISSING_TOOLS=1
fi

if [ -z $CLANG ]; then
    MISSING_TOOLS=1
fi

if [ $MISSING_TOOLS -eq 1 ]; then
  echo "these tests require clang and bpftool, you might be able to do something like this:"
  echo "sudo apt-get install -y clang linux-tools-common linux-tools-aws linux-tools-5.15.0-1019-aws"
  exit 1
fi

TEST_SUITE="compat-bpf"

export BASEDIR=$(cd $(dirname "$0") && cd .. && pwd)
. "$BASEDIR/tests/include/common.sh"
. "$BASEDIR/tests/include/compat.sh"
. "$BASEDIR/tests/include/testlib.sh"

PINNED_PATH="/sys/fs/bpf/fwtk"

begin_test "create table, chain and bpf rule"
(
    $GO_BIN_PATH/fwtk-input-filter-bpf -chain=$CHAIN -table=$TABLE  -filter="src 198.51.100.1"
)
end_test

begin_test "rule should already exist"
(
    $GO_BIN_PATH/fwtk-input-filter-bpf -chain=$CHAIN -table=$TABLE  -filter="src 198.51.100.1" 2>&1 | grep 'rule 0d0e0a0d already exists'
)
end_test

begin_test "json diff"
(
    $NFT_LIST_TABLE_JSON ip $TABLE | python3 $BASEDIR/tests/py/compare.py $BASEDIR/tests/fixtures/ip-fixture-filter.json
)
end_test
begin_test "delete table"
(
    nft delete table ip $TABLE
)
end_test

begin_test "compile ebpf"
(
    make -C $BASEDIR/tests/pinned_bpf compat-bpf
)
end_test

begin_test "load ebpf"
(
    $BPFTOOL prog load $BASEDIR/tests/pinned_bpf/bpf.o $PINNED_PATH
)
end_test

begin_test "create table, chain and bpf rule"
(
    $GO_BIN_PATH/fwtk-input-filter-bpf -chain=$CHAIN -table=$TABLE  -filter=$PINNED_PATH
)
end_test

begin_test "python compare"
(
    $NFT_LIST_TABLE_JSON ip $TABLE | python3 $BASEDIR/tests/py/compare.py $BASEDIR/tests/fixtures/ip-fixture-pinned.json
)
end_test
begin_test "delete table"
(
    nft delete table ip $TABLE
)
end_test

