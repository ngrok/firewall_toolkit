#!/bin/bash

TEST_SUITE="integration-bpf"

export BASEDIR=$(cd $(dirname "$0") && cd .. && pwd)
. "$BASEDIR/tests/include/common.sh"
. "$BASEDIR/tests/include/compat.sh"
. "$BASEDIR/tests/include/testlib.sh"

if [ -f /.dockerenv ]; then
    echo "[fw-input-filter-bpf] doesn't work inside docker, quitting"
    exit 0
fi

# quad9 dns
TEST_IP="149.112.112.112"

begin_test "create table, chain and bpf rule"
(
    $GO_BIN_PATH/fwtk-input-filter-bpf -chain=$CHAIN -table=$TABLE  -filter="host $TEST_IP"
)
end_test

# "host $TEST_IP" will look at src and dst ip
# it will block $TEST_IP as the src or dst even if its inside an input filter
# as a result we can test using dns and we will send the query but not recieve the response
begin_test "dns timeout"
(
    $NFT_LIST_TABLE ip $TABLE
    host google.com $TEST_IP | grep 'no servers could be reached'
)
end_test

begin_test "delete table"
(
    nft delete table ip $TABLE
)
end_test