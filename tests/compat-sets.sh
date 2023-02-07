#!/bin/bash

TEST_SUITE="compat-sets"

export BASEDIR=$(cd $(dirname "$0") && cd .. && pwd)
. "$BASEDIR/tests/include/common.sh"
. "$BASEDIR/tests/include/compat.sh"
. "$BASEDIR/tests/include/testlib.sh"

begin_test "create tables, chain and sets"
(
    $GO_BIN_PATH/fwtk-input-filter-sets -chain=$CHAIN -table=$TABLE -iplist=$BASEDIR/tests/compat_ip.list -portlist=$BASEDIR/tests/compat_port.list
)
end_test

begin_test "rules should already exist"
(
    $GO_BIN_PATH/fwtk-input-filter-sets -chain=$CHAIN -table=$TABLE -iplist=$BASEDIR/tests/compat_ip.list -portlist=$BASEDIR/tests/compat_port.list 2>&1 | grep 'rule 0d0e0a0d already exists'
)
end_test

begin_test "python compare"
(
    $NFT_LIST_TABLE_JSON inet $TABLE | python3 $BASEDIR/tests/py/compare.py $BASEDIR/tests/fixtures/compat-sets.json
)
end_test

begin_test "delete table"
(
    nft delete table inet $TABLE
)
end_test


