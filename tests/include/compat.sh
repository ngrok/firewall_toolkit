#!/bin/sh

if [ `whoami` != "root" ]; then
    echo "needs root"
    exit 1
fi

JQ=`which jq`

if [ -z $JQ ]; then
    echo "jq not installed"
    exit 1
fi

JQ="$JQ -r"
GO_BIN_PATH=/go/bin
NFT_LIST_TABLE_JSON="$NFT -j list table"
TABLE="compat-test"
CHAIN="filter"

# clean up
nft delete table ip $TABLE &> /dev/null || true
nft delete table inet $TABLE &> /dev/null || true
