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

begin_test "validate nft output: hook"
(
    $NFT_LIST_TABLE inet $TABLE
    $NFT_LIST_TABLE_JSON inet $TABLE | $JQ .nftables[].chain.hook | grep input
)
end_test

begin_test "validate nft output: priority"
(
    $NFT_LIST_TABLE inet $TABLE
    $NFT_LIST_TABLE_JSON inet $TABLE | $JQ .nftables[].chain.type | grep filter
)
end_test

begin_test "validate nft output: rule protocol ip"
(
    $NFT_LIST_TABLE inet $TABLE
    $NFT_LIST_TABLE_JSON inet $TABLE | $JQ '.nftables[].rule.expr | select (. != null) | .[].match' | grep '"protocol": "ip"'
)
end_test

begin_test "validate nft output: rule protocol ipv6"
(
    $NFT_LIST_TABLE inet $TABLE
    $NFT_LIST_TABLE_JSON inet $TABLE | $JQ '.nftables[].rule.expr | select (. != null) | .[].match' | grep '"protocol": "ip6"'
)
end_test

begin_test "validate nft output: rule saddr field"
(
    $NFT_LIST_TABLE inet $TABLE
    $NFT_LIST_TABLE_JSON inet $TABLE | $JQ '.nftables[].rule.expr | select (. != null) | .[].match' | grep '"field": "saddr"'
)
end_test

begin_test "validate nft output: rule transport protocol field"
(
    $NFT_LIST_TABLE inet $TABLE
    $NFT_LIST_TABLE_JSON inet $TABLE | $JQ '.nftables[].rule.expr | select (. != null) | .[].match' | grep '"protocol": "tcp"'
)
end_test

begin_test "validate nft output: rule dport field"
(
    $NFT_LIST_TABLE inet $TABLE
    $NFT_LIST_TABLE_JSON inet $TABLE | $JQ '.nftables[].rule.expr | select (. != null) | .[].match' | grep '"field": "dport"'
)
end_test

begin_test "validate nft output: rule drop verdict"
(
    $NFT_LIST_TABLE inet $TABLE
    $NFT_LIST_TABLE_JSON inet $TABLE | $JQ '.nftables[].rule.expr | select (. != null) | .[]' | tail -n 2 | head -n 1 | grep drop
)
end_test

begin_test "validate nft output: set flags"
(
    $NFT_LIST_TABLE inet $TABLE
    $NFT_LIST_TABLE_JSON inet $TABLE | $JQ '.nftables[].set | select(.name == "port_blocklist") | .flags' | grep interval
)
end_test

begin_test "validate nft output: ipv4 set"
(
    $NFT_LIST_TABLE inet $TABLE
    $NFT_LIST_TABLE_JSON inet $TABLE | $JQ .nftables[].set.name | grep ipv4_blocklist
)
end_test

begin_test "validate nft output: ipv4 set content (single ip)"
(
    $NFT_LIST_TABLE inet $TABLE
    $NFT_LIST_TABLE_JSON inet $TABLE | $JQ '.nftables[].set | select(.name == "ipv4_blocklist") | .elem[].elem.val' | grep 198.51.100.200
)
end_test

begin_test "validate nft output: ipv4 set content (range start)"
(
    $NFT_LIST_TABLE inet $TABLE
    $NFT_LIST_TABLE_JSON inet $TABLE | $JQ '.nftables[].set | select(.name == "ipv4_blocklist") | .elem[].elem.val' | grep -A1 range | tail -n 1 | grep 198.51.100.1
)
end_test

begin_test "validate nft output: ipv4 set content (range end)"
(
    $NFT_LIST_TABLE inet $TABLE
    $NFT_LIST_TABLE_JSON inet $TABLE | $JQ '.nftables[].set | select(.name == "ipv4_blocklist") | .elem[].elem.val' | grep -A2 range | tail -n 1 | grep 198.51.100.100
)
end_test

begin_test "validate nft output: ipv4 set content (cidr address)"
(
    $NFT_LIST_TABLE inet $TABLE
    $NFT_LIST_TABLE_JSON inet $TABLE | $JQ '.nftables[].set | select(.name == "ipv4_blocklist") | .elem[].elem.val' | grep -A1 prefix | tail -n 1 | grep 203.0.113.100
)
end_test

begin_test "validate nft output: ipv4 set content (cidr mask)"
(
    $NFT_LIST_TABLE inet $TABLE
    $NFT_LIST_TABLE_JSON inet $TABLE | $JQ '.nftables[].set | select(.name == "ipv4_blocklist") | .elem[].elem.val' | grep -A2 prefix | tail -n 1 | grep 30
)
end_test

begin_test "validate nft output: ipv6 set"
(
    $NFT_LIST_TABLE inet $TABLE
    $NFT_LIST_TABLE_JSON inet $TABLE | $JQ .nftables[].set.name | grep ipv6_blocklist
)
end_test

begin_test "validate nft output: ipv6 set content (single ip)"
(
    $NFT_LIST_TABLE inet $TABLE
    $NFT_LIST_TABLE_JSON inet $TABLE | $JQ '.nftables[].set | select(.name == "ipv6_blocklist") | .elem[].elem.val' | grep 2001:1db8:85a3:1:1:8a2e:1370:7334
)
end_test

begin_test "validate nft output: ipv6 set content (range start)"
(
    $NFT_LIST_TABLE inet $TABLE
    $NFT_LIST_TABLE_JSON inet $TABLE | $JQ '.nftables[].set | select(.name == "ipv6_blocklist") | .elem[].elem.val' | grep -A1 range | tail -n 1 | grep 2001:1db8:85a3:1:1:8a2e:1370:7336
)
end_test

begin_test "validate nft output: ipv6 set content (range end)"
(
    $NFT_LIST_TABLE inet $TABLE
    $NFT_LIST_TABLE_JSON inet $TABLE | $JQ '.nftables[].set | select(.name == "ipv6_blocklist") | .elem[].elem.val' | grep -A2 range | tail -n 1 | grep 2001:1db8:85a3:1:1:8a2e:1370:7339
)
end_test

begin_test "validate nft output: ipv6 set content (cidr address)"
(
    $NFT_LIST_TABLE inet $TABLE
    $NFT_LIST_TABLE_JSON inet $TABLE | $JQ '.nftables[].set | select(.name == "ipv6_blocklist") | .elem[].elem.val' | grep -A1 prefix | tail -n 1 | grep 2001:db8:1234
)
end_test

begin_test "validate nft output: ipv6 set content (cidr mask)"
(
    $NFT_LIST_TABLE inet $TABLE
    $NFT_LIST_TABLE_JSON inet $TABLE | $JQ '.nftables[].set | select(.name == "ipv6_blocklist") | .elem[].elem.val' | grep -A2 prefix | tail -n 1 | grep 48
)
end_test

begin_test "validate nft output: port set"
(
    $NFT_LIST_TABLE inet $TABLE
    $NFT_LIST_TABLE_JSON inet $TABLE | $JQ .nftables[].set.name | grep port_blocklist
)
end_test

begin_test "validate nft output: port set content (single port)"
(
    $NFT_LIST_TABLE inet $TABLE
    $NFT_LIST_TABLE_JSON inet $TABLE | $JQ '.nftables[].set | select(.name == "port_blocklist") | .elem[].elem.val' | grep 8080
)
end_test

begin_test "validate nft output: port set content (port range start small)"
(
    $NFT_LIST_TABLE inet $TABLE
    $NFT_LIST_TABLE_JSON inet $TABLE | $JQ '.nftables[].set | select(.name == "port_blocklist") | .elem[].elem.val' | grep -A1 range | head -n 2 | tail -n 1 | grep 1000
)
end_test

begin_test "validate nft output: port set content (port range end small)"
(
    $NFT_LIST_TABLE inet $TABLE
    $NFT_LIST_TABLE_JSON inet $TABLE | $JQ '.nftables[].set | select(.name == "port_blocklist") | .elem[].elem.val' | grep -A2 range | head -n 3 | tail -n 1 | grep 1001
)
end_test

begin_test "validate nft output: port set content (port range start large)"
(
    $NFT_LIST_TABLE inet $TABLE
    $NFT_LIST_TABLE_JSON inet $TABLE | $JQ '.nftables[].set | select(.name == "port_blocklist") | .elem[].elem.val' | grep -A1 range | tail -n 1 | grep 3000
)
end_test

begin_test "validate nft output: port set content (port range end large)"
(
    $NFT_LIST_TABLE inet $TABLE
    $NFT_LIST_TABLE_JSON inet $TABLE | $JQ '.nftables[].set | select(.name == "port_blocklist") | .elem[].elem.val' | grep -A2 range | tail -n 1 | grep 4999
)
end_test

# begin_test "delete table"
# (
#     nft delete table inet $TABLE
# )
end_test
