#!/bin/bash

TEST_SUITE="integration-sets"

export BASEDIR=$(cd $(dirname "$0") && cd .. && pwd)
. "$BASEDIR/tests/include/common.sh"
. "$BASEDIR/tests/include/testlib.sh"

SERVER_IP=172.200.1.100
CLIENT_IP=$(head -n 1 $BASEDIR/tests/integration_ip.list)

CURL_TIMEOUT=3
CURL="docker run --network tests_integration --ip $CLIENT_IP curlimages/curl curl --connect-timeout $CURL_TIMEOUT"

DOCKER_CONTAINER_NAME="fwtk-input-filter-sets-manager" # matches docker-compose.yml
DOCKER_COMPOSE_EXEC="docker-compose -f $BASEDIR/tests/docker-compose.yml exec $DOCKER_CONTAINER_NAME"

TEST_IP_LIST_PATH="/go/src/github.com/ngrok/firewall_toolkit/tests/integration_ip.list"
TEST_PORT_LIST_PATH="/go/src/github.com/ngrok/firewall_toolkit/tests/integration_port.list"

TABLE="testmanager" # matches integration-wrapper.sh

begin_test "$CLIENT_IP to $SERVER_IP:8000 blocked"
(
    $DOCKER_COMPOSE_EXEC $NFT_LIST_TABLE inet $TABLE
    $CURL $SERVER_IP:8000
)
end_test_exfail

begin_test "$CLIENT_IP to $SERVER_IP:8001 allowed"
(
    $DOCKER_COMPOSE_EXEC $NFT_LIST_TABLE inet $TABLE
    $CURL $SERVER_IP:8001
)
end_test

begin_test "$CLIENT_IP to $SERVER_IP:8002 allowed"
(
    $DOCKER_COMPOSE_EXEC $NFT_LIST_TABLE inet $TABLE
    $CURL $SERVER_IP:8002
)
end_test

begin_test "replace port 8000 with 8001"
(
    $DOCKER_COMPOSE_EXEC $NFT_LIST_TABLE inet $TABLE
    $DOCKER_COMPOSE_EXEC bash -c "echo 8001 > $TEST_PORT_LIST_PATH"
)
end_test

begin_test "$CLIENT_IP to $SERVER_IP:8000 allowed"
(
    $DOCKER_COMPOSE_EXEC $NFT_LIST_TABLE inet $TABLE
    $CURL $SERVER_IP:8000
)
end_test

begin_test "$CLIENT_IP to $SERVER_IP:8001 blocked"
(
    $DOCKER_COMPOSE_EXEC $NFT_LIST_TABLE inet $TABLE
    $CURL $SERVER_IP:8001
)
end_test_exfail

begin_test "$CLIENT_IP to $SERVER_IP:8002 allowed"
(
    $DOCKER_COMPOSE_EXEC $NFT_LIST_TABLE inet $TABLE
    $CURL $SERVER_IP:8002
)
end_test

begin_test "replace port 8001 with 8001-8002"
(
    $DOCKER_COMPOSE_EXEC $NFT_LIST_TABLE inet $TABLE
    $DOCKER_COMPOSE_EXEC bash -c "echo 8001-8002 > $TEST_PORT_LIST_PATH"
)
end_test

begin_test "$CLIENT_IP to $SERVER_IP:8000 allowed"
(
    $DOCKER_COMPOSE_EXEC $NFT_LIST_TABLE inet $TABLE
    $CURL $SERVER_IP:8000
)
end_test

begin_test "$CLIENT_IP to $SERVER_IP:8001 blocked"
(
    $DOCKER_COMPOSE_EXEC $NFT_LIST_TABLE inet $TABLE
    $CURL $SERVER_IP:8001
)
end_test_exfail

begin_test "$CLIENT_IP to $SERVER_IP:8002 blocked"
(
    $DOCKER_COMPOSE_EXEC $NFT_LIST_TABLE inet $TABLE
    $CURL $SERVER_IP:8002
)
end_test_exfail

begin_test "remove all ports from the list"
(
    $DOCKER_COMPOSE_EXEC $NFT_LIST_TABLE inet $TABLE
    $DOCKER_COMPOSE_EXEC bash -c "echo '' > $TEST_PORT_LIST_PATH"
)
end_test

begin_test "$CLIENT_IP to $SERVER_IP:8000 allowed"
(
    $DOCKER_COMPOSE_EXEC $NFT_LIST_TABLE inet $TABLE
    $CURL $SERVER_IP:8000
)
end_test

begin_test "$CLIENT_IP to $SERVER_IP:8001 allowed"
(
    $DOCKER_COMPOSE_EXEC $NFT_LIST_TABLE inet $TABLE
    $CURL $SERVER_IP:8001
)
end_test

begin_test "$CLIENT_IP to $SERVER_IP:8002 allowed"
(
    $DOCKER_COMPOSE_EXEC $NFT_LIST_TABLE inet $TABLE
    $CURL $SERVER_IP:8002
)
end_test

begin_test "add port 8000 back to the list"
(
    $DOCKER_COMPOSE_EXEC $NFT_LIST_TABLE inet $TABLE
    $DOCKER_COMPOSE_EXEC bash -c "echo '8000' > $TEST_PORT_LIST_PATH"
)
end_test

begin_test "add ip range (172.200.1.101-172.200.1.105) to the list"
(
    $DOCKER_COMPOSE_EXEC $NFT_LIST_TABLE inet $TABLE
    $DOCKER_COMPOSE_EXEC bash -c "echo '172.200.1.101-172.200.1.105' > $TEST_IP_LIST_PATH"
)
end_test

begin_test "$CLIENT_IP to $SERVER_IP:8000 blocked"
(
    $DOCKER_COMPOSE_EXEC $NFT_LIST_TABLE inet $TABLE
    $CURL $SERVER_IP:8000
)
end_test_exfail

begin_test "$CLIENT_IP to $SERVER_IP:8001 allowed"
(
    $DOCKER_COMPOSE_EXEC $NFT_LIST_TABLE inet $TABLE
    $CURL $SERVER_IP:8001
)
end_test

begin_test "$CLIENT_IP to $SERVER_IP:8002 allowed"
(
    $DOCKER_COMPOSE_EXEC $NFT_LIST_TABLE inet $TABLE
    $CURL $SERVER_IP:8002
)
end_test

begin_test "remove all ips from the list"
(
    $DOCKER_COMPOSE_EXEC $NFT_LIST_TABLE inet $TABLE
    $DOCKER_COMPOSE_EXEC bash -c "echo '' > $TEST_IP_LIST_PATH"
)
end_test

begin_test "$CLIENT_IP to $SERVER_IP:8000 allowed"
(
    $DOCKER_COMPOSE_EXEC $NFT_LIST_TABLE inet $TABLE
    $CURL $SERVER_IP:8000
)
end_test

begin_test "$CLIENT_IP to $SERVER_IP:8001 allowed"
(
    $DOCKER_COMPOSE_EXEC $NFT_LIST_TABLE inet $TABLE
    $CURL $SERVER_IP:8001
)
end_test

begin_test "$CLIENT_IP to $SERVER_IP:8002 allowed"
(
    $DOCKER_COMPOSE_EXEC $NFT_LIST_TABLE inet $TABLE
    $CURL $SERVER_IP:8002
)
end_test