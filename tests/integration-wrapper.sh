#!/bin/bash

# https://docs.docker.com/config/containers/multi-service_container/

# turn on bash's job control
set -m

# Start the primary process and put it in the background
python3 -m http.server --cgi 8000 2> /var/log/py-http-8000.log &
python3 -m http.server --cgi 8001 2> /var/log/py-http-8001.log &
python3 -m http.server --cgi 8002 2> /var/log/py-http-8002.log &

# Start the helper process
/go/bin/fwtk-input-filter-sets \
    -chain=filter \
    -table=testmanager \
    -iplist=/go/src/github.com/ngrok/firewall_toolkit/tests/integration_ip.list \
    -portlist=/go/src/github.com/ngrok/firewall_toolkit/tests/integration_port.list \
    -mode=manager

# the my_helper_process might need to know how to wait on the
# primary process to start before it does its work and returns

# now we bring the primary process back into the foreground
# and leave it there
fg %1
