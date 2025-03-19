FROM golang:bookworm

ADD . /go/src/github.com/ngrok/firewall_toolkit
WORKDIR /go/src/github.com/ngrok/firewall_toolkit

RUN apt-get update && apt-get install -y make libpcap-dev jq nftables python3 git && apt-get clean

RUN make input-filter-sets
RUN make input-filter-bpf
