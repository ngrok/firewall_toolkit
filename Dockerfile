# we use bookworm here because of nftables bugs in nft 0.9.8 (in bullseye)
FROM debian:bookworm-slim

ADD . /go/src/github.com/ngrok/firewall_toolkit
WORKDIR /go/src/github.com/ngrok/firewall_toolkit

RUN apt-get update && apt-get install -y golang make libpcap-dev jq nftables python3 git && apt-get clean

RUN make input-filter-sets
RUN make input-filter-bpf