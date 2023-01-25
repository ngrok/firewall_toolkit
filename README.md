# Firewall Toolkit

This is a collection of golang libraries and tools for managing nftables. It provides a high level API for interacting with nftables and is built on top of [google/nftables](https://github.com/google/nftables). The library provides support for managing nftables sets, rules as well as building the appropriate bpf objects to add bpf/ebpf filters to nftables.
* `pkg/expressions` includes nftables expression partials for generating common firewall rules.
* `pkg/xtables` library for bpf/ebpf nftables rule creation. It supports adding all three types of xtables bpf match configurations: bytecode, pinned bpf programs and socket file descriptors.
* `pkg/set` is a library for managing nftables sets, it supports IPv4, IPv6 and port based set types.
* `pkg/rule` is a library for managing nftable rules, it uses rule "user data" to provide unique IDs for each rule in a given chain.
* `pkg/logger` supports the stdlib log and [zerolog](https://github.com/rs/zerolog), or bring your own logger.
* `pkg/utils` utility functions for validating IPs and etc.
* `cmd/*` provides tools you can use to manage nftables built on top of the firewall_toolkit, also serves as an example of how to use the library.

__Note__: 🚧 Firewall Toolkit is fully functional and well tested but should be considered alpha/experimental software without support. If you find any bugs please let us know by opening an issue or pull request.

### Example tools

The following tools are both examples of how to use the library as well as standalone tools you can use.

#### `fwtk-input-filter-bpf`

This program does the following:
* Creates a nftables ipv4 table and input filter chain of given names
* Uses the contents of the `-filter` flag to create a xtables bpf match nftables rule 
  * The `-filter` flag can contain:
    * A tcpdump-style filter
    * A path to a pinned bpf program (i.e. `bpftool prog load ...`)
    * A file descriptor of a socket with a bpf program attached to it
* The rule can either accept or drop traffic based on the filter with the `-verdict` switch

```
$ make input-filter-bpf
$ sudo ~/go/bin/fwtk-input-filter-bpf -chain=filter -table=bpf -filter="host 198.51.100.1"
```

```
$ sudo nft list table bpf
table ip bpf {
	chain filter {
		type filter hook input priority filter; policy accept;
		#match bpf 48 0 0 0,84 0 0 240,21 0 5 64,32 0 0 12,21 2 0 3325256705,32 0 0 16,21 0 1 3325256705,6 0 0 65535,6 0 0 0 drop
	}
}
```

`tests/compat-bpf.sh` includes an example of a pinned bpf program (requires `clang`, `bpftool`, etc) and add it to nftables using `fwtk-input-filter-bpf`:
```
table ip bpf {
	chain filter {
		type filter hook input priority filter; policy accept;
		#match bpf pinned /sys/fs/bpf/fwtk drop
	}
}
```

#### `fwtk-input-filter-sets`

This program does the following:
* Creates a nftables inet table and input filter chain of given names
* Creates IPv4, IPv6 and ports nftables sets 
* Populates those sets with the contents of given files (i.e. `tests/compat_ip.list`)
* Creates two nftables rules using those sets that:
  * Verifies that the transport protocol is TCP
  * Verifies if the traffic is IPv4 or IPv6
  * Checks the destination port against the ports set
  * Checks the source address against the appropriate IP set
  * Creates a counter on each rule
  * Drops incoming traffic that matches all of the above sets, protocols, etc

```
$ make input-filter-sets
$ sudo ~/go/bin/fwtk-input-filter-sets -chain=filter -table=test -iplist=tests/compat_ip.list -portlist=tests/compat_port.list
```
```
$ sudo nft list table inet test
table inet test {
	set ipv4_blocklist {
		type ipv4_addr
		flags interval
		counter
		elements = { 198.51.100.1-198.51.100.100 counter packets 0 bytes 0, 198.51.100.200 counter packets 0 bytes 0,
			     203.0.113.100/30 counter packets 0 bytes 0 }
	}

	set ipv6_blocklist {
		type ipv6_addr
		flags interval
		counter
		elements = { 2001:db8:1234::/48 counter packets 0 bytes 0,
			     2001:1db8:85a3:1:1:8a2e:1370:7334 counter packets 0 bytes 0,
			     2001:1db8:85a3:1:1:8a2e:1370:7336-2001:1db8:85a3:1:1:8a2e:1370:7339 counter packets 0 bytes 0 }
	}

	set port_blocklist {
		type inet_service
		flags interval
		counter
		elements = { 1000-1001 counter packets 0 bytes 0, 3000-4999 counter packets 0 bytes 0, 8080 counter packets 0 bytes 0 }
	}

	chain filter {
		type filter hook input priority filter; policy accept;
		ip saddr @ipv4_blocklist tcp dport @port_blocklist counter packets 0 bytes 0 drop
		ip6 saddr @ipv6_blocklist tcp dport @port_blocklist counter packets 0 bytes 0 drop
	}
}
```

`fwtk-input-filer-sets` can also be run in `manager` daemon mode which will periodically update each set using a given update function, in this case one that will re-read the port and ip files.

## Building and running

### Dependencies
* golang 1.19
* libpcap for bpf support (for debian based distros `apt-get install libpcap-dev`)
* The full test suite requires docker, docker-compose, etc
  
### Local
This will `go install` the above tools on your local machine:
```
make input-filter-sets
make input-filter-bpf
```

### Docker
This will build a `firewal_toolkit` docker image you can use locally:
```
make docker-build
```

### Tests 
Running all the tests requires docker and docker-compose. Using `make` you can run various subsections of the tests, most of the subsections of tests can also be run inside docker usually by prefixing `docker-` to the make command. 

Normal golang unit tests can be run using:
```
make test
```

Running the golang unit tests inside docker:
```
make docker-test
```

`nftables` compatibility tests (requires root permissions, linux, nftables, etc):
```
sudo make compat-test
```

Running the compat tests inside docker:
```
make docker-compat-test
```

Integration tests:
```
make docker-integration-run
```

All tests:
```
make docker-ci
```

### Notes
* The bpf support uses [google/gopacket](https://github.com/google/gopacket) which [doesn't play well with arm](https://github.com/google/gopacket/issues?q=is%3Aissue+is%3Aopen+arm+).
* xtables match bpf doesn't seem to work inside a docker container even if `xt_bpf` is loaded.
```
# lsmod | grep xt_bpf
xt_bpf                 20480  1
x_tables               53248  6 xt_conntrack,nft_compat,xt_bpf,xt_addrtype,ip_tables,xt_MASQUERADE
# nft list table test
XT match bpf not found
table ip test {
	chain filter {
		type filter hook input priority filter; policy accept;
		drop
	}
}
```
* nftables 0.9.8 has a bug when printing out sets that contain intervals and counters, if you run `fwtk-input-filer-sets` on 0.9.8 it should work but you won't be able to use the `nft` command
```
# nft list tables
table inet test
free(): double free detected in tcache 2
Aborted (core dumped)
```

## Getting help

If you have a problem or suggestion, please [open an issue](https://github.com/ngrok/firewall_toolkit/issues/new) in this repository. While we cannot guarantee support if time allows we will do our best to help. Please note that this project adheres to the [Contributor Covenant Code of Conduct](/CODE_OF_CONDUCT.md). We are also available in [slack](https://ngrok.com/slack).

## Contributing

Please see our [contributing document](/CONTRIBUTING.md) if you would like to participate!

### License

`firewall_toolkit` is licensed under the MIT license.

### Authors

`firewall_toolkit` is designed, authored, reviewed and supported by the members of ngrok's network edge team, including [@joewilliams](https://github.com/joewilliams), [@masonj188](https://github.com/masonj188), [@Megalonia](https://github.com/Megalonia).
