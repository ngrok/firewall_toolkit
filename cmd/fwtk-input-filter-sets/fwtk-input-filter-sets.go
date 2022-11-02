//go:build linux

/*
fwtk-input-filter-sets is a utility that manages nftables sets and rules

Usage:

	sudo ~/go/bin/fwtk-input-filter-sets [flags]

Flags:

	-chain=<chain name>
	-table=<table name>
	-mode=<oneshot (default) | manager>
	-iplist=<path>
	-portlist=<path>

This command will create a inet table, chain and sets using the names and files specified by the flags above.
The files can contain IPs, CIDRs, ports and ranges, see tests/*.list for examples.
Manager mode will run continuously re-reading the files on a timer.
*/
package main

import (
	"bufio"
	"bytes"
	"flag"
	"os"
	"sync"
	"time"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"

	"github.com/ngrok/firewall_toolkit/pkg/expressions"
	"github.com/ngrok/firewall_toolkit/pkg/logger"
	"github.com/ngrok/firewall_toolkit/pkg/set"
)

const (
	RefreshInterval = 1000 * time.Millisecond
)

func main() {
	table := flag.String("table", "", "nftables table name")
	chain := flag.String("chain", "", "nftables chain name")
	mode := flag.String("mode", "oneshot", "oneshot or manager")
	ipFile := flag.String("iplist", "./ip.list", "file containing list of ips")
	portFile := flag.String("portlist", "./port.list", "file containing list of ports")

	flag.Parse()

	exists := []bool{}
	flag.VisitAll(func(f *flag.Flag) {
		if len(f.Value.String()) > 0 {
			exists = append(exists, true)
		}
	})

	if len(exists) != 5 {
		flag.PrintDefaults()
		os.Exit(1)
	}

	c, err := nftables.New()
	if err != nil {
		logger.Default.Fatalf("nftables connection failed: %v", err)
	}

	nfTable := c.AddTable(&nftables.Table{
		Family: nftables.TableFamilyINet,
		Name:   *table,
	})

	nfChain := c.AddChain(&nftables.Chain{
		Name:     *chain,
		Table:    nfTable,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookInput,
		Priority: nftables.ChainPriorityFilter,
	})

	if err := c.Flush(); err != nil {
		logger.Default.Fatalf("add table and chain flush failed: %v", err)
	}

	// create all the sets you plan to use
	ipv4Set, err := set.New("ipv4_blocklist", c, nfTable, nftables.TypeIPAddr)
	if err != nil {
		logger.Default.Fatalf("new set failed %v", err)
	}

	ipv6Set, err := set.New("ipv6_blocklist", c, nfTable, nftables.TypeIP6Addr)
	if err != nil {
		logger.Default.Fatalf("new set failed %v", err)
	}

	portSet, err := set.New("port_blocklist", c, nfTable, nftables.TypeInetService)
	if err != nil {
		logger.Default.Fatalf("new set failed %v", err)
	}

	// get the lists of things to add to the sets
	ipSource := newSource(*ipFile)
	ipList, err := ipSource.getIPList()
	if err != nil {
		logger.Default.Fatalf("error getting ip block list: %v", err)
	}

	portSource := newSource(*portFile)
	portList, err := portSource.getPortList()
	if err != nil {
		logger.Default.Fatalf("error getting port block list: %v", err)
	}

	// put everything in the sets
	if err := ipv4Set.ClearAndAddElements(ipList); err != nil {
		logger.Default.Fatalf("failed to update ipv4 set elements: %v", err)
	}

	if err := ipv6Set.ClearAndAddElements(ipList); err != nil {
		logger.Default.Fatalf("failed to update ipv6 set elements: %v", err)
	}

	if err := portSet.ClearAndAddElements(portList); err != nil {
		logger.Default.Fatalf("failed to update port set elements: %v", err)
	}

	rules, err := c.GetRules(nfTable, nfChain)
	if err != nil {
		logger.Default.Fatal(err)
	}

	// we should use handles for this but they aren't available until after flush
	// https://github.com/google/nftables/pull/88
	IPv4RuleExists := false
	IPv6RuleExists := false
	IPv4RuleID := []byte{0xd, 0xe, 0xa, 0xd}
	IPv6RuleID := []byte{0xc, 0xa, 0xf, 0xe}
	flush := false
	for _, rule := range rules {
		if bytes.Equal(rule.UserData, IPv4RuleID) {
			IPv4RuleExists = true
		}

		if bytes.Equal(rule.UserData, IPv6RuleID) {
			IPv6RuleExists = true
		}
	}

	if !IPv4RuleExists {
		ipV4Rule, err := generateRule(portSet.Set, ipv4Set.Set)
		if err != nil {
			logger.Default.Fatal(err)
		}

		c.AddRule(&nftables.Rule{
			Table:    nfTable,
			Chain:    nfChain,
			Exprs:    ipV4Rule,
			UserData: IPv4RuleID,
		})

		flush = true
	}

	if !IPv6RuleExists {
		ipV6Rule, err := generateRule(portSet.Set, ipv6Set.Set)
		if err != nil {
			logger.Default.Fatal(err)
		}

		c.AddRule(&nftables.Rule{
			Table:    nfTable,
			Chain:    nfChain,
			Exprs:    ipV6Rule,
			UserData: IPv6RuleID,
		})

		flush = true
	}

	if flush {
		if err := c.Flush(); err != nil {
			logger.Default.Fatalf("add rules flush failed: %v", err)
		}
	}

	// manager mode will keep running refreshing sets based on what's in the files
	if *mode == "manager" {
		var wg sync.WaitGroup
		wg.Add(3)

		ipv4SetManager, err := set.SetManagerInit(
			&wg,
			c,
			&ipv4Set,
			ipSource.getIPList,
			RefreshInterval,
			logger.Default,
		)

		if err != nil {
			logger.Default.Fatal(err)
		}

		ipv6SetManager, err := set.SetManagerInit(
			&wg,
			c,
			&ipv6Set,
			ipSource.getIPList,
			RefreshInterval,
			logger.Default,
		)

		if err != nil {
			logger.Default.Fatal(err)
		}

		portSetManager, err := set.SetManagerInit(
			&wg,
			c,
			&portSet,
			portSource.getPortList,
			RefreshInterval,
			logger.Default,
		)

		if err != nil {
			logger.Default.Fatal(err)
		}

		go ipv4SetManager.Start()
		go ipv6SetManager.Start()
		go portSetManager.Start()

		wg.Wait()
	}
}

// example of how to get set data from some external source
type listSource struct {
	path string
}

func newSource(path string) listSource {
	return listSource{path}
}

func (s *listSource) getIPList() ([]set.SetData, error) {
	return getIPListFromFile(s.path)
}

func (s *listSource) getPortList() ([]set.SetData, error) {
	return getPortListFromFile(s.path)
}

func getIPListFromFile(path string) ([]set.SetData, error) {
	list, err := readFile(path)
	if err != nil {
		return []set.SetData{}, err
	}

	return set.AddressStringsToSetData(list)
}

func getPortListFromFile(path string) ([]set.SetData, error) {
	list, err := readFile(path)
	if err != nil {
		return []set.SetData{}, err
	}

	return set.PortStringsToSetData(list)
}

func readFile(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return []string{}, err
	}
	defer file.Close()

	list := []string{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		text := scanner.Text()
		if len(text) == 0 {
			return []string{}, nil
		}
		if text[0:1] != "#" {
			list = append(list, text)
		}

	}

	if err := scanner.Err(); err != nil {
		return []string{}, err
	}

	return list, nil
}

func generateRule(portSet *nftables.Set, ipSet *nftables.Set) ([]expr.Any, error) {
	// FIXME: we should come up with a better, more abstract way to build rules like this
	// create all the rule expressions to use the sets
	expressionList := []expr.Any{}

	// this is an inet table so we need to check ipv4 vs ipv6
	switch ipSet.KeyType {
	case nftables.TypeIPAddr:
		e, err := expressions.CompareProtocolFamily(unix.NFPROTO_IPV4)
		expressionList = append(expressionList, e...)
		if err != nil {
			return []expr.Any{}, err
		}
	case nftables.TypeIP6Addr:
		e, err := expressions.CompareProtocolFamily(unix.NFPROTO_IPV6)
		expressionList = append(expressionList, e...)
		if err != nil {
			return []expr.Any{}, err
		}
	}

	// check the source ip against what's in the set
	addressLookup, err := expressions.CompareSourceAddressSet(ipSet)
	if err != nil {
		return []expr.Any{}, err
	}

	// use the port set to compare the destination port
	// used for v4 and v6
	portLookup, err := expressions.CompareDestinationPortSet(portSet)
	if err != nil {
		return []expr.Any{}, err
	}

	// we only care about tcp
	// used for v4 and v6
	transportLookup, err := expressions.CompareTransportProtocol(unix.IPPROTO_TCP)
	if err != nil {
		return []expr.Any{}, err
	}

	// combine all the expressions into a rule
	expressionList = append(expressionList, addressLookup...)
	expressionList = append(expressionList, transportLookup...)
	expressionList = append(expressionList, portLookup...)
	expressionList = append(expressionList, expressions.Counter())
	expressionList = append(expressionList, expressions.Drop())

	return expressionList, nil
}
