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
	"context"
	"flag"
	"os"
	"time"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sys/unix"

	"github.com/ngrok/firewall_toolkit/pkg/expressions"
	"github.com/ngrok/firewall_toolkit/pkg/logger"
	"github.com/ngrok/firewall_toolkit/pkg/rule"
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
	ipv4Set, err := set.New(c, nfTable, "ipv4_blocklist", nftables.TypeIPAddr)
	if err != nil {
		logger.Default.Fatalf("new set failed %v", err)
	}

	ipv6Set, err := set.New(c, nfTable, "ipv6_blocklist", nftables.TypeIP6Addr)
	if err != nil {
		logger.Default.Fatalf("new set failed %v", err)
	}

	portSet, err := set.New(c, nfTable, "port_blocklist", nftables.TypeInetService)
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
	if err := ipv4Set.ClearAndAddElements(c, ipList); err != nil {
		logger.Default.Fatalf("failed to update ipv4 set elements: %v", err)
	}

	if err := ipv6Set.ClearAndAddElements(c, ipList); err != nil {
		logger.Default.Fatalf("failed to update ipv6 set elements: %v", err)
	}

	if err := portSet.ClearAndAddElements(c, portList); err != nil {
		logger.Default.Fatalf("failed to update port set elements: %v", err)
	}

	if err := c.Flush(); err != nil {
		logger.Default.Fatalf("add elements flush failed: %v", err)
	}

	ruleTarget := rule.NewRuleTarget(nfTable, nfChain)

	ruleInfo := newRuleInfo(portSet, ipv4Set, ipv6Set)

	ruleData, err := ruleInfo.createRuleData()
	if err != nil {
		logger.Default.Fatalf("failed to create rules: %v", err)
	}

	flush := false
	for _, rD := range ruleData {
		added, err := ruleTarget.Add(c, rD)
		if err != nil {
			logger.Default.Fatalf("adding rule %x failed: %v", rD.ID, err)
		}

		if added {
			logger.Default.Infof("rule %x added", rD.ID)
			flush = true
		} else {
			logger.Default.Infof("rule %x already exists", rD.ID)
		}
	}

	if flush {
		if err := c.Flush(); err != nil {
			logger.Default.Fatalf("add rules flush failed: %v", err)
		}
	}

	// manager mode will keep running refreshing sets based on what's in the files
	if *mode == "manager" {
		ctx, cancel := context.WithCancel(context.Background())
		eg, gctx := errgroup.WithContext(ctx)
		defer cancel()

		ipv4SetManager, err := set.ManagerInit(
			c,
			ipv4Set,
			ipSource.getIPList,
			RefreshInterval,
			logger.Default,
		)

		if err != nil {
			logger.Default.Fatal(err)
		}

		ipv6SetManager, err := set.ManagerInit(
			c,
			ipv6Set,
			ipSource.getIPList,
			RefreshInterval,
			logger.Default,
		)

		if err != nil {
			logger.Default.Fatal(err)
		}

		portSetManager, err := set.ManagerInit(
			c,
			portSet,
			portSource.getPortList,
			RefreshInterval,
			logger.Default,
		)

		if err != nil {
			logger.Default.Fatal(err)
		}

		ruleManager, err := rule.ManagerInit(
			c,
			ruleTarget,
			ruleInfo.createRuleData,
			RefreshInterval,
			logger.Default,
		)

		if err != nil {
			logger.Default.Fatal(err)
		}

		eg.Go(func() error {
			return ipv4SetManager.Start(gctx)
		})

		eg.Go(func() error {
			return ipv6SetManager.Start(gctx)
		})

		eg.Go(func() error {
			return portSetManager.Start(gctx)
		})

		eg.Go(func() error {
			return ruleManager.Start(gctx)
		})

		if err := eg.Wait(); err != nil {
			logger.Default.Fatal(err)
		}
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

type ruleInfo struct {
	PortSet set.Set
	IPv4Set set.Set
	IPv6Set set.Set
}

func newRuleInfo(portSet set.Set, ipv4Set set.Set, ipv6Set set.Set) ruleInfo {
	return ruleInfo{
		PortSet: portSet,
		IPv4Set: ipv4Set,
		IPv6Set: ipv6Set,
	}
}

func (s *ruleInfo) createRuleData() ([]rule.RuleData, error) {
	ipv6Exprs, err := generateExpression(s.PortSet.Set, s.IPv6Set.Set)
	if err != nil {
		return []rule.RuleData{}, err
	}

	ipv4Exprs, err := generateExpression(s.PortSet.Set, s.IPv4Set.Set)
	if err != nil {
		return []rule.RuleData{}, err
	}

	// give each rule a unique id so we can track it's existence
	ipv4Rule := rule.NewRuleData([]byte{0xd, 0xe, 0xa, 0xd}, ipv4Exprs)
	ipv6Rule := rule.NewRuleData([]byte{0xc, 0xa, 0xf, 0xe}, ipv6Exprs)

	return []rule.RuleData{ipv4Rule, ipv6Rule}, nil
}

func generateExpression(portSet *nftables.Set, ipSet *nftables.Set) ([]expr.Any, error) {
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
