//go:build linux

/*
A library for managing nftables rules
*/
package rule

import (
	"bytes"
	"fmt"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

// RuleTarget represents a location to manipulate nftables rules
type RuleTarget struct {
	table *nftables.Table
	chain *nftables.Chain
}

type RuleUsageCounter struct {
	protocol string
	verdict  string
	bytes    int64
	packets  int64
}

// Create a new location to manipulate nftables rules
func NewRuleTarget(table *nftables.Table, chain *nftables.Chain) RuleTarget {
	return RuleTarget{
		table: table,
		chain: chain,
	}
}

// Add a rule with a given ID to a specific table and chain, returns true if the rule was added
func (r *RuleTarget) Add(c *nftables.Conn, ruleData RuleData) (bool, error) {
	exists, err := r.Exists(c, ruleData)
	if err != nil {
		return false, err
	}

	if exists {
		return false, nil
	}

	add(c, r.table, r.chain, ruleData)
	return true, nil
}

func add(c *nftables.Conn, table *nftables.Table, chain *nftables.Chain, ruleData RuleData) {
	c.AddRule(&nftables.Rule{
		Table:    table,
		Chain:    chain,
		Exprs:    ruleData.Expressions,
		UserData: ruleData.ID,
	})
}

// Delete a rule with a given ID from a specific table and chain, returns true if the rule was deleted
func (r *RuleTarget) Delete(c *nftables.Conn, ruleData RuleData) (bool, error) {
	rules, err := c.GetRules(r.table, r.chain)
	if err != nil {
		return false, err
	}

	rule := findRuleByID(ruleData.ID, rules)

	if rule.Table.Name == "" {
		// if the rule we get back is empty (the final return in findRuleByID) we didn't find it
		return false, nil
	}

	if err := c.DelRule(rule); err != nil {
		return false, err
	}

	return true, nil
}

// Determine if a rule with a given ID exists in a specific table and chain
func (r *RuleTarget) Exists(c *nftables.Conn, ruleData RuleData) (bool, error) {
	rules, err := c.GetRules(r.table, r.chain)
	if err != nil {
		return false, err
	}

	rule := findRuleByID(ruleData.ID, rules)

	if rule.Table == nil {
		// if the rule we get back is empty (the final return in findRuleByID) we didn't find it
		return false, nil
	}

	return true, nil
}

// Compare existing and incoming rule IDs adding/removing the difference
//
// First return value is true if the number of rules has changed, false if there were no updates. The second
// and third return values indicate the number of rules added or removed, respectively.
func (r *RuleTarget) Update(c *nftables.Conn, rules []RuleData) (bool, int, int, error) {
	var modified bool
	existingRules, err := c.GetRules(r.table, r.chain)
	if err != nil {
		return false, 0, 0, fmt.Errorf("error getting existing rules for update: %v", err)
	}

	addRDList, removeRDList := genRuleDelta(existingRules, rules)

	if len(removeRDList) > 0 {
		for _, rule := range removeRDList {
			err := c.DelRule(rule)
			if err != nil {
				return false, 0, 0, err
			}
			modified = true
		}
	}

	if len(addRDList) > 0 {
		for _, rule := range addRDList {
			add(c, r.table, r.chain, rule)
			modified = true
		}
	}

	return modified, len(addRDList), len(removeRDList), nil
}

// Get the nftables table and chain associated with this RuleTarget
func (r *RuleTarget) GetTableAndChain() (*nftables.Table, *nftables.Chain) {
	return r.table, r.chain
}

func (r *RuleTarget) Get(c *nftables.Conn) ([]*nftables.Rule, error) {
	return c.GetRules(r.table, r.chain)
}

func (r *RuleTarget) GetRuleUsageCounters(c *nftables.Conn) ([]RuleUsageCounter, error) {
	rules, err := r.Get(c)

	if err != nil {
		return nil, err
	}

	usageCounters := make([]RuleUsageCounter, len(rules))
	for i, rule := range rules {
		verdict := "accept"
		protocol := ""
		nfproto := false
		var bytes, packets int64

		for _, ex := range rule.Exprs {
			if meta, ok := ex.(*expr.Meta); ok {
				nfproto = meta.Key == expr.MetaKeyNFPROTO
			}

			if compare, ok := ex.(*expr.Cmp); ok {
				// The nfproto meta tag comes before the protocol comparison in expressions
				if nfproto {
					if compare.Data[0] == byte(nftables.TableFamilyIPv4) {
						protocol = "ipv4"
					} else if compare.Data[0] == byte(nftables.TableFamilyIPv6) {
						protocol = "ipv6"
					}
				}
			}

			if counter, ok := ex.(*expr.Counter); ok {
				bytes = int64(counter.Bytes)
				packets = int64(counter.Packets)
			}

			if ver, ok := ex.(*expr.Verdict); ok {
				if ver.Kind == expr.VerdictDrop {
					verdict = "drop"
				}
			}
		}

		usageCounters[i] = RuleUsageCounter{
			verdict:  verdict,
			protocol: protocol,
			bytes:    bytes,
			packets:  packets,
		}
	}

	return usageCounters, nil

}

func genRuleDelta(existingRules []*nftables.Rule, newRules []RuleData) (add []RuleData, remove []*nftables.Rule) {
	existingRuleMap := make(map[string]*nftables.Rule)
	for _, existingRule := range existingRules {
		existingRuleMap[string(existingRule.UserData)] = existingRule
	}

	for _, ruleData := range newRules {
		if _, exists := existingRuleMap[string(ruleData.ID)]; !exists {
			add = append(add, ruleData)
		} else {
			delete(existingRuleMap, string(ruleData.ID))
		}
	}

	for _, v := range existingRuleMap {
		remove = append(remove, v)
	}

	return
}

func findRuleByID(id []byte, rules []*nftables.Rule) *nftables.Rule {
	for _, rule := range rules {
		if bytes.Equal(rule.UserData, id) {
			return rule
		}
	}
	return &nftables.Rule{}
}
