//go:build linux

/*
A library for managing nftables rules
*/
package rule

import (
	"bytes"

	"github.com/google/nftables"
)

// RuleTarget represents a location to manipulate nftables rules
type RuleTarget struct {
	Table *nftables.Table
	Chain *nftables.Chain
}

// Create a new location to manipulate nftables rules
func NewRuleTarget(table *nftables.Table, chain *nftables.Chain) RuleTarget {
	return RuleTarget{
		Table: table,
		Chain: chain,
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

	add(c, r.Table, r.Chain, ruleData)
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
	rules, err := c.GetRules(r.Table, r.Chain)
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
	rules, err := c.GetRules(r.Table, r.Chain)
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

func findRuleByID(id []byte, rules []*nftables.Rule) *nftables.Rule {
	for _, rule := range rules {
		if bytes.Equal(rule.UserData, id) {
			return rule
		}
	}
	return &nftables.Rule{}
}
