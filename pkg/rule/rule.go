//go:build linux

/*
A library for managing nftables rules
*/
package rule

import (
	"bytes"

	"github.com/google/nftables"
)

// Add a rule with a given ID to a specific table and chain, returns true if the rule was added
func Add(c *nftables.Conn, table *nftables.Table, chain *nftables.Chain, ruleData RuleData) (bool, error) {
	exists, err := Exists(c, table, chain, ruleData)
	if err != nil {
		return false, err
	}

	if exists {
		return false, nil
	}

	add(c, table, chain, ruleData)
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
func Delete(c *nftables.Conn, table *nftables.Table, chain *nftables.Chain, ruleData RuleData) (bool, error) {
	rules, err := c.GetRules(table, chain)
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
func Exists(c *nftables.Conn, table *nftables.Table, chain *nftables.Chain, ruleData RuleData) (bool, error) {
	rules, err := c.GetRules(table, chain)
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
