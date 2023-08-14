package rule

import (
	"fmt"

	"github.com/google/nftables/expr"
)

// RuleData is a struct that is used to create rules in a given table and chain
type RuleData struct {
	Expressions []expr.Any
	// we use rule user data to store the ID
	// we do this so we can give each rule a specific id across hosts and etc
	// handles are less deterministic without setting them explicitly and lack context (only ints)
	ID []byte
	// FIXME: we'll probably want stuff like position and handle at some point
}

// Create a new RuleData from an ID and list of nftables expressions
func NewRuleData(id []byte, exprs []expr.Any) RuleData {
	return RuleData{
		Expressions: exprs,
		ID:          id,
	}
}

func (d RuleData) counters() (bytes *int64, packets *int64, error error) {
	for _, ex := range d.Expressions {
		switch v := ex.(type) {
		case *expr.Counter:
			bytes := int64(v.Bytes)
			packets := int64(v.Packets)
			return &bytes, &packets, nil
		}
	}

	return nil, nil, fmt.Errorf("no counter expression found for rule %s", d.ID)
}
