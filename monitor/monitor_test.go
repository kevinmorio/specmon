// Copyright (C) 2025 CISPA Helmholtz Center for Information Security
// Author: Kevin Morio <kevin.morio@cispa.de>
//
// This file is part of SpecMon.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with program. If not, see <https://www.gnu.org/licenses/>.

package monitor_test

import (
	"strings"
	"testing"

	"github.com/specmon/specmon/monitor"
	"github.com/specmon/specmon/rule"
	"github.com/specmon/specmon/term"
)

// TestMonitorMultipleFrFacts tests a bug in conflictSet with a
// rule with two Fr facts, and we test the internal rule matching logic.
func TestMonitorMultipleFrFacts(t *testing.T) {
	// Create a simple rule that consumes two Fr facts with a pseudo trigger
	testRule := &rule.Rule{
		Name: "TwoFr",
		LHS: []*rule.Fact{
			rule.NewFact("Fr", []term.Term{term.NewVariable("x")}, rule.LinearFact),
			rule.NewFact("Fr", []term.Term{term.NewVariable("y")}, rule.LinearFact),
		},
		RHS: []*rule.Fact{
			rule.NewFact("State", []term.Term{term.NewVariable("x"), term.NewVariable("y")}, rule.LinearFact),
		},
		Attrs: map[string]rule.Attribute{
			"trigger": rule.TermAttribute{
				Value: []term.Term{
					term.NewFunction("pair", []term.Term{
						term.NewFunction("test", []term.Term{}),
						term.NewFunction("pair", []term.Term{}),
					}),
				},
			},
		},
	}

	// Create monitor with this rule
	mon, err := monitor.NewMonitor([]*rule.Rule{testRule})
	if err != nil {
		t.Fatalf("Failed to create monitor: %v", err)
	}

	// Get the initial config and add two Fr facts with different values
	configs := mon.Configs()
	if len(configs) != 1 {
		t.Fatalf("Expected 1 initial config, got %d", len(configs))
	}
	config := configs[0]

	// Add two Fr facts with different values
	// The conflictSet bug should affect how these are matched by the rule
	config.AddFact(rule.NewFact("Fr", []term.Term{term.NewConstant("alice")}, rule.LinearFact))
	config.AddFact(rule.NewFact("Fr", []term.Term{term.NewConstant("bob")}, rule.LinearFact))

	// Verify we have 2 facts
	if len(config.Facts()) != 2 {
		t.Fatalf("Expected 2 facts, got %d", len(config.Facts()))
	}

	// Process the test event that matches our pseudo trigger
	testEvent := term.NewFunction("pair", []term.Term{
		term.NewFunction("test", []term.Term{}),
		term.NewFunction("pair", []term.Term{}),
	})

	_, err = mon.ProcessEvent(testEvent)
	if err != nil {
		t.Fatalf("ProcessEvent failed: %v", err)
	}

	// Check the resulting configurations
	// The broken conflictSet should cause different behavior in rule matching
	resultConfigs := mon.Configs()
	if len(resultConfigs) == 0 {
		t.Errorf("Expected some configurations after processing event")
	}

	t.Logf("Processed event successfully, got %d result configs", len(resultConfigs))
}

// TestMonitorRestrictionViolation tests that when multiple rules can match an event
// but one fails due to a restriction violation (e.g., Eq check), the monitor continues
// to try other rules instead of returning an error immediately.
func TestMonitorRestrictionViolation(t *testing.T) {
	// Create an In rule that adds In(x) to state
	inRule := &rule.Rule{
		Name: "In",
		LHS:  []*rule.Fact{},
		RHS: []*rule.Fact{
			rule.NewFact("In", []term.Term{term.NewVariable("x")}, rule.LinearFact),
		},
		Attrs: map[string]rule.Attribute{
			"trigger": rule.TermAttribute{
				Value: []term.Term{
					term.NewFunction("pair", []term.Term{
						term.NewFunction("in", []term.Term{}),
						term.NewVariable("x"),
					}),
				},
			},
		},
	}

	// Create rule A: consumes In($x) with restriction Eq($x, '1')
	ruleA := &rule.Rule{
		Name: "A",
		LHS: []*rule.Fact{
			rule.NewFact("In", []term.Term{term.NewVariable("$x")}, rule.LinearFact),
		},
		RHS: []*rule.Fact{
			rule.NewFact("A", []term.Term{
				term.NewFunction("h", []term.Term{term.NewVariable("$x")}),
			}, rule.LinearFact),
		},
		Act: []*rule.Fact{
			rule.NewFact("Eq", []term.Term{
				term.NewVariable("$x"),
				term.NewConstant("1"),
			}, rule.LinearFact),
		},
		Attrs: map[string]rule.Attribute{
			"trigger": rule.TermAttribute{
				Value: []term.Term{
					term.NewFunction("pair", []term.Term{
						term.NewFunction("h", []term.Term{term.NewVariable("$x")}),
						term.NewVariable("h$x"),
					}),
				},
			},
		},
	}

	// Create rule B: consumes In($x) with restriction Eq($x, '2')
	ruleB := &rule.Rule{
		Name: "B",
		LHS: []*rule.Fact{
			rule.NewFact("In", []term.Term{term.NewVariable("$x")}, rule.LinearFact),
		},
		RHS: []*rule.Fact{
			rule.NewFact("B", []term.Term{
				term.NewFunction("h", []term.Term{term.NewVariable("$x")}),
			}, rule.LinearFact),
		},
		Act: []*rule.Fact{
			rule.NewFact("Eq", []term.Term{
				term.NewVariable("$x"),
				term.NewConstant("2"),
			}, rule.LinearFact),
		},
		Attrs: map[string]rule.Attribute{
			"trigger": rule.TermAttribute{
				Value: []term.Term{
					term.NewFunction("pair", []term.Term{
						term.NewFunction("h", []term.Term{term.NewVariable("$x")}),
						term.NewVariable("h$x"),
					}),
				},
			},
		},
	}

	// Create monitor with all three rules
	mon, err := monitor.NewMonitor([]*rule.Rule{inRule, ruleA, ruleB})
	if err != nil {
		t.Fatalf("Failed to create monitor: %v", err)
	}

	// Process first event: <in(), 1>
	inEvent := term.NewFunction("pair", []term.Term{
		term.NewFunction("in", []term.Term{}),
		term.NewConstant("1"),
	})

	_, err = mon.ProcessEvent(inEvent)
	if err != nil {
		t.Fatalf("ProcessEvent failed for in event: %v", err)
	}

	// Process second event: <h(1), 42>
	hEvent := term.NewFunction("pair", []term.Term{
		term.NewFunction("h", []term.Term{term.NewConstant("1")}),
		term.NewConstant("42"),
	})

	_, err = mon.ProcessEvent(hEvent)
	if err != nil {
		t.Fatalf("ProcessEvent failed for h event: %v", err)
	}

	// Check the resulting configurations
	resultConfigs := mon.Configs()
	if len(resultConfigs) != 1 {
		t.Fatalf("Expected 1 configuration, got %d", len(resultConfigs))
	}

	// Verify that rule A was applied (fact A exists) and rule B was not (fact B doesn't exist)
	config := resultConfigs[0]
	facts := config.Facts()

	foundA := false
	foundB := false
	for _, fact := range facts {
		if fact.Name == "A" {
			foundA = true
		}
		if fact.Name == "B" {
			foundB = true
		}
	}

	if !foundA {
		t.Errorf("Expected fact A to exist (rule A should have succeeded)")
	}
	if foundB {
		t.Errorf("Expected fact B to not exist (rule B should have failed due to restriction)")
	}

	t.Logf("Test passed: Rule A succeeded, Rule B failed due to restriction violation")
}

// TestMonitorTriggerAnchoredToCurrentEvent pins the trigger-anchoring
// semantics: every rule application performed while processing event a
// must consume an instance of a itself. A buffered seen-event may only
// fill the REMAINING trigger slots of a multi-trigger rule; it can
// never supply the binding for the slot the current event matched.
//
// Scenario: R1 buffers go-events (its done-trigger never arrives). R2
// consumes Gate() on <go, x>, where x occurs only in the trigger. The
// trace buffers <go,'1'> while R2 is inapplicable (no Gate), creates
// Gate(), then sends <go,'2'>.
//
// Exactly two configurations must result:
//
//	{ [Gate()]     | seen: <go,'1'>, <go,'2'> }  (R1 buffered <go,'2'>)
//	{ [State('2')] | seen: <go,'1'> }            (R2 fired on <go,'2'>)
//
// A configuration containing State('1') -- R2 fired by binding x from
// the buffered <go,'1'> instead of the arriving event -- is invalid
// and must be unreachable. (Matching the trigger patterns against the
// seen set with the event binding left open reintroduces it.)
func TestMonitorTriggerAnchoredToCurrentEvent(t *testing.T) {
	pairEv := func(name string, arg term.Term) *term.Function {
		return term.NewFunction("pair", []term.Term{
			term.NewFunction(name, []term.Term{}), arg,
		})
	}

	r1 := &rule.Rule{
		Name: "R1", LHS: []*rule.Fact{}, RHS: []*rule.Fact{},
		Attrs: map[string]rule.Attribute{
			"trigger": rule.TermAttribute{Value: []term.Term{
				pairEv("go", term.NewVariable("y")),
				pairEv("done", term.NewVariable("y")),
			}},
		},
	}
	r2 := &rule.Rule{
		Name: "R2",
		LHS:  []*rule.Fact{rule.NewFact("Gate", []term.Term{}, rule.LinearFact)},
		RHS:  []*rule.Fact{rule.NewFact("State", []term.Term{term.NewVariable("x")}, rule.LinearFact)},
		Attrs: map[string]rule.Attribute{
			"trigger": rule.TermAttribute{Value: []term.Term{
				pairEv("go", term.NewVariable("x")),
			}},
		},
	}
	r3 := &rule.Rule{
		Name: "R3", LHS: []*rule.Fact{},
		RHS: []*rule.Fact{rule.NewFact("Gate", []term.Term{}, rule.LinearFact)},
		Attrs: map[string]rule.Attribute{
			"trigger": rule.TermAttribute{Value: []term.Term{
				pairEv("mk", term.NewVariable("z")),
			}},
		},
	}

	mon, err := monitor.NewMonitor([]*rule.Rule{r1, r2, r3})
	if err != nil {
		t.Fatalf("NewMonitor: %v", err)
	}
	step := func(name, val string) {
		if _, err := mon.ProcessEvent(pairEv(name, term.NewConstant(val))); err != nil {
			t.Fatalf("ProcessEvent(%s,%s): %v", name, val, err)
		}
	}

	step("go", "1")
	step("mk", "0")
	step("go", "2")

	configs := mon.Configs()
	if len(configs) != 2 {
		for i, c := range configs {
			t.Logf("config %d: %s", i, c)
		}
		t.Fatalf("expected exactly 2 configurations, got %d", len(configs))
	}

	var sawFired, sawBuffered bool
	for _, c := range configs {
		s := c.String()
		if strings.Contains(s, "State('1')") {
			t.Errorf("invalid configuration reached: R2 bound its trigger from the buffered <go,'1'>: %s", s)
		}
		switch {
		case strings.Contains(s, "State('2')") && strings.Contains(s, "<go(), '1'>"):
			sawFired = true
		case strings.Contains(s, "Gate()") &&
			strings.Contains(s, "<go(), '1'>") && strings.Contains(s, "<go(), '2'>"):
			sawBuffered = true
		}
	}
	if !sawFired {
		t.Errorf("missing configuration { [State('2')] | seen: <go,'1'> }")
	}
	if !sawBuffered {
		t.Errorf("missing configuration { [Gate()] | seen: <go,'1'>, <go,'2'> }")
	}
}
