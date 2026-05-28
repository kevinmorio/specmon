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

package monitor

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/fnv"
	"slices"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/specmon/specmon/rule"
	"github.com/specmon/specmon/term"
)

// Config is a configuration of the monitor.
type Config struct {
	// facts is a multiset of facts that are true in the current configuration.
	facts []*rule.Fact

	// factCounts indexes facts by predicate name so CountByName is O(1)
	// instead of walking c.facts. Maintained incrementally by AddFact /
	// DeleteFact / Clone.
	factCounts map[string]int

	// factsByName buckets facts by predicate name so conflictSetFacts can
	// iterate only the relevant predicate, not all of c.facts. Maintained
	// incrementally by AddFact / DeleteFact / Clone.
	factsByName map[string][]*rule.Fact

	// seen is a multiset of events that have been seen in the current configuration
	// and that have not been processed yet.
	seen []term.Term

	// trace is a list of action facts that have been recorded in the current configuration.
	trace []*rule.Fact

	// hashCache memoizes Hash() so repeated lookups in HashSet[*Config]
	// don't re-walk all facts/seen/trace per call. Any mutation must
	// call invalidateHash().
	hashCache    uint64
	hashCacheSet bool
}

// NewConfig returns a new configuration.
func NewConfig() *Config {
	return &Config{
		facts:       []*rule.Fact{},
		factCounts:  make(map[string]int),
		factsByName: make(map[string][]*rule.Fact),
		seen:        []term.Term{},
		trace:       []*rule.Fact{},
	}
}

// Facts returns the facts of the configuration.
func (c *Config) Facts() []*rule.Fact {
	return c.facts
}

func (c *Config) DeleteFact(t *rule.Fact) bool {
	i := slices.IndexFunc(c.facts, func(s *rule.Fact) bool {
		return t.Equal(s)
	})

	if i == -1 {
		return false
	}

	removed := c.facts[i]
	c.facts = slices.Delete(c.facts, i, i+1)
	if n := c.factCounts[removed.Name]; n <= 1 {
		delete(c.factCounts, removed.Name)
	} else {
		c.factCounts[removed.Name] = n - 1
	}
	if bucket := c.factsByName[removed.Name]; len(bucket) > 0 {
		// Remove the first matching pointer-or-equal entry from the bucket.
		bi := slices.IndexFunc(bucket, func(s *rule.Fact) bool { return removed.Equal(s) })
		if bi >= 0 {
			bucket = slices.Delete(bucket, bi, bi+1)
			if len(bucket) == 0 {
				delete(c.factsByName, removed.Name)
			} else {
				c.factsByName[removed.Name] = bucket
			}
		}
	}
	c.invalidateHash()

	log.Tracef("removed %s\n", t)

	return true
}

func (c *Config) AddFact(t *rule.Fact) {
	c.facts = append(c.facts, t)
	c.factCounts[t.Name]++
	c.factsByName[t.Name] = append(c.factsByName[t.Name], t)
	c.invalidateHash()
}

// FactsByName returns the slice of facts in c whose predicate name matches.
// The returned slice is owned by the Config; callers must not mutate it.
func (c *Config) FactsByName(name string) []*rule.Fact {
	return c.factsByName[name]
}

func (c *Config) Clone() *Config {
	d := NewConfig()
	d.facts = slices.Clone(c.facts)
	d.seen = slices.Clone(c.seen)
	d.trace = slices.Clone(c.trace)

	// Copy the factCounts map so further mutations on the clone don't
	// disturb the original.
	if len(c.factCounts) > 0 {
		d.factCounts = make(map[string]int, len(c.factCounts))
		for k, v := range c.factCounts {
			d.factCounts[k] = v
		}
	}

	// Copy the factsByName index so the clone can be mutated independently.
	// The bucket slices are cloned (shallow), so each clone owns its slice
	// header but the *rule.Fact pointers inside are shared (Facts are
	// treated as immutable after construction).
	if len(c.factsByName) > 0 {
		d.factsByName = make(map[string][]*rule.Fact, len(c.factsByName))
		for k, v := range c.factsByName {
			d.factsByName[k] = slices.Clone(v)
		}
	}

	return d
}

func (c *Config) FactsAsSlice() []*rule.Fact {
	return c.facts
}

func (c *Config) FactsAsSliceWithName(name string) []*rule.Fact {
	var T []*rule.Fact
	for _, t := range c.facts {
		if t.Name == name {
			T = append(T, t)
		}
	}

	return T
}

// CountByName returns how many facts in c carry the given predicate name.
// Used by the rule-applicability gate to skip rules whose LHS requires
// more instances of a predicate than the config currently has. O(1)
// via the factCounts index maintained by AddFact / DeleteFact.
func (c *Config) CountByName(name string) int {
	return c.factCounts[name]
}

func (c *Config) String() string {
	facts := make([]string, len(c.facts))
	for i := range c.facts {
		facts[i] = c.facts[i].String()
	}
	factsStr := strings.Join(facts, "\n")

	seen := make([]string, len(c.seen))
	for i := range c.seen {
		seen[i] = c.seen[i].String()
	}
	seenStr := strings.Join(seen, "\n")

	trace := make([]string, len(c.trace))
	for i := range c.trace {
		trace[i] = c.trace[i].String()
	}
	traceStr := strings.Join(trace, "\n")

	return fmt.Sprintf("{ [ %s ] | %s | %s }", factsStr, seenStr, traceStr)
}

func (c *Config) Hash() uint64 {
	if c.hashCacheSet {
		return c.hashCache
	}
	h := fnv.New64a()

	for _, f := range c.facts {
		hash := f.Hash()
		var buf [8]byte
		binary.LittleEndian.PutUint64(buf[:], hash)
		h.Write(buf[:])
	}

	for _, f := range c.trace {
		hash := f.Hash()
		var buf [8]byte
		binary.LittleEndian.PutUint64(buf[:], hash)
		h.Write(buf[:])
	}

	for _, f := range c.seen {
		hash := f.Hash()
		var buf [8]byte
		binary.LittleEndian.PutUint64(buf[:], hash)
		h.Write(buf[:])
	}

	c.hashCache = h.Sum64()
	c.hashCacheSet = true
	return c.hashCache
}

// invalidateHash clears the memoized Hash. Callers that mutate facts,
// seen, or trace must call this so the next Hash() recomputes.
func (c *Config) invalidateHash() {
	c.hashCache = 0
	c.hashCacheSet = false
}

func (c *Config) AddSeen(t term.Term) {
	c.seen = append(c.seen, t)
	c.invalidateHash()
}

func (c *Config) DeleteSeen(t term.Term) bool {
	i := slices.IndexFunc(c.seen, func(s term.Term) bool {
		return t.Equal(s)
	})

	if i == -1 {
		return false
	}

	c.seen = slices.Delete(c.seen, i, i+1)
	c.invalidateHash()

	return true
}

// ApplyRule applies a rule to a configuration and returns the resulting configuration.
// If ev is a tuple of the form <fn, ret>, then fn is replaced by ret.
func (c *Config) ApplyRule(r *rule.Rule, b *term.Binding) (*Config, []*rule.Fact, error) {
	log.Infof("   applying rule %s\n", r.Name)

	s := r.Subst(b)
	t := r.Subst(b)

	for _, f := range s.Triggers() {
		t = t.Subst(splitTupleBinding(f))
	}
	t = t.ReplaceFormats()

	if !t.IsGround() {
		return nil, nil, fmt.Errorf("expected ground rule (%s), got variables: %v", t.Name, s.Vars())
	}

	d := c.Clone()

	// Delete the facts from the LHS.
	for _, f := range t.LHS {
		if f.IsLinear() && !d.DeleteFact(f) {
			return nil, nil, fmt.Errorf("cannot delete non-existing fact '%s'", f)
		}
	}

	// Add the facts from the RHS.
	for _, f := range t.RHS {
		if !strings.HasSuffix(f.Name, "_") {
			d.AddFact(f)
		}
	}

	// Remove triggers from seen events.
	// Triggers in s still contain formats.
	for _, f := range s.Triggers() {
		if !d.DeleteSeen(term.ReplaceFormats(f)) {
			return nil, nil, fmt.Errorf("cannot delete non-existing event '%s'", f)
		}
	}

	// Add action facts to trace.
	// FIXME: For performance reasons, this is commented out.
	// d.trace = append(d.trace, t.Act...)

	// Check if special event restrictions are satisfied.
	if err := restrSatisfied(t.Act); err != nil {
		// Don't wrap restriction violations to avoid redundant error messages
		if errors.Is(err, ErrRestrictionViolated) {
			return nil, nil, err
		}
		return nil, nil, fmt.Errorf("rule not applied: %w", err)
	}

	return d, t.Act, nil
}

func splitTupleBinding(a term.Term) *term.Binding {
	b := term.NewBinding()

	fst, snd := splitPair(a)
	if fst == nil || snd == nil {
		return b
	}

	b.Set(fst, snd)

	return b
}

func splitPair(t term.Term) (term.Term, term.Term) {
	f, err := term.AsFunction(t)
	if err != nil || f == nil {
		return nil, nil
	}

	if f.Name != term.PairFunctionName || len(f.Args) != 2 {
		return nil, nil
	}

	fst := f.Args[0]
	snd := f.Args[1]

	return fst, snd
}

func restrSatisfied(trace []*rule.Fact) error {
	for _, t := range trace {
		switch t.Name {
		case "Eq", "Equal":
			if len(t.Args) != 2 {
				return fmt.Errorf("event restriction: %s must have two arguments", t.Name)
			}
			if !t.Args[0].Equal(t.Args[1]) {
				return fmt.Errorf("%w: %s", ErrRestrictionViolated, t)
			}
		case "Neq", "NotEqual", "Unequal":
			if len(t.Args) != 2 {
				return fmt.Errorf("event restriction: %s must have two arguments", t.Name)
			}
			if t.Args[0].Equal(t.Args[1]) {
				return fmt.Errorf("%w: %s", ErrRestrictionViolated, t)
			}
		}
	}

	return nil
}
