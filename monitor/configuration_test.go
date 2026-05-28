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
	"testing"

	"github.com/specmon/specmon/data"
	"github.com/specmon/specmon/monitor"
	"github.com/specmon/specmon/rule"
	"github.com/specmon/specmon/term"
)

func newFFact(args ...term.Term) *rule.Fact {
	return rule.NewFact("F", args, rule.LinearFact)
}

// TestConfigHashPreservesMultiplicity guards against the XOR-cancellation
// bug where [F, F] and [] hashed to the same value because F.Hash() ^
// F.Hash() = 0. Since data.HashMap keys solely by Config.Hash() with no
// Equal fallback, a collision here silently merges structurally distinct
// configurations.
func TestConfigHashPreservesMultiplicity(t *testing.T) {
	f := newFFact(term.NewConstant("a"))

	empty := monitor.NewConfig()

	singleton := monitor.NewConfig()
	singleton.AddFact(f)

	doubled := monitor.NewConfig()
	doubled.AddFact(f)
	doubled.AddFact(f)

	tripled := monitor.NewConfig()
	tripled.AddFact(f)
	tripled.AddFact(f)
	tripled.AddFact(f)

	hashes := map[string]uint64{
		"empty":     empty.Hash(),
		"singleton": singleton.Hash(),
		"doubled":   doubled.Hash(),
		"tripled":   tripled.Hash(),
	}

	for nameA, hA := range hashes {
		for nameB, hB := range hashes {
			if nameA == nameB {
				continue
			}
			if hA == hB {
				t.Errorf("Hash() collision between %s and %s (both = %d) — multiplicity not preserved",
					nameA, nameB, hA)
			}
		}
	}
}

// TestConfigHashOrderIndependent verifies that the order in which facts
// are added does NOT affect the hash. This is the intended multiset
// behavior that the original (order-dependent) FNV streaming lacked.
func TestConfigHashOrderIndependent(t *testing.T) {
	fa := newFFact(term.NewConstant("a"))
	fb := newFFact(term.NewConstant("b"))
	fc := newFFact(term.NewConstant("c"))

	ab := monitor.NewConfig()
	ab.AddFact(fa)
	ab.AddFact(fb)
	ab.AddFact(fc)

	ba := monitor.NewConfig()
	ba.AddFact(fc)
	ba.AddFact(fa)
	ba.AddFact(fb)

	if ab.Hash() != ba.Hash() {
		t.Errorf("Hash() depends on insertion order: %d != %d", ab.Hash(), ba.Hash())
	}
}

// TestConfigHashSetDistinguishesDuplicates is the integration test for
// the multiplicity guarantee: two configs that differ only in fact
// multiplicity must coexist in data.HashSet[*Config]. data.HashMap keys
// by hash and has no Equal fallback, so this only passes if Hash()
// itself separates them.
func TestConfigHashSetDistinguishesDuplicates(t *testing.T) {
	f := newFFact(term.NewConstant("a"))

	singleton := monitor.NewConfig()
	singleton.AddFact(f)

	doubled := monitor.NewConfig()
	doubled.AddFact(f)
	doubled.AddFact(f)

	set := data.NewHashSet[*monitor.Config]()
	set.Add(singleton)
	set.Add(doubled)

	if set.Size() != 2 {
		t.Errorf("HashSet collapsed two configs differing in multiplicity: size = %d, want 2", set.Size())
	}
}

// TestConfigHashSeenSeparate verifies that a fact and a term hashed
// equally do not cancel across the facts/seen sections.
func TestConfigHashSeenSeparate(t *testing.T) {
	a := term.NewConstant("a")
	fa := newFFact(a)

	withFact := monitor.NewConfig()
	withFact.AddFact(fa)

	withSeen := monitor.NewConfig()
	withSeen.AddSeen(a)

	if withFact.Hash() == withSeen.Hash() {
		t.Errorf("Hash() does not separate facts from seen events: both hash to %d", withFact.Hash())
	}
}

// TestConfigHashLengthSensitivity guards against the sum-collision case
// where mix(F) + mix(G) happens to equal 2*mix(H). Even when section
// accumulators tie, the length prefix folded into the final FNV-1a
// must keep distinct-cardinality configs apart.
func TestConfigHashLengthSensitivity(t *testing.T) {
	f := newFFact(term.NewConstant("f"))
	g := newFFact(term.NewConstant("g"))
	h := newFFact(term.NewConstant("h"))

	two := monitor.NewConfig()
	two.AddFact(f)
	two.AddFact(g)

	one := monitor.NewConfig()
	one.AddFact(h)

	// Even if (extremely unlikely) the accumulators tied, factCount
	// differs and is folded into the digest. The configs MUST hash
	// differently.
	if two.Hash() == one.Hash() {
		t.Errorf("Hash() collapsed configs with different fact counts: both = %d", two.Hash())
	}
}

// TestConfigHashCacheInvalidated verifies the cache is cleared on
// mutation. A stale cache would let a config hash to its old value
// after AddFact/DeleteFact/AddSeen/DeleteSeen.
func TestConfigHashCacheInvalidated(t *testing.T) {
	c := monitor.NewConfig()
	before := c.Hash()
	c.AddFact(newFFact(term.NewConstant("a")))
	after := c.Hash()
	if before == after {
		t.Errorf("Hash() returned cached value after AddFact: %d", before)
	}
}

// BenchmarkConfigHashCold measures uncached Config.Hash() cost for a
// realistic config size. Cache is invalidated each iteration via AddFact
// so we measure the full recomputation path.
func BenchmarkConfigHashCold(b *testing.B) {
	c := monitor.NewConfig()
	for i := 0; i < 100; i++ {
		c.AddFact(newFFact(term.NewConstant("v"), term.NewConstant(i)))
	}
	// Warm one fact so we can re-add it cheaply.
	probe := newFFact(term.NewConstant("probe"))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// AddFact invalidates the cache; the immediate Hash() then
		// recomputes from scratch.
		c.AddFact(probe)
		_ = c.Hash()
	}
}

// BenchmarkConfigHashHot measures the cached path. With the cache
// working, repeated Hash() calls should be a single map lookup +
// branch.
func BenchmarkConfigHashHot(b *testing.B) {
	c := monitor.NewConfig()
	for i := 0; i < 100; i++ {
		c.AddFact(newFFact(term.NewConstant("v"), term.NewConstant(i)))
	}
	_ = c.Hash() // warm cache
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = c.Hash()
	}
}
