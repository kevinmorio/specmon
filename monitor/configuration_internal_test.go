// Copyright (C) 2026 CISPA Helmholtz Center for Information Security
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
// along with this program. If not, see <https://www.gnu.org/licenses/>.

package monitor

import (
	"testing"

	"github.com/specmon/specmon/data"
	"github.com/specmon/specmon/term"
)

func testPendingApplication(ruleOrdinal int, value int64, outstanding ...int) pendingApplication {
	binding := term.NewBinding()
	binding.Set(term.NewVariable("value"), term.NewConstant(value))
	return pendingApplication{ruleOrdinal: ruleOrdinal, binding: binding, outstanding: outstanding}
}

func configWithPending(applications ...pendingApplication) *Config {
	config := NewConfig()
	for _, application := range applications {
		config.addPending(application)
	}
	return config
}

func TestConfigCloneKeepsPendingStateIndependent(t *testing.T) {
	original := NewConfig()
	original.addPending(testPendingApplication(2, 1, 0, 2))
	clone := original.Clone()

	original.replacePending(0, testPendingApplication(2, 9, 1, 2))

	value, ok := clone.pending[0].binding.Get(term.NewVariable("value"))
	if !ok || !value.Equal(term.NewConstant[int64](1)) {
		t.Fatalf("clone binding changed with source: %v", clone.pending[0].binding)
	}
	if got := clone.pending[0].outstanding; len(got) != 2 || got[0] != 0 || got[1] != 2 {
		t.Fatalf("clone outstanding slots changed with source: %v", got)
	}

	clone.removePending(0)
	if len(original.pending) != 1 {
		t.Fatalf("removing clone pending state changed source: %v", original.pending)
	}
}

func TestConfigPendingHashIsCanonical(t *testing.T) {
	first := testPendingApplication(1, 1, 0)
	second := testPendingApplication(2, 2, 1, 3)

	forward := NewConfig()
	forward.addPending(first)
	forward.addPending(second)
	reverse := NewConfig()
	reverse.addPending(second)
	reverse.addPending(first)
	if forward.Hash() != reverse.Hash() {
		t.Fatalf("pending insertion order changed hash: %d != %d", forward.Hash(), reverse.Hash())
	}
}

func TestConfigPendingHashPreservesIdentityAndMultiplicity(t *testing.T) {
	pending := testPendingApplication(1, 1, 0, 2)
	cases := map[string]*Config{
		"empty":             NewConfig(),
		"one":               configWithPending(pending),
		"two":               configWithPending(pending, pending),
		"different rule":    configWithPending(testPendingApplication(2, 1, 0, 2)),
		"different binding": configWithPending(testPendingApplication(1, 2, 0, 2)),
		"different slots":   configWithPending(testPendingApplication(1, 1, 0, 1)),
	}

	seen := make(map[uint64]string, len(cases))
	set := data.NewHashSet[*Config]()
	for name, config := range cases {
		hash := config.Hash()
		if previous, ok := seen[hash]; ok {
			t.Errorf("pending hash collision between %q and %q: %d", previous, name, hash)
		}
		seen[hash] = name
		set.Add(config)
	}
	if set.Size() != len(cases) {
		t.Fatalf("configuration set collapsed pending identities: got %d, want %d", set.Size(), len(cases))
	}
}

func TestConfigPendingStateIsNotExposedAsFacts(t *testing.T) {
	config := NewConfig()
	config.addPending(testPendingApplication(0, 1, 2))

	if facts := config.Facts(); len(facts) != 0 {
		t.Fatalf("pending state exposed through Facts: %v", facts)
	}
	if got := config.String(); got != "{ [  ] |  |  }" {
		t.Fatalf("pending state exposed through String: %s", got)
	}
}

func TestConfigPendingMutatorsInvalidateHash(t *testing.T) {
	config := NewConfig()
	emptyHash := config.Hash()
	config.addPending(testPendingApplication(0, 1, 0))
	addedHash := config.Hash()
	if addedHash == emptyHash {
		t.Fatal("adding pending state did not invalidate the hash")
	}

	config.replacePending(0, testPendingApplication(0, 2, 1))
	replacedHash := config.Hash()
	if replacedHash == addedHash {
		t.Fatal("replacing pending state did not invalidate the hash")
	}

	config.removePending(0)
	if got := config.Hash(); got != emptyHash {
		t.Fatalf("removing pending state produced hash %d, want empty hash %d", got, emptyHash)
	}
}
