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

package rule

import (
	"encoding/json"
	"testing"

	"github.com/specmon/specmon/term"
	"github.com/stretchr/testify/require"
)

func TestRulesetRoundTrip(t *testing.T) {
	t.Parallel()

	r := &Rule{
		Name: "R",
		LHS: []*Fact{
			NewFact("In", []term.Term{
				term.NewVariable("x"),
				term.NewConstant[int](7),
				term.NewConstant[[]byte]([]byte{0xde, 0xad, 0xbe, 0xef}),
			}, LinearFact),
		},
		Act: []*Fact{
			NewFact("Act", []term.Term{term.NewFunction("f", []term.Term{term.NewVariable("x")})}, LinearFact),
		},
		RHS: []*Fact{
			NewFact("Out", []term.Term{term.NewConstant[string]("ok")}, PersistentFact),
		},
		Attrs: map[string]Attribute{
			RoleAttributeName: StringAttribute{Value: "client"},
			TriggerAttributeName: TermAttribute{
				Value: []term.Term{
					term.NewFunction("trigger", []term.Term{term.NewVariable("x"), term.NewConstant[int](1)}),
				},
			},
		},
	}

	b, err := MarshalRuleset([]*Rule{r}, RulesetMeta{Generator: "specmon/dev"})
	require.NoError(t, err)

	got, meta, err := UnmarshalRuleset(b)
	require.NoError(t, err)
	require.Equal(t, "specmon/dev", meta.Generator)
	require.Len(t, got, 1)

	assertRuleEqual(t, r, got[0])
}

func TestRulesetRejectsUnsupportedVersion(t *testing.T) {
	t.Parallel()

	b, err := MarshalRuleset([]*Rule{}, RulesetMeta{})
	require.NoError(t, err)

	var payload map[string]any
	require.NoError(t, json.Unmarshal(b, &payload))
	payload["format_version"] = "2.0.0"
	b, err = json.Marshal(payload)
	require.NoError(t, err)

	_, _, err = UnmarshalRuleset(b)
	require.ErrorContains(t, err, `unsupported ruleset format version "2.0.0"`)
}

func TestRulesetRejectsUnknownFields(t *testing.T) {
	t.Parallel()

	b := []byte(`{"format":"specmon-ruleset","format_version":"1.0.0","rules":[],"extra":1}`)
	_, _, err := UnmarshalRuleset(b)
	require.Error(t, err)
	require.ErrorContains(t, err, "unknown field")
}

func TestFactUnmarshalJSON(t *testing.T) {
	t.Parallel()

	raw := []byte(`{
		"name":"F",
		"arguments":[
			{"type":"constant","const_kind":"int","value":7},
			{"type":"constant","const_kind":"bytes","value":"0xdead"},
			{"type":"constant","const_kind":"string","value":"0xnothex"},
			{"type":"variable","name":"x"},
			{"type":"function","name":"g","args":[{"type":"constant","const_kind":"string","value":"ok"}]}
		],
		"type":"linear"
	}`)

	var f Fact
	require.NoError(t, json.Unmarshal(raw, &f))
	require.Equal(t, "F", f.Name)
	require.Equal(t, LinearFact, f.Type)
	require.Len(t, f.Args, 5)

	i, err := term.AsConstant[int](f.Args[0])
	require.NoError(t, err)
	require.Equal(t, 7, i.Value)

	b, err := term.AsConstant[[]byte](f.Args[1])
	require.NoError(t, err)
	require.Equal(t, []byte{0xde, 0xad}, b.Value)

	s, err := term.AsConstant[string](f.Args[2])
	require.NoError(t, err)
	require.Equal(t, "0xnothex", s.Value)
}

func assertRuleEqual(t *testing.T, expected, actual *Rule) {
	t.Helper()

	require.Equal(t, expected.Name, actual.Name)
	require.Len(t, actual.LHS, len(expected.LHS))
	require.Len(t, actual.Act, len(expected.Act))
	require.Len(t, actual.RHS, len(expected.RHS))

	for i := range expected.LHS {
		require.True(t, expected.LHS[i].Equal(actual.LHS[i]))
		require.Equal(t, expected.LHS[i].Type, actual.LHS[i].Type)
	}
	for i := range expected.Act {
		require.True(t, expected.Act[i].Equal(actual.Act[i]))
		require.Equal(t, expected.Act[i].Type, actual.Act[i].Type)
	}
	for i := range expected.RHS {
		require.True(t, expected.RHS[i].Equal(actual.RHS[i]))
		require.Equal(t, expected.RHS[i].Type, actual.RHS[i].Type)
	}

	require.Equal(t, expected.Attrs[RoleAttributeName].GetString(), actual.Attrs[RoleAttributeName].GetString())

	wantTrigger := expected.Attrs[TriggerAttributeName].GetTerms()
	gotTrigger := actual.Attrs[TriggerAttributeName].GetTerms()
	require.Len(t, gotTrigger, len(wantTrigger))
	for i := range wantTrigger {
		require.True(t, wantTrigger[i].Equal(gotTrigger[i]))
	}
}
