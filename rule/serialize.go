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
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/specmon/specmon/term"
)

const (
	RulesetFormat        = "specmon-ruleset"
	RulesetFormatVersion = "1.0.0"
	MaxRulesetRules      = 100000
	MaxRulesetTermDepth  = 256
)

const (
	attrKindString = "string"
	attrKindTerms  = "terms"
)

type RulesetMeta struct {
	Schema    string
	Generator string
	Source    *RulesetSource
}

type RulesetSource struct {
	Hash      string   `json:"hash,omitempty"`
	Role      string   `json:"role,omitempty"`
	Defines   []string `json:"defines,omitempty"`
	Decompose bool     `json:"decompose"`
}

type rulesetEnvelope struct {
	Schema        string         `json:"$schema,omitempty"`
	Format        string         `json:"format"`
	FormatVersion string         `json:"format_version"`
	Generator     string         `json:"generator,omitempty"`
	Source        *RulesetSource `json:"source,omitempty"`
	Rules         []ruleDTO      `json:"rules"`
}

type ruleDTO struct {
	Name  string                  `json:"name"`
	LHS   []factDTO               `json:"lhs"`
	Act   []factDTO               `json:"act"`
	RHS   []factDTO               `json:"rhs"`
	Attrs map[string]attributeDTO `json:"attributes,omitempty"`
}

type factDTO struct {
	Name string          `json:"name"`
	Args []term.WeakTerm `json:"arguments,omitempty"`
	Type FactType        `json:"type"`
}

type attributeDTO struct {
	Kind   string          `json:"kind"`
	String string          `json:"string,omitempty"`
	Terms  []term.WeakTerm `json:"terms,omitempty"`
}

func MarshalRuleset(rules []*Rule, meta RulesetMeta) ([]byte, error) {
	dtoRules := make([]ruleDTO, len(rules))
	for i, r := range rules {
		dto, err := toRuleDTO(r)
		if err != nil {
			return nil, fmt.Errorf("cannot serialize rule %d: %w", i, err)
		}
		dtoRules[i] = dto
	}

	env := rulesetEnvelope{
		Schema:        meta.Schema,
		Format:        RulesetFormat,
		FormatVersion: RulesetFormatVersion,
		Generator:     meta.Generator,
		Source:        meta.Source,
		Rules:         dtoRules,
	}
	b, err := json.Marshal(env)
	if err != nil {
		return nil, fmt.Errorf("cannot marshal ruleset: %w", err)
	}

	return b, nil
}

func UnmarshalRuleset(b []byte) ([]*Rule, RulesetMeta, error) {
	var env rulesetEnvelope
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(&env); err != nil {
		return nil, RulesetMeta{}, fmt.Errorf("cannot decode ruleset: %w", err)
	}
	var extra struct{}
	if err := d.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, RulesetMeta{}, fmt.Errorf("cannot decode ruleset: unexpected trailing data")
	}

	if err := validateEnvelope(env); err != nil {
		return nil, RulesetMeta{}, err
	}

	rules := make([]*Rule, len(env.Rules))
	for i, r := range env.Rules {
		rr, err := fromRuleDTO(r)
		if err != nil {
			return nil, RulesetMeta{}, fmt.Errorf("cannot deserialize rule %d: %w", i, err)
		}
		rules[i] = rr
	}

	if err := validateRulesetTerms(rules); err != nil {
		return nil, RulesetMeta{}, err
	}

	return rules, RulesetMeta{
		Schema:    env.Schema,
		Generator: env.Generator,
		Source:    env.Source,
	}, nil
}

func validateEnvelope(e rulesetEnvelope) error {
	if e.Format != RulesetFormat {
		return fmt.Errorf("unsupported ruleset format %q", e.Format)
	}
	if e.FormatVersion != RulesetFormatVersion {
		return fmt.Errorf(
			"unsupported ruleset format version %q (this binary supports %q)",
			e.FormatVersion,
			RulesetFormatVersion,
		)
	}
	if e.Rules == nil {
		return fmt.Errorf("ruleset is missing 'rules'")
	}
	if len(e.Rules) > MaxRulesetRules {
		return fmt.Errorf("ruleset contains %d rules, limit is %d", len(e.Rules), MaxRulesetRules)
	}

	return nil
}

func validateRulesetTerms(rules []*Rule) error {
	for i, r := range rules {
		for _, f := range r.LHS {
			if err := validateFactDepth(f, MaxRulesetTermDepth); err != nil {
				return fmt.Errorf("rule[%d] lhs: %w", i, err)
			}
		}
		for _, f := range r.Act {
			if err := validateFactDepth(f, MaxRulesetTermDepth); err != nil {
				return fmt.Errorf("rule[%d] act: %w", i, err)
			}
		}
		for _, f := range r.RHS {
			if err := validateFactDepth(f, MaxRulesetTermDepth); err != nil {
				return fmt.Errorf("rule[%d] rhs: %w", i, err)
			}
		}
		for name, attr := range r.Attrs {
			for _, t := range attr.GetTerms() {
				if err := validateTermDepth(t, 1, MaxRulesetTermDepth); err != nil {
					return fmt.Errorf("rule[%d] attr[%s]: %w", i, name, err)
				}
			}
		}
	}

	return nil
}

func validateFactDepth(f *Fact, max int) error {
	for i, t := range f.Args {
		if err := validateTermDepth(t, 1, max); err != nil {
			return fmt.Errorf("fact %s arg[%d]: %w", f.Name, i, err)
		}
	}

	return nil
}

func validateTermDepth(t term.Term, depth, max int) error {
	if depth > max {
		return fmt.Errorf("term nesting exceeds limit %d", max)
	}
	fn, err := term.AsFunction(t)
	if err != nil {
		return nil
	}

	for _, arg := range fn.Args {
		if err := validateTermDepth(arg, depth+1, max); err != nil {
			return err
		}
	}

	return nil
}

func toRuleDTO(r *Rule) (ruleDTO, error) {
	lhs, err := toFactsDTO(r.LHS)
	if err != nil {
		return ruleDTO{}, err
	}
	act, err := toFactsDTO(r.Act)
	if err != nil {
		return ruleDTO{}, err
	}
	rhs, err := toFactsDTO(r.RHS)
	if err != nil {
		return ruleDTO{}, err
	}

	attrs := make(map[string]attributeDTO, len(r.Attrs))
	for k, attr := range r.Attrs {
		a, err := toAttributeDTO(attr)
		if err != nil {
			return ruleDTO{}, fmt.Errorf("attribute %s: %w", k, err)
		}
		attrs[k] = a
	}

	return ruleDTO{
		Name:  r.Name,
		LHS:   lhs,
		Act:   act,
		RHS:   rhs,
		Attrs: attrs,
	}, nil
}

func fromRuleDTO(r ruleDTO) (*Rule, error) {
	attrs := make(map[string]Attribute, len(r.Attrs))
	for k, attr := range r.Attrs {
		a, err := fromAttributeDTO(attr)
		if err != nil {
			return nil, fmt.Errorf("attribute %s: %w", k, err)
		}
		attrs[k] = a
	}

	lhs, err := fromFactsDTO(r.LHS)
	if err != nil {
		return nil, fmt.Errorf("lhs: %w", err)
	}
	act, err := fromFactsDTO(r.Act)
	if err != nil {
		return nil, fmt.Errorf("act: %w", err)
	}
	rhs, err := fromFactsDTO(r.RHS)
	if err != nil {
		return nil, fmt.Errorf("rhs: %w", err)
	}

	return &Rule{
		Name:  r.Name,
		LHS:   lhs,
		Act:   act,
		RHS:   rhs,
		Attrs: attrs,
	}, nil
}

func toFactsDTO(fs []*Fact) ([]factDTO, error) {
	out := make([]factDTO, len(fs))
	for i, f := range fs {
		dto, err := toFactDTO(f)
		if err != nil {
			return nil, fmt.Errorf("fact %d: %w", i, err)
		}
		out[i] = dto
	}
	return out, nil
}

func fromFactsDTO(fs []factDTO) ([]*Fact, error) {
	out := make([]*Fact, len(fs))
	for i, f := range fs {
		fact, err := fromFactDTO(f)
		if err != nil {
			return nil, fmt.Errorf("fact %d: %w", i, err)
		}
		out[i] = fact
	}
	return out, nil
}

func toFactDTO(f *Fact) (factDTO, error) {
	args := make([]term.WeakTerm, len(f.Args))
	for i, arg := range f.Args {
		w, err := term.ToWeakTerm(arg)
		if err != nil {
			return factDTO{}, fmt.Errorf("arg %d: %w", i, err)
		}
		args[i] = w
	}
	return factDTO{Name: f.Name, Args: args, Type: f.Type}, nil
}

func fromFactDTO(f factDTO) (*Fact, error) {
	args := make([]term.Term, len(f.Args))
	for i, arg := range f.Args {
		t, err := term.FromWeakTerm(arg)
		if err != nil {
			return nil, fmt.Errorf("arg %d: %w", i, err)
		}
		args[i] = t
	}
	return &Fact{Name: f.Name, Args: args, Type: f.Type}, nil
}

func toAttributeDTO(attr Attribute) (attributeDTO, error) {
	switch a := attr.(type) {
	case StringAttribute:
		return attributeDTO{Kind: attrKindString, String: a.Value}, nil
	case TermAttribute:
		terms := make([]term.WeakTerm, len(a.Value))
		for i, trm := range a.Value {
			w, err := term.ToWeakTerm(trm)
			if err != nil {
				return attributeDTO{}, fmt.Errorf("term %d: %w", i, err)
			}
			terms[i] = w
		}
		return attributeDTO{Kind: attrKindTerms, Terms: terms}, nil
	default:
		return attributeDTO{}, fmt.Errorf("unsupported attribute type %T", attr)
	}
}

//nolint:ireturn // Attribute is the only sensible return type for a discriminated-union factory.
func fromAttributeDTO(a attributeDTO) (Attribute, error) {
	switch a.Kind {
	case attrKindString:
		return StringAttribute{Value: a.String}, nil
	case attrKindTerms:
		terms := make([]term.Term, len(a.Terms))
		for i, trm := range a.Terms {
			t, err := term.FromWeakTerm(trm)
			if err != nil {
				return nil, fmt.Errorf("term %d: %w", i, err)
			}
			terms[i] = t
		}
		return TermAttribute{Value: terms}, nil
	default:
		return nil, fmt.Errorf("unsupported attribute kind %q", a.Kind)
	}
}
