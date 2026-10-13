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

package term_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"testing"

	"github.com/specmon/specmon/term"
)

func decodeJSONArgument(argument string) (term.Term, error) {
	input := fmt.Sprintf(`{"name":"event","type":"function","args":[%s]}`, argument)
	var function term.Function
	if err := json.Unmarshal([]byte(input), &function); err != nil {
		return nil, err
	}
	return function.Args[0], nil
}

func TestWeakTermValueRemainsPublicJSON(t *testing.T) {
	t.Parallel()

	weak := term.WeakTerm{
		Type:      term.ConstantType,
		ConstKind: term.StringConstantKind,
		Value:     "public value",
	}
	encoded, err := json.Marshal(weak)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var object map[string]any
	if err := json.Unmarshal(encoded, &object); err != nil {
		t.Fatalf("Unmarshal encoded WeakTerm: %v", err)
	}
	if object["value"] != "public value" {
		t.Fatalf("Marshal = %s, want public value field", encoded)
	}
}

func TestTypedConstantJSONRoundTrip(t *testing.T) {
	t.Parallel()

	input := `{"name":"event","type":"function","args":[
  {"type":"constant","const_kind":"int","value":"0"},
  {"type":"constant","const_kind":"int","value":-1},
  {"type":"constant","const_kind":"int","value":"9007199254740993"},
  {"type":"constant","const_kind":"int","value":"-9223372036854775808"},
  {"type":"constant","const_kind":"string","value":"9007199254740993"},
  {"type":"constant","const_kind":"bytes","value":"0x01AB"},
  {"type":"constant","const_kind":"bytes","value":"0x"},
  {"type":"constant","const_kind":"bytes","value":null},
  {"name":"nested","type":"function","args":[{"type":"constant","const_kind":"int","value":9223372036854775807}]}
]}`
	var function term.Function
	if err := json.Unmarshal([]byte(input), &function); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	zero, err := term.AsConstant[int64](function.Args[0])
	if err != nil || zero.Value != 0 {
		t.Fatalf("zero = %v, %v", function.Args[0], err)
	}
	negative, err := term.AsConstant[int64](function.Args[1])
	if err != nil || negative.Value != -1 {
		t.Fatalf("negative = %v, %v", function.Args[1], err)
	}
	integer, err := term.AsConstant[int64](function.Args[2])
	if err != nil || integer.Value != 9007199254740993 {
		t.Fatalf("integer = %v, %v", function.Args[2], err)
	}
	minimum, err := term.AsConstant[int64](function.Args[3])
	if err != nil || minimum.Value != math.MinInt64 {
		t.Fatalf("minimum = %v, %v", function.Args[3], err)
	}
	stringValue, err := term.AsConstant[string](function.Args[4])
	if err != nil || stringValue.Value != "9007199254740993" {
		t.Fatalf("string = %v, %v", function.Args[4], err)
	}
	bytesValue, _ := term.AsConstant[[]byte](function.Args[5])
	empty, _ := term.AsConstant[[]byte](function.Args[6])
	nilValue, _ := term.AsConstant[[]byte](function.Args[7])
	if !bytes.Equal(bytesValue.Value, []byte{0x01, 0xab}) || empty.Value == nil || len(empty.Value) != 0 || nilValue.Value != nil {
		t.Fatalf("byte values = %#v, %#v, %#v", bytesValue.Value, empty.Value, nilValue.Value)
	}

	encoded, err := json.Marshal(&function)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	for _, canonical := range [][]byte{
		[]byte(`{"type":"constant","const_kind":"int","value":"0"}`),
		[]byte(`"const_kind":"int","value":"-1"`),
		[]byte(`"const_kind":"int","value":"9007199254740993"`),
		[]byte(`"const_kind":"int","value":"-9223372036854775808"`),
		[]byte(`"const_kind":"string","value":"9007199254740993"`),
		[]byte(`"const_kind":"bytes","value":"0x01ab"`),
		[]byte(`"const_kind":"bytes","value":"0x"`),
		[]byte(`"const_kind":"bytes","value":null`),
		[]byte(`"const_kind":"int","value":"9223372036854775807"`),
	} {
		if !bytes.Contains(encoded, canonical) {
			t.Errorf("Marshal output %s lacks %s", encoded, canonical)
		}
	}
}

func TestTypedStringJSONEscapes(t *testing.T) {
	t.Parallel()

	decoded, err := decodeJSONArgument(`{"type":"constant","const_kind":"string","value":"quote: \", newline: \n, umlaut: \u00e4"}`)
	if err != nil {
		t.Fatalf("decode escaped string: %v", err)
	}
	constant, err := term.AsConstant[string](decoded)
	if err != nil || constant.Value != "quote: \", newline: \n, umlaut: ä" {
		t.Fatalf("escaped string = %v, %v", decoded, err)
	}
}

func TestTypedConstantJSONRejectsInvalidValues(t *testing.T) {
	t.Parallel()

	invalid := []string{
		`{"type":"constant","const_kind":"int","value":"-0"}`,
		`{"type":"constant","const_kind":"int","value":"+1"}`,
		`{"type":"constant","const_kind":"int","value":"01"}`,
		`{"type":"constant","const_kind":"int","value":"1.0"}`,
		`{"type":"constant","const_kind":"int","value":"1e3"}`,
		`{"type":"constant","const_kind":"int","value":1e3}`,
		`{"type":"constant","const_kind":"int","value":1.5}`,
		`{"type":"constant","const_kind":"int","value":"9223372036854775808"}`,
		`{"type":"constant","const_kind":"int","value":"-9223372036854775809"}`,
		`{"type":"constant","const_kind":"int"}`,
		`{"type":"constant","const_kind":"string","value":123}`,
		`{"type":"constant","const_kind":"string","value":true}`,
		`{"type":"constant","const_kind":"string"}`,
		`{"type":"constant","const_kind":"bytes","value":"0x0"}`,
		`{"type":"constant","const_kind":"bytes","value":"0X00"}`,
		`{"type":"constant","const_kind":"bytes"}`,
		`{"type":"constant","const_kind":"unknown","value":"x"}`,
		`{"type":"constant","value":{"nested":1}}`,
		`{"type":"unknown","value":"x"}`,
	}
	for _, argument := range invalid {
		if value, err := decodeJSONArgument(argument); err == nil {
			t.Errorf("decoded invalid argument %s as %v", argument, value)
		}
	}
}

func TestFunctionJSONNestedErrors(t *testing.T) {
	t.Parallel()

	nested := func(arguments string) string {
		return fmt.Sprintf(`{"name":"event","type":"function","args":[{"name":"inner","type":"function","args":[%s]}]}`, arguments)
	}

	t.Run("value fault", func(t *testing.T) {
		t.Parallel()
		// The value fault is found while decoding, before the invalid
		// integer in the first argument is converted.
		input := nested(`{"type":"constant","const_kind":"int","value":"01"},{"type":"constant","value":true}`)
		var function term.Function
		err := json.Unmarshal([]byte(input), &function)
		if err == nil || err.Error() != "failed to unmarshal JSON: unsupported JSON value type" {
			t.Fatalf("Unmarshal error = %v", err)
		}
	})

	t.Run("type fault", func(t *testing.T) {
		t.Parallel()
		var function term.Function
		err := json.Unmarshal([]byte(nested(`{"name":5}`)), &function)
		var typeErr *json.UnmarshalTypeError
		if !errors.As(err, &typeErr) || typeErr.Field != "args.args.name" {
			t.Fatalf("Unmarshal error = %v, want a type error at args.args.name", err)
		}
		if !strings.HasPrefix(err.Error(), "failed to unmarshal JSON: ") {
			t.Fatalf("Unmarshal error = %q, want the unmarshal prefix", err)
		}
	})

	t.Run("conversion fault", func(t *testing.T) {
		t.Parallel()
		input := nested(`{"type":"constant","const_kind":"int","value":"1"},{"type":"constant","const_kind":"int","value":"01"}`)
		var function term.Function
		err := json.Unmarshal([]byte(input), &function)
		if err == nil || !strings.HasPrefix(err.Error(), `argument 0: argument 1: invalid typed integer "01": `) {
			t.Fatalf("Unmarshal error = %v", err)
		}
	})
}

func TestLegacyConstantJSONCompatibility(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		argument string
		want     term.Term
		// nilBytes requires nil bytes, which re-encode as null; Equal does
		// not tell them from empty bytes.
		nilBytes bool
	}{
		{"integer", `{"type":"constant","value":9223372036854775807}`, term.NewConstant[int64](math.MaxInt64), false},
		{"numeric string", `{"type":"constant","value":"123"}`, term.NewConstant("123"), false},
		{"bytes", `{"type":"constant","value":"0x01AB"}`, term.NewConstant([]byte{0x01, 0xab}), false},
		{"odd hex string", `{"type":"constant","value":"0x0"}`, term.NewConstant("0x0"), false},
		{"nil", `{"type":"constant","value":null}`, term.NewConstant[[]byte](nil), true},
		{"missing", `{"type":"constant"}`, term.NewConstant[[]byte](nil), true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got, err := decodeJSONArgument(test.argument)
			if err != nil || !got.Equal(test.want) {
				t.Fatalf("decode = %v, %v; want %v", got, err, test.want)
			}
			encoded, err := json.Marshal(got)
			if err != nil || !bytes.Contains(encoded, []byte(`"const_kind"`)) {
				t.Fatalf("canonical re-encoding = %s, %v", encoded, err)
			}
			if test.nilBytes {
				constant, err := term.AsConstant[[]byte](got)
				if err != nil || constant.Value != nil || !bytes.Contains(encoded, []byte(`"value":null`)) {
					t.Fatalf("decoded %v, re-encoded %s; want nil bytes encoded as null", got, encoded)
				}
			}
		})
	}
}

func BenchmarkFunctionJSONDecode(b *testing.B) {
	input := []byte(`{"name":"event","type":"function","args":[
  {"type":"constant","const_kind":"int","value":"1"},
  {"type":"constant","const_kind":"string","value":"two"},
  {"type":"constant","const_kind":"bytes","value":"0x0304"},
  {"name":"nested","type":"function","args":[
    {"type":"constant","const_kind":"int","value":"5"},
    {"type":"constant","const_kind":"string","value":"six"},
    {"type":"constant","const_kind":"bytes","value":"0x0708"}
  ]},
  {"type":"constant","const_kind":"int","value":"9"},
  {"type":"constant","const_kind":"string","value":"ten"},
  {"type":"constant","const_kind":"bytes","value":"0x0b0c"},
  {"name":"tail","type":"function","args":[{"type":"constant","const_kind":"int","value":"13"}]}
]}`)

	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		var function term.Function
		if err := json.Unmarshal(input, &function); err != nil {
			b.Fatalf("Unmarshal: %v", err)
		}
	}
}
