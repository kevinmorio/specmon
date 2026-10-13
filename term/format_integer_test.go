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
	"math"
	"testing"

	"github.com/specmon/specmon/term"
)

func formatField(kind term.FormatType, value term.Term, width ...int64) *term.Function {
	args := []term.Term{value}
	if len(width) > 0 {
		args = append(args, term.NewConstant(width[0]))
	}
	return term.NewFunction(string(kind), args)
}

func encodeFormatField(field *term.Function, binding *term.Binding) ([]byte, error) {
	if binding == nil {
		binding = term.NewBinding()
	}
	return term.FormatToBytes([]*term.Function{field}, binding)
}

func TestFormatIntegerFieldWidths(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		value   int64
		width   []int64
		want    []byte
		wantErr bool
	}{
		{"zero width", 0, []int64{0}, []byte{}, false},
		{"zero width rejects one", 1, []int64{0}, nil, true},
		{"one byte zero", 0, []int64{1}, []byte{0x00}, false},
		{"one byte maximum", 1<<8 - 1, []int64{1}, []byte{0xff}, false},
		{"one byte overflow", 1 << 8, []int64{1}, nil, true},
		{"two byte maximum", 1<<16 - 1, []int64{2}, []byte{0xff, 0xff}, false},
		{"two byte overflow", 1 << 16, []int64{2}, nil, true},
		{"seven byte maximum", 1<<56 - 1, []int64{7}, bytes.Repeat([]byte{0xff}, 7), false},
		{"seven byte overflow", 1 << 56, []int64{7}, nil, true},
		{"eight byte maximum", math.MaxInt64, []int64{8}, []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f}, false},
		{"negative value", -1, []int64{8}, nil, true},
		{"width above eight", 0, []int64{9}, nil, true},
		{"default width", 0x0201, nil, []byte{0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got, err := encodeFormatField(
				formatField(term.FormatIntType, term.NewConstant(test.value), test.width...),
				nil,
			)
			if test.wantErr {
				if err == nil {
					t.Fatalf("FormatToBytes returned %x", got)
				}
				return
			}
			if err != nil || !bytes.Equal(got, test.want) {
				t.Fatalf("FormatToBytes = %x, %v; want %x", got, err, test.want)
			}
			value := term.NewVariable("value")
			binding, err := term.ParseFormat([]*term.Function{formatField(term.FormatIntType, value, int64(len(got)))}, got)
			if err != nil {
				t.Fatalf("ParseFormat(%x): %v", got, err)
			}
			if parsed, ok := binding.Get(value); !ok || !parsed.Equal(term.NewConstant(test.value)) {
				t.Fatalf("ParseFormat(%x) = %v, want %d", got, parsed, test.value)
			}
		})
	}
	field := []*term.Function{formatField(term.FormatIntType, term.NewVariable("value"), 8)}
	if _, err := term.ParseFormat(field, []byte{0, 0, 0, 0, 0, 0, 0, 0x80}); err == nil {
		t.Fatal("ParseFormat accepted a value above MaxInt64")
	}
}

func TestFormatIntegerFieldBindingsAndNarrowing(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name    string
		value   []byte
		want    []byte
		wantErr bool
	}{
		{"accepted eight to two", []byte{0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, []byte{0x01, 0x02}, false},
		{"rejected eight to two", []byte{0x01, 0x02, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00}, nil, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got, err := encodeFormatField(formatField(term.FormatIntType, term.NewConstant(test.value), 2), nil)
			if test.wantErr {
				if err == nil {
					t.Fatalf("FormatToBytes returned %x", got)
				}
				return
			}
			if err != nil || !bytes.Equal(got, test.want) {
				t.Fatalf("FormatToBytes = %x, %v; want %x", got, err, test.want)
			}
		})
	}

	raw := formatField(term.FormatByteType, term.NewConstant([]byte{0x01, 0x02, 0x00}), 2)
	if got, err := encodeFormatField(raw, nil); err == nil {
		t.Fatalf("raw byte field narrowed to %x", got)
	}
}

func TestFormatIntegerParseConstructRoundTrip(t *testing.T) {
	t.Parallel()

	l := term.NewVariable("l")
	s := term.NewVariable("s")
	fields := []*term.Function{
		formatField(term.FormatIntType, l, 2),
		formatField(term.FormatIntType, s, 2),
	}
	input := []byte{0x01, 0x02, 0x03, 0x04}
	binding, err := term.ParseFormat(fields, input)
	if err != nil {
		t.Fatalf("ParseFormat: %v", err)
	}
	got, err := term.FormatToBytes(fields, binding)
	if err != nil || !bytes.Equal(got, input) {
		t.Fatalf("FormatToBytes = %x, %v; want %x", got, err, input)
	}

	parsed, err := term.ParseFormat([]*term.Function{formatField(term.FormatIntType, l, 2)}, []byte{0xff, 0x00})
	if err != nil {
		t.Fatalf("ParseFormat rejected narrowing source: %v", err)
	}
	narrowed, err := encodeFormatField(formatField(term.FormatIntType, l, 1), parsed)
	if err != nil || !bytes.Equal(narrowed, []byte{0xff}) {
		t.Fatalf("accepted narrowing = %x, %v", narrowed, err)
	}

	parsed, err = term.ParseFormat([]*term.Function{formatField(term.FormatIntType, l, 2)}, []byte{0x00, 0x01})
	if err != nil {
		t.Fatalf("ParseFormat rejected narrowing source: %v", err)
	}
	if got, err := encodeFormatField(formatField(term.FormatIntType, l, 1), parsed); err == nil {
		t.Fatalf("rejected narrowing encoded as %x", got)
	}
}

// TestFormatIntegerFieldWithoutWidth checks that an int field without a
// width takes eight bytes wherever it is, so that constructing the parsed
// binding gives the input back.
func TestFormatIntegerFieldWithoutWidth(t *testing.T) {
	t.Parallel()

	x := term.NewVariable("x")
	a := term.NewVariable("a")
	prefixed := []*term.Function{formatField(term.FormatByteType, x, 2), formatField(term.FormatIntType, a)}
	tests := []struct {
		name    string
		fields  []*term.Function
		input   []byte
		want    int64
		wantErr bool
	}{
		{"eight remaining bytes", prefixed, []byte{1, 2, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f}, math.MaxInt64, false},
		{"one remaining byte", prefixed, []byte{1, 2, 3}, 0, true},
		{"seven remaining bytes", prefixed, append([]byte{1, 2}, make([]byte, 7)...), 0, true},
		{"nine remaining bytes", prefixed, append([]byte{1, 2}, make([]byte, 9)...), 0, true},
		{"no remaining byte", prefixed, []byte{1, 2}, 0, true},
		{
			"byte variable without width before the last field",
			[]*term.Function{formatField(term.FormatByteType, x), formatField(term.FormatIntType, a)},
			make([]byte, 10), 0, true,
		},
		{
			"variable before the last field",
			[]*term.Function{formatField(term.FormatIntType, a), formatField(term.FormatByteType, x)},
			[]byte{7, 0, 0, 0, 0, 0, 0, 0, 1, 2},
			7, false,
		},
		{
			"known value before the last field",
			[]*term.Function{formatField(term.FormatIntType, term.NewConstant[int64](5)), formatField(term.FormatIntType, a)},
			[]byte{5, 0, 0, 0, 0, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0},
			7, false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			binding, err := term.ParseFormat(test.fields, test.input)
			if test.wantErr {
				if err == nil {
					t.Fatalf("ParseFormat = %v, want an error", binding)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseFormat: %v", err)
			}
			value, ok := binding.Get(a)
			if got, err := term.AsInt(value); !ok || err != nil || got != test.want {
				t.Fatalf("a = %v, want %d", value, test.want)
			}
			if encoded, err := term.FormatToBytes(test.fields, binding); err != nil || !bytes.Equal(encoded, test.input) {
				t.Fatalf("FormatToBytes = %x, %v; want the input %x", encoded, err, test.input)
			}
		})
	}
}
