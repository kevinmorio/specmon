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

package utils

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Indent indents a string by n spaces.
func Indent(s string, n int) string {
	var b strings.Builder
	for _, line := range strings.Split(s, "\n") {
		b.WriteString(strings.Repeat(" ", n))
		b.WriteString(line)
		b.WriteString("\n")
	}

	return b.String()
}

const NumberLinesIndent = 1

func NumberLines(s string, offset int) string {
	lines := strings.Split(s, "\n")
	first, last := offset, offset+len(lines)
	maxLen := max(len(strconv.Itoa(first)), len(strconv.Itoa(last)))

	var b strings.Builder
	for i, line := range lines {
		d := strconv.Itoa(offset + i + 1)
		indent := maxLen - len(d) + NumberLinesIndent
		b.WriteString(strings.Repeat(" ", indent))
		b.WriteString(d)
		b.WriteString(" │ ")
		b.WriteString(line)
		b.WriteString("\n")
	}

	return b.String()
}

// IsStdinConnected returns true if stdin is connected to a pipe or file.
func IsStdinConnected() bool {
	fi, _ := os.Stdin.Stat()

	return (fi.Mode() & os.ModeCharDevice) == 0
}

// Unique returns a slice with unique elements.
// The order of the elements is preserved.
func Unique[F fmt.Stringer](vals []F) []F {
	M := make(map[string]bool)
	var result []F

	for _, val := range vals {
		if _, ok := M[val.String()]; !ok {
			M[val.String()] = true
			result = append(result, val)
		}
	}

	return result
}

// BytesToInt converts a byte slice to an int using the specified byte order.
// An empty byte slice is converted to 0.
func BytesToInt(b []byte, order binary.ByteOrder) (int, error) {
	const encodedIntBytes = 8

	// SpecMon encodes integers as 8-byte values regardless of the target word size.
	if len(b) > encodedIntBytes {
		return 0, fmt.Errorf("byte slice too long to convert to int: %d", len(b))
	}

	// Ensure that the byte slice is padded to the encoded integer width.
	padded := PadWithByteOrder(b, order, encodedIntBytes)
	r := bytes.NewReader(padded)

	var value int64
	if err := binary.Read(r, order, &value); err != nil {
		return 0, fmt.Errorf("cannot convert bytes to int: %w", err)
	}

	converted := int(value)
	if int64(converted) != value {
		return 0, fmt.Errorf("cannot convert bytes to int: overflow")
	}

	return converted, nil
}

// IntToBytes converts an integer to a byte slice using the specified byte order.
func IntToBytes(i int, order binary.ByteOrder) []byte {
	var buf [8]byte
	// Convert the int to uint64 explicitly using int64 to handle negative values correctly.
	//nolint:gosec
	order.PutUint64(buf[:], uint64(int64(i)))

	return buf[:]
}

// PadWithByteOrder pads a byte slice to the right (little endian) or left (big endian) with zeros.
// If the byte slice is already longer than the specified length, it is returned as is.
func PadWithByteOrder(s []byte, order binary.ByteOrder, length int) []byte {
	if len(s) >= length {
		return s
	}

	padded := make([]byte, length)
	if order == binary.LittleEndian {
		copy(padded, s)
	} else {
		copy(padded[length-len(s):], s)
	}

	return padded
}

func Pluralize(s string, n int) string {
	if n == 1 {
		return s
	}

	return s + "s"
}

func MedianDuration(numbers []time.Duration) float64 {
	sort.Slice(numbers, func(i, j int) bool { return numbers[i] < numbers[j] })
	middle := len(numbers) / 2
	if len(numbers)%2 == 0 {
		return float64(numbers[middle-1]+numbers[middle]) / 2
	}

	return float64(numbers[middle])
}
