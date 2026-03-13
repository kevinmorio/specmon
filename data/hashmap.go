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

package data

import (
	"fmt"
	"hash"
	"hash/fnv"
	"reflect"
	"sort"
	"strings"
)

type Hasher interface {
	Hash() uint64
}

type HashMap[K, V any] struct {
	m map[uint64][]Entry[K, V]
	h hash.Hash64
}

type Entry[K, V any] struct {
	Key   K
	Value V
}

func NewHashMap[K, V any]() *HashMap[K, V] {
	return &HashMap[K, V]{
		m: make(map[uint64][]Entry[K, V]),
		h: fnv.New64a(),
	}
}

func (h *HashMap[K, V]) hash(k K) uint64 {
	var b []byte

	switch t := any(k).(type) {
	case Hasher:
		return t.Hash()
	case fmt.Stringer:
		b = []byte(t.String())
	default:
		b = []byte(fmt.Sprintf("%v", k))
	}

	h.h.Reset()
	h.h.Write(b)

	return h.h.Sum64()
}

func (h *HashMap[K, V]) Get(k K) (V, bool) {
	entries, ok := h.m[h.hash(k)]
	if !ok {
		var zero V
		return zero, false
	}

	for _, entry := range entries {
		if hashMapKeysEqual(entry.Key, k) {
			return entry.Value, true
		}
	}

	var zero V
	return zero, false
}

func (h *HashMap[K, V]) Set(k K, v V) {
	hash := h.hash(k)
	entries := h.m[hash]
	for i, entry := range entries {
		if hashMapKeysEqual(entry.Key, k) {
			entries[i] = Entry[K, V]{k, v}
			h.m[hash] = entries
			return
		}
	}

	h.m[hash] = append(entries, Entry[K, V]{k, v})
}

func (h *HashMap[K, V]) Remove(k K) {
	hash := h.hash(k)
	entries, ok := h.m[hash]
	if !ok {
		return
	}

	for i, entry := range entries {
		if hashMapKeysEqual(entry.Key, k) {
			entries = append(entries[:i], entries[i+1:]...)
			if len(entries) == 0 {
				delete(h.m, hash)
			} else {
				h.m[hash] = entries
			}
			return
		}
	}
}

func (h *HashMap[K, V]) Empty() bool {
	return h.Size() == 0
}

func (h *HashMap[K, V]) Keys() []K {
	keys := make([]K, 0, h.Size())

	for _, entries := range h.m {
		for _, entry := range entries {
			keys = append(keys, entry.Key)
		}
	}

	return keys
}

func (h *HashMap[K, V]) Values() []V {
	values := make([]V, 0, h.Size())

	for _, entries := range h.m {
		for _, entry := range entries {
			values = append(values, entry.Value)
		}
	}

	return values
}

func (h *HashMap[K, V]) Size() int {
	size := 0
	for _, entries := range h.m {
		size += len(entries)
	}

	return size
}

func (h *HashMap[K, V]) String() string {
	s := "HashMap["

	for _, entries := range h.m {
		for _, entry := range entries {
			s += fmt.Sprintf("%v", entry.Key)
			s += ":"
			s += fmt.Sprintf("%v", entry.Value)
			s += " "
		}
	}
	s = strings.TrimSuffix(s, " ")

	return s + "]"
}

func (h *HashMap[K, V]) Iterate(f func(K, V) bool) {
	for _, entries := range h.m {
		for _, entry := range entries {
			if !f(entry.Key, entry.Value) {
				return
			}
		}
	}
}

func (h *HashMap[K, V]) IterateSorted(f func(K, V) bool) {
	keys := make([]uint64, 0, len(h.m))

	for k := range h.m {
		keys = append(keys, k)
	}

	sort.Slice(keys, func(i, j int) bool {
		return keys[i] < keys[j]
	})

	for _, k := range keys {
		for _, entry := range h.m[k] {
			if !f(entry.Key, entry.Value) {
				return
			}
		}
	}
}

func (h *HashMap[K, V]) Clone() *HashMap[K, V] {
	c := &HashMap[K, V]{
		m: make(map[uint64][]Entry[K, V], len(h.m)),
	}

	for k, entries := range h.m {
		c.m[k] = append([]Entry[K, V](nil), entries...)
	}

	return c
}

func (h *HashMap[K, V]) Extend(hp *HashMap[K, V]) *HashMap[K, V] {
	u := h.Clone()

	for _, entries := range hp.m {
		for _, entry := range entries {
			u.Set(entry.Key, entry.Value)
		}
	}

	return u
}

func hashMapKeysEqual[K any](a, b K) bool {
	return reflect.DeepEqual(a, b)
}
