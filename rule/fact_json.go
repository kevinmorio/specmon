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
	"fmt"

	"github.com/specmon/specmon/term"
)

type weakFact struct {
	Name string          `json:"name"`
	Args []term.WeakTerm `json:"arguments,omitempty"`
	Type FactType        `json:"type"`
}

// UnmarshalJSON reconstructs interface-typed fact arguments using term.WeakTerm dispatch.
func (f *Fact) UnmarshalJSON(data []byte) error {
	var wf weakFact
	if err := json.Unmarshal(data, &wf); err != nil {
		return fmt.Errorf("cannot unmarshal fact: %w", err)
	}

	args := make([]term.Term, len(wf.Args))
	for i, a := range wf.Args {
		t, err := term.FromWeakTerm(a)
		if err != nil {
			return fmt.Errorf("cannot decode fact argument %d: %w", i, err)
		}
		args[i] = t
	}

	f.Name = wf.Name
	f.Args = args
	f.Type = wf.Type

	return nil
}
