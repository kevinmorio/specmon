//go:build no_treesitter

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

package parser

import (
	"context"
	"errors"

	"github.com/specmon/specmon/rule"
)

var ErrParserNotAvailable = errors.New(
	"this build was compiled without the tree-sitter parser; " +
		"provide a compiled .json ruleset instead of a .spthy file",
)

func ParseFile(_ context.Context, _ string, _ []string) ([]*rule.Rule, error) {
	return nil, ErrParserNotAvailable
}
