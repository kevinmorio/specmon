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

package term

import "testing"

func TestEvaluatableFunctionsAreImplementedAndReserved(t *testing.T) {
	representatives := map[string]Term{
		CatFunctionName: NewFunction(CatFunctionName, []Term{
			NewFunction(string(FormatByteType), []Term{NewConstant([]byte{0x01})}),
		}),
		AddFunctionName: NewFunction(AddFunctionName, []Term{NewConstant[int64](1), NewConstant[int64](2)}),
		AndFunctionName: NewFunction(AndFunctionName, []Term{NewConstant[int64](3), NewConstant[int64](1)}),
		OrFunctionName:  NewFunction(OrFunctionName, []Term{NewConstant[int64](2), NewConstant[int64](1)}),
		XorFunctionName: NewFunction(XorFunctionName, []Term{NewConstant[int64](3), NewConstant[int64](1)}),
		NotFunctionName: NewFunction(NotFunctionName, []Term{NewConstant[int64](0)}),
		SliceFunctionName: NewFunction(SliceFunctionName, []Term{
			NewConstant([]byte{0x01, 0x02}),
			NewConstant[int64](0),
			NewConstant[int64](0),
		}),
		ReverseFuncName: NewFunction(ReverseFuncName, []Term{NewConstant([]byte{0x01, 0x02})}),
	}

	if len(representatives) != len(evaluatableFunctions) {
		t.Fatalf("representative count = %d, evaluatable function count = %d", len(representatives), len(evaluatableFunctions))
	}
	for name := range evaluatableFunctions {
		representative, ok := representatives[name]
		if !ok {
			t.Errorf("evaluatable function %q has no ground representative", name)
			continue
		}
		if !ReservedNames.Contains(name) {
			t.Errorf("evaluatable function %q is not reserved", name)
		}
		got, err := Evaluate(representative)
		if err != nil {
			t.Errorf("Evaluate representative for %q: %v", name, err)
			continue
		}
		if got.GetType() != ConstantType {
			t.Errorf("Evaluate representative for %q returned %s, want constant", name, got)
		}
	}
}
