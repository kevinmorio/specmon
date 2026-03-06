# Plan: Compiled Ruleset Format and Unified Rule Loading

## Goals

1. Remove the runtime dependency on tree-sitter for deployment targets like WASM/TinyGo.
2. Add a clean way to turn `.spthy` specifications into a JSON ruleset artifact.
3. Keep end-user UX simple with one integrated CLI (no git-style external command discovery).
4. Allow SpecMon to load rules automatically by file extension:
   - `.spthy` -> parse via tree-sitter
   - `.json` (recommended: `.ruleset.json`) -> deserialize compiled ruleset
5. Enable optional parser-free build variants.

## Agreed Product Decisions

1. Use an integrated command model (`specmon <subcommand>`), not `specmon-*` plugin discovery.
2. Introduce a built-in compiler command (`specmon compile`) to emit JSON rulesets.
3. Auto-select loader from file extension, with an explicit override flag:
   - `--rules-format auto|spthy|json`
4. In parser-free builds, `.spthy` inputs fail with a clear error explaining that only compiled rulesets are supported.
5. Do not invent a custom schema language; use standard JSON Schema for documentation only (no runtime library dependency).
6. Workstream 5 (embedded static ruleset via `embedded_ruleset` build tag) was deferred and not implemented.

## Format Strategy (Versioned and Safe)

### Envelope

Versioned JSON envelope with explicit metadata:

- `$schema`: optional URL to the hosted JSON Schema for IDE autocompletion
- `format`: fixed identifier (`specmon-ruleset`)
- `format_version`: schema version (starting with `1.0.0`)
- `generator`: tool/version info (e.g. `specmon/0.2.0`)
- `source`: optional provenance (input hash, role, defines, decompose flags)
- `rules`: compiled rules payload

### Version mismatch policy

When loading a `.json` ruleset, if `format_version` does not match the supported version, fail immediately:

```
unsupported ruleset format version "2.0.0" (this binary supports "1.0.0")
```

No silent fallback or partial parsing.

### Schema Definition

The JSON Schema Draft 2020-12 document is referenced at
`https://specmon.github.io/specmon/schema/ruleset-v1.schema.json` and added as `$schema`
in compiled rulesets. No JSON Schema library is used at runtime; validation is done by
explicit Go checks.

The schema file itself (`docs/public/schema/ruleset-v1.schema.json`) was not created as
part of this implementation and remains a future task.

## Serialization Design

### Terms and `WeakTerm` refactoring

The existing `WeakTerm` struct is used as the term DTO. The implementation introduced
two exported package-level functions in `term/term.go`:

- `ToWeakTerm(Term) (WeakTerm, error)` — converts a concrete term to its serializable form.
- `FromWeakTerm(WeakTerm) (Term, error)` — reconstructs a concrete term from its weak form.

`FromWeakTerm` is self-recursive for function arguments and is the single entry point for
the serialization layer in `rule/`. This required removing `fromWeakTerm` from the `Term`
interface and deleting the three concrete implementations (`Constant[T]`, `Variable`,
`Function`), which had become dead or circular:

- `Constant[T].fromWeakTerm` was never called by `FromWeakTerm` (which dispatched to
  `fromWeakConstant` instead) and existed only to satisfy the interface.
- `Function.fromWeakTerm` called `FromWeakTerm` for each argument, creating circular
  mutual delegation with no benefit.
- `Variable.fromWeakTerm` was a two-line helper only called from `FromWeakTerm` itself.

With the interface method removed, `FromWeakTerm` is self-contained: variables are built
inline, functions recurse back into `FromWeakTerm` for sub-terms, and constants are
dispatched to `fromWeakConstant`. `Function.UnmarshalJSON` was updated to call
`FromWeakTerm` + `AsFunction` instead of the deleted method.

`WeakTerm` gained a `const_kind` field (`"int"`, `"string"`, `"bytes"`) for unambiguous
constant round-tripping. Without it the old heuristic (checking for `"0x"` prefixes on
strings) was fragile. The backward-compatible decode path for older payloads without
`const_kind` is preserved in `fromWeakConstant`.

### Attributes

`Rule.Attrs` is `map[string]Attribute` where `Attribute` is an interface.
`encoding/json` cannot round-trip interface values without type information. An unexported
tagged-union DTO is used:

```go
type attributeDTO struct {
    Kind   string          `json:"kind"`             // "string" | "terms"
    String string          `json:"string,omitempty"`
    Terms  []term.WeakTerm `json:"terms,omitempty"`
}
```

Serialization converts each `Attribute` to `attributeDTO`; deserialization switches on
`Kind` to reconstruct `StringAttribute` or `TermAttribute`.

### Replacing `rule.ReadRules`

`rule.ReadRules` used `log.Panic` for errors and loaded a bare `[]Rule` with no envelope.
It was removed; `UnmarshalRuleset` replaces its role for all call sites.

## Implementation

### Files changed

| File | Change |
|---|---|
| `term/term.go` | Added `ToWeakTerm`, `FromWeakTerm`, `fromWeakConstant`, `weakInt`; added `ConstKind` field and `ConstantIntKind`/`ConstantStringKind`/`ConstantBytesKind` constants to `WeakTerm`; removed `fromWeakTerm` from `Term` interface and deleted all three concrete implementations; updated `Function.UnmarshalJSON` |
| `rule/serialize.go` | New: `RulesetMeta`, `RulesetSource`, envelope + DTO types, `MarshalRuleset`, `UnmarshalRuleset`, `validateEnvelope`, depth validation |
| `rule/fact_json.go` | New: `Fact.UnmarshalJSON` using `WeakTerm` dispatch for `Args` |
| `rule/serialize_test.go` | New: round-trip, version-mismatch, unknown-field, and `Fact.UnmarshalJSON` tests |
| `rule/rules.go` | Removed `ReadRules` and its now-unused imports |
| `rule/translation_integration_test.go` | Guarded with `//go:build !no_treesitter` |
| `cmd/compile.go` | New: `specmon compile` command |
| `cmd/shared.go` | Added `LoadRules` (auto/spthy/json dispatch), `validateRulesetOptions`, `equalStringSets`; kept `ProcessRules` as internal helper |
| `cmd/root.go` | Added `RulesFormat` field to `RootConfig`; updated `RunE` to call `LoadRules`; registered `NewCompileCmd` |
| `cmd/monitor.go` | Reads `--rules-format` flag; calls `LoadRules` instead of `ProcessRules` |
| `cmd/rewrite.go` | Same as `monitor.go` |
| `parser/parser.go` | Guarded with `//go:build !no_treesitter` |
| `parser/preprocessor.go` | Guarded with `//go:build !no_treesitter` |
| `parser/stub_no_treesitter.go` | New: `ParseFile` stub returning `ErrParserNotAvailable` |
| `flake.nix` | Added `pkgs.tinygo` to dev shell; normalized `buildInputs` indentation to spaces |

### Key implementation details

**`MarshalRuleset`** does not call `validateEnvelope` on its own output — the envelope is
built from hardcoded constants so it is always valid. `validateEnvelope` is only called in
`UnmarshalRuleset`.

**`UnmarshalRuleset`** uses `json.NewDecoder` with `DisallowUnknownFields()` and checks for
trailing data after the first decode. After decoding, `validateEnvelope` runs before any
rule deserialization. A separate `validateRulesetTerms` pass enforces nesting depth limits
(`MaxRulesetTermDepth = 256`) and rule count limits (`MaxRulesetRules = 100_000`).

**`LoadRules`** returns `(rules, rules, rules)` for the JSON path — the compiled file is
expected to already contain the decomposed rules (recorded at compile time). The three
return slots are kept for API compatibility with `ProcessRules`.

**`validateRulesetOptions`** checks `--role`, `--defines`, and `--decompose` against
`source` metadata when present. Returns `nil` if `source` is absent, so rulesets compiled
without provenance load without restriction.

**`equalStringSets`** sorts copies of both slices and compares with `slices.Equal`.

**`compile.go`** reads the spec file twice: once via `LoadRules` to obtain the processed
rules, and once with `os.ReadFile` to compute the SHA-256 hash. This duplication is
unavoidable without refactoring `ProcessRules` to expose the file bytes.

**`flake.nix`**: `pkgs.tinygo` was added to the dev shell to support `no_treesitter` /
TinyGo build workflows locally.

## Documentation

### Pages added

- `docs/src/content/docs/guides/compile.md` — step-by-step guide: compiling, loading
  compiled rulesets, CI/CD pipeline example, `no_treesitter` build, cross-compilation
  (Linux amd64/arm64 with Zig/musl, macOS native, CGO-free slim variants).
- `docs/src/content/docs/reference/ruleset-format.md` — envelope field tables, term/fact/
  attribute JSON shapes, `const_kind` encoding, version mismatch policy, schema URL.

### Pages updated

- `docs/src/content/docs/reference/cli.md` — added `compile` command section with flags
  and examples; added `--rules-format` to global flags; updated all `<spec-path>`
  descriptions to mention `.ruleset.json`; added compiled-ruleset example to `monitor`.
- `docs/src/content/docs/getting-started/installation.md` — updated the help-text example
  to reflect the current output (`compile`, `rewrite`, `--defines`, `--rules-format`).
- `docs/astro.config.mjs` — added "Guides" sidebar group with `guides/compile`; added
  "Ruleset Format" to the "Reference" group; fixed inconsistent tab indentation in the
  Reference items block.

### Not done

- `docs/public/schema/ruleset-v1.schema.json` — the canonical JSON Schema file was not
  created. The URL is referenced in the docs and emitted in compiled rulesets, but the
  file itself is a future task.

## Acceptance Criteria

1. ✅ Users can run `monitor` and `rewrite` with either `.spthy` or compiled `.json` rulesets.
2. ✅ Parser-free build (`no_treesitter`) works end-to-end with compiled rulesets.
3. ✅ `.spthy` in a parser-free build returns a clear actionable error message.
4. ✅ Format is versioned; version mismatches fail with a clear error — no silent parsing.
5. ✅ No external command auto-discovery mechanism is introduced.
6. ✅ `rule.ReadRules` is removed and replaced by the new loader.
7. ✅ All new `.go` files carry the AGPL-3.0 license header.
8. ✅ New files live in `rule/`, `cmd/`, or `parser/`; no new top-level package is introduced.
