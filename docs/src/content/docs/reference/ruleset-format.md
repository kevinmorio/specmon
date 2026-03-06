---
title: Ruleset Format
description: JSON envelope specification for compiled SpecMon rulesets
---

A compiled ruleset is a versioned JSON file produced by `specmon compile`. It encapsulates all processed rules and provenance metadata in a self-contained artifact that can be loaded without the tree-sitter parser.

## Envelope structure

```json
{
  "$schema": "https://specmon.github.io/specmon/schema/ruleset-v1.schema.json",
  "format": "specmon-ruleset",
  "format_version": "1.0.0",
  "generator": "specmon/0.2.0",
  "source": {
    "hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "role": "client",
    "defines": ["SPECMON"],
    "decompose": true
  },
  "rules": [
    {
      "name": "Client_Init",
      "lhs": [],
      "act": [],
      "rhs": [
        {
          "name": "ClientState",
          "arguments": [
            { "type": "variable", "name": "~id" }
          ],
          "type": "persistent"
        }
      ],
      "attributes": {
        "role": { "kind": "string", "string": "client" }
      }
    }
  ]
}
```

## Top-level fields

| Field | Type | Required | Description |
|---|---|---|---|
| `$schema` | string | no | URL of the JSON Schema document for IDE support |
| `format` | string | **yes** | Fixed identifier: `"specmon-ruleset"` |
| `format_version` | string | **yes** | Schema version string, e.g. `"1.0.0"` |
| `generator` | string | no | Tool and version that produced the file, e.g. `"specmon/0.2.0"` |
| `source` | object | no | Provenance metadata recorded at compile time |
| `rules` | array | **yes** | Compiled rule objects (may be empty) |

## Source provenance fields

The `source` object is written by `specmon compile` and validated when the ruleset is loaded. If `source` is absent, no validation is performed.

| Field | Type | Description |
|---|---|---|
| `hash` | string | SHA-256 hex digest of the original `.spthy` file bytes |
| `role` | string | Value of `--role` at compile time (empty string if not set) |
| `defines` | string array | Values of `--defines` at compile time |
| `decompose` | boolean | Value of `--decompose` at compile time |

When loading a compiled ruleset with `monitor` or `rewrite`, SpecMon checks that the current `--role`, `--defines`, and `--decompose` flags match the recorded values. A mismatch is a hard error:

```
compiled ruleset options mismatch: role="server" but ruleset was compiled with role="client"; recompile or adjust --role
```

## Rule objects

Each entry in `rules` has the following fields:

| Field | Type | Description |
|---|---|---|
| `name` | string | Rule name |
| `lhs` | fact array | Left-hand side (consumed facts) |
| `act` | fact array | Action facts (labels) |
| `rhs` | fact array | Right-hand side (produced facts) |
| `attributes` | object | Optional map of rule attributes (role, trigger, hints) |

### Fact objects

| Field | Type | Description |
|---|---|---|
| `name` | string | Fact name |
| `arguments` | term array | List of term arguments |
| `type` | string | `"linear"` or `"persistent"` |

### Term objects

Terms use a tagged representation with a `type` discriminator:

**Constant:**
```json
{ "type": "constant", "const_kind": "int",    "value": 42 }
{ "type": "constant", "const_kind": "string", "value": "hello" }
{ "type": "constant", "const_kind": "bytes",  "value": "0xdeadbeef" }
```

The `const_kind` field disambiguates the Go type of the constant. Byte arrays are encoded as lowercase hex strings prefixed with `0x`.

**Variable:**
```json
{ "type": "variable", "name": "~x" }
```

**Function:**
```json
{
  "type": "function",
  "name": "pair",
  "args": [
    { "type": "variable", "name": "x" },
    { "type": "constant", "const_kind": "string", "value": "ok" }
  ]
}
```

### Attribute objects

Rule attributes use a tagged union with a `kind` field:

**String attribute** (e.g. `role`):
```json
{ "kind": "string", "string": "client" }
```

**Term attribute** (e.g. `trigger`, `hints`):
```json
{
  "kind": "terms",
  "terms": [
    { "type": "function", "name": "trigger", "args": [...] }
  ]
}
```

## Version compatibility

The supported format version is `1.0.0`. If a ruleset declares a different `format_version`, loading fails immediately:

```
unsupported ruleset format version "2.0.0" (this binary supports "1.0.0")
```

Recompile the ruleset with the current version of `specmon compile` to resolve the error. There is no silent fallback or partial parsing.

## JSON Schema

A JSON Schema Draft 2020-12 document is published at:

```
https://specmon.github.io/specmon/schema/ruleset-v1.schema.json
```

Add it as the `$schema` key in your ruleset for IDE autocompletion. `specmon compile` sets this field automatically.

The schema is documentation only — no JSON Schema library is used at runtime. Validation is performed by explicit Go checks in the loader.
