---
title: Event Format
description: Structure and format of events in SpecMon's monitoring pipeline
---

SpecMon monitors applications by processing streams of events. This page describes the structure of events and how to provide them to SpecMon.

## Event structure

Events are JSON objects with a timestamp and event data:

```json
{
  "time": 1700000000000000000,
  "event": {
    "name": "function_name",
    "type": "function",
    "args": [...]
  }
}
```

### Fields

| Field | Type | Description |
|-------|------|-------------|
| `time` | integer | Timestamp in nanoseconds (Unix epoch) |
| `event` | object | The event data |
| `event.name` | string | Name of the operation |
| `event.type` | string | Always `"function"` |
| `event.args` | array | Arguments to the operation |

## Argument types

Arguments can be constants or nested function calls:

### Constants

Every constant emitted by SpecMon carries a `const_kind` that fixes its value
type. Integers use a canonical decimal string so values across the full signed
64 bit range remain exact:

```json
{
  "type": "constant",
  "const_kind": "int",
  "value": "9007199254740993"
}
```

Strings retain their literal value; invalid UTF-8 is replaced by U+FFFD, both
when a string is decoded and when it is written:

```json
{
  "type": "constant",
  "const_kind": "string",
  "value": "9007199254740993"
}
```

Bytes use a lowercase `0x` prefix and hexadecimal output:

```json
{
  "type": "constant",
  "const_kind": "bytes",
  "value": "0x1234abcd"
}
```

Empty bytes use `"0x"`. Nil bytes use an explicit JSON `null`, which is
distinct from an empty byte string in the encoding; when terms are compared,
nil and empty bytes are equal.

Typed integer input accepts either the canonical decimal string or a bare JSON
integer with the same canonical spelling. Fractions, exponents, leading zeroes,
`-0`, and values outside the signed 64 bit range are rejected. Typed byte input
requires a lowercase `0x` prefix and an even number of hexadecimal digits. The
digits may use either case on input and are lowercase on output.

### Legacy input

Input without `const_kind` remains accepted where its meaning is unambiguous.
Bare JSON integers are decoded exactly; numbers with a fraction or an exponent
are rejected. Strings remain strings unless they have
a lowercase `0x` prefix followed by an even number of valid hexadecimal digits.
A missing or null legacy value means nil bytes. A numeric string remains a
string and is never inferred to be an integer.

SpecMon always emits the typed representation. This includes JSON output from
`specmon rewrite` and the structured event in a violation hook payload.

### Functions

Nested function calls with their own arguments:

```json
{
  "name": "hash",
  "type": "function",
  "args": [
    {"type": "constant", "const_kind": "bytes", "value": "0x6d657373616765"}
  ]
}
```

A function without arguments may be written with `"args": []`, with
`"args": null` or without `args`; all three decode to the same term. On output,
a function decoded from JSON has `"args": []`, whichever form its input had,
and one that a rule built has `"args": null`.

## Common event patterns

### Function call with return value

Most events represent a function call paired with its return value using the `pair` wrapper:

```json
{
  "time": 1700000000000000000,
  "event": {
    "name": "pair",
    "type": "function",
    "args": [
      {
        "name": "hash",
        "type": "function",
        "args": [
          {"type": "constant", "const_kind": "bytes", "value": "0x68656c6c6f"}
        ]
      },
      {"type": "constant", "const_kind": "bytes", "value": "0x2cf24dba"}
    ]
  }
}
```

This represents a hash call with a byte result.

The `pair` structure is: `<function_call, return_value>`

## Input sources

SpecMon accepts events from multiple sources:

### File input

```bash
specmon monitor protocol.spthy --in events.json
```

Or via stdin:
```bash
cat events.json | specmon monitor protocol.spthy --in -
```

Here `--in -` is optional.

### TCP socket

```bash
specmon monitor protocol.spthy --in localhost:8080
```

SpecMon listens on the socket and the application connects to send events.

## Pre-trace events

Load initial state before processing live events:

```bash
specmon monitor protocol.spthy --pre-trace setup.json --in live-events.json
```

Pre-trace events establish facts (like long-term keys) before monitoring begins.

## Requirements

1. **Use line-delimited JSON**: One JSON object per line (lines starting with `//` are ignored)
2. **Declare constant kinds**: Use `int`, `string`, or `bytes` in `const_kind`
3. **Use hex encoding for bytes**: Prefix byte values with lowercase `0x`
4. **Pair function calls with results**: Use the `pair` wrapper consistently
5. **Include timestamps**: Allow per-event timing analysis
6. **Match specification names**: Event function names should match rule triggers

## Debugging events

### Validate format

Check that events are valid JSON:
```bash
cat events.json | jq .
```

### Inspect with verbose mode

```bash
specmon monitor --verbose protocol.spthy < events.json
```

This shows each event as it's processed and which rules fire.

### Common issues

**Events not matching rules:**
- Check function names match specification
- Verify argument order and types
- Ensure `pair` wrapper is present for function calls with results

**Timestamp issues:**
- Use nanoseconds precision
- Check for clock skew in distributed systems

**Encoding problems:**
- Include `const_kind` in generated events
- Use a lowercase `0x` prefix and an even number of hexadecimal digits for bytes
- Keep integer values inside the signed 64 bit range

## Next steps

- [**Using go-annotate**](/instrumentation/go-annotate/) — Automatic Go instrumentation
- [**Using Frida**](/instrumentation/frida/) — Dynamic instrumentation
- [**CLI Commands**](/reference/cli/) — Monitor command options
