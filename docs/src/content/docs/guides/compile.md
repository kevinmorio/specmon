---
title: Compiling Rulesets
description: Compile .spthy specifications into portable JSON rulesets for deployment without the tree-sitter parser
---

SpecMon can pre-compile a `.spthy` specification into a self-contained JSON ruleset. The compiled file is portable, versioned, and can be loaded by `monitor` and `rewrite` without the tree-sitter parser — enabling lighter deployment targets such as static Linux binaries, WASM, or TinyGo environments.

## When to compile

Use compiled rulesets when:

- You want to separate the compile step from the monitoring runtime (e.g. in CI/CD).
- You are deploying to targets where CGO or tree-sitter is unavailable.
- You want to lock the ruleset to a specific role, define set, and decomposition state.
- You want fast startup: loading a compiled ruleset skips parsing entirely.

## Step 1: compile the specification

```bash
specmon compile --out protocol.ruleset.json protocol.spthy
```

The compiled file includes the processed rules and provenance metadata (source hash, role, defines, decompose flag). The recommended file extension is `.ruleset.json`.

Pass the same flags you would use at monitoring time:

```bash
# Compile for a specific role with a preprocessor define
specmon --role client --defines SPECMON compile --out client.ruleset.json protocol.spthy

# Compile without rule decomposition
specmon --decompose=false compile --out raw.ruleset.json protocol.spthy
```

Inspect the output to stdout (omit `--out`):

```bash
specmon compile protocol.spthy | head -40
```

## Step 2: use the compiled ruleset

Pass the `.ruleset.json` file anywhere a `.spthy` file is accepted. The format is detected automatically from the `.json` extension.

```bash
# Monitor with a compiled ruleset
specmon monitor --in events.json protocol.ruleset.json

# Rewrite with a compiled ruleset
specmon rewrite --json --in raw.json protocol.ruleset.json

# Explicit format override (useful when the extension is non-standard)
specmon --rules-format json monitor --in events.json protocol.rules
```

### Metadata validation

If the compiled ruleset contains `source` metadata, SpecMon checks that the `--role`, `--defines`, and `--decompose` flags match the values used at compile time. A mismatch fails with an actionable error:

```
compiled ruleset options mismatch: role="server" but ruleset was compiled with role="client"; recompile or adjust --role
```

Recompile the ruleset with matching flags, or adjust the flags passed to `monitor`/`rewrite`.

## Step 3: pipeline example

A typical CI/CD pipeline:

```bash
# 1. Compile once (build step)
specmon --role client --defines SPECMON \
  compile --out artifacts/client.ruleset.json src/protocol.spthy

# 2. Distribute the binary + ruleset to the target host

# 3. Monitor on the target (no .spthy file or parser needed)
specmon --role client monitor --in /var/log/events.json artifacts/client.ruleset.json
```

## Build variants

### Parser-free build (`no_treesitter`)

The default SpecMon binary includes the tree-sitter parser via CGO. To build without it — producing a pure-Go binary that can only load compiled rulesets — use the `no_treesitter` build tag:

```bash
go build -tags no_treesitter -o specmon-slim .
```

Attempting to pass a `.spthy` file to the slim binary returns a clear error:

```
this build was compiled without the tree-sitter parser; provide a compiled .json ruleset instead of a .spthy file
```

Compiled rulesets work as normal:

```bash
./specmon-slim monitor --in events.json protocol.ruleset.json
```

### Cross-compilation

#### Linux amd64 (static, musl)

Use [Zig](https://ziglang.org/) as the C cross-compiler for fully static musl binaries. This is the same toolchain used by the official GoReleaser workflow.

```bash
CC="zig cc -target x86_64-linux-musl" \
  CGO_ENABLED=1 GOOS=linux GOARCH=amd64 \
  go build -o specmon-linux-amd64 .
```

Parser-free variant (no CGO required, simpler cross-compilation):

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  go build -tags no_treesitter -o specmon-linux-amd64-slim .
```

#### Linux arm64 (static, musl)

```bash
CC="zig cc -target aarch64-linux-musl" \
  CGO_ENABLED=1 GOOS=linux GOARCH=arm64 \
  go build -o specmon-linux-arm64 .
```

Parser-free variant:

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 \
  go build -tags no_treesitter -o specmon-linux-arm64-slim .
```

#### macOS (native)

```bash
# Intel
GOOS=darwin GOARCH=amd64 go build -o specmon-darwin-amd64 .

# Apple Silicon
GOOS=darwin GOARCH=arm64 go build -o specmon-darwin-arm64 .
```

macOS builds use the system Clang and do not require Zig.

### Combining tags

Build a static Linux binary that only accepts compiled rulesets:

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  go build -tags no_treesitter -o specmon-linux-amd64-slim .
```

This binary has no CGO dependencies and loads only `.ruleset.json` files.

## Ruleset format

See [Ruleset Format](/reference/ruleset-format/) for the full JSON envelope specification, field descriptions, and version compatibility policy.
