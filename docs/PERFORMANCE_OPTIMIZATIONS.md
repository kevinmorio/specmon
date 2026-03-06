# Performance Optimizations

This document summarizes the performance optimizations implemented for the term and binding subsystems, their measured impact, and lessons learned.

## Baseline

**Benchmark:** `signal-slow` with 300 events (head-300)

| Metric | Value |
|--------|-------|
| Runtime | 7.96s |
| Total allocations | 14.2GB |
| Main hotspot | `Binding.Set` at 52% of allocations |

---

## Optimization Summary

### Final Results

| Metric | Baseline | Final | Improvement |
|--------|----------|-------|-------------|
| **Runtime** | 7.96s | 5.59s | **-30%** |
| **Total allocations** | 14.2GB | 9.6GB | **-32%** |
| `Binding.Set` | 7.5GB | 4.3GB | **-43%** |
| `Binding.Clone` | 633MB | 0 | **-100%** |

---

## Phase 1: Correctness Fixes

### 1.1 Fix `data.HashMap` Collision Handling

**Problem:** `HashMap` used `map[uint64]Entry` which silently overwrote entries on hash collision, causing data loss.

**Solution:** Changed to `map[uint64][]Entry` with bucket chains, proper equality checking via `keysEqual()`.

**Impact:** Correctness fix (no performance change expected).

**Files:** `data/hashmap.go`, `data/hashset.go`

### 1.2 Fix `data.HashSet`

**Problem:** Inherited collision bug from `HashMap`.

**Solution:** Changed to use `*HashMap` pointer, added nil guards.

**Impact:** Correctness fix.

---

## Phase 2: Quick Wins

### 2.1 Singleton Empty Binding

**Problem:** `NewBinding()` allocated a new struct every time.

**Solution:** Return shared `emptyBinding` singleton with copy-on-write in `Set()`.

```go
var emptyBinding = &Binding{}

func NewBinding() *Binding {
    return emptyBinding
}

func (b *Binding) Set(k, v Term) *Binding {
    if b == emptyBinding {
        // Copy-on-write: create new binding
    }
    // ...
}
```

**Impact:** Reduced allocations for empty bindings.

### 2.2 Cache Variable Pointers in `Binding.Iterate`

**Problem:** In `varOnly` path, `Iterate()` called `NewVariable(name)` on each iteration, hitting the pool with mutex acquisition.

**Solution:** Store `*Variable` pointers in `bindingVar` struct.

```go
type bindingVar struct {
    key *Variable  // Cached pointer
    val Term
}
```

**Impact:** Reduced pool lock contention during iteration.

### 2.3 Cache `AsBytes` for String Constants

**Problem:** `AsBytes(*Constant[string])` converted `[]byte(c.Value)` on every call.

**Solution:** Added `cachedBytes []byte` field to `Constant`, populated on creation.

```go
type Constant[T ConstantConstraint] struct {
    Value       T
    cachedBytes []byte  // Cached for string constants
    // ...
}
```

**Impact:** ~0.8GB allocation reduction in `AsBytes`.

### 2.4 Pre-allocate in `Vars()` Functions

**Problem:** `Terms.Vars()` and `Facts.Vars()` used `append()` without pre-allocation.

**Solution:** Added `VarCount()` helper to estimate capacity, then pre-allocate.

```go
func (ts Terms) Vars() []*Variable {
    total := 0
    for _, t := range ts {
        total += countVars(t)
    }
    vars := make([]*Variable, 0, total)
    // ...
}
```

**Impact:** Reduced slice growth allocations.

---

## Phase 3: Medium Effort Optimizations

### 3.1 Replace `deepcopy` in `Rule.Clone()`

**Problem:** `deepcopy.MustAnything(r)` created new term/fact pointers, breaking interning invariants.

**Solution:** Manual clone with shallow slice copies that preserve interned pointers.

```go
func (r *Rule) Clone() *Rule {
    return &Rule{
        Name: r.Name,
        LHS:  append([]*Fact(nil), r.LHS...),
        Act:  append([]*Fact(nil), r.Act...),
        RHS:  append([]*Fact(nil), r.RHS...),
        Attrs: cloneAttrs(r.Attrs),
    }
}
```

**Impact:** Preserved interning, enabled pointer-based optimizations.

### 3.2 Trail-Based Backtracking in `conflictSet`

**Problem:** `dfs(pos+1, delta.Extend(b))` created new binding on every DFS recursion.

**Solution:** Use trail stack to record changes and unwind on backtrack.

```go
trail := term.NewBindingTrail()
// ...
mark := trail.Mark()
b = b.MergeWithTrail(delta, trail)
dfs(pos+1, b)
b = b.Unwind(trail, mark)
```

**Impact:** Significant reduction in binding allocations during conflict set computation.

### 3.3 Replace `HashSet[*Binding]` with `bindingSet`

**Problem:** `data.HashSet` had collision bug and allocated heavily.

**Solution:** Custom `bindingSet` with slice storage and hash-based deduplication.

```go
type bindingSet struct {
    bindings []*term.Binding
    seen     map[uint64][]int  // hash -> indices
}
```

**Impact:** Correct deduplication with proper collision handling.

---

## Phase 4: HAMT-Based Persistent Binding

### 4.1 Persistent Binding with HAMT

**Problem:** `Binding.Clone()` was O(n), `Set()` allocated on every call due to copy-on-write.

**Solution:** Replace mutable binding with Hash Array Mapped Trie (HAMT).

```go
type Binding struct {
    root *hamtNode
    size int
    hash uint64
}

// Clone is now O(1) - just return same pointer
func (b *Binding) Clone() *Binding {
    return b
}

// Set shares structure via path copying
func (b *Binding) Set(k, v Term) *Binding {
    newRoot, added := b.root.set(k, v, k.Hash(), 0)
    return &Binding{root: newRoot, size: newSize}
}
```

**HAMT Properties:**
- 32-way branching (5 bits per level)
- O(log32 n) for Get/Set/Remove
- Structural sharing between versions
- O(1) Clone (identity function)

**Trail Simplification:**
```go
type BindingTrail struct {
    snapshots []*Binding  // Just store binding pointers
}

func (b *Binding) Unwind(trail *BindingTrail, mark int) *Binding {
    return trail.snapshots[mark]  // O(1) pointer swap
}
```

**Impact:**

| Metric | Before HAMT | After HAMT | Change |
|--------|-------------|------------|--------|
| Runtime | 6.68s | 5.59s | **-16%** |
| Total allocs | 13.5GB | 9.6GB | **-29%** |
| `Binding.Clone` | 633MB | 0 | **-100%** |

**Files:** `term/hamt.go` (new), `term/binding.go`

---

## Failed Optimization: Incremental Merge in `Fact.Unify`

### What Was Tried

**Hypothesis:** Merging bindings incrementally instead of collecting partials would be faster.

**Implementation:**
```go
// ATTEMPTED (BAD)
b := term.NewBinding()
for i, a := range f.Args {
    b1, _ := a.Unify(other.Args[i])
    b1.Iterate(func(k, v term.Term) bool {
        b = b.Set(k, v)  // One Set() per key
        return true
    })
}
```

### Why It Failed

Each `Set()` call triggered copy-on-write on the singleton `emptyBinding`:
- If partial has 5 keys → 5 `Set()` calls → 5 allocations
- Original approach: 1 `Extend()` call → 1 allocation

**Measured Impact:**
- Runtime: +35% (6.68s → 11.73s)
- Allocations: +46% (14.2GB → 20.8GB)
- `Binding.Set`: +96% (7.5GB → 14.7GB)

### Lesson Learned

With copy-on-write semantics, **bulk operations** (`Extend()`) are more efficient than **iterative mutations** (`Set()` in a loop). The singleton pattern for empty bindings amplifies this effect.

**Correct approach (kept):**
```go
var partials []*term.Binding
for i, a := range f.Args {
    b1, _ := a.Unify(other.Args[i])
    if b1.Size() > 0 {
        partials = append(partials, b1)
    }
}
b := term.NewBinding()
for _, partial := range partials {
    b = b.Extend(partial)  // Bulk merge
}
```

---

## Removed Optimizations

### `varOnly` Fast Path

**What it was:** Special case for bindings containing only variable keys, using `map[string]bindingVar` instead of `HashMap`.

**Why removed:** With HAMT, the overhead is already low (O(log32 n)) and the code complexity wasn't justified. HAMT provides consistent performance for all key types.

---

## Files Modified

| File | Changes |
|------|---------|
| `data/hashmap.go` | Bucket-based collision handling |
| `data/hashset.go` | Pointer to HashMap, nil guards |
| `term/hamt.go` | **New** - HAMT implementation |
| `term/binding.go` | HAMT-based binding, simplified trail |
| `term/term.go` | `cachedBytes` field, `VarCount()`/`AppendVars()` |
| `rule/fact.go` | Pre-allocated `Vars()` |
| `rule/rules.go` | Manual `Clone()` without deepcopy |
| `monitor/monitor.go` | Trail-based backtracking, `bindingSet` |

---

## Profiling Commands

```bash
# Run with profiling
./specmon monitor -s spec.json -t trace.json \
    --cpuprofile cpu.pprof --memprofile mem.pprof

# Analyze memory allocations
go tool pprof -alloc_space -top mem.pprof

# Analyze CPU
go tool pprof -top cpu.pprof

# Compare benchmarks
go test -bench=. -benchmem ./term/... > bench.txt
benchstat old.txt new.txt
```

---

## Future Considerations

1. **Small binding optimization:** For bindings with ≤4 entries, an inline array might be faster than HAMT traversal.

2. **Hash caching in HAMT nodes:** Could cache subtree hashes for faster `Binding.Hash()`.

3. **Parallel iteration:** HAMT structure enables parallel traversal if needed.
