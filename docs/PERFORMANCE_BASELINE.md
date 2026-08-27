# Performance Baseline — attack-core

This document establishes the performance baseline for `attack-core` index operations, the methodology for measurement, and the thresholds that CI enforces.

---

## Summary

| Operation | Metric | Threshold | Typical | Complexity |
|-----------|--------|-----------|---------|------------|
| `index.get(technique_id)` | Mean latency | < 0.01 ms | ~0.002 ms | O(1) dict lookup |
| `index.search(keyword)` | p95 latency | < 5 ms | ~1.2 ms | O(n) substring scan |
| `AttackIndex.load()` | Cold start | < 2000 ms | ~800 ms | One-time parse |
| Memory (loaded index) | RSS delta | < 150 MB | ~95 MB | Full ATT&CK corpus |

---

## Design Rationale

### O(1) Lookups via `get()`

The `AttackIndex` stores all techniques in a Python `dict` keyed by technique ID (e.g., `"T1059"`). Dictionary lookup in CPython is amortized O(1) via hash table, giving sub-microsecond access regardless of corpus size.

**Why this matters:** Security tools performing real-time detection need to resolve technique IDs in hot paths. A 10μs budget per lookup allows thousands of enrichments per second on a single core.

### Search Performance

`index.search(keyword)` performs a case-insensitive substring match across technique names and descriptions. This is inherently O(n) over the corpus but benefits from:

- Pre-lowercased search fields at load time
- Short-circuit on first match per technique
- CPython's optimized `str.__contains__`

The p95 threshold of 5ms accommodates the full ATT&CK Enterprise corpus (~800 techniques) with headroom for future growth.

---

## Benchmark Methodology

### Environment

- **Python**: 3.11+ (CPython)
- **OS**: Ubuntu 22.04 (CI), validated on macOS/Windows
- **Hardware**: GitHub Actions runner (2 vCPU, 7 GB RAM)
- **Isolation**: No concurrent workloads; dedicated job in CI

### Procedure

1. Load the full ATT&CK Enterprise STIX bundle via `AttackIndex.load()`.
2. **get() benchmark**: Call `index.get(tid)` for every technique ID, repeated 100 iterations. Measure wall-clock time per call using `time.perf_counter_ns()`.
3. **search() benchmark**: Call `index.search(kw)` for 100 representative keywords, repeated 100 iterations. Measure wall-clock time per call.
4. Compute mean, median, p95, p99, and max for each operation.
5. Assert thresholds; fail CI if exceeded.

### Running Locally

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run benchmark
python benchmarks/lookup_perf.py --iterations 100

# Run with threshold enforcement
python benchmarks/lookup_perf.py --fail-on-threshold

# Output to file
python benchmarks/lookup_perf.py --output results.json
```

---

## Baseline Results

Captured on: 2026-08-15 | Python 3.12.4 | Ubuntu 22.04 (GitHub Actions)

### `index.get()` — Dictionary Lookup

```
Total calls:      76,800 (768 techniques × 100 iterations)
Mean:             0.0018 ms
Median:           0.0015 ms
p95:              0.0031 ms
p99:              0.0058 ms
Max:              0.0412 ms
Threshold:        < 0.01 ms (mean)
Status:           ✓ PASS
```

### `index.search()` — Keyword Search

```
Total calls:      10,000 (100 keywords × 100 iterations)
Mean:             1.18 ms
Median:           1.05 ms
p95:              2.41 ms
p99:              3.87 ms
Max:              6.12 ms
Threshold:        < 5 ms (p95)
Status:           ✓ PASS
```

### `AttackIndex.load()` — Cold Start

```
Iterations:       10
Mean:             823 ms
Median:           811 ms
p95:              892 ms
Threshold:        < 2000 ms
Status:           ✓ PASS
```

---

## Threshold Tuning Guidelines

Thresholds should be set at **3–5× the typical observed value** to avoid flaky CI while still catching regressions:

| Operation | Typical | Multiplier | Threshold |
|-----------|---------|------------|-----------|
| get() mean | 0.002 ms | 5× | 0.01 ms |
| search() p95 | 2.4 ms | ~2× | 5 ms |
| load() | 820 ms | ~2.5× | 2000 ms |

If a new ATT&CK version significantly increases corpus size, thresholds may need adjustment. Document any changes in the PR description.

---

## Regression Detection

The CI pipeline (`ci.yml`) runs benchmarks on every push to `main` and on PRs:

```yaml
- name: Performance benchmark
  run: python benchmarks/lookup_perf.py --fail-on-threshold --output perf-results.json

- name: Upload benchmark results
  uses: actions/upload-artifact@v4
  with:
    name: perf-results
    path: perf-results.json
```

### Interpreting Failures

| Scenario | Likely Cause | Action |
|----------|-------------|--------|
| get() threshold exceeded | Added processing to lookup path | Profile with `cProfile`; check for added validation |
| search() threshold exceeded | Corpus grew or search logic changed | Check if linear scan needs optimization |
| Flaky failure (passes on re-run) | CI runner contention | Re-run; if persistent, adjust threshold |

---

## Future Optimizations

If search performance becomes a bottleneck:

1. **Inverted index**: Pre-tokenize descriptions into a term→technique_id mapping. Reduces search to O(1) per token.
2. **Compiled regex**: For pattern-based searches, pre-compile patterns at load time.
3. **Rust extension**: For extreme performance needs, move the hot loop to a compiled extension (via PyO3/maturin).

These are documented for future reference; current performance meets all requirements.
