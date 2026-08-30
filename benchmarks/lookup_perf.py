"""
Performance benchmark for attack_core index operations.

Measures:
  - index.get() latency over all technique IDs (must be < 0.01ms per call, O(1))
  - index.search() latency with 100 keywords (p95 must be < 5ms)

Outputs JSON report to stdout (or file via --output).

Usage:
    python benchmarks/lookup_perf.py
    python benchmarks/lookup_perf.py --output results.json
    python benchmarks/lookup_perf.py --iterations 1000
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
from pathlib import Path

# ---------------------------------------------------------------------------
# Keyword corpus for search benchmarks
# ---------------------------------------------------------------------------
SEARCH_KEYWORDS: list[str] = [
    "phishing",
    "credential",
    "lateral",
    "persistence",
    "exfiltration",
    "discovery",
    "privilege",
    "escalation",
    "defense",
    "evasion",
    "initial",
    "access",
    "execution",
    "impact",
    "collection",
    "command",
    "control",
    "resource",
    "development",
    "reconnaissance",
    "spearphishing",
    "attachment",
    "link",
    "service",
    "exploit",
    "public",
    "application",
    "remote",
    "desktop",
    "protocol",
    "brute",
    "force",
    "password",
    "spraying",
    "kerberoasting",
    "token",
    "manipulation",
    "process",
    "injection",
    "dll",
    "side-loading",
    "registry",
    "run",
    "keys",
    "scheduled",
    "task",
    "boot",
    "logon",
    "autostart",
    "browser",
    "extensions",
    "clipboard",
    "data",
    "encrypted",
    "channel",
    "proxy",
    "multi-hop",
    "domain",
    "fronting",
    "fallback",
    "channels",
    "ingress",
    "tool",
    "transfer",
    "archive",
    "collected",
    "audio",
    "capture",
    "video",
    "screen",
    "keylogging",
    "input",
    "credentials",
    "file",
    "directory",
    "network",
    "share",
    "email",
    "local",
    "cloud",
    "storage",
    "object",
    "automated",
    "man-in-the-middle",
    "adversary",
    "firmware",
    "corruption",
    "wiper",
    "defacement",
    "endpoint",
    "denial",
    "account",
    "manipulation",
    "trusted",
    "relationship",
    "supply",
    "chain",
    "compromise",
    "hardware",
    "additions",
    "traffic",
    "signaling",
    "steganography",
    "protocol",
    "tunneling",
    "non-standard",
    "port",
    "web",
    "shell",
    "implant",
]

assert (
    len(SEARCH_KEYWORDS) >= 100
), f"Expected at least 100 keywords, got {len(SEARCH_KEYWORDS)}"


def _time_ns() -> int:
    """High-resolution monotonic time in nanoseconds."""
    return time.perf_counter_ns()


def benchmark_get(index, iterations: int) -> dict:
    """Benchmark index.get() over all technique IDs."""
    # ATTACKIndex does not expose a public "all IDs" accessor; derive the list
    # of technique/sub-technique IDs from the internal id map.
    technique_ids: list[str] = [
        obj.attack_id for obj in index._by_id.values() if hasattr(obj, "attack_id")
    ]

    if not technique_ids:
        raise RuntimeError("No technique IDs found in index — cannot benchmark get()")

    latencies_ns: list[int] = []

    for _ in range(iterations):
        for tid in technique_ids:
            start = _time_ns()
            _ = index.get(tid)
            elapsed = _time_ns() - start
            latencies_ns.append(elapsed)

    latencies_ms = [ns / 1_000_000 for ns in latencies_ns]

    mean_ms = statistics.mean(latencies_ms)
    median_ms = statistics.median(latencies_ms)
    p95_ms = sorted(latencies_ms)[int(len(latencies_ms) * 0.95)]
    p99_ms = sorted(latencies_ms)[int(len(latencies_ms) * 0.99)]
    max_ms = max(latencies_ms)

    return {
        "operation": "get",
        "total_calls": len(latencies_ms),
        "technique_count": len(technique_ids),
        "iterations": iterations,
        "mean_ms": round(mean_ms, 6),
        "median_ms": round(median_ms, 6),
        "p95_ms": round(p95_ms, 6),
        "p99_ms": round(p99_ms, 6),
        "max_ms": round(max_ms, 6),
        "threshold_ms": 0.01,
        "pass": mean_ms < 0.01,
    }


def benchmark_search(index, iterations: int) -> dict:
    """Benchmark index.search() with 100 keywords."""
    latencies_ns: list[int] = []

    for _ in range(iterations):
        for keyword in SEARCH_KEYWORDS:
            start = _time_ns()
            _ = index.search(keyword)
            elapsed = _time_ns() - start
            latencies_ns.append(elapsed)

    latencies_ms = [ns / 1_000_000 for ns in latencies_ns]

    mean_ms = statistics.mean(latencies_ms)
    median_ms = statistics.median(latencies_ms)
    p95_ms = sorted(latencies_ms)[int(len(latencies_ms) * 0.95)]
    p99_ms = sorted(latencies_ms)[int(len(latencies_ms) * 0.99)]
    max_ms = max(latencies_ms)

    return {
        "operation": "search",
        "total_calls": len(latencies_ms),
        "keyword_count": len(SEARCH_KEYWORDS),
        "iterations": iterations,
        "mean_ms": round(mean_ms, 6),
        "median_ms": round(median_ms, 6),
        "p95_ms": round(p95_ms, 6),
        "p99_ms": round(p99_ms, 6),
        "max_ms": round(max_ms, 6),
        "threshold_p95_ms": 5.0,
        "pass": p95_ms < 5.0,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Performance benchmark for attack_core index operations"
    )
    parser.add_argument(
        "--iterations",
        type=int,
        default=100,
        help="Number of full passes over technique IDs / keywords (default: 100)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Write JSON results to file (default: stdout)",
    )
    parser.add_argument(
        "--fail-on-threshold",
        action="store_true",
        default=False,
        help="Exit with code 1 if any threshold is exceeded",
    )
    args = parser.parse_args()

    # Import the library under test
    try:
        from attack_core import ATTACKIndex, ATTACKLoader
    except ImportError:
        print(
            "ERROR: attack_core is not installed. "
            "Install with: pip install attack-core",
            file=sys.stderr,
        )
        return 1

    print("Loading ATT&CK index...", file=sys.stderr)
    index = ATTACKIndex(ATTACKLoader())
    print(
        f"Index loaded. Running benchmarks (iterations={args.iterations})...",
        file=sys.stderr,
    )

    get_results = benchmark_get(index, iterations=args.iterations)
    search_results = benchmark_search(index, iterations=args.iterations)

    report = {
        "benchmark": "attack_core_lookup_perf",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "python_version": sys.version,
        "iterations": args.iterations,
        "results": {
            "get": get_results,
            "search": search_results,
        },
        "overall_pass": get_results["pass"] and search_results["pass"],
    }

    json_output = json.dumps(report, indent=2)

    if args.output:
        args.output.write_text(json_output, encoding="utf-8")
        print(f"Results written to {args.output}", file=sys.stderr)
    else:
        print(json_output)

    # Summary to stderr
    print("\n--- Summary ---", file=sys.stderr)
    print(
        f"  get()    mean: {get_results['mean_ms']:.4f} ms  "
        f"(threshold: <{get_results['threshold_ms']} ms) "
        f"{'✓ PASS' if get_results['pass'] else '✗ FAIL'}",
        file=sys.stderr,
    )
    print(
        f"  search() p95:  {search_results['p95_ms']:.4f} ms  "
        f"(threshold: <{search_results['threshold_p95_ms']} ms) "
        f"{'✓ PASS' if search_results['pass'] else '✗ FAIL'}",
        file=sys.stderr,
    )

    if args.fail_on_threshold and not report["overall_pass"]:
        print("\nFAILED: One or more thresholds exceeded.", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
