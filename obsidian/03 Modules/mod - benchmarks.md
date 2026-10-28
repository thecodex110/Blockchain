---
tags: [module, worklet/3]
files: [blockchain_lite/benchmarks/pow_benchmark.py, docs/pow_benchmark_chart.png]
---
# mod — benchmarks

`pow_benchmark.py` (REQ-013, Worklet 3.5):
- `run_difficulty_benchmark` → `DifficultyBenchmarkRow` per D: mean, median, stdev, min, max time + Geometric-distribution analysis (expected `2^D` tries)
- `compare_hasher_throughput(seconds)` — bit-level vs hashlib hashes/s
- `format_benchmark_markdown_table`, `generate_full_experiment_report`, `get_benchmark_environment_metadata`

Chart: `docs/pow_benchmark_chart.png`. Demo stage 6 runs D ∈ {0, 4, 8, 10}. See [[Proof-of-Work]].

Back to [[Code Map]].
