# Initial native SAML baseline

Recorded 2026-10-20. This is a baseline-only change: runtime library code and
dependencies are unchanged. There is no candidate speedup or before/after
delta yet, and this is not a comparison with the pre-upgrade 0.9 stack.

## Source and environment

- Runtime base: `7854bfbcd27ad9454e7fb80580e3b1d5d8360bcd` (merged 0.10 dependency update).
- Uncommitted harness branch: `perf/saml-baseline`.
- Harness SHA-256: `86d9c4b9ec53b1277968d0323d169e8414a94c2229ada17542d07da58b3da836`.
- Cargo.lock SHA-256: `0c59a17ccb09d9cfdcda4ff82150de66d60757f8771eee5891b192796188f8f3`.
- Executable SHA-256: `7281b66f9011739562e2701ef1edfacccaeb28833c5a5118dff6c53cb3b99702`.
- Local gamlastan 0.10.0; registry bergshamra 0.11.0, kryptering 0.7.0,
  uppsala 0.12.0. Metadata confirmed these sources; no sibling overrides.
- rustc 1.98.0 (88d9e12ae 2026-08-18), Cargo 1.98.0 (797e8a9bc 2026-08-05).
- Default Cargo bench profile, opt-level 3, no debug assertions or debug info;
  no custom RUSTFLAGS or bench profile overrides.
- x86_64 Linux 7.0.0-34-generic, KVM guest, 8 exposed CPUs reporting
  Intel Core Ultra 7 155H. No CPU affinity or governor controls were imposed.
- All compilation and regression tests finished before timing. Shared-host
  scheduling/frequency effects remain uncontrolled.

The generated corpus was `/tmp/gamlastan-perf.g8MQz1`. Its files are generated
artifacts, not committed input files; regenerate using the guide and check
these identities before comparing, or preserve the corpus across builds.

| Fixture | Bytes | SHA-256 |
| --- | ---: | --- |
| small-response | 3554 | `db71c3828317bbabc9337b1768dcc85af946734a13981cdaaa434ea96fb6e374` |
| medium-assertion | 8169 | `2ca0690156578c4d6f3f59b2f716752c05465de7633dfc163e56f57d1c1cf5f4` |
| large-both | 47496 | `944a41f90ec2d317cd97eb5b24e8d3d075b161ba1c8d296374ac2e934cda49ef` |

## Commands

Build, corpus generation and positive/negative smoke checks follow
[the benchmark guide](performance.md). The optimized executable was
`target/release/deps/saml_pipeline-0e78d6bb3831efdf`. The recorded sample loop
was:

```sh
set -e
for fixture in small-response medium-assertion large-both; do
  for phase in parse extract verify verify-all pipeline; do
    case "$phase" in parse|extract) iterations=5000 ;; *) iterations=1000 ;; esac
    for run in 1 2 3 4 5; do
      /usr/bin/time -f "sample,$fixture,$phase,$run,%e,%M" \
        "$PERF_BIN" "$phase" "$PERF_CORPUS/$fixture.xml" "$iterations"
    done
  done
done
```

Each run was a fresh worker process with ten warmup operations. There were
75 successful measured processes. A separate 500-iteration large-pipeline
pilot and smoke runs are excluded from the table and raw sample set.

## Results

Five-run medians and full observed ranges, not confidence intervals.
Elapsed us/op is the warm API loop; wall seconds and peak RSS include
process initialization, validation and warmup. RSS values are medians of
whole-process high-water marks, not incremental phase allocations.

| Fixture | Phase | Median us/op | Min-max us/op | Median wall s | Median peak RSS KiB |
| --- | --- | ---: | ---: | ---: | ---: |
| small-response | parse | 16.6 | 16.0-20.8 | 0.08 | 5736 |
| small-response | extract | 24.5 | 19.8-35.7 | 0.12 | 5748 |
| small-response | verify | 632.0 | 507.7-962.4 | 0.65 | 5828 |
| small-response | verify-all | 524.4 | 512.2-562.7 | 0.53 | 5752 |
| small-response | pipeline | 540.5 | 526.7-591.1 | 0.55 | 5768 |
| medium-assertion | parse | 40.9 | 38.5-44.5 | 0.21 | 5780 |
| medium-assertion | extract | 50.1 | 48.3-56.3 | 0.25 | 5736 |
| medium-assertion | verify | 694.9 | 632.6-819.3 | 0.70 | 5676 |
| medium-assertion | verify-all | 680.5 | 653.8-703.1 | 0.69 | 5728 |
| medium-assertion | pipeline | 705.6 | 693.6-730.4 | 0.71 | 5780 |
| large-both | parse | 231.9 | 225.5-331.4 | 1.17 | 6136 |
| large-both | extract | 295.9 | 286.7-305.3 | 1.48 | 6168 |
| large-both | verify | 1721.9 | 1699.6-2021.9 | 1.74 | 6212 |
| large-both | verify-all | 2573.5 | 2533.0-2947.6 | 2.60 | 6108 |
| large-both | pipeline | 2974.0 | 2845.4-3233.0 | 3.01 | 6032 |

Noise is material: the small single-signature verification samples span
roughly 508-962 us/op, and short parse samples include timing windows below
0.1 seconds. In particular, the single-signature verify/verify-all medians
must not be interpreted as a performance difference between those APIs.
For optimization acceptance, increase short-case iteration counts and
alternate baseline/candidate binaries on a quieter host. These measurements
establish reproducibility and expose variability, not a regression threshold.

## Verification

- Debug and optimized harness smoke checks passed: repeated fixture generation
  produced identical bytes, expected attribute/signature counts held, all
  phases completed, and altered signed content, truncated XML and DTDs failed.
- Zero iterations and unknown phases fail; generating into an existing corpus
  fails without changing the original files (hashes checked afterwards).
- Workspace suite: 1,148 passed, 12 ignored. No new runtime behavior.
- Workspace Clippy with warnings denied and formatting checks passed.
- `cargo +1.88.0 check -p gamlastan --bench saml_pipeline --locked
  --target-dir target/msrv-1.88` passed.
- Cargo.lock is unchanged. No downstream service/wheel was modified or measured.

## Raw samples

The input bytes, counts and hashes are mapped above; warmup is 10 for every
row. Columns retain measured total nanoseconds, reported ns/op, GNU time's
wall seconds and peak RSS in KiB. Output from stdout/stderr was joined in
per-stream run order (the streams can be interleaved differently).

```csv
fixture,phase,run,iterations,elapsed_ns,ns_per_op,wall_seconds,peak_rss_kib
small-response,parse,1,5000,103914700,20782.9,0.11,5672
small-response,parse,2,5000,83190101,16638.0,0.08,5736
small-response,parse,3,5000,82078623,16415.7,0.08,5768
small-response,parse,4,5000,79893711,15978.7,0.08,5676
small-response,parse,5,5000,83289979,16658.0,0.08,5824
small-response,extract,1,5000,122582857,24516.6,0.12,5708
small-response,extract,2,5000,141256505,28251.3,0.14,5748
small-response,extract,3,5000,98920219,19784.0,0.10,5736
small-response,extract,4,5000,178480178,35696.0,0.19,5896
small-response,extract,5,5000,117370580,23474.1,0.12,5884
small-response,verify,1,1000,632019444,632019.4,0.65,5772
small-response,verify,2,1000,962427329,962427.3,0.98,5896
small-response,verify,3,1000,639414427,639414.4,0.65,5828
small-response,verify,4,1000,507691990,507692.0,0.51,5616
small-response,verify,5,1000,514484869,514484.9,0.52,5852
small-response,verify-all,1,1000,524405813,524405.8,0.53,5752
small-response,verify-all,2,1000,562721521,562721.5,0.57,5852
small-response,verify-all,3,1000,514438346,514438.3,0.52,5692
small-response,verify-all,4,1000,538810077,538810.1,0.54,5828
small-response,verify-all,5,1000,512200317,512200.3,0.52,5624
small-response,pipeline,1,1000,554402160,554402.2,0.56,5784
small-response,pipeline,2,1000,526707392,526707.4,0.53,5676
small-response,pipeline,3,1000,535544949,535544.9,0.54,5624
small-response,pipeline,4,1000,540458624,540458.6,0.55,5768
small-response,pipeline,5,1000,591114184,591114.2,0.60,5836
medium-assertion,parse,1,5000,192273084,38454.6,0.19,5752
medium-assertion,parse,2,5000,200360418,40072.1,0.20,5896
medium-assertion,parse,3,5000,210878963,42175.8,0.22,5780
medium-assertion,parse,4,5000,222391879,44478.4,0.22,5624
medium-assertion,parse,5,5000,204357927,40871.6,0.21,5824
medium-assertion,extract,1,5000,258643437,51728.7,0.26,5676
medium-assertion,extract,2,5000,281582140,56316.4,0.29,5736
medium-assertion,extract,3,5000,241387322,48277.5,0.24,5728
medium-assertion,extract,4,5000,245324659,49064.9,0.25,5824
medium-assertion,extract,5,5000,250614557,50122.9,0.25,5904
medium-assertion,verify,1,1000,632605659,632605.7,0.64,5676
medium-assertion,verify,2,1000,694876615,694876.6,0.70,5660
medium-assertion,verify,3,1000,819318467,819318.5,0.83,5712
medium-assertion,verify,4,1000,729136742,729136.7,0.74,5660
medium-assertion,verify,5,1000,658658271,658658.3,0.67,5836
medium-assertion,verify-all,1,1000,685866021,685866.0,0.69,5676
medium-assertion,verify-all,2,1000,680472812,680472.8,0.69,5624
medium-assertion,verify-all,3,1000,655033914,655033.9,0.66,5768
medium-assertion,verify-all,4,1000,703079249,703079.2,0.71,5728
medium-assertion,verify-all,5,1000,653755440,653755.4,0.66,5896
medium-assertion,pipeline,1,1000,705590837,705590.8,0.71,5604
medium-assertion,pipeline,2,1000,708608080,708608.1,0.72,5820
medium-assertion,pipeline,3,1000,730393202,730393.2,0.74,5828
medium-assertion,pipeline,4,1000,693583245,693583.2,0.70,5768
medium-assertion,pipeline,5,1000,694163707,694163.7,0.70,5780
large-both,parse,1,5000,1159459927,231892.0,1.17,6236
large-both,parse,2,5000,1127352974,225470.6,1.13,6156
large-both,parse,3,5000,1142568215,228513.6,1.15,6136
large-both,parse,4,5000,1657151724,331430.3,1.67,6060
large-both,parse,5,5000,1465607226,293121.4,1.47,6128
large-both,extract,1,5000,1479578589,295915.7,1.48,6280
large-both,extract,2,5000,1526402874,305280.6,1.53,6024
large-both,extract,3,5000,1433433246,286686.6,1.45,6132
large-both,extract,4,5000,1436850046,287370.0,1.44,6236
large-both,extract,5,5000,1501811808,300362.4,1.51,6168
large-both,verify,1,1000,1721891712,1721891.7,1.74,6212
large-both,verify,2,1000,1825228465,1825228.5,1.84,6272
large-both,verify,3,1000,2021856149,2021856.1,2.04,5980
large-both,verify,4,1000,1699583041,1699583.0,1.73,6048
large-both,verify,5,1000,1706269396,1706269.4,1.73,6264
large-both,verify-all,1,1000,2573529880,2573529.9,2.60,6036
large-both,verify-all,2,1000,2564082097,2564082.1,2.60,6108
large-both,verify-all,3,1000,2947649895,2947649.9,2.98,6112
large-both,verify-all,4,1000,2647218446,2647218.4,2.68,5860
large-both,verify-all,5,1000,2532999049,2532999.0,2.56,6132
large-both,pipeline,1,1000,2973954279,2973954.3,3.01,6032
large-both,pipeline,2,1000,2991959390,2991959.4,3.03,6012
large-both,pipeline,3,1000,3232991125,3232991.1,3.30,6136
large-both,pipeline,4,1000,2845378389,2845378.4,2.89,5972
large-both,pipeline,5,1000,2864686290,2864686.3,2.90,6112
```

