# Reuse parsed XML during enveloped verification

## Change and compatibility

`SamlVerifier::verify_enveloped` and `verify_all_enveloped` now pass the same
unmodified document through E91, algorithm policy and bergshamra's
document-taking verifier. With the default guards, this replaces three
top-level parses with one. This count comes from the call paths, not runtime
parser instrumentation. Generic transforms can still reparse internally.
The benchmark's pipeline still performs a separate strict protocol parse and
typed extraction after verifying signatures.

There is no new public API, dependency update, policy relaxation, cache or
version bump beyond the existing unreleased 0.10.0. The public string-taking
E91 helper delegates to the same internal document scan.

- Metadata parsing rules are retained, including structural comment/PI
  tolerance and rejection of split value text, DTDs and CDATA.
- Guard order and parse-error context are retained. E91 precedes algorithm
  policy, which precedes backend processing.
- When callers explicitly disable E91, select permissive algorithms and
  disable HMAC rejection, the existing raw backend parser behavior remains.
  The optimization does not silently strengthen or weaken that legacy mode.
- First-signature versus all-signature selection, duplicate-ID detection,
  reference coverage, trusted-key policy and per-signature results remain
  backend responsibilities with the same context configuration.
- The backend receives the original input alongside its exact, unmodified
  document. No external or mutated DOM is accepted, so the original source
  cannot become stale through this internal path.
- This does not change the protocol consumer's obligation to perform strict
  parsing, signature binding, audience/recipient/time and replay validation.

## Correctness evidence

The new differential tests retain the old parse/guard/string-backend sequence
as an oracle. They compare full debug representations, including error
variants/messages, signature/reference NodeIds, digest flags and key metadata.
The namespace/algorithm scan logic is shared; this comparison specifically
checks the changed orchestration, not an independent implementation of every
security rule.

There are 720 comparisons across three signature layouts, 15 input variants,
eight combinations of E91/algorithm/HMAC guards, and first/all verification.
Inputs include valid signatures, altered prefixes and signed text, SHA-1/HMAC
methods, SHA-1 digests, duplicate IDs, ds:Object, split comments/PIs, CDATA,
DTDs, truncated XML and unsigned responses. Additional tests check:

- Structural comments/PIs remain acceptable to the verifier, while strict
  protocol parsing still rejects them.
- A malformed outer signature does not hide a valid assertion signature.
- A signed XPath-transform fallback verifies with original source bytes and
  rejects tampered content.

Final checks: 1,152 workspace tests passed, 12 ignored; benchmark smoke checks
passed in debug and optimized builds; workspace Clippy with warnings denied,
Rust 1.88 all-target checks, formatting and diff checks passed. The ignored
HSM test was not rerun for this change.

## Measurement setup

Measured on 2026-10-20 using the unchanged [benchmark harness](performance.md).
The previous [baseline record](performance-baseline.md) is preserved. These
are fresh paired measurements, not comparisons against its earlier timings.

- Baseline: merged commit `9741718c6f4da5dd42453b37959d665da1b619f4`.
- Candidate: that commit plus the uncommitted `perf/reuse-verification-document`
  change. Runtime source SHA-256:
  - `src/crypto/verifier.rs`: `05679ae4601d66a199d2c51aedb59a09e8acaa3a30a7ae9a674b784e1c4d94c3`
  - `src/security/signature.rs`: `b7a674d9d99159b311151a3dffef5548433eb025d2f86c260709288684a5ea3a`
- Executables saved in `/tmp/gamlastan-verify-compare.80zYwS`:
  - `baseline`: `7281b66f9011739562e2701ef1edfacccaeb28833c5a5118dff6c53cb3b99702`
  - `candidate`: `556588d49f6eb7ba58cce04387a8441c33e46c34f8a382b8f9675382718e5b6c`
- Unchanged harness SHA-256:
  `86d9c4b9ec53b1277968d0323d169e8414a94c2229ada17542d07da58b3da836`.
- Unchanged lockfile SHA-256:
  `0c59a17ccb09d9cfdcda4ff82150de66d60757f8771eee5891b192796188f8f3`.
- Local gamlastan 0.10.0, registry bergshamra 0.11.0, kryptering 0.7.0 and
  uppsala 0.12.0; dependency sources checked with Cargo metadata.
- Rust 1.98.0, default optimized bench profile, no CPU-specific flags or profile
  overrides; x86_64 Linux 7.0.0-34-generic, 8-vCPU KVM guest reporting Intel
  Core Ultra 7 155H. No affinity/governor controls; shared-host noise remains.
- `perf stat` was unavailable (`perf_event_paranoid=4`); no privileges or kernel
  settings were changed, and no CPU-profile attribution is claimed.

Both binaries were built with `cargo bench -p gamlastan --bench saml_pipeline
--locked --no-run --message-format=json` and copied before the next build.
All compilation/tests finished before paired timing. Every measured worker
uses one fixture/phase, ten warmups and a fresh process. Baseline/candidate order
reverses on even-numbered pairs. Parse-only measurements are an unchanged-path
control, not an optimization target.

The corpus is the same generated set in `/tmp/gamlastan-perf.g8MQz1`, with
input sizes/hashes recorded in the baseline document: small-response 3,554
bytes, medium-assertion 8,169 bytes, large-both 47,496 bytes. Both variants'
CSV outputs retain identical hashes, attribute counts and signature counts.
Certificate time checks alone are disabled for the static test certificate.

The following loop records five pairs per case/phase. `wall_seconds` and
`peak_rss_kib` cover the whole worker, including setup, verification preflight
and warmup. They do not measure per-operation live heap. The initial unpaired
baseline pilot is excluded.

```sh
set -e
for fixture in small-response medium-assertion large-both; do
  for phase in parse verify verify-all pipeline; do
    case "$fixture:$phase" in
      small-response:parse) iterations=50000 ;;
      medium-assertion:parse) iterations=20000 ;;
      large-both:parse) iterations=5000 ;;
      large-both:*) iterations=1000 ;;
      *) iterations=2000 ;;
    esac
    for run in 1 2 3 4 5; do
      if [ "$((run % 2))" -eq 1 ]; then
        variants="baseline candidate"
      else
        variants="candidate baseline"
      fi
      for variant in $variants; do
        /usr/bin/time -f "sample,$fixture,$phase,$run,$variant,%e,%M" \
          "$PERF_COMPARE/$variant" "$phase" \
          "$PERF_CORPUS/$fixture.xml" "$iterations"
      done
    done
  done
done
```

Use `PERF_COMPARE` and `PERF_CORPUS` for the binary and corpus directories above,
or equivalent preserved artifacts on another machine. This native benchmark
does not establish tunnelbana throughput or pygamlastan API improvements; those
consumers remain unchanged. No lxml/libxml2 comparison is included.

## Paired results

All 120 workers completed successfully. The table reports five-run medians,
with delta calculated as candidate median / baseline median - 1. Negative
latency deltas are better. These are observations on this VM, not confidence
intervals or guaranteed production improvements.

| Case / phase | Baseline us/op | Candidate us/op | Delta | Median peak RSS KiB, baseline -> candidate |
| --- | ---: | ---: | ---: | ---: |
| small-response / parse | 15.5 | 16.8 | 8.8% | 5676 -> 5988 |
| small-response / verify | 602.9 | 553.7 | -8.2% | 5844 -> 5948 |
| small-response / verify-all | 556.7 | 517.1 | -7.1% | 5660 -> 5856 |
| small-response / pipeline | 618.2 | 572.8 | -7.3% | 5740 -> 5860 |
| medium-assertion / parse | 41.8 | 40.0 | -4.2% | 5760 -> 5952 |
| medium-assertion / verify | 691.1 | 634.8 | -8.1% | 5768 -> 5880 |
| medium-assertion / verify-all | 695.1 | 644.0 | -7.3% | 5728 -> 5880 |
| medium-assertion / pipeline | 767.1 | 712.9 | -7.1% | 5696 -> 5880 |
| large-both / parse | 246.2 | 241.4 | -2.0% | 6152 -> 6220 |
| large-both / verify | 1814.0 | 1330.6 | -26.6% | 6228 -> 6096 |
| large-both / verify-all | 2841.8 | 2168.4 | -23.7% | 6160 -> 6188 |
| large-both / pipeline | 3068.8 | 2561.5 | -16.5% | 6160 -> 6324 |

For large-both, all five paired runs improved: first-signature verification
by 10.1-29.9%, all-signature verification by 17.6-32.0%, and the native
verify/parse/extract pipeline by 8.3-26.7%. The medians indicate a useful
improvement on this larger input. The generic XPath fallback is regression
tested but is not one of the measured fast-path fixtures.

Small/medium verification medians are about 7-8% lower, but controls expose
substantial noise: unchanged parse median deltas range from -4.2% to +8.8%,
and individual control pairs vary more. Some small/medium verification pairs
regress. Do not treat those modest median changes as conclusive speedups.

There is no consistent RSS reduction. Several candidate process medians are
higher; the raw values include code pages, allocator retention, setup and
preflight, not just live DOM storage. This change makes no memory-savings
claim. Future work should measure real downstream workloads and, if needed,
use allocation profiling rather than interpreting process RSS as live heap.

## Raw paired samples

Input hashes and counts matched the preserved corpus on every row. Warmup
was 10 throughout. Streams were joined in per-stream run order; stdout and
GNU time's stderr can be interleaved differently. The rows below preserve
the actual alternating execution order and include both variants' total
timed nanoseconds, reported ns/op, whole-process wall time and peak RSS.

```csv
fixture,phase,pair,variant,iterations,elapsed_ns,ns_per_op,wall_seconds,peak_rss_kib
small-response,parse,1,baseline,50000,771112712,15422.3,0.78,5676
small-response,parse,1,candidate,50000,864395663,17287.9,0.86,6048
small-response,parse,2,candidate,50000,1091360370,21827.2,1.09,5984
small-response,parse,2,baseline,50000,814572910,16291.5,0.81,5548
small-response,parse,3,baseline,50000,784386039,15687.7,0.78,5788
small-response,parse,3,candidate,50000,694247136,13884.9,0.69,6072
small-response,parse,4,candidate,50000,842175839,16843.5,0.84,5988
small-response,parse,4,baseline,50000,769639028,15392.8,0.77,5676
small-response,parse,5,baseline,50000,773736592,15474.7,0.78,5772
small-response,parse,5,candidate,50000,784317780,15686.4,0.79,5940
small-response,verify,1,baseline,2000,1130329206,565164.6,1.14,5852
small-response,verify,1,candidate,2000,1054424416,527212.2,1.06,5952
small-response,verify,2,candidate,2000,1096620460,548310.2,1.10,5900
small-response,verify,2,baseline,2000,1205871222,602935.6,1.21,5500
small-response,verify,3,baseline,2000,1229620016,614810.0,1.24,5768
small-response,verify,3,candidate,2000,1662375090,831187.5,1.67,5948
small-response,verify,4,candidate,2000,1107395330,553697.7,1.12,5952
small-response,verify,4,baseline,2000,1303578626,651789.3,1.31,5916
small-response,verify,5,baseline,2000,1131539327,565769.7,1.14,5844
small-response,verify,5,candidate,2000,1150749936,575375.0,1.16,5876
small-response,verify-all,1,baseline,2000,1206387561,603193.8,1.21,5768
small-response,verify-all,1,candidate,2000,1034286384,517143.2,1.04,5856
small-response,verify-all,2,candidate,2000,1059882040,529941.0,1.07,5820
small-response,verify-all,2,baseline,2000,1076775542,538387.8,1.08,5496
small-response,verify-all,3,baseline,2000,1040916752,520458.4,1.05,5636
small-response,verify-all,3,candidate,2000,996798038,498399.0,1.00,6004
small-response,verify-all,4,candidate,2000,1010055082,505027.5,1.01,5824
small-response,verify-all,4,baseline,2000,1113472205,556736.1,1.12,5660
small-response,verify-all,5,baseline,2000,1114748867,557374.4,1.12,5736
small-response,verify-all,5,candidate,2000,1307078086,653539.0,1.31,5996
small-response,pipeline,1,baseline,2000,1194033105,597016.6,1.20,5692
small-response,pipeline,1,candidate,2000,1061841799,530920.9,1.07,5844
small-response,pipeline,2,candidate,2000,1111088791,555544.4,1.12,6004
small-response,pipeline,2,baseline,2000,1112175378,556087.7,1.12,5768
small-response,pipeline,3,baseline,2000,1280068635,640034.3,1.29,5840
small-response,pipeline,3,candidate,2000,1196512034,598256.0,1.20,5860
small-response,pipeline,4,candidate,2000,1145617647,572808.8,1.15,5672
small-response,pipeline,4,baseline,2000,1236378534,618189.3,1.24,5740
small-response,pipeline,5,baseline,2000,1391476473,695738.2,1.40,5568
small-response,pipeline,5,candidate,2000,1164827929,582414.0,1.18,6004
medium-assertion,parse,1,baseline,20000,1323763286,66188.2,1.33,5660
medium-assertion,parse,1,candidate,20000,884551710,44227.6,0.89,6008
medium-assertion,parse,2,candidate,20000,799673103,39983.7,0.80,5856
medium-assertion,parse,2,baseline,20000,905323993,45266.2,0.91,5692
medium-assertion,parse,3,baseline,20000,800322173,40016.1,0.80,5848
medium-assertion,parse,3,candidate,20000,815169914,40758.5,0.82,5856
medium-assertion,parse,4,candidate,20000,779860239,38993.0,0.78,5952
medium-assertion,parse,4,baseline,20000,794537020,39726.9,0.79,5760
medium-assertion,parse,5,baseline,20000,835047325,41752.4,0.84,5776
medium-assertion,parse,5,candidate,20000,782109464,39105.5,0.78,6004
medium-assertion,verify,1,baseline,2000,1402067488,701033.7,1.42,5772
medium-assertion,verify,1,candidate,2000,1213982130,606991.1,1.22,5824
medium-assertion,verify,2,candidate,2000,1269649293,634824.6,1.27,5880
medium-assertion,verify,2,baseline,2000,1382177591,691088.8,1.39,5632
medium-assertion,verify,3,baseline,2000,1389809783,694904.9,1.40,5920
medium-assertion,verify,3,candidate,2000,1230801938,615401.0,1.24,5816
medium-assertion,verify,4,candidate,2000,1337262852,668631.4,1.34,6068
medium-assertion,verify,4,baseline,2000,1348932157,674466.1,1.36,5768
medium-assertion,verify,5,baseline,2000,1342138358,671069.2,1.35,5728
medium-assertion,verify,5,candidate,2000,1338357029,669178.5,1.35,5920
medium-assertion,verify-all,1,baseline,2000,1371129171,685564.6,1.38,5632
medium-assertion,verify-all,1,candidate,2000,1270050016,635025.0,1.28,6012
medium-assertion,verify-all,2,candidate,2000,1551665455,775832.7,1.56,5844
medium-assertion,verify-all,2,baseline,2000,1390229819,695114.9,1.40,5860
medium-assertion,verify-all,3,baseline,2000,1391101351,695550.7,1.40,5728
medium-assertion,verify-all,3,candidate,2000,1288083114,644041.6,1.29,5752
medium-assertion,verify-all,4,candidate,2000,1445878490,722939.2,1.45,5880
medium-assertion,verify-all,4,baseline,2000,1582580279,791290.1,1.60,5916
medium-assertion,verify-all,5,baseline,2000,1369090298,684545.1,1.38,5564
medium-assertion,verify-all,5,candidate,2000,1181619231,590809.6,1.19,6068
medium-assertion,pipeline,1,baseline,2000,1659046886,829523.4,1.67,5848
medium-assertion,pipeline,1,candidate,2000,1490888184,745444.1,1.50,5828
medium-assertion,pipeline,2,candidate,2000,1452397487,726198.7,1.47,5996
medium-assertion,pipeline,2,baseline,2000,1541998704,770999.4,1.55,5628
medium-assertion,pipeline,3,baseline,2000,1534109611,767054.8,1.54,5696
medium-assertion,pipeline,3,candidate,2000,1381725423,690862.7,1.39,5880
medium-assertion,pipeline,4,candidate,2000,1425875076,712937.5,1.44,5976
medium-assertion,pipeline,4,baseline,2000,1479115789,739557.9,1.49,5776
medium-assertion,pipeline,5,baseline,2000,1448081941,724041.0,1.45,5636
medium-assertion,pipeline,5,candidate,2000,1341769431,670884.7,1.36,5624
large-both,parse,1,baseline,5000,1393623771,278724.8,1.40,6160
large-both,parse,1,candidate,5000,1760471224,352094.2,1.77,6084
large-both,parse,2,candidate,5000,1144918632,228983.7,1.15,6100
large-both,parse,2,baseline,5000,1231249558,246249.9,1.24,6152
large-both,parse,3,baseline,5000,1222889459,244577.9,1.24,6012
large-both,parse,3,candidate,5000,1122680280,224536.1,1.13,6260
large-both,parse,4,candidate,5000,1240392656,248078.5,1.26,6220
large-both,parse,4,baseline,5000,1340158701,268031.7,1.35,6064
large-both,parse,5,baseline,5000,1170282775,234056.6,1.18,6284
large-both,parse,5,candidate,5000,1207152106,241430.4,1.22,6320
large-both,verify,1,baseline,1000,1875374566,1875374.6,1.92,6228
large-both,verify,1,candidate,1000,1685351413,1685351.4,1.70,6168
large-both,verify,2,candidate,1000,1292366990,1292367.0,1.31,6072
large-both,verify,2,baseline,1000,1844638772,1844638.8,1.87,6228
large-both,verify,3,baseline,1000,1814042887,1814042.9,1.83,6112
large-both,verify,3,candidate,1000,1330607910,1330607.9,1.36,6340
large-both,verify,4,candidate,1000,1278015813,1278015.8,1.29,6096
large-both,verify,4,baseline,1000,1767397545,1767397.5,1.79,6232
large-both,verify,5,baseline,1000,1777952944,1777952.9,1.80,6120
large-both,verify,5,candidate,1000,1413518403,1413518.4,1.43,6096
large-both,verify-all,1,baseline,1000,2729798805,2729798.8,2.76,6228
large-both,verify-all,1,candidate,1000,2115574289,2115574.3,2.14,6188
large-both,verify-all,2,candidate,1000,2261449643,2261449.6,2.29,6092
large-both,verify-all,2,baseline,1000,3005311183,3005311.2,3.04,6228
large-both,verify-all,3,baseline,1000,3117275340,3117275.3,3.15,6160
large-both,verify-all,3,candidate,1000,2119888988,2119889.0,2.14,6220
large-both,verify-all,4,candidate,1000,2168434878,2168434.9,2.19,6276
large-both,verify-all,4,baseline,1000,2631317194,2631317.2,2.67,5884
large-both,verify-all,5,baseline,1000,2841815564,2841815.6,2.88,6060
large-both,verify-all,5,candidate,1000,2333541895,2333541.9,2.36,6096
large-both,pipeline,1,baseline,1000,3341730814,3341730.8,3.38,6060
large-both,pipeline,1,candidate,1000,2451057808,2451057.8,2.48,6348
large-both,pipeline,2,candidate,1000,2535283789,2535283.8,2.56,6324
large-both,pipeline,2,baseline,1000,3068753405,3068753.4,3.10,6160
large-both,pipeline,3,baseline,1000,3220235919,3220235.9,3.25,6228
large-both,pipeline,3,candidate,1000,2679134194,2679134.2,2.70,6208
large-both,pipeline,4,candidate,1000,2561531419,2561531.4,2.59,6276
large-both,pipeline,4,baseline,1000,3064924169,3064924.2,3.10,6044
large-both,pipeline,5,baseline,1000,3044425789,3044425.8,3.08,6300
large-both,pipeline,5,candidate,1000,2792221715,2792221.7,2.83,6412
```

