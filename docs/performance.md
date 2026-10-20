# SAML pipeline performance baseline

The `saml_pipeline` benchmark measures native operations used by downstream
SAML consumers. It is deliberately a small, dependency-free process harness:
run one input and phase per process, keep fixture generation outside that
process, and retain the same fixture bytes for later comparisons. This follows
the uv research's separation of setup from timed work and use of `black_box`.
It is not a statistical benchmarking framework or a complete SSO load test.

## Workloads

The generator uses the existing **test-only** RSA key/certificate in
`crates/gamlastan/tests/fixtures/enc-{key,cert}.pem`. Never deploy these keys.
IDs, timestamps, attribute names/values and RSA-SHA256/SHA256 signatures are
fixed. Generation self-checks each signed document before writing it, and
refuses to overwrite an existing corpus.

| Fixture | Attributes | Signed elements |
| --- | ---: | --- |
| small-response | 4 | Response |
| medium-assertion | 32 | Assertion |
| large-both | 256 | Response and Assertion |

Each document has one assertion and one value per attribute. These are
synthetic XML/crypto workloads, not captured production traffic. Only the
fixture certificate's time checks are disabled. Algorithm, trusted-key,
reference-digest, E91 and wrapping-protection defaults remain enabled.

| Phase | Timed work |
| --- | --- |
| `parse` | Strict `parse_secure` plus document destruction |
| `extract` | Strict parse plus borrowed `ResponseRef` extraction and destruction |
| `verify` | `verify_enveloped`, checking the first signature |
| `verify-all` | `verify_all_enveloped`, checking every signature |
| `pipeline` | All-signature verification, then strict parse and typed extraction |

`extract` includes parsing; it is not an isolated deserialization timer.
`verify` is intentionally not equivalent to `verify-all` on the double-signed
case. The pipeline does not perform audience, time, recipient or replay
validation and must not be copied as a complete SSO acceptance procedure.

Every measurement reads just one fixture, prepares the trusted verifier,
validates the fixture and warms the selected operation ten times before the
timer starts. Every timed verification checks the result, so a failure cannot
silently become a fast benchmark result. Values are passed through
`std::hint::black_box`; allocations and destruction inside each API call
remain inside the timer. File I/O, key preparation and CSV output are excluded.

## Build and run

From the workspace root, with Rust, `jq` and GNU `time` installed:

```sh
# Smoke checks: deterministic generation, cardinality, all phases, and rejection
# of changed signed content, truncated XML and DTDs. Also run in CI.
cargo test -p gamlastan --bench saml_pipeline --locked -- --self-test

# Capture the exact optimized executable, not a potentially stale filename glob.
PERF_BIN="$(cargo bench -p gamlastan --bench saml_pipeline --locked \
  --no-run --message-format=json |
  jq -r 'select(.reason == "compiler-artifact" and
    .target.name == "saml_pipeline" and .executable != null) | .executable')"

PERF_CORPUS="$(mktemp -d)"
"$PERF_BIN" --generate "$PERF_CORPUS"

# Run the binary directly: timing Cargo would include build/startup noise.
for run in 1 2 3 4 5; do
  /usr/bin/time -f 'wall_seconds=%e peak_rss_kib=%M' \
    "$PERF_BIN" pipeline "$PERF_CORPUS/large-both.xml" 500
done
```

Repeat for each phase and fixture. The CSV records bytes, attribute/signature
counts, iterations, warmup count, total timed nanoseconds, ns/op and input
SHA-256. Use a positive iteration count that gives a long enough timing window
on the machine under test. The default Cargo bench profile is optimized; no
workspace profile, allocator or CPU-specific flags are changed by this target.

For CPU profiling, optionally rebuild with symbols and record the changed
profile explicitly:

```sh
CARGO_PROFILE_BENCH_DEBUG=1 cargo bench -p gamlastan --bench saml_pipeline \
  --locked --no-run
# Resolve PERF_BIN again as above with the same environment before profiling.
perf record -g -- "$PERF_BIN" pipeline "$PERF_CORPUS/large-both.xml" 10000
```

## Interpreting results

GNU time's wall time and peak RSS cover the **entire worker process**, including
input loading, key setup, positive-control verification and warmup. Signing
and corpus generation are separate processes. RSS is not live heap or
per-operation allocation; preflight verification can dominate even the
parse-only process's high-water mark. Do not subtract phase RSS numbers.

Use the median of independent runs and preserve the range to expose noise.
Alternate baseline/candidate binaries using the **same generated files**;
compare SHA-256, success status, compiler, lockfile, profile and host details.
Do not infer a speedup merely from adding this harness or from differences
between unrelated workload sizes. Retain raw output as well as summaries.

The initial results are in [the baseline record](performance-baseline.md).
The first runtime optimization, sharing parsed XML between verification
stages, is measured in [the document-reuse comparison](performance-verification.md).
This first slice does not measure allocation counts, parse counts, isolated
canonicalization/crypto time, cold verification, metadata, rollover keys, HSM
latency, Python FFI or tunnelbana throughput. Those require separate cases and
actual downstream artifacts. No lxml/libxml2 comparison is attempted.
