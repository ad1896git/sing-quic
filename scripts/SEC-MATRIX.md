# SEC-MATRIX

Run from the repository root with Python 3 and Go **1.22.12**:

```sh
python3 scripts/security-matrix.py --output /path/to/new/evidence-directory
```

`--dependencies standalone|shipped|all` selects dependency sets. `--go` selects
the executable. The output directory must not exist. Each command has a timeout;
the runner exits nonzero on unexpected failures and writes `results.json`,
`results.md`, the resolved module lists, exact commands, and Go JSON test logs.
`results.json` records every skip with its package, test name and reason.

Both sets run standard, `debug`, `with_low_memory`, and the combined tags, each
with and without `-race`. A separate combined-tag race row selects fragment
bounds, low-datagram round trips and TUIC waiter ownership. These cover empty
payloads, nonpositive MTUs, header-adjacent limits, zero negotiated-size error
injection, the 255/256 fragment boundary, maximum payload/address sizes, and
buffer ownership on write/retry errors. Existing opt-in stream burst stress
tests remain skipped with their existing reason; this matrix is not a stress
measurement or a full external-peer interoperability suite.

Before either dependency set, the runner executes `scripts/test_security_matrix.py`
and retains `verifier-self-tests.log`. To run these checks alone:

```sh
SEC_MATRIX_GO=/path/to/go1.22.12 python3 -B -m unittest discover \
  -s scripts -p test_security_matrix.py -v
```

The self-tests apply the same attacks to **both PASS and XFAIL** expectations:
post-test and background panics, silent exits, failed/fatal assertions (including
subtests and another goroutine), a TestMain suppressing those failures with exit
0, actual in-test and post-`m.Run` races under `-race`, hostile inherited
GORACE/GOFLAGS settings, signals, hangs, test deadlines, build/converter
failures, stale/missing binaries, lost output, wrong diagnostics, vacuous runs,
missing/extra/duplicate tests and packages, unexpected skips, corrupt lifecycles,
and malformed/raw output. Real stdlib-only Go probes use the production row
executor and classifier, with bounded subprocess deadlines and cleanup. Controls
accept both expected outcomes, package interleaving, and split output chunks.
The suite also independently reproduces Go's exit-2 normalization and dr2's
failed-assertion/package-pass contradiction via `go test -json`, then proves the
shared production path rejects both.

The standalone set uses this module's unchanged `go.mod`/`go.sum`: sing 0.4.1,
quic-go 0.46.0-beta.4. The shipped overlay uses nekoray
`218b2a142d2732b7ff09420fb5a33fcb7b5dbca9`, which pins sing-quic base
`56e36b45e5ec061cc5629ca653c3b46fcf9c51f5` and quic-go
`7101329b86a0c801e643fc8ccf730ec89be10663` (0.47.0-beta.2). The runner verifies
the pins, the core's sing 0.4.3 requirement and local quic-go replace directive,
and the carried congestion/DG-FIX patch SHA-256
`e7c92615397316d191b01fca25f44075b353b9a95310fda80dd9e5dd19e12ded`,
then applies that exact patch to an isolated checkout. A temporary modfile
selects these dependencies for the current tests;
it also resolves the transitive sys/text versions selected by sing 0.4.3.
Repository module files and the module cache are not patched. This tests the
sing-quic dependency combination used by nekoray, not the full nekobox_core
executable. It does not close FU-D or establish that all congestion races are
absent; KI-1's patch addresses a separate read synchronization defect.

On macOS the runner uses external linking because macOS 27 rejects Go 1.22's
internally linked test executables without LC_UUID. Linux uses normal linking.
The GitHub workflow runs both dependency sets on Linux and uploads the evidence.

## Controlled Go environment and cold caches

The runner normalizes its environment before self-tests and dependency setup;
`run_row` normalizes again before building, executing and converting binaries.
It sets `GORACE=log_path=stderr exitcode=66 halt_on_error=1 atexit_sleep_ms=0`.
A detected race is visible in the owned stderr capture and exits 66, which is
accepted by neither PASS (0) nor XFAIL (1). This includes races after `m.Run`
when no testing.T is active. Inherited `exitcode=0/1` or `log_path` cannot
redirect reports or make a detected race an accepted status.

| Variable | Effective handling |
| --- | --- |
| `GOENV` | `off`; ignore settings saved with `go env -w` |
| `GOTOOLCHAIN` | `local`; require the selected Go 1.22.12 executable |
| `GOWORK` | `off`; ignore ambient workspace selection |
| `GOFLAGS` | `-mod=readonly`; all row flags are explicit argv entries |
| `CGO_ENABLED` | `1`, including every race build |
| `GOTRACEBACK` | `all`; retain panic stacks |
| `GODEBUG` | Empty; Go's default runtime behavior |
| `GOMAXPROCS` | `2`; fixed parallel runtime, including race probes |
| Other `GO*`, including `GOOS`, `GOARCH`, `GOEXPERIMENT`, `GOPATH` | Removed except the cache/module-transport settings below; native/default Go settings apply |
| `CGO_*`, `CC`, `CXX`, `FC`, `AR`, `PKG_CONFIG` | Removed before setting `CGO_ENABLED`; use native compiler defaults |
| `NKR_TEST_LOWDGRAM`, `NKR_STRESS_STREAMS` | Removed at startup; shipped rows and the standalone XFAIL row explicitly enable the low-datagram opt-in |
| `GOCACHE`, `GOMODCACHE` | Retained to support isolated warm or cold scratch caches |
| `GOPROXY`, `GOSUMDB`, `GOPRIVATE`, `GONOPROXY`, `GONOSUMDB`, `GOINSECURE`, `GOVCS` | Retained module transport/auth policy; downloads must succeed |

The environment contract and each command's effective controlled variables are
recorded in `results.json` (null means unset). `go-env.log` records resolved
native target, cache paths and compiler defaults. Module transport settings may
contain credentials and are not copied into the transcript. PATH, HOME, temporary
directory and network/auth settings still locate trusted tools and dependencies.
The runner assumes a trusted Go/native toolchain and ordinary cache contents.

Each dependency set runs bounded `go mod download` before module/package
inventory parsing, using the same controlled environment and overlay modfile.
Download output has its own log; any error stops the matrix. A cold module cache
therefore does not feed download notices into the strict package parser. The
binary transcript grammar and package inventory checks remain unchanged.

## KI-LOWDGRAM: shipped PASS, standalone XFAIL

All three protocols' `TestLowDatagramRoundTrip` negotiate a real QUIC loopback
pair and use `udpPacketConn.WriteTo` (`packet=false`) or `WritePacket`
(`packet=true`), followed by the actual protocol decoder and reassembler. Each
case compares the original payload and destination. Frame size 0 selects the
QUIC default, rather than advertising zero bytes. Both APIs pass sizes
0/1/31/32/33/255/256/4096 at the default limit. With peer frame size 64, sizes
0/1/31/32/33 pass in both sets. Sizes 255/256/4096 now pass with the shipped
DG-FIX patch; they still fail with standalone quic-go 0.46.0-beta.4.

Outside the matrix, the 18 affected cases still default to explicit
`KNOWN-FAIL/XFAIL KI-LOWDGRAM` skips because the repository module selects the
unfixed standalone dependency. The runner explicitly enables their unchanged
assertions in **every shipped row**, requiring all 96 datagram leaves to pass
under every tag/race combination and the boundary selection. The separate
shipped low-datagram row requires the same 18 formerly failing leaves to PASS
with zero skips. Standalone normal rows retain the 18 skips, and its separate
known-low-datagram row requires the exact 18 failures. Enable the cases manually
with:

```sh
NKR_TEST_LOWDGRAM=1 go test -count=1 -timeout=180s \
  -run '^TestLowDatagramRoundTrip/frame=64/packet=.*/size=(255|256|4096)$' \
  ./hysteria ./hysteria2 ./tuic
```

With standalone dependencies this command **exits 1** with
`PROTOCOL_VIOLATION (local): DATAGRAM frame too large` for each case. Adding
`-modfile` for the generated shipped overlay must instead produce 18 PASS leaves
and exit 0. Add the external-link flag on macOS.

## One outcome classifier for every row

Every PASS and XFAIL row uses `run_row` and `verify_outcome`. There is no
separate permissive PASS branch. The runner builds each selected package with
`go test -c`, including that row's tags, race flag, and dependency modfile, then
directly runs its fresh binary with `-test.v=test2json -test.count=1` and a
180-second test deadline. Python owns the process and records `Popen.wait()`'s
real OS status. PASS binaries must exit 0; XFAIL binaries must exit 1. A build
must exit 0 without diagnostics. A stale executable is removed before building;
a missing executable fails. Outer 300-second deadlines kill and reap the process
group. Neither `go test` nor `test2json` can normalize the captured binary status.

After completion, `go tool test2json -p <package>` reads the captured combined
stdout/stderr from stdin. Conversion must succeed. All raw UTF-8 output must
survive in the JSON Output events in source order, except Go's line-leading
framing marker and NAME controls for the exact expected tests (or empty reset).
Dropped/added diagnostics, invalid bytes or unknown controls fail closed. Raw
logs, JSONL, statuses, commands, selected environment, and deadlines are retained.

`scripts/security-matrix-tests.json` is a reviewed, explicit inventory of every
normal test/subtest, the existing stress skip's exact reason, and the packages
without tests. It was checked against every tag/race/dependency result at the
reviewed head `4e9898ee`; it is **never regenerated from the current run**. Debug
adds its one build-tagged test; the boundary selection filters the inventory;
the focused low-datagram expectation names the three parents and 18 leaves
explicitly. The inventory also pins `low_datagram_expected`: standalone XFAIL
and shipped PASS; it never infers these from an observed result.
Changes to test names, test coverage or allowed output require a reviewed update
of this inventory. A bypassed `m.Run`, silently removed subtest, extra test or
new skip cannot redefine success. Full rows also check `go list ./...` against
the package inventory and run `go build ./...` under the row's flags, covering
packages without tests; those five packages are recorded as `[no test files]`.

The shared classifier requires each package/test to start and terminate exactly
once with its expected action. Children must complete before their parent; every
named test must exist and no extra test is accepted. Output must match the
complete pinned Go grammar: RUN, the exact expected diagnostic for an allowed
skip or known failure, terminal PASS/SKIP/FAIL, and final package PASS/FAIL.
Passing tests currently emit no extra diagnostics, so unexpected logs also fail
and require review. Unknown JSON fields/actions, duplicate keys, output outside
a running lifecycle and incomplete/truncated transcripts fail. Tests with an
unexpected fail action are rejected even if TestMain returns 0 and the package
reports pass. Failures in subtests, other goroutines, cleanup and the race
detector are rejected independently of a successful outer status; the controlled
race channel above also covers post-test races.

XFAIL additionally requires one exact `PROTOCOL_VIOLATION (local): DATAGRAM frame
too large` at each named `low_datagram_test.go` assertion, exactly 18 failing
leaves, three failing parents/packages, and no skips. A distinct
`DatagramTooLargeError`, remote error, added assertion, panic, race or trailing
diagnostic fails. Standalone normal rows require their 78 passing datagram leaves
and 18 explicit known-failure skips. Shipped normal/boundary rows require all 96
leaves to PASS, and the focused row requires all 18 leaves to PASS. Any shipped
failure, missing leaf, or skip is rejected, including the old exact XFAIL output.
All payload/destination/receipt assertions are retained.
An exit status or matching diagnostic alone never establishes a green row.

## DEFECT: KI-LOWDGRAM (P2, shipped fixed by DG-FIX)

Historical severity: **P2**, shipped affected before DG-FIX. The remaining
standalone defect is in quic-go's shared
`connection.SendDatagram` size check, which takes the maximum of the peer limit
and path estimate. It affects both client and server sending paths. The runtime
repro is client-to-server; server exposure follows from the common transport and
packet writer code. A configured remote server can advertise the small limit to
a default client, then the client's UDP write can cause the server to close that
QUIC connection, including multiplexed streams. This requires a connection to
that peer and outbound UDP traffic, and grants no demonstrated capability beyond
disrupting that peer's own connection. It is not an arbitrary unauthenticated
network trigger. No crash, leak, or unbounded allocation was observed or shown by
this repro; the transport queues are bounded. This is a scoped availability and
interoperability defect, separate from the FU-D/KI-1 congestion races.

These pinned quic-go versions advertise 16,383 bytes by default. Both default
peers pass the exercised cases; this defect requires a smaller advertised bound
from a configured peer or another implementation. The tested sizes are sample
points, not a minimum failing size or proof that every larger payload fails.
The review's deliberately injected process panic demonstrates a verifier gap,
not a product crash. The shipped patch is fixed by nekoray PR #47, merged at
`a4d6f17dab745eb20043ad8938aa65d7f7fcc40a`, and included in the pinned
`218b2a14` baseline. Standalone remains unfixed.

DG-FIX bounds `connection.SendDatagram` by the minimum of the peer's
`DatagramFrame.MaxDataLen` and the path bound, returning an accurate
`DatagramTooLargeError` before enqueue. It also checks minimum encoded-frame
size and revalidates queued frames after transport-parameter changes, in both
ordinary and ECH backends. The three `packet.go` implementations'
`WriteTo`/`WritePacket` already use the typed error in `retryFragmented`, allowing
the exercised low-limit writes to fragment without a connection close.

This follow-up changes only matrix scripts, the reviewed expectation inventory,
and this documentation. No production Go code or module manifests change.
Nekoray needs no sing-quic re-pin to receive the fix: its carried patch already
contains DG-FIX, and these test/CI changes do not affect the shipped executable.
