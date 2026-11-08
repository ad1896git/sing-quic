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
0, actual races under `-race`, signals, hangs, test deadlines, build/converter
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
`1127938594e4c67352124ff6362dc704bd0faeeb`, which pins sing-quic base
`9c9fdac85d4bfbfa0336ea1c1154b384c84c259d` and quic-go
`7101329b86a0c801e643fc8ccf730ec89be10663` (0.47.0-beta.2). The runner verifies
the pins, the core's sing 0.4.3 requirement and local quic-go replace directive,
and the congestion patch digest, then applies that exact patch to an isolated
checkout. A temporary modfile selects these dependencies for the current tests;
it also resolves the transitive sys/text versions selected by sing 0.4.3.
Repository module files and the module cache are not patched. This tests the
sing-quic dependency combination used by nekoray, not the full nekobox_core
executable. It does not close FU-D or establish that all congestion races are
absent; KI-1's patch addresses a separate read synchronization defect.

On macOS the runner uses external linking because macOS 27 rejects Go 1.22's
internally linked test executables without LC_UUID. Linux uses normal linking.
The GitHub workflow runs both dependency sets on Linux and uploads the evidence.

## KI-LOWDGRAM: explicit known failure

All three protocols' `TestLowDatagramRoundTrip` negotiate a real QUIC loopback
pair and use `udpPacketConn.WriteTo` (`packet=false`) or `WritePacket`
(`packet=true`), followed by the actual protocol decoder and reassembler. Each
case compares the original payload and destination. Frame size 0 selects the
QUIC default, rather than advertising zero bytes. Both APIs pass sizes
0/1/31/32/33/255/256/4096 at the default limit. With peer frame size 64, sizes
0/1/31/32/33 pass, while 255/256/4096 fail in both dependency sets.

The 18 failing cases default to explicit `KNOWN-FAIL/XFAIL KI-LOWDGRAM` skips,
pending owner/orchestrator decision. Enable their unchanged assertions with:

```sh
NKR_TEST_LOWDGRAM=1 go test -count=1 -timeout=180s \
  -run '^TestLowDatagramRoundTrip/frame=64/packet=.*/size=(255|256|4096)$' \
  ./hysteria ./hysteria2 ./tuic
```

This command **exits 1** with `PROTOCOL_VIOLATION (local): DATAGRAM frame too
large` for each case. Add `-modfile` for the generated shipped overlay, or the
external-link flag on macOS.

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
the opt-in expectation names the three parents and 18 known leaves explicitly.
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
detector cannot be hidden by a successful outer status.

XFAIL additionally requires one exact `PROTOCOL_VIOLATION (local): DATAGRAM frame
too large` at each named `low_datagram_test.go` assertion, exactly 18 failing
leaves, three failing parents/packages, and no skips. A distinct
`DatagramTooLargeError`, remote error, added assertion, panic, race or trailing
diagnostic fails. Normal rows require their 78 passing datagram leaves and 18
explicit known-failure skips, including payload/destination/receipt assertions.
An exit status or matching diagnostic alone never establishes a green row.

## DEFECT: KI-LOWDGRAM (P2, shipped affected)

Proposed severity: **P2**, shipped affected. The defect is in quic-go's shared
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
not a product crash. This PR tightens that verifier and retains the transport
defect without implementing its fix.

A separate product fix should bound `connection.SendDatagram` by the peer's
`DatagramFrame.MaxDataLen` (and the path bound), returning an accurate
`DatagramTooLargeError` before enqueue. The three `packet.go` implementations'
`WriteTo`/`WritePacket` already use that error in `retryFragmented`. Limits too
small for a header should return a clean error; ordinary low limits should
fragment without a connection close. No product fix is included here.
