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

The self-tests reject panics (including actual post-test `TestMain` and
background panics), silent post-test exits 0/2, signals, hangs, Go timeouts,
build/converter failures, lost converter output, fatal/race diagnostics,
a different error cause, vacuous passes, missing/extra/duplicate rows, invalid
lifecycles, and malformed/non-JSON output. They also reproduce Go's silent
normalization of a binary's exit 2 into outer exit 1, then require rejection by
the same direct-binary path used in the matrix. Process probes create a temporary
standard-library-only Go module and remove it after the checks. Positive controls
require the exact failures and accept valid interleaving/output chunking.

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

For each dependency set, the runner instead builds each selected package with
`go test -c` and directly executes its fresh binary with
`-test.v=test2json -test.count=1 -test.timeout=180s -test.run=<selection>`.
It owns each process and records its actual OS exit status using `Popen.wait`.
This avoids `go test`'s normalization of silent binary exit 2 into outer exit 1.
Each build must exit 0 without diagnostics; **each binary itself must exit 1**,
without hitting the outer 300-second deadline. A timeout kills/reaps the process
group and fails regardless of the transcript.

Only after a binary exits, `go tool test2json -p <package>` reads its completed
raw log from stdin; the converter never runs the binary. Conversion must exit 0.
All raw UTF-8 output must survive in the JSON Output events, except Go's known
line-leading marker and selected-test NAME controls. Lost/added diagnostics,
invalid bytes, unknown NAME controls, or any disagreement fail verification.
The raw logs, decoded JSONL, actual binary exits, exact commands and deadlines
are preserved in the CI artifacts.

XFAIL requires agreement between those direct statuses and the entire decoded
outcome: exactly the 18 named failing leaves with one exact transport diagnostic
each, three failing parents, and three final package failures. The verifier
allowlists the complete lifecycle and output, including the binary's final
`FAIL` line; it rejects unknown JSON fields/actions and duplicate JSON keys.
An exit 1 alone or a matching diagnostic alone never establishes XFAIL.
Package-level/raw stderr diagnostics fail even after all expected failures.
A panic, fatal error, race, build/converter failure, timeout, changed error,
pass, skip, missing/extra/duplicate row, truncated/invalid lifecycle, unexpected
status, or other output fails the matrix. Normal rows retain the explicit skips.

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
