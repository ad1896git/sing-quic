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
external-link flag on macOS. The runner executes this opt-in command for each
dependency set and only records XFAIL if exactly these 18 leaf tests fail with
that diagnostic. A timeout, build failure, changed outcome, or other failed
test fails the matrix. Normal rows retain the explicit skips in their logs.

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

A separate product fix should bound `connection.SendDatagram` by the peer's
`DatagramFrame.MaxDataLen` (and the path bound), returning an accurate
`DatagramTooLargeError` before enqueue. The three `packet.go` implementations'
`WriteTo`/`WritePacket` already use that error in `retryFragmented`. Limits too
small for a header should return a clean error; ordinary low limits should
fragment without a connection close. No product fix is included here.
