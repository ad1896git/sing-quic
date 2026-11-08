"""Fail-closed XFAIL acceptance tests; no network or third-party dependencies."""

import copy
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import unittest


SPEC = importlib.util.spec_from_file_location("security_matrix", Path(__file__).with_name("security-matrix.py"))
MATRIX = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MATRIX)
PARENT = "TestLowDatagramRoundTrip"
PACKAGE = "github.com/sagernet/sing-quic/hysteria"
LEAF = f"{PARENT}/frame=64/packet=false/size=255"
SIGNATURE = "PROTOCOL_VIOLATION (local): DATAGRAM frame too large"


def fixture():
    events = []

    def event(action, package, test=None, output=None):
        item = {"Action": action, "Package": package}
        if test is not None:
            item["Test"] = test
        if output is not None:
            item["Output"] = output
        events.append(item)

    for protocol in ["hysteria", "hysteria2", "tuic"]:
        package = f"github.com/sagernet/sing-quic/{protocol}"
        event("start", package)
        event("run", package, PARENT)
        event("output", package, PARENT, f"=== RUN   {PARENT}\n")
        for api in ["false", "true"]:
            for size in [255, 256, 4096]:
                leaf = f"{PARENT}/frame=64/packet={api}/size={size}"
                event("run", package, leaf)
                event("output", package, leaf, f"=== RUN   {leaf}\n")
                event("output", package, leaf, f"    low_datagram_test.go:73: {SIGNATURE}\n")
                event("output", package, leaf, f"--- FAIL: {leaf} (0.01s)\n")
                event("fail", package, leaf)
        event("output", package, PARENT, f"--- FAIL: {PARENT} (0.10s)\n")
        event("fail", package, PARENT)
        event("output", package, output="FAIL\n")
        event("output", package, output=f"FAIL\t{package}\t0.101s\n")
        event("fail", package)
    return events


def transcript(events):
    return "".join(json.dumps(event) + "\n" for event in events)


class KnownFailureVerifierTests(unittest.TestCase):
    def test_exact_failures_accepted(self):
        MATRIX.verify_known_failure(transcript(fixture()), 1)

    def test_other_exit_codes_rejected(self):
        for code in [0, 2, 124, -9]:
            with self.subTest(exit_code=code), self.assertRaises(RuntimeError):
                MATRIX.verify_known_failure(transcript(fixture()), code)

    def test_empty_or_non_json_rejected(self):
        for raw in ["", "\n", "null\n", "[]\n", "{}\n", "{broken\n",
                    transcript(fixture()) + "panic: process failure\n",
                    "# build error\n" + transcript(fixture())]:
            with self.subTest(raw=raw[-100:]), self.assertRaises(RuntimeError):
                MATRIX.verify_known_failure(raw, 1)

    def test_changed_leaf_error_rejected(self):
        for error in ["DATAGRAM frame too large",  # DatagramTooLargeError is distinct.
                      "INTERNAL_ERROR (local): DATAGRAM frame too large",
                      "PROTOCOL_VIOLATION (local): unrelated transport failure",
                      "PROTOCOL_VIOLATION (remote): DATAGRAM frame too large",
                      "context deadline exceeded", "write n=0 err=closed",
                      "panic: " + SIGNATURE, SIGNATURE + ": extra cause", ""]:
            events = fixture()
            target = next(e for e in events if SIGNATURE in e.get("Output", ""))
            target["Output"] = f"    low_datagram_test.go:73: {error}\n"
            with self.subTest(error=error), self.assertRaises(RuntimeError):
                MATRIX.verify_known_failure(transcript(events), 1)

    def test_additional_diagnostics_rejected_at_every_scope(self):
        for diagnostic in ["panic: unrelated post-test process panic\n",
                           "fatal error: concurrent map writes\n",
                           "WARNING: DATA RACE\n", "panic: test timed out after 3m0s\n",
                           "FAIL [build failed]\n", "exit status 2\n",
                           "unexpected cleanup error\n"]:
            for test in [None, PARENT, LEAF]:
                events = fixture()
                position = next(i for i, e in enumerate(events)
                                if e["Action"] == "fail" and e.get("Test") == test)
                extra = {"Action": "output", "Package": PACKAGE, "Output": diagnostic}
                if test is not None:
                    extra["Test"] = test
                events.insert(position, extra)
                with self.subTest(diagnostic=diagnostic, scope=test), self.assertRaises(RuntimeError):
                    MATRIX.verify_known_failure(transcript(events), 1)

    def test_missing_extra_duplicate_or_passed_rows_rejected(self):
        for name in ["missing-leaf", "extra-leaf", "duplicate-leaf", "passed-leaf", "skipped-leaf",
                     "missing-parent", "passed-parent", "missing-package", "extra-package",
                     "duplicate-package", "passed-package", "truncated", "wrong-package-prefix"]:
            events = fixture()
            if name == "missing-leaf":
                events = [e for e in events if (e["Package"], e.get("Test")) != (PACKAGE, LEAF)]
            elif name in ["extra-leaf", "duplicate-leaf"]:
                extra = [copy.deepcopy(e) for e in events if (e["Package"], e.get("Test")) == (PACKAGE, LEAF)]
                if name == "extra-leaf":
                    for e in extra:
                        e["Test"] = e["Test"].replace("size=255", "size=257")
                        if "Output" in e:
                            e["Output"] = e["Output"].replace("size=255", "size=257")
                events[3:3] = extra
            elif name in ["passed-leaf", "skipped-leaf", "passed-parent", "passed-package"]:
                test = LEAF if name.endswith("leaf") else PARENT if name.endswith("parent") else None
                target = next(e for e in events if e["Action"] == "fail" and e.get("Test") == test)
                target["Action"] = "skip" if name == "skipped-leaf" else "pass"
            elif name == "missing-parent":
                events = [e for e in events if e.get("Test") != PARENT or e["Package"] != PACKAGE]
            elif name == "missing-package":
                events = [e for e in events if e["Package"] != PACKAGE]
            elif name in ["extra-package", "duplicate-package"]:
                extra = [copy.deepcopy(e) for e in events if e["Package"] == PACKAGE]
                if name == "extra-package":
                    for e in extra:
                        e["Package"] += "-extra"
                events += extra
            elif name == "truncated":
                events.pop()
            elif name == "wrong-package-prefix":
                for e in events:
                    e["Package"] = e["Package"].replace("github.com/sagernet", "example.org/other")
            with self.subTest(outcome=name), self.assertRaises(RuntimeError):
                MATRIX.verify_known_failure(transcript(events), 1)

    def test_signature_must_belong_to_the_named_row(self):
        events = fixture()
        diagnostic = next(e for e in events if SIGNATURE in e.get("Output", ""))
        diagnostic.pop("Test")
        with self.assertRaises(RuntimeError):
            MATRIX.verify_known_failure(transcript(events), 1)

    def test_real_go_testmain_panic_after_expected_failures(self):
        # Reproduce the review's process-level failure using an isolated stdlib
        # module, never injecting a panic into the actual protocol packages.
        source = '''package probe
import ("fmt"; "os"; "testing")
func TestLowDatagramRoundTrip(t *testing.T) {
    for _, api := range []bool{false, true} {
        for _, size := range []int{255, 256, 4096} {
            t.Run(fmt.Sprintf("frame=64/packet=%t/size=%d", api, size), func(t *testing.T) {
                t.Fatal("PROTOCOL_VIOLATION (local): DATAGRAM frame too large")
            })
        }
    }
}
func TestMain(m *testing.M) {
    code := m.Run()
    if os.Getenv("SEC_MATRIX_PROBE_PANIC") == "1" { panic("unrelated post-test process panic") }
    os.Exit(code)
}
'''
        with tempfile.TemporaryDirectory(prefix=".verifier-probe-", dir=Path(__file__).parent) as directory:
            root = Path(directory)
            (root / "go.mod").write_text("module github.com/sagernet/sing-quic\n\ngo 1.22\n")
            for protocol in ["hysteria", "hysteria2", "tuic"]:
                (root / protocol).mkdir()
                (root / protocol / "low_datagram_test.go").write_text(source)
            env = dict(os.environ, GOTOOLCHAIN="local", GOWORK="off", GOFLAGS="-mod=readonly")
            for panic in [False, True]:
                env["SEC_MATRIX_PROBE_PANIC"] = "1" if panic else "0"
                cmd = [env.get("SEC_MATRIX_GO", "go"), "test", "-json", "-count=1", "-timeout=20s"]
                if sys.platform == "darwin":
                    cmd += ["-ldflags=-linkmode=external"]
                with tempfile.TemporaryFile() as log:
                    process = subprocess.Popen(cmd + ["./..."], cwd=root, env=env, stdout=log,
                                               stderr=subprocess.STDOUT, start_new_session=True)
                    try:
                        process.wait(timeout=60)
                    except subprocess.TimeoutExpired:
                        os.killpg(process.pid, signal.SIGKILL)
                        process.wait()
                        self.fail("Go verifier probe exceeded 60 seconds")
                    log.seek(0)
                    raw = log.read().decode()
                self.assertEqual(process.returncode, 1, raw)
                if panic:
                    self.assertIn("panic: unrelated post-test process panic", raw)
                    # All 18 expected leaf failures still occurred before panic.
                    leaves = [e for e in map(json.loads, raw.splitlines())
                              if e.get("Action") == "fail" and "/size=" in e.get("Test", "")]
                    self.assertEqual(len(leaves), 18)
                    with self.assertRaisesRegex(RuntimeError, "unexpected output"):
                        MATRIX.verify_known_failure(raw, process.returncode)
                else:
                    MATRIX.verify_known_failure(raw, process.returncode)


if __name__ == "__main__":
    unittest.main()
