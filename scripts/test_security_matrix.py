"""Fail-closed XFAIL acceptance tests; no network or third-party dependencies."""

import copy
import importlib.util
import json
import os
import sys
from pathlib import Path
import tempfile
import unittest


SPEC = importlib.util.spec_from_file_location("security_matrix", Path(__file__).with_name("security-matrix.py"))
MATRIX = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MATRIX)
PARENT = "TestLowDatagramRoundTrip"
PACKAGE = "github.com/sagernet/sing-quic/hysteria"
LEAF = f"{PARENT}/frame=64/packet=false/size=255"
EXITS = {f"github.com/sagernet/sing-quic/{p}": 1 for p in MATRIX.PROTOCOLS}
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
        event("fail", package)
    return events


def transcript(events):
    return "".join(json.dumps(event) + "\n" for event in events)


class KnownFailureVerifierTests(unittest.TestCase):
    def test_exact_failures_accepted(self):
        MATRIX.verify_known_failure(transcript(fixture()), EXITS)

    def test_other_exit_codes_rejected(self):
        for code in [0, 2, 124, -9]:
            with self.subTest(exit_code=code), self.assertRaises(RuntimeError):
                MATRIX.verify_known_failure(transcript(fixture()), dict(EXITS, **{PACKAGE: code}))

    def test_empty_or_non_json_rejected(self):
        for raw in ["", "\n", "null\n", "[]\n", "{}\n", "{broken\n",
                    transcript(fixture()) + "panic: process failure\n",
                    "# build error\n" + transcript(fixture())]:
            with self.subTest(raw=raw[-100:]), self.assertRaises(RuntimeError):
                MATRIX.verify_known_failure(raw, EXITS)

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
                MATRIX.verify_known_failure(transcript(events), EXITS)

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
                    MATRIX.verify_known_failure(transcript(events), EXITS)

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
                MATRIX.verify_known_failure(transcript(events), EXITS)

    def test_signature_must_belong_to_the_named_row(self):
        events = fixture()
        diagnostic = next(e for e in events if SIGNATURE in e.get("Output", ""))
        diagnostic.pop("Test")
        with self.assertRaises(RuntimeError):
            MATRIX.verify_known_failure(transcript(events), EXITS)

    def test_missing_extra_or_invalid_binary_status_rejected(self):
        for exits in [1, {}, {PACKAGE: 1}, dict(EXITS, extra=1),
                      dict(EXITS, **{PACKAGE: True}), dict(EXITS, **{PACKAGE: "1"}),
                      dict(EXITS, **{PACKAGE: None})]:
            with self.subTest(exits=exits), self.assertRaises(RuntimeError):
                MATRIX.verify_known_failure(transcript(fixture()), exits)

    def test_converter_cannot_discard_or_add_output(self):
        raw = b"\x16=== NAME  TestLowDatagramRoundTrip\n\x16FAIL\n"
        decoded = transcript([{"Action": "output", "Output": "FAIL\n"}])
        MATRIX.verify_conversion(raw, decoded)
        for bad_raw, bad_json in [(raw + b"cleanup error\n", decoded),
                                  (raw + b"\xff\n", decoded),
                                  (raw + b"\x16=== NAME  unrelated error\n", decoded),
                                  (b"", decoded), (raw, ""), (raw, "not JSON")]:
            with self.subTest(raw=bad_raw, json=bad_json), self.assertRaises(RuntimeError):
                MATRIX.verify_conversion(bad_raw, bad_json)

    def test_valid_interleaving_and_output_chunks_accepted(self):
        by_package = [[e for e in fixture() if e["Package"] == p] for p in EXITS]
        events = [e for group in zip(*by_package) for e in group]
        split = []
        for event in events:
            if event["Action"] == "output":
                split.extend(dict(event, Output=c) for c in event["Output"])
            else:
                split.append(event)
        MATRIX.verify_known_failure(transcript(split), EXITS)

    def test_corrupt_events_and_lifecycle_rejected(self):
        for corruption in ["unknown-action", "unknown-field", "hidden-output", "late-output",
                           "early-parent", "early-package", "duplicate-diagnostic"]:
            events = fixture()
            leaf_run = next(e for e in events if e["Action"] == "run" and e.get("Test") == LEAF)
            if corruption == "unknown-action":
                leaf_run["Action"] = "pause"
            elif corruption == "unknown-field":
                leaf_run["Error"] = "hidden error"
            elif corruption == "hidden-output":
                leaf_run["Output"] = "panic: hidden error"
            elif corruption == "late-output":
                events.append({"Action": "output", "Package": PACKAGE, "Output": "error"})
            elif corruption in ["early-parent", "early-package"]:
                test = PARENT if corruption == "early-parent" else None
                terminal = next(e for e in events if e["Action"] == "fail" and e.get("Test") == test)
                events.remove(terminal)
                events.insert(3, terminal)
            else:
                diagnostic = next(e for e in events if SIGNATURE in e.get("Output", ""))
                events.insert(events.index(diagnostic), copy.deepcopy(diagnostic))
            with self.subTest(corruption=corruption), self.assertRaises(RuntimeError):
                MATRIX.verify_known_failure(transcript(events), EXITS)
        raw = transcript(fixture()).replace('"Action": "start"', '"Action": "pass", "Action": "start"', 1)
        with self.assertRaisesRegex(RuntimeError, "duplicate JSON field"):
            MATRIX.verify_known_failure(raw, EXITS)


PROBE_SOURCE = '''package probe
import ("fmt"; "os"; "testing"; "time"; "syscall")
func TestLowDatagramRoundTrip(t *testing.T) {
    if os.Getenv("SEC_MATRIX_PROBE") == "no-tests" { return }
    for _, api := range []bool{false, true} {
        for _, size := range []int{255, 256, 4096} {
            t.Run(fmt.Sprintf("frame=64/packet=%t/size=%d", api, size), func(t *testing.T) {
                t.Error("PROTOCOL_VIOLATION (local): DATAGRAM frame too large")
                if os.Getenv("SEC_MATRIX_PROBE") == "timeout" { time.Sleep(time.Hour) }
            })
        }
    }
}
func TestMain(m *testing.M) {
    mode := os.Getenv("SEC_MATRIX_PROBE")
    if mode == "skip-all" { os.Exit(0) }
    code := m.Run()
    switch mode {
    case "trailing-output": fmt.Fprintln(os.Stderr, "unrelated cleanup error")
    case "exit2": os.Exit(2)
    case "exit0": os.Exit(0)
    case "panic": panic("unrelated post-test process panic")
    case "goroutine-panic":
        go func() { panic("unrelated background panic") }()
        time.Sleep(time.Hour)
    case "hang": time.Sleep(time.Hour)
    case "signal": syscall.Kill(os.Getpid(), syscall.SIGKILL)
    }
    os.Exit(code)
}
'''


class RealProcessVerifierTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # An isolated stdlib-only module: never mutate real protocol tests.
        cls.temp = tempfile.TemporaryDirectory(prefix=".verifier-probe-", dir=Path(__file__).parent)
        cls.addClassCleanup(cls.temp.cleanup)
        cls.root = Path(cls.temp.name).resolve()
        (cls.root / "go.mod").write_text("module github.com/sagernet/sing-quic\n\ngo 1.22\n")
        for protocol in MATRIX.PROTOCOLS:
            (cls.root / protocol).mkdir()
            (cls.root / protocol / "low_datagram_test.go").write_text(PROBE_SOURCE)
        cls.go = os.environ.get("SEC_MATRIX_GO", "go")
        cls.env = dict(os.environ, GOTOOLCHAIN="local", GOWORK="off", GOFLAGS="-mod=readonly",
                       NKR_TEST_LOWDGRAM="1", CGO_ENABLED="1")

    def probe(self, mode, rejection=None, go=None):
        out = self.root / mode
        out.mkdir()
        records = []
        env = dict(self.env, SEC_MATRIX_PROBE=mode)
        try:
            if rejection:
                with self.assertRaisesRegex(RuntimeError, rejection):
                    MATRIX.run_known_failure(go or self.go, self.root, out, "probe", [], env, records,
                                             binary_timeout=2, test_timeout="1s")
            else:
                exits = MATRIX.run_known_failure(go or self.go, self.root, out, "probe", [], env, records,
                                                 binary_timeout=2, test_timeout="1s")
                self.assertEqual(exits, EXITS)
        finally:
            summary = [{"command": r["command"], "exit": r.get("exit"),
                        "timed_out": r.get("timed_out")} for r in records]
            print(f"real probe {mode}: " + json.dumps(summary), flush=True)
        return out, records

    def test_real_expected_failure_control(self):
        self.probe("control")

    def test_real_post_test_exit2_hidden_by_go_test(self):
        out, records = self.probe("exit2", "each test binary to exit 1")
        binary_runs = [r for r in records if r["command"][0].endswith(".test")]
        self.assertEqual([r["exit"] for r in binary_runs], [2, 2, 2])
        events = list(map(json.loads, (out / "probe.jsonl").read_text().splitlines()))
        self.assertEqual(sum(e["Action"] == "fail" and "/size=" in e.get("Test", "") for e in events), 18)
        # Reproduce Go's normalization independently: the same binaries' tests
        # report outer exit 1, with all 18 leaves failed and no exit-status text.
        cmd = [self.go, "test", "-json", "-count=1", "-timeout=2s"]
        if MATRIX.sys.platform == "darwin":
            cmd += ["-ldflags=-linkmode=external"]
        log = out / "go-test-normalized.jsonl"
        record = MATRIX.capture_command(cmd + ["./..."], log, self.root,
                                        dict(self.env, SEC_MATRIX_PROBE="exit2"), records, 60)
        self.assertEqual(record["exit"], 1)
        self.assertFalse(record["timed_out"])
        self.assertNotIn("exit status 2", log.read_text())
        outer_events = list(map(json.loads, log.read_text().splitlines()))
        self.assertEqual(sum(e["Action"] == "fail" and "/size=" in e.get("Test", "") for e in outer_events), 18)

    def test_real_post_test_exit0_inconsistent_with_failures(self):
        self.probe("exit0", "each test binary to exit 1")

    def test_real_go_testmain_panic_after_expected_failures(self):
        out, _ = self.probe("panic", "each test binary to exit 1|unexpected output")
        raw = (out / "probe-hysteria-binary.log").read_text()
        self.assertIn("panic: unrelated post-test process panic", raw)
        self.assertEqual(raw.count("PROTOCOL_VIOLATION (local): DATAGRAM frame too large"), 6)

    def test_real_background_panic_after_expected_failures(self):
        self.probe("goroutine-panic", "each test binary to exit 1|unexpected output")

    def test_real_hang_after_expected_failures(self):
        self.probe("hang", "test binary timed out")

    def test_real_go_test_timeout(self):
        self.probe("timeout", "each test binary to exit 1|unexpected")

    def test_real_diagnostic_after_expected_failures_with_exit1(self):
        self.probe("trailing-output", "unexpected output")

    def test_real_signal_after_expected_failures(self):
        self.probe("signal", "each test binary to exit 1")

    def test_real_skip_all_testmain(self):
        self.probe("skip-all", "each test binary to exit 1")

    def test_real_no_selected_leaves(self):
        self.probe("no-tests", "each test binary to exit 1")

    def test_real_converter_failure_or_missing_output(self):
        real_go = MATRIX.shutil.which(self.go)
        for mode, body, rejection in [
                ("converter-error", 'print("converter failed"); sys.exit(2)', "command exit"),
                ("converter-empty", 'sys.exit(0)', "raw test output and JSON output disagree")]:
            wrapper = self.root / mode
            wrapper.write_text(f"#!{sys.executable}\nimport os, sys\n"
                               f"if sys.argv[1:3] == ['tool', 'test2json']:\n    {body}\n"
                               f"os.execv({real_go!r}, [{real_go!r}] + sys.argv[1:])\n")
            wrapper.chmod(0o700)
            # Use another name for the output directory.
            self.probe(mode + "-probe", rejection, go=str(wrapper))

    def test_real_build_failure(self):
        path = self.root / "hysteria" / "broken_test.go"
        path.write_text("package probe\nthis does not compile\n")
        try:
            self.probe("build-failure", "command exit")
        finally:
            path.unlink()


if __name__ == "__main__":
    unittest.main()
